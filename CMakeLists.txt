cmake_minimum_required(VERSION 3.14)
project(hpp_proto
  VERSION 0.1.0
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20) # requires for compiling is_utf
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(HPP_PROTO_PROTOC_PLUGIN "Enable protoc plugin" ON)
option(HPP_PROTO_TESTS "Enable HPP_PROTO tests" ${PROJECT_IS_TOP_LEVEL})
option(HPP_PROTO_BENCHMARKS "Enable buidling benchmarks" OFF)

option(HPP_PROTO_ENABLE_SANITIZER "Enable address and undefined behavor sanitizer" OFF)

set(HPP_PROTO_PROTOC "find" CACHE STRING "'find' for locating using find_program, or 'compile' for compiling from source")
set_property(CACHE HPP_PROTO_PROTOC PROPERTY STRINGS
  "find" "compile")

if(APPLE)
  set(CMAKE_CXX_VISIBILITY_PRESET "hidden")
  set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
endif()

if(MSVC)
  add_compile_options("/EHsc")
else()
  set(HPP_PROTO_COMPILE_OPTIONS "-Wall" "-Wall" "-Wextra")
endif()

if(HPP_PROTO_ENABLE_SANITIZER)
  if(MSVC)
    add_compile_options("/fsanitize=address" "/Zi")
    add_link_options("/fsanitize=address")
  else()
    add_compile_options("-fsanitize=address,undefined" "-fno-omit-frame-pointer")
    add_link_options("-fsanitize=address,undefined")
  endif()
endif()

if(CMAKE_GENERATOR MATCHES "Visual Studio")
  find_program(ccache_exe ccache)

  if(ccache_exe)
    file(COPY_FILE
      ${ccache_exe} ${CMAKE_BINARY_DIR}/cl.exe
      ONLY_IF_DIFFERENT)

    # By default Visual Studio generators will use /Zi which is not compatible
    # with ccache, so tell Visual Studio to use /Z7 instead.
    message(STATUS "Setting MSVC debug information format to 'Embedded'")
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug,RelWithDebInfo>:Embedded>")

    set(CMAKE_VS_GLOBALS
      "CLToolExe=cl.exe"
      "CLToolPath=${CMAKE_BINARY_DIR}"
      "TrackFileAccess=false"
      "UseMultiToolTask=true"
      "DebugInformationFormat=OldStyle"
    )
  endif()
endif()

include(third-party.cmake)

add_library(libhpp_proto INTERFACE)
target_include_directories(libhpp_proto INTERFACE
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${glaze_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(libhpp_proto INTERFACE cxx_std_20)
target_link_libraries(libhpp_proto INTERFACE is_utf8)

add_library(libhpp_proto_no_utf8_validation INTERFACE)
target_include_directories(libhpp_proto_no_utf8_validation INTERFACE
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${glaze_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(libhpp_proto_no_utf8_validation INTERFACE cxx_std_20)
target_compile_definitions(libhpp_proto_no_utf8_validation INTERFACE HPP_PROTO_NO_UTF8_VALIDATION)

add_library(hpp_proto::libhpp_proto ALIAS libhpp_proto)
add_library(hpp_proto::libhpp_proto_no_utf8_validation ALIAS libhpp_proto_no_utf8_validation)

if(MSVC)
  target_compile_options(libhpp_proto INTERFACE "/Zc:preprocessor")
  target_compile_options(libhpp_proto_no_utf8_validation INTERFACE "/Zc:preprocessor")
endif()

if(HPP_PROTO_TESTS)
  enable_testing()
  add_subdirectory(unittests)
  include(CTest)
endif()

if(HPP_PROTO_PROTOC_PLUGIN)
  include(cmake/protobuf_generate.cmake)

  add_subdirectory(protoc-plugin)

  if(HPP_PROTO_TESTS)
    add_subdirectory(tests)
    add_subdirectory(tutorial)
  endif()

  if(HPP_PROTO_BENCHMARKS)
    add_subdirectory(benchmarks)
  endif()

  write_basic_package_version_file(
    lib/cmake/hpp_proto/hpp_proto-config-version.cmake
    COMPATIBILITY AnyNewerVersion
  )

  if(HPP_PROTO_PROTOC STREQUAL "compile")
    # copy google proto files into include directory
    file(GLOB GOOGLE_PROTOFILES RELATIVE "${protobuf_SOURCE_DIR}/src/google/protobuf" "${protobuf_SOURCE_DIR}/src/google/protobuf/*.proto")
    list(FILTER GOOGLE_PROTOFILES EXCLUDE REGEX ".*test.*")
    list(APPEND GOOGLE_PROTOFILES "compiler/plugin.proto")

    foreach(f ${GOOGLE_PROTOFILES})
      configure_file(${protobuf_SOURCE_DIR}/src/google/protobuf/${f} include/google/protobuf/${f} COPYONLY)
    endforeach()

    install(TARGETS protoc EXPORT hpp_proto-targets)
  endif()

  install(TARGETS libhpp_proto EXPORT hpp_proto-targets)

  install(DIRECTORY include/ TYPE INCLUDE)
  install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/ TYPE INCLUDE)
  install(SCRIPT "${glaze_BINARY_DIR}/cmake_install.cmake")

  configure_file(hpp_proto-config.cmake.in lib/cmake/hpp_proto/hpp_proto-config.cmake @ONLY)
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/hpp_proto/hpp_proto-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/hpp_proto/hpp_proto-config-version.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/protobuf_generate.cmake"
    DESTINATION "lib/cmake/hpp_proto")

  install(
    FILES ${is_utf8_SOURCE_DIR}/include/is_utf8.h
    TYPE INCLUDE
  )

  install(
    TARGETS is_utf8
    EXPORT hpp_proto-targets
  )

  install(EXPORT hpp_proto-targets
    DESTINATION lib/cmake/hpp_proto
    NAMESPACE hpp_proto::)
  export(EXPORT hpp_proto-targets FILE lib/cmake/hpp_proto/hpp_proto-targets.cmake
    NAMESPACE hpp_proto::)
endif(HPP_PROTO_PROTOC_PLUGIN)
