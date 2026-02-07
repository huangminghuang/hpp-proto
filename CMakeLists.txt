cmake_minimum_required(VERSION 3.25)
message("CMake Version: ${CMAKE_VERSION}")
project(hpp_proto
  VERSION 1.0.0
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(HPP_PROTO_PROTOC_PLUGIN "Enable protoc plugin" ON)
option(HPP_PROTO_TESTS "Enable HPP_PROTO tests" ${PROJECT_IS_TOP_LEVEL})
option(HPP_PROTO_BENCHMARKS "Enable building benchmarks" OFF)
option(HPP_PROTO_FUZZER_ONLY "Build only fuzzers and their dependencies" OFF)

option(HPP_PROTO_TEST_USE_PROTOBUF "Use libprotobuf to generate data for tests" OFF)

set(HPP_PROTO_PROTOC "find" CACHE STRING "'find' for locating using find_program, 'compile' for compiling from source, or 'download' for downloading precompiled executable from github")
set_property(CACHE HPP_PROTO_PROTOC PROPERTY STRINGS
  "find" "compile" "download")

if(HPP_PROTO_FUZZER_ONLY)
  if(NOT HPP_PROTO_PROTOC_PLUGIN)
    message(FATAL_ERROR "HPP_PROTO_FUZZER_ONLY requires HPP_PROTO_PROTOC_PLUGIN=ON")
  endif()

  set(HPP_PROTO_TESTS OFF CACHE BOOL "Enable HPP_PROTO tests" FORCE)
  set(HPP_PROTO_BENCHMARKS OFF CACHE BOOL "Enable building benchmarks" FORCE)
endif()

if(APPLE)
  set(CMAKE_CXX_VISIBILITY_PRESET "hidden")
  set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
endif()

if(MSVC)
  message(" compiler version ${CMAKE_CXX_COMPILER_VERSION}")
  add_compile_options("/EHsc")

  if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.42 AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 19.43)
    message(WARNING "MSVC 19.42 has known bug to compile glaze, disable all JSON support")
    set(HPP_PROTO_DISABLE_GLAZE ON)
  endif()
else()
  set(HPP_PROTO_COMPILE_OPTIONS "-Wall" "-Wall" "-Wextra" "-Werror=sign-conversion")
endif()

if(CMAKE_GENERATOR MATCHES "Visual Studio" AND CMAKE_CXX_COMPILER_LAUNCHER STREQUAL "ccache")
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

include(third-parties.cmake)

set(CMAKE_CXX_FLAGS_COVERAGE "${CMAKE_CXX_FLAGS} -g -O0 --coverage -fprofile-arcs -ftest-coverage")

if(HPP_PROTO_DISABLE_GLAZE)
  add_compile_definitions(BOOST_UT_DISABLE_MODULE HPP_PROTO_DISABLE_GLAZE)
endif()

add_library(libhpp_proto INTERFACE)
target_include_directories(libhpp_proto INTERFACE
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<INSTALL_INTERFACE:include>)

target_compile_features(libhpp_proto INTERFACE cxx_std_23)
target_link_libraries(libhpp_proto INTERFACE is_utf8)

add_library(hpp_proto::libhpp_proto ALIAS libhpp_proto)

if(MSVC)
  target_compile_options(libhpp_proto INTERFACE "/Zc:preprocessor")
endif()

if(HPP_PROTO_TESTS OR HPP_PROTO_FUZZER_ONLY)
  enable_testing()
  add_subdirectory(unittests)
  include(CTest)
endif()

if(HPP_PROTO_PROTOC_PLUGIN)
  include(cmake/protobuf_generate_hpp.cmake)

  add_subdirectory(protoc-plugin)

  if(HPP_PROTO_TESTS AND NOT HPP_PROTO_PROTOC STREQUAL "compile")
    include(cmake/grpc_check.cmake)
  endif()

  if(HPP_PROTO_TESTS)
    add_subdirectory(tests)
    add_subdirectory(tutorial)
  endif()
  if(HPP_PROTO_FUZZER_ONLY)
    add_subdirectory(fuzz)
  endif()
  if(HPP_PROTO_BENCHMARKS)
    add_subdirectory(benchmarks)
  endif()

  include(CMakePackageConfigHelpers)
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
  elseif(HPP_PROTO_PROTOC STREQUAL "download")
    if(DEFINED HPP_PROTO_PROTOC_ZIP_PATH)
      configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/protoc_install.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/protoc_install.cmake"
        @ONLY
      )
      install(SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/protoc_install.cmake")
    endif()
  endif()

  install(TARGETS libhpp_proto EXPORT hpp_proto-targets)

  install(DIRECTORY include/ TYPE INCLUDE)
  install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/ TYPE INCLUDE)
  

  configure_file(hpp_proto-config.cmake.in lib/cmake/hpp_proto/hpp_proto-config.cmake @ONLY)
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/hpp_proto/hpp_proto-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/hpp_proto/hpp_proto-config-version.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/protobuf_generate_hpp.cmake"
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

include(cmake/coverage.cmake)
