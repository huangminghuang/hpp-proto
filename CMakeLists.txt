cmake_minimum_required(VERSION 3.14)
message("CMake Version: ${CMAKE_VERSION}")
project(hpp_proto
  VERSION 0.9.0
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20) # requires for compiling is_utf
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(HPP_PROTO_PROTOC_PLUGIN "Enable protoc plugin" ON)
option(HPP_PROTO_WELLKNOWN_TYPES "Enable code generation for Wellknown types" ${HPP_PROTO_PROTOC_PLUGIN})
option(HPP_PROTO_TESTS "Enable HPP_PROTO tests" ${PROJECT_IS_TOP_LEVEL})
option(HPP_PROTO_BENCHMARKS "Enable building benchmarks" OFF)

option(HPP_PROTO_ENABLE_SANITIZERS "The sanitizer to enable" OFF)
option(HPP_PROTO_BUILD_FUZZ "Build fuzz target" OFF)
option(HPP_PROTO_TEST_USE_PROTOBUF "Use libprotobuf to generate data for tests" OFF)

set(HPP_PROTO_PROTOC "find" CACHE STRING "'find' for locating using find_program, or 'compile' for compiling from source")
set_property(CACHE HPP_PROTO_PROTOC PROPERTY STRINGS
  "find" "compile")

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

if(HPP_PROTO_ENABLE_SANITIZERS)
  if(MSVC)
    # add_compile_options("/fsanitize=address")
    # add_link_options("/fsanitize=address")
  else()
    add_compile_options("-fsanitize=${HPP_PROTO_ENABLE_SANITIZERS}" "-fno-omit-frame-pointer")
    add_link_options("-fsanitize=${HPP_PROTO_ENABLE_SANITIZERS}")
  endif()
endif()

set(CMAKE_CXX_FLAGS_COVERAGE "${CMAKE_CXX_FLAGS} -g -O0 --coverage -fprofile-arcs -ftest-coverage")

if(HPP_PROTO_DISABLE_GLAZE)
  add_compile_definitions(BOOST_UT_DISABLE_MODULE HPP_PROTO_DISABLE_GLAZE)
endif()

add_library(libhpp_proto INTERFACE)
target_include_directories(libhpp_proto INTERFACE
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_include_directories(libhpp_proto SYSTEM INTERFACE
  $<BUILD_INTERFACE:${glaze_SOURCE_DIR}/include>)
target_compile_features(libhpp_proto INTERFACE cxx_std_23)
target_link_libraries(libhpp_proto INTERFACE is_utf8)

add_library(hpp_proto::libhpp_proto ALIAS libhpp_proto)

if(MSVC)
  target_compile_options(libhpp_proto INTERFACE "/Zc:preprocessor")
endif()

if(HPP_PROTO_TESTS)
  enable_testing()
  add_subdirectory(unittests)
  include(CTest)
endif()

if(HPP_PROTO_PROTOC_PLUGIN)
  include(cmake/protobuf_generate_hpp.cmake)

  add_subdirectory(protoc-plugin)

  if(HPP_PROTO_TESTS)
    function(add_hpp_proto_test name)
      add_test(NAME ${name} COMMAND ${name} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
      set_property(TEST ${name} PROPERTY ENVIRONMENT "${HPP_PROTO_TEST_ENVIRONMENT}")
    endfunction(add_hpp_proto_test)

    add_subdirectory(tests)
    add_subdirectory(tutorial)
    if (HPP_PROTO_BUILD_FUZZ AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
      add_subdirectory(fuzz)
    endif()
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
