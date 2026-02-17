cmake_minimum_required(VERSION 3.25)
message("CMake Version: ${CMAKE_VERSION}")
project(hpp_proto
  DESCRIPTION "A modern C++23 implementation of Protocol Buffers"
  VERSION 1.0.0
  LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(HPP_PROTO_PROTOC "find" CACHE STRING "'find' for locating using find_program, or 'compile' for compiling from source")
set_property(CACHE HPP_PROTO_PROTOC PROPERTY STRINGS "find" "compile")
option(HPP_PROTO_TESTS "Enable HPP_PROTO tests" ${PROJECT_IS_TOP_LEVEL})

# The following options are internal and not part of the public interface.
option(HPP_PROTO_PROTOC_PLUGIN "Enable protoc plugin" ON)
option(HPP_PROTO_BENCHMARKS "Enable building benchmarks" OFF)
option(HPP_PROTO_FUZZER_ONLY "Build only fuzzers and their dependencies" OFF)

if(HPP_PROTO_FUZZER_ONLY)
  if(NOT HPP_PROTO_PROTOC_PLUGIN)
    message(FATAL_ERROR "HPP_PROTO_FUZZER_ONLY requires HPP_PROTO_PROTOC_PLUGIN=ON")
  endif()

  set(HPP_PROTO_TESTS OFF CACHE BOOL "Enable HPP_PROTO tests" FORCE)
  set(HPP_PROTO_BENCHMARKS OFF CACHE BOOL "Enable building benchmarks" FORCE)
endif()

if(NOT MSVC)
  set(HPP_PROTO_COMPILE_OPTIONS "-Wall" "-Wextra" "-Werror=sign-conversion")
endif()

include(third-parties.cmake)
include(cmake/coverage.cmake)

add_library(hpp_proto_core INTERFACE)

file(GLOB_RECURSE HPP_PROTO_CORE_PUBLIC_HEADERS CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/include/hpp_proto/*.hpp")
target_sources(hpp_proto_core INTERFACE
  FILE_SET HEADERS
  BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
  FILES ${HPP_PROTO_CORE_PUBLIC_HEADERS})

target_link_libraries(hpp_proto_core INTERFACE is_utf8)
add_library(hpp_proto::hpp_proto_core ALIAS hpp_proto_core)
install(TARGETS hpp_proto_core EXPORT hpp_proto-targets
  FILE_SET HEADERS DESTINATION include)

if(HPP_PROTO_TESTS)
  enable_testing()
  include(CTest)
  include("cmake/hpp_proto_test_helpers.cmake")
  add_subdirectory(unittests)
endif()

if(NOT HPP_PROTO_PROTOC_PLUGIN)
  return()
endif()

include(cmake/protobuf_generate_hpp.cmake)

add_subdirectory(protoc-plugin)
include(hpp_proto.cmake)

if(HPP_PROTO_TESTS AND NOT HPP_PROTO_PROTOC STREQUAL "compile")
  include(cmake/grpc_check.cmake)
endif()

if(HPP_PROTO_TESTS OR HPP_PROTO_FUZZER_ONLY)
  add_subdirectory(tests)
endif()

if(PROJECT_IS_TOP_LEVEL AND HPP_PROTO_TESTS)
  add_subdirectory(tutorial)
endif()

if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/fuzz) # conan recipe exclude fuzz directory 
  add_subdirectory(fuzz)
endif()

if(HPP_PROTO_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()

include(cmake/hpp_proto_install_package.cmake)
