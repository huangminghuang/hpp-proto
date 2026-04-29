cmake_minimum_required(VERSION 3.25)
message("CMake Version: ${CMAKE_VERSION}")
project(hpp_proto
  DESCRIPTION "A modern C++23 implementation of Protocol Buffers"
  VERSION 1.0.0
  LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(PROJECT_IS_TOP_LEVEL)
  find_program(HPP_PROTO_CLANG_FORMAT NAMES clang-format)
  file(GLOB_RECURSE HPP_PROTO_FORMAT_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/tutorial/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/tutorial/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unittests/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unittests/*.hpp")

  if(HPP_PROTO_CLANG_FORMAT)
    add_custom_target(format
      COMMAND "${HPP_PROTO_CLANG_FORMAT}" -i ${HPP_PROTO_FORMAT_SOURCES}
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      COMMENT "Running clang-format"
      VERBATIM)
  else()
    message(STATUS "clang-format not found; the format target will not be available")
  endif()
endif()

set(HPP_PROTO_PROTOC "find" CACHE STRING "'find' for locating using find_program, or 'compile' for compiling from source")
set_property(CACHE HPP_PROTO_PROTOC PROPERTY STRINGS "find" "compile")
set(HPP_PROTO_PROTOC_GEN_HPP "" CACHE FILEPATH
    "Path to host protoc-gen-hpp executable. If set, hpp-proto uses this binary instead of building src/protoc-plugin.")
option(HPP_PROTO_TESTS "Enable HPP_PROTO tests" ${PROJECT_IS_TOP_LEVEL})
option(HPP_PROTO_CORE_TESTS_ONLY "Build only unittests targets (core tests only)" OFF)

# The following options are internal and not part of the public interface.
option(HPP_PROTO_BENCHMARKS "Enable building benchmarks" OFF)
option(HPP_PROTO_FUZZER_ONLY "Build only fuzzers and their dependencies" OFF)

if(HPP_PROTO_CORE_TESTS_ONLY AND HPP_PROTO_FUZZER_ONLY)
  message(FATAL_ERROR "HPP_PROTO_CORE_TESTS_ONLY and HPP_PROTO_FUZZER_ONLY cannot both be ON")
endif()

if(HPP_PROTO_CORE_TESTS_ONLY)
  set(HPP_PROTO_TESTS ON CACHE BOOL "Enable HPP_PROTO tests" FORCE)
  set(HPP_PROTO_BENCHMARKS OFF CACHE BOOL "Enable building benchmarks" FORCE)
  set(HPP_PROTO_FUZZER_ONLY OFF CACHE BOOL "Build only fuzzers and their dependencies" FORCE)
endif()

if(HPP_PROTO_FUZZER_ONLY)
  set(HPP_PROTO_TESTS OFF CACHE BOOL "Enable HPP_PROTO tests" FORCE)
  set(HPP_PROTO_BENCHMARKS OFF CACHE BOOL "Enable building benchmarks" FORCE)
endif()

if(CMAKE_CROSSCOMPILING AND NOT HPP_PROTO_PROTOC_GEN_HPP)
  find_program(HPP_PROTO_PROTOC_GEN_HPP
    NAMES protoc-gen-hpp
    NO_CMAKE_FIND_ROOT_PATH)

  if(HPP_PROTO_PROTOC_GEN_HPP)
    set(HPP_PROTO_PROTOC_GEN_HPP "${HPP_PROTO_PROTOC_GEN_HPP}" CACHE FILEPATH
      "Path to host protoc-gen-hpp executable. If set, hpp-proto uses this binary instead of building src/protoc-plugin."
      FORCE)
    message(STATUS "Cross-compiling: found host protoc-gen-hpp at ${HPP_PROTO_PROTOC_GEN_HPP}")
  else()
    message(FATAL_ERROR
      "Cross-compiling requires -DHPP_PROTO_PROTOC_GEN_HPP or protoc-gen-hpp in PATH.")
  endif()
endif()

if(HPP_PROTO_PROTOC_GEN_HPP)
  if(NOT EXISTS "${HPP_PROTO_PROTOC_GEN_HPP}")
    message(FATAL_ERROR
      "HPP_PROTO_PROTOC_GEN_HPP does not exist: ${HPP_PROTO_PROTOC_GEN_HPP}")
  endif()
  if(NOT IS_EXECUTABLE "${HPP_PROTO_PROTOC_GEN_HPP}")
    message(FATAL_ERROR
      "HPP_PROTO_PROTOC_GEN_HPP is not executable: ${HPP_PROTO_PROTOC_GEN_HPP}")
  endif()
endif()

if(NOT MSVC)
  set(HPP_PROTO_COMPILE_OPTIONS "-Wall" "-Wextra" "-Werror=sign-conversion")
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # Alias-enabled JSON metadata can substantially increase constexpr work in Glaze
    # for very large generated messages (e.g., TestAllTypes). Raise GCC's default
    # constexpr operation budget to avoid spurious compile failures in CI.
    list(APPEND HPP_PROTO_COMPILE_OPTIONS "-fconstexpr-ops-limit=67108864")
  endif()
else()
  # Ensure exception unwind semantics are enabled for MSVC builds.
  # This is required for tests that use boost::ut `throws(...)` and avoids C4530.
  add_compile_options("/EHsc")
endif()

include(third-parties.cmake)
include(cmake/coverage.cmake)

add_library(hpp_proto_core INTERFACE)

file(GLOB_RECURSE HPP_PROTO_CORE_PUBLIC_HEADERS CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/include/hpp_proto/*.hpp")
list(FILTER HPP_PROTO_CORE_PUBLIC_HEADERS EXCLUDE REGEX ".*/include/hpp_proto/dynamic_message/.*\\.hpp$")
target_sources(hpp_proto_core INTERFACE
  FILE_SET HEADERS
  BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
  FILES ${HPP_PROTO_CORE_PUBLIC_HEADERS})

if(is_utf8_ADDED)
  target_link_libraries(hpp_proto_core INTERFACE is_utf8)
else()
  target_link_libraries(hpp_proto_core INTERFACE is_utf8::is_utf8)
endif()
add_library(hpp_proto::hpp_proto_core ALIAS hpp_proto_core)
if(NOT HPP_PROTO_CORE_TESTS_ONLY)
  install(TARGETS hpp_proto_core EXPORT hpp_proto-targets
    FILE_SET HEADERS DESTINATION include)
endif()

if(HPP_PROTO_TESTS)
  enable_testing()
  include(CTest)
  include("cmake/hpp_proto_test_helpers.cmake")
  add_subdirectory(unittests)
endif()

if(HPP_PROTO_CORE_TESTS_ONLY)
  return()
endif()

if(HPP_PROTO_PROTOC_GEN_HPP)
  add_executable(protoc-gen-hpp IMPORTED GLOBAL)
  set_target_properties(protoc-gen-hpp PROPERTIES
    IMPORTED_LOCATION "${HPP_PROTO_PROTOC_GEN_HPP}")
  add_executable(hpp_proto::protoc-gen-hpp ALIAS protoc-gen-hpp)
  message(STATUS "Using external protoc-gen-hpp: ${HPP_PROTO_PROTOC_GEN_HPP}")
endif()

include(cmake/protobuf_generate_hpp.cmake)
add_subdirectory(src)

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
