cmake_minimum_required(VERSION 3.14)
project(hpp_proto 
        VERSION 0.1.0
        LANGUAGES CXX)

include(cmake/CPM.cmake)

if (APPLE)
    set(CMAKE_CXX_VISIBILITY_PRESET "hidden")
    set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
endif()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

CPMAddPackage(
  NAME glaze
  VERSION 2.0.6.mod2
  GITHUB_REPOSITORY huangminghuang/glaze
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED On)
CPMAddPackage(
  NAME protobuf
  VERSION 24.4
  GITHUB_REPOSITORY protocolbuffers/protobuf
  OPTIONS "ABSL_PROPAGATE_CXX_STD ON"
          "protobuf_INSTALL OFF"
          "protobuf_BUILD_TESTS OFF"
          "protobuf_BUILD_PROTOBUF_BINARIES ON"
          "protobuf_BUILD_PROTOC_BINARIES ON"
          "EXCLUDE_FROM_ALL"
)
CPMAddPackage("gh:fmtlib/fmt#10.1.0")

option(HPP_PROTO_TESTS "Enable HPP_PROTO tests" ON)
option(HPP_PROTO_BENCHMARKS "Enable buidling benchmarks" OFF)
option(HPP_ENABLE_CLANG_TIDY "Enable clang tidy" OFF)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  file(REAL_PATH ${CMAKE_CXX_COMPILER} CLANG_REAL_PATH)
  cmake_path(GET CLANG_REAL_PATH PARENT_PATH CLANG_DIR)
endif()


if (HPP_ENABLE_CLANG_TIDY)
  if (EXISTS "${CLANG_DIR}/clang-tidy")
    set(CLANG_TIDY_EXE "${CLANG_DIR}/clang-tidy")
  else()
    find_program(CLANG_TIDY_EXE NAME clang-tidy)
  endif()
  if (CLANG_TIDY_EXE)
    set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE};-p;${CMAKE_CURRENT_BINARY_DIR}")
    configure_file(clang-tidy-disable-all-checks ${CMAKE_CURRENT_BINARY_DIR}/_deps/.clang-tidy)
  else()
    message(FATAL_ERROR "clang-tidy not found")
  endif()
else()
  set(CMAKE_CXX_CLANG_TIDY)
endif()


add_library(libhpp_proto INTERFACE)
target_include_directories(libhpp_proto INTERFACE 
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${glaze_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(libhpp_proto INTERFACE cxx_std_20)
if (MSVC)
    # warning level 4
    target_compile_options(libhpp_proto INTERFACE /W4)
else()
    # additional warnings
    target_compile_options(libhpp_proto INTERFACE -Wall -Wextra -Wpedantic)
endif()

add_library(hpp_proto::libhpp_proto ALIAS libhpp_proto)
add_executable(hpp_proto::protoc ALIAS protoc)

include(cmake/protobuf_generate.cmake)

add_subdirectory(protoc-plugin)
if (HPP_PROTO_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if (HPP_PROTO_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()

write_basic_package_version_file(
    lib/cmake/hpp_proto/hpp_proto-config-version.cmake
    COMPATIBILITY AnyNewerVersion
)

# copy google proto files into include directory
file(GLOB GOOGLE_PROTOFILES RELATIVE  "${protobuf_SOURCE_DIR}/src/google/protobuf" "${protobuf_SOURCE_DIR}/src/google/protobuf/*.proto")
list(FILTER GOOGLE_PROTOFILES EXCLUDE REGEX ".*test.*")
foreach(f ${GOOGLE_PROTOFILES})
  configure_file(${protobuf_SOURCE_DIR}/src/google/protobuf/${f} include/google/protobuf/${f} COPYONLY)
endforeach()
configure_file(${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/plugin.proto include/google/protobuf/compiler/plugin.proto COPYONLY)


install(DIRECTORY include/ TYPE INCLUDE)
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/ TYPE INCLUDE)
install(TARGETS protoc libhpp_proto EXPORT hpp_proto-targets)
install(SCRIPT "${glaze_BINARY_DIR}/cmake_install.cmake")

configure_file(hpp_proto-config.cmake.in lib/cmake/hpp_proto/hpp_proto-config.cmake COPYONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/hpp_proto/hpp_proto-config.cmake" 
              "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/hpp_proto/hpp_proto-config-version.cmake" 
              "${CMAKE_CURRENT_SOURCE_DIR}/cmake/protobuf_generate.cmake"
        DESTINATION "lib/cmake/hpp_proto")

install(EXPORT hpp_proto-targets 
        DESTINATION lib/cmake/hpp_proto
        NAMESPACE hpp_proto::)
export(EXPORT hpp_proto-targets FILE lib/cmake/hpp_proto/hpp_proto-targets.cmake 
       NAMESPACE hpp_proto::)
