cmake_minimum_required(VERSION 3.14)
project(hpp_proto
  VERSION 0.1.0
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(HPP_PROTO_PROTOC_PLUGIN "Enable protoc plugin" ON)
option(HPP_PROTO_TESTS "Enable HPP_PROTO tests" ${PROJECT_IS_TOP_LEVEL})
option(HPP_PROTO_BENCHMARKS "Enable buidling benchmarks" OFF)
option(HPP_PROTO_ENABLE_CLANG_TIDY "Enable clang tidy" OFF)
option(HPP_PROTO_COMPILE_PROTOC "Alwyas compile protoc from source" OFF)

include(cmake/CPM.cmake)

if(APPLE)
  set(CMAKE_CXX_VISIBILITY_PRESET "hidden")
  set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

CPMAddPackage(
  NAME glaze
  GIT_TAG v2.9.5.mod
  GITHUB_REPOSITORY huangminghuang/glaze
)

CPMAddPackage(
  NAME is_utf8
  VERSION 1.3.2
  GITHUB_REPOSITORY simdutf/is_utf8
  DOWNLOAD_ONLY ON
)

add_subdirectory(${is_utf8_SOURCE_DIR}/src ${is_utf8_BINARY_DIR})

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  file(REAL_PATH ${CMAKE_CXX_COMPILER} CLANG_REAL_PATH)
  cmake_path(GET CLANG_REAL_PATH PARENT_PATH CLANG_DIR)
endif()

if(HPP_PROTO_ENABLE_CLANG_TIDY)
  if(EXISTS "${CLANG_DIR}/clang-tidy")
    set(CLANG_TIDY_EXE "${CLANG_DIR}/clang-tidy")
  else()
    find_program(CLANG_TIDY_EXE NAME clang-tidy)
  endif()

  if(CLANG_TIDY_EXE)
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
target_link_libraries(libhpp_proto INTERFACE is_utf8)

add_library(libhpp_proto_no_utf8_validation INTERFACE)
target_include_directories(libhpp_proto_no_utf8_validation INTERFACE
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${glaze_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(libhpp_proto_no_utf8_validation INTERFACE cxx_std_20)
target_compile_definitions(libhpp_proto_no_utf8_validation INTERFACE HPP_PROTO_NO_UTF8_VALIDATION)



add_library(hpp_proto::libhpp_proto ALIAS libhpp_proto)

if(HPP_PROTO_TESTS)
  CPMAddPackage(
    NAME ut
    GITHUB_REPOSITORY boost-ext/ut
    VERSION 2.0.1
    DOWNLOAD_ONLY ON
  )
  add_library(Boost::ut INTERFACE IMPORTED)
  target_include_directories(Boost::ut INTERFACE ${ut_SOURCE_DIR}/include)
  target_compile_definitions(Boost::ut INTERFACE BOOST_UT_DISABLE_MODULE)

  enable_testing()
  add_subdirectory(unittests)
  include(CTest)
endif()

if(HPP_PROTO_PROTOC_PLUGIN)
  if (NOT HPP_PROTO_COMPILE_PROTOC)
    find_package(Protobuf)
  endif()

  if(NOT Protobuf_FOUND)
    CPMAddPackage(
      NAME protobuf
      VERSION 27.0
      GITHUB_REPOSITORY protocolbuffers/protobuf
      OPTIONS "ABSL_PROPAGATE_CXX_STD ON"
      "protobuf_INSTALL OFF"
      "protobuf_BUILD_TESTS OFF"
      "protobuf_BUILD_PROTOBUF_BINARIES ON"
      "protobuf_BUILD_PROTOC_BINARIES ON"
      "EXCLUDE_FROM_ALL"
    )
    add_executable(protobuf::protoc ALIAS protoc)
    add_library(protobuf::libprotobuf ALIAS libprotobuf)
    add_library(protobuf::libprotoc ALIAS libprotoc)
    set(Protobuf_INCLUDE_DIRS ${protobuf_SOURCE_DIR}/src)  
  endif(NOT Protobuf_FOUND)

  if(HPP_PROTO_BENCHMARKS)
    CPMAddPackage(
      NAME benchmark
      GITHUB_REPOSITORY google/benchmark
      VERSION 1.8.3
      OPTIONS
      "BENCHMARK_ENABLE_TESTING OFF"
      "BENCHMARK_ENABLE_INSTALL OFF"
    )
  endif(HPP_PROTO_BENCHMARKS)

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

  if(NOT Protobuf_FOUND)
    # copy google proto files into include directory
    file(GLOB GOOGLE_PROTOFILES RELATIVE "${protobuf_SOURCE_DIR}/src/google/protobuf" "${protobuf_SOURCE_DIR}/src/google/protobuf/*.proto")
    list(FILTER GOOGLE_PROTOFILES EXCLUDE REGEX ".*test.*")

    foreach(f ${GOOGLE_PROTOFILES})
      configure_file(${protobuf_SOURCE_DIR}/src/google/protobuf/${f} include/google/protobuf/${f} COPYONLY)
    endforeach()

    configure_file(${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/plugin.proto include/google/protobuf/compiler/plugin.proto COPYONLY)
    install(TARGETS protoc libhpp_proto EXPORT hpp_proto-targets)
  endif(NOT Protobuf_FOUND)

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
