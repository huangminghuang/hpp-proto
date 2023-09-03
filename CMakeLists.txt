cmake_minimum_required(VERSION 3.14)
project(hpp_proto 
        VERSION 0.1.0
        LANGUAGES CXX)

include(cmake/CPM.cmake)

if (APPLE)
    set(CMAKE_CXX_VISIBILITY_PRESET "hidden")
    set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
endif()

CPMAddPackage(gh:eyalz800/zpp_bits@4.4.13)
CPMAddPackage("gh:huangminghuang/glaze#develop")
set(EXPECTED_BUILD_TESTS OFF)
CPMAddPackage(gh:TartanLlama/expected@1.1.0)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED On)
CPMAddPackage(
  NAME protobuf
  VERSION 24.2
  GITHUB_REPOSITORY protocolbuffers/protobuf
  OPTIONS "ABSL_PROPAGATE_CXX_STD ON"
          "protobuf_INSTALL OFF"
          "protobuf_BUILD_TESTS OFF"
          "protobuf_BUILD_PROTOBUF_BINARIES ON"
          "protobuf_BUILD_PROTOC_BINARIES ON"
          "EXCLUDE_FROM_ALL"
)

option(HPP_PROTO_TESTS "Enable HPP_PROTO tests" ON)

add_library(hpp_proto_libhpp_proto INTERFACE)
target_include_directories(hpp_proto_libhpp_proto INTERFACE 
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${zpp_bits_SOURCE_DIR}>
  $<BUILD_INTERFACE:${expected_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(hpp_proto_libhpp_proto INTERFACE cxx_std_20)

add_library(hpp_proto::libhpp_proto ALIAS hpp_proto_libhpp_proto)

add_subdirectory(protoc-plugin)
if (HPP_PROTO_TESTS)
  enable_testing()
  add_subdirectory(tests)
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
install(DIRECTORY ${expected_SOURCE_DIR}/include/ TYPE INCLUDE)
install(FILES ${zpp_bits_SOURCE_DIR}/zpp_bits.h TYPE INCLUDE)
install(TARGETS protoc hpp_proto_libhpp_proto EXPORT hpp_proto-targets)
install(SCRIPT "${glaze_BINARY_DIR}/cmake_install.cmake")

configure_file(hpp_proto-config.cmake.in lib/cmake/hpp_proto/hpp_proto-config.cmake COPYONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/hpp_proto/hpp_proto-config.cmake" 
              "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/hpp_proto/hpp_proto-config-version.cmake" 
              "${CMAKE_CURRENT_CURRENT_DIR}/cmake/add_hpp_proto_lib.cmake"
        DESTINATION "lib/cmake/hpp_proto")

install(EXPORT hpp_proto-targets 
        DESTINATION lib/cmake/hpp_proto)
export(EXPORT hpp_proto-targets FILE lib/cmake/hpp_proto/hpp_proto-targets.cmake)
