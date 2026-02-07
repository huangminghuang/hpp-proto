cmake_minimum_required(VERSION 3.25)

project(hpp_proto_tutorial
  VERSION 1.0.0
  LANGUAGES CXX)

if(PROJECT_IS_TOP_LEVEL)
  set(HPP_PROTO_GIT_TAG "" CACHE STRING "Use find_package(hpp-proto) if empty; otherwise the hpp-proto git tag for fetch_content")
  if(HPP_PROTO_GIT_TAG)
    include(FetchContent)

    FetchContent_Declare(
      hpp_proto
      GIT_REPOSITORY https://github.com/huangminghuang/hpp-proto.git
      GIT_TAG ${HPP_PROTO_GIT_TAG}
      GIT_SHALLOW TRUE
    )

    FetchContent_MakeAvailable(hpp_proto)

    ## Due to the variable scope issue, the following is the most reliable way to get Protobuf_INCLUDE_DIRS properly set
    ## when using FetchContent to declare hpp-proto as dependency.  
    get_target_property(PROTOC_LOCATION hpp_proto::protoc IMPORTED_LOCATION)
    get_filename_component(PROTOC_BASE_DIR ${PROTOC_LOCATION} DIRECTORY)
    get_filename_component(Protobuf_INCLUDE_DIRS "${PROTOC_BASE_DIR}/../include" ABSOLUTE)

  else()
    find_package(hpp_proto CONFIG REQUIRED)
  endif()
  include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/grpc_check.cmake)
elseif(NOT HPP_PROTO_TESTS)
  return()
else()
  set(WELLKNOWN_TARGET hpp_proto::well_known_types)
endif()

add_library(addressbook_proto3 INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/addressbook_proto3.proto)
target_include_directories(addressbook_proto3 SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(
    TARGET addressbook_proto3
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
)

add_library(addressbook_proto2 INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/addressbook_proto2.proto)
target_include_directories(addressbook_proto2 SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(
    TARGET addressbook_proto2
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR} # # required when the proto file is not in ${CMAKE_CURRENT_SOURCE_DIR}
)

add_library(any_demo INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/any_demo.proto)
target_include_directories(any_demo INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(any_demo INTERFACE ${WELLKNOWN_TARGET})
protobuf_generate_hpp(
    TARGET any_demo
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(regular)
add_subdirectory(non_owning)
add_subdirectory(dynamic_message)
add_subdirectory(compile_time_serialization)
add_subdirectory(pmr)

if (NOT HPP_PROTO_PROTOC STREQUAL "compile")
  add_subdirectory(grpc)
endif()
