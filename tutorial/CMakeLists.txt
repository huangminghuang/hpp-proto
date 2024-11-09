cmake_minimum_required(VERSION 3.24)

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
    get_target_property(PROTOC_LCOATION protobuf::protoc IMPORTED_LOCATION)
    get_filename_component(PROTOC_BASE_DIR ${PROTOC_LCOATION} DIRECTORY)
    get_filename_component(Protobuf_INCLUDE_DIRS "${PROTOC_BASE_DIR}/../include" ABSOLUTE)

  else()
    find_package(hpp_proto CONFIG REQUIRED)
  endif()
endif()

add_subdirectory(regular)
add_subdirectory(non_owning)
add_subdirectory(mixed_ownership)
add_subdirectory(compile_time_serialization)
add_subdirectory(dynamic_serializer)