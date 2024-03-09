set(proto_files benchmark_messages_proto3.proto benchmark_messages_proto2.proto)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/owning)
add_library(hpp_owning_benchmark_messages_lib INTERFACE ${proto_files})
protobuf_generate(TARGET hpp_owning_benchmark_messages_lib
    LANGUAGE hpp
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/owning
    PLUGIN_OPTIONS "root_namespace=owning")

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/non_owning)
add_library(hpp_non_owning_benchmark_messages_lib INTERFACE ${proto_files})
protobuf_generate(TARGET hpp_non_owning_benchmark_messages_lib
    LANGUAGE hpp
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/non_owning
    PLUGIN_OPTIONS "non_owning,root_namespace=non_owning")

add_library(google_benchmark_messages_lib OBJECT ${proto_files})
protobuf_generate(TARGET google_benchmark_messages_lib
    LANGUAGE cpp)

add_executable(proto_bench benchmark.cpp)
target_include_directories(proto_bench PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(proto_bench 
    hpp_owning_benchmark_messages_lib
    hpp_non_owning_benchmark_messages_lib 
    google_benchmark_messages_lib
    benchmark::benchmark_main)
