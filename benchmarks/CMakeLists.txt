

set(proto_files benchmark_messages_proto3.proto benchmark_messages_proto2.proto packed_repeated_message.proto)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/owning)
add_library(hpp_owning_benchmark_messages_lib INTERFACE ${proto_files})
protobuf_generate_hpp(TARGET hpp_owning_benchmark_messages_lib
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/owning
    PLUGIN_OPTIONS "root_namespace=owning")

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/non_owning)
add_library(hpp_non_owning_benchmark_messages_lib INTERFACE ${proto_files})
protobuf_generate_hpp(TARGET hpp_non_owning_benchmark_messages_lib
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/non_owning
    PLUGIN_OPTIONS "non_owning,root_namespace=non_owning")

add_library(google_benchmark_messages_lib OBJECT ${proto_files})
protobuf_generate(TARGET google_benchmark_messages_lib
    LANGUAGE cpp)
target_link_libraries(google_benchmark_messages_lib PUBLIC protobuf::libprotobuf)

add_library(google_benchmark_messages_lite_lib OBJECT benchmark_messages_proto3_lite.proto)
protobuf_generate(TARGET google_benchmark_messages_lite_lib
    LANGUAGE cpp)
target_link_libraries(google_benchmark_messages_lite_lib PUBLIC protobuf::libprotobuf-lite)

add_executable(proto_bench benchmark.cpp)

target_include_directories(proto_bench PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(proto_bench
    hpp_owning_benchmark_messages_lib
    hpp_non_owning_benchmark_messages_lib
    google_benchmark_messages_lib
    benchmark::benchmark_main)

add_executable(hpp_proto_decode_encode hpp_proto_decode_encode.cpp)
target_include_directories(hpp_proto_decode_encode PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(hpp_proto_decode_encode hpp_owning_benchmark_messages_lib)

add_executable(google_decode_encode google_decode_encode.cpp)
target_link_libraries(google_decode_encode google_benchmark_messages_lib)
target_include_directories(google_decode_encode PUBLIC ${CMAKE_CURRENT_BINARY_DIR})


add_executable(google_decode_encode_lite google_decode_encode_lite.cpp)
target_link_libraries(google_decode_encode_lite google_benchmark_messages_lite_lib)
target_include_directories(google_decode_encode_lite PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
