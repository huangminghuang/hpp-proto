
if(NOT HPP_PROTO_BENCHMARKS)
    return()
endif()

set(proto_files benchmark_messages_proto3.proto benchmark_messages_proto2.proto packed_repeated_message.proto)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
add_library(hpp_benchmark_messages_lib INTERFACE ${proto_files})
protobuf_generate_hpp(TARGET hpp_benchmark_messages_lib
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/hpp
    PLUGIN_OPTIONS "namespace_prefix=hpp")

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
    hpp_benchmark_messages_lib
    google_benchmark_messages_lib
    benchmark::benchmark_main)

add_executable(hpp_proto_decode_encode hpp_proto_decode_encode.cpp)
target_include_directories(hpp_proto_decode_encode PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(hpp_proto_decode_encode hpp_benchmark_messages_lib)

add_executable(google_decode_encode google_decode_encode.cpp)
target_link_libraries(google_decode_encode google_benchmark_messages_lib)
target_include_directories(google_decode_encode PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

add_executable(google_decode_encode_lite google_decode_encode_lite.cpp)
target_link_libraries(google_decode_encode_lite google_benchmark_messages_lite_lib)
target_include_directories(google_decode_encode_lite PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    set(SYSTEM_NAME "Mac")
else()
    set(SYSTEM_NAME ${CMAKE_SYSTEM_NAME})
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_bench.result
    COMMAND proto_bench > ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_bench.result
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS proto_bench
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_bench.json
    ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_bench.png
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/process_proto_bench_output.py --platform ${SYSTEM_NAME} --json --chart ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_bench.result
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_bench.result process_proto_bench_output.py
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_sizes.json
    ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_sizes.png
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/gen_sizes.py --platform ${SYSTEM_NAME} ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS gen_sizes.py hpp_proto_decode_encode google_decode_encode google_decode_encode_lite
)

add_custom_target(benchmarks
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_bench.json
    ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_bench.png
    ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_sizes.json
    ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_sizes.png)

add_custom_target(clean_benchmarks
    COMMAND ${CMAKE_COMMAND} -E remove
    ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_bench.result
    ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_bench.json
    ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_bench.png
    ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_sizes.json
    ${CMAKE_CURRENT_SOURCE_DIR}/${SYSTEM_NAME}_sizes.png
    COMMENT "Cleaning generated benchmark files"
)