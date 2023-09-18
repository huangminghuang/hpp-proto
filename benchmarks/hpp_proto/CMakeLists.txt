

add_hpp_proto_lib(benchmark_messages_proto_lib
    INPUT_DIR   ${CMAKE_CURRENT_SOURCE_DIR}/..
    PROTO_FILES benchmark_messages_proto3.proto benchmark_messages_proto2.proto)


add_hpp_proto_lib(non_owning_benchmark_messages_proto_lib
    INPUT_DIR    INPUT_DIR   ${CMAKE_CURRENT_SOURCE_DIR}/..
    OUTPUT_DIR   ${CMAKE_CURRENT_BINARY_DIR}/non_owning
    PROTO_FILES  benchmark_messages_proto3.proto benchmark_messages_proto2.proto
    ENVIRONMENTS "HPP_NON_OWNING=ON")

get_filename_component(DATA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
add_executable(proto2_msg1_bench hpp_benchmark.cpp)
target_compile_definitions(proto2_msg1_bench PRIVATE PROTO2 DATA_DIR=${DATA_DIR})
target_link_libraries(proto2_msg1_bench PRIVATE benchmark_messages_proto_lib)

add_executable(proto3_msg1_bench hpp_benchmark.cpp)
target_compile_definitions(proto3_msg1_bench PRIVATE PROTO3 DATA_DIR=${DATA_DIR})
target_link_libraries(proto3_msg1_bench PRIVATE benchmark_messages_proto_lib)
