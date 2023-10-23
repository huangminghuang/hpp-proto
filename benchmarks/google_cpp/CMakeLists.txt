

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../../clang-tidy-disable-all-checks .clang-tidy)

set(proto_files ../benchmark_messages_proto3.proto ../benchmark_messages_proto2.proto)
add_library(benchmark_messages_google_lib OBJECT ${proto_files})
target_include_directories(benchmark_messages_google_lib PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET benchmark_messages_google_lib
                  LANGUAGE cpp
                  IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/..)

get_filename_component(DATA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)

if (NOT HPP_ENABLE_CLANG_TIDY)
    add_executable(google_cpp_proto2_msg1_bench google_cpp_benchmark.cpp)
    target_compile_definitions(google_cpp_proto2_msg1_bench PRIVATE PROTO2)
    target_link_libraries(google_cpp_proto2_msg1_bench benchmark_messages_google_lib)
    target_include_directories(google_cpp_proto2_msg1_bench PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/..)

    add_executable(google_cpp_proto3_msg1_bench google_cpp_benchmark.cpp)
    target_compile_definitions(google_cpp_proto3_msg1_bench PRIVATE PROTO3)
    target_link_libraries(google_cpp_proto3_msg1_bench benchmark_messages_google_lib)
    target_include_directories(google_cpp_proto3_msg1_bench PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/..)
endif()

