
set(proto_files ../benchmark_messages_proto3.proto ../benchmark_messages_proto2.proto)

add_library(benchmark_messages_proto_lib INTERFACE ${proto_files})
target_include_directories(benchmark_messages_proto_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET benchmark_messages_proto_lib
                  LANGUAGE hpp
                  IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/..)

add_library(non_owning_benchmark_messages_proto_lib INTERFACE ${proto_files})
target_include_directories(non_owning_benchmark_messages_proto_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/non_owning)
protobuf_generate(TARGET non_owning_benchmark_messages_proto_lib
                  LANGUAGE hpp
                  PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/non_owning
                  IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/..
                  PLUGIN_OPTIONS "non_owning")


get_filename_component(DATA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
add_executable(proto2_msg1_bench hpp_benchmark.cpp)
target_compile_definitions(proto2_msg1_bench PRIVATE PROTO2 DATA_DIR=${DATA_DIR})
target_link_libraries(proto2_msg1_bench PRIVATE benchmark_messages_proto_lib)
target_include_directories(proto2_msg1_bench PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/..)


add_executable(proto3_msg1_bench hpp_benchmark.cpp)
target_compile_definitions(proto3_msg1_bench PRIVATE PROTO3 DATA_DIR=${DATA_DIR})
target_link_libraries(proto3_msg1_bench PRIVATE benchmark_messages_proto_lib)
target_include_directories(proto3_msg1_bench PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/..)

add_executable(proto3_msg1_non_owing_bench hpp_benchmark.cpp)
target_compile_definitions(proto3_msg1_non_owing_bench PRIVATE PROTO3 DATA_DIR=${DATA_DIR} NON_OWNING)
target_link_libraries(proto3_msg1_non_owing_bench PRIVATE non_owning_benchmark_messages_proto_lib)
target_include_directories(proto3_msg1_non_owing_bench PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/..)