
add_executable(fuzz_unittest_TestAllTypes fuzz_unittest_TestAllTypes.cpp)
target_link_libraries(fuzz_unittest_TestAllTypes PRIVATE unittest_proto_lib)
target_compile_options(fuzz_unittest_TestAllTypes PRIVATE -fsanitize=fuzzer,address,undefined)
target_link_options(fuzz_unittest_TestAllTypes PRIVATE -fsanitize=fuzzer,address,undefined)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../tests/data/protobuf_unittest.TestAllTypes.binpb 
               ${CMAKE_CURRENT_BINARY_DIR}/fuzz_unittest_TestAllTypes_corpus/protobuf_unittest.TestAllTypes.binpb COPYONLY)

add_executable(fuzz_unittest_TestMap fuzz_unittest_TestMap.cpp)
target_link_libraries(fuzz_unittest_TestMap PRIVATE unittest_proto_lib)
target_compile_options(fuzz_unittest_TestMap PRIVATE -fsanitize=fuzzer,address,undefined)
target_link_options(fuzz_unittest_TestMap PRIVATE -fsanitize=fuzzer,address,undefined)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../tests/data/protobuf_unittest.TestMap.binpb 
                ${CMAKE_CURRENT_BINARY_DIR}/fuzz_unittest_TestMap_corpus/protobuf_unittest.TestMap.binpb COPYONLY)
              
add_executable(fuzz_proto3_unittest_TestAllTypes fuzz_proto3_unittest_TestAllTypes.cpp)
target_link_libraries(fuzz_proto3_unittest_TestAllTypes PRIVATE unittest_proto3_proto_lib)
target_compile_options(fuzz_proto3_unittest_TestAllTypes PRIVATE -fsanitize=fuzzer,address,undefined)
target_link_options(fuzz_proto3_unittest_TestAllTypes PRIVATE -fsanitize=fuzzer,address,undefined)
                
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../tests/data/proto3_unittest.TestAllTypes.binpb 
               ${CMAKE_CURRENT_BINARY_DIR}/fuzz_proto3_unittest_TestAllTypes_corpus/proto3_unittest.TestAllTypes.binpb COPYONLY)

add_executable(fuzz_case fuzz_case.cpp)
target_link_libraries(fuzz_case PRIVATE unittest_proto_lib)

