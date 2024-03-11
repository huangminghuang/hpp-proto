
if(MSVC)
    add_compile_options(/bigobj /wd4459 /wd4125)
endif()


add_subdirectory(gpb_proto_json)

include(../cmake/gen_proto_descriptor_set.cmake)

gen_proto_descriptor_set(unittest_proto3.bin
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    PROTOS ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_proto3.proto)

add_library(unittest_proto3_proto_lib INTERFACE)
target_include_directories(unittest_proto3_proto_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(
    TARGET unittest_proto3_proto_lib
    LANGUAGE hpp
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    PROTOS ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_proto3.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import_public.proto)

add_executable(proto3_lite_test unittest_proto3_test.cpp)
target_link_libraries(proto3_lite_test PRIVATE unittest_proto3_proto_lib Boost::ut glaze::glaze gpb_proto_json)

add_test(NAME proto3_lite_test
    COMMAND proto3_lite_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_property(TEST proto3_lite_test PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0")

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/non_owning)

add_library(non_owning_unittest_proto3_proto_lib INTERFACE)
target_include_directories(non_owning_unittest_proto3_proto_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(
    TARGET non_owning_unittest_proto3_proto_lib
    LANGUAGE hpp
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/non_owning
    PROTOS ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_proto3.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import_public.proto
    PLUGIN_OPTIONS non_owning,root_namespace=non_owning,top_directory=non_owning)

add_executable(non_owning_proto3_test non_owning_proto3_test.cpp)
target_link_libraries(non_owning_proto3_test PRIVATE Boost::ut glaze::glaze non_owning_unittest_proto3_proto_lib gpb_proto_json)
target_include_directories(non_owning_proto3_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME non_owning_proto3_test
    COMMAND non_owning_proto3_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_property(TEST non_owning_proto3_test PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0")

add_library(non_owning_unittest_proto2_proto_lib INTERFACE)
target_include_directories(non_owning_unittest_proto2_proto_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(
    TARGET non_owning_unittest_proto2_proto_lib
    LANGUAGE hpp
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/non_owning
    PROTOS ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest.proto
    PLUGIN_OPTIONS non_owning,root_namespace=non_owning,top_directory=non_owning)

add_executable(non_owning_proto2_test non_owning_proto2_test.cpp)
target_link_libraries(non_owning_proto2_test Boost::ut glaze::glaze non_owning_unittest_proto2_proto_lib gpb_proto_json)
target_include_directories(non_owning_proto2_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
add_test(NAME non_owning_proto2_test
    COMMAND non_owning_proto2_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_property(TEST non_owning_proto2_test PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0")

gen_proto_descriptor_set(unittest_proto2.bin
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    PROTOS ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest.proto)

add_library(unittest_proto_lib INTERFACE)
target_include_directories(unittest_proto_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(
    TARGET unittest_proto_lib
    LANGUAGE hpp
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    PROTOS ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest.proto)

add_executable(proto2_lite_test unittest_proto2_test.cpp)
target_link_libraries(proto2_lite_test PRIVATE unittest_proto_lib Boost::ut glaze::glaze gpb_proto_json)

add_test(NAME proto2_lite_test
    COMMAND proto2_lite_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_property(TEST proto2_lite_test PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0")

gen_proto_descriptor_set(map_unittest.bin
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    PROTOS ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/map_unittest.proto)

add_library(map_unittest_proto_lib INTERFACE)
target_include_directories(map_unittest_proto_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(
    TARGET map_unittest_proto_lib
    LANGUAGE hpp
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    PROTOS ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/map_unittest.proto)

add_executable(map_test map_test.cpp)
target_link_libraries(map_test PRIVATE map_unittest_proto_lib Boost::ut glaze::glaze gpb_proto_json)

add_test(NAME map_test
    COMMAND map_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_property(TEST map_test PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0")

add_library(any_test_lib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/any_test.proto)
target_include_directories(any_test_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/../include)
protobuf_generate(
    TARGET any_test_lib
    LANGUAGE hpp
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${Protobuf_INCLUDE_DIRS} )

add_library(non_owning_any_test_lib INTERFACE 
    ${Protobuf_INCLUDE_DIRS}/google/protobuf/any.proto 
    ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/any_test.proto
    ${Protobuf_INCLUDE_DIRS}/google/protobuf/field_mask.proto)
target_include_directories(non_owning_any_test_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(
    TARGET non_owning_any_test_lib
    LANGUAGE hpp
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${Protobuf_INCLUDE_DIRS} 
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/non_owning
    PLUGIN_OPTIONS non_owning,root_namespace=non_owning,top_directory=non_owning)

add_executable(any_test any_test.cpp)
target_link_libraries(any_test PRIVATE Boost::ut hpp_proto::libhpp_proto glaze::glaze any_test_lib non_owning_any_test_lib)

add_test(NAME any_test
    COMMAND any_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(dynamic_serializer_tests dynamic_serializer_tests.cpp)
target_link_libraries(dynamic_serializer_tests PRIVATE unittest_proto3_proto_lib map_unittest_proto_lib Boost::ut glaze::glaze gpb_proto_json any_test_lib)

add_test(NAME dynamic_serializer_tests
    COMMAND dynamic_serializer_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_property(TEST dynamic_serializer_tests PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0")

add_executable(well_known_types_tests well_known_types_tests.cpp)
target_include_directories(well_known_types_tests PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/../include ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(well_known_types_tests PRIVATE hpp_proto::libhpp_proto Boost::ut glaze::glaze)
add_dependencies(well_known_types_tests well_known_types)
add_test(NAME well_known_types_tests
    COMMAND well_known_types_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
set_property(TEST well_known_types_tests PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0")