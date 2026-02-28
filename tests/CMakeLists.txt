add_compile_options(${HPP_PROTO_COMPILE_OPTIONS})

if(MSVC)
    add_compile_options("/bigobj" "/wd4459" "/wd4125")
endif()

set(Min_Protobuf_VERSION 3.12.0)

if("${Protobuf_VERSION}" VERSION_LESS "${Min_Protobuf_VERSION}")
    message(WARNING "The programs in tests directory requires protobuf version ${Min_Protobuf_VERSION} or greater.")
    return()
endif()

include(test_descriptors.cmake)

if(NOT HPP_PROTO_TESTS)
    return()
endif()

add_subdirectory(gpb_proto_json)
add_subdirectory(data)
add_subdirectory(grpc)

add_hpp_proto_test(
    NAME proto3_test
    SOURCES unittest_proto3_test.cpp
    LINK_LIBRARIES unittest_proto3_proto_lib Boost::ut glaze::glaze gpb_proto_json)

add_hpp_proto_test(
    NAME proto2_test
    SOURCES unittest_proto2_test.cpp
    LINK_LIBRARIES unittest_proto_lib Boost::ut glaze::glaze gpb_proto_json)

add_hpp_proto_test(
    NAME map_test
    SOURCES map_test.cpp
    LINK_LIBRARIES map_unittest_proto_lib Boost::ut glaze::glaze gpb_proto_json)

add_hpp_proto_test(
    NAME unittest_well_known_types_test
    SOURCES unittest_well_known_types_test.cpp
    LINK_LIBRARIES hpp_proto::dynamic_message well_known_types unittest_well_known_types_proto_lib Boost::ut glaze::glaze gpb_proto_json)

add_hpp_proto_generated_test_lib(
    NAME any_test_lib
    SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/any_test.proto"
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
    LINK_LIBRARIES well_known_types
    REQUIRES Protobuf_INCLUDE_DIRS)

add_hpp_proto_test(
    NAME any_test
    SOURCES any_test.cpp
    LINK_LIBRARIES Boost::ut hpp_proto::hpp_proto_core hpp_proto::dynamic_message glaze::glaze any_test_lib
    REQUIRES Protobuf_INCLUDE_DIRS)

add_hpp_proto_test(
    NAME well_known_types_tests
    SOURCES well_known_types_tests.cpp
    LINK_LIBRARIES hpp_proto::dynamic_message well_known_types Boost::ut glaze::glaze
    DEPENDENCIES well_known_types
    REQUIRES Protobuf_INCLUDE_DIRS)

add_hpp_proto_test(
    NAME dynamic_message_test
    SOURCES dynamic_message_test.cpp dynamic_message_factory_test.cpp
    LINK_LIBRARIES hpp_proto::dynamic_message unittest_proto3_proto_lib map_unittest_proto_lib Boost::ut glaze::glaze gpb_proto_json any_test_lib
    REQUIRES Protobuf_INCLUDE_DIRS)

add_hpp_proto_generated_test_lib(
    NAME hpp_options_test_lib
    SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/hpp_options_test.proto"
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")

add_hpp_proto_test(
    NAME hpp_options_test
    SOURCES hpp_options_test.cpp
    LINK_LIBRARIES hpp_options_test_lib)

add_hpp_proto_test(
    NAME read_json_consistency_test
    SOURCES read_json_consistency_test.cpp
    LINK_LIBRARIES hpp_proto::dynamic_message unittest_proto_lib unittest_proto3_proto_lib map_unittest_proto_lib well_known_types Boost::ut glaze::glaze)

add_hpp_proto_generated_test_lib(
    NAME unittest_lite_proto_lib
    SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_lite.proto"
        "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import_lite.proto"
        "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import_public_lite.proto"
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
    PROTOC_OPTIONS ${PROTOC3_OPTIONAL_OPTION}
    REQUIRES edition_support)

add_hpp_proto_test(
    NAME lite_test
    SOURCES unittest_lite_test.cpp
    LINK_LIBRARIES unittest_lite_proto_lib Boost::ut glaze::glaze gpb_proto_json
    REQUIRES edition_support)

add_hpp_proto_generated_test_lib(
    NAME editions_test_lib
    SOURCES "basic_test_editions.proto" "editions_test.proto"
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
    REQUIRES edition_support)

add_hpp_proto_test(
    NAME editions_test
    SOURCES basic_test_editions_test.cpp
    LINK_LIBRARIES editions_test_lib
    REQUIRES edition_support)

add_hpp_proto_generated_test_lib(
    NAME basic_test_proto2_lib
    SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/basic_test_proto2.proto"
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
    PLUGIN_OPTIONS "proto2_explicit_presence=.TestMessage.explicit_field,namespace_prefix=test"
    REQUIRES edition_support)

add_hpp_proto_test(
    NAME basic_test_proto2
    SOURCES basic_test_proto2.cpp
    LINK_LIBRARIES basic_test_proto2_lib
    REQUIRES edition_support)
