add_compile_options(${HPP_PROTO_COMPILE_OPTIONS})

if(MSVC)
    add_compile_options("/bigobj" "/wd4459" "/wd4125")
endif()

set(Min_Protobuf_VERSION 3.12.0)

if("${Protobuf_VERSION}" VERSION_LESS "${Min_Protobuf_VERSION}")
    message(WARNING "The programs in tests directory requires protobuf version ${Min_Protobuf_VERSION} or greater.")
else()
    if("${Protobuf_VERSION}" VERSION_LESS "3.15.0")
        set(PROTOC3_OPTIONAL_OPTION --experimental_allow_proto3_optional)
    endif()

    if(HPP_PROTO_TEST_USE_PROTOBUF)
        if((TARGET protobuf::libprotoc) AND("${Protobuf_VERSION}" VERSION_GREATER_EQUAL "22.0"))
            set(use_libprotobuf ON)
        else()
            message(WARNING "libprotobuf 22.0 and above is required to generate test data")
        endif()
    endif()

    set(edition_support OFF)

    if(("${Protobuf_VERSION}" VERSION_GREATER_EQUAL "28.0"))
        set(edition_support ON)
    endif()

    add_subdirectory(gpb_proto_json)

    set(unittest_desc_pb_sources google/protobuf/unittest.proto
        google/protobuf/unittest_proto3.proto
        google/protobuf/map_unittest.proto)

    if(edition_support)
        list(APPEND unittest_desc_pb_sources google/protobuf/unittest_lite.proto)
    endif()

    add_custom_command(
        COMMENT "Generating unittest.desc.binpb"
        OUTPUT unittest.desc.binpb
        COMMAND protobuf::protoc
        ARGS -I "${CMAKE_CURRENT_SOURCE_DIR}" ${PROTOC3_OPTIONAL_OPTION} --include_imports --descriptor_set_out=unittest.desc.binpb
        ${unittest_desc_pb_sources}
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    )

    add_subdirectory(data)

    add_custom_target(unittest.desc.binpb.target ALL
        DEPENDS unittest.desc.binpb)

    add_library(unittest_proto3_proto_lib INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_proto3.proto"
        "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import.proto"
        "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import_public.proto")
    target_include_directories(unittest_proto3_proto_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
    protobuf_generate_hpp(
        TARGET unittest_proto3_proto_lib
        IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
        PROTOC_OPTIONS ${PROTOC3_OPTIONAL_OPTION})

    add_executable(proto3_test unittest_proto3_test.cpp)
    target_link_libraries(proto3_test PRIVATE unittest_proto3_proto_lib Boost::ut glaze::glaze gpb_proto_json)

    add_test(NAME proto3_test
        COMMAND proto3_test
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})


    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/non_owning")

    add_library(non_owning_unittest_proto3_proto_lib INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_proto3.proto"
        "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import.proto"
        "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import_public.proto")

    target_include_directories(non_owning_unittest_proto3_proto_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
    protobuf_generate_hpp(
        TARGET non_owning_unittest_proto3_proto_lib
        IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
        PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/non_owning"
        PROTOC_OPTIONS ${PROTOC3_OPTIONAL_OPTION}
        PLUGIN_OPTIONS "non_owning,namespace_prefix=non_owning,directory_prefix=non_owning")

    add_executable(non_owning_proto3_test non_owning_proto3_test.cpp)
    target_link_libraries(non_owning_proto3_test PRIVATE Boost::ut glaze::glaze non_owning_unittest_proto3_proto_lib gpb_proto_json)
    target_include_directories(non_owning_proto3_test SYSTEM PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

    add_test(NAME non_owning_proto3_test
        COMMAND non_owning_proto3_test
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    add_library(non_owning_unittest_proto2_proto_lib INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest.proto")
    target_include_directories(non_owning_unittest_proto2_proto_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
    protobuf_generate_hpp(
        TARGET non_owning_unittest_proto2_proto_lib
        IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
        PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/non_owning"
        PLUGIN_OPTIONS "non_owning,namespace_prefix=non_owning,directory_prefix=non_owning")

    add_executable(non_owning_proto2_test non_owning_proto2_test.cpp)
    target_link_libraries(non_owning_proto2_test Boost::ut glaze::glaze non_owning_unittest_proto2_proto_lib gpb_proto_json)
    add_test(NAME non_owning_proto2_test
        COMMAND non_owning_proto2_test
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

    add_library(unittest_proto_lib INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest.proto")
    target_include_directories(unittest_proto_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
    protobuf_generate_hpp(
        TARGET unittest_proto_lib
        IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}")

    add_executable(proto2_test unittest_proto2_test.cpp)
    target_link_libraries(proto2_test PRIVATE unittest_proto_lib Boost::ut glaze::glaze gpb_proto_json)

    add_test(NAME proto2_test
        COMMAND proto2_test
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    add_library(map_unittest_proto_lib INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/map_unittest.proto")
    target_include_directories(map_unittest_proto_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
    protobuf_generate_hpp(
        TARGET map_unittest_proto_lib
        IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(map_unittest_proto_lib INTERFACE unittest_proto_lib)

    add_executable(map_test map_test.cpp)
    target_link_libraries(map_test PRIVATE map_unittest_proto_lib Boost::ut glaze::glaze gpb_proto_json)

    add_test(NAME map_test
        COMMAND map_test
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    add_library(non_owning_map_unittest_proto_lib INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/map_unittest.proto")
    target_include_directories(non_owning_map_unittest_proto_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
    protobuf_generate_hpp(
        TARGET non_owning_map_unittest_proto_lib
        IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
        PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/non_owning"
        PLUGIN_OPTIONS "non_owning,namespace_prefix=non_owning,directory_prefix=non_owning")

    if(Protobuf_INCLUDE_DIRS)
        add_library(any_test_lib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/any_test.proto)
        target_include_directories(any_test_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/../include)
        protobuf_generate_hpp(
            TARGET any_test_lib
            IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}")
        target_link_libraries(any_test_lib INTERFACE well_known_types)

        add_library(non_owning_any_lib INTERFACE
            "${Protobuf_INCLUDE_DIRS}/google/protobuf/any.proto"
            "${Protobuf_INCLUDE_DIRS}/google/protobuf/field_mask.proto")

        target_include_directories(non_owning_any_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
        protobuf_generate_hpp(
            TARGET non_owning_any_lib
            IMPORT_DIRS "${Protobuf_INCLUDE_DIRS}"
            PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/non_owning"
            PLUGIN_OPTIONS "non_owning,namespace_prefix=non_owning,directory_prefix=non_owning")

        add_library(non_owning_any_test_lib INTERFACE
            "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/any_test.proto")

        target_include_directories(non_owning_any_test_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
        protobuf_generate_hpp(
            TARGET non_owning_any_test_lib
            IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
            PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/non_owning"
            PLUGIN_OPTIONS "non_owning,namespace_prefix=non_owning,directory_prefix=non_owning")

        target_link_libraries(non_owning_any_test_lib INTERFACE non_owning_any_lib well_known_types)

        add_executable(any_test any_test.cpp)
        target_link_libraries(any_test PRIVATE Boost::ut hpp_proto::libhpp_proto glaze::glaze any_test_lib non_owning_any_test_lib)

        add_test(NAME any_test
            COMMAND any_test
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

        add_executable(dynamic_serializer_tests dynamic_serializer_tests.cpp)

        if(edition_support)
            target_compile_definitions(dynamic_serializer_tests PRIVATE EDITION_SUPPORT)
        endif()

        target_link_libraries(dynamic_serializer_tests PRIVATE unittest_proto3_proto_lib map_unittest_proto_lib Boost::ut glaze::glaze gpb_proto_json any_test_lib)

        add_test(NAME dynamic_serializer_tests
            COMMAND dynamic_serializer_tests
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

        add_executable(dynamic_serializer_coverage_tests dynamic_serializer_coverage_tests.cpp)
        target_link_libraries(dynamic_serializer_coverage_tests PRIVATE hpp_proto::libhpp_proto Boost::ut glaze::glaze unittest_proto3_proto_lib)
        add_hpp_proto_test(dynamic_serializer_coverage_tests)

        add_executable(well_known_types_tests well_known_types_tests.cpp)
        target_include_directories(well_known_types_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
        target_link_libraries(well_known_types_tests PRIVATE well_known_types hpp_proto::libhpp_proto Boost::ut glaze::glaze)
        add_dependencies(well_known_types_tests well_known_types)
        add_test(NAME well_known_types_tests
            COMMAND well_known_types_tests
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    else()
        message(WARNING "No proto file for well known types are found, all tests involves well known types are skipped.")
    endif(Protobuf_INCLUDE_DIRS)

    add_executable(proto3_decode proto3_decode.cpp)
    target_link_libraries(proto3_decode PRIVATE unittest_proto3_proto_lib)

    add_library(hpp_options_test_lib INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/hpp_options_test.proto")
    protobuf_generate_hpp(
            TARGET hpp_options_test_lib
            IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/../include"
            PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
    target_include_directories(hpp_options_test_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})

    add_executable(hpp_options_test hpp_options_test.cpp)
    target_link_libraries(hpp_options_test PRIVATE hpp_options_test_lib)

    if(edition_support)
        add_library(unittest_lite_proto_lib INTERFACE
            "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_lite.proto"
            "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import_lite.proto"
            "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import_public_lite.proto")
        target_include_directories(unittest_lite_proto_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
        protobuf_generate_hpp(
            TARGET unittest_lite_proto_lib
            IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
            PROTOC_OPTIONS ${PROTOC3_OPTIONAL_OPTION})

        add_executable(lite_test unittest_lite_test.cpp)
        target_link_libraries(lite_test PRIVATE unittest_lite_proto_lib Boost::ut glaze::glaze gpb_proto_json)

        add_test(NAME lite_test
            COMMAND lite_test
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

        add_library(editions_test_lib INTERFACE "basic_test_editions.proto" "editions_test.proto")
        target_include_directories(editions_test_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
        protobuf_generate_hpp(
            TARGET editions_test_lib
            IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}")

        add_executable(editions_test basic_test_editions_test.cpp)
        target_link_libraries(editions_test PRIVATE editions_test_lib)

        add_library(basic_test_proto2_lib INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/basic_test_proto2.proto")
        target_include_directories(basic_test_proto2_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
        protobuf_generate_hpp(
            TARGET basic_test_proto2_lib
            IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
            PLUGIN_OPTIONS "proto2_explicit_presence=.TestMessage.explicit_field,numeric_keyed_map=std.map,string_keyed_map=std.unordered_map")

        add_executable(basic_test_proto2 basic_test_proto2.cpp)
        target_link_libraries(basic_test_proto2 PRIVATE basic_test_proto2_lib)

        add_test(NAME editions_test
            COMMAND editions_test
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    endif()
endif()
