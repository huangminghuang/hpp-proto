if("${Protobuf_VERSION}" VERSION_LESS "3.15.0")
    set(PROTOC3_OPTIONAL_OPTION --experimental_allow_proto3_optional)
endif()

if(("${Protobuf_VERSION}" VERSION_GREATER_EQUAL "28.0"))
    set(edition_support ON)
else()
    set(edition_support OFF)
endif()

set(unittest_desc_pb_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_proto3.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/map_unittest.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_well_known_types.proto
)

if(edition_support)
    list(APPEND unittest_desc_pb_sources ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_lite.proto)
endif()

add_custom_command(
    COMMENT "Generating unittest.desc.binpb"
    OUTPUT unittest.desc.binpb
    COMMAND hpp_proto::protoc
    ARGS -I "${CMAKE_CURRENT_SOURCE_DIR}" ${PROTOC3_OPTIONAL_OPTION} --include_imports --descriptor_set_out=unittest.desc.binpb
    ${unittest_desc_pb_sources}
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)

add_custom_target(unittest.desc.binpb.target ALL DEPENDS unittest.desc.binpb)

add_library(unittest_proto3_proto_lib INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_proto3.proto"
    "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import.proto"
    "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_import_public.proto"
)
target_include_directories(unittest_proto3_proto_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(
    TARGET unittest_proto3_proto_lib
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
    PROTOC_OPTIONS ${PROTOC3_OPTIONAL_OPTION}
)

add_library(unittest_proto_lib INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest.proto")
target_include_directories(unittest_proto_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(
    TARGET unittest_proto_lib
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
)

add_library(map_unittest_proto_lib INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/map_unittest.proto")
target_include_directories(map_unittest_proto_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(
    TARGET map_unittest_proto_lib
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(map_unittest_proto_lib INTERFACE unittest_proto_lib)

add_library(unittest_well_known_types_proto_lib INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_well_known_types.proto")
target_include_directories(unittest_well_known_types_proto_lib SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(unittest_well_known_types_proto_lib INTERFACE unittest_proto_lib)
protobuf_generate_hpp(
    TARGET unittest_well_known_types_proto_lib
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
)