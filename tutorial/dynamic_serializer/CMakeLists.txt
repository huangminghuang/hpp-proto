
add_custom_command(
    COMMENT "Generating addressbook_proto3.desc.binpb"
    OUTPUT addressbook_proto3.desc.binpb
    COMMAND protobuf::protoc -I "${CMAKE_CURRENT_SOURCE_DIR}/.." --descriptor_set_out=addressbook_proto3.desc.binpb
    ${CMAKE_CURRENT_SOURCE_DIR}/../addressbook_proto3.proto
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)

add_custom_target(addressbook_proto3_descriptor
    DEPENDS addressbook_proto3.desc.binpb)

add_executable(protobuf_json_conversion protobuf_json_conversion.cpp)
target_link_libraries(protobuf_json_conversion PRIVATE hpp_proto::libhpp_proto)
add_dependencies(protobuf_json_conversion addressbook_proto3_descriptor)

add_hpp_proto_test(protobuf_json_conversion)
