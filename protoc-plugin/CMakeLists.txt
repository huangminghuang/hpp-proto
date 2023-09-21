CPMAddPackage("gh:fmtlib/fmt#10.0.0")

add_executable(protoc-gen-hpp hpp_gen.cpp)
target_link_libraries(protoc-gen-hpp PRIVATE hpp_proto::libhpp_proto fmt::fmt)
install(TARGETS protoc-gen-hpp EXPORT hpp_proto-targets)

set(PROTO_FILES google/protobuf/descriptor.proto 
                google/protobuf/compiler/plugin.proto)

add_custom_target(gpb_descriptor
    COMMENT "processing ${PROTO_FILES}"
    COMMAND ${CMAKE_COMMAND} -E env "HPP_EXPLICIT_PRESENCE=.google.protobuf.FieldDescriptorProto.oneof_index,.google.protobuf.FieldOptions.packed" $<TARGET_FILE:protoc> --plugin=protoc-gen-hpp=$<TARGET_FILE:protoc-gen-hpp> --hpp_out=${CMAKE_CURRENT_SOURCE_DIR}/../include  -I ${protobuf_SOURCE_DIR}/src ${PROTO_FILES}
    DEPENDS protoc protoc-gen-hpp
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)
