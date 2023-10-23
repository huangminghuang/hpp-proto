
add_executable(protoc-gen-hpp hpp_gen.cpp)
add_executable(hpp_proto::protoc-gen-hpp ALIAS protoc-gen-hpp)
target_link_libraries(protoc-gen-hpp PRIVATE hpp_proto::libhpp_proto fmt::fmt)
install(TARGETS protoc-gen-hpp EXPORT hpp_proto-targets)

if (MSVC)
    target_compile_definitions(protoc-gen-hpp PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

set(proto_files google/protobuf/descriptor.proto 
                google/protobuf/compiler/plugin.proto)

add_custom_target(gpb_descriptor
    COMMENT "processing ${proto_files}"
    COMMAND $<TARGET_FILE:protoc> --plugin=protoc-gen-hpp=$<TARGET_FILE:protoc-gen-hpp> --hpp_out=${CMAKE_CURRENT_SOURCE_DIR}/../include  -I ${protobuf_SOURCE_DIR}/src 
             --hpp_opt=explicit_presence=.google.protobuf.FieldDescriptorProto.oneof_index,explicit_presence=.google.protobuf.FieldOptions.packed ${proto_files}
    DEPENDS protoc protoc-gen-hpp
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)
