add_compile_options(${HPP_PROTO_COMPILE_OPTIONS})

add_executable(protoc-gen-hpp hpp_gen.cpp)
add_executable(hpp_proto::protoc-gen-hpp ALIAS protoc-gen-hpp)
target_link_libraries(protoc-gen-hpp PRIVATE hpp_proto::libhpp_proto fmt::fmt)
install(TARGETS protoc-gen-hpp EXPORT hpp_proto-targets)

if(MSVC)
    target_compile_definitions(protoc-gen-hpp PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

if(Protobuf_INCLUDE_DIRS)
    set(proto_files google/protobuf/descriptor.proto
        google/protobuf/compiler/plugin.proto)

    add_custom_target(gpb_descriptor
        COMMENT "processing ${proto_files}"
        COMMAND protobuf::protoc --plugin=protoc-gen-hpp=$<TARGET_FILE:protoc-gen-hpp> --hpp_out=${CMAKE_CURRENT_SOURCE_DIR}/../include -I ${Protobuf_INCLUDE_DIRS}
        --hpp_opt=proto2_explicit_presence=.google.protobuf.FieldDescriptorProto.oneof_index,proto2_explicit_presence=.google.protobuf.FieldOptions.packed ${proto_files}
        DEPENDS protobuf::protoc protoc-gen-hpp
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        VERBATIM
    )

    set(well_known_types_proto
        ${Protobuf_INCLUDE_DIRS}/google/protobuf/any.proto
        ${Protobuf_INCLUDE_DIRS}/google/protobuf/api.proto
        ${Protobuf_INCLUDE_DIRS}/google/protobuf/duration.proto
        ${Protobuf_INCLUDE_DIRS}/google/protobuf/empty.proto
        ${Protobuf_INCLUDE_DIRS}/google/protobuf/field_mask.proto
        ${Protobuf_INCLUDE_DIRS}/google/protobuf/source_context.proto
        ${Protobuf_INCLUDE_DIRS}/google/protobuf/struct.proto
        ${Protobuf_INCLUDE_DIRS}/google/protobuf/timestamp.proto
        ${Protobuf_INCLUDE_DIRS}/google/protobuf/type.proto
        ${Protobuf_INCLUDE_DIRS}/google/protobuf/wrappers.proto)

    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/../include)

    add_library(well_known_types INTERFACE ${well_known_types_proto})
    protobuf_generate(
        TARGET well_known_types
        LANGUAGE hpp
        IMPORT_DIRS "${Protobuf_INCLUDE_DIRS}"
        PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/../include)
    target_link_libraries(well_known_types INTERFACE hpp_proto::libhpp_proto)
endif()
