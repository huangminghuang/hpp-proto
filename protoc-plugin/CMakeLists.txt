add_compile_options(${HPP_PROTO_COMPILE_OPTIONS})

add_executable(protoc-gen-hpp hpp_gen.cpp)
target_compile_definitions(protoc-gen-hpp PRIVATE HPP_PROTO_VERSION="${PROJECT_VERSION}")
add_executable(hpp_proto::protoc-gen-hpp ALIAS protoc-gen-hpp)
target_link_libraries(protoc-gen-hpp PRIVATE hpp_proto::libhpp_proto)

set_target_properties(protoc-gen-hpp
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/../bin"
)
install(TARGETS protoc-gen-hpp EXPORT hpp_proto-targets)

if(MSVC)
    target_compile_definitions(protoc-gen-hpp PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(protoc-gen-hpp PRIVATE /bigobj)
endif()

if(Protobuf_INCLUDE_DIRS)
    set(descriptor_proto_files
        google/protobuf/descriptor.proto
        google/protobuf/compiler/plugin.proto)

    add_custom_target(gpb_descriptor
        COMMENT "processing ${descriptor_proto_files} hpp_proto/hpp_options.pb"
        COMMAND hpp_proto::protoc --plugin=protoc-gen-hpp=$<TARGET_FILE:protoc-gen-hpp> --hpp_out=${CMAKE_CURRENT_SOURCE_DIR}/../include -I ${Protobuf_INCLUDE_DIRS}
        --hpp_opt=proto2_explicit_presence=.google.protobuf.FieldDescriptorProto.oneof_index,proto2_explicit_presence=.google.protobuf.FieldOptions.packed ${descriptor_proto_files}
        COMMAND hpp_proto::protoc --plugin=protoc-gen-hpp=$<TARGET_FILE:protoc-gen-hpp> --hpp_out=${CMAKE_CURRENT_SOURCE_DIR}/../include -I ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/../include/hpp_proto/hpp_options.proto
        DEPENDS hpp_proto::protoc ${CMAKE_CURRENT_SOURCE_DIR}/../include/hpp_proto/hpp_options.proto
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
    protobuf_generate_hpp(
        TARGET well_known_types
        IMPORT_DIRS "${Protobuf_INCLUDE_DIRS}"
        PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/../include)
    add_library(hpp_proto::well_known_types ALIAS well_known_types)
    install(TARGETS well_known_types EXPORT hpp_proto-targets
        FILE_SET HEADERS DESTINATION
        ${CMAKE_INSTALL_INCLUDEDIR})
endif()
