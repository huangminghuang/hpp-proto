if(NOT Protobuf_INCLUDE_DIRS)
    return()
endif()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)

set(descriptor_proto_files
    google/protobuf/descriptor.proto
    google/protobuf/compiler/plugin.proto)

add_custom_target(update_descriptor
    COMMENT "processing ${descriptor_proto_files} hpp_proto/hpp_options.pb"
    COMMAND hpp_proto::protoc --plugin=protoc-gen-hpp=$<TARGET_FILE:protoc-gen-hpp> --hpp_out=${CMAKE_CURRENT_SOURCE_DIR}/../include -I ${Protobuf_INCLUDE_DIRS}
    --hpp_opt=proto2_explicit_presence=.google.protobuf.FieldDescriptorProto.oneof_index,proto2_explicit_presence=.google.protobuf.FieldOptions.packed ${descriptor_proto_files}
    COMMAND hpp_proto::protoc --plugin=protoc-gen-hpp=$<TARGET_FILE:protoc-gen-hpp> --hpp_out=${CMAKE_CURRENT_SOURCE_DIR}/../include -I ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/hpp_proto/hpp_options.proto
    DEPENDS hpp_proto::protoc ${CMAKE_CURRENT_SOURCE_DIR}/../include/hpp_proto/hpp_options.proto
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)

file(GLOB_RECURSE DESCRIPTOR_PUBLIC_HEADERS CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/include/google/protobuf/*.hpp")
add_library(descriptor_lib INTERFACE)
target_sources(descriptor_lib INTERFACE
    FILE_SET HEADERS
    BASE_DIRS "include"
    FILES ${DESCRIPTOR_PUBLIC_HEADERS}
)

install(TARGETS descriptor_lib EXPORT hpp_proto-targets
    FILE_SET HEADERS DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR})

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

add_library(well_known_types INTERFACE ${well_known_types_proto})
protobuf_generate_hpp(
    TARGET well_known_types
    IMPORT_DIRS "${Protobuf_INCLUDE_DIRS}"
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
install(TARGETS well_known_types EXPORT hpp_proto-targets
    FILE_SET HEADERS DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR})

add_library(hpp_proto INTERFACE)
target_link_libraries(hpp_proto INTERFACE hpp_proto_core well_known_types descriptor_lib)
add_library(hpp_proto::hpp_proto ALIAS hpp_proto)
install(TARGETS hpp_proto EXPORT hpp_proto-targets)
