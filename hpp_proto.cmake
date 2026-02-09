if(NOT Protobuf_INCLUDE_DIRS)
    return()
endif()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)
add_library(descriptor_lib INTERFACE)
protobuf_generate_hpp(
    TARGET descriptor_lib
    PROTOS ${CMAKE_CURRENT_SOURCE_DIR}/include/hpp_proto/hpp_options.proto
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)

protobuf_generate_hpp(
    TARGET descriptor_lib
    PROTOS ${Protobuf_INCLUDE_DIRS}/google/protobuf/descriptor.proto
    ${Protobuf_INCLUDE_DIRS}/google/protobuf/compiler/plugin.proto
    IMPORT_DIRS "${Protobuf_INCLUDE_DIRS}"
    PLUGIN_OPTIONS "proto2_explicit_presence=.google.protobuf.FieldDescriptorProto.oneof_index,proto2_explicit_presence=.google.protobuf.FieldOptions.packed"
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)

if(EXISTS ${Protobuf_INCLUDE_DIRS}/google/protobuf/compiler/plugin.proto)
    protobuf_generate_hpp(
        TARGET descriptor_lib
        PROTOS ${Protobuf_INCLUDE_DIRS}/google/protobuf/compiler/plugin.proto
        IMPORT_DIRS "${Protobuf_INCLUDE_DIRS}"
        PLUGIN_OPTIONS "proto2_explicit_presence=.google.protobuf.FieldDescriptorProto.oneof_index,proto2_explicit_presence=.google.protobuf.FieldOptions.packed"
        PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
else()
    # ubuntu 24.04 protobuf-compiler package does not ship plugin.proto
    add_library(plugin_lib INTERFACE)
    target_sources(plugin_lib
        FILE_SET public_headers
        TYPE HEADERS
        BASE_DIRS "include"
        FILES "include/google/protobuf/compiler/plugin.msg.hpp"
        "include/google/protobuf/compiler/plugin.pb.hpp"
        "include/google/protobuf/compiler/plugin.glz.hpp"
        "include/google/protobuf/compiler/plugin.desc.hpp"
    )
    install(TARGETS plugin_lib EXPORT hpp_proto-targets
        FILE_SET HEADERS DESTINATION
        ${CMAKE_INSTALL_INCLUDEDIR})
endif()

install(TARGETS descriptor_lib EXPORT hpp_proto-targets
    FILE_SET HEADERS DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}
    COMPONENT gpb_descriptors)

add_custom_target(update_descriptor
    COMMENT "update descriptor generated files"
    DEPENDS ${_descriptor_header_list}
    COMMAND ${CMAKE_COMMAND} -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_SOURCE_DIR} -DCMAKE_INSTALL_COMPONENT=gpb_descriptors -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_install.cmake")

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

if (TARGET plugin_lib)
    add_library(hpp_proto INTERFACE plugin_lib)
endif()

add_library(hpp_proto INTERFACE)
target_link_libraries(hpp_proto INTERFACE hpp_proto_core well_known_types descriptor_lib)
add_library(hpp_proto::hpp_proto ALIAS hpp_proto)
install(TARGETS hpp_proto EXPORT hpp_proto-targets)
