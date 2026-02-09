
add_custom_command(
    COMMENT "Generating addressbook_proto3.desc.binpb"
    OUTPUT addressbook_proto3.desc.binpb
    COMMAND hpp_proto::protoc
    ARGS -I "${CMAKE_CURRENT_SOURCE_DIR}/.." --include_imports --descriptor_set_out=addressbook_proto3.desc.binpb
    addressbook_proto3.proto
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)

add_custom_target(addressbook_proto3.desc.binpb.target ALL
    DEPENDS addressbook_proto3.desc.binpb)

add_executable(dynamic_message_tutorial_proto3 tutorial_proto3_dynamic.cpp)
target_compile_features(dynamic_message_tutorial_proto3 PRIVATE cxx_std_23)
target_link_libraries(dynamic_message_tutorial_proto3 PRIVATE hpp_proto::hpp_proto glaze::glaze)
if (MSVC)
    target_compile_options(dynamic_message_tutorial_proto3 PRIVATE /bigobj)
endif()

add_test(NAME dynamic_message_tutorial_proto3
    COMMAND tutorial_proto3
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
