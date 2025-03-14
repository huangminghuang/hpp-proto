add_library(regular_addressbook INTERFACE)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/regular)
target_include_directories(regular_addressbook SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(
    TARGET regular_addressbook
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/.. # # required when the proto file is not in ${CMAKE_CURRENT_SOURCE_DIR}
    PROTOS ../addressbook_proto3.proto
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/regular
    PLUGIN_OPTIONS namespace_prefix=regular,directory_prefix=regular)

add_library(non_owning_addressbook INTERFACE)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/non_owning)
target_include_directories(non_owning_addressbook SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(
    TARGET non_owning_addressbook
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/.. # # required when the proto file is not in ${CMAKE_CURRENT_SOURCE_DIR}
    PROTOS ../addressbook_proto3.proto
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/non_owning
    PLUGIN_OPTIONS non_owning,namespace_prefix=non_owning,directory_prefix=non_owning)

add_executable(mixed_ownership_tutorial mixed_ownership_tutorial.cpp)
target_link_libraries(mixed_ownership_tutorial PRIVATE regular_addressbook non_owning_addressbook)

add_test(NAME mixed_ownership_tutorial
    COMMAND mixed_ownership_tutorial
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})