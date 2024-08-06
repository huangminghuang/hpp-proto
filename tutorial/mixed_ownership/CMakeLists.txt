add_library(regular_addressbook INTERFACE)
target_include_directories(regular_addressbook INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET regular_addressbook
                  IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/.. ## required when the proto file is not in ${CMAKE_CURRENT_SOURCE_DIR}
                  PROTOS ../addressbook_proto3.proto
                  LANGUAGE hpp
                  PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/regular
                  PLUGIN_OPTIONS root_namespace=regular,top_directory=regular)

add_library(non_owning_addressbook INTERFACE)
target_include_directories(non_owning_addressbook INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET non_owning_addressbook
                IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/.. ## required when the proto file is not in ${CMAKE_CURRENT_SOURCE_DIR}
                PROTOS ../addressbook_proto3.proto
                LANGUAGE hpp
                PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/non_owning
                PLUGIN_OPTIONS non_owning,root_namespace=non_owning,top_directory=non_owning)

add_executable(mixed_ownership_tutorial mixed_ownership_tutorial.cpp)
target_link_libraries(mixed_ownership_tutorial PRIVATE regular_addressbook non_owning_addressbook)

add_test(NAME mixed_ownership_tutorial
    COMMAND mixed_ownership_tutorial
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})