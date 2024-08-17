add_library(non_owning_addressbook_proto3 INTERFACE)
target_include_directories(non_owning_addressbook_proto3 INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET non_owning_addressbook_proto3
                  IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/.. ## required when the proto file is not in ${CMAKE_CURRENT_SOURCE_DIR}
                  PROTOS ../addressbook_proto3.proto
                  LANGUAGE hpp
                  PLUGIN_OPTIONS non_owning)

add_executable(non_owning_tutorial_proto3 non_owning_tutorial_proto3.cpp)
target_link_libraries(non_owning_tutorial_proto3 PRIVATE non_owning_addressbook_proto3)

add_test(NAME non_owning_tutorial_proto3
    COMMAND non_owning_tutorial_proto3
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_library(non_owning_addressbook_proto2 INTERFACE)
target_include_directories(non_owning_addressbook_proto2 INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET non_owning_addressbook_proto2
                  IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/.. ## required when the proto file is not in ${CMAKE_CURRENT_SOURCE_DIR}
                  PROTOS ../addressbook_proto2.proto 
                  LANGUAGE hpp
                  PLUGIN_OPTIONS non_owning)

add_executable(non_owning_tutorial_proto2 non_owning_tutorial_proto2.cpp)
target_link_libraries(non_owning_tutorial_proto2 PRIVATE non_owning_addressbook_proto2)

add_test(NAME non_owning_tutorial_proto2
    COMMAND non_owning_tutorial_proto2
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

