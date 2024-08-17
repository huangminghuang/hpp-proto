add_library(addressbook_proto3 INTERFACE)
target_include_directories(addressbook_proto3 INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET addressbook_proto3
                  IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/.. ## required when the proto file is not in ${CMAKE_CURRENT_SOURCE_DIR}
                  PROTOS ../addressbook_proto3.proto
                  LANGUAGE hpp)

add_executable(tutorial_proto3 tutorial_proto3.cpp)
target_link_libraries(tutorial_proto3 PRIVATE addressbook_proto3)

add_test(NAME regular_tutorial_proto3
    COMMAND tutorial_proto3
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_library(addressbook_proto2 INTERFACE)
target_include_directories(addressbook_proto2 INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET addressbook_proto2
                  IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/.. ## required when the proto file is not in ${CMAKE_CURRENT_SOURCE_DIR}
                  PROTOS ../addressbook_proto2.proto 
                  LANGUAGE hpp)

add_executable(tutorial_proto2 tutorial_proto2.cpp)
target_link_libraries(tutorial_proto2 PRIVATE addressbook_proto2)

add_test(NAME regular_tutorial_proto2
    COMMAND tutorial_proto2
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

