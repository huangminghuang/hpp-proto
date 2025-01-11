add_library(addressbook_proto3 INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/../addressbook_proto3.proto)
target_include_directories(addressbook_proto3 SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(
    TARGET addressbook_proto3
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/.. # # required when the proto file is not in ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(tutorial_proto3 tutorial_proto3.cpp)
target_link_libraries(tutorial_proto3 PRIVATE addressbook_proto3)

add_test(NAME regular_tutorial_proto3
    COMMAND tutorial_proto3
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_library(addressbook_proto2 INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/../addressbook_proto2.proto)
target_include_directories(addressbook_proto2 SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(
    TARGET addressbook_proto2
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/.. # # required when the proto file is not in ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(tutorial_proto2 tutorial_proto2.cpp)
target_link_libraries(tutorial_proto2 PRIVATE addressbook_proto2)

add_test(NAME regular_tutorial_proto2
    COMMAND tutorial_proto2
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_library(any_demo INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/../any_demo.proto)
target_include_directories(any_demo INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(any_demo INTERFACE hpp_proto::well_known_types)
protobuf_generate_hpp(
    TARGET any_demo
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/.. ${Protobuf_INCLUDE_DIRS})

add_executable(tutorial_any tutorial_any.cpp)
target_link_libraries(tutorial_any PRIVATE any_demo addressbook_proto3)
add_test(NAME tutorial_any
    COMMAND tutorial_any
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})