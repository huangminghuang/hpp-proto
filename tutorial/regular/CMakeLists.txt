
add_executable(tutorial_proto3 tutorial_proto3.cpp)
target_link_libraries(tutorial_proto3 PRIVATE glaze::glaze addressbook_proto3)

add_test(NAME regular_tutorial_proto3
    COMMAND tutorial_proto3
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(tutorial_proto2 tutorial_proto2.cpp)
target_link_libraries(tutorial_proto2 PRIVATE glaze::glaze addressbook_proto2)

add_test(NAME regular_tutorial_proto2
    COMMAND tutorial_proto2
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(tutorial_any tutorial_any.cpp)
target_link_libraries(tutorial_any PRIVATE any_demo addressbook_proto3)
add_test(NAME tutorial_any
    COMMAND tutorial_any
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
