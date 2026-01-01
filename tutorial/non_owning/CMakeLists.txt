
add_executable(non_owning_tutorial_proto3 non_owning_tutorial_proto3.cpp)
target_link_libraries(non_owning_tutorial_proto3 PRIVATE addressbook_proto3)

add_test(
    NAME non_owning_tutorial_proto3
    COMMAND non_owning_tutorial_proto3
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})


add_executable(non_owning_tutorial_proto2 non_owning_tutorial_proto2.cpp)
target_link_libraries(non_owning_tutorial_proto2 PRIVATE addressbook_proto2)

add_test(NAME non_owning_tutorial_proto2
    COMMAND non_owning_tutorial_proto2
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    
add_executable(non_owning_tutorial_any non_owning_tutorial_any.cpp)
target_link_libraries(non_owning_tutorial_any PRIVATE any_demo addressbook_proto3)
add_test(NAME non_owning_tutorial_any
    COMMAND non_owning_tutorial_any
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
