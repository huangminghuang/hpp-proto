add_executable(pmr_tutorial_proto3 pmr_tutorial_proto3.cpp)
target_link_libraries(pmr_tutorial_proto3 PRIVATE glaze::glaze addressbook_proto3)
add_test(NAME pmr_tutorial_proto3
    COMMAND pmr_tutorial_proto3
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})