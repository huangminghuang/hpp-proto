add_executable(pmr_traits pmr_traits.cpp)
target_link_libraries(pmr_traits PRIVATE addressbook_proto3)
add_test(NAME pmr_traits
    COMMAND pmr_traits
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})