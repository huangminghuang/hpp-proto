
if (NOT HPP_PROTO_TESTS)
    return()
endif()

add_executable(pb_serializer_tests pb_serializer_tests.cpp)
target_link_libraries(pb_serializer_tests PRIVATE hpp_proto::libhpp_proto Boost::ut)
if (MSVC)
    target_compile_options(pb_serializer_tests PRIVATE /bigobj)
endif()

add_test(NAME pb_serializer_tests
    COMMAND pb_serializer_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(merge_message_tests merge_message_tests.cpp)
target_link_libraries(merge_message_tests PRIVATE hpp_proto::libhpp_proto Boost::ut)
add_test(NAME merge_message_tests
    COMMAND merge_message_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(optional_indirect_tests optional_indirect_tests.cpp)
target_link_libraries(optional_indirect_tests PRIVATE hpp_proto::libhpp_proto Boost::ut)
add_test(NAME optional_indirect_tests
    COMMAND optional_indirect_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(indirect_tests indirect_tests.cpp)
target_link_libraries(indirect_tests PRIVATE hpp_proto::libhpp_proto Boost::ut)
add_test(NAME indirect_tests
    COMMAND indirect_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

if (NOT HPP_PROTO_DISABLE_GLAZE)
add_executable(json_serializer_tests json_serializer_tests.cpp)
target_link_libraries(json_serializer_tests PRIVATE hpp_proto::libhpp_proto Boost::ut glaze::glaze)

add_test(NAME json_serializer_tests
    COMMAND json_serializer_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()
