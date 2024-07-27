if (MSVC)
  add_compile_options("/Zc:preprocessor" "/W4")
else()
  add_compile_options("-Wall" "-Wall" "-Wextra" "-Wpedantic")
endif()

add_executable(pb_serializer_tests pb_serializer_tests.cpp)
target_link_libraries(pb_serializer_tests PRIVATE hpp_proto::libhpp_proto Boost::ut)
if (MSVC)
    target_compile_options(pb_serializer_tests PRIVATE /bigobj)
endif()

add_test(NAME pb_serializer_tests
    COMMAND pb_serializer_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(json_serializer_tests json_serializer_tests.cpp)
target_link_libraries(json_serializer_tests PRIVATE hpp_proto::libhpp_proto Boost::ut glaze::glaze)

add_test(NAME json_serializer_tests
    COMMAND json_serializer_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})