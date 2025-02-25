

add_executable(pb_serializer_tests pb_serializer_tests.cpp)
target_link_libraries(pb_serializer_tests PRIVATE hpp_proto::libhpp_proto Boost::ut)

if(MSVC)
    target_compile_options(pb_serializer_tests PRIVATE /bigobj)
endif()

add_hpp_proto_test( pb_serializer_tests)

if(NOT HPP_PROTO_DISABLE_GLAZE)
    add_executable(json_serializer_tests json_serializer_tests.cpp)
    target_link_libraries(json_serializer_tests PRIVATE hpp_proto::libhpp_proto Boost::ut glaze::glaze)
    add_hpp_proto_test(json_serializer_tests)
endif()