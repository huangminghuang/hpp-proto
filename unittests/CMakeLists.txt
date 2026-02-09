
if (NOT HPP_PROTO_TESTS)
    return()
endif()

add_hpp_proto_test(
    NAME pb_serializer_tests
    SOURCES pb_serializer_tests.cpp
    LINK_LIBRARIES hpp_proto::libhpp_proto Boost::ut)
if (MSVC)
    target_compile_options(pb_serializer_tests PRIVATE /bigobj)
endif()

add_hpp_proto_test(
    NAME merge_message_tests
    SOURCES merge_message_tests.cpp
    LINK_LIBRARIES hpp_proto::libhpp_proto Boost::ut)

add_hpp_proto_test(
    NAME optional_indirect_tests
    SOURCES optional_indirect_tests.cpp
    LINK_LIBRARIES hpp_proto::libhpp_proto glaze::glaze Boost::ut)

add_hpp_proto_test(
    NAME indirect_tests
    SOURCES indirect_tests.cpp
    LINK_LIBRARIES hpp_proto::libhpp_proto Boost::ut)

add_hpp_proto_test(
    NAME json_serializer_tests
    SOURCES json_serializer_tests.cpp
    LINK_LIBRARIES hpp_proto::libhpp_proto Boost::ut glaze::glaze)
