
if (NOT HPP_PROTO_TESTS)
    return()
endif()

add_hpp_proto_test(
    NAME pb_serializer_tests
    SOURCES pb_serializer_tests.cpp
    LINK_LIBRARIES hpp_proto::hpp_proto_core Boost::ut)
if (MSVC)
    target_compile_options(pb_serializer_tests PRIVATE /bigobj)
endif()

add_hpp_proto_test(
    NAME merge_message_tests
    SOURCES merge_message_tests.cpp
    LINK_LIBRARIES hpp_proto::hpp_proto_core Boost::ut)

set(HPP_PROTO_STD_FLAT_MAP_CHECK_SOURCE "${CMAKE_CURRENT_BINARY_DIR}/std_flat_map_check.cpp")
file(WRITE "${HPP_PROTO_STD_FLAT_MAP_CHECK_SOURCE}" "
#include <version>
#ifdef __cpp_lib_flat_map
#include <flat_map>
int main() { return 0; }
#else
#error __cpp_lib_flat_map is not defined
#endif
")
try_compile(HPP_PROTO_HAS_STD_FLAT_MAP
    "${CMAKE_CURRENT_BINARY_DIR}/std_flat_map_check"
    SOURCES "${HPP_PROTO_STD_FLAT_MAP_CHECK_SOURCE}"
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON)

if(NOT HPP_PROTO_HAS_STD_FLAT_MAP)
    add_hpp_proto_test(
        NAME flat_map_tests
        SOURCES flat_map_tests.cpp
        LINK_LIBRARIES hpp_proto::hpp_proto_core Boost::ut)
endif()

add_hpp_proto_test(
    NAME optional_indirect_tests
    SOURCES optional_indirect_tests.cpp
    LINK_LIBRARIES hpp_proto::hpp_proto_core glaze::glaze Boost::ut)

add_hpp_proto_test(
    NAME indirect_tests
    SOURCES indirect_tests.cpp
    LINK_LIBRARIES hpp_proto::hpp_proto_core Boost::ut)

add_hpp_proto_test(
    NAME json_serializer_tests
    SOURCES json_serializer_tests.cpp
    LINK_LIBRARIES hpp_proto::hpp_proto_core Boost::ut glaze::glaze)
