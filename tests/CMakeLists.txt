
# use CPMAddPackage for ut would make ut part of the installed target
FetchContent_Declare(
  ut
  GIT_REPOSITORY https://github.com/boost-ext/ut
  GIT_TAG        v1.1.9
)

if(NOT ut_POPULATED)
  FetchContent_Populate(ut)
endif()

if (CMAKE_BUILD_TYPE STREQUAL Debug AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
# g++ have problem to compile absil (used by google protobuf) when sanitizer is enabled
# https://github.com/abseil/abseil-cpp/issues/1379
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address -fno-omit-frame-pointer)
endif()

add_library(Boost::ut INTERFACE IMPORTED)
target_include_directories(Boost::ut INTERFACE ${ut_SOURCE_DIR}/include)

add_subdirectory(gpb_proto_json)

add_executable(pb_serializer_tests pb_serializer_tests.cpp)
target_link_libraries(pb_serializer_tests PRIVATE hpp_proto::libhpp_proto Boost::ut)
target_compile_options(pb_serializer_tests PRIVATE -ftemplate-backtrace-limit=0)

add_test(NAME pb_serializer_tests 
         COMMAND pb_serializer_tests 
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})


add_executable(json_serializer_tests json_serializer_tests.cpp)
target_link_libraries(json_serializer_tests PRIVATE hpp_proto::libhpp_proto Boost::ut glaze::glaze)

add_test(NAME json_serializer_tests 
         COMMAND json_serializer_tests 
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

include(../cmake/add_hpp_proto_lib.cmake)
include(../cmake/gen_proto_descriptor_set.cmake)

gen_proto_descriptor_set(unittest_proto3.bin
    INPUT_DIR ${protobuf_SOURCE_DIR}/src
    PROTO_FILES google/protobuf/unittest_proto3.proto)

add_hpp_proto_lib(unittest_proto3_proto_lib
    INPUT_DIR   ${protobuf_SOURCE_DIR}/src
    PROTO_FILES google/protobuf/unittest_proto3.proto 
                google/protobuf/unittest_import.proto 
                google/protobuf/unittest_import_public.proto)

add_executable(proto3_lite_test unittest_proto3_test.cpp)
target_link_libraries(proto3_lite_test PRIVATE unittest_proto3_proto_lib Boost::ut glaze::glaze gpb_proto_json)

add_test(NAME proto3_lite_test 
         COMMAND proto3_lite_test 
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_property(TEST proto3_lite_test PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0")


add_hpp_proto_lib(non_owning_unittest_proto3_proto_lib
    INPUT_DIR    ${protobuf_SOURCE_DIR}/src
    OUTPUT_DIR   ${CMAKE_CURRENT_BINARY_DIR}/non_owning
    PROTO_FILES  google/protobuf/unittest_proto3.proto 
                 google/protobuf/unittest_import.proto 
                 google/protobuf/unittest_import_public.proto
    ENVIRONMENTS "HPP_NON_OWNING=ON" 
                 "HPP_ROOT_NAMESPACE=non_owning"
                 "HPP_TOP_DIRECTORY=non_owning")

add_executable(non_owning_proto3_test non_owning_proto3_test.cpp)
target_link_libraries(non_owning_proto3_test PRIVATE Boost::ut glaze::glaze non_owning_unittest_proto3_proto_lib )
target_include_directories(non_owning_proto3_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})


add_hpp_proto_lib(non_owning_unittest_proto2_proto_lib
    INPUT_DIR    ${protobuf_SOURCE_DIR}/src
    OUTPUT_DIR   ${CMAKE_CURRENT_BINARY_DIR}/non_owning
    PROTO_FILES  google/protobuf/unittest.proto 
    ENVIRONMENTS "HPP_NON_OWNING=ON" 
                 "HPP_ROOT_NAMESPACE=non_owning"
                 "HPP_TOP_DIRECTORY=non_owning"
)
add_executable(non_owning_proto2_test non_owning_proto2_test.cpp)
target_link_libraries(non_owning_proto2_test Boost::ut non_owning_unittest_proto2_proto_lib )

gen_proto_descriptor_set(unittest_proto2.bin
    INPUT_DIR ${protobuf_SOURCE_DIR}/src
    PROTO_FILES google/protobuf/unittest.proto)

add_hpp_proto_lib(unittest_proto_lib 
    INPUT_DIR    ${protobuf_SOURCE_DIR}/src
    PROTO_FILES  google/protobuf/unittest.proto)

add_executable(proto2_lite_test unittest_proto2_test.cpp)
target_link_libraries(proto2_lite_test PRIVATE unittest_proto_lib Boost::ut glaze::glaze gpb_proto_json)

add_test(NAME proto2_lite_test 
         COMMAND proto2_lite_test 
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_property(TEST proto2_lite_test PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0")


gen_proto_descriptor_set(map_unittest.bin
    INPUT_DIR ${protobuf_SOURCE_DIR}/src
    PROTO_FILES google/protobuf/map_unittest.proto)

add_hpp_proto_lib(map_unittest_proto_lib 
    INPUT_DIR    ${protobuf_SOURCE_DIR}/src
    PROTO_FILES  google/protobuf/map_unittest.proto)

add_executable(dynamic_serializer_tests dynamic_serializer_tests.cpp)
target_link_libraries(dynamic_serializer_tests PRIVATE unittest_proto3_proto_lib map_unittest_proto_lib Boost::ut glaze::glaze gpb_proto_json)

add_test(NAME dynamic_serializer_tests 
         COMMAND dynamic_serializer_tests 
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_property(TEST dynamic_serializer_tests PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0")