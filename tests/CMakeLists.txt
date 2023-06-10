
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

add_executable(proto_test proto_tests.cpp)
target_link_libraries(proto_test PRIVATE hpp_proto::libhpp_proto Boost::ut)
target_compile_options(proto_test PRIVATE -ftemplate-backtrace-limit=0)

add_test(NAME proto_test 
         COMMAND proto_test 
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})


add_executable(glaze_tests glaze_tests.cpp)
target_link_libraries(glaze_tests PRIVATE hpp_proto::libhpp_proto Boost::ut glaze::glaze)

add_test(NAME glaze_tests 
         COMMAND glaze_tests 
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

include(../cmake/add_hpp_proto_lib.cmake)
include(../cmake/gen_proto_descriptor_set.cmake)

gen_proto_descriptor_set(unittest_proto3.bin
    INPUT_DIR ${protobuf_SOURCE_DIR}/src
    PROTO_FILES google/protobuf/unittest_proto3.proto)

add_custom_target(proto3.bin
                  DEPENDS unittest_proto3.bin)

add_hpp_proto_lib(proto3_lite_lib
    INPUT_DIR   ${protobuf_SOURCE_DIR}/src
    PROTO_FILES google/protobuf/unittest_proto3.proto 
                google/protobuf/unittest_import.proto 
                google/protobuf/unittest_import_public.proto)

add_executable(proto3_lite_test unittest_proto3_test.cpp)
target_link_libraries(proto3_lite_test PRIVATE proto3_lite_lib Boost::ut glaze::glaze gpb_proto_json)

add_dependencies(proto3_lite_test proto3.bin)

add_test(NAME proto3_lite_test 
         COMMAND proto3_lite_test 
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_property(TEST proto3_lite_test PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0")


gen_proto_descriptor_set(unittest_proto2.bin
    INPUT_DIR ${protobuf_SOURCE_DIR}/src
    PROTO_FILES google/protobuf/unittest.proto)

add_custom_target(proto2.bin
                  DEPENDS unittest_proto2.bin)

add_hpp_proto_lib(proto2_lite_lib 
    INPUT_DIR    ${CMAKE_CURRENT_SOURCE_DIR} 
    INCLUDE_DIRS ${protobuf_SOURCE_DIR}/src
    PROTO_FILES  google/protobuf/unittest.proto)

add_executable(proto2_lite_test unittest_proto2_test.cpp)
target_link_libraries(proto2_lite_test PRIVATE proto2_lite_lib Boost::ut glaze::glaze gpb_proto_json)
target_compile_options(proto2_lite_test PRIVATE -Wno-deprecated-declarations)

add_dependencies(proto2_lite_test proto2.bin)

add_test(NAME proto2_lite_test 
         COMMAND proto2_lite_test 
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_property(TEST proto2_lite_test PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_container_overflow=0")
