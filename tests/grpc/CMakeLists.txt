
if (HPP_PROTO_PROTOC STREQUAL "compile")
    return()
endif()

find_package(gRPC CONFIG 1.51)
find_package(Python3 COMPONENTS Interpreter)

if(NOT gRPC_FOUND)
    message(WARNING "gRPC not found, skipping grpc_tests target")
    return()
endif()

if(NOT Python3_Interpreter_FOUND)
    message(WARNING "Python3 interpreter not found, skipping grpc_tests target")
    return()
endif()


add_library(grpc_proto_lib INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/echo_stream.proto")
target_include_directories(grpc_proto_lib SYSTEM INTERFACE
    ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(
    TARGET grpc_proto_lib
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/.."
    PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(grpc_proto_lib INTERFACE gRPC::grpc++)

set(GRPC_TEST_CASES
    unary_tests.cpp
    client_stream_tests.cpp
    server_stream_tests.cpp
    bidi_stream_tests.cpp)

add_executable(grpc_test_server
    grpc_test_server.cpp)
target_link_libraries(grpc_test_server PRIVATE
    grpc_proto_lib
    hpp_proto::libhpp_proto
    gRPC::grpc++)
target_include_directories(grpc_test_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})

set(GRPC_TEST_RUNNER "${CMAKE_CURRENT_SOURCE_DIR}/run_grpc_test.py")

foreach(test_src IN LISTS GRPC_TEST_CASES)
    get_filename_component(test_name "${test_src}" NAME_WE)
    set(target_name "grpc_${test_name}")

    add_executable(${target_name}
        grpc_tests.cpp
        "${test_src}")
    target_link_libraries(${target_name} PRIVATE
        grpc_proto_lib
        hpp_proto::libhpp_proto
        Boost::ut
        glaze::glaze
        gRPC::grpc++)
    target_include_directories(${target_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME ${target_name}
        COMMAND ${Python3_EXECUTABLE} "${GRPC_TEST_RUNNER}" $<TARGET_FILE:grpc_test_server> $<TARGET_FILE:${target_name}>
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endforeach()

set(GRPC_OFFICIAL_PROTO_AVAILABLE OFF)
if(TARGET protobuf::libprotobuf AND TARGET protobuf::protoc AND TARGET gRPC::grpc_cpp_plugin)
    set(GRPC_OFFICIAL_PROTO_AVAILABLE ON)
else()
    message(WARNING "Skipping official protobuf-based grpc unary test; required protobuf/gRPC targets not found")
endif()

if(GRPC_OFFICIAL_PROTO_AVAILABLE)
    set(GRPC_OFFICIAL_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/official")
    file(MAKE_DIRECTORY "${GRPC_OFFICIAL_GENERATED_DIR}")
    set(GRPC_OFFICIAL_PROTO "${CMAKE_CURRENT_SOURCE_DIR}/echo_stream.proto")
    set(GRPC_OFFICIAL_PB_CC "${GRPC_OFFICIAL_GENERATED_DIR}/echo_stream.pb.cc")
    set(GRPC_OFFICIAL_PB_H "${GRPC_OFFICIAL_GENERATED_DIR}/echo_stream.pb.h")
    set(GRPC_OFFICIAL_GRPC_CC "${GRPC_OFFICIAL_GENERATED_DIR}/echo_stream.grpc.pb.cc")
    set(GRPC_OFFICIAL_GRPC_H "${GRPC_OFFICIAL_GENERATED_DIR}/echo_stream.grpc.pb.h")

    add_custom_command(
        OUTPUT "${GRPC_OFFICIAL_PB_CC}" "${GRPC_OFFICIAL_PB_H}"
        COMMAND $<TARGET_FILE:protobuf::protoc>
        ARGS --cpp_out "${GRPC_OFFICIAL_GENERATED_DIR}"
             --proto_path "${CMAKE_CURRENT_SOURCE_DIR}"
             "${GRPC_OFFICIAL_PROTO}"
        DEPENDS "${GRPC_OFFICIAL_PROTO}" protobuf::protoc
        COMMENT "Generating official protobuf sources for grpc unary compatibility test"
        VERBATIM)

    add_custom_command(
        OUTPUT "${GRPC_OFFICIAL_GRPC_CC}" "${GRPC_OFFICIAL_GRPC_H}"
        COMMAND $<TARGET_FILE:protobuf::protoc>
        ARGS --grpc_out "${GRPC_OFFICIAL_GENERATED_DIR}"
             --plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>
             --proto_path "${CMAKE_CURRENT_SOURCE_DIR}"
             "${GRPC_OFFICIAL_PROTO}"
        DEPENDS "${GRPC_OFFICIAL_PROTO}" protobuf::protoc gRPC::grpc_cpp_plugin "${GRPC_OFFICIAL_PB_H}"
        COMMENT "Generating official gRPC stubs for unary compatibility test"
        VERBATIM)

    add_library(grpc_official_proto STATIC
        "${GRPC_OFFICIAL_PB_CC}"
        "${GRPC_OFFICIAL_GRPC_CC}")
    target_include_directories(grpc_official_proto PUBLIC
        "${GRPC_OFFICIAL_GENERATED_DIR}")
    target_link_libraries(grpc_official_proto PUBLIC
        protobuf::libprotobuf
        gRPC::grpc++)
    target_compile_options(grpc_official_proto PRIVATE
        $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-w>)

    add_executable(grpc_unary_official_tests
        grpc_tests.cpp
        unary_official_tests.cpp)
    target_link_libraries(grpc_unary_official_tests PRIVATE
        grpc_official_proto
        Boost::ut)
    set_property(TARGET grpc_official_proto grpc_unary_official_tests PROPERTY CXX_CLANG_TIDY "" )

    add_test(NAME grpc_unary_official_tests
        COMMAND ${Python3_EXECUTABLE} "${GRPC_TEST_RUNNER}" $<TARGET_FILE:grpc_test_server> $<TARGET_FILE:grpc_unary_official_tests>
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()
