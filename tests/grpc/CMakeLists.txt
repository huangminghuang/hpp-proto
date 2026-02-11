if(NOT GRPC_SUPPORT)
    return()
endif()

add_hpp_proto_generated_test_lib(
    NAME grpc_proto_lib
    SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/echo_stream.proto"
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/.."
    PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}"
    LINK_LIBRARIES gRPC::grpc++)

add_hpp_proto_test(
    NAME grpc_test_server
    SOURCES grpc_test_server.cpp
    LINK_LIBRARIES grpc_proto_lib hpp_proto::hpp_proto_core gRPC::grpc++
    NO_TEST)

set(GRPC_TEST_RUNNER "${CMAKE_CURRENT_SOURCE_DIR}/run_grpc_test.py")

add_hpp_proto_test(
    NAME grpc_unary_tests
    SOURCES grpc_tests.cpp unary_tests.cpp
    LINK_LIBRARIES grpc_proto_lib hpp_proto::hpp_proto_core Boost::ut glaze::glaze gRPC::grpc++)

add_hpp_proto_test(
    NAME grpc_client_stream_tests
    SOURCES grpc_tests.cpp client_stream_tests.cpp
    LINK_LIBRARIES grpc_proto_lib hpp_proto::hpp_proto_core Boost::ut glaze::glaze gRPC::grpc++)

add_hpp_proto_test(
    NAME grpc_server_stream_tests
    SOURCES grpc_tests.cpp server_stream_tests.cpp
    LINK_LIBRARIES grpc_proto_lib hpp_proto::hpp_proto_core Boost::ut glaze::glaze gRPC::grpc++)

add_hpp_proto_test(
    NAME grpc_bidi_stream_tests
    SOURCES grpc_tests.cpp bidi_stream_tests.cpp
    LINK_LIBRARIES grpc_proto_lib hpp_proto::hpp_proto_core Boost::ut glaze::glaze gRPC::grpc++)

add_hpp_proto_test(
    NAME grpc_server_failure_tests
    SOURCES grpc_tests.cpp server_failure_tests.cpp
    LINK_LIBRARIES grpc_proto_lib hpp_proto::hpp_proto_core Boost::ut glaze::glaze gRPC::grpc++)

add_hpp_proto_test(
    NAME grpc_serialization_tests
    SOURCES grpc_tests.cpp grpc_serialization_tests.cpp
    LINK_LIBRARIES grpc_proto_lib hpp_proto::hpp_proto_core Boost::ut glaze::glaze gRPC::grpc++)

if(TARGET protobuf::libprotobuf AND TARGET protobuf::protoc
    AND TARGET gRPC::grpc_cpp_plugin AND Python3_Interpreter_FOUND)
    find_package(Python3 COMPONENTS Interpreter)

    if(NOT Python3_Interpreter_FOUND)
        return()
    endif()

    set(GRPC_OFFICIAL_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/official")
    file(MAKE_DIRECTORY "${GRPC_OFFICIAL_GENERATED_DIR}")

    add_library(grpc_official_proto STATIC ${CMAKE_CURRENT_SOURCE_DIR}/echo_stream.proto)

    protobuf_generate(
        TARGET grpc_official_proto
        LANGUAGE cpp
        IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
        PROTOC_OUT_DIR "${GRPC_OFFICIAL_GENERATED_DIR}"
        PROTOS "${GRPC_OFFICIAL_PROTO}")

    protobuf_generate(
        TARGET grpc_official_proto
        LANGUAGE grpc
        IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
        PROTOC_OUT_DIR "${GRPC_OFFICIAL_GENERATED_DIR}"
        PROTOS "${GRPC_OFFICIAL_PROTO}"
        PLUGIN protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>
        DEPENDENCIES gRPC::grpc_cpp_plugin
        GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc)

    target_include_directories(grpc_official_proto PUBLIC "${GRPC_OFFICIAL_GENERATED_DIR}")
    target_link_libraries(grpc_official_proto PUBLIC protobuf::libprotobuf gRPC::grpc++)
    target_compile_options(grpc_official_proto PRIVATE $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-w>)

    add_hpp_proto_test(
        NAME grpc_unary_official_tests
        SOURCES grpc_tests.cpp unary_official_tests.cpp
        LINK_LIBRARIES grpc_official_proto Boost::ut
        REQUIRES HPP_PROTO_GRPC_OFFICIAL_ENABLED)

    target_compile_features(grpc_unary_official_tests PRIVATE cxx_std_23)
    set_property(TARGET grpc_official_proto grpc_unary_official_tests PROPERTY CXX_CLANG_TIDY "")

    add_test(NAME grpc_interoperability_test
        COMMAND ${Python3_EXECUTABLE} "${GRPC_TEST_RUNNER}" $<TARGET_FILE:grpc_test_server> $<TARGET_FILE:grpc_unary_official_tests>
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()
