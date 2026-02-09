
if(HPP_PROTO_PROTOC STREQUAL "compile")
    return()
endif()

if(NOT GRPC_SUPPORT)
    message(STATUS "gRPC not supported, skipping grpc test targets")
    return()
endif()

add_library(grpc_proto_lib INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/echo_stream.proto")
protobuf_generate_hpp(
    TARGET grpc_proto_lib
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/.."
    PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(grpc_proto_lib INTERFACE gRPC::grpc++)

set(GRPC_TEST_CASES
    unary_tests.cpp
    client_stream_tests.cpp
    server_stream_tests.cpp
    bidi_stream_tests.cpp
    server_failure_tests.cpp)

add_executable(grpc_test_server
    grpc_test_server.cpp)
target_link_libraries(grpc_test_server PRIVATE
    grpc_proto_lib
    hpp_proto::libhpp_proto
    gRPC::grpc++)

set(GRPC_TEST_RUNNER "${CMAKE_CURRENT_SOURCE_DIR}/run_grpc_test.py")

foreach(test_src IN LISTS GRPC_TEST_CASES)
    get_filename_component(test_name "${test_src}" NAME_WE)
    set(target_name "grpc_${test_name}")

    add_executable(${target_name}
        grpc_tests.cpp
        "${test_src}")
    target_link_libraries(${target_name} PRIVATE
        grpc_proto_lib
        libhpp_proto
        Boost::ut
        glaze::glaze
        gRPC::grpc++)
    add_test(NAME ${target_name}
        COMMAND $<TARGET_FILE:${target_name}>
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endforeach()

add_executable(grpc_serialization_tests
    grpc_tests.cpp
    grpc_serialization_tests.cpp)
target_link_libraries(grpc_serialization_tests PRIVATE
    grpc_proto_lib
    hpp_proto::libhpp_proto
    Boost::ut
    glaze::glaze
    gRPC::grpc++)
add_test(NAME grpc_serialization_tests
    COMMAND $<TARGET_FILE:grpc_serialization_tests>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set(GRPC_OFFICIAL_PROTO_AVAILABLE OFF)

if(TARGET protobuf::libprotobuf AND TARGET protobuf::protoc AND TARGET gRPC::grpc_cpp_plugin)
    set(GRPC_OFFICIAL_PROTO_AVAILABLE ON)
else()
    message(WARNING "Skipping official protobuf-based grpc unary test; required protobuf/gRPC targets not found")
endif()

if(GRPC_OFFICIAL_PROTO_AVAILABLE)
    find_package(Python3 COMPONENTS Interpreter)
    if(NOT Python3_Interpreter_FOUND)
        message(WARNING "Python3 interpreter not found, skipping grpc_tests target")
        return()
    endif()

    set(GRPC_OFFICIAL_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/official")
    file(MAKE_DIRECTORY "${GRPC_OFFICIAL_GENERATED_DIR}")

    add_library(grpc_official_proto STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/echo_stream.proto)

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
    target_compile_features(grpc_unary_official_tests PRIVATE cxx_std_23)
    target_link_libraries(grpc_unary_official_tests PRIVATE
        grpc_official_proto
        Boost::ut)
    set_property(TARGET grpc_official_proto grpc_unary_official_tests PROPERTY CXX_CLANG_TIDY "")

    add_test(NAME grpc_interoperability_test
        COMMAND ${Python3_EXECUTABLE} "${GRPC_TEST_RUNNER}" $<TARGET_FILE:grpc_test_server> $<TARGET_FILE:grpc_unary_official_tests>
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()
