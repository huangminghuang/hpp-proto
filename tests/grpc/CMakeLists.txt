
if (HPP_PROTO_PROTOC STREQUAL "compile")
    return()
endif()

find_package(gRPC CONFIG 1.51)

if(NOT gRPC_FOUND)
    message(WARNING "gRPC not found, skipping grpc_quality_tests target")
    return()
endif()

if (HPP_PROTO_ENABLE_SANITIZERS)
    # Unless we compile the grpc library direct with sanitizers; otherwise, we
    # will have false positives. Just disable the sanitizer entirely.
    add_compile_options(-fno-sanitize=${HPP_PROTO_ENABLE_SANITIZERS})
    add_link_options(-fno-sanitize=${HPP_PROTO_ENABLE_SANITIZERS})
endif()

include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES gRPC::grpc++)
check_cxx_source_compiles("
      #include <grpcpp/grpcpp.h>
      int main() {
        grpc::CreateChannel(\"127.0.0.0:1234\", grpc::InsecureChannelCredentials());
        return 0;
      }
    " HPP_PROTO_GRPC_TESTS_COMPILE)
set(CMAKE_REQUIRED_LIBRARIES)

if(NOT HPP_PROTO_GRPC_TESTS_COMPILE)
    message(WARNING "gRPC headers found but compilation failed, skipping grpc_quality_tests target")
    return()
endif()

add_library(grpc_quality_proto_lib INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/echo_stream.proto")
target_include_directories(grpc_quality_proto_lib SYSTEM INTERFACE
    ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(
    TARGET grpc_quality_proto_lib
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/.."
    PROTOC_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(grpc_quality_proto_lib INTERFACE gRPC::grpc++)

set(GRPC_QUALITY_TEST_CASES
    unary_tests.cpp
    client_stream_tests.cpp
    server_stream_tests.cpp
    bidi_stream_tests.cpp)

foreach(test_src IN LISTS GRPC_QUALITY_TEST_CASES)
    get_filename_component(test_name "${test_src}" NAME_WE)
    set(target_name "grpc_${test_name}")

    add_executable(${target_name}
        grpc_quality_tests.cpp
        "${test_src}")
    target_link_libraries(${target_name} PRIVATE
        grpc_quality_proto_lib
        hpp_proto::libhpp_proto
        Boost::ut
        glaze::glaze
        gRPC::grpc++)
    target_include_directories(${target_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME ${target_name}
        COMMAND ${target_name}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endforeach()
