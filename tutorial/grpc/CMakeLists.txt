find_package(gRPC CONFIG 1.51)

if(gRPC_FOUND AND NOT HPP_PROTO_ENABLE_SANITIZERS)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        include(CheckCXXSourceCompiles)

        # Check for libc++
        check_cxx_source_compiles("
            #include <string>
            #ifdef _LIBCPP_VERSION
            int main() { return 0; }
            #else
            #error Not libc++
            #endif
            " HAS_LIBCXX)

        if(HAS_LIBCXX)
            get_target_property(LIBGRPC_PATH gRPC::grpc++ LOCATION)
            execute_process(
                COMMAND ldd "${LIBGRPC_PATH}"
                OUTPUT_VARIABLE LDD_OUTPUT
                RESULT_VARIABLE LDD_RESULT
                OUTPUT_STRIP_TRAILING_WHITESPACE
            )
            if(LDD_RESULT EQUAL 0)
                string(FIND LDD_OUTPUT "libc++" LIBCXX_FOUND)
                if(LIBCXX_FOUND EQUAL -1)
                    message(WARNING "gRPC library is not built with libc++. Skipping grpc example.")
                    return()
                endif()
            else()
                message(FATAL_ERROR "Failed to run ldd on gRPC library: ${LDD_OUTPUT}")
            endif()
        endif()
    endif()

    # # when sanitizer is enable, we can't use gRPC unless the gRPC library is built with sanitizer.
    add_library(helloworld INTERFACE)

    protobuf_generate_hpp(TARGET helloworld
        PROTOS helloworld.proto)

    target_link_libraries(helloworld INTERFACE gRPC::grpc++)
    target_include_directories(helloworld INTERFACE ${CMAKE_CURRENT_BINARY_DIR})

    add_executable(greeter_client
        greeter_client.cpp
    )
    target_link_libraries(greeter_client PRIVATE
        helloworld)

    add_executable(greeter_server
        greeter_server.cpp
    )

    target_link_libraries(greeter_server PRIVATE
        helloworld)

    find_program(BASH_PATH bash)

    if(BASH_PATH)
        add_test(NAME greeter_test
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/greeter_test.sh
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        set_tests_properties(greeter_test PROPERTIES TIMEOUT 30)
    endif()
endif()