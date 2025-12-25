
if(NOT GRPC_SUPPORT)
    message(STATUS "gRPC not supported, skipping grpc tutorial targets")
    return()
endif()

# # when sanitizer is enable, we can't use gRPC unless the gRPC library is built with sanitizer.
add_library(helloworld INTERFACE)

protobuf_generate_hpp(TARGET helloworld
    PROTOS helloworld.proto)

target_link_libraries(helloworld INTERFACE gRPC::grpc++ hpp_proto::well_known_types)
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
