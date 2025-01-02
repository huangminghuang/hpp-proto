# find_package(Protobuf CONFIG) # REQUIRED for find_package(gRPC) to work
find_package(gRPC CONFIG 1.66)

if(gRPC_FOUND)
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
endif()