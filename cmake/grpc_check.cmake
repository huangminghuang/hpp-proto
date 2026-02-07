
find_package(gRPC CONFIG 1.51)
if(NOT GRPC_SUPPORT AND gRPC_FOUND)
    try_compile(GRPC_SUPPORT
        ${CMAKE_CURRENT_BINARY_DIR}/grpc_check
        ${CMAKE_CURRENT_LIST_DIR}/grpc_check.cpp
        LINK_LIBRARIES gRPC::grpc++
    )
endif()
