cmake_minimum_required(VERSION 3.14)

project(hpp_proto_tutorial 
        VERSION 1.0.0
        LANGUAGES CXX)


find_package(hpp_proto REQUIRED)


add_hpp_proto_lib(tutorial_lib
    INPUT_DIR   ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_DIR  ${CMAKE_CURRENT_BINARY_DIR}
    PROTO_FILES tutorial.proto)


add_executable(tutorial_proto tutorial_proto.cpp)
target_link_libraries(tutorial_proto PRIVATE tutorial_lib)

add_executable(tutorial_json tutorial_json.cpp)
target_link_libraries(tutorial_json PRIVATE tutorial_lib)