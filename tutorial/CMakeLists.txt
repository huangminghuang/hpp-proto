cmake_minimum_required(VERSION 3.24)

project(hpp_proto_tutorial 
        VERSION 1.0.0
        LANGUAGES CXX)

if(PROJECT_IS_TOP_LEVEL)
  find_package(hpp_proto CONFIG REQUIRED)
endif()

if (MSVC)
  add_compile_options("/Zc:preprocessor" "/W4")
else()
  add_compile_options("-Wall" "-Wall" "-Wextra" "-Wpedantic")
endif()

add_library(tutorial_lib INTERFACE tutorial.proto)
target_include_directories(tutorial_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET tutorial_lib
                  LANGUAGE hpp)

add_executable(tutorial_proto tutorial_proto.cpp)
target_link_libraries(tutorial_proto PRIVATE tutorial_lib)

add_executable(tutorial_json tutorial_json.cpp)
target_link_libraries(tutorial_json PRIVATE tutorial_lib)