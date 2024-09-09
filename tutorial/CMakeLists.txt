cmake_minimum_required(VERSION 3.24)

project(hpp_proto_tutorial 
        VERSION 1.0.0
        LANGUAGES CXX)

if(PROJECT_IS_TOP_LEVEL)
  find_package(hpp_proto CONFIG REQUIRED)  
endif()


add_subdirectory(regular)
add_subdirectory(non_owning)
add_subdirectory(mixed_ownership)
add_subdirectory(compile_time_serialization)
add_subdirectory(dynamic_serializer)