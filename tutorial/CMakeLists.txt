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

add_subdirectory(regular)
add_subdirectory(non_owning)
add_subdirectory(mixed_ownership)