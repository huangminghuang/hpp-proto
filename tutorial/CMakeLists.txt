cmake_minimum_required(VERSION 3.24)

project(hpp_proto_tutorial 
        VERSION 1.0.0
        LANGUAGES CXX)

if(PROJECT_IS_TOP_LEVEL)
  find_package(hpp_proto CONFIG REQUIRED)
else()
  # disable clang-tidy check for generated file
  configure_file(../clang-tidy-disable-all-checks .clang-tidy)
endif()


add_subdirectory(regular)
add_subdirectory(non_owning)
add_subdirectory(mixed_ownership)