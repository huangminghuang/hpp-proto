add_library(person INTERFACE)
target_include_directories(person INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET person
    PROTOS person.proto
    LANGUAGE hpp
    PLUGIN_OPTIONS non_owning)
add_executable(compile_time_serialization compile_time_serialization.cpp)
target_link_libraries(compile_time_serialization PRIVATE person)
