add_library(addressbook_lite INTERFACE)
target_include_directories(addressbook_lite INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET addressbook_lite
    PROTOS addressbook_lite.proto
    LANGUAGE hpp
    PLUGIN_OPTIONS non_owning)
add_executable(compile_time_serialization compile_time_serialization.cpp)
target_link_libraries(compile_time_serialization PRIVATE addressbook_lite)
