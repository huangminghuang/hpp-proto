add_library(addressbook_lite INTERFACE)
target_include_directories(addressbook_lite INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET addressbook_lite
    PROTOS addressbook_lite.proto
    LANGUAGE hpp
    PLUGIN_OPTIONS non_owning)
add_executable(consteval_proto main.cpp)
target_link_libraries(consteval_proto PRIVATE addressbook_lite)
