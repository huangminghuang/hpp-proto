if (NOT MSVC OR CMAKE_CXX_COMPILER_VERSION VERSION_LESS 19.43)
    add_library(person INTERFACE)
    target_include_directories(person SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
    protobuf_generate_hpp(TARGET person
        PROTOS person.proto
        PLUGIN_OPTIONS non_owning)
    add_executable(compile_time_serialization compile_time_serialization.cpp)
    target_link_libraries(compile_time_serialization PRIVATE person)
endif()
