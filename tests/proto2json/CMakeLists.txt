add_library(proto2json proto2json.cpp)
target_include_directories(proto2json PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(proto2json PRIVATE libprotobuf libprotoc)