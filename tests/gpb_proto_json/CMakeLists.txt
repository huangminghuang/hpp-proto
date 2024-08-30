
include(GenerateExportHeader)

if(NOT TARGET absl::status)
  find_package(absl REQUIRED)
endif()

add_library(gpb_proto_json SHARED gpb_proto_json.cpp)
target_include_directories(gpb_proto_json PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(gpb_proto_json PUBLIC protobuf::libprotobuf protobuf::libprotoc absl::status)
generate_export_header(gpb_proto_json)

set_target_properties(gpb_proto_json
  PROPERTIES
  POSITION_INDEPENDENT_CODE 1
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN 1
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/..
)