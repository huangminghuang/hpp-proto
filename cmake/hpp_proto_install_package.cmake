include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  lib/cmake/hpp_proto/hpp_proto-config-version.cmake
  COMPATIBILITY AnyNewerVersion
)

if(HPP_PROTO_PROTOC STREQUAL "compile")
  # copy google proto files into include directory
  file(GLOB GOOGLE_PROTOFILES RELATIVE "${protobuf_SOURCE_DIR}/src/google/protobuf" "${protobuf_SOURCE_DIR}/src/google/protobuf/*.proto")
  list(FILTER GOOGLE_PROTOFILES EXCLUDE REGEX ".*test.*")
  list(APPEND GOOGLE_PROTOFILES "compiler/plugin.proto")

  foreach(f ${GOOGLE_PROTOFILES})
    configure_file(${protobuf_SOURCE_DIR}/src/google/protobuf/${f} include/google/protobuf/${f} COPYONLY)
  endforeach()

  install(TARGETS protoc EXPORT hpp_proto-targets)
endif()




configure_file(hpp_proto-config.cmake.in lib/cmake/hpp_proto/hpp_proto-config.cmake @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/hpp_proto/hpp_proto-config.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/lib/cmake/hpp_proto/hpp_proto-config-version.cmake"
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/protobuf_generate_hpp.cmake"
  DESTINATION "lib/cmake/hpp_proto")

install(
  TARGETS is_utf8
  EXPORT hpp_proto-targets
)

install(EXPORT hpp_proto-targets
  DESTINATION lib/cmake/hpp_proto
  NAMESPACE hpp_proto::)
export(EXPORT hpp_proto-targets FILE lib/cmake/hpp_proto/hpp_proto-targets.cmake
  NAMESPACE hpp_proto::)
