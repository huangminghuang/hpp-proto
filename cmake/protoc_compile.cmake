function(hpp_proto_compile_protoc)
    set(Protobuf_VERSION "${HPP_PROTO_PROTOC_VERSION}")
    CPMAddPackage(
        NAME protobuf
        VERSION ${Protobuf_VERSION}
        GITHUB_REPOSITORY protocolbuffers/protobuf
        SYSTEM ON
        OPTIONS "ABSL_PROPAGATE_CXX_STD ON"
        "protobuf_FORCE_FETCH_DEPENDENCIES ON"
        "protobuf_INSTALL OFF"
        "protobuf_BUILD_TESTS OFF"
        "protobuf_BUILD_PROTOBUF_BINARIES ON"
        "protobuf_BUILD_PROTOC_BINARIES ON"
        "protobuf_MSVC_STATIC_RUNTIME OFF"
        "EXCLUDE_FROM_ALL"
        ${system_package}
    )
    set_target_properties(protoc
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    add_executable(protobuf::protoc ALIAS protoc)
    set(Protobuf_INCLUDE_DIRS ${protobuf_SOURCE_DIR}/src PARENT_SCOPE)
    # Protobuf's source tree keeps utf8_validity.h under third_party/utf8_range.
    # Add it to the exported include dirs so dependent targets can compile.
    if(TARGET libprotobuf)
        target_include_directories(libprotobuf INTERFACE ${protobuf_SOURCE_DIR}/third_party/utf8_range)
    endif()
    if(TARGET libprotobuf-lite)
        target_include_directories(libprotobuf-lite INTERFACE ${protobuf_SOURCE_DIR}/third_party/utf8_range)
    endif()
endfunction()
