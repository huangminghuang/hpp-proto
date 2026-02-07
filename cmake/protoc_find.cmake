function(hpp_proto_find_protoc)
    find_program(PROTOC_PROGRAM NAMES protoc)
    # Give opportunity to users to provide an external protoc executable
    # (this is a feature of official FindProtobuf.cmake)
    set(Protobuf_PROTOC_EXECUTABLE ${PROTOC_PROGRAM} CACHE FILEPATH "The protoc compiler")
    if(PROTOC_PROGRAM)
        execute_process(
            COMMAND "${PROTOC_PROGRAM}" --version
            OUTPUT_VARIABLE protoc_version_output
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        string(REGEX MATCH "[0-9]+(\\.[0-9]+)*" Protobuf_VERSION "${protoc_version_output}")
        message(Protobuf_VERSION=${Protobuf_VERSION})
        get_filename_component(PROTOC_BASE_DIR ${PROTOC_PROGRAM} DIRECTORY)
        get_filename_component(PROTOBUF_INCLUDE_DIR "${PROTOC_BASE_DIR}/../include" ABSOLUTE)

        if(EXISTS ${PROTOBUF_INCLUDE_DIR}/google/protobuf/any.proto)
            set(Protobuf_INCLUDE_DIRS ${PROTOBUF_INCLUDE_DIR} PARENT_SCOPE)
            message(Protobuf_INCLUDE_DIRS=${Protobuf_INCLUDE_DIRS})
        endif()

        add_executable(protoc IMPORTED GLOBAL)
        set_property(TARGET protoc PROPERTY IMPORTED_LOCATION ${PROTOC_PROGRAM})
        add_executable(hpp_proto::protoc ALIAS protoc)
    else()
        message(FATAL_ERROR "Could not find 'protoc', you can\n"
            "  - make sure 'protoc' is available in your PATH system variable, or\n"
            "  - use '-DHPP_PROTO_PROTOC=compile' for compiling protoc from source, or\n"
            "  - use '-DHPP_PROTO_PROTOC=download' for downloading a prebuilt protoc, or\n"
            "  - use '-DProtobuf_PROTOC_EXECUTABLE=/path/to/bin/protoc' to specify the absolute path of protoc.")
    endif()
endfunction()
