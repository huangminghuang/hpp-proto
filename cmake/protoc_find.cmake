function(hpp_proto_find_protoc)
    if(NOT PROTOC_PROGRAM)
        find_program(PROTOC_PROGRAM NAMES protoc)
    endif()
    if(PROTOC_PROGRAM)
        get_filename_component(PROTOC_PROGRAM "${PROTOC_PROGRAM}" ABSOLUTE)
        if(NOT EXISTS "${PROTOC_PROGRAM}" OR IS_DIRECTORY "${PROTOC_PROGRAM}")
            message(FATAL_ERROR "PROTOC_PROGRAM must be an existing file: ${PROTOC_PROGRAM}")
        endif()
        execute_process(
            COMMAND "${PROTOC_PROGRAM}" --version
            OUTPUT_VARIABLE protoc_version_output
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        string(REGEX MATCH "[0-9]+(\\.[0-9]+)*" Protobuf_VERSION "${protoc_version_output}")
        set(Protobuf_VERSION ${Protobuf_VERSION} PARENT_SCOPE)
        get_filename_component(PROTOC_BASE_DIR ${PROTOC_PROGRAM} DIRECTORY)
        get_filename_component(PROTOBUF_INCLUDE_DIR "${PROTOC_BASE_DIR}/../include" ABSOLUTE)

        if(EXISTS ${PROTOBUF_INCLUDE_DIR}/google/protobuf/any.proto)
            set(Protobuf_INCLUDE_DIRS ${PROTOBUF_INCLUDE_DIR} PARENT_SCOPE)
        endif()

        if(NOT TARGET protoc)
            add_executable(protoc IMPORTED GLOBAL)
        endif()
        set_property(TARGET protoc PROPERTY IMPORTED_LOCATION "${PROTOC_PROGRAM}")
        if(NOT TARGET hpp_proto::protoc)
            add_executable(hpp_proto::protoc ALIAS protoc)
        endif()
    else()
        message(FATAL_ERROR "Could not find 'protoc', you can\n"
            "  - make sure 'protoc' is available in your PATH system variable, or\n"
            "  - use '-DHPP_PROTO_PROTOC=compile' for compiling protoc from source, or\n"
            "  - use '-DPROTOC_PROGRAM=/path/to/bin/protoc' to specify the absolute path of protoc, or"
            "  - for vcpkg, use feature 'vcpkg-protobuf'.\n"
)
    endif()
endfunction()
