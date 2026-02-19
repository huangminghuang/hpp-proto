if( NOT TARGET hpp_proto::protoc )
    if( NOT PROTOC_PROGRAM )
        # Locate protoc executable
        # Workaround for legacy "cmake" generator in case of cross-build
        if( CMAKE_CROSSCOMPILING )
            find_program( PROTOC_PROGRAM NAMES protoc PATHS ENV PATH NO_DEFAULT_PATH )
        endif()

        # And here this will work fine with "CMakeToolchain" (for native & cross-build)
        # and legacy "cmake" generator in case of native build
        if( NOT PROTOC_PROGRAM )
            find_program( PROTOC_PROGRAM NAMES protoc )
        endif()
    endif()

    if( NOT PROTOC_PROGRAM )
        message( FATAL_ERROR "Could not find 'protoc'. Set PROTOC_PROGRAM to an absolute path." )
    endif()

    get_filename_component( PROTOC_PROGRAM "${PROTOC_PROGRAM}" ABSOLUTE )

    if( NOT EXISTS "${PROTOC_PROGRAM}" OR IS_DIRECTORY "${PROTOC_PROGRAM}" )
        message( FATAL_ERROR "PROTOC_PROGRAM must be an existing file: ${PROTOC_PROGRAM}" )
    endif()

    # Create executable imported target hpp_proto::protoc
    add_executable( hpp_proto::protoc IMPORTED )
    set_property( TARGET hpp_proto::protoc PROPERTY IMPORTED_LOCATION "${PROTOC_PROGRAM}" )
endif()

if( NOT TARGET hpp_proto::protoc-gen-hpp )
    # Create executable imported target hpp_proto::protoc-gen-hpp
    add_executable( hpp_proto::protoc-gen-hpp IMPORTED )
    set_property( TARGET hpp_proto::protoc-gen-hpp PROPERTY IMPORTED_LOCATION "${PROTOC_GEN_HPP_PROGRAM}" )
endif()
