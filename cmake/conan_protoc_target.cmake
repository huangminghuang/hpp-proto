if(NOT TARGET hpp_proto::protoc)
    # Locate protoc executable
    ## Workaround for legacy "cmake" generator in case of cross-build
    if(CMAKE_CROSSCOMPILING)
        find_program(PROTOC_PROGRAM NAMES protoc PATHS ENV PATH NO_DEFAULT_PATH)
    endif()
    ## And here this will work fine with "CMakeToolchain" (for native & cross-build)
    ## and legacy "cmake" generator in case of native build
    if(NOT PROTOC_PROGRAM)
        find_program(PROTOC_PROGRAM NAMES protoc)
    endif()
    ## Last resort: we search in package folder directly
    if(NOT PROTOC_PROGRAM)
        set(PROTOC_PROGRAM "${CMAKE_CURRENT_LIST_DIR}/../../../bin/protoc${CMAKE_EXECUTABLE_SUFFIX}")
    endif()
    get_filename_component(PROTOC_PROGRAM "${PROTOC_PROGRAM}" ABSOLUTE)

    # Give opportunity to users to provide an external protoc executable
    # (this is a feature of official FindProtobuf.cmake)
    set(Protobuf_PROTOC_EXECUTABLE ${PROTOC_PROGRAM} CACHE FILEPATH "The protoc compiler")

    # Create executable imported target protobuf::protoc
    add_executable(protobuf::protoc IMPORTED)
    set_property(TARGET protobuf::protoc PROPERTY IMPORTED_LOCATION ${Protobuf_PROTOC_EXECUTABLE})
endif()

if(NOT TARGET hpp_proto::protoc-gen-hpp)
    # Locate protoc-gen-hpp executable
    ## Workaround for legacy "cmake" generator in case of cross-build
    if(CMAKE_CROSSCOMPILING)
        find_program(PROTOC_GEN_HPP_PROGRAM NAMES protoc-gen-hpp PATHS ENV PATH NO_DEFAULT_PATH)
    endif()
    ## And here this will work fine with "CMakeToolchain" (for native & cross-build)
    ## and legacy "cmake" generator in case of native build
    if(NOT PROTOC_GEN_HPP_PROGRAM)
        find_program(PROTOC_GEN_HPP_PROGRAM NAMES protoc-gen-hpp)
    endif()
    ## Last resort: we search in package folder directly
    if(NOT PROTOC_GEN_HPP_PROGRAM)
        set(PROTOC_GEN_HPP_PROGRAM "${CMAKE_CURRENT_LIST_DIR}/../../../bin/protoc-gen-hpp${CMAKE_EXECUTABLE_SUFFIX}")
    endif()
    get_filename_component(PROTOC_GEN_HPP_PROGRAM "${PROTOC_GEN_HPP_PROGRAM}" ABSOLUTE)

    # Give opportunity to users to provide an external protoc executable
    # (this is a feature of official FindProtobuf.cmake)
    set(PROTOC_GEN_HPP_EXECUTABLE ${PROTOC_GEN_HPP_PROGRAM} CACHE FILEPATH "The protoc-gen-hpp compiler")

    # Create executable imported target hpp_proto::protoc-gen-hpp
    add_executable(hpp_proto::protoc-gen-hpp IMPORTED)
    set_property(TARGET hpp_proto::protoc-gen-hpp PROPERTY IMPORTED_LOCATION ${PROTOC_GEN_HPP_EXECUTABLE})
endif()