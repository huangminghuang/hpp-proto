if (CMAKE_CROSSCOMPILING)
    # Since we are cross-compiling, we use the pre-built version of the program.
    find_program(HPP_HOST_TOOL_PATH
            NAMES protoc-gen-hpp
            NO_CMAKE_FIND_ROOT_PATH
    )

    if(NOT HPP_HOST_TOOL_PATH)
        message(FATAL_ERROR
                "Cross-compiling: 'protoc-gen-hpp' not found in PATH. "
                "Please install it on the host or provide -DHPP_HOST_TOOL_PATH."
        )
    endif()

    # Make the binary available as imported target.
    add_executable(protoc-gen-hpp IMPORTED GLOBAL)
    set_target_properties(protoc-gen-hpp PROPERTIES
            IMPORTED_LOCATION "${HPP_HOST_TOOL_PATH}"
    )

    add_executable(hpp_proto::protoc-gen-hpp ALIAS protoc-gen-hpp)

    message(STATUS "Using host protoc-gen-hpp: ${HPP_HOST_TOOL_PATH}")
    return()
endif ()

add_compile_options(${HPP_PROTO_COMPILE_OPTIONS})

add_executable(protoc-gen-hpp hpp_gen.cpp)
target_compile_definitions(protoc-gen-hpp PRIVATE HPP_PROTO_VERSION="${PROJECT_VERSION}")
add_executable(hpp_proto::protoc-gen-hpp ALIAS protoc-gen-hpp)
target_compile_features(protoc-gen-hpp PRIVATE cxx_std_23)
target_link_libraries(protoc-gen-hpp PRIVATE hpp_proto::hpp_proto_core)

set_target_properties(protoc-gen-hpp
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
install(TARGETS protoc-gen-hpp EXPORT hpp_proto-targets)

if(MSVC)
    target_compile_definitions(protoc-gen-hpp PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(protoc-gen-hpp PRIVATE /bigobj)
endif()
