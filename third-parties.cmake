include(cmake/CPM.cmake)

find_package(Git REQUIRED)

if (CMAKE_VERSION GREATER_EQUAL 3.25)
    set(system_package SYSTEM)
endif()

CPMAddPackage(
    NAME glaze
    GIT_TAG v5.0.2
    GITHUB_REPOSITORY stephenberry/glaze
    PATCH_COMMAND ${GIT_EXECUTABLE} apply --ignore-space-change --ignore-whitespace ${CMAKE_CURRENT_SOURCE_DIR}/glaze-5.0.2.patch
    UPDATE_DISCONNECTED ON
    ${system_package}
)

CPMAddPackage(
    NAME is_utf8
    VERSION 1.4.1
    GITHUB_REPOSITORY simdutf/is_utf8
    DOWNLOAD_ONLY ON
)
add_subdirectory(${is_utf8_SOURCE_DIR}/src ${is_utf8_BINARY_DIR})
target_compile_features(is_utf8 INTERFACE cxx_std_20)
get_target_property(IS_UTF8_COMPILER_OPTIONS is_utf8 COMPILE_OPTIONS)
if(IS_UTF8_COMPILER_OPTIONS MATCHES "fsanitize=address")
    message(FATAL_ERROR "is_utf8 is not compatible with address sanitizer")
endif()

CPMAddPackage("gh:fmtlib/fmt#11.1.4")
set_target_properties(is_utf8 fmt PROPERTIES CXX_CLANG_TIDY "")


if(HPP_PROTO_PROTOC STREQUAL "find")
    find_package(Protobuf CONFIG)
    if(NOT Protobuf_FOUND)
        find_program(PROTOC_PATH NAMES protoc)

        if(PROTOC_PATH)
            execute_process(
                COMMAND "${PROTOC_PATH}" --version
                OUTPUT_VARIABLE protoc_version_output
                OUTPUT_STRIP_TRAILING_WHITESPACE
            )
            string(REGEX MATCH "[0-9]+(\\.[0-9]+)*" Protobuf_VERSION "${protoc_version_output}")
            message(Protobuf_VERSION=${Protobuf_VERSION})
            get_filename_component(PROTOC_BASE_DIR ${PROTOC_PATH} DIRECTORY)
            get_filename_component(PROTOBUF_INCLUDE_DIR "${PROTOC_BASE_DIR}/../include" ABSOLUTE)

            if(EXISTS ${PROTOBUF_INCLUDE_DIR}/google/protobuf/any.proto)
                set(Protobuf_INCLUDE_DIRS ${PROTOBUF_INCLUDE_DIR})
                message(Protobuf_INCLUDE_DIRS=${Protobuf_INCLUDE_DIRS})
            endif()

            add_executable(protoc IMPORTED GLOBAL)
            set_property(TARGET protoc PROPERTY
                IMPORTED_LOCATION ${PROTOC_PATH})
            add_executable(protobuf::protoc ALIAS protoc)
        else()
            message(FATAL_ERROR "Could not find 'protoc', you can\n"
                "  - make sure 'protoc' is available in your PATH system variable, or\n"
                "  - use '-DHPP_PROTO_PROTOC=compile' for compiling protoc from source, or\n"
                "  - use '-DCMAKE_PROGRAM_PATH=/path/bin' to specify the absolute directory of protoc.")
        endif() 
    else()
        get_target_property(Protobuf_INCLUDE_DIRS protobuf::libprotobuf INTERFACE_INCLUDE_DIRECTORIES)
    endif()
elseif(HPP_PROTO_PROTOC STREQUAL "compile")
    set(Protobuf_VERSION 29.3)
    CPMAddPackage(
        NAME protobuf
        VERSION ${Protobuf_VERSION}
        GITHUB_REPOSITORY protocolbuffers/protobuf
        SYSTEM ON
        OPTIONS "ABSL_PROPAGATE_CXX_STD ON"
        "protobuf_INSTALL OFF"
        "protobuf_BUILD_TESTS OFF"
        "protobuf_BUILD_PROTOBUF_BINARIES ON"
        "protobuf_BUILD_PROTOC_BINARIES ON"
        "EXCLUDE_FROM_ALL"
        ${system_package}
    )
    set_target_properties(protoc
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    add_executable(protobuf::protoc ALIAS protoc)
    set(Protobuf_INCLUDE_DIRS ${protobuf_SOURCE_DIR}/src)
else()
    message(FATAL_ERROR "HPP_PROTO_PROTOC must be set to 'find' or 'compile'")
endif()

if(HPP_PROTO_TESTS)
    CPMAddPackage(
        NAME ut
        GITHUB_REPOSITORY boost-ext/ut
        VERSION 2.3.0
        DOWNLOAD_ONLY ON
    )
    add_library(Boost::ut INTERFACE IMPORTED)
    target_include_directories(Boost::ut INTERFACE ${ut_SOURCE_DIR}/include)
    target_compile_definitions(Boost::ut INTERFACE BOOST_UT_DISABLE_MODULE)
endif(HPP_PROTO_TESTS)

if(HPP_PROTO_BENCHMARKS)
    CPMAddPackage(
        NAME benchmark
        GITHUB_REPOSITORY google/benchmark
        VERSION 1.8.3
        OPTIONS
        "BENCHMARK_ENABLE_TESTING OFF"
        "BENCHMARK_ENABLE_INSTALL OFF"
    )
endif()