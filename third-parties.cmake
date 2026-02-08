include(cmake/CPM.cmake)

find_package(Git REQUIRED)

if(CMAKE_VERSION GREATER_EQUAL 3.25)
    set(system_package SYSTEM)
endif()

set(HPP_PROTO_GLAZE_VERSION 7.0.2)
CPMAddPackage(
    NAME glaze
    GIT_TAG v${HPP_PROTO_GLAZE_VERSION}
    GITHUB_REPOSITORY stephenberry/glaze
    ${system_package}
)
if(glaze_ADDED)
    install(SCRIPT "${glaze_BINARY_DIR}/cmake_install.cmake")
endif()

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

set_target_properties(is_utf8 PROPERTIES CXX_CLANG_TIDY "")

if(HPP_PROTO_PROTOC_PLUGIN)
    set(HPP_PROTO_PROTOC_VERSION "33.5")

    if(HPP_PROTO_PROTOC STREQUAL "find")
        include(cmake/protoc_find.cmake)
        hpp_proto_find_protoc()
    elseif(HPP_PROTO_PROTOC STREQUAL "compile")
        include(cmake/protoc_compile.cmake)
        hpp_proto_compile_protoc()
    else()
        message(FATAL_ERROR "HPP_PROTO_PROTOC must be set to 'find' or 'compile'")
    endif()
endif()

if(HPP_PROTO_TESTS)
    CPMAddPackage(
        NAME ut
        GITHUB_REPOSITORY boost-ext/ut
        VERSION 2.3.1
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
        VERSION 1.9.4
        OPTIONS
        "BENCHMARK_ENABLE_TESTING OFF"
        "BENCHMARK_ENABLE_INSTALL OFF"
    )
endif()
