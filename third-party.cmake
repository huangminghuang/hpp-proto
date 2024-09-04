include(cmake/CPM.cmake)

CPMAddPackage(
    NAME glaze
    GIT_TAG v2.9.5.mod
    GITHUB_REPOSITORY huangminghuang/glaze
)

CPMAddPackage(
    NAME is_utf8
    VERSION 1.3.2
    GITHUB_REPOSITORY simdutf/is_utf8
    DOWNLOAD_ONLY ON
)

add_subdirectory(${is_utf8_SOURCE_DIR}/src ${is_utf8_BINARY_DIR})

if(HPP_PROTO_TESTS)
    CPMAddPackage(
        NAME ut
        GITHUB_REPOSITORY boost-ext/ut
        VERSION 2.0.1
        DOWNLOAD_ONLY ON
    )
    add_library(Boost::ut INTERFACE IMPORTED)
    target_include_directories(Boost::ut INTERFACE ${ut_SOURCE_DIR}/include)
    target_compile_definitions(Boost::ut INTERFACE BOOST_UT_DISABLE_MODULE)
endif()

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