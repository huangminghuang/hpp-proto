include(cmake/CPM.cmake)
CPMUsePackageLock("${CMAKE_CURRENT_LIST_DIR}/cpm-package-lock.cmake")

find_package(Git REQUIRED)

if(CMAKE_VERSION GREATER_EQUAL 3.25)
    set(system_package SYSTEM)
endif()

set(HPP_PROTO_GLAZE_VERSION 7.8.4)
set(HPP_PROTO_GLAZE_COMMIT 0a21fd9dbd36963790b6f26b9539050e13d78649)
CPMAddPackage(
    NAME glaze
    VERSION ${HPP_PROTO_GLAZE_VERSION}
    GIT_TAG ${HPP_PROTO_GLAZE_COMMIT}
    GITHUB_REPOSITORY stephenberry/glaze
    OPTIONS "glaze_INSTALL ON"
    ${system_package}
)
if(glaze_ADDED)
    install(SCRIPT "${glaze_BINARY_DIR}/cmake_install.cmake")
endif()

set(HPP_PROTO_IS_UTF8_VERSION 1.4.1)
set(HPP_PROTO_IS_UTF8_COMMIT 77103c7462b9498f0bbc238260d1f1408a66a461)
if(NOT CPM_LOCAL_PACKAGES_ONLY)
    CPMAddPackage(
        NAME is_utf8
        VERSION ${HPP_PROTO_IS_UTF8_VERSION}
        GIT_TAG ${HPP_PROTO_IS_UTF8_COMMIT}
        GITHUB_REPOSITORY simdutf/is_utf8
        DOWNLOAD_ONLY ON
    )
    add_subdirectory(${is_utf8_SOURCE_DIR}/src ${is_utf8_BINARY_DIR})
    add_library(is_utf8::is_utf8 ALIAS is_utf8)
    target_compile_features(is_utf8 PRIVATE cxx_std_20)
    get_target_property(IS_UTF8_COMPILER_OPTIONS is_utf8 COMPILE_OPTIONS)

    if(IS_UTF8_COMPILER_OPTIONS MATCHES "fsanitize=address")
        message(FATAL_ERROR "is_utf8 is not compatible with address sanitizer")
    endif()

    set_target_properties(is_utf8 PROPERTIES CXX_CLANG_TIDY "")
else()
    find_package(is_utf8 CONFIG REQUIRED)
    set(is_utf8_ADDED OFF)
endif()

set(HPP_PROTO_PROTOC_VERSION "35.0")
set(HPP_PROTO_PROTOC_COMMIT e59364c38e10de3686a3305ff11fbfc59a10dbd8)
set(HPP_PROTO_ABSEIL_VERSION "20250512.1")
set(HPP_PROTO_ABSEIL_COMMIT 76bb24329e8bf5f39704eb10d21b9a80befa7c81)

if(HPP_PROTO_CORE_TESTS_ONLY)
    message(STATUS "HPP_PROTO_CORE_TESTS_ONLY=ON: skipping protoc setup")
elseif(HPP_PROTO_PROTOC STREQUAL "find")
    include(cmake/protoc_find.cmake)
    hpp_proto_find_protoc()
elseif(HPP_PROTO_PROTOC STREQUAL "compile")
    include(cmake/protoc_compile.cmake)
    hpp_proto_compile_protoc()
else()
    message(FATAL_ERROR "HPP_PROTO_PROTOC must be set to 'find' or 'compile'")
endif()

if(HPP_PROTO_TESTS)
    set(HPP_PROTO_UT_VERSION 2.3.1)
    set(HPP_PROTO_UT_COMMIT f923e6fe4b7542d75e0c4ee54ad0af6a5382a87c)
    CPMAddPackage(
        NAME ut
        GITHUB_REPOSITORY boost-ext/ut
        VERSION ${HPP_PROTO_UT_VERSION}
        GIT_TAG ${HPP_PROTO_UT_COMMIT}
        DOWNLOAD_ONLY ON
    )
    add_library(Boost::ut INTERFACE IMPORTED)
    target_include_directories(Boost::ut INTERFACE ${ut_SOURCE_DIR}/include)
    target_compile_definitions(Boost::ut INTERFACE BOOST_UT_DISABLE_MODULE)
endif(HPP_PROTO_TESTS)

if(HPP_PROTO_BENCHMARKS)
    set(HPP_PROTO_BENCHMARK_VERSION 1.9.5)
    set(HPP_PROTO_BENCHMARK_COMMIT 192ef10025eb2c4cdd392bc502f0c852196baa48)
    CPMAddPackage(
        NAME benchmark
        GITHUB_REPOSITORY google/benchmark
        VERSION ${HPP_PROTO_BENCHMARK_VERSION}
        GIT_TAG ${HPP_PROTO_BENCHMARK_COMMIT}
        OPTIONS
        "BENCHMARK_ENABLE_TESTING OFF"
        "BENCHMARK_ENABLE_INSTALL OFF"
    )
endif()
