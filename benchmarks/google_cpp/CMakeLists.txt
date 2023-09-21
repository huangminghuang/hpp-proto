
function(add_google_proto_lib target)
    set(oneValueArgs OUTPUT_DIR INPUT_DIR)
    set(multiValueArgs PROTO_FILES INCLUDE_DIRS)
    cmake_parse_arguments(CPP "${options}" "${oneValueArgs}"
                          "${multiValueArgs}" ${ARGN})

    if (NOT CPP_INPUT_DIR)
        set(CPP_INPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
    endif()

    if (NOT CPP_OUTPUT_DIR)
        set(CPP_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR})
    endif()

    foreach(PROTO ${CPP_PROTO_FILES})
        cmake_path(ABSOLUTE_PATH PROTO BASE_DIRECTORY ${CPP_OUTPUT_DIR} OUTPUT_VARIABLE FILE_BASE)
        cmake_path(REPLACE_EXTENSION FILE_BASE LAST_ONLY ".pb.h" OUTPUT_VARIABLE HEADER)
        cmake_path(REPLACE_EXTENSION FILE_BASE LAST_ONLY ".pb.cc" OUTPUT_VARIABLE SRC)
        list(APPEND GENERATED_FILES ${HEADER} ${SRC})
        list(APPEND SOURCE_FILES ${CPP_INPUT_DIR}/${PROTO})
    endforeach()
    
    set(INCLUDE_DIRS ${CPP_INPUT_DIR} ${CPP_INCLUDE_DIRS})

    list(TRANSFORM INCLUDE_DIRS PREPEND -I)

    add_custom_command(
        COMMENT "processing ${CPP_PROTO_FILES}"
        OUTPUT ${GENERATED_FILES}
        COMMAND ${COMMAND_PREFIX} $<TARGET_FILE:protoc> --cpp_out=${CPP_OUTPUT_DIR} ${INCLUDE_DIRS} ${CPP_PROTO_FILES}
        DEPENDS protoc ${SOURCE_FILES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        VERBATIM
    )

    add_library(${target} INTERFACE)
    target_sources(${target} INTERFACE ${GENERATED_FILES})
    target_include_directories(${target} INTERFACE ${CPP_OUTPUT_DIR})
    target_link_libraries(${target} INTERFACE libprotobuf)
    target_compile_features(${target} INTERFACE cxx_std_20)
endfunction()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../../clang-tidy-disable-all-checks .clang-tidy)

add_google_proto_lib(benchmark_messages_google_proto2_lib
    INPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..
    PROTO_FILES benchmark_messages_proto2.proto
)

add_google_proto_lib(benchmark_messages_google_proto3_lib
    INPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..
    PROTO_FILES benchmark_messages_proto3.proto
)

get_filename_component(DATA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)

if (NOT HPP_ENABLE_CLANG_TIDY)
    add_executable(google_cpp_proto2_msg1_bench google_cpp_benchmark.cpp)
    target_compile_definitions(google_cpp_proto2_msg1_bench PRIVATE PROTO2)
    target_link_libraries(google_cpp_proto2_msg1_bench benchmark_messages_google_proto2_lib)
    target_include_directories(google_cpp_proto2_msg1_bench PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/..)

    add_executable(google_cpp_proto3_msg1_bench google_cpp_benchmark.cpp)
    target_compile_definitions(google_cpp_proto3_msg1_bench PRIVATE PROTO3)
    target_link_libraries(google_cpp_proto3_msg1_bench benchmark_messages_google_proto3_lib)
    target_include_directories(google_cpp_proto3_msg1_bench PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/..)
endif()

