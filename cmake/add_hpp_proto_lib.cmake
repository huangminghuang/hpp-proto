function(add_hpp_proto_lib target)
    set(oneValueArgs OUTPUT_DIR INPUT_DIR)
    set(multiValueArgs PROTO_FILES INCLUDE_DIRS ENVIRONMENTS)
    cmake_parse_arguments(HPP "${options}" "${oneValueArgs}"
                          "${multiValueArgs}" ${ARGN})

    if (NOT HPP_INPUT_DIR)
        set(HPP_INPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
    endif()

    if (NOT HPP_OUTPUT_DIR)
        set(HPP_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR})
    endif()

    foreach(PROTO ${HPP_PROTO_FILES})
        cmake_path(ABSOLUTE_PATH PROTO BASE_DIRECTORY ${HPP_OUTPUT_DIR} OUTPUT_VARIABLE FILE_BASE)
        cmake_path(REPLACE_EXTENSION FILE_BASE LAST_ONLY ".msg.hpp" OUTPUT_VARIABLE MSG)
        cmake_path(REPLACE_EXTENSION FILE_BASE LAST_ONLY ".pb.hpp" OUTPUT_VARIABLE PB_META)
        cmake_path(REPLACE_EXTENSION FILE_BASE LAST_ONLY ".glz.hpp" OUTPUT_VARIABLE GLZ_META)
        list(APPEND GENERATED_FILES ${MSG} ${PB_META} ${GLZ_META})
        list(APPEND SOURCE_FILES ${HPP_INPUT_DIR}/${PROTO})
    endforeach()
    
    set(INCLUDE_DIRS ${HPP_INPUT_DIR} ${HPP_INCLUDE_DIRS})

    list(TRANSFORM INCLUDE_DIRS PREPEND -I)

    if (HPP_ENVIRONMENTS)
        set(COMMAND_PREFIX ${CMAKE_COMMAND} -E env ${HPP_ENVIRONMENTS})
    endif()

    add_custom_command(
        COMMENT "processing ${HPP_PROTO_FILES}"
        OUTPUT ${GENERATED_FILES}
        COMMAND ${COMMAND_PREFIX} $<TARGET_FILE:protoc> --plugin=protoc-gen-hpp=$<TARGET_FILE:protoc-gen-hpp> --hpp_out=${HPP_OUTPUT_DIR} ${INCLUDE_DIRS} ${HPP_PROTO_FILES}
        DEPENDS protoc protoc-gen-hpp ${SOURCE_FILES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        VERBATIM
    )

    add_library(${target} INTERFACE)
    target_sources(${target} INTERFACE ${GENERATED_FILES})
    target_include_directories(${target} INTERFACE ${HPP_OUTPUT_DIR})
    target_link_libraries(${target} INTERFACE hpp_proto::libhpp_proto)
    target_compile_features(${target} INTERFACE cxx_std_20)
endfunction()