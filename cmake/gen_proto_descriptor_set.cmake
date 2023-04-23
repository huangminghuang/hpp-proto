
function(gen_proto_descriptor_set out_file)
    set(oneValueArgs INPUT_DIR)
        set(multiValueArgs PROTO_FILES INCLUDE_DIRS)
        cmake_parse_arguments(HPP "${options}" "${oneValueArgs}"
                            "${multiValueArgs}" ${ARGN})

    if (NOT HPP_INPUT_DIR)
        set(HPP_INPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
    endif()
    
    set(INCLUDE_DIRS ${HPP_INPUT_DIR} ${HPP_INCLUDE_DIRS})

    list(TRANSFORM INCLUDE_DIRS PREPEND -I)
                            
    add_custom_command(
        COMMENT "Generating ${out_file}"
        OUTPUT  ${out_file}
        COMMAND protoc ${INCLUDE_DIRS} --include_imports --descriptor_set_out=${out_file} ${HPP_PROTO_FILES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endfunction()