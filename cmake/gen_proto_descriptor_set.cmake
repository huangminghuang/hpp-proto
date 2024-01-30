
function(gen_proto_descriptor_set out_file)
    set(oneValueArgs "")
        set(multiValueArgs PROTOS IMPORT_DIRS)
        cmake_parse_arguments(HPP "${options}" "${oneValueArgs}"
                            "${multiValueArgs}" ${ARGN})

    if (NOT HPP_IMPORT_DIRS)
        set(HPP_IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR})
    endif()

    foreach(_path ${HPP_IMPORT_DIRS})
        cmake_path(ABSOLUTE_PATH _path BASE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} NORMALIZE OUTPUT_VARIABLE _abs_path)
        list(APPEND _include_dirs ${_abs_path})
    endforeach()

    foreach(_path ${HPP_PROTOS})
        cmake_path(ABSOLUTE_PATH _path BASE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} NORMALIZE OUTPUT_VARIABLE _abs_proto_path)  
        set(_rel_proto_path)     
        foreach(_dir ${_include_dirs})
            cmake_path(IS_PREFIX _dir ${_abs_proto_path} result)
            if (result)
                cmake_path(RELATIVE_PATH _abs_proto_path BASE_DIRECTORY ${_dir} OUTPUT_VARIABLE _rel_proto_path)
                list(APPEND _rel_protos ${_rel_proto_path})
                break()
            endif()
        endforeach()
    endforeach()

    list(TRANSFORM _include_dirs PREPEND -I)

    if (NOT TARGET protobuf::protoc)
      add_exectuable(protobuf::protoc ALIAS hpp_proto::protoc)
    endif()
                            
    add_custom_command(
        COMMENT "Generating ${out_file}"
        OUTPUT  ${out_file}
        COMMAND protobuf::protoc 
        ARGS ${_include_dirs} --include_imports --descriptor_set_out=${out_file} ${_rel_protos}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_custom_target(${out_file}.target ALL
                      DEPENDS ${out_file})
endfunction()