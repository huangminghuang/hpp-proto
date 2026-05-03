function(hpp_proto_register_clang_tidy_input_targets)
    foreach(_hpp_proto_clang_tidy_input IN LISTS ARGN)
        if(TARGET ${_hpp_proto_clang_tidy_input})
            set_property(GLOBAL APPEND PROPERTY
                HPP_PROTO_CLANG_TIDY_INPUT_TARGETS
                ${_hpp_proto_clang_tidy_input})
        endif()
    endforeach()
endfunction()
