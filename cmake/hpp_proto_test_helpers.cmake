function(hpp_proto_requires_any out_var)
    set(_hpp_proto_requires_any_enabled FALSE)
    foreach(_required_var IN LISTS ARGN)
        if(DEFINED ${_required_var} AND ${_required_var})
            set(_hpp_proto_requires_any_enabled TRUE)
            break()
        endif()
    endforeach()

    set(${out_var} ${_hpp_proto_requires_any_enabled} PARENT_SCOPE)
endfunction()

function(add_hpp_proto_test)
    cmake_parse_arguments(add_hpp_proto_test "NO_TEST" "NAME" "SOURCES;LINK_LIBRARIES;REQUIRES;DEPENDENCIES" "${ARGN}")

    if(add_hpp_proto_test_REQUIRES)
        hpp_proto_requires_any(_add_hpp_proto_test_enabled ${add_hpp_proto_test_REQUIRES})
        if(NOT _add_hpp_proto_test_enabled)
            return()
        endif()
    endif()

    add_executable(${add_hpp_proto_test_NAME} ${add_hpp_proto_test_SOURCES})
    target_link_libraries(${add_hpp_proto_test_NAME} PRIVATE ${add_hpp_proto_test_LINK_LIBRARIES})
    if(add_hpp_proto_test_DEPENDENCIES)
        add_dependencies(${add_hpp_proto_test_NAME} ${add_hpp_proto_test_DEPENDENCIES})
    endif()

    if(NOT add_hpp_proto_test_NO_TEST)
        add_test(NAME ${add_hpp_proto_test_NAME}
            COMMAND ${add_hpp_proto_test_NAME}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    endif()
endfunction()

function(add_hpp_proto_test_lib)
    cmake_parse_arguments(add_hpp_proto_test_lib "" "NAME;TYPE" "SOURCES;LINK_LIBRARIES;REQUIRES" "${ARGN}")

    if(add_hpp_proto_test_lib_REQUIRES)
        hpp_proto_requires_any(_add_hpp_proto_test_lib_enabled ${add_hpp_proto_test_lib_REQUIRES})
        if(NOT _add_hpp_proto_test_lib_enabled)
            return()
        endif()
    endif()

    if(NOT add_hpp_proto_test_lib_TYPE)
        set(add_hpp_proto_test_lib_TYPE INTERFACE)
    endif()

    add_library(${add_hpp_proto_test_lib_NAME} ${add_hpp_proto_test_lib_TYPE} ${add_hpp_proto_test_lib_SOURCES})

    if(add_hpp_proto_test_lib_TYPE STREQUAL INTERFACE)
        set(_add_hpp_proto_test_lib_link_scope INTERFACE)
    else()
        set(_add_hpp_proto_test_lib_link_scope PRIVATE)
    endif()

    if(add_hpp_proto_test_lib_LINK_LIBRARIES)
        target_link_libraries(${add_hpp_proto_test_lib_NAME}
            ${_add_hpp_proto_test_lib_link_scope}
            ${add_hpp_proto_test_lib_LINK_LIBRARIES})
    endif()
endfunction()

function(add_hpp_proto_generated_test_lib)
    cmake_parse_arguments(add_hpp_proto_generated_test_lib "" "NAME;PROTOC_OUT_DIR;PLUGIN_OPTIONS" "SOURCES;IMPORT_DIRS;LINK_LIBRARIES;REQUIRES;PROTOC_OPTIONS" "${ARGN}")

    add_hpp_proto_test_lib(
        NAME ${add_hpp_proto_generated_test_lib_NAME}
        TYPE INTERFACE
        SOURCES ${add_hpp_proto_generated_test_lib_SOURCES}
        LINK_LIBRARIES ${add_hpp_proto_generated_test_lib_LINK_LIBRARIES}
        REQUIRES ${add_hpp_proto_generated_test_lib_REQUIRES})

    if(NOT TARGET ${add_hpp_proto_generated_test_lib_NAME})
        return()
    endif()

    set(_args TARGET ${add_hpp_proto_generated_test_lib_NAME})

    if(add_hpp_proto_generated_test_lib_IMPORT_DIRS)
        list(APPEND _args IMPORT_DIRS ${add_hpp_proto_generated_test_lib_IMPORT_DIRS})
    endif()

    if(add_hpp_proto_generated_test_lib_PLUGIN_OPTIONS)
        list(APPEND _args PLUGIN_OPTIONS ${add_hpp_proto_generated_test_lib_PLUGIN_OPTIONS})
    endif()

    if(add_hpp_proto_generated_test_lib_PROTOC_OPTIONS)
        list(APPEND _args PROTOC_OPTIONS ${add_hpp_proto_generated_test_lib_PROTOC_OPTIONS})
    endif()

    if(add_hpp_proto_generated_test_lib_PROTOC_OUT_DIR)
        list(APPEND _args PROTOC_OUT_DIR ${add_hpp_proto_generated_test_lib_PROTOC_OUT_DIR})
    endif()

    protobuf_generate_hpp(${_args})
endfunction()
