
function(add_fuzz_target target source)
  add_executable(${target} ${source})
  target_link_libraries(${target} PRIVATE hpp_proto::libhpp_proto unittest_proto_lib)
  target_compile_options(${target} PRIVATE ${HPP_PROTO_FUZZ_CXX_FLAGS})
  target_link_options(${target} PRIVATE ${HPP_PROTO_FUZZ_LINKER_FLAGS})

  if(DEFINED HPP_PROTO_FUZZ_CXX_FLAGS)
    add_executable(${target}_debug_case ${source} fuzz_case_main.cpp)
    target_link_libraries(${target}_debug_case PRIVATE hpp_proto::libhpp_proto unittest_proto_lib)
  endif()
endfunction()

add_fuzz_target(fuzz_pb_serializer fuzz_pb_serializer.cpp)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/corpus)
