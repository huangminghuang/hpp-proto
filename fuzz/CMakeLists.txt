
function(add_fuzz_target target source)
  add_executable(${target} ${source})
  target_link_libraries(${target} PRIVATE hpp_proto::libhpp_proto ${ARGN})
  target_compile_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined)

  add_executable(${target}_debug_case ${source} fuzz_case_main.cpp)
  target_link_libraries(${target}_debug_case PRIVATE hpp_proto::libhpp_proto ${ARGN})
endfunction()

add_fuzz_target(fuzz_pb_serializer fuzz_pb_serializer.cpp unittest_proto_lib)
add_fuzz_target(fuzz_dynamic_serializer fuzz_dynamic_serializer.cpp)    
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/corpus)            



