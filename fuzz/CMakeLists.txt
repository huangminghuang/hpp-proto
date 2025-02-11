
if(DEFINED ENV{LIB_FUZZING_ENGINE})
  set(LIB_FUZZING_ENGINE $ENV{LIB_FUZZING_ENGINE})
else()
  set(FUZZ_COMPILE_FLAGS -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all)
  set(LIB_FUZZING_ENGINE -fsanitize=fuzzer,address,undefined)
endif()

function(add_fuzz_target target source)
  add_executable(${target} ${source})
  target_link_libraries(${target} PRIVATE hpp_proto::libhpp_proto unittest_proto_lib)
  target_compile_options(${target} PRIVATE ${FUZZ_COMPILE_FLAGS})
  target_link_options(${target} PRIVATE ${LIB_FUZZING_ENGINE})

  if(DEFINED FUZZ_COMPILE_FLAGS)
    add_executable(${target}_debug_case ${source} fuzz_case_main.cpp)
    target_compile_options(${target}_debug_case PRIVATE -fsanitize=address,undefined)
    target_link_libraries(${target}_debug_case PRIVATE hpp_proto::libhpp_proto unittest_proto_lib)
  endif()
endfunction()

add_fuzz_target(fuzz_pb_serializer fuzz_pb_serializer.cpp)
add_fuzz_target(fuzz_dynamic_serializer fuzz_dynamic_serializer.cpp)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/corpus)
