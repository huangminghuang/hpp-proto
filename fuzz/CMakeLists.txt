# Find Python and run the script to generate the prefixed corpus from test data.
# This ensures the corpus is ready before the fuzzer targets are built.
find_package(Python3 REQUIRED COMPONENTS Interpreter)

if(Python3_FOUND)
  # Path to the script, now located inside the fuzz/ directory
  set(corpus_script ${CMAKE_CURRENT_SOURCE_DIR}/append_fuzz_suffix.py)

  # Define the output directory for the generated corpus inside the build tree
  set(script_output_dir ${CMAKE_CURRENT_BINARY_DIR}/pb_seed_corpus)

  message(STATUS "Generating fuzzer corpus by running script: ${corpus_script}")

  execute_process(
    COMMAND ${Python3_EXECUTABLE} ${corpus_script} --output-dir=${script_output_dir}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    RESULT_VARIABLE script_result
    OUTPUT_VARIABLE script_output
    ERROR_VARIABLE script_output # Capture both stdout and stderr
  )

  if(script_result EQUAL 0)
    message(STATUS "Corpus generation script output:\n${script_output}")
  else()
    message(FATAL_ERROR "Failed to run corpus generation script ${corpus_script}:\n${script_output}")
  endif()
endif()

function(add_fuzz_target target source)
  add_executable(${target} ${source} read_file.cpp)
  target_link_libraries(${target} PRIVATE hpp_proto::libhpp_proto unittest_proto_lib)
  target_compile_options(${target} PRIVATE ${HPP_PROTO_FUZZ_CXX_FLAGS})
  target_link_options(${target} PRIVATE ${HPP_PROTO_FUZZ_LINKER_FLAGS})

  if(DEFINED HPP_PROTO_FUZZ_CXX_FLAGS)
    add_executable(${target}_debug_case ${source} fuzz_case_main.cpp read_file.cpp)
    target_link_libraries(${target}_debug_case PRIVATE hpp_proto::libhpp_proto unittest_proto_lib)
  endif()

  configure_file(${target}.sh ${target}.sh COPYONLY)
  configure_file(${target}.dict ${target}.dict COPYONLY)
endfunction()

add_fuzz_target(fuzz_pb fuzz_pb_serializer.cpp)

# The line `file(MAKE_DIRECTORY ...)` has been removed as the script now handles directory creation.
