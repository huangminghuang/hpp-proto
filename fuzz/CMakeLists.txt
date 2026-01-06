# Detect available libfuzz support using try_compile.
set(HPP_PROTO_FUZZ_COMPILE_OPTIONS -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all)
set(HPP_PROTO_FUZZ_LINK_OPTIONS -fsanitize=fuzzer,address,undefined)
if(DEFINED ENV{SANITIZER})
  if("$ENV{SANITIZER}" STREQUAL "address")
    set(HPP_PROTO_FUZZ_COMPILE_OPTIONS -fsanitize=fuzzer,address -fno-sanitize-recover=all)
    set(HPP_PROTO_FUZZ_LINK_OPTIONS -fsanitize=fuzzer,address)
  elseif("$ENV{SANITIZER}" STREQUAL "undefined")
    set(HPP_PROTO_FUZZ_COMPILE_OPTIONS -fsanitize=fuzzer,undefined -fno-sanitize-recover=all)
    set(HPP_PROTO_FUZZ_LINK_OPTIONS -fsanitize=fuzzer,undefined)
  elseif("$ENV{SANITIZER}" STREQUAL "coverage")
    set(HPP_PROTO_FUZZ_COMPILE_OPTIONS -fsanitize=fuzzer-no-link)
    set(HPP_PROTO_FUZZ_LINK_OPTIONS -fsanitize=fuzzer-no-link)
  endif()
endif()


unset(FUZZER_SUPPORT CACHE)
try_compile(FUZZER_SUPPORT
  ${CMAKE_CURRENT_BINARY_DIR}/fuzzer_check
  ${CMAKE_CURRENT_SOURCE_DIR}/fuzzer_check.cpp
  CMAKE_FLAGS -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS};"${HPP_PROTO_FUZZ_COMPILE_OPTIONS}"
  LINK_OPTIONS "${HPP_PROTO_FUZZ_LINK_OPTIONS}"
)

if(NOT FUZZER_SUPPORT)
  message(WARNING "Fuzzer sanitizer not supported, skipping fuzzer targets")
  return()
endif()

# Find Python and run the script to generate the suffixed corpus from test data.
# This ensures the corpus is ready before the fuzzer targets are built.
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# Path to the script, now located inside the fuzz/ directory
set(corpus_script ${CMAKE_CURRENT_SOURCE_DIR}/append_fuzz_suffix.py)

# Define the output root for generated corpora inside the build tree.
set(script_output_root ${CMAKE_CURRENT_BINARY_DIR})

message(STATUS "Generating fuzzer corpus by running script: ${corpus_script}")

execute_process(
  COMMAND ${Python3_EXECUTABLE} ${corpus_script} --output-root=${script_output_root} --formats=binpb,json
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

# Copy unittest.desc.binpb from the tests build into the fuzz build dir.
set(unittest_desc_src ${CMAKE_CURRENT_BINARY_DIR}/../tests/unittest.desc.binpb)
set(unittest_desc_dst ${CMAKE_CURRENT_BINARY_DIR}/unittest.desc.binpb)
add_custom_command(
  OUTPUT ${unittest_desc_dst}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/fuzz
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${unittest_desc_src} ${unittest_desc_dst}
  DEPENDS unittest.desc.binpb.target
  COMMENT "Copying unittest.desc.binpb into fuzz build directory"
)
add_custom_target(fuzz_unittest_desc ALL DEPENDS ${unittest_desc_dst})

# Copy static seed corpus files into the binary dir.
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/binpb_seed_corpus)
file(GLOB binpb_seed_corpus_files ${CMAKE_CURRENT_SOURCE_DIR}/binpb_seed_corpus/*)

foreach(seed_file IN LISTS binpb_seed_corpus_files)
  get_filename_component(seed_name ${seed_file} NAME)
  configure_file(${seed_file} ${CMAKE_CURRENT_BINARY_DIR}/binpb_seed_corpus/${seed_name} COPYONLY)
endforeach()

function(add_fuzz_target type source)
  set(target fuzz_${type})
  add_executable(${target} ${source} common.cpp)
  target_link_libraries(${target} PRIVATE hpp_proto::libhpp_proto unittest_proto_lib)
  add_dependencies(${target} fuzz_unittest_desc)

  target_compile_options(${target} PRIVATE ${HPP_PROTO_FUZZ_COMPILE_OPTIONS} -UNDEBUG)
  target_link_options(${target} PRIVATE ${HPP_PROTO_FUZZ_LINK_OPTIONS})

  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${type}_corpus")
  add_test(NAME ${target} COMMAND ${target} ${type}_corpus ${type}_seed_corpus -dict=${target}.dict -rss_limit_mb=4096 -timeout=3600 -runs=100000)

  configure_file(${target}.dict ${target}.dict COPYONLY)
  configure_file(${target}.sh ${target}.sh COPYONLY)
endfunction()
add_fuzz_target(binpb fuzz_binpb.cpp)
add_fuzz_target(json fuzz_json.cpp)
