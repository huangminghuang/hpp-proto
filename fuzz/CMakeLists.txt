# Detect available libfuzz support using try_compile.
if(NOT DEFINED HPP_PROTO_FUZZ_COMPILE_OPTIONS)
  set(HPP_PROTO_FUZZ_COMPILE_OPTIONS -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all)
endif()

if(NOT DEFINED HPP_PROTO_FUZZ_LINK_OPTIONS)
  set(HPP_PROTO_FUZZ_LINK_OPTIONS -fsanitize=fuzzer,address,undefined)
endif()

unset(FUZZER_SUPPORT CACHE)
try_compile(FUZZER_SUPPORT
  ${CMAKE_CURRENT_BINARY_DIR}/fuzzer_check
  ${CMAKE_CURRENT_SOURCE_DIR}/fuzzer_check.cpp
  COMPILE_DEFINITIONS ${HPP_PROTO_FUZZ_COMPILE_OPTIONS}
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

function(copy_and_append_byte input_file dest_dir byte_value)
  get_filename_component(_name "${input_file}" NAME)
  set(_output "${dest_dir}/${_name}")

  add_custom_command(
    OUTPUT "${_output}"
    COMMAND ${Python3_EXECUTABLE} -c
            "from pathlib import Path; data = Path(r'${input_file}').read_bytes(); Path(r'${_output}').write_bytes(data + bytes([${byte_value}]))"
    DEPENDS "${input_file}"
    COMMENT "Copying ${input_file} and appending one byte"
    VERBATIM
  )

  add_custom_target(seed_${_name} ALL
    DEPENDS "${_output}"
  )
endfunction()

function(gen_seed_corpus data_dir file_list type)
  set(_output_dir "${CMAKE_CURRENT_BINARY_DIR}/${type}_seed_corpus")
  file(MAKE_DIRECTORY ${_output_dir})

  set(_index 0)
  foreach(_file IN LISTS file_list)
    copy_and_append_byte("${data_dir}/${_file}.${type}" "${_output_dir}" "${_index}")
    math(EXPR _index "${_index} + 1")
  endforeach()
endfunction()

set(seed_list "proto3_unittest.TestAllTypes"
  "protobuf_unittest.TestAllTypes"
  "protobuf_unittest.TestMap"
  "proto2_unittest.TestWellKnownTypes")

set(data_dir ${CMAKE_CURRENT_SOURCE_DIR}/../tests/data)
gen_seed_corpus("${data_dir}" "${seed_list}" binpb)
gen_seed_corpus("${data_dir}" "${seed_list}" json)

# Copy unittest.desc.binpb from the tests build into the fuzz build dir.
set(unittest_desc_src ${CMAKE_CURRENT_BINARY_DIR}/../tests/unittest.desc.binpb)
set(unittest_desc_dst ${CMAKE_CURRENT_BINARY_DIR}/unittest.desc.binpb)
add_custom_command(
  OUTPUT ${unittest_desc_dst}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/fuzz
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${unittest_desc_src} ${unittest_desc_dst}
  DEPENDS ${unittest_desc_src} unittest.desc.binpb.target
  COMMENT "Copying unittest.desc.binpb into fuzz build directory"
)
add_custom_target(fuzz_unittest_desc ALL DEPENDS ${unittest_desc_dst})

set(descriptor_seed_dir ${CMAKE_CURRENT_BINARY_DIR}/descriptor_seed_corpus)
set(descriptor_seed_file ${descriptor_seed_dir}/unittest.desc.binpb)
add_custom_command(
  OUTPUT ${descriptor_seed_file}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${descriptor_seed_dir}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${unittest_desc_dst} ${descriptor_seed_file}
  DEPENDS ${unittest_desc_dst}
  COMMENT "Creating descriptor-set fuzz seed corpus"
)
add_custom_target(fuzz_descriptor_seed ALL DEPENDS ${descriptor_seed_file})

# Copy static seed corpus files into the binary dir.
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/binpb_seed_corpus)
file(GLOB binpb_seed_corpus_files ${CMAKE_CURRENT_SOURCE_DIR}/binpb_seed_corpus/*)

foreach(seed_file IN LISTS binpb_seed_corpus_files)
  get_filename_component(seed_name ${seed_file} NAME)
  configure_file(${seed_file} ${CMAKE_CURRENT_BINARY_DIR}/binpb_seed_corpus/${seed_name} COPYONLY)
endforeach()

add_library(fuzz_common common.cpp json_extern.cpp binpb_extern.cpp)
target_link_libraries(
  fuzz_common
  PUBLIC
    glaze::glaze
    hpp_proto::hpp_proto
    hpp_proto::dynamic_message
    unittest_proto3_proto_lib
    unittest_proto_lib
    map_unittest_proto_lib
    unittest_well_known_types_proto_lib)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  # Alias metadata roughly doubles JSON key entries for very large protos (for example TestAllTypes),
  # which can exceed Clang's default expression nesting depth/constexpr budget in Glaze reflection.
  target_compile_options(fuzz_common PRIVATE -fbracket-depth=512 -fconstexpr-steps=67108864)
endif()

function(enable_fuzz_compile_instrumentation target)
  get_target_property(_is_imported ${target} IMPORTED)
  if(NOT _is_imported)
    target_compile_options(${target} PRIVATE ${HPP_PROTO_FUZZ_COMPILE_OPTIONS} -UNDEBUG)
  endif()
endfunction()

# These object-producing targets are all reachable from a fuzz entry point.
enable_fuzz_compile_instrumentation(fuzz_common)
enable_fuzz_compile_instrumentation(dynamic_message)
if(TARGET is_utf8)
  enable_fuzz_compile_instrumentation(is_utf8)
endif()

function(add_fuzz_target type source)
  set(target fuzz_${type})
  add_executable(${target} ${source})
  target_link_libraries(${target} PRIVATE fuzz_common)
  add_dependencies(${target} fuzz_unittest_desc)

  enable_fuzz_compile_instrumentation(${target})
  target_link_options(${target} PRIVATE ${HPP_PROTO_FUZZ_LINK_OPTIONS})

  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${type}_corpus")
  add_test(NAME ${target} COMMAND ${target} ${type}_corpus ${type}_seed_corpus -dict=${target}.dict -rss_limit_mb=4096 -timeout=3600 -runs=100000)

  configure_file(${target}.dict ${target}.dict COPYONLY)
  configure_file(${target}.sh ${target}.sh COPYONLY)
endfunction()

add_fuzz_target(binpb fuzz_binpb.cpp)
add_fuzz_target(json fuzz_json.cpp)

add_executable(fuzz_descriptor fuzz_descriptor.cpp)
target_link_libraries(fuzz_descriptor PRIVATE hpp_proto::dynamic_message)
add_dependencies(fuzz_descriptor fuzz_descriptor_seed)
enable_fuzz_compile_instrumentation(fuzz_descriptor)
target_link_options(fuzz_descriptor PRIVATE ${HPP_PROTO_FUZZ_LINK_OPTIONS})

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/descriptor_corpus")
add_test(
  NAME fuzz_descriptor
  COMMAND fuzz_descriptor descriptor_corpus descriptor_seed_corpus
          -dict=fuzz_descriptor.dict -rss_limit_mb=4096 -timeout=3600 -runs=100000)

configure_file(fuzz_descriptor.dict fuzz_descriptor.dict COPYONLY)
configure_file(fuzz_descriptor.sh fuzz_descriptor.sh COPYONLY)
