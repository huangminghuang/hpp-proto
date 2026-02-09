set(CMAKE_CXX_FLAGS_COVERAGE "${CMAKE_CXX_FLAGS} -g -O0 --coverage -fprofile-arcs -ftest-coverage")

if(CMAKE_CONFIGURATION_TYPES)
  list(FIND CMAKE_CONFIGURATION_TYPES "Coverage" _coverage_config_index)
else()
  set(_coverage_config_index -1)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Coverage" OR _coverage_config_index GREATER_EQUAL 0)
  find_program(LCOV_EXECUTABLE lcov)
  find_program(GENHTML_EXECUTABLE genhtml)

  if(LCOV_EXECUTABLE)
    set(COVERAGE_EXCLUDE_PATTERNS
      "/usr/include/*"
      "${CMAKE_CURRENT_SOURCE_DIR}/include/google/protobuf/*"
      "${CMAKE_CURRENT_SOURCE_DIR}/tutorial/*"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/*"
      "${CMAKE_BINARY_DIR}/*"
      "$ENV{CPM_SOURCE_CACHE}/*"
    )
    set(COVERAGE_LCOV_ARGS
      --ignore-errors inconsistent,unsupported,format,unused
      --rc derive_function_end_line=0
    )

    add_custom_target(coverage_filtered_info
      COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
      COMMAND ${LCOV_EXECUTABLE} --capture --directory ${CMAKE_BINARY_DIR}
      --output-file ${CMAKE_BINARY_DIR}/coverage.info
      ${COVERAGE_LCOV_ARGS}
      COMMAND ${LCOV_EXECUTABLE} --remove ${CMAKE_BINARY_DIR}/coverage.info
      ${COVERAGE_EXCLUDE_PATTERNS}
      --output-file ${CMAKE_BINARY_DIR}/coverage.filtered.info
      ${COVERAGE_LCOV_ARGS}
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      COMMENT "Generating coverage.filtered.info"
      VERBATIM
    )

    if(GENHTML_EXECUTABLE)
      add_custom_target(coverage_html
        DEPENDS coverage_filtered_info
        COMMAND ${GENHTML_EXECUTABLE} ${CMAKE_BINARY_DIR}/coverage.filtered.info
        --output-directory ${CMAKE_BINARY_DIR}/coverage-report
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Generating coverage HTML report"
        VERBATIM
      )
    endif()
  endif()
endif()
