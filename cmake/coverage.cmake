set(CMAKE_CXX_FLAGS_COVERAGE "${CMAKE_CXX_FLAGS} -g -O0 --coverage -fprofile-arcs -ftest-coverage")

if(CMAKE_CONFIGURATION_TYPES)
  list(FIND CMAKE_CONFIGURATION_TYPES "Coverage" _coverage_config_index)
else()
  set(_coverage_config_index -1)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Coverage" OR _coverage_config_index GREATER_EQUAL 0)
  find_program(GCOVR_EXECUTABLE gcovr)

  if(GCOVR_EXECUTABLE)
    set(COVERAGE_GCOVR_EXCLUDES
      ".*/usr/include/.*"
      ".*/include/google/protobuf/.*"
      ".*/tutorial/.*"
      ".*/tests/.*"
      "${CMAKE_BINARY_DIR}/.*"
    )

    if(DEFINED ENV{CPM_SOURCE_CACHE} AND NOT "$ENV{CPM_SOURCE_CACHE}" STREQUAL "")
      list(APPEND COVERAGE_GCOVR_EXCLUDES "$ENV{CPM_SOURCE_CACHE}/.*")
    endif()

    set(COVERAGE_GCOVR_EXCLUDE_ARGS)
    foreach(pattern IN LISTS COVERAGE_GCOVR_EXCLUDES)
      list(APPEND COVERAGE_GCOVR_EXCLUDE_ARGS --exclude "${pattern}")
    endforeach()

    add_custom_target(coverage_gcovr
      COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
      COMMAND ${GCOVR_EXECUTABLE}
      --root ${CMAKE_CURRENT_SOURCE_DIR}
      --xml-pretty
      --xml ${CMAKE_BINARY_DIR}/coverage.cobertura.xml
      --print-summary
      --txt ${CMAKE_BINARY_DIR}/coverage.txt
      --gcov-ignore-errors all
      ${COVERAGE_GCOVR_EXCLUDE_ARGS}
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      COMMENT "Generating coverage reports with gcovr"
      VERBATIM
    )

    # Backward-compatible target name used by existing CI workflow steps.
    add_custom_target(coverage_filtered_info
      DEPENDS coverage_gcovr
    )

    add_custom_target(coverage_html
      DEPENDS coverage_gcovr
      COMMAND ${GCOVR_EXECUTABLE}
      --root ${CMAKE_CURRENT_SOURCE_DIR}
      --html-details ${CMAKE_BINARY_DIR}/coverage-report/index.html
      --html-title "hpp-proto coverage"
      --gcov-ignore-errors all
      ${COVERAGE_GCOVR_EXCLUDE_ARGS}
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      COMMENT "Generating coverage HTML report with gcovr"
      VERBATIM
    )
  endif()
endif()
