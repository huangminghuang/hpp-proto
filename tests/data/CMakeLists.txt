file(GLOB verification_files RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/*.pb ${CMAKE_CURRENT_SOURCE_DIR}/*.json)

foreach(f ${verification_files})
    configure_file(${f} ${f} COPYONLY)
endforeach()
