add_executable(compatbility_test "hpp_proto_test.cpp")

add_test(NAME compatbility_test 
         COMMAND compatbility_test 
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})