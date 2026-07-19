add_compile_options(${HPP_PROTO_COMPILE_OPTIONS})

add_library(hpp_proto_cpp_lexical STATIC cpp_lexical_emitter.cpp)
target_compile_features(hpp_proto_cpp_lexical PUBLIC cxx_std_23)
target_include_directories(hpp_proto_cpp_lexical PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

add_library(hpp_proto_generator_core STATIC hpp_generator.cpp)
target_compile_features(hpp_proto_generator_core PUBLIC cxx_std_23)
target_include_directories(hpp_proto_generator_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(hpp_proto_generator_core PUBLIC hpp_proto::hpp_proto_core hpp_proto_cpp_lexical)

add_executable(protoc-gen-hpp protoc-gen-hpp.cpp)
target_compile_definitions(protoc-gen-hpp PRIVATE HPP_PROTO_VERSION="${PROJECT_VERSION}")
add_executable(hpp_proto::protoc-gen-hpp ALIAS protoc-gen-hpp)
target_compile_features(protoc-gen-hpp PRIVATE cxx_std_23)
target_link_libraries(protoc-gen-hpp PRIVATE hpp_proto_generator_core)

set_target_properties(protoc-gen-hpp
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
install(TARGETS protoc-gen-hpp EXPORT hpp_proto-targets)

if(MSVC)
    target_compile_definitions(protoc-gen-hpp PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(hpp_proto_generator_core PRIVATE /bigobj)
endif()
