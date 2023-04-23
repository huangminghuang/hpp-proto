CPMAddPackage("gh:fmtlib/fmt#9.1.0")

add_executable(protoc-gen-hpp hpp_generator.cpp)
target_link_libraries(protoc-gen-hpp PRIVATE hpp_proto::libhpp_proto fmt::fmt)
install(TARGETS protoc-gen-hpp EXPORT hpp_proto-targets)