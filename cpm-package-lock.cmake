# CPM Package Lock
# This file should be committed to version control

# glaze
CPMDeclarePackage(glaze
  NAME glaze
  VERSION 7.8.4
  GIT_TAG 0a21fd9dbd36963790b6f26b9539050e13d78649
  GITHUB_REPOSITORY stephenberry/glaze
  OPTIONS
    "glaze_INSTALL ON"
)
# is_utf8
CPMDeclarePackage(is_utf8
  NAME is_utf8
  VERSION 1.4.1
  GIT_TAG 77103c7462b9498f0bbc238260d1f1408a66a461
  DOWNLOAD_ONLY ON
  GITHUB_REPOSITORY simdutf/is_utf8
)
# protobuf
CPMDeclarePackage(protobuf
  NAME protobuf
  VERSION 35.0
  GIT_TAG e59364c38e10de3686a3305ff11fbfc59a10dbd8
  GITHUB_REPOSITORY protocolbuffers/protobuf
  SYSTEM ON
  OPTIONS
    "ABSL_PROPAGATE_CXX_STD ON"
    "protobuf_FORCE_FETCH_DEPENDENCIES ON"
    "protobuf_INSTALL OFF"
    "protobuf_BUILD_TESTS OFF"
    "protobuf_BUILD_PROTOBUF_BINARIES ON"
    "protobuf_BUILD_PROTOC_BINARIES ON"
    "protobuf_MSVC_STATIC_RUNTIME OFF"
)
# ut
CPMDeclarePackage(ut
  NAME ut
  VERSION 2.3.1
  GIT_TAG f923e6fe4b7542d75e0c4ee54ad0af6a5382a87c
  DOWNLOAD_ONLY ON
  GITHUB_REPOSITORY boost-ext/ut
)
# benchmark
CPMDeclarePackage(benchmark
  NAME benchmark
  VERSION 1.9.5
  GIT_TAG 192ef10025eb2c4cdd392bc502f0c852196baa48
  GITHUB_REPOSITORY google/benchmark
  OPTIONS
    "BENCHMARK_ENABLE_TESTING OFF"
    "BENCHMARK_ENABLE_INSTALL OFF"
)
