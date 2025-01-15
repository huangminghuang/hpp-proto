#include <google/protobuf/unittest_proto3.pb.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  proto3_unittest::TestAllTypes message;
  auto status = hpp::proto::read_proto(message, std::span{data, size});
  return status.ok() ? 0 : 1;
}