#include <google/protobuf/map_unittest.pb.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  protobuf_unittest::TestMap message;
  auto status = hpp::proto::read_proto(message, std::span{data, size});
  return status.ok() ? 0 : 1;
}