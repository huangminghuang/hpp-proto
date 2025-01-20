#include <fuzzer/FuzzedDataProvider.h>
#include <google/protobuf/unittest_proto3.pb.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  std::vector<std::vector<char>> input;

  while (input.size() < 9) {
    auto v = provider.ConsumeBytes<char>(provider.ConsumeIntegralInRange<int>(10, 128));
    if (v.empty()) {
      break;
    }
    input.push_back(std::move(v));
  };

  auto v = provider.ConsumeRemainingBytes<char>();
  if (!v.empty())
    input.push_back(std::move(v));
  // std::span input(data, size);

  proto3_unittest::TestAllTypes message;
  auto status = hpp::proto::read_proto(message, input);
  return status.ok() ? 0 : 1;
}