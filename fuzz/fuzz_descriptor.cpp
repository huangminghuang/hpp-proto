#include <cstddef>
#include <cstdint>
#include <span>

#include <hpp_proto/dynamic_message/factory.hpp>

extern "C" __attribute__((visibility("default"))) int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const auto input = std::span{data, size};
  [[maybe_unused]] auto factory = hpp_proto::dynamic_message_factory::create(input);
  return 0;
}
