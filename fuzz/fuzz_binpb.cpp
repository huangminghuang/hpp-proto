

#include <google/protobuf/map_unittest.pb.hpp>
#include <google/protobuf/unittest.pb.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>

#include "common.hpp"


// Define the variant of all message types we fuzz
using message_variant_t = std::variant<proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits>,
                                       protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits>,
                                       protobuf_unittest::TestMap<hpp::proto::non_owning_traits>>;

std::vector<std::vector<char>> split_input(FuzzedDataProvider &provider) {
  std::vector<std::vector<char>> result;
  while (result.size() < 9) {
    auto v = provider.ConsumeBytes<char>(provider.ConsumeIntegralInRange<int>(128, 256));
    if (v.empty()) {
      break;
    }
    result.push_back(std::move(v));
  };

  auto v = provider.ConsumeRemainingBytes<char>();
  if (!v.empty()) {
    result.push_back(std::move(v));
  }
  return result;
}

template <typename T>
void round_trip_test(const T &in_message, T &&out_message) {
  std::vector<char> buffer1, buffer2;
  assert(hpp::proto::write_binpb(in_message, buffer1).ok());
  // Skip comparing the serialized buffer to the raw input because unknown fields are dropped on parse.
  // Skip structural comparison of messages; NaN payloads make equality fail even when bitwise identical.
  std::pmr::monotonic_buffer_resource mr;
  if constexpr (concepts::use_non_owning_traits<T>) {
    assert(hpp::proto::read_binpb(out_message, buffer1, hpp::proto::alloc_from(mr)).ok());
  } else {
    assert(hpp::proto::read_binpb(out_message, buffer1).ok());
  }
  assert(hpp::proto::write_binpb(out_message, buffer2).ok());
  assert(std::ranges::equal(buffer1, buffer2));
}

extern "C" __attribute__((visibility("default"))) int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  // choice_options encodes message type and whether to split input.
  // Maximum choice_options will be (std::variant_size_v<message_variant_t> * 2 - 1).
  // Using uint8_t will consume 1 byte for this option.
  uint8_t choice_options = provider.ConsumeIntegralInRange<uint8_t>(0, std::variant_size_v<message_variant_t> * 2 - 1);

  std::pmr::monotonic_buffer_resource mr; // Needs to be alive during read_binpb
  message_variant_t message_variant;      // Holds the deserialized message

  auto message_type_index = choice_options % std::variant_size_v<message_variant_t>;

  // Extract further options from choice_options
  bool to_split = (choice_options / std::variant_size_v<message_variant_t>) % 2;

  set_variant_by_index(message_variant, message_type_index);

  auto do_read = [&](const auto &input) {
    return std::visit(
        [&](auto &non_owning_message) {
          using non_owning_message_t = std::remove_reference_t<decltype(non_owning_message)>;
          using owning_message_t = decltype(hpp::proto::rebind_traits(non_owning_message));
          auto msg_name = message_name(non_owning_message);
          owning_message_t owning_message;
          hpp::proto::message_value_mref dyn_message = factory.get_message(msg_name, mr).value();

          auto non_owning_read_ok = hpp::proto::read_binpb(non_owning_message, input, hpp::proto::alloc_from{mr}).ok();
          auto owning_read_ok = hpp::proto::read_binpb(owning_message, input).ok();
          auto dyn_read_ok = hpp::proto::read_binpb(dyn_message, input).ok();

          assert(non_owning_read_ok == owning_read_ok && owning_read_ok == dyn_read_ok);
          if (dyn_read_ok) {
            round_trip_test(non_owning_message, non_owning_message_t{});
            round_trip_test(owning_message, owning_message_t{});
            round_trip_test(dyn_message, factory.get_message(msg_name, mr).value());
          }
          return dyn_read_ok ? 0 : -1;
        },
        message_variant);
  };

  return to_split ? do_read(split_input(provider)) : do_read(provider.ConsumeRemainingBytes<char>());
}
