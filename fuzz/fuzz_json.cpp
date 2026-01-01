#include <google/protobuf/map_unittest.glz.hpp>
#include <google/protobuf/unittest.glz.hpp>
#include <google/protobuf/unittest_proto3.glz.hpp>

#include "common.hpp"
#include <hpp_proto/dynamic_message/json.hpp>

// Define the variant of all message types we fuzz
using message_variant_t = std::variant<proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits>,
                                       protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits>,
                                       protobuf_unittest::TestMap<hpp::proto::non_owning_traits>>;

template <typename T>
void round_trip_test(const T &in_message, T &&out_message) { // NOLINT(cppcoreguidelines-missing-std-forward)
  std::string buffer1;
  std::string buffer2;
  assert(hpp::proto::write_json(in_message, buffer1).ok());
  // Skip comparing the serialized buffer to the raw input because unknown fields are dropped on parse.
  // Skip structural comparison of messages; NaN payloads make equality fail even when bitwise identical.
  std::pmr::monotonic_buffer_resource mr;
  hpp::proto::json_status status;
  if constexpr (concepts::use_non_owning_traits<T>) {
    status = hpp::proto::read_json(out_message, buffer1, hpp::proto::alloc_from(mr));
  } else {
    status = hpp::proto::read_json(out_message, buffer1);
  }
  if (!status.ok()) {
    std::cerr << "roundtrip read failed:" << status.message(buffer1) << "\n";
  }
  assert(status.ok());
  assert(hpp::proto::write_json(out_message, buffer2).ok());
  if (buffer1 != buffer2) {
    auto [it1, it2] = std::ranges::mismatch(buffer1, buffer2);
    auto sw1 = std::string_view{it1 - 20, buffer1.end()};
    auto sw2 = std::string_view{it2 - 20, buffer2.end()};
    std::cerr << sw1 << "\n" << sw2 << "\n";
  }
}

extern "C" __attribute__((visibility("default"))) int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  // choice_options encodes message type and whether to split input.
  // Maximum choice_options will be (std::variant_size_v<message_variant_t> - 1).
  // Using uint8_t will consume 1 byte for this option.
  constexpr auto kVariantCount = std::variant_size_v<message_variant_t>;
  static_assert(kVariantCount > 0);
  auto choice_options =
      provider.ConsumeIntegralInRange<uint8_t>(0, static_cast<uint8_t>(kVariantCount - 1));

  std::pmr::monotonic_buffer_resource mr; // Needs to be alive during read_binpb
  message_variant_t message_variant;      // Holds the deserialized message

  auto message_type_index = choice_options % std::variant_size_v<message_variant_t>;

  set_variant_by_index(message_variant, message_type_index);

  auto do_read = [&](std::string_view input) {
    return std::visit(
        [&](auto &non_owning_message) -> int {
          using non_owning_message_t = std::remove_reference_t<decltype(non_owning_message)>;
          using owning_message_t = decltype(hpp::proto::rebind_traits(non_owning_message));
          std::string_view msg_name = message_name(non_owning_message);
          owning_message_t owning_message;
          hpp::proto::message_value_mref dyn_message = factory.get_message(msg_name, mr).value();

          auto non_owning_read_status = hpp::proto::read_json(non_owning_message, input, hpp::proto::alloc_from{mr});
          auto owning_read_status = hpp::proto::read_json(owning_message, input);
          auto dyn_read_status = hpp::proto::read_json(dyn_message, input);

          bool all_status_same = (non_owning_read_status.ok() == owning_read_status.ok() &&
                                  owning_read_status.ok() == dyn_read_status.ok());
          if (!all_status_same) {
            auto print_error = [&input](std::string_view name, auto status) {
              if (!status.ok()) {
                std::cerr << name << " failed:" << status.message(input) << "\n";
              }
            };
            print_error("non-owning", non_owning_read_status);
            print_error("owning", owning_read_status);
            print_error("dyn", dyn_read_status);
          }
          assert(all_status_same);
          if (dyn_read_status.ok()) {
            round_trip_test(non_owning_message, non_owning_message_t{});
            round_trip_test(owning_message, owning_message_t{});
            round_trip_test(dyn_message, factory.get_message(msg_name, mr).value());
          }
          return dyn_read_status.ok() ? 0 : -1;
        },
        message_variant);
  };
  auto remaining = provider.ConsumeRemainingBytes<char>();
  return do_read({remaining.begin(), remaining.end()});
}
