#include <google/protobuf/map_unittest.pb.hpp>
#include <google/protobuf/unittest.pb.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>

#include <google/protobuf/map_unittest.glz.hpp>
#include <google/protobuf/unittest.glz.hpp>
#include <google/protobuf/unittest_proto3.glz.hpp>
#include <hpp_proto/dynamic_message/json.hpp>

#include "common.hpp"

// Define the variant of all message types we fuzz
using message_variant_t = std::variant<proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits>,
                                       protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits>,
                                       protobuf_unittest::TestMap<hpp::proto::non_owning_traits>>;

std::vector<std::span<const uint8_t>> split_input(std::span<const uint8_t> input) {
  std::vector<std::span<const uint8_t>> result{2};
  result[0] = std::span{input.data(), input.size() / 2};
  result[1] = std::span{input.begin() + result[0].size(), input.end()};
  return result;
}

template <typename T>
// NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
std::vector<char> round_trip_test(const T &in_message, T &&out_message) {
  std::vector<char> buffer1;
  std::vector<char> buffer2;
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
  return buffer1;
}

extern "C" __attribute__((visibility("default"))) int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  std::pmr::monotonic_buffer_resource mr; // Needs to be alive during read_binpb
  message_variant_t message_variant;      // Holds the deserialized message
  auto message_type_index = data[size - 1] % std::variant_size_v<message_variant_t>;

  set_variant_by_index(message_variant, message_type_index);

  auto do_read = [&](const auto &input) -> std::expected<std::vector<char>, std::errc> {
    return std::visit(
        [&](auto &non_owning_message) -> std::expected<std::vector<char>, std::errc> {
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
            auto non_owning_write = round_trip_test(non_owning_message, non_owning_message_t{});
            auto owning_write = round_trip_test(owning_message, owning_message_t{});
            auto dyn_write = round_trip_test(dyn_message, factory.get_message(msg_name, mr).value());

            if (msg_name != message_name(protobuf_unittest::TestMap<hpp::proto::non_owning_traits>{})) {
              // Map field reads reorder entries, so protobuf re-encoding is not stable.
              assert(non_owning_write == owning_write);
            }
            if (non_owning_write != dyn_write) {
              std::string non_owing_json;
              assert(hpp::proto::write_json(non_owning_message, non_owing_json).ok());
              std::cout << "non_owning: " << non_owing_json << "\n";
              std::string dyn_json;
              assert(hpp::proto::write_json(dyn_message, dyn_json).ok());
              std::cout << "dyn: " << dyn_json << "\n";
            }
            assert(non_owning_write == dyn_write);
            return dyn_write;
          } else {
            return std::unexpected(std::errc::bad_message);
          }
        },
        message_variant);
  };

  auto input = std::span{data, size - 1};
  auto non_split_result = do_read(input);
  if (size > 32) {
    auto split_result = do_read(split_input(input));
    assert(non_split_result == split_result);
  }

  return non_split_result.has_value() ? 0 : -1;
}
