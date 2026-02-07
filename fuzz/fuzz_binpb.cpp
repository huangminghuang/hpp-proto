#include <google/protobuf/map_unittest.pb.hpp>
#include <google/protobuf/unittest.pb.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>
#include <google/protobuf/unittest_well_known_types.pb.hpp>

#include "binpb_extern.hpp"
#include "json_extern.hpp"

using namespace std::string_view_literals;
// Define the variant of all message types we fuzz
using message_variant_t = std::variant<proto3_unittest::TestAllTypes<hpp_proto::stable_traits>,
                                       protobuf_unittest::TestAllTypes<hpp_proto::stable_traits>,
                                       protobuf_unittest::TestMap<hpp_proto::stable_traits>,
                                       proto2_unittest::TestWellKnownTypes<hpp_proto::stable_traits>>;

std::vector<std::span<const std::byte>> split_input(std::span<const std::byte> input) {
  std::vector<std::span<const std::byte>> result{2};
  result[0] = std::span{input.data(), input.size() / 2};
  result[1] = std::span{input.begin() + static_cast<std::ptrdiff_t>(result[0].size()), input.end()};
  return result;
}

template <typename T>
// NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
std::vector<std::byte> round_trip_test(const T &in_message, T &&out_message) {
  std::vector<std::byte> buffer1;
  assert(util::write_binpb(in_message, buffer1).ok());
  // std::string dyn_json;
  // assert(hpp_proto::write_json(in_message, dyn_json).ok());
  // std::cout << "in_message: " << dyn_json << "\n";

  // Skip comparing the serialized buffer to the raw input because unknown fields are dropped on parse.
  // Skip structural comparison of messages; NaN payloads make equality fail even when bitwise identical.
  std::pmr::monotonic_buffer_resource mr;
  if constexpr (concepts::use_non_owning_traits<T>) {
    assert(util::read_binpb(out_message, to_bytes(buffer1), hpp_proto::alloc_from(mr)).ok());
  } else {
    assert(util::read_binpb(out_message, to_bytes(buffer1)).ok());
  }

  // assert(hpp_proto::write_json(out_message, dyn_json).ok());
  // std::cout << "out_message: " << dyn_json << "\n";
  util::fuzz_out_sink sink;
  assert(util::write_binpb(out_message, sink).ok());
  assert(std::ranges::equal(buffer1, sink.written()));
  return buffer1;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
extern "C" __attribute__((visibility("default"))) int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  std::pmr::monotonic_buffer_resource mr; // Needs to be alive during read_binpb
  message_variant_t message_variant;      // Holds the deserialized message
  auto message_type_index = data[size - 1] % std::variant_size_v<message_variant_t>; // NOLINT

  set_variant_by_index(message_variant, message_type_index);

  // NOLINTNEXTLINE(readability-function-cognitive-complexity)
  auto do_read = [&](const auto &input) -> std::expected<std::vector<std::byte>, std::errc> {
    return std::visit(
        [&](auto &owning_message) -> std::expected<std::vector<std::byte>, std::errc> {
          using owning_message_t = std::remove_reference_t<decltype(owning_message)>;
          using non_owning_message_t =
              decltype(hpp_proto::rebind_traits<hpp_proto::non_owning_traits>(owning_message));
          auto msg_name = message_name(owning_message);
          non_owning_message_t non_owning_message;
          hpp_proto::message_value_mref dyn_message = factory.get_message(msg_name, mr).value();

          // Google's parser can accept bytes that serialize differently for map fields. Example schema:
          // ```
          // message TestMap {
          //   map<int32, int32> field = 4;
          // }
          // ```
          // The bytes "\x22\x04\x28\x00\x10\x01" may parse yet re-encode as "\x22\x04\x08\x00\x10\x01".
          // Hpp-proto does not show this behavior, so raw parse results are not directly comparable.

          auto non_owning_read_ok = util::read_binpb(non_owning_message, input, hpp_proto::alloc_from{mr}).ok();
          auto owning_read_ok = util::read_binpb(owning_message, input).ok();
          auto dyn_read_ok = util::read_binpb(dyn_message, input).ok();

          assert(non_owning_read_ok == owning_read_ok && owning_read_ok == dyn_read_ok);
          if (dyn_read_ok) {
            auto non_owning_write = round_trip_test(non_owning_message, non_owning_message_t{});
            auto owning_write = round_trip_test(owning_message, owning_message_t{});
            auto dyn_write = round_trip_test(dyn_message, factory.get_message(msg_name, mr).value());

            if (msg_name != "protobuf_unittest.TestMap"sv && msg_name != "proto2_unittest.TestWellKnownTypes"sv) {
              // Map fields can reorder entries on read, so encoded bytes may differ.
              assert(non_owning_write == owning_write);
            }
            if (non_owning_write != dyn_write) {
              std::string non_owing_json;
              assert(util::write_json(non_owning_message, non_owing_json).ok());
              std::cout << "non_owning: " << non_owing_json << "\n";
              std::string dyn_json;
              assert(util::write_json(dyn_message, dyn_json).ok());
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

  auto input = std::as_bytes(std::span{data, size - 1});
  auto non_split_result = do_read(input);
  if (size > 32) {
    auto splitted = split_input(input);
    auto split_result = do_read(std::span(splitted));
    assert(non_split_result == split_result);
  }

  return non_split_result.has_value() ? 0 : -1;
}
