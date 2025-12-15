#include <algorithm>
#include <cassert> // Added for assert
#include <functional>
#include <fuzzer/FuzzedDataProvider.h>
#include <google/protobuf/map_unittest.pb.hpp>
#include <google/protobuf/unittest.pb.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>
#include <hpp_proto/dynamic_message.hpp>
#include <numeric>
#include <ranges>
#include <variant>

std::string read_file(const char *filename);

static hpp::proto::dynamic_message_factory factory;

extern "C" __attribute__((visibility("default"))) int LLVMFuzzerInitialize(int *argc, char ***argv) {
  return factory.init(read_file("../tests/unittest.desc.binpb")) ? 0 : -1;
}

// Define the variant of all message types we fuzz
using message_variant_t = std::variant<proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits>,
                                       protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits>,
                                       protobuf_unittest::TestMap<hpp::proto::non_owning_traits>>;

std::vector<std::vector<char>> split_input(FuzzedDataProvider &provider) {
  std::vector<std::vector<char>> result;
  while (result.size() < 9) {
    auto v = provider.ConsumeBytes<char>(provider.ConsumeIntegralInRange<int>(10, 128));
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

bool buffer_equal(const std::vector<char> &lhs, const std::vector<char> &rhs) { return std::ranges::equal(lhs, rhs); }

bool buffer_equal(const std::vector<char> &lhs, const std::vector<std::vector<char>> &rhs) {
  return std::ranges::equal(lhs, rhs | std::views::join);
}

// Helper function to set variant by runtime index
template <typename... Ts>
void set_variant_by_index(std::variant<Ts...> &v, size_t index) {
  // 1. Define the Variant type for clarity
  using VariantType = std::variant<Ts...>;
  constexpr size_t Size = sizeof...(Ts);

  // 2. Create a static table of function pointers
  static constexpr auto table = []<size_t... Is>(std::index_sequence<Is...>) {
    return std::array<void (*)(VariantType &), Size>{// Expand a lambda for every index I
                                                     [](VariantType &var) { var.template emplace<Is>(); }...};
  }(std::make_index_sequence<Size>{});
  table[index](v);
}

static std::string_view message_name(const auto &message) {
  std::string_view type_url = message_type_url(message);
  auto slash_pos = type_url.find('/');
  return type_url.substr(slash_pos + 1);
}

extern "C" __attribute__((visibility("default"))) int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  // choice_options encodes message type and whether to split input.
  // Maximum choice_options will be (std::variant_size_v<message_variant_t> * 2 - 1).
  // Using uint8_t will consume 1 byte for this option.
  uint8_t choice_options = provider.ConsumeIntegralInRange<uint8_t>(0, std::variant_size_v<message_variant_t> * 2 - 1);

  std::pmr::monotonic_buffer_resource mr; // Needs to be alive during read_proto
  message_variant_t message_variant;      // Holds the deserialized message

  auto message_type_index = choice_options % std::variant_size_v<message_variant_t>;

  // Extract further options from choice_options
  bool to_split = (choice_options / std::variant_size_v<message_variant_t>) % 2;

  set_variant_by_index(message_variant, message_type_index);

  hpp::proto::status status;
  auto do_read = [&](const auto &input) {
    return std::visit(
        [&](auto &non_owning_message) {
          using non_owning_message_t = std::remove_reference_t<decltype(non_owning_message)>;
          using owning_message_t = decltype(hpp::proto::rebind_traits(non_owning_message));
          owning_message_t owning_message;
          auto dyn_message = factory.get_message(message_name(owning_message), mr).value();

          auto non_owning_read_ok = hpp::proto::read_proto(non_owning_message, input, hpp::proto::alloc_from{mr}).ok();
          auto owning_read_ok = hpp::proto::read_proto(owning_message, input).ok();
          auto dyn_read_ok = hpp::proto::read_proto(dyn_message, input).ok();

          assert(non_owning_read_ok == owning_read_ok && owning_read_ok == dyn_read_ok);
          if (dyn_read_ok) {
            std::vector<char> intermediate_buffer;
            assert(hpp::proto::write_proto(non_owning_message, intermediate_buffer).ok());
            assert(buffer_equal(intermediate_buffer, input));

            intermediate_buffer.resize(0);
            assert(hpp::proto::write_proto(owning_message, intermediate_buffer).ok());
            if (message_type_index != 2) {
              // The output can only be stable when there are no map fields; otherwise,
              // the field elements would be reordered.
              assert(buffer_equal(intermediate_buffer, input));
            }

            intermediate_buffer.resize(0);
            assert(hpp::proto::write_proto(dyn_message, intermediate_buffer).ok());
            assert(buffer_equal(intermediate_buffer, input));
          }
          return dyn_read_ok ? 0 : -1;
        },
        message_variant);
  };

  return to_split ? do_read(split_input(provider)) : do_read(provider.ConsumeRemainingBytes<char>());
}
