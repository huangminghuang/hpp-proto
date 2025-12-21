#pragma once
#include <algorithm>
#include <cassert> // Added for assert
#include <functional>
#include <fuzzer/FuzzedDataProvider.h>

#include <hpp_proto/dynamic_message/factory.hpp>
#include <hpp_proto/dynamic_message/binpb.hpp>

std::vector<char> read_file(const char *filename);

static hpp::proto::dynamic_message_factory factory;

extern "C" __attribute__((visibility("default"))) int LLVMFuzzerInitialize(int *argc, char ***argv) {
  return factory.init(read_file("../tests/unittest.desc.binpb")) ? 0 : -1;
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

namespace concepts {
template <typename T>
concept use_non_owning_traits =
    requires { requires std::same_as<typename T::hpp_proto_traits_type, ::hpp::proto::non_owning_traits>; };
}; // namespace concepts