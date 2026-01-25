#pragma once
#include <algorithm>
#include <cassert> // Added for assert
#include <functional>
#include <fuzzer/FuzzedDataProvider.h>

#include <hpp_proto/dynamic_message/binpb.hpp>
#include <hpp_proto/dynamic_message/factory.hpp>

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables,misc-use-anonymous-namespace)
extern hpp::proto::dynamic_message_factory factory;

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
  table[index](v); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
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

std::span<const std::byte> to_bytes(hpp::proto::concepts::contiguous_byte_range auto const &data) {
  return std::as_bytes(std::span{std::ranges::data(data), std::ranges::size(data)});
}
