#pragma once
#include <string_view>
#include <ranges>
#include <hpp_proto/memory_resource_utils.hpp>

namespace hpp::proto {

struct file_descriptor_pb {
  std::string_view value;

  constexpr bool operator==(const file_descriptor_pb &) const = default;
  constexpr bool operator<(const file_descriptor_pb &other) const { return value < other.value; };
};

namespace concepts {
template <typename T>
concept input_bytes_range =
    std::ranges::input_range<T> && contiguous_byte_range<typename std::ranges::range_value_t<T>>;

template <typename T>
concept file_descriptor_pb_array =
    std::ranges::input_range<T> && std::same_as<typename std::ranges::range_value_t<T>, file_descriptor_pb>;
} // namespace concepts
} // namespace hpp::proto
