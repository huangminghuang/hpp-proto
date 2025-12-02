#pragma once
#include <algorithm>
#include <array>
#include <functional>
#include <type_traits>
#include <hpp_proto/memory_resource_utils.hpp>
#include <ranges>
#include <string_view>

namespace hpp::proto {

/// Used to represent the protobuf encoded binary stream of google.protobuf.FileDescriptorProto
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
concept file_descriptor_pb_range =
    std::ranges::input_range<T> && std::same_as<typename std::ranges::range_value_t<T>, file_descriptor_pb>;
} // namespace concepts

template <std::size_t N>
class distinct_file_descriptor_pb_array : public std::array<file_descriptor_pb, N> {
public:
  constexpr explicit distinct_file_descriptor_pb_array(std::initializer_list<file_descriptor_pb> list)
      : std::array<file_descriptor_pb, N>{} {
    std::copy_n(list.begin(), std::min(list.size(), N), this->begin());
  }
};

template <typename... Ts>
  requires(sizeof...(Ts) > 0 && (std::is_convertible_v<Ts, file_descriptor_pb> && ...))
distinct_file_descriptor_pb_array(Ts...)->distinct_file_descriptor_pb_array<sizeof...(Ts)>;

// TODO: an consteval function to combine multiple distinct_file_descriptor_pb_array into one

} // namespace hpp::proto

namespace std {
template <>
struct hash<hpp::proto::file_descriptor_pb> {
  size_t operator()(const hpp::proto::file_descriptor_pb &d) const noexcept {
    return std::hash<std::string_view>{}(d.value);
  }
};
} // namespace std
