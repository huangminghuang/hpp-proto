// MIT License
//
// Copyright (c) 2024 Huang-Ming Huang
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <cstddef>
#include <concepts>
#include <ranges>
#include <span>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>

#include <hpp_proto/memory_resource_utils.hpp>
#include <hpp_proto/binpb/varint.hpp>
namespace hpp::proto::concepts {

template <typename T>
concept is_enum = std::is_enum_v<T> && !std::same_as<std::byte, T>;

template <typename T>
concept is_boolean = std::same_as<hpp::proto::boolean, T>;

template <typename T>
concept is_empty = std::is_empty_v<T>;


template <typename T>
concept associative_container = std::ranges::range<T> && requires(T container) { typename std::remove_cvref_t<T>::key_type; };

template <typename T>
concept tuple = !std::ranges::range<T> && requires(T tuple) { sizeof(std::tuple_size<std::remove_cvref_t<T>>); };

template <typename T>
concept variant = requires(T variant) {
  variant.index();
  std::get_if<0>(&variant);
  std::variant_size_v<std::remove_cvref_t<T>>;
};

template <typename T>
concept string_value_type = std::same_as<T, char> || std::same_as<T, char8_t>;

template <typename T>
concept repeated = std::ranges::contiguous_range<T> && !byte_type<typename T::value_type>;

template <typename T>
concept basic_string_view = requires {
  typename T::value_type;
  requires string_value_type<typename T::value_type>;
  requires std::same_as<T, std::basic_string_view<typename T::value_type, std::char_traits<typename T::value_type>>>;
};

template <typename T>
concept basic_string = requires {
  typename T::value_type;
  typename T::allocator_type;
  requires string_value_type<typename T::value_type>;
  requires std::same_as<T, std::basic_string<typename T::value_type, std::char_traits<typename T::value_type>,
                                             typename T::allocator_type>>;
};

template <typename T>
concept string_like = basic_string_view<T> || basic_string<T>;

template <typename T>
concept has_local_meta = concepts::tuple<typename std::decay_t<T>::pb_meta>;

template <typename T>
concept has_explicit_meta = concepts::tuple<decltype(pb_meta(std::declval<T>()))>;

template <typename T>
concept has_meta = has_local_meta<T> || has_explicit_meta<T>;

template <typename T>
concept dereferenceable = requires(T item) { *item; };

template <typename T>
concept optional_message_view = std::same_as<T, ::hpp::proto::optional_message_view<typename T::value_type>>;

template <typename T>
concept oneof_type = concepts::variant<T>;

template <typename T>
concept arithmetic = std::is_arithmetic_v<T> || concepts::varint<T>;

template <typename T>
concept singular = arithmetic<T> || is_enum<T> || basic_string<T> || contiguous_byte_range<T>;

template <typename T>
concept is_map_entry = requires {
  typename T::key_type;
  typename T::mapped_type;
};

template <typename T>
concept is_pair = std::same_as<T, std::pair<typename T::first_type, typename T::second_type>>;

template <typename T>
concept span = requires {
  typename T::element_type;
  requires std::derived_from<T, std::span<typename T::element_type>> || concepts::basic_string_view<T>;
};

template <typename T>
concept is_oneof_field_meta = requires { typename T::alternatives_meta; };

template <typename T>
concept byte_deserializable = (std::is_arithmetic_v<T> && !std::same_as<T, bool>) || std::same_as<std::byte, T>;

template <typename T>
concept is_size_cache_iterator = requires(T v) {
  { v++ } -> std::same_as<T>;
  *v;
};

template <typename T>
concept non_owning_bytes =
    basic_string_view<std::remove_cvref_t<T>> ||
    (concepts::dynamic_sized_view<std::remove_cvref_t<T>> && concepts::byte_type<typename T::value_type>);

template <typename T>
concept has_extension = has_meta<T> && requires(T value) { value.extensions; };

template <typename T>
concept pb_extensions = requires {
  typename T::unknown_fields_range_t::value_type;
  requires is_pair<typename T::unknown_fields_range_t::value_type>;
} && (!std::is_empty_v<std::remove_cvref_t<T>>);

template <typename T>
concept pb_unknown_fields =
    requires { typename T::unknown_fields_range_t; } && (!std::is_empty_v<std::remove_cvref_t<T>>) && !pb_extensions<T>;

template <typename T>
concept has_unknown_fields_or_extensions = has_meta<T> && requires(T value) {
  value.pb_unknown_fields_;
  requires pb_unknown_fields<decltype(value.pb_unknown_fields_)> || pb_extensions<decltype(value.pb_unknown_fields_)>;
};

template <typename T>
concept no_cached_size = is_enum<T> || byte_serializable<T> || concepts::varint<T> || pb_unknown_fields<T> ||
                         pb_extensions<T> || std::is_empty_v<T>;

template <typename T>
concept is_basic_in = requires { typename T::is_basic_in; };

template <typename T>
concept is_basic_out = requires { typename T::is_basic_out; };

template <typename Range>
concept segmented_byte_range = std::ranges::random_access_range<Range> && contiguous_byte_range<std::ranges::range_value_t<Range>>;

template <typename Range>
concept input_byte_range = segmented_byte_range<Range> || contiguous_byte_range<Range>;

template <typename R>
concept uint32_pair_contiguous_range = std::ranges::contiguous_range<R> && is_pair<std::ranges::range_value_t<R>> &&
                                       std::same_as<typename std::ranges::range_value_t<R>::first_type, std::uint32_t>;

template <typename T, typename U>
concept isomorphic_message =
    requires(T t, U u) { requires std::same_as<decltype(rebind_traits(t)), decltype(rebind_traits(u))>; };

template <typename T>
concept is_any = requires(T &obj) {
  { obj.type_url };
  requires concepts::string_like<std::remove_reference_t<decltype(obj.type_url)>>;
  { obj.value } -> concepts::contiguous_byte_range;
};

template <typename T>
concept string_view_or_bytes_view = std::same_as<T, bytes_view> || concepts::basic_string_view<T>;

template <typename T>
concept arithmetic_pair = is_pair<T> && std::is_arithmetic_v<typename T::first_type> && std::is_arithmetic_v<typename T::second_type>;

} // namespace hpp::proto::concepts

