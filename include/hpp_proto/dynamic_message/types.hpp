// MIT License
//
// Copyright (c) Huang-Ming Huang
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
#include <cstdint>
#include <ranges>
#include <span>
#include <string_view>
#include <type_traits>

#include <hpp_proto/dynamic_message/repeated_field_iterator.hpp>

namespace hpp::proto {

template <std::ranges::input_range Range>
struct sized_input_range { // NOLINT(hicpp-member-init)
  Range &range_;           // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
  std::size_t size_;

  [[nodiscard]] auto begin() const { return std::ranges::begin(range_); }
  [[nodiscard]] auto end() const { return std::ranges::end(range_); }
  [[nodiscard]] std::size_t size() const { return size_; }
};

template <typename R>
sized_input_range(R &&range, std::size_t size) -> sized_input_range<std::remove_cvref_t<R>>;

template <typename U, typename = void>
struct range_value_or_void {
  using type = void;
};
template <typename U>
struct range_value_or_void<U, std::void_t<std::ranges::range_value_t<U>>> {
  using type = std::ranges::range_value_t<U>;
};
template <typename U>
using range_value_or_void_t = typename range_value_or_void<U>::type;

template <typename T>
struct get_traits {
  using type = T;
};

enum class field_kind_t : uint8_t {
  KIND_DOUBLE = 1,
  KIND_FLOAT = 2,
  KIND_INT64 = 3,
  KIND_UINT64 = 4,
  KIND_INT32 = 5,
  KIND_FIXED64 = 6,
  KIND_FIXED32 = 7,
  KIND_BOOL = 8,
  KIND_STRING = 9,
  KIND_MESSAGE = 11,
  KIND_BYTES = 12,
  KIND_UINT32 = 13,
  KIND_ENUM = 14,
  KIND_SFIXED32 = 15,
  KIND_SFIXED64 = 16,
  KIND_SINT32 = 17,
  KIND_SINT64 = 18,
  KIND_REPEATED_DOUBLE = 19,
  KIND_REPEATED_FLOAT = 20,
  KIND_REPEATED_INT64 = 21,
  KIND_REPEATED_UINT64 = 22,
  KIND_REPEATED_INT32 = 23,
  KIND_REPEATED_FIXED64 = 24,
  KIND_REPEATED_FIXED32 = 25,
  KIND_REPEATED_BOOL = 26,
  KIND_REPEATED_STRING = 27,
  KIND_REPEATED_MESSAGE = 29,
  KIND_REPEATED_BYTES = 30,
  KIND_REPEATED_UINT32 = 31,
  KIND_REPEATED_ENUM = 32,
  KIND_REPEATED_SFIXED32 = 33,
  KIND_REPEATED_SFIXED64 = 34,
  KIND_REPEATED_SINT32 = 35,
  KIND_REPEATED_SINT64 = 36
};

enum class wellknown_types_t : uint8_t {
  NONE = 0,
  ANY = 1,
  TIMESTAMP = 2,
  DURATION = 3,
  FIELDMASK = 4,
  VALUE = 5,
  LISTVALUE = 6,
  STRUCT = 7,
  WRAPPER = 8
};

enum class dynamic_message_errc : uint8_t {
  no_error,
  no_such_field,
  no_such_value,
  invalid_field_type,
  invalid_enum_name,
  unknown_enum_value,
  wrong_message_type,
  unknown_message_name
};

namespace concepts {
template <typename T>
concept contiguous_std_byte_range =
    std::ranges::contiguous_range<T> && std::same_as<std::ranges::range_value_t<T>, std::byte>;

template <typename T>
concept const_field_ref = !T::is_mutable && requires { T::field_kind; };

template <typename T>
concept mutable_field_ref = T::is_mutable && requires { T::field_kind; };
} // namespace concepts

template <typename T>
struct value_type_identity {
  using value_type = T;
};

template <typename T>
struct value_proxy {
  T value;
  [[nodiscard]] T *operator->() noexcept { return std::addressof(value); }
  [[nodiscard]] const T *operator->() const noexcept { return std::addressof(value); }
};

} // namespace hpp::proto
