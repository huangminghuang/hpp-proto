// MIT License
//
// Copyright (c) 2023 Huang-Ming Huang
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

#include <algorithm>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>
#include <span>

#if __has_include(<flat_map>)
#include <flat_map>
namespace hpp::proto {
using std::flat_map;
}
#else
#include <hpp_proto/flat_map.h>
namespace hpp::proto {
using stdext::flat_map;
}
#endif

#ifdef _LIBCPP_VERSION
#define HPP_PROTO_DISABLE_THREEWAY_COMPARITOR
#endif
namespace hpp::proto {



#ifndef __cpp_lib_bit_cast
namespace std {
using namespace ::std;
template <class ToType, class FromType,
          class = enable_if_t<sizeof(ToType) == sizeof(FromType) && is_trivially_copyable_v<ToType> &&
                              is_trivially_copyable_v<FromType>>>
constexpr ToType bit_cast(FromType const &from) noexcept {
  return __builtin_bit_cast(ToType, from);
}
} // namespace std
#endif

// workaround for clang not supporting floating-point types in non-type template
// parameters as of clang-15
template <int64_t x>
struct double_wrapper {
  constexpr bool operator==(double v) const { return v == std::bit_cast<double>(x); }
};
template <int32_t x>
struct float_wrapper {
  constexpr bool operator==(float v) const { return v == std::bit_cast<float>(x); }
};

#if defined(__clang__)
#if defined(__cpp_lib_bit_cast)
#define HPP_PROTO_WRAP_FLOAT(v)                                                                                        \
  hpp::proto::float_wrapper<std::bit_cast<int32_t>(v)> {}
#define HPP_PROTO_WRAP_DOUBLE(v)                                                                                       \
  hpp::proto::double_wrapper<std::bit_cast<int64_t>(v)> {}
#else
#define HPP_PROTO_WRAP_FLOAT(v)                                                                                        \
  hpp::proto::float_wrapper<hpp::proto::std::bit_cast<int32_t>(v)> {}
#define HPP_PROTO_WRAP_DOUBLE(v)                                                                                       \
  hpp::proto::double_wrapper<hpp::proto::std::bit_cast<int64_t>(v)> {}
#endif
#else
#define HPP_PROTO_WRAP_FLOAT(v) v
#define HPP_PROTO_WRAP_DOUBLE(v) v
#endif

template <int64_t x>
static constexpr auto unwrap(double_wrapper<x>) {
  return std::bit_cast<double>(x);
}

template <int32_t x>
static constexpr auto unwrap(float_wrapper<x>) {
  return std::bit_cast<float>(x);
}

template <typename T>
static constexpr auto unwrap(T v) {
  return v;
}

template <typename T, auto Default = std::monostate{}>
class optional {
  std::optional<T> impl;

public:
  using value_type = T;

  constexpr optional() noexcept = default;
  constexpr optional(std::nullopt_t) noexcept : impl(std::nullopt) {}

  constexpr optional(optional &&) = default;
  constexpr optional(const optional &) = default;

  template <class U>
  constexpr optional(const optional<U> &other) : impl(other.impl) {}
  template <class U>
  constexpr optional(optional<U> &&other) : impl(std::move(other.impl)) {}

  constexpr optional(const std::optional<T> &other) : impl(other) {}
  constexpr optional(std::optional<T> &&other) : impl(std::move(other)) {}
  template <class U>
  constexpr optional(const std::optional<U> &other) : impl(other) {}
  template <class U>
  constexpr optional(std::optional<U> &&other) : impl(std::move(other)) {}

  template <class... Args>
  constexpr explicit optional(std::in_place_t, Args &&...args) : impl(std::in_place, forward<Args>(args)...) {}

  template <class U, class... Args>
  constexpr explicit optional(std::in_place_t, std::initializer_list<U> ilist, Args &&...args)
      : impl(std::in_place, ilist, forward<Args>(args)...) {}

  template <typename U>
    requires std::convertible_to<U, T>
  constexpr optional(U &&value) : impl(std::forward<U>(value)) {}

  constexpr optional &operator=(std::nullopt_t) noexcept {
    impl = std::nullopt;
    return *this;
  }

  template <typename U>
    requires std::convertible_to<U, T>
  constexpr optional &operator=(U &&value) {
    impl = std::forward<U>(value);
    return *this;
  }

  constexpr optional &operator=(const optional &) = default;
  constexpr optional &operator=(optional &&) = default;

  template <class U>
  constexpr optional &operator=(const optional<U> &other) {
    impl = other.imp;
    return *this;
  }
  template <class U>
  constexpr optional &operator=(optional<U> &&other) {
    impl = std::move(other.imp);
    return *this;
  }

  constexpr optional &operator=(const std::optional<T> &v) {
    impl = v;
    return *this;
  }

  constexpr optional &operator=(std::optional<T> &&v) {
    impl = move(v);
    return *this;
  }

  constexpr bool has_value() const noexcept { return impl.has_value(); }
  constexpr operator bool() const noexcept { return has_value(); }

  constexpr T &value() & { return impl.value(); }
  constexpr const T &value() const & { return impl.value(); }
  constexpr T &&value() && { return std::move(impl.value()); }
  constexpr const T &&value() const && { return std::move(impl.value()); }

  template <class U>
  constexpr T value_or(U &&default_value) const & {
    return impl.value_or(default_value);
  }
  template <class U>
  constexpr T value_or(U &&default_value) && {
    return impl.value_or(default_value);
  }

  constexpr T *operator->() noexcept { return impl.operator->(); }
  constexpr const T *operator->() const noexcept { return impl.operator->(); }

  constexpr T &operator*() & noexcept { return *impl; }
  constexpr const T &operator*() const & noexcept { return *impl; }
  constexpr T &&operator*() && noexcept { return *impl; }
  constexpr const T &&operator*() const && noexcept { return *impl; }

  template <typename... Args>
  constexpr T &emplace(Args &&...args) {
    return impl.emplace(std::forward<Args>(args)...);
  }
  constexpr void swap(optional &other) noexcept { impl.swap(other.impl); }
  constexpr void reset() noexcept { impl.reset(); }

  constexpr T value_or_default() const {
    if constexpr (std::is_same_v<std::remove_cvref_t<decltype(Default)>, std::monostate>)
      return this->value_or(T{});
    else if constexpr (requires { T{Default.data(), Default.size()}; }) {
      return this->value_or(T{Default.data(), Default.size()});
    } else if constexpr (requires {
                           requires sizeof(typename T::value_type) == sizeof(typename decltype(Default)::value_type);
                           T{(const typename T::value_type *)Default.data(),
                             (const typename T::value_type *)Default.data() + Default.size()};
                         }) {
      return this->value_or(T{(const typename T::value_type *)Default.data(),
                              (const typename T::value_type *)Default.data() + Default.size()});
    } else
      return this->value_or(unwrap(Default));
  }

  constexpr bool operator==(const optional &other) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR
  constexpr auto operator<=>(const optional &other) const = default;
#endif
};

template <typename T>
class heap_based_optional {
  T *obj = nullptr;

public:
  using value_type = T;
  constexpr heap_based_optional() noexcept {}
  constexpr heap_based_optional(std::nullopt_t) noexcept {}
  constexpr ~heap_based_optional() { delete obj; }

  constexpr heap_based_optional(const T &object) : obj(new T(object)) {}
  constexpr heap_based_optional(heap_based_optional &&other) noexcept { std::swap(obj, other.obj); }
  constexpr heap_based_optional(const heap_based_optional &other) : obj(other.obj ? new T(*other.obj) : nullptr) {}

  template <class... Args>
  constexpr explicit heap_based_optional(std::in_place_t, Args &&...args)
      : obj(new T{std::forward<Args &&>(args)...}) {}

  constexpr heap_based_optional &operator=(heap_based_optional &&other) noexcept {
    std::swap(obj, other.obj);
    return *this;
  }

  constexpr heap_based_optional &operator=(const heap_based_optional &other) {
    heap_based_optional tmp(other);
    std::swap(obj, tmp.obj);
    return *this;
  }

  constexpr bool has_value() const noexcept { return obj; }
  constexpr operator bool() const noexcept { return has_value(); }

  constexpr T &value() {
    if (!has_value())
      throw std::bad_optional_access();
    return *obj;
  }
  constexpr const T &value() const {
    if (!has_value())
      throw std::bad_optional_access();
    return *obj;
  }

  constexpr T &operator*() noexcept { return *obj; }
  constexpr const T &operator*() const noexcept { return *obj; }

  constexpr T *operator->() noexcept { return obj; }
  constexpr const T *operator->() const noexcept { return obj; }

  constexpr T &emplace() {
    heap_based_optional tmp;
    tmp.obj = new T;
    std::swap(obj, tmp.obj);
    return *obj;
  }

  constexpr void swap(heap_based_optional &other) noexcept { std::swap(obj, other.obj); }
  constexpr void reset() noexcept {
    delete obj;
    obj == nullptr;
  }

  constexpr bool operator==(const T &rhs) const {
    if (has_value()) {
      return **this == rhs;
    } else {
      return false;
    }
  }

  constexpr bool operator==(const heap_based_optional &rhs) const {
    if (has_value() && rhs.has_value())
      return **this == *rhs;
    else
      return has_value() == rhs.has_value();
  }

  constexpr bool operator==(std::nullopt_t) const { return !has_value(); }

#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  constexpr std::strong_ordering operator<=>(const heap_based_optional &rhs) const {
    if (has_value() && rhs.has_value()) {
      return **this <=> *rhs;
    } else {
      return has_value() <=> rhs.has_value();
    }
  }

  constexpr std::strong_ordering operator<=>(const T &rhs) const {
    if (has_value()) {
      return **this <=> rhs;
    } else {
      return std::strong_ordering::less;
    }
  }

  constexpr std::strong_ordering operator<=>(std::nullopt_t) const {
    return has_value() ? std::strong_ordering::greater : std::strong_ordering::equal;
  }
#endif
};

template <std::size_t Len>
struct compile_time_string {
  using value_type = char;
  char data_[Len];
  constexpr size_t size() const { return Len - 1; }
  constexpr compile_time_string(const char (&init)[Len]) { std::copy_n(init, Len, data_); }
  constexpr const char *data() const { return data_; }

  constexpr bool operator==(std::string_view v) const { return v == data(); }
  constexpr bool operator==(std::span<const std::byte> v) const {
    const std::byte *b = reinterpret_cast<const std::byte *>(data_);
    return std::equal(v.begin(), v.end(), b, b + size());
  }

  constexpr bool operator==(const std::vector<std::byte>& v) const {
    const std::byte *b = reinterpret_cast<const std::byte *>(data_);
    return std::equal(v.begin(), v.end(), b, b + size());
  }

  constexpr bool operator==(const std::vector<char> &v) const {
    return operator==(std::string_view{v.data(), v.size()});
  }
};

template <compile_time_string str>
const auto make_compile_time_string() {
  return str;
}

namespace literals {
template <compile_time_string str>
constexpr auto operator""_hppproto_s() {
  return str;
}


template <compile_time_string str>
constexpr auto operator""_bytes() {
  const std::byte *b = reinterpret_cast<const std::byte *>(str.data_);
  return std::vector<std::byte>{b, b + str.size()};
}

template <compile_time_string str>
auto operator""_bytes_span() {
  static auto value = str;
  const std::byte *b = reinterpret_cast<const std::byte *>(value.data_);
  return std::span<const std::byte>{b, b + value.size()};
}

} // namespace literals

using bytes = std::vector<std::byte>;

struct boolean {
  bool value = false;
  boolean() = default;
  boolean(bool v) : value(v) {}
  operator bool() const { return value; }
};

template <typename T, auto Default = std::monostate{}>
constexpr bool is_default_value(const T &val) {
  if constexpr (std::is_same_v<decltype(Default), std::monostate>) {
    if constexpr (requires { val.empty(); })
      return val.empty();
    if constexpr (requires { val.has_value(); })
      return !val.has_value();
    if constexpr (std::is_class_v<T>)
      return false;
    else
      return val == T{};
  } else {
    return Default == val;
  }
}

} // namespace hpp::proto
