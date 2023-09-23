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
#include <cassert>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

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

#if !defined(__cpp_lib_flat_map)
#define HPP_PROTO_DISABLE_THREEWAY_COMPARATOR
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
    if constexpr (std::is_same_v<std::remove_cvref_t<decltype(Default)>, std::monostate>) {
      return this->value_or(T{});
    } else if constexpr (requires { T{Default.data(), Default.size()}; }) {
      return this->value_or(T{Default.data(), Default.size()});
    } else if constexpr (requires {
                           requires sizeof(typename T::value_type) == sizeof(typename decltype(Default)::value_type);
                           T{(const typename T::value_type *)Default.data(),
                             (const typename T::value_type *)Default.data() + Default.size()};
                         }) {
      return this->value_or(T{(const typename T::value_type *)Default.data(),
                              (const typename T::value_type *)Default.data() + Default.size()});
    } else {
      return this->value_or(unwrap(Default));
    }
  }

  constexpr bool operator==(const optional &other) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARATOR
  constexpr auto operator<=>(const optional &other) const = default;
#endif
};

// remove the implicit conversions for optional<bool> because those are very error-prone to use.
template <auto Default>
class optional<bool, Default> {
  uint8_t impl = 0x80; // use 0x80 to denote empty state
  static constexpr bool as_bool(bool v) { return v; }
  static constexpr bool as_bool(std::monostate) { return false; }
  static constexpr bool default_value = as_bool(Default);
  bool &deref() { return *std::bit_cast<bool *>(&impl); }

public:
  using value_type = bool;
  constexpr optional() noexcept = default;
  constexpr optional(bool v) noexcept { impl = uint8_t(v); };
  constexpr optional(const optional &) noexcept = default;
  constexpr optional &operator=(const optional &) noexcept = default;

  constexpr bool has_value() const noexcept { return impl != 0x80; }
  constexpr bool operator*() const noexcept {
    assert(has_value());
    return impl;
  }
  bool &operator*() noexcept {
    assert(has_value());
    return deref();
  }

  bool &emplace() noexcept {
    impl = uint8_t(default_value);
    return deref();
  }
  constexpr bool value() const {
    if (!has_value()) {
      throw std::bad_optional_access{};
    }
    return impl;
  }

  constexpr bool value_or_default() const noexcept {
    if (has_value()) {
      return impl;
    }
    return default_value;
  }

  constexpr optional &operator=(bool v) noexcept {
    impl = uint8_t(v);
    return *this;
  }
  constexpr bool operator==(const optional &other) const = default;
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
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *obj;
  }
  constexpr const T &value() const {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
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
    if (has_value() && rhs.has_value()) {
      return *obj == *rhs.obj;
    } else {
      return has_value() == rhs.has_value();
    }
  }

  constexpr bool operator==(std::nullopt_t) const { return !has_value(); }

#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARATOR

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
};

template <compile_time_string cts>
struct cts_wrapper {
  static constexpr compile_time_string str{cts};
  constexpr size_t size() const { return str.size(); }
  constexpr const char *data() const { return str.data(); }
  constexpr const char *c_str() const { return str.data(); }

  operator std::string() const { return std::string{data()}; }
  operator std::vector<std::byte>() const {
    return std::vector<std::byte>{std::bit_cast<const std::byte *>(data()),
                                  std::bit_cast<const std::byte *>(data()) + size()};
  }

  operator std::vector<char>() const { return std::vector<char>{data(), data() + size()}; }

  operator std::string_view() const { return std::string_view(data(), size()); }
  operator std::span<const std::byte>() const {
    return std::span<const std::byte>{std::bit_cast<const std::byte *>(data()), size()};
  }
  operator std::span<char>() const { return std::span<char>{data(), size()}; }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::string &rhs) {
    return static_cast<std::string>(lhs) == rhs;
  }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::string_view &rhs) {
    return static_cast<std::string_view>(lhs) == rhs;
  }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::vector<std::byte> &rhs) {
    return static_cast<std::vector<std::byte>>(lhs) == rhs;
  }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::span<const std::byte> &rhs) {
    const std::byte *b = std::bit_cast<const std::byte *>(lhs.data());
    return std::equal(rhs.begin(), rhs.end(), b, b + lhs.size());
  }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::vector<char> &rhs) {
    return static_cast<std::vector<char>>(lhs) == rhs;
  }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::span<const char> &rhs) {
    return std::equal(rhs.begin(), rhs.end(), lhs.data(), lhs.data() + lhs.size());
  }
};

using bytes = std::vector<std::byte>;
using bytes_view = std::span<const std::byte>;

namespace literals {

template <compile_time_string str>
constexpr auto operator""_cts() {
  return cts_wrapper<str>{};
}

template <compile_time_string str>
constexpr auto operator""_bytes() {
  return static_cast<bytes>(cts_wrapper<str>{});
}

template <compile_time_string str>
auto operator""_bytes_view() {
  return static_cast<bytes_view>(cts_wrapper<str>{});
}

} // namespace literals

struct boolean {
  bool value = false;
  boolean() = default;
  boolean(bool v) : value(v) {}
  operator bool() const { return value; }
};

template <typename T, auto Default = std::monostate{}>
constexpr bool is_default_value(const T &val) {
  if constexpr (std::is_same_v<std::remove_cvref_t<decltype(Default)>, std::monostate>) {
    if constexpr (requires { val.empty(); }) {
      return val.empty();
    }
    if constexpr (requires { val.has_value(); }) {
      return !val.has_value();
    }
    if constexpr (std::is_class_v<T>) {
      return false;
    } else {
      return val == T{};
    }
  } else if constexpr (requires { val.has_value(); }) {
    return val.has_value() && Default == *val;
  } else {
    return Default == val;
  }
}

namespace concepts {
template <typename T>
concept memory_resource = requires(T &object) {
  { object.allocate(8, 8) } -> std::same_as<void *>;
};
} // namespace concepts

namespace detail {

template <typename T, concepts::memory_resource MemoryResource>
class growable_span {
public:
  using value_type = std::remove_const_t<T>;

  growable_span(std::span<T> &base, MemoryResource &mr) : base_(base), mr(mr) {}

  void resize(std::size_t n) {
    if (data_ == nullptr || n > base_.size()) {
      data_ = static_cast<value_type *>(mr.allocate(n * sizeof(value_type), alignof(value_type)));
      assert(data_ != nullptr);
      std::uninitialized_copy(base_.begin(), base_.end(), data_);

      if constexpr (!std::is_trivial_v<T>) {
        std::uninitialized_default_construct(data_ + base_.size(), data_ + n);
      } else {
#ifdef __cpp_lib_start_lifetime_as
        std::start_lifetime_as_array(data_ + base.size(), n);
#endif
      }
      base_ = std::span<T>{data_, n};
    } else {
      base_ = std::span<T>(base_.data(), n);
    }
  }

  value_type *data() const { return data_; }
  value_type &operator[](std::size_t n) { return data_[n]; }
  std::size_t size() const { return base_.size(); }
  value_type *begin() const { return data_; }
  value_type *end() const { return data_ + size(); }

  void clear() {
    base_ = std::span<T>{};
    data_ = nullptr;
  }

private:
  std::span<T> &base_;
  value_type *data_ = nullptr;
  MemoryResource &mr;
};
} // namespace detail

} // namespace hpp::proto
