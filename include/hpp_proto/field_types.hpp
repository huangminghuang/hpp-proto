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

#include <algorithm>
#include <cassert>
#include <functional>
#include <hpp_proto/flat_map.hpp>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>
namespace hpp::proto {
using stdext::flat_map;
}

namespace hpp::proto {

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

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#if defined(__clang__)
#define HPP_PROTO_WRAP_FLOAT(v)                                                                                        \
  hpp::proto::float_wrapper<std::bit_cast<int32_t>(v)> {}
#define HPP_PROTO_WRAP_DOUBLE(v)                                                                                       \
  hpp::proto::double_wrapper<std::bit_cast<int64_t>(v)> {}
#else
#define HPP_PROTO_WRAP_FLOAT(v) v
#define HPP_PROTO_WRAP_DOUBLE(v) v
#endif
// NOLINTEND(cppcoreguidelines-macro-usage)

template <int64_t x>
static constexpr auto unwrap(double_wrapper<x> /* unused */) {
  return std::bit_cast<double>(x);
}

template <int32_t x>
static constexpr auto unwrap(float_wrapper<x> /* unused */) {
  return std::bit_cast<float>(x);
}

template <typename T>
static constexpr auto unwrap(T v) {
  return v;
}

// NOLINTBEGIN(hicpp-explicit-conversions)
template <typename T, auto Default = std::monostate{}>
class optional {
public:
  static constexpr bool has_default_value = true;
  constexpr static T default_value() {
    if constexpr (std::is_same_v<std::remove_cvref_t<decltype(Default)>, std::monostate>) {
      return T{};
    } else if constexpr (std::is_fundamental_v<T> || std::is_enum_v<T>) {
      return unwrap(Default);
    } else {
      static_assert(sizeof(typename T::value_type) == 1);
      return T{(const typename T::value_type *)Default.data(),
               (const typename T::value_type *)Default.data() + Default.size()};
    }
  }

private:
  T _value = default_value();
  bool _present = false;

public:
  using value_type = T;

  constexpr optional() noexcept = default;
  constexpr ~optional() noexcept = default;
  constexpr optional(std::nullopt_t /* unused */) noexcept {}

  constexpr optional(optional &&other) = default;
  constexpr optional(const optional &) = default;

  template <class U>
  constexpr optional(const optional<U> &other) : _value(other._value), _present(other.present) {}

  template <class U>
  constexpr optional(optional<U> &&other) : _value(std::move(other)._value), _present(other.present) {}

  constexpr optional(const std::optional<T> &other)
      : _value(other.value_or(default_value())), _present(other.has_value()) {}

  constexpr optional(std::optional<T> &&other) : _present(other.has_value()) {
    _value = std::move(other).value_or(default_value());
  }

  template <class U>
  constexpr optional(const std::optional<U> &other)
      : _value(other.value_or(default_value())), _present(other.has_value()) {}

  template <class U>
  constexpr optional(std::optional<U> &&other) : _present(other.has_value()) {
    _value = std::move(other).value_or(default_value());
  }

  template <class... Args>
  constexpr explicit optional(std::in_place_t, Args &&...args) : _value(std::forward<Args>(args)...), _present(true) {}

  template <class U, class... Args>
  constexpr explicit optional(std::in_place_t, std::initializer_list<U> list, Args &&...args)
      : _value(list, std::forward<Args>(args)...), _present(true) {}

  template <typename U>
    requires std::convertible_to<U, T>
  constexpr optional(U &&value) : _value(std::forward<U>(value)), _present(true) {}

  constexpr optional &operator=(std::nullopt_t /* unused */) noexcept {
    this->reset();
    return *this;
  }

  template <typename U>
    requires std::convertible_to<U, T>
  constexpr optional &operator=(U &&value) {
    static_assert(!std::is_pointer_v<T>);
    _value = static_cast<T>(std::forward<U>(value));
    _present = true;
    return *this;
  }

  constexpr optional &operator=(const optional &) = default;
  constexpr optional &operator=(optional &&) = default;

  template <class U>
    requires std::convertible_to<U, T>
  constexpr optional &operator=(const optional<U> &other) {
    _value = *other;
    _present = other.has_value();
    return *this;
  }

  template <class U>
  constexpr optional &operator=(optional<U> &&other) {
    _value = std::move(other)._value;
    _present = other.has_value();
    return *this;
  }

  constexpr optional &operator=(const std::optional<T> &other) {
    _value = other.value_or(default_value());
    _present = other.has_value();
    return *this;
  }

  constexpr optional &operator=(std::optional<T> &&other) {
    _value = std::move(other).value_or(default_value());
    _present = other.has_value();
    return *this;
  }

  [[nodiscard]] constexpr bool has_value() const noexcept { return _present; }
  [[nodiscard]] constexpr operator bool() const noexcept { return _present; }

  [[nodiscard]] constexpr T &value() & { return _value; }
  [[nodiscard]] constexpr const T &value() const & { return _value; }
  [[nodiscard]] constexpr T &&value() && { return std::move(_value); }
  [[nodiscard]] constexpr const T &&value() const && { return static_cast<const T &&>(_value); }

  template <class U>
  constexpr T value_or(U &&default_value) const & {
    return has_value() ? _value : static_cast<T>(std::forward<U>(default_value));
  }
  template <class U>
  constexpr T value_or(U &&default_value) && {
    return has_value() ? std::move(_value) : static_cast<T>(std::forward<U>(default_value));
  }

  constexpr T *operator->() noexcept { return &_value; }
  constexpr const T *operator->() const noexcept { return &_value; }

  constexpr T &operator*() & noexcept { return value(); }
  constexpr const T &operator*() const & noexcept { return value(); }

  constexpr T &&operator*() && noexcept { return value(); }
  constexpr const T &&operator*() const && noexcept { return value(); }

  template <typename... Args>
  constexpr T &emplace(Args &&...args) {
    _value = T{std::forward<Args>(args)...};
    _present = true;
    return _value;
  }

  constexpr void swap(optional &other) noexcept {
    using std::swap;
    swap(_value, other._value);
    swap(_present, other._present);
  }

  constexpr void reset() noexcept {
    _value = default_value();
    _present = false;
  }

  template <class F>
  constexpr auto and_then(F &&f) & {
    if (has_value()) {
      return std::invoke(std::forward<F>(f), _value);
    } else {
      return std::remove_cvref_t<std::invoke_result_t<F, T &>>{};
    }
  }

  template <class F>
  constexpr auto and_then(F &&f) const & {
    if (has_value()) {
      return std::invoke(std::forward<F>(f), _value);
    } else {
      return std::remove_cvref_t<std::invoke_result_t<F, const T &>>{};
    }
  }

  template <class F>
  constexpr auto and_then(F &&f) && {
    if (has_value()) {
      return std::invoke(std::forward<F>(f), std::move(_value));
    } else {
      return std::remove_cvref_t<std::invoke_result_t<F, const T>>{};
    }
  }

  template <class F>
  constexpr auto and_then(F &&f) const && {
    if (has_value()) {
      return std::invoke(std::forward<F>(f), std::move(_value));
    } else {
      return std::remove_cvref_t<std::invoke_result_t<F, const T>>{};
    }
  }

  template <class F>
  constexpr auto transform(F &&f) & {
    using U = std::remove_cv_t<std::invoke_result_t<F, T &>>;
    if (has_value()) {
      return std::optional<U>{std::invoke(std::forward<F>(f), _value)};
    } else {
      return std::optional<U>{};
    }
  }

  template <class F>
  constexpr auto transform(F &&f) const & {
    using U = std::remove_cv_t<std::invoke_result_t<F, const T &>>;
    if (has_value()) {
      return std::optional<U>{std::invoke(std::forward<F>(f), _value)};
    } else {
      return std::optional<U>{};
    }
  }

  template <class F>
  constexpr auto transform(F &&f) && {
    using U = std::remove_cv_t<std::invoke_result_t<F, T>>;
    if (has_value()) {
      return std::optional<U>{std::invoke(std::forward<F>(f), std::move(_value))};
    } else {
      return std::optional<U>{};
    }
  }

  template <class F>
  constexpr auto transform(F &&f) const && {
    using U = std::remove_cv_t<std::invoke_result_t<F, const T>>;
    if (has_value()) {
      return std::optional<U>{std::invoke(std::forward<F>(f), std::move(_value))};
    } else {
      return std::optional<U>{};
    }
  }

  template <class F>
  constexpr optional or_else(F &&f) const & {
    return has_value() ? _value : std::forward<F>(f)();
  }

  template <class F>
  constexpr optional or_else(F &&f) && {
    return has_value() ? std::move(_value) : std::forward<F>(f)();
  }

  constexpr bool operator==(const optional &other) const = default;
};

// remove the implicit conversions for optional<bool> because those are very error-prone to use.
template <auto Default>
class optional<bool, Default> {
  static constexpr bool as_bool(bool v) { return v; }
  static constexpr bool as_bool(std::monostate) { return false; }

public:
  static constexpr bool has_default_value = true;
  static constexpr bool default_value() { return as_bool(Default); }

private:
  static constexpr uint8_t default_state = 0x80 | uint8_t(default_value()); // use 0x80 to denote empty state
  bool &deref() { return reinterpret_cast<bool &>(impl); }
  uint8_t impl = default_state;

public:
  using value_type = bool;
  constexpr optional() noexcept = default;
  constexpr ~optional() noexcept = default;
  constexpr optional(bool v) noexcept : impl(uint8_t(v)) {};
  constexpr optional(const optional &) noexcept = default;
  constexpr optional(optional &&) noexcept = default;
  constexpr optional &operator=(const optional &) noexcept = default;
  constexpr optional &operator=(optional &&) noexcept = default;

  [[nodiscard]] constexpr bool has_value() const noexcept { return (impl & 0x80) == 0; }
  constexpr bool operator*() const noexcept { return value(); }

  bool &emplace() noexcept {
    impl = uint8_t(default_value());
    return deref();
  }

  bool &emplace(bool v) noexcept {
    impl = uint8_t(v);
    return deref();
  }

  [[nodiscard]] constexpr bool value() const { return static_cast<bool>(impl & 0x01); }

  constexpr optional &operator=(bool v) noexcept {
    impl = uint8_t(v);
    return *this;
  }
  constexpr bool operator==(const optional &other) const = default;

  constexpr void swap(optional &other) noexcept { std::swap(impl, other.impl); }
  constexpr void reset() noexcept { impl = default_state; }

  template <class F>
  constexpr auto and_then(F &&f) const {
    if (has_value()) {
      return std::invoke(std::forward<F>(f), value());
    } else {
      return std::remove_cvref_t<std::invoke_result_t<F, bool>>{};
    }
  }

  template <class F>
  constexpr auto transform(F &&f) const {
    using U = std::remove_cv_t<std::invoke_result_t<F, bool>>;
    if (has_value()) {
      return std::optional<U>{std::invoke(std::forward<F>(f), value())};
    } else {
      return std::optional<U>{};
    }
  }
};

template <typename T>
class heap_based_optional {
  std::unique_ptr<T> obj;

public:
  using value_type = T;
  constexpr heap_based_optional() noexcept = default;
  constexpr ~heap_based_optional() noexcept = default;

  constexpr heap_based_optional(std::nullopt_t /* unused */) noexcept {};

  constexpr heap_based_optional(const T &object) : obj(new T(object)) {}
  constexpr heap_based_optional(heap_based_optional &&other) noexcept : obj(std::move(other)) {}
  constexpr heap_based_optional(const heap_based_optional &other) : obj(other.obj ? new T(*other.obj) : nullptr) {}

  template <class... Args>
  constexpr explicit heap_based_optional(std::in_place_t, Args &&...args)
      : obj(new T{std::forward<Args &&>(args)...}) {}

  // NOLINTBEGIN(cppcoreguidelines-rvalue-reference-param-not-moved)
  constexpr heap_based_optional &operator=(heap_based_optional &&other) noexcept {
    obj = std::move(other.obj);
    return *this;
  }
  // NOLINTEND(cppcoreguidelines-rvalue-reference-param-not-moved)

  constexpr heap_based_optional &operator=(const heap_based_optional &other) {
    heap_based_optional tmp(other);
    obj = std::move(tmp.obj);
    return *this;
  }

  [[nodiscard]] constexpr bool has_value() const noexcept { return static_cast<bool>(obj); }
  constexpr operator bool() const noexcept { return has_value(); }

  constexpr T &value() {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *obj;
  }
  [[nodiscard]] constexpr const T &value() const {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *obj;
  }

  constexpr T &operator*() noexcept { return *obj; }
  constexpr const T &operator*() const noexcept { return *obj; }

  constexpr T *operator->() noexcept { return *obj; }
  constexpr const T *operator->() const noexcept { return *obj; }

  constexpr T &emplace() {
    obj = std::make_unique<T>();
    return *obj;
  }

  constexpr void swap(heap_based_optional &other) noexcept { std::swap(obj, other.obj); }
  constexpr void reset() noexcept { obj.reset(); }

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

  constexpr bool operator==(std::nullopt_t /* unused */) const { return !has_value(); }
};

template <typename T>
class optional_message_view {
  const T *obj = nullptr;

public:
  using value_type = T;
  constexpr optional_message_view() noexcept = default;
  constexpr ~optional_message_view() noexcept = default;

  constexpr optional_message_view(std::nullptr_t /* unused */) noexcept {};

  constexpr optional_message_view(const T *object) : obj(object) {}
  constexpr optional_message_view(optional_message_view &&other) noexcept : obj(other.obj) {}
  constexpr optional_message_view(const optional_message_view &other) noexcept : obj(other.obj) {}

  // NOLINTBEGIN(cppcoreguidelines-rvalue-reference-param-not-moved)
  constexpr optional_message_view &operator=(optional_message_view &&other) noexcept {
    obj = other.obj;
    return *this;
  }
  // NOLINTEND(cppcoreguidelines-rvalue-reference-param-not-moved)

  // NOLINTBEGIN(bugprone-unhandled-self-assignment, cert-oop54-cpp)
  constexpr optional_message_view &operator=(const optional_message_view &other) noexcept {
    obj = other.obj;
    return *this;
  }
  // NOLINTEND(bugprone-unhandled-self-assignment, cert-oop54-cpp)

  constexpr optional_message_view &operator=(const T *other) noexcept {
    obj = other;
    return *this;
  }

  constexpr optional_message_view &operator=(std::nullptr_t /* unused */) noexcept {
    obj = nullptr;
    return *this;
  }

  [[nodiscard]] constexpr bool has_value() const noexcept { return static_cast<bool>(obj); }
  constexpr operator bool() const noexcept { return has_value(); }

  [[nodiscard]] constexpr const T &value() const {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *obj;
  }

  constexpr const T &operator*() const noexcept { return *obj; }

  constexpr const T *operator->() const noexcept { return obj; }

  constexpr void swap(optional_message_view &other) noexcept { std::swap(obj, other.obj); }
  constexpr void reset() noexcept { obj = nullptr; }

  constexpr bool operator==(const optional_message_view &rhs) const {
    if (has_value() && rhs.has_value()) {
      return *obj == *rhs.obj;
    } else {
      return has_value() == rhs.has_value();
    }
  }

  constexpr bool operator==(std::nullptr_t /* unused */) const { return !has_value(); }
};

// NOLINTBEGIN(cppcoreguidelines-special-member-functions,hicpp-special-member-functions)
template <typename T>
class equality_comparable_span : public std::span<T> {
public:
  using std::span<T>::span;
  constexpr equality_comparable_span(const equality_comparable_span &other) noexcept
      : std::span<T>(other.data(), other.size()) {}

  constexpr equality_comparable_span &operator=(const equality_comparable_span &other) noexcept = default;

  // NOLINTBEGIN(cppcoreguidelines-c-copy-assignment-signature)
  template <typename U>
  constexpr equality_comparable_span &operator=(const std::span<U> &other) noexcept {
    static_cast<std::span<T> &>(*this) = other;
    return *this;
  }
  // NOLINTEND(cppcoreguidelines-c-copy-assignment-signature)

  friend constexpr bool operator==(const equality_comparable_span<T> &lhs, const equality_comparable_span<T> &rhs) {
    return std::ranges::equal(lhs, rhs);
  }
};
// NOLINTEND(cppcoreguidelines-special-member-functions,hicpp-special-member-functions)

template <std::size_t Len>
struct compile_time_string {
  using value_type = char;
  char data_[Len] = {};
  [[nodiscard]] constexpr std::size_t size() const { return Len - 1; }
  constexpr compile_time_string(const char (&init)[Len]) { std::copy_n(&init[0], Len, &data_[0]); }
  [[nodiscard]] constexpr const char *data() const { return &data_[0]; }
};

template <std::size_t Len>
struct compile_time_bytes {
  using value_type = char;
  std::byte data_[Len] = {};
  [[nodiscard]] constexpr std::size_t size() const { return Len - 1; }
  constexpr compile_time_bytes(const char (&init)[Len]) {
    std::transform(&init[0], &init[Len], &data_[0], [](char c) { return static_cast<std::byte>(c); });
  }
  [[nodiscard]] constexpr const std::byte *data() const { return &data_[0]; }
};

template <compile_time_string cts>
struct bytes_literal {
  static constexpr compile_time_bytes bytes{cts.data_};

  [[nodiscard]] constexpr size_t size() const { return bytes.size(); }
  [[nodiscard]] constexpr const std::byte *data() const { return bytes.data(); }
  [[nodiscard]] constexpr const std::byte *begin() const { return bytes.data(); }
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  [[nodiscard]] constexpr const std::byte *end() const { return bytes.data() + size(); }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

  constexpr operator equality_comparable_span<const std::byte>() const {
    return equality_comparable_span<const std::byte>{data(), size()};
  }
  explicit operator std::vector<std::byte>() const { return std::vector<std::byte>{begin(), end()}; }

  friend constexpr bool operator==(const bytes_literal &lhs, const equality_comparable_span<const std::byte> &rhs) {
    return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
  }
};

namespace concepts {
template <typename Type>
concept byte_type = std::same_as<std::remove_cv_t<Type>, char> || std::same_as<std::remove_cv_t<Type>, unsigned char> ||
                    std::same_as<std::remove_cv_t<Type>, std::byte>;

template <typename Type>
concept flat_map = requires {
  typename Type::key_type;
  typename Type::mapped_type;
  requires std::same_as<Type, ::hpp::proto::flat_map<typename Type::key_type, typename Type::mapped_type>>;
};
}; // namespace concepts

template <compile_time_string cts>
struct string_literal {
  static constexpr compile_time_string str{cts};
  [[nodiscard]] constexpr size_t size() const { return str.size(); }
  [[nodiscard]] constexpr const char *data() const { return str.data(); }
  [[nodiscard]] constexpr const char *c_str() const { return str.data(); }
  [[nodiscard]] constexpr const char *begin() const { return str.data(); }
  [[nodiscard]] constexpr const char *end() const { return str.data() + size(); }

  explicit operator std::string() const { return std::string{data()}; }
  constexpr operator std::string_view() const { return std::string_view(data(), size()); }

  friend constexpr bool operator==(const string_literal &lhs, const std::string &rhs) {
    return static_cast<std::string_view>(lhs) == rhs;
  }

  friend constexpr bool operator==(const string_literal &lhs, const std::string_view &rhs) {
    return static_cast<std::string_view>(lhs) == rhs;
  }
};

using bytes = std::vector<std::byte>;
using bytes_view = equality_comparable_span<const std::byte>;

struct boolean {
  bool value = false;
  constexpr boolean() = default;
  constexpr boolean(bool v) : value(v) {}
  constexpr operator bool() const { return value; }
};
// NOLINTEND(hicpp-explicit-conversions)

template <typename T, auto Default = std::monostate{}>
constexpr bool is_default_value(const T &val) {
  if constexpr (std::is_same_v<std::remove_cvref_t<decltype(Default)>, std::monostate>) {
    if constexpr (requires { val.empty(); }) {
      return val.empty();
    } else if constexpr (requires { val.has_value(); }) {
      return !val.has_value();
    } else if constexpr (std::is_class_v<T>) {
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

inline const char *message_name(auto &&v)
  requires requires { message_type_url(v); }
{
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  return message_type_url(v).c_str() + std::size("type.googleapis.com");
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}

template <concepts::flat_map T>
constexpr static void reserve(T &mut, std::size_t size) {
  typename T::key_container_type keys;
  typename T::mapped_container_type values;
  keys.reserve(size);
  values.reserve(size);
  mut.replace(std::move(keys), std::move(values));
}
} // namespace hpp::proto
