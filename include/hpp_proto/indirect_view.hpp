#pragma once
#include <cassert>
#include <compare>

namespace hpp_proto {

template <typename T>
class indirect_view {

public:
  using value_type = T;

private:
  T* obj_ = nullptr;

  static const T *default_object() {
    static T default_obj;
    return &default_obj;
  }

public:
  constexpr indirect_view() = default;
  // NOLINTNEXTLINE
  constexpr indirect_view(T* obj) : obj_(obj) {}
  constexpr indirect_view(const indirect_view &) = default;
  constexpr indirect_view(indirect_view &&) = default;
  ~indirect_view() = default;

  constexpr indirect_view &operator=(indirect_view &&) = default;
  constexpr indirect_view &operator=(const indirect_view &) = default;
  constexpr void reset(T *obj) {
    obj_ = obj;
  }

  [[nodiscard]] T *pointer() const { return obj_; }
  [[nodiscard]] constexpr const T &value() const noexcept { return obj_ == nullptr ? *default_object() : *obj_; }
  constexpr const T &operator*() const noexcept { return value(); }
  constexpr const T *operator->() const noexcept { return std::addressof(value()); }

  constexpr bool operator==(const T &rhs) const
    requires requires { value() == rhs; }
  {
    return value() == rhs;
  }
  constexpr bool operator==(const indirect_view &rhs) const
    requires requires { value() == rhs.value(); }
  {
    return value() == rhs.value();
  }

  constexpr auto operator<=>(const T &rhs) const
    requires requires { value() <=> rhs; }
  {
    return value() <=> rhs;
  }
  constexpr auto operator<=>(const indirect_view &rhs) const
    requires requires { *obj_ <=> *rhs.obj_; }
  {
    return value() <=> rhs.value();
  }

  constexpr void swap(indirect_view &other) noexcept { std::swap(obj_, other.obj_); }
};
} // namespace hpp_proto