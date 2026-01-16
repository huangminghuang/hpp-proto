#pragma once
#include <compare>

namespace hpp::proto {

template <typename T>
class indirect_view {

public:
  using value_type = T;

private:
  using pointer = const T *;
  pointer obj_;

  static const T *default_object() {
    static T default_obj;
    return &default_obj;
  }

public:
  constexpr indirect_view() : obj_(default_object()) {}
  // NOLINTNEXTLINE
  constexpr indirect_view(pointer obj) : obj_(obj) {}
  constexpr indirect_view(const indirect_view &) = default;
  constexpr indirect_view(indirect_view &&) = default;
  ~indirect_view() = default;

  constexpr indirect_view &operator=(indirect_view &&) = default;
  constexpr indirect_view &operator=(const indirect_view &) = default;
  constexpr indirect_view &operator=(pointer obj) {
    obj_ = obj;
    return *this;
  }

  [[nodiscard]] constexpr const T &value() const noexcept { return *obj_; }
  constexpr const T &operator*() const noexcept { return *obj_; }
  constexpr const T *operator->() const noexcept { return obj_; }

  constexpr bool operator==(const T &rhs) const { return *obj_ == rhs; }
  constexpr bool operator==(const indirect_view &rhs) const { return *obj_ == *rhs.obj_; }

  constexpr auto operator<=>(const T &rhs) const { return *obj_ <=> rhs; }
  constexpr auto operator<=>(const indirect_view &rhs) const { return *obj_ <=> *rhs.obj_; }

  constexpr void swap(indirect_view &other) noexcept { std::swap(obj_, other.obj_); }
};
} // namespace hpp::proto