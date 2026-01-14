#pragma once

#include <functional>
#include <initializer_list>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

namespace hpp::proto {

template <typename T, typename Allocator = std::allocator<T>>
class optional_indirect {
public:
  using value_type = T;
  using allocator_type = typename std::allocator_traits<Allocator>::template rebind_alloc<T>;
  using allocator_arg_t = std::allocator_arg_t;

private:
  using allocator_traits = std::allocator_traits<allocator_type>;
  using pointer = typename allocator_traits::pointer;

  [[no_unique_address]] allocator_type alloc_{};
  pointer obj_ = nullptr;

public:
  constexpr optional_indirect() noexcept = default;
  constexpr explicit optional_indirect(const allocator_type &alloc) noexcept : alloc_(alloc) {}
  constexpr optional_indirect(allocator_arg_t, const allocator_type &alloc) noexcept : alloc_(alloc) {}
  constexpr ~optional_indirect() noexcept { reset(); }

  constexpr explicit optional_indirect(std::nullopt_t /* unused */) noexcept {};
  constexpr optional_indirect(allocator_arg_t, const allocator_type &alloc, std::nullopt_t /* unused */) noexcept
      : alloc_(alloc) {}

  // NOLINTNEXTLINE
  constexpr optional_indirect(const T &object) { emplace(object); }
  constexpr optional_indirect(allocator_arg_t, const allocator_type &alloc, const T &object) : alloc_(alloc) {
    emplace(object);
  }
  constexpr optional_indirect(optional_indirect &&other) noexcept
      : alloc_(std::move(other.alloc_)), obj_(std::exchange(other.obj_, nullptr)) {}
  constexpr optional_indirect(const optional_indirect &other)
      : alloc_(allocator_traits::select_on_container_copy_construction(other.alloc_)) {
    if (other.obj_) {
      emplace(*other.raw_ptr());
    }
  }
  constexpr optional_indirect(allocator_arg_t, const allocator_type &alloc, const optional_indirect &other)
      : alloc_(alloc) {
    if (other.obj_) {
      emplace(*other.raw_ptr());
    }
  }
  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  constexpr optional_indirect(allocator_arg_t, const allocator_type &alloc, optional_indirect &&other) : alloc_(alloc) {
    if constexpr (allocator_traits::is_always_equal::value) {
      obj_ = std::exchange(other.obj_, nullptr);
    } else {
      if (alloc_ == other.alloc_) {
        obj_ = std::exchange(other.obj_, nullptr);
      } else if (other.obj_) {
        emplace(std::move(*other.raw_ptr()));
      }
    }
  }

  template <class... Args>
  constexpr explicit optional_indirect(std::in_place_t, Args &&...args) {
    emplace(std::forward<Args>(args)...);
  }
  template <class... Args>
  constexpr explicit optional_indirect(allocator_arg_t, const allocator_type &alloc, std::in_place_t, Args &&...args)
      : alloc_(alloc) {
    emplace(std::forward<Args>(args)...);
  }

  constexpr optional_indirect &
  operator=(optional_indirect &&other) noexcept(allocator_traits::propagate_on_container_move_assignment::value ||
                                                allocator_traits::is_always_equal::value) {
    if (this == &other) {
      return *this;
    }
    if constexpr (allocator_traits::propagate_on_container_move_assignment::value) {
      reset();
      alloc_ = std::move(other.alloc_);
      obj_ = std::exchange(other.obj_, nullptr);
      return *this;
    }
    if constexpr (allocator_traits::is_always_equal::value) {
      reset();
      obj_ = std::exchange(other.obj_, nullptr);
      return *this;
    }
    if (alloc_ == other.alloc_) {
      reset();
      obj_ = std::exchange(other.obj_, nullptr);
      return *this;
    }
    if (other.obj_) {
      if (obj_) {
        *raw_ptr() = std::move(*other.raw_ptr());
      } else {
        emplace(std::move(*other.raw_ptr()));
      }
    } else {
      reset();
    }
    return *this;
  }

  constexpr optional_indirect &operator=(const optional_indirect &other) {
    if (this != &other) {
      if constexpr (allocator_traits::propagate_on_container_copy_assignment::value) {
        if (alloc_ != other.alloc_) {
          reset();
        }
        alloc_ = other.alloc_;
      }
      if (other.obj_) {
        emplace(*other.raw_ptr());
      } else {
        reset();
      }
    }
    return *this;
  }

  [[nodiscard]] constexpr bool has_value() const noexcept { return obj_ != nullptr; }
  constexpr explicit operator bool() const noexcept { return has_value(); }

  constexpr T &value() {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *raw_ptr();
  }
  [[nodiscard]] constexpr const T &value() const {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *raw_ptr();
  }

  constexpr T &operator*() noexcept { return *raw_ptr(); }
  constexpr const T &operator*() const noexcept { return *raw_ptr(); }

  constexpr T *operator->() noexcept { return raw_ptr(); }
  constexpr const T *operator->() const noexcept { return raw_ptr(); }

  constexpr T &emplace() {
    reset();
    obj_ = allocator_traits::allocate(alloc_, 1);
    allocator_traits::construct(alloc_, obj_);
    return *raw_ptr();
  }

  template <class... Args>
  constexpr T &emplace(Args &&...args) {
    reset();
    obj_ = allocator_traits::allocate(alloc_, 1);
    allocator_traits::construct(alloc_, obj_, std::forward<Args>(args)...);
    return *raw_ptr();
  }

  constexpr void swap(optional_indirect &other) noexcept(allocator_traits::propagate_on_container_swap::value ||
                                                         allocator_traits::is_always_equal::value) {
    if (this == &other) {
      return;
    }
    using std::swap;
    if constexpr (allocator_traits::is_always_equal::value) {
      swap(obj_, other.obj_);
      return;
    }

    if constexpr (allocator_traits::propagate_on_container_swap::value) {
      swap(alloc_, other.alloc_);
    }
    if (alloc_ == other.alloc_) {
      swap(obj_, other.obj_);
    } else if (obj_ && other.obj_) {
      swap(*raw_ptr(), *other.raw_ptr());
    } else if (obj_) {
      other.emplace(std::move(*raw_ptr()));
      reset();
    } else if (other.obj_) {
      emplace(std::move(*other.raw_ptr()));
      other.reset();
    }
  }
  constexpr void reset() noexcept {
    if (obj_) {
      allocator_traits::destroy(alloc_, obj_);
      allocator_traits::deallocate(alloc_, obj_, 1);
      obj_ = nullptr;
    }
  }

  constexpr bool operator==(const T &rhs) const {
    if (has_value()) {
      return **this == rhs;
    } else {
      return false;
    }
  }

  constexpr bool operator==(const optional_indirect &rhs) const {
    if (has_value()) {
      return rhs.has_value() && *raw_ptr() == *rhs.raw_ptr();
    } else {
      return !rhs.has_value();
    }
  }

  constexpr bool operator==(std::nullopt_t /* unused */) const { return !has_value(); }

  [[nodiscard]] constexpr allocator_type get_allocator() const noexcept { return alloc_; }

  template <class F>
  constexpr auto and_then(F &&f) & {
    using result_t = std::remove_cvref_t<std::invoke_result_t<F, T &>>;
    if (has_value()) {
      return std::invoke(std::forward<F>(f), **this);
    }
    return result_t{};
  }

  template <class F>
  constexpr auto and_then(F &&f) const & {
    using result_t = std::remove_cvref_t<std::invoke_result_t<F, const T &>>;
    if (has_value()) {
      return std::invoke(std::forward<F>(f), **this);
    }
    return result_t{};
  }

  template <class F>
  constexpr auto and_then(F &&f) && {
    using result_t = std::remove_cvref_t<std::invoke_result_t<F, T &&>>;
    if (has_value()) {
      return std::invoke(std::forward<F>(f), std::move(**this));
    }
    return result_t{};
  }

  template <class F>
  constexpr auto and_then(F &&f) const && {
    using result_t = std::remove_cvref_t<std::invoke_result_t<F, const T &&>>;
    if (has_value()) {
      return std::invoke(std::forward<F>(f), std::move(**this));
    }
    return result_t{};
  }

  template <class F>
  constexpr auto transform(F &&f) & {
    using result_t = std::remove_cv_t<std::invoke_result_t<F, T &>>;
    if (has_value()) {
      return std::optional<result_t>(std::invoke(std::forward<F>(f), **this));
    }
    return std::optional<result_t>{};
  }

  template <class F>
  constexpr auto transform(F &&f) const & {
    using result_t = std::remove_cv_t<std::invoke_result_t<F, const T &>>;
    if (has_value()) {
      return std::optional<result_t>(std::invoke(std::forward<F>(f), **this));
    }
    return std::optional<result_t>{};
  }

  template <class F>
  constexpr auto transform(F &&f) && {
    using result_t = std::remove_cv_t<std::invoke_result_t<F, T &&>>;
    if (has_value()) {
      return std::optional<result_t>(std::invoke(std::forward<F>(f), std::move(**this)));
    }
    return std::optional<result_t>{};
  }

  template <class F>
  constexpr auto transform(F &&f) const && {
    using result_t = std::remove_cv_t<std::invoke_result_t<F, const T &&>>;
    if (has_value()) {
      return std::optional<result_t>(std::invoke(std::forward<F>(f), std::move(**this)));
    }
    return std::optional<result_t>{};
  }

  template <class F>
  constexpr optional_indirect or_else(F &&f) const & {
    if (has_value()) {
      return *this;
    }
    return std::invoke(std::forward<F>(f));
  }

  template <class F>
  constexpr optional_indirect or_else(F &&f) && {
    if (has_value()) {
      return std::move(*this);
    }
    return std::invoke(std::forward<F>(f));
  }

private:
  [[nodiscard]] constexpr T *raw_ptr() noexcept { return std::to_address(obj_); }
  [[nodiscard]] constexpr const T *raw_ptr() const noexcept { return std::to_address(obj_); }
};

/// Used for recursive non-owning message types
template <typename T>
class optional_indirect_view {
  const T *obj = nullptr;

public:
  using value_type = T;
  constexpr optional_indirect_view() noexcept = default;
  constexpr ~optional_indirect_view() noexcept = default;

  constexpr explicit optional_indirect_view(std::nullptr_t /* unused */) noexcept {};
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  constexpr optional_indirect_view(const T *object) : obj(object) {}
  constexpr optional_indirect_view(optional_indirect_view &&other) noexcept : obj(other.obj) {}
  constexpr optional_indirect_view(const optional_indirect_view &other) noexcept : obj(other.obj) {}

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  constexpr optional_indirect_view &operator=(optional_indirect_view &&other) noexcept {
    obj = other.obj;
    return *this;
  }

  constexpr optional_indirect_view &operator=(const optional_indirect_view &other) noexcept = default;

  constexpr optional_indirect_view &operator=(const T *other) noexcept {
    obj = other;
    return *this;
  }

  constexpr optional_indirect_view &operator=(std::nullptr_t /* unused */) noexcept {
    obj = nullptr;
    return *this;
  }

  [[nodiscard]] constexpr bool has_value() const noexcept { return static_cast<bool>(obj); }
  constexpr explicit operator bool() const noexcept { return has_value(); }

  [[nodiscard]] constexpr const T &value() const {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *obj;
  }

  constexpr const T &operator*() const noexcept { return *obj; }

  constexpr const T *operator->() const noexcept { return obj; }

  constexpr void swap(optional_indirect_view &other) noexcept { std::swap(obj, other.obj); }
  constexpr void reset() noexcept { obj = nullptr; }

  constexpr bool operator==(const optional_indirect_view &rhs) const {
    if (has_value() && rhs.has_value()) {
      return *obj == *rhs.obj;
    } else {
      return has_value() == rhs.has_value();
    }
  }

  constexpr bool operator==(std::nullptr_t /* unused */) const { return !has_value(); }

  template <class F>
  constexpr auto and_then(F &&f) const & {
    using result_t = std::remove_cvref_t<std::invoke_result_t<F, const T &>>;
    if (has_value()) {
      return std::invoke(std::forward<F>(f), **this);
    }
    return result_t{};
  }

  template <class F>
  constexpr auto and_then(F &&f) const && {
    using result_t = std::remove_cvref_t<std::invoke_result_t<F, const T &&>>;
    if (has_value()) {
      return std::invoke(std::forward<F>(f), std::move(**this));
    }
    return result_t{};
  }

  template <class F>
  constexpr auto transform(F &&f) const & {
    using result_t = std::remove_cv_t<std::invoke_result_t<F, const T &>>;
    if (has_value()) {
      return std::optional<result_t>(std::invoke(std::forward<F>(f), **this));
    }
    return std::optional<result_t>{};
  }

  template <class F>
  constexpr auto transform(F &&f) const && {
    using result_t = std::remove_cv_t<std::invoke_result_t<F, const T &&>>;
    if (has_value()) {
      return std::optional<result_t>(std::invoke(std::forward<F>(f), std::move(**this)));
    }
    return std::optional<result_t>{};
  }

  template <class F>
  constexpr optional_indirect_view or_else(F &&f) const & {
    if (has_value()) {
      return *this;
    }
    return std::invoke(std::forward<F>(f));
  }
};

} // namespace hpp::proto
