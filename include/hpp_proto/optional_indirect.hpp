#pragma once

#include <functional>
#include <initializer_list>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

namespace hpp_proto {

template <typename T, typename Allocator = std::allocator<T>>
class optional_indirect {
public:
  using value_type = T;
  using allocator_type = std::allocator_traits<Allocator>::template rebind_alloc<T>;
  using allocator_arg_t = std::allocator_arg_t;

private:
  using allocator_traits = std::allocator_traits<allocator_type>;
  using pointer = allocator_traits::pointer;

  [[no_unique_address]] allocator_type alloc_{};
  pointer obj_ = nullptr;

public:
  constexpr optional_indirect() noexcept = default;
  // NOLINTNEXTLINE(modernize-pass-by-value)
  constexpr explicit optional_indirect(const allocator_type &alloc) noexcept : alloc_(alloc) {}
  // NOLINTNEXTLINE(modernize-pass-by-value)
  constexpr optional_indirect(allocator_arg_t /*allocator_arg*/, const allocator_type &alloc) noexcept
      : alloc_(alloc) {}
  constexpr ~optional_indirect() noexcept { reset(); }

  constexpr explicit optional_indirect(std::nullopt_t /* unused */) noexcept {};
  // NOLINTNEXTLINE(modernize-pass-by-value)
  constexpr optional_indirect(allocator_arg_t /*allocator_arg*/, const allocator_type &alloc,
                              std::nullopt_t /* unused */) noexcept
      : alloc_(alloc) {}

  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  constexpr optional_indirect(const T &object) { emplace(object); }
  // NOLINTNEXTLINE(modernize-pass-by-value)
  constexpr optional_indirect(allocator_arg_t /*allocator_arg*/, const allocator_type &alloc, const T &object)
      : alloc_(alloc) {
    emplace(object);
  }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  constexpr optional_indirect(T &&object) { emplace(std::move(object)); }
  // NOLINTNEXTLINE(modernize-pass-by-value)
  constexpr optional_indirect(allocator_arg_t /*allocator_arg*/, const allocator_type &alloc, T &&object)
      : alloc_(alloc) {
    emplace(std::move(object));
  }
  constexpr optional_indirect(optional_indirect &&other) noexcept(std::is_nothrow_move_constructible_v<allocator_type>)
      : alloc_(std::move(other.alloc_)), obj_(std::exchange(other.obj_, nullptr)) {}
  constexpr optional_indirect(const optional_indirect &other) // NOLINT(misc-no-recursion)
      : alloc_(allocator_traits::select_on_container_copy_construction(other.alloc_)) {
    if (other.obj_) {
      emplace(*other.raw_ptr());
    }
  }
  // NOLINTNEXTLINE(modernize-pass-by-value)
  constexpr optional_indirect(allocator_arg_t /*allocator_arg*/, const allocator_type &alloc,
                              const optional_indirect &other)
      : alloc_(alloc) {
    if (other.obj_) {
      emplace(*other.raw_ptr());
    }
  }
  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved,modernize-pass-by-value)
  constexpr optional_indirect(allocator_arg_t /*allocator_arg*/, const allocator_type &alloc, optional_indirect &&other)
      : alloc_(alloc) {
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
  constexpr explicit optional_indirect(std::in_place_t /*in_place*/, Args &&...args) {
    emplace(std::forward<Args>(args)...);
  }
  template <class... Args>
  // NOLINTNEXTLINE(modernize-pass-by-value)
  constexpr explicit optional_indirect(allocator_arg_t /*allocator_arg*/, const allocator_type &alloc,
                                       std::in_place_t /*in_place*/, Args &&...args)
      : alloc_(alloc) {
    emplace(std::forward<Args>(args)...);
  }

  constexpr optional_indirect &
  operator=(optional_indirect &&other) noexcept(std::is_nothrow_move_assignable_v<allocator_type>)
    requires(allocator_traits::propagate_on_container_move_assignment::value)
  {
    move_assign_with_allocator_propagation(other);
    return *this;
  }

  constexpr optional_indirect &operator=(optional_indirect &&other) noexcept
    requires(!allocator_traits::propagate_on_container_move_assignment::value &&
             allocator_traits::is_always_equal::value)
  {
    move_assign_with_equal_allocator(other);
    return *this;
  }

  // Unequal non-propagating allocators require value move/allocate fallback, so this overload cannot be noexcept.
  // NOLINTNEXTLINE(bugprone-exception-escape,cppcoreguidelines-noexcept-move-operations,hicpp-noexcept-move,misc-no-recursion,performance-noexcept-move-constructor)
  constexpr optional_indirect &operator=(optional_indirect &&other)
    requires(!allocator_traits::propagate_on_container_move_assignment::value &&
             !allocator_traits::is_always_equal::value)
  {
    move_assign_with_runtime_allocator_check(other);
    return *this;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  constexpr optional_indirect &operator=(T &&other) {
    if (obj_) {
      *raw_ptr() = std::move(other);
    } else {
      emplace(std::move(other));
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

  constexpr T &value() & {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *raw_ptr();
  }
  [[nodiscard]] constexpr const T &value() const & {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *raw_ptr();
  }
  [[nodiscard]] constexpr T &&value() && {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return std::move(*raw_ptr());
  }
  [[nodiscard]] constexpr const T &&value() const && {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return std::move(*raw_ptr());
  }

  constexpr T &operator*() & noexcept { return *raw_ptr(); }
  constexpr const T &operator*() const & noexcept { return *raw_ptr(); }
  constexpr T &&operator*() && noexcept { return std::move(*raw_ptr()); }
  constexpr const T &&operator*() const && noexcept { return std::move(*raw_ptr()); }

  constexpr T *operator->() noexcept { return raw_ptr(); }
  constexpr const T *operator->() const noexcept { return raw_ptr(); }

  constexpr T &emplace() { return emplace_impl(); }

  template <class... Args>
  constexpr T &emplace(Args &&...args) { // NOLINT(misc-no-recursion)
    return emplace_impl(std::forward<Args>(args)...);
  }

  constexpr void swap(optional_indirect &other) noexcept(std::is_nothrow_swappable_v<allocator_type>)
    requires(allocator_traits::propagate_on_container_swap::value)
  {
    swap_with_allocator_propagation(other);
  }

  constexpr void swap(optional_indirect &other) noexcept
    requires(!allocator_traits::propagate_on_container_swap::value && allocator_traits::is_always_equal::value)
  {
    swap_with_equal_allocator(other);
  }

  // Unequal non-propagating allocators require value move/allocate fallback, so this overload cannot be noexcept.
  // NOLINTNEXTLINE(bugprone-exception-escape,cppcoreguidelines-noexcept-swap,performance-noexcept-swap)
  constexpr void swap(optional_indirect &other)
    requires(!allocator_traits::propagate_on_container_swap::value && !allocator_traits::is_always_equal::value)
  {
    swap_with_runtime_allocator_check(other);
  }

  constexpr void reset() noexcept {
    if (obj_) {
      allocator_traits::destroy(alloc_, std::to_address(obj_));
      allocator_traits::deallocate(alloc_, obj_, 1);
      obj_ = nullptr;
    }
  }

  constexpr bool operator==(const T &rhs) const {
    if (has_value()) {
      return **this == rhs;
    }
    return false;
  }

  // NOLINTNEXTLINE(misc-no-recursion)
  constexpr bool operator==(const optional_indirect &rhs) const {
    if (has_value()) {
      return rhs.has_value() && *raw_ptr() == *rhs.raw_ptr();
    }
    return !rhs.has_value();
  }

  constexpr bool operator==(std::nullopt_t /* unused */) const noexcept { return !has_value(); }

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
  template <class... Args>
  constexpr T &emplace_impl(Args &&...args) { // NOLINT(misc-no-recursion)
    auto *new_obj = allocator_traits::allocate(alloc_, 1);
    try {
      allocator_traits::construct(alloc_, std::to_address(new_obj), std::forward<Args>(args)...);
    } catch (...) {
      allocator_traits::deallocate(alloc_, new_obj, 1);
      throw;
    }
    if (obj_) {
      allocator_traits::destroy(alloc_, std::to_address(obj_));
      allocator_traits::deallocate(alloc_, obj_, 1);
    }
    obj_ = new_obj;
    return *raw_ptr();
  }

  [[nodiscard]] constexpr T *raw_ptr() noexcept { return std::to_address(obj_); }
  [[nodiscard]] constexpr const T *raw_ptr() const noexcept { return std::to_address(obj_); }

  constexpr void move_assign_with_allocator_propagation(optional_indirect &other) noexcept(
      std::is_nothrow_move_assignable_v<allocator_type>) {
    if (this != &other) {
      release_object();
      alloc_ = std::move(other.alloc_);
      take_object_from(other);
    }
  }

  constexpr void move_assign_with_equal_allocator(optional_indirect &other) noexcept {
    if (this != &other) {
      release_object();
      take_object_from(other);
    }
  }

  constexpr void move_assign_with_runtime_allocator_check(optional_indirect &other) {
    if (this != &other && !try_take_object_with_equal_allocator(other)) {
      move_value_or_release(other);
    }
  }

  constexpr bool try_take_object_with_equal_allocator(optional_indirect &other) {
    if (!(alloc_ == other.alloc_)) {
      return false;
    }
    release_object();
    take_object_from(other);
    return true;
  }

  constexpr void move_value_or_release(optional_indirect &other) {
    if (other.obj_) {
      move_value_from(other);
    } else {
      release_object();
    }
  }

  constexpr void move_value_from(optional_indirect &other) {
    if (obj_) {
      *raw_ptr() = std::move(*other.raw_ptr());
    } else {
      emplace(std::move(*other.raw_ptr()));
    }
  }

  constexpr void
  swap_with_allocator_propagation(optional_indirect &other) noexcept(std::is_nothrow_swappable_v<allocator_type>) {
    if (this != &other) {
      swap_allocators(other);
      swap_object_pointers(other);
    }
  }

  constexpr void swap_with_equal_allocator(optional_indirect &other) noexcept {
    if (this != &other) {
      swap_object_pointers(other);
    }
  }

  constexpr void swap_with_runtime_allocator_check(optional_indirect &other) {
    if (this != &other && !try_swap_object_with_equal_allocator(other)) {
      swap_values_or_rehome(other);
    }
  }

  constexpr bool try_swap_object_with_equal_allocator(optional_indirect &other) {
    if (!(alloc_ == other.alloc_)) {
      return false;
    }
    swap_object_pointers(other);
    return true;
  }

  constexpr void swap_values_or_rehome(optional_indirect &other) {
    if (both_have_objects(other)) {
      swap_object_values(other);
    } else {
      rehome_present_value(other);
    }
  }

  constexpr void rehome_present_value(optional_indirect &other) {
    if (obj_) {
      move_value_to_empty(other);
    } else if (other.obj_) {
      other.move_value_to_empty(*this);
    }
  }

  [[nodiscard]] constexpr bool both_have_objects(const optional_indirect &other) const noexcept {
    return obj_ && other.obj_;
  }

  constexpr void swap_allocators(optional_indirect &other) noexcept(std::is_nothrow_swappable_v<allocator_type>) {
    using std::swap;
    swap(alloc_, other.alloc_);
  }

  constexpr void swap_object_pointers(optional_indirect &other) noexcept {
    using std::swap;
    swap(obj_, other.obj_);
  }

  constexpr void swap_object_values(optional_indirect &other) {
    using std::swap;
    swap(*raw_ptr(), *other.raw_ptr());
  }

  constexpr void move_value_to_empty(optional_indirect &empty) {
    empty.emplace(std::move(*raw_ptr()));
    release_object();
  }

  constexpr void take_object_from(optional_indirect &other) noexcept { obj_ = std::exchange(other.obj_, nullptr); }

  constexpr void release_object() noexcept { reset(); }
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
    }
    return has_value() == rhs.has_value();
  }

  constexpr bool operator==(std::nullptr_t /* unused */) const noexcept { return !has_value(); }

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

} // namespace hpp_proto
