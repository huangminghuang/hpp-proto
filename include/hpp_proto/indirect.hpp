#pragma once

#include <compare>
#include <initializer_list>
#include <memory>
#include <type_traits>
#include <utility>

namespace hpp_proto {

template <typename T, typename Allocator = std::allocator<T>>
class indirect {
public:
  using value_type = T;
  using allocator_type = std::allocator_traits<Allocator>::template rebind_alloc<T>;
  using allocator_arg_t = std::allocator_arg_t;

private:
  using allocator_traits = std::allocator_traits<allocator_type>;
  using pointer = allocator_traits::pointer;

  [[no_unique_address]] allocator_type alloc_{};
  pointer obj_;

public:
  constexpr indirect() : obj_(allocate_default()) {}
  constexpr explicit indirect(allocator_type alloc) : alloc_(std::move(alloc)), obj_(allocate_default()) {}
  constexpr indirect(allocator_arg_t /*allocator_arg*/, allocator_type alloc)
      : alloc_(std::move(alloc)), obj_(allocate_default()) {}
  constexpr ~indirect() { destroy(); }

  template <class... Args>
  constexpr explicit indirect(std::in_place_t /*allocator_arg*/, Args &&...args)
      : obj_(allocate_construct(std::forward<Args>(args)...)) {}
  template <class... Args>
  constexpr explicit indirect(allocator_arg_t /*allocator_arg*/, allocator_type alloc, std::in_place_t /*in_place*/,
                              Args &&...args)
      : alloc_(std::move(alloc)), obj_(allocate_construct(std::forward<Args>(args)...)) {}

  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  constexpr indirect(T &&object) : obj_(allocate_construct(std::move(object))) {}

  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  constexpr indirect(const T &object) : obj_(allocate_construct(object)) {}

  constexpr indirect(allocator_arg_t /*allocator_arg*/, allocator_type alloc, T &&object)
      : alloc_(std::move(alloc)), obj_(allocate_construct(std::move(object))) {}

  constexpr indirect(const indirect &other)
      : alloc_(allocator_traits::select_on_container_copy_construction(other.alloc_)),
        obj_(allocate_construct(*other.raw_ptr())) {}
  constexpr indirect(indirect &&other) noexcept(std::is_nothrow_move_constructible_v<allocator_type>)
      : alloc_(std::move(other.alloc_)), obj_(std::exchange(other.obj_, nullptr)) {}

  constexpr indirect(allocator_arg_t /*allocator_arg*/, allocator_type alloc, const indirect &other)
      : alloc_(std::move(alloc)), obj_(allocate_construct(*other.raw_ptr())) {}

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  constexpr indirect(allocator_arg_t /*allocator_arg*/, allocator_type alloc, indirect &&other)
      : alloc_(std::move(alloc)) {
    if constexpr (allocator_traits::is_always_equal::value) {
      obj_ = std::exchange(other.obj_, nullptr);
    } else {
      if (alloc_ == other.alloc_) {
        obj_ = std::exchange(other.obj_, nullptr);
      } else if (other.obj_) {
        obj_ = allocate_construct(std::move(*other.raw_ptr()));
      } else {
        obj_ = allocate_default();
      }
    }
  }

  constexpr indirect &operator=(const indirect &other) {
    if (this != &other) {
      if constexpr (allocator_traits::propagate_on_container_copy_assignment::value) {
        if (alloc_ != other.alloc_) {
          destroy();
          alloc_ = other.alloc_;
          obj_ = allocate_construct(*other.raw_ptr());
          return *this;
        }
        alloc_ = other.alloc_;
      }
      if (obj_) {
        *raw_ptr() = *other.raw_ptr();
      } else {
        obj_ = allocate_construct(*other.raw_ptr());
      }
    }
    return *this;
  }

  constexpr indirect &operator=(T &&other) {
    if (obj_) {
      *raw_ptr() = std::move(other);
    } else {
      obj_ = allocate_construct(std::move(other));
    }
    return *this;
  }

  constexpr indirect &operator=(const T &other) {
    if (obj_) {
      *raw_ptr() = other;
    } else {
      obj_ = allocate_construct(other);
    }
    return *this;
  }

  constexpr indirect &operator=(indirect &&other) noexcept(std::is_nothrow_move_assignable_v<allocator_type>)
    requires(allocator_traits::propagate_on_container_move_assignment::value)
  {
    move_assign_with_allocator_propagation(other);
    return *this;
  }

  constexpr indirect &operator=(indirect &&other) noexcept
    requires(!allocator_traits::propagate_on_container_move_assignment::value &&
             allocator_traits::is_always_equal::value)
  {
    move_assign_with_equal_allocator(other);
    return *this;
  }

  // Unequal non-propagating allocators require value move/allocate fallback, so this overload cannot be noexcept.
  // NOLINTNEXTLINE(bugprone-exception-escape,cppcoreguidelines-noexcept-move-operations,hicpp-noexcept-move,performance-noexcept-move-constructor)
  constexpr indirect &operator=(indirect &&other)
    requires(!allocator_traits::propagate_on_container_move_assignment::value &&
             !allocator_traits::is_always_equal::value)
  {
    move_assign_with_runtime_allocator_check(other);
    return *this;
  }

  [[nodiscard]] constexpr T &value() & noexcept { return *raw_ptr(); }
  [[nodiscard]] constexpr const T &value() const & noexcept { return *raw_ptr(); }
  [[nodiscard]] constexpr T &&value() && noexcept { return std::move(*raw_ptr()); }
  [[nodiscard]] constexpr const T &&value() const && noexcept { return std::move(*raw_ptr()); }

  constexpr T &operator*() & noexcept { return *raw_ptr(); }
  constexpr const T &operator*() const & noexcept { return *raw_ptr(); }
  constexpr T &&operator*() && noexcept { return std::move(*raw_ptr()); }
  constexpr const T &&operator*() const && noexcept { return std::move(*raw_ptr()); }

  constexpr T *operator->() noexcept { return raw_ptr(); }
  constexpr const T *operator->() const noexcept { return raw_ptr(); }

  constexpr bool operator==(const T &rhs) const
      noexcept(noexcept(std::declval<const T &>() == std::declval<const T &>()))
    requires requires { *obj_ == rhs; }
  {
    return *raw_ptr() == rhs;
  }
  constexpr bool operator==(const indirect &rhs) const
      noexcept(noexcept(std::declval<const T &>() == std::declval<const T &>()))
    requires requires { *obj_ == *rhs.obj_; }
  {
    return *raw_ptr() == *rhs.raw_ptr();
  }

  constexpr auto operator<=>(const T &rhs) const
      noexcept(noexcept(std::declval<const T &>() <=> std::declval<const T &>()))
    requires requires { *obj_ <=> rhs; }
  {
    return *raw_ptr() <=> rhs;
  }
  constexpr auto operator<=>(const indirect &rhs) const
      noexcept(noexcept(std::declval<const T &>() <=> std::declval<const T &>()))
    requires requires { *obj_ <=> *rhs.obj_; }
  {
    return *raw_ptr() <=> *rhs.raw_ptr();
  }

  constexpr void swap(indirect &other) noexcept(std::is_nothrow_swappable_v<allocator_type>)
    requires(allocator_traits::propagate_on_container_swap::value)
  {
    swap_with_allocator_propagation(other);
  }

  constexpr void swap(indirect &other) noexcept
    requires(!allocator_traits::propagate_on_container_swap::value && allocator_traits::is_always_equal::value)
  {
    swap_with_equal_allocator(other);
  }

  // Unequal non-propagating allocators require value move/allocate fallback, so this overload cannot be noexcept.
  // NOLINTNEXTLINE(bugprone-exception-escape,cppcoreguidelines-noexcept-swap,performance-noexcept-swap)
  constexpr void swap(indirect &other)
    requires(!allocator_traits::propagate_on_container_swap::value && !allocator_traits::is_always_equal::value)
  {
    swap_with_runtime_allocator_check(other);
  }

  [[nodiscard]] constexpr allocator_type get_allocator() const noexcept { return alloc_; }

private:
  [[nodiscard]] constexpr T *raw_ptr() noexcept { return std::to_address(obj_); }
  [[nodiscard]] constexpr const T *raw_ptr() const noexcept { return std::to_address(obj_); }

  constexpr void
  move_assign_with_allocator_propagation(indirect &other) noexcept(std::is_nothrow_move_assignable_v<allocator_type>) {
    if (this != &other) {
      release_object();
      alloc_ = std::move(other.alloc_);
      take_object_from(other);
    }
  }

  constexpr void move_assign_with_equal_allocator(indirect &other) noexcept {
    if (this != &other) {
      release_object();
      take_object_from(other);
    }
  }

  constexpr void move_assign_with_runtime_allocator_check(indirect &other) {
    if (this != &other && !try_take_object_with_equal_allocator(other)) {
      move_value_or_release(other);
    }
  }

  constexpr bool try_take_object_with_equal_allocator(indirect &other) {
    if (!(alloc_ == other.alloc_)) {
      return false;
    }
    release_object();
    take_object_from(other);
    return true;
  }

  constexpr void move_value_or_release(indirect &other) {
    if (other.obj_) {
      move_value_from(other);
    } else {
      release_object();
    }
  }

  constexpr void move_value_from(indirect &other) {
    if (obj_) {
      *raw_ptr() = std::move(*other.raw_ptr());
    } else {
      obj_ = allocate_construct(std::move(*other.raw_ptr()));
    }
  }

  constexpr void
  swap_with_allocator_propagation(indirect &other) noexcept(std::is_nothrow_swappable_v<allocator_type>) {
    if (this != &other) {
      swap_allocators(other);
      swap_object_pointers(other);
    }
  }

  constexpr void swap_with_equal_allocator(indirect &other) noexcept {
    if (this != &other) {
      swap_object_pointers(other);
    }
  }

  constexpr void swap_with_runtime_allocator_check(indirect &other) {
    if (this != &other && !try_swap_object_with_equal_allocator(other)) {
      swap_values_or_rehome(other);
    }
  }

  constexpr bool try_swap_object_with_equal_allocator(indirect &other) {
    if (!(alloc_ == other.alloc_)) {
      return false;
    }
    swap_object_pointers(other);
    return true;
  }

  constexpr void swap_values_or_rehome(indirect &other) {
    if (both_have_objects(other)) {
      swap_object_values(other);
    } else {
      rehome_present_value(other);
    }
  }

  constexpr void rehome_present_value(indirect &other) {
    if (obj_) {
      move_value_to_empty(other);
    } else if (other.obj_) {
      other.move_value_to_empty(*this);
    }
  }

  [[nodiscard]] constexpr bool both_have_objects(const indirect &other) const noexcept { return obj_ && other.obj_; }

  constexpr void swap_allocators(indirect &other) noexcept(std::is_nothrow_swappable_v<allocator_type>) {
    using std::swap;
    swap(alloc_, other.alloc_);
  }

  constexpr void swap_object_pointers(indirect &other) noexcept {
    using std::swap;
    swap(obj_, other.obj_);
  }

  constexpr void swap_object_values(indirect &other) {
    using std::swap;
    swap(*raw_ptr(), *other.raw_ptr());
  }

  constexpr void move_value_to_empty(indirect &empty) {
    empty.obj_ = empty.allocate_construct(std::move(*raw_ptr()));
    release_object();
  }

  constexpr void take_object_from(indirect &other) noexcept { obj_ = std::exchange(other.obj_, nullptr); }

  constexpr void release_object() noexcept { destroy(); }

  constexpr pointer allocate_default() {
    pointer p = allocator_traits::allocate(alloc_, 1);
    try {
      allocator_traits::construct(alloc_, std::to_address(p));
    } catch (...) {
      allocator_traits::deallocate(alloc_, p, 1);
      throw;
    }
    return p;
  }

  template <class... Args>
  constexpr pointer allocate_construct(Args &&...args) {
    pointer p = allocator_traits::allocate(alloc_, 1);
    try {
      allocator_traits::construct(alloc_, std::to_address(p), std::forward<Args>(args)...);
    } catch (...) {
      allocator_traits::deallocate(alloc_, p, 1);
      throw;
    }
    return p;
  }

  constexpr void destroy() noexcept {
    if (obj_) {
      allocator_traits::destroy(alloc_, std::to_address(obj_));
      allocator_traits::deallocate(alloc_, obj_, 1);
      obj_ = nullptr;
    }
  }
};

} // namespace hpp_proto
