#pragma once

#include <compare>
#include <initializer_list>
#include <memory>
#include <type_traits>
#include <utility>

namespace hpp::proto {

template <typename T, typename Allocator = std::allocator<T>>
class indirect {
public:
  using value_type = T;
  using allocator_type = typename std::allocator_traits<Allocator>::template rebind_alloc<T>;
  using allocator_arg_t = std::allocator_arg_t;

private:
  using allocator_traits = std::allocator_traits<allocator_type>;
  using pointer = typename allocator_traits::pointer;

  [[no_unique_address]] allocator_type alloc_{};
  pointer obj_;

public:
  constexpr indirect() : obj_(allocate_default()) {}
  constexpr explicit indirect(const allocator_type &alloc) : alloc_(alloc), obj_(allocate_default()) {}
  constexpr indirect(allocator_arg_t, const allocator_type &alloc) : alloc_(alloc), obj_(allocate_default()) {}
  constexpr ~indirect() { destroy(); }

  template <class... Args>
  constexpr explicit indirect(std::in_place_t, Args &&...args)
      : obj_(allocate_construct(std::forward<Args>(args)...)) {}
  template <class... Args>
  constexpr explicit indirect(allocator_arg_t, const allocator_type &alloc, std::in_place_t, Args &&...args)
      : alloc_(alloc), obj_(allocate_construct(std::forward<Args>(args)...)) {}

  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  constexpr indirect(T &&object) : obj_(allocate_construct(std::move(object))) {}

  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  constexpr indirect(const T &object) : obj_(allocate_construct(object)) {}

  constexpr indirect(allocator_arg_t, const allocator_type &alloc, T &&object)
      : alloc_(alloc), obj_(allocate_construct(std::move(object))) {}

  constexpr indirect(const indirect &other)
      : alloc_(allocator_traits::select_on_container_copy_construction(other.alloc_)),
        obj_(allocate_construct(*other.raw_ptr())) {}
  constexpr indirect(indirect &&other) noexcept
      : alloc_(std::move(other.alloc_)), obj_(std::exchange(other.obj_, nullptr)) {}

  constexpr indirect(allocator_arg_t, const allocator_type &alloc, const indirect &other)
      : alloc_(alloc), obj_(allocate_construct(*other.raw_ptr())) {}

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  constexpr indirect(allocator_arg_t, const allocator_type &alloc, indirect &&other) : alloc_(alloc) {
    if constexpr (allocator_traits::is_always_equal::value) {
      obj_ = std::exchange(other.obj_, nullptr);
    } else {
      if (alloc_ == other.alloc_) {
        obj_ = std::exchange(other.obj_, nullptr);
      } else {
        obj_ = allocate_construct(std::move(*other.raw_ptr()));
      }
    }
  }

  constexpr indirect &operator=(const indirect &other) {
    if (this != &other) {
      if constexpr (allocator_traits::propagate_on_container_copy_assignment::value) {
        if (alloc_ != other.alloc_) {
          destroy();
        }
        alloc_ = other.alloc_;
      }
      *raw_ptr() = *other.raw_ptr();
    }
    return *this;
  }

  constexpr indirect &operator=(T &&other) {
    *raw_ptr() = std::move(other);
    return *this;
  }

  constexpr indirect &operator=(const T &other) {
    *raw_ptr() = other;
    return *this;
  }

  constexpr indirect &
  operator=(indirect &&other) noexcept(allocator_traits::propagate_on_container_move_assignment::value ||
                                       allocator_traits::is_always_equal::value) {
    if (this == &other) {
      return *this;
    }
    if constexpr (allocator_traits::propagate_on_container_move_assignment::value) {
      destroy();
      alloc_ = std::move(other.alloc_);
      obj_ = std::exchange(other.obj_, nullptr);
      return *this;
    } else if constexpr (allocator_traits::is_always_equal::value) {
      destroy();
      obj_ = std::exchange(other.obj_, nullptr);
      return *this;
    } else {
      if (alloc_ == other.alloc_) {
        destroy();
        obj_ = std::exchange(other.obj_, nullptr);
        return *this;
      }
      *raw_ptr() = std::move(*other.raw_ptr());
      return *this;
    }
  }

  [[nodiscard]] constexpr T &value() & { return *raw_ptr(); }
  [[nodiscard]] constexpr const T &value() const & { return *raw_ptr(); }
  [[nodiscard]] constexpr T &&value() && { return std::move(*raw_ptr()); }
  [[nodiscard]] constexpr const T &&value() const && { return std::move(*raw_ptr()); }

  constexpr T &operator*() & { return *raw_ptr(); }
  constexpr const T &operator*() const & { return *raw_ptr(); }
  constexpr T &&operator*() && { return std::move(*raw_ptr()); }
  constexpr const T &&operator*() const && { return std::move(*raw_ptr()); }

  constexpr T *operator->() noexcept { return raw_ptr(); }
  constexpr const T *operator->() const noexcept { return raw_ptr(); }

  constexpr bool operator==(const T &rhs) const { return *raw_ptr() == rhs; }
  constexpr bool operator==(const indirect &rhs) const { return *raw_ptr() == *rhs.raw_ptr(); }

  constexpr auto operator<=>(const T &rhs) const { return *raw_ptr() <=> rhs; }
  constexpr auto operator<=>(const indirect &rhs) const { return *raw_ptr() <=> *rhs.raw_ptr(); }

  constexpr void swap(indirect &other) noexcept(allocator_traits::propagate_on_container_swap::value ||
                                                allocator_traits::is_always_equal::value) {
    using std::swap;
    if constexpr (allocator_traits::propagate_on_container_swap::value) {
      swap(alloc_, other.alloc_);
    }
    if constexpr (allocator_traits::is_always_equal::value) {
      swap(obj_, other.obj_);
    } else {
      if (alloc_ == other.alloc_) {
        swap(obj_, other.obj_);
      } else {
        swap(*raw_ptr(), *other.raw_ptr());
      }
    }
  }

  [[nodiscard]] constexpr allocator_type get_allocator() const noexcept { return alloc_; }

private:
  [[nodiscard]] constexpr T *raw_ptr() noexcept { return std::to_address(obj_); }
  [[nodiscard]] constexpr const T *raw_ptr() const noexcept { return std::to_address(obj_); }

  constexpr pointer allocate_default() {
    pointer p = allocator_traits::allocate(alloc_, 1);
    allocator_traits::construct(alloc_, p);
    return p;
  }

  template <class... Args>
  constexpr pointer allocate_construct(Args &&...args) {
    pointer p = allocator_traits::allocate(alloc_, 1);
    allocator_traits::construct(alloc_, p, std::forward<Args>(args)...);
    return p;
  }

  constexpr void destroy() noexcept {
    if (obj_) {
      allocator_traits::destroy(alloc_, obj_);
      allocator_traits::deallocate(alloc_, obj_, 1);
      obj_ = nullptr;
    }
  }
};

} // namespace hpp::proto
