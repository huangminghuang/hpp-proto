#pragma once

#include <algorithm>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

struct throwing_constructible {
  int value{};
  explicit throwing_constructible(int v) {
    if (v < 0) {
      throw std::runtime_error("negative is invalid");
    }
    value = v;
  }
};

struct counting_alloc_state {
  std::size_t alloc_count{};
  std::size_t dealloc_count{};
};

template <class T>
struct counting_allocator {
  using value_type = T;
  using is_always_equal = std::false_type;

  std::shared_ptr<counting_alloc_state> state = std::make_shared<counting_alloc_state>();

  counting_allocator() = default;
  explicit counting_allocator(std::shared_ptr<counting_alloc_state> s) : state(std::move(s)) {}

  template <class U>
  explicit counting_allocator(const counting_allocator<U> &other) noexcept : state(other.state) {}

  [[nodiscard]] T *allocate(std::size_t n) {
    state->alloc_count += n;
    return std::allocator<T>{}.allocate(n);
  }

  void deallocate(T *p, std::size_t n) noexcept {
    state->dealloc_count += n;
    std::allocator<T>{}.deallocate(p, n);
  }

  template <class U>
  constexpr bool operator==(const counting_allocator<U> &rhs) const noexcept {
    return state == rhs.state;
  }
};

struct tracking_alloc_state {
  std::size_t alloc_count{};
  std::size_t dealloc_count{};
  std::size_t mismatched_dealloc_count{};
  std::vector<void *> live_allocations;
};

template <class T>
struct propagating_swap_tracking_allocator {
  using value_type = T;
  using is_always_equal = std::false_type;
  using propagate_on_container_swap = std::true_type;

  std::shared_ptr<tracking_alloc_state> state = std::make_shared<tracking_alloc_state>();

  propagating_swap_tracking_allocator() = default;
  explicit propagating_swap_tracking_allocator(std::shared_ptr<tracking_alloc_state> s) : state(std::move(s)) {}

  template <class U>
  explicit propagating_swap_tracking_allocator(const propagating_swap_tracking_allocator<U> &other) noexcept
      : state(other.state) {}

  [[nodiscard]] T *allocate(std::size_t n) {
    auto *ptr = std::allocator<T>{}.allocate(n);
    try {
      state->live_allocations.push_back(ptr);
      state->alloc_count += n;
    } catch (...) {
      std::allocator<T>{}.deallocate(ptr, n);
      throw;
    }
    return ptr;
  }

  void deallocate(T *ptr, std::size_t n) noexcept {
    auto it = std::find(state->live_allocations.begin(), state->live_allocations.end(), ptr);
    if (it == state->live_allocations.end()) {
      state->mismatched_dealloc_count += n;
    } else {
      state->live_allocations.erase(it);
    }
    state->dealloc_count += n;
    std::allocator<T>{}.deallocate(ptr, n);
  }

  friend void swap(propagating_swap_tracking_allocator &lhs, propagating_swap_tracking_allocator &rhs) noexcept {
    using std::swap;
    swap(lhs.state, rhs.state);
  }

  template <class U>
  constexpr bool operator==(const propagating_swap_tracking_allocator<U> &rhs) const noexcept {
    return state == rhs.state;
  }
};

template <class T>
struct throwing_move_ctor_allocator {
  using value_type = T;
  using is_always_equal = std::false_type;

  throwing_move_ctor_allocator() = default;
  throwing_move_ctor_allocator(const throwing_move_ctor_allocator & /*other*/) = default;
  throwing_move_ctor_allocator(throwing_move_ctor_allocator && /*other*/) noexcept(false) {}
  throwing_move_ctor_allocator &operator=(const throwing_move_ctor_allocator & /*other*/) = default;
  throwing_move_ctor_allocator &operator=(throwing_move_ctor_allocator && /*other*/) = default;
  ~throwing_move_ctor_allocator() = default;

  template <class U>
  explicit throwing_move_ctor_allocator(const throwing_move_ctor_allocator<U> & /*other*/) noexcept {}

  [[nodiscard]] T *allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
  void deallocate(T *p, std::size_t n) noexcept { std::allocator<T>{}.deallocate(p, n); }

  template <class U>
  constexpr bool operator==(const throwing_move_ctor_allocator<U> & /*other*/) const noexcept {
    return true;
  }
};

template <class T>
// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions,hicpp-special-member-functions)
struct throwing_move_assign_allocator {
  using value_type = T;
  using is_always_equal = std::false_type;
  using propagate_on_container_move_assignment = std::true_type;

  throwing_move_assign_allocator() = default;
  throwing_move_assign_allocator(const throwing_move_assign_allocator & /*other*/) = default;
  throwing_move_assign_allocator(throwing_move_assign_allocator && /*other*/) noexcept = default;
  throwing_move_assign_allocator &operator=(const throwing_move_assign_allocator & /*other*/) = default;
  throwing_move_assign_allocator &operator=(throwing_move_assign_allocator && /*other*/) noexcept(false) {
    return *this;
  }

  template <class U>
  explicit throwing_move_assign_allocator(const throwing_move_assign_allocator<U> & /*other*/) noexcept {}

  [[nodiscard]] T *allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
  void deallocate(T *p, std::size_t n) noexcept { std::allocator<T>{}.deallocate(p, n); }

  template <class U>
  constexpr bool operator==(const throwing_move_assign_allocator<U> & /*other*/) const noexcept {
    return true;
  }
};

template <class T>
// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions,hicpp-special-member-functions)
struct throwing_swap_allocator {
  using value_type = T;
  using is_always_equal = std::false_type;
  using propagate_on_container_swap = std::true_type;

  throwing_swap_allocator() = default;
  throwing_swap_allocator(const throwing_swap_allocator & /*other*/) = default;
  throwing_swap_allocator(throwing_swap_allocator && /*other*/) noexcept = default;
  throwing_swap_allocator &operator=(const throwing_swap_allocator & /*other*/) = default;
  throwing_swap_allocator &operator=(throwing_swap_allocator && /*other*/) noexcept = default;

  template <class U>
  explicit throwing_swap_allocator(const throwing_swap_allocator<U> & /*other*/) noexcept {}

  [[nodiscard]] T *allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
  void deallocate(T *p, std::size_t n) noexcept { std::allocator<T>{}.deallocate(p, n); }

  friend void swap(throwing_swap_allocator & /*lhs*/, throwing_swap_allocator & /*rhs*/) noexcept(false) {}

  template <class U>
  constexpr bool operator==(const throwing_swap_allocator<U> & /*other*/) const noexcept {
    return true;
  }
};

template <class T>
struct propagating_copy_allocator {
  using value_type = T;
  using is_always_equal = std::false_type;
  using propagate_on_container_copy_assignment = std::true_type;

  int id{};

  propagating_copy_allocator() = default;
  explicit propagating_copy_allocator(int value) : id(value) {}

  template <class U>
  explicit propagating_copy_allocator(const propagating_copy_allocator<U> &other) noexcept : id(other.id) {}

  [[nodiscard]] T *allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
  void deallocate(T *p, std::size_t n) noexcept { std::allocator<T>{}.deallocate(p, n); }

  template <class U>
  constexpr bool operator==(const propagating_copy_allocator<U> &rhs) const noexcept {
    return id == rhs.id;
  }
};
