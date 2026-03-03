#pragma once

#include <cstddef>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>

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
  counting_allocator(const counting_allocator<U> &other) noexcept : state(other.state) {}

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

template <class T>
struct throwing_move_ctor_allocator {
  using value_type = T;
  using is_always_equal = std::false_type;

  throwing_move_ctor_allocator() = default;
  throwing_move_ctor_allocator(const throwing_move_ctor_allocator &) = default;
  throwing_move_ctor_allocator(throwing_move_ctor_allocator &&) noexcept(false) {}
  throwing_move_ctor_allocator &operator=(const throwing_move_ctor_allocator &) = default;
  throwing_move_ctor_allocator &operator=(throwing_move_ctor_allocator &&) = default;

  template <class U>
  throwing_move_ctor_allocator(const throwing_move_ctor_allocator<U> &) noexcept {}

  [[nodiscard]] T *allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
  void deallocate(T *p, std::size_t n) noexcept { std::allocator<T>{}.deallocate(p, n); }

  template <class U>
  constexpr bool operator==(const throwing_move_ctor_allocator<U> &) const noexcept {
    return true;
  }
};

template <class T>
struct throwing_move_assign_allocator {
  using value_type = T;
  using is_always_equal = std::false_type;
  using propagate_on_container_move_assignment = std::true_type;

  throwing_move_assign_allocator() = default;
  throwing_move_assign_allocator(const throwing_move_assign_allocator &) = default;
  throwing_move_assign_allocator(throwing_move_assign_allocator &&) noexcept = default;
  throwing_move_assign_allocator &operator=(const throwing_move_assign_allocator &) = default;
  throwing_move_assign_allocator &operator=(throwing_move_assign_allocator &&) noexcept(false) { return *this; }

  template <class U>
  throwing_move_assign_allocator(const throwing_move_assign_allocator<U> &) noexcept {}

  [[nodiscard]] T *allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
  void deallocate(T *p, std::size_t n) noexcept { std::allocator<T>{}.deallocate(p, n); }

  template <class U>
  constexpr bool operator==(const throwing_move_assign_allocator<U> &) const noexcept {
    return true;
  }
};

template <class T>
struct throwing_swap_allocator {
  using value_type = T;
  using is_always_equal = std::false_type;
  using propagate_on_container_swap = std::true_type;

  throwing_swap_allocator() = default;
  throwing_swap_allocator(const throwing_swap_allocator &) = default;
  throwing_swap_allocator(throwing_swap_allocator &&) noexcept = default;
  throwing_swap_allocator &operator=(const throwing_swap_allocator &) = default;
  throwing_swap_allocator &operator=(throwing_swap_allocator &&) noexcept = default;

  template <class U>
  throwing_swap_allocator(const throwing_swap_allocator<U> &) noexcept {}

  [[nodiscard]] T *allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
  void deallocate(T *p, std::size_t n) noexcept { std::allocator<T>{}.deallocate(p, n); }

  friend void swap(throwing_swap_allocator &, throwing_swap_allocator &) noexcept(false) {}

  template <class U>
  constexpr bool operator==(const throwing_swap_allocator<U> &) const noexcept {
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
  propagating_copy_allocator(const propagating_copy_allocator<U> &other) noexcept : id(other.id) {}

  [[nodiscard]] T *allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
  void deallocate(T *p, std::size_t n) noexcept { std::allocator<T>{}.deallocate(p, n); }

  template <class U>
  constexpr bool operator==(const propagating_copy_allocator<U> &rhs) const noexcept {
    return id == rhs.id;
  }
};
