#pragma once

#include <algorithm>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

// Test literals and intentionally mutable setup values keep allocator scenarios readable.
// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)

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

template <class T, bool PropagateOnSwap, bool PropagateOnMoveAssignment>
struct tracking_allocator {
  using value_type = T;
  using is_always_equal = std::false_type;
  using propagate_on_container_swap = std::bool_constant<PropagateOnSwap>;
  using propagate_on_container_move_assignment = std::bool_constant<PropagateOnMoveAssignment>;

  template <class U>
  struct rebind {
    using other = tracking_allocator<U, PropagateOnSwap, PropagateOnMoveAssignment>;
  };

  std::shared_ptr<tracking_alloc_state> state = std::make_shared<tracking_alloc_state>();

  tracking_allocator() = default;
  explicit tracking_allocator(std::shared_ptr<tracking_alloc_state> s) : state(std::move(s)) {}

  template <class U>
  explicit tracking_allocator(const tracking_allocator<U, PropagateOnSwap, PropagateOnMoveAssignment> &other) noexcept
      : state(other.state) {}

  [[nodiscard]] T *allocate(std::size_t n) {
    auto *ptr = std::allocator<T>{}.allocate(n);
    try {
      state->live_allocations.push_back(ptr);
      state->alloc_count += n;
      // LCOV_EXCL_START
    } catch (...) {
      std::allocator<T>{}.deallocate(ptr, n);
      throw;
    }
    // LCOV_EXCL_STOP
    return ptr;
  }

  void deallocate(T *ptr, std::size_t n) noexcept {
    auto it = std::find(state->live_allocations.begin(), state->live_allocations.end(), ptr);
    if (it != state->live_allocations.end()) {
      state->live_allocations.erase(it);
    } else {                                // LCOV_EXCL_LINE
      state->mismatched_dealloc_count += n; // LCOV_EXCL_LINE
    }
    state->dealloc_count += n;
    std::allocator<T>{}.deallocate(ptr, n);
  }

  friend void swap(tracking_allocator &lhs, tracking_allocator &rhs) noexcept {
    using std::swap;
    swap(lhs.state, rhs.state);
  }

  template <class U>
  constexpr bool
  operator==(const tracking_allocator<U, PropagateOnSwap, PropagateOnMoveAssignment> &rhs) const noexcept {
    return state == rhs.state;
  }
};

template <class T>
using non_propagating_tracking_allocator = tracking_allocator<T, false, false>;

template <class T>
using propagating_move_tracking_allocator = tracking_allocator<T, false, true>;

template <class T>
using propagating_swap_tracking_allocator = tracking_allocator<T, true, false>;

[[nodiscard]] inline bool tracking_alloc_state_is_clear(const tracking_alloc_state &state, std::size_t alloc_count,
                                                        std::size_t dealloc_count) noexcept {
  return state.alloc_count == alloc_count && state.dealloc_count == dealloc_count &&
         state.mismatched_dealloc_count == 0 && state.live_allocations.empty();
}

template <class Wrapped>
void steal_storage_from_second(Wrapped &storage_owner, Wrapped &emptied) {
  storage_owner = std::move(emptied);
}

template <template <class, class> class Wrapper, template <class> class AllocTemplate, class Exercise>
[[nodiscard]] bool with_two_engaged_tracked_wrappers(Exercise exercise) {
  auto left_state = std::make_shared<tracking_alloc_state>();
  auto right_state = std::make_shared<tracking_alloc_state>();
  using Alloc = AllocTemplate<int>;
  using Wrapped = Wrapper<int, Alloc>;

  bool exercise_ok = false;
  {
    Wrapped left(std::allocator_arg, Alloc{left_state}, 1);
    Wrapped right(std::allocator_arg, Alloc{right_state}, 2);

    exercise_ok = exercise(left, right, left_state, right_state);
  }

  return exercise_ok && tracking_alloc_state_is_clear(*left_state, 1, 1) &&
         tracking_alloc_state_is_clear(*right_state, 1, 1);
}

template <template <class, class> class Wrapper>
[[nodiscard]] bool propagating_move_assignment_transfers_allocator_and_storage() {
  return with_two_engaged_tracked_wrappers<Wrapper, propagating_move_tracking_allocator>(
      [](auto &left, auto &right, const auto & /*left_state*/, const auto &right_state) {
        using Alloc = std::remove_cvref_t<decltype(left.get_allocator())>;
        left = std::move(right);
        return *left == 2 && left.get_allocator() == Alloc{right_state};
      });
}

template <template <class, class> class Wrapper>
[[nodiscard]] bool unequal_allocator_move_assignment_moves_value_without_stealing_storage() {
  return with_two_engaged_tracked_wrappers<Wrapper, non_propagating_tracking_allocator>(
      [](auto &left, auto &right, const auto &left_state, const auto & /*right_state*/) {
        using Alloc = std::remove_cvref_t<decltype(left.get_allocator())>;
        left = std::move(right);
        return *left == 2 && left.get_allocator() == Alloc{left_state};
      });
}

template <template <class, class> class Wrapper>
[[nodiscard]] bool unequal_allocator_swap_between_engaged_objects_moves_values() {
  return with_two_engaged_tracked_wrappers<Wrapper, non_propagating_tracking_allocator>(
      [](auto &left, auto &right, const auto &left_state, const auto &right_state) {
        using Alloc = std::remove_cvref_t<decltype(left.get_allocator())>;
        left.swap(right);
        return *left == 2 && *right == 1 && left.get_allocator() == Alloc{left_state} &&
               right.get_allocator() == Alloc{right_state};
      });
}

template <template <class, class> class Wrapper>
[[nodiscard]] bool propagating_swap_between_engaged_objects_transfers_allocators() {
  return with_two_engaged_tracked_wrappers<Wrapper, propagating_swap_tracking_allocator>(
      [](auto &left, auto &right, const auto &left_state, const auto &right_state) {
        using Alloc = std::remove_cvref_t<decltype(left.get_allocator())>;
        left.swap(right);
        return *left == 2 && *right == 1 && left.get_allocator() == Alloc{right_state} &&
               right.get_allocator() == Alloc{left_state};
      });
}

template <template <class, class> class Optional>
[[nodiscard]] bool propagating_optional_swap_engaged_with_empty_transfers_allocators() {
  auto left_state = std::make_shared<tracking_alloc_state>();
  auto right_state = std::make_shared<tracking_alloc_state>();
  using Alloc = propagating_swap_tracking_allocator<int>;
  using Wrapped = Optional<int, Alloc>;

  bool swap_ok = false;
  {
    Wrapped left(std::allocator_arg, Alloc{left_state}, 3);
    Wrapped right(std::allocator_arg, Alloc{right_state});

    left.swap(right);

    swap_ok = !left.has_value() && right.has_value() && *right == 3 && left.get_allocator() == Alloc{right_state} &&
              right.get_allocator() == Alloc{left_state};
  }

  return swap_ok && tracking_alloc_state_is_clear(*left_state, 1, 1) &&
         tracking_alloc_state_is_clear(*right_state, 0, 0);
}

template <template <class, class> class Optional>
[[nodiscard]] bool unequal_allocator_optional_move_assignment_handles_empty_states() {
  using Alloc = non_propagating_tracking_allocator<int>;
  using Wrapped = Optional<int, Alloc>;

  auto empty_target_state = std::make_shared<tracking_alloc_state>();
  auto source_state = std::make_shared<tracking_alloc_state>();
  bool empty_target_ok = false;
  {
    Wrapped target(std::allocator_arg, Alloc{empty_target_state});
    Wrapped source(std::allocator_arg, Alloc{source_state}, 3);

    target = std::move(source);

    empty_target_ok = target.has_value() && *target == 3;
  }

  auto target_state = std::make_shared<tracking_alloc_state>();
  auto empty_source_state = std::make_shared<tracking_alloc_state>();
  bool empty_source_ok = false;
  {
    Wrapped target(std::allocator_arg, Alloc{target_state}, 4);
    Wrapped source(std::allocator_arg, Alloc{empty_source_state});

    target = std::move(source);

    empty_source_ok = !target.has_value();
  }

  return empty_target_ok && empty_source_ok && tracking_alloc_state_is_clear(*empty_target_state, 1, 1) &&
         tracking_alloc_state_is_clear(*source_state, 1, 1) && tracking_alloc_state_is_clear(*target_state, 1, 1) &&
         tracking_alloc_state_is_clear(*empty_source_state, 0, 0);
}

template <template <class, class> class Optional>
[[nodiscard]] bool unequal_allocator_optional_swap_handles_empty_states() {
  using Alloc = non_propagating_tracking_allocator<int>;
  using Wrapped = Optional<int, Alloc>;

  auto left_engaged_state = std::make_shared<tracking_alloc_state>();
  auto right_empty_state = std::make_shared<tracking_alloc_state>();
  bool engaged_left_ok = false;
  {
    Wrapped left(std::allocator_arg, Alloc{left_engaged_state}, 5);
    Wrapped right(std::allocator_arg, Alloc{right_empty_state});

    left.swap(right);

    engaged_left_ok = !left.has_value() && right.has_value() && *right == 5;
  }

  auto left_empty_state = std::make_shared<tracking_alloc_state>();
  auto right_engaged_state = std::make_shared<tracking_alloc_state>();
  bool engaged_right_ok = false;
  {
    Wrapped left(std::allocator_arg, Alloc{left_empty_state});
    Wrapped right(std::allocator_arg, Alloc{right_engaged_state}, 6);

    left.swap(right);

    engaged_right_ok = left.has_value() && *left == 6 && !right.has_value();
  }

  return engaged_left_ok && engaged_right_ok && tracking_alloc_state_is_clear(*left_engaged_state, 1, 1) &&
         tracking_alloc_state_is_clear(*right_empty_state, 1, 1) &&
         tracking_alloc_state_is_clear(*left_empty_state, 1, 1) &&
         tracking_alloc_state_is_clear(*right_engaged_state, 1, 1);
}

template <template <class, class> class Wrapper>
[[nodiscard]] bool unequal_allocator_indirect_move_assignment_handles_empty_states() {
  using Alloc = non_propagating_tracking_allocator<int>;
  using Wrapped = Wrapper<int, Alloc>;

  auto empty_target_state = std::make_shared<tracking_alloc_state>();
  auto source_state = std::make_shared<tracking_alloc_state>();
  bool empty_target_ok = false;
  {
    Wrapped keeper(std::allocator_arg, Alloc{empty_target_state}, 7);
    Wrapped target(std::allocator_arg, Alloc{empty_target_state}, 8);
    steal_storage_from_second(keeper, target);
    Wrapped source(std::allocator_arg, Alloc{source_state}, 9);

    target = std::move(source);

    empty_target_ok = *target == 9 && target.get_allocator() == Alloc{empty_target_state};
  }

  auto target_state = std::make_shared<tracking_alloc_state>();
  auto empty_source_state = std::make_shared<tracking_alloc_state>();
  bool empty_source_ok = false;
  {
    Wrapped target(std::allocator_arg, Alloc{target_state}, 10);
    Wrapped keeper(std::allocator_arg, Alloc{empty_source_state}, 11);
    Wrapped source(std::allocator_arg, Alloc{empty_source_state}, 12);
    steal_storage_from_second(keeper, source);

    target = std::move(source);

    empty_source_ok = target.get_allocator() == Alloc{target_state};
  }

  return empty_target_ok && empty_source_ok && tracking_alloc_state_is_clear(*empty_target_state, 3, 3) &&
         tracking_alloc_state_is_clear(*source_state, 1, 1) && tracking_alloc_state_is_clear(*target_state, 1, 1) &&
         tracking_alloc_state_is_clear(*empty_source_state, 2, 2);
}

template <template <class, class> class Wrapper>
[[nodiscard]] bool unequal_allocator_indirect_swap_handles_empty_states() {
  using Alloc = non_propagating_tracking_allocator<int>;
  using Wrapped = Wrapper<int, Alloc>;

  auto left_empty_state = std::make_shared<tracking_alloc_state>();
  auto right_engaged_state = std::make_shared<tracking_alloc_state>();
  bool engaged_right_ok = false;
  {
    Wrapped keeper(std::allocator_arg, Alloc{left_empty_state}, 13);
    Wrapped left(std::allocator_arg, Alloc{left_empty_state}, 14);
    steal_storage_from_second(keeper, left);
    Wrapped right(std::allocator_arg, Alloc{right_engaged_state}, 15);

    left.swap(right);

    engaged_right_ok = *left == 15;
  }

  auto left_engaged_state = std::make_shared<tracking_alloc_state>();
  auto right_empty_state = std::make_shared<tracking_alloc_state>();
  bool engaged_left_ok = false;
  {
    Wrapped left(std::allocator_arg, Alloc{left_engaged_state}, 16);
    Wrapped keeper(std::allocator_arg, Alloc{right_empty_state}, 17);
    Wrapped right(std::allocator_arg, Alloc{right_empty_state}, 18);
    steal_storage_from_second(keeper, right);

    left.swap(right);

    engaged_left_ok = *right == 16;
  }

  return engaged_right_ok && engaged_left_ok && tracking_alloc_state_is_clear(*left_empty_state, 3, 3) &&
         tracking_alloc_state_is_clear(*right_engaged_state, 1, 1) &&
         tracking_alloc_state_is_clear(*left_engaged_state, 1, 1) &&
         tracking_alloc_state_is_clear(*right_empty_state, 3, 3);
}

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

// NOLINTEND(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)
