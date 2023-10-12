// Type your code here, or load an example.
#include <algorithm>
#include <array>
#include <bit>
#include <climits>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <numeric>
#include <optional>
#include <ranges>
#include <span>
#include <tuple>
#include <variant>
#include <vector>

#ifndef __cpp_lib_bit_cast
namespace std {
using namespace ::std;
template <class ToType, class FromType,
          class = enable_if_t<sizeof(ToType) == sizeof(FromType) && is_trivially_copyable_v<ToType> &&
                              is_trivially_copyable_v<FromType>>>
constexpr ToType bit_cast(FromType const &from) noexcept {
  return __builtin_bit_cast(ToType, from);
}
} // namespace std
#endif

#if !defined(__cpp_lib_ranges)
namespace std {
namespace ranges {
template <typename Range1, typename Range2>
constexpr bool equal(Range1 &&r1, Range2 &&r2) {
  return std::equal(std::begin(r1), std::end(r1), std::begin(r2), std::end(r2));
}
} // namespace ranges
} // namespace std
#endif

#if defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#define TL_EXPECTED_EXCEPTIONS_ENABLED
#endif

#if (defined(_MSC_VER) && _MSC_VER == 1900)
#define TL_EXPECTED_MSVC2015
#define TL_EXPECTED_MSVC2015_CONSTEXPR
#else
#define TL_EXPECTED_MSVC2015_CONSTEXPR constexpr
#endif

#if (defined(__GNUC__) && __GNUC__ == 4 && __GNUC_MINOR__ <= 9 && !defined(__clang__))
#define TL_EXPECTED_GCC49
#endif

#if (defined(__GNUC__) && __GNUC__ == 5 && __GNUC_MINOR__ <= 4 && !defined(__clang__))
#define TL_EXPECTED_GCC54
#endif

#if (defined(__GNUC__) && __GNUC__ == 5 && __GNUC_MINOR__ <= 5 && !defined(__clang__))
#define TL_EXPECTED_GCC55
#endif

#if !defined(TL_ASSERT)
// can't have assert in constexpr in C++11 and GCC 4.9 has a compiler bug
#if (__cplusplus > 201103L) && !defined(TL_EXPECTED_GCC49)
#include <cassert>
#define TL_ASSERT(x) assert(x)
#else
#define TL_ASSERT(x)
#endif
#endif

#if (defined(__GNUC__) && __GNUC__ == 4 && __GNUC_MINOR__ <= 9 && !defined(__clang__))
// GCC < 5 doesn't support overloading on const&& for member functions

#define TL_EXPECTED_NO_CONSTRR
// GCC < 5 doesn't support some standard C++11 type traits
#define TL_EXPECTED_IS_TRIVIALLY_COPY_CONSTRUCTIBLE(T) std::has_trivial_copy_constructor<T>
#define TL_EXPECTED_IS_TRIVIALLY_COPY_ASSIGNABLE(T) std::has_trivial_copy_assign<T>

// This one will be different for GCC 5.7 if it's ever supported
#define TL_EXPECTED_IS_TRIVIALLY_DESTRUCTIBLE(T) std::is_trivially_destructible<T>

// GCC 5 < v < 8 has a bug in is_trivially_copy_constructible which breaks
// std::vector for non-copyable types
#elif (defined(__GNUC__) && __GNUC__ < 8 && !defined(__clang__))
#ifndef TL_GCC_LESS_8_TRIVIALLY_COPY_CONSTRUCTIBLE_MUTEX
#define TL_GCC_LESS_8_TRIVIALLY_COPY_CONSTRUCTIBLE_MUTEX
namespace tl {
namespace detail {
template <class T>
struct is_trivially_copy_constructible : std::is_trivially_copy_constructible<T> {};
#ifdef _GLIBCXX_VECTOR
template <class T, class A>
struct is_trivially_copy_constructible<std::vector<T, A>> : std::false_type {};
#endif
} // namespace detail
} // namespace tl
#endif

#define TL_EXPECTED_IS_TRIVIALLY_COPY_CONSTRUCTIBLE(T) tl::detail::is_trivially_copy_constructible<T>
#define TL_EXPECTED_IS_TRIVIALLY_COPY_ASSIGNABLE(T) std::is_trivially_copy_assignable<T>
#define TL_EXPECTED_IS_TRIVIALLY_DESTRUCTIBLE(T) std::is_trivially_destructible<T>
#else
#define TL_EXPECTED_IS_TRIVIALLY_COPY_CONSTRUCTIBLE(T) std::is_trivially_copy_constructible<T>
#define TL_EXPECTED_IS_TRIVIALLY_COPY_ASSIGNABLE(T) std::is_trivially_copy_assignable<T>
#define TL_EXPECTED_IS_TRIVIALLY_DESTRUCTIBLE(T) std::is_trivially_destructible<T>
#endif

#if __cplusplus > 201103L
#define TL_EXPECTED_CXX14
#endif

#ifdef TL_EXPECTED_GCC49
#define TL_EXPECTED_GCC49_CONSTEXPR
#else
#define TL_EXPECTED_GCC49_CONSTEXPR constexpr
#endif

#if (__cplusplus == 201103L || defined(TL_EXPECTED_MSVC2015) || defined(TL_EXPECTED_GCC49))
#define TL_EXPECTED_11_CONSTEXPR
#else
#define TL_EXPECTED_11_CONSTEXPR constexpr
#endif

namespace tl {
template <class T, class E>
class expected;

#ifndef TL_MONOSTATE_INPLACE_MUTEX
#define TL_MONOSTATE_INPLACE_MUTEX
class monostate {};

struct in_place_t {
  explicit in_place_t() = default;
};
static constexpr in_place_t in_place{};
#endif

template <class E>
class unexpected {
public:
  static_assert(!std::is_same<E, void>::value, "E must not be void");

  unexpected() = delete;
  constexpr explicit unexpected(const E &e) : m_val(e) {}

  constexpr explicit unexpected(E &&e) : m_val(std::move(e)) {}

  template <class... Args, typename std::enable_if<std::is_constructible<E, Args &&...>::value>::type * = nullptr>
  constexpr explicit unexpected(Args &&...args) : m_val(std::forward<Args>(args)...) {}
  template <class U, class... Args,
            typename std::enable_if<std::is_constructible<E, std::initializer_list<U> &, Args &&...>::value>::type * =
                nullptr>
  constexpr explicit unexpected(std::initializer_list<U> l, Args &&...args) : m_val(l, std::forward<Args>(args)...) {}

  constexpr const E &value() const & { return m_val; }
  TL_EXPECTED_11_CONSTEXPR E &value() & { return m_val; }
  TL_EXPECTED_11_CONSTEXPR E &&value() && { return std::move(m_val); }
  constexpr const E &&value() const && { return std::move(m_val); }

private:
  E m_val;
};

#ifdef __cpp_deduction_guides
template <class E>
unexpected(E) -> unexpected<E>;
#endif

template <class E>
constexpr bool operator==(const unexpected<E> &lhs, const unexpected<E> &rhs) {
  return lhs.value() == rhs.value();
}
template <class E>
constexpr bool operator!=(const unexpected<E> &lhs, const unexpected<E> &rhs) {
  return lhs.value() != rhs.value();
}
template <class E>
constexpr bool operator<(const unexpected<E> &lhs, const unexpected<E> &rhs) {
  return lhs.value() < rhs.value();
}
template <class E>
constexpr bool operator<=(const unexpected<E> &lhs, const unexpected<E> &rhs) {
  return lhs.value() <= rhs.value();
}
template <class E>
constexpr bool operator>(const unexpected<E> &lhs, const unexpected<E> &rhs) {
  return lhs.value() > rhs.value();
}
template <class E>
constexpr bool operator>=(const unexpected<E> &lhs, const unexpected<E> &rhs) {
  return lhs.value() >= rhs.value();
}

template <class E>
unexpected<typename std::decay<E>::type> make_unexpected(E &&e) {
  return unexpected<typename std::decay<E>::type>(std::forward<E>(e));
}

struct unexpect_t {
  unexpect_t() = default;
};
static constexpr unexpect_t unexpect{};

namespace detail {
template <typename E>
[[noreturn]] TL_EXPECTED_11_CONSTEXPR void throw_exception(E &&e) {
#ifdef TL_EXPECTED_EXCEPTIONS_ENABLED
  throw std::forward<E>(e);
#else
  (void)e;
#ifdef _MSC_VER
  __assume(0);
#else
  __builtin_unreachable();
#endif
#endif
}

#ifndef TL_TRAITS_MUTEX
#define TL_TRAITS_MUTEX
// C++14-style aliases for brevity
template <class T>
using remove_const_t = typename std::remove_const<T>::type;
template <class T>
using remove_reference_t = typename std::remove_reference<T>::type;
template <class T>
using decay_t = typename std::decay<T>::type;
template <bool E, class T = void>
using enable_if_t = typename std::enable_if<E, T>::type;
template <bool B, class T, class F>
using conditional_t = typename std::conditional<B, T, F>::type;

// std::conjunction from C++17
template <class...>
struct conjunction : std::true_type {};
template <class B>
struct conjunction<B> : B {};
template <class B, class... Bs>
struct conjunction<B, Bs...> : std::conditional<bool(B::value), conjunction<Bs...>, B>::type {};

#if defined(_LIBCPP_VERSION) && __cplusplus == 201103L
#define TL_TRAITS_LIBCXX_MEM_FN_WORKAROUND
#endif

// In C++11 mode, there's an issue in libc++'s std::mem_fn
// which results in a hard-error when using it in a noexcept expression
// in some cases. This is a check to workaround the common failing case.
#ifdef TL_TRAITS_LIBCXX_MEM_FN_WORKAROUND
template <class T>
struct is_pointer_to_non_const_member_func : std::false_type {};
template <class T, class Ret, class... Args>
struct is_pointer_to_non_const_member_func<Ret (T::*)(Args...)> : std::true_type {};
template <class T, class Ret, class... Args>
struct is_pointer_to_non_const_member_func<Ret (T::*)(Args...) &> : std::true_type {};
template <class T, class Ret, class... Args>
struct is_pointer_to_non_const_member_func<Ret (T::*)(Args...) &&> : std::true_type {};
template <class T, class Ret, class... Args>
struct is_pointer_to_non_const_member_func<Ret (T::*)(Args...) volatile> : std::true_type {};
template <class T, class Ret, class... Args>
struct is_pointer_to_non_const_member_func<Ret (T::*)(Args...) volatile &> : std::true_type {};
template <class T, class Ret, class... Args>
struct is_pointer_to_non_const_member_func<Ret (T::*)(Args...) volatile &&> : std::true_type {};

template <class T>
struct is_const_or_const_ref : std::false_type {};
template <class T>
struct is_const_or_const_ref<T const &> : std::true_type {};
template <class T>
struct is_const_or_const_ref<T const> : std::true_type {};
#endif

// std::invoke from C++17
// https://stackoverflow.com/questions/38288042/c11-14-invoke-workaround
template <
    typename Fn, typename... Args,
#ifdef TL_TRAITS_LIBCXX_MEM_FN_WORKAROUND
    typename = enable_if_t<!(is_pointer_to_non_const_member_func<Fn>::value && is_const_or_const_ref<Args...>::value)>,
#endif
    typename = enable_if_t<std::is_member_pointer<decay_t<Fn>>::value>, int = 0>
constexpr auto invoke(Fn &&f, Args &&...args) noexcept(noexcept(std::mem_fn(f)(std::forward<Args>(args)...)))
    -> decltype(std::mem_fn(f)(std::forward<Args>(args)...)) {
  return std::mem_fn(f)(std::forward<Args>(args)...);
}

template <typename Fn, typename... Args, typename = enable_if_t<!std::is_member_pointer<decay_t<Fn>>::value>>
constexpr auto invoke(Fn &&f, Args &&...args) noexcept(noexcept(std::forward<Fn>(f)(std::forward<Args>(args)...)))
    -> decltype(std::forward<Fn>(f)(std::forward<Args>(args)...)) {
  return std::forward<Fn>(f)(std::forward<Args>(args)...);
}

// std::invoke_result from C++17
template <class F, class, class... Us>
struct invoke_result_impl;

template <class F, class... Us>
struct invoke_result_impl<F, decltype(detail::invoke(std::declval<F>(), std::declval<Us>()...), void()), Us...> {
  using type = decltype(detail::invoke(std::declval<F>(), std::declval<Us>()...));
};

template <class F, class... Us>
using invoke_result = invoke_result_impl<F, void, Us...>;

template <class F, class... Us>
using invoke_result_t = typename invoke_result<F, Us...>::type;

#if defined(_MSC_VER) && _MSC_VER <= 1900
// TODO make a version which works with MSVC 2015
template <class T, class U = T>
struct is_swappable : std::true_type {};

template <class T, class U = T>
struct is_nothrow_swappable : std::true_type {};
#else
// https://stackoverflow.com/questions/26744589/what-is-a-proper-way-to-implement-is-swappable-to-test-for-the-swappable-concept
namespace swap_adl_tests {
// if swap ADL finds this then it would call std::swap otherwise (same
// signature)
struct tag {};

template <class T>
tag swap(T &, T &);
template <class T, std::size_t N>
tag swap(T (&a)[N], T (&b)[N]);

// helper functions to test if an unqualified swap is possible, and if it
// becomes std::swap
template <class, class>
std::false_type can_swap(...) noexcept(false);
template <class T, class U, class = decltype(swap(std::declval<T &>(), std::declval<U &>()))>
std::true_type can_swap(int) noexcept(noexcept(swap(std::declval<T &>(), std::declval<U &>())));

template <class, class>
std::false_type uses_std(...);
template <class T, class U>
std::is_same<decltype(swap(std::declval<T &>(), std::declval<U &>())), tag> uses_std(int);

template <class T>
struct is_std_swap_noexcept : std::integral_constant<bool, std::is_nothrow_move_constructible<T>::value &&
                                                               std::is_nothrow_move_assignable<T>::value> {};

template <class T, std::size_t N>
struct is_std_swap_noexcept<T[N]> : is_std_swap_noexcept<T> {};

template <class T, class U>
struct is_adl_swap_noexcept : std::integral_constant<bool, noexcept(can_swap<T, U>(0))> {};
} // namespace swap_adl_tests

template <class T, class U = T>
struct is_swappable
    : std::integral_constant<bool, decltype(detail::swap_adl_tests::can_swap<T, U>(0))::value &&
                                       (!decltype(detail::swap_adl_tests::uses_std<T, U>(0))::value ||
                                        (std::is_move_assignable<T>::value && std::is_move_constructible<T>::value))> {
};

template <class T, std::size_t N>
struct is_swappable<T[N], T[N]>
    : std::integral_constant<bool, decltype(detail::swap_adl_tests::can_swap<T[N], T[N]>(0))::value &&
                                       (!decltype(detail::swap_adl_tests::uses_std<T[N], T[N]>(0))::value ||
                                        is_swappable<T, T>::value)> {};

template <class T, class U = T>
struct is_nothrow_swappable
    : std::integral_constant<bool, is_swappable<T, U>::value &&
                                       ((decltype(detail::swap_adl_tests::uses_std<T, U>(0))::value &&
                                         detail::swap_adl_tests::is_std_swap_noexcept<T>::value) ||
                                        (!decltype(detail::swap_adl_tests::uses_std<T, U>(0))::value &&
                                         detail::swap_adl_tests::is_adl_swap_noexcept<T, U>::value))> {};
#endif
#endif

// Trait for checking if a type is a tl::expected
template <class T>
struct is_expected_impl : std::false_type {};
template <class T, class E>
struct is_expected_impl<expected<T, E>> : std::true_type {};
template <class T>
using is_expected = is_expected_impl<decay_t<T>>;

template <class T, class E, class U>
using expected_enable_forward_value =
    detail::enable_if_t<std::is_constructible<T, U &&>::value && !std::is_same<detail::decay_t<U>, in_place_t>::value &&
                        !std::is_same<expected<T, E>, detail::decay_t<U>>::value &&
                        !std::is_same<unexpected<E>, detail::decay_t<U>>::value>;

template <class T, class E, class U, class G, class UR, class GR>
using expected_enable_from_other = detail::enable_if_t<
    std::is_constructible<T, UR>::value && std::is_constructible<E, GR>::value &&
    !std::is_constructible<T, expected<U, G> &>::value && !std::is_constructible<T, expected<U, G> &&>::value &&
    !std::is_constructible<T, const expected<U, G> &>::value &&
    !std::is_constructible<T, const expected<U, G> &&>::value && !std::is_convertible<expected<U, G> &, T>::value &&
    !std::is_convertible<expected<U, G> &&, T>::value && !std::is_convertible<const expected<U, G> &, T>::value &&
    !std::is_convertible<const expected<U, G> &&, T>::value>;

template <class T, class U>
using is_void_or = conditional_t<std::is_void<T>::value, std::true_type, U>;

template <class T>
using is_copy_constructible_or_void = is_void_or<T, std::is_copy_constructible<T>>;

template <class T>
using is_move_constructible_or_void = is_void_or<T, std::is_move_constructible<T>>;

template <class T>
using is_copy_assignable_or_void = is_void_or<T, std::is_copy_assignable<T>>;

template <class T>
using is_move_assignable_or_void = is_void_or<T, std::is_move_assignable<T>>;

} // namespace detail

namespace detail {
struct no_init_t {};
static constexpr no_init_t no_init{};

// Implements the storage of the values, and ensures that the destructor is
// trivial if it can be.
//
// This specialization is for where neither `T` or `E` is trivially
// destructible, so the destructors must be called on destruction of the
// `expected`
template <class T, class E, bool = std::is_trivially_destructible<T>::value,
          bool = std::is_trivially_destructible<E>::value>
struct expected_storage_base {
  constexpr expected_storage_base() : m_val(T{}), m_has_val(true) {}
  constexpr expected_storage_base(no_init_t) : m_no_init(), m_has_val(false) {}

  template <class... Args, detail::enable_if_t<std::is_constructible<T, Args &&...>::value> * = nullptr>
  constexpr expected_storage_base(in_place_t, Args &&...args) : m_val(std::forward<Args>(args)...), m_has_val(true) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr expected_storage_base(in_place_t, std::initializer_list<U> il, Args &&...args)
      : m_val(il, std::forward<Args>(args)...), m_has_val(true) {}
  template <class... Args, detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t, Args &&...args)
      : m_unexpect(std::forward<Args>(args)...), m_has_val(false) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t, std::initializer_list<U> il, Args &&...args)
      : m_unexpect(il, std::forward<Args>(args)...), m_has_val(false) {}

  ~expected_storage_base() {
    if (m_has_val) {
      m_val.~T();
    } else {
      m_unexpect.~unexpected<E>();
    }
  }
  union {
    T m_val;
    unexpected<E> m_unexpect;
    char m_no_init;
  };
  bool m_has_val;
};

// This specialization is for when both `T` and `E` are trivially-destructible,
// so the destructor of the `expected` can be trivial.
template <class T, class E>
struct expected_storage_base<T, E, true, true> {
  constexpr expected_storage_base() : m_val(T{}), m_has_val(true) {}
  constexpr expected_storage_base(no_init_t) : m_no_init(), m_has_val(false) {}

  template <class... Args, detail::enable_if_t<std::is_constructible<T, Args &&...>::value> * = nullptr>
  constexpr expected_storage_base(in_place_t, Args &&...args) : m_val(std::forward<Args>(args)...), m_has_val(true) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr expected_storage_base(in_place_t, std::initializer_list<U> il, Args &&...args)
      : m_val(il, std::forward<Args>(args)...), m_has_val(true) {}
  template <class... Args, detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t, Args &&...args)
      : m_unexpect(std::forward<Args>(args)...), m_has_val(false) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t, std::initializer_list<U> il, Args &&...args)
      : m_unexpect(il, std::forward<Args>(args)...), m_has_val(false) {}

  ~expected_storage_base() = default;
  union {
    T m_val;
    unexpected<E> m_unexpect;
    char m_no_init;
  };
  bool m_has_val;
};

// T is trivial, E is not.
template <class T, class E>
struct expected_storage_base<T, E, true, false> {
  constexpr expected_storage_base() : m_val(T{}), m_has_val(true) {}
  TL_EXPECTED_MSVC2015_CONSTEXPR expected_storage_base(no_init_t) : m_no_init(), m_has_val(false) {}

  template <class... Args, detail::enable_if_t<std::is_constructible<T, Args &&...>::value> * = nullptr>
  constexpr expected_storage_base(in_place_t, Args &&...args) : m_val(std::forward<Args>(args)...), m_has_val(true) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr expected_storage_base(in_place_t, std::initializer_list<U> il, Args &&...args)
      : m_val(il, std::forward<Args>(args)...), m_has_val(true) {}
  template <class... Args, detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t, Args &&...args)
      : m_unexpect(std::forward<Args>(args)...), m_has_val(false) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t, std::initializer_list<U> il, Args &&...args)
      : m_unexpect(il, std::forward<Args>(args)...), m_has_val(false) {}

  ~expected_storage_base() {
    if (!m_has_val) {
      m_unexpect.~unexpected<E>();
    }
  }

  union {
    T m_val;
    unexpected<E> m_unexpect;
    char m_no_init;
  };
  bool m_has_val;
};

// E is trivial, T is not.
template <class T, class E>
struct expected_storage_base<T, E, false, true> {
  constexpr expected_storage_base() : m_val(T{}), m_has_val(true) {}
  constexpr expected_storage_base(no_init_t) : m_no_init(), m_has_val(false) {}

  template <class... Args, detail::enable_if_t<std::is_constructible<T, Args &&...>::value> * = nullptr>
  constexpr expected_storage_base(in_place_t, Args &&...args) : m_val(std::forward<Args>(args)...), m_has_val(true) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr expected_storage_base(in_place_t, std::initializer_list<U> il, Args &&...args)
      : m_val(il, std::forward<Args>(args)...), m_has_val(true) {}
  template <class... Args, detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t, Args &&...args)
      : m_unexpect(std::forward<Args>(args)...), m_has_val(false) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t, std::initializer_list<U> il, Args &&...args)
      : m_unexpect(il, std::forward<Args>(args)...), m_has_val(false) {}

  ~expected_storage_base() {
    if (m_has_val) {
      m_val.~T();
    }
  }
  union {
    T m_val;
    unexpected<E> m_unexpect;
    char m_no_init;
  };
  bool m_has_val;
};

// `T` is `void`, `E` is trivially-destructible
template <class E>
struct expected_storage_base<void, E, false, true> {
#if __GNUC__ <= 5
// no constexpr for GCC 4/5 bug
#else
  TL_EXPECTED_MSVC2015_CONSTEXPR
#endif
  expected_storage_base() : m_has_val(true) {}

  constexpr expected_storage_base(no_init_t) : m_val(), m_has_val(false) {}

  constexpr expected_storage_base(in_place_t) : m_has_val(true) {}

  template <class... Args, detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t, Args &&...args)
      : m_unexpect(std::forward<Args>(args)...), m_has_val(false) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t, std::initializer_list<U> il, Args &&...args)
      : m_unexpect(il, std::forward<Args>(args)...), m_has_val(false) {}

  ~expected_storage_base() = default;
  struct dummy {};
  union {
    unexpected<E> m_unexpect;
    dummy m_val;
  };
  bool m_has_val;
};

// `T` is `void`, `E` is not trivially-destructible
template <class E>
struct expected_storage_base<void, E, false, false> {
  constexpr expected_storage_base() : m_dummy(), m_has_val(true) {}
  constexpr expected_storage_base(no_init_t) : m_dummy(), m_has_val(false) {}

  constexpr expected_storage_base(in_place_t) : m_dummy(), m_has_val(true) {}

  template <class... Args, detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t, Args &&...args)
      : m_unexpect(std::forward<Args>(args)...), m_has_val(false) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t, std::initializer_list<U> il, Args &&...args)
      : m_unexpect(il, std::forward<Args>(args)...), m_has_val(false) {}

  ~expected_storage_base() {
    if (!m_has_val) {
      m_unexpect.~unexpected<E>();
    }
  }

  union {
    unexpected<E> m_unexpect;
    char m_dummy;
  };
  bool m_has_val;
};

// This base class provides some handy member functions which can be used in
// further derived classes
template <class T, class E>
struct expected_operations_base : expected_storage_base<T, E> {
  using expected_storage_base<T, E>::expected_storage_base;

  template <class... Args>
  void construct(Args &&...args) noexcept {
    new (std::addressof(this->m_val)) T(std::forward<Args>(args)...);
    this->m_has_val = true;
  }

  template <class Rhs>
  void construct_with(Rhs &&rhs) noexcept {
    new (std::addressof(this->m_val)) T(std::forward<Rhs>(rhs).get());
    this->m_has_val = true;
  }

  template <class... Args>
  void construct_error(Args &&...args) noexcept {
    new (std::addressof(this->m_unexpect)) unexpected<E>(std::forward<Args>(args)...);
    this->m_has_val = false;
  }

#ifdef TL_EXPECTED_EXCEPTIONS_ENABLED

  // These assign overloads ensure that the most efficient assignment
  // implementation is used while maintaining the strong exception guarantee.
  // The problematic case is where rhs has a value, but *this does not.
  //
  // This overload handles the case where we can just copy-construct `T`
  // directly into place without throwing.
  template <class U = T, detail::enable_if_t<std::is_nothrow_copy_constructible<U>::value> * = nullptr>
  void assign(const expected_operations_base &rhs) noexcept {
    if (!this->m_has_val && rhs.m_has_val) {
      geterr().~unexpected<E>();
      construct(rhs.get());
    } else {
      assign_common(rhs);
    }
  }

  // This overload handles the case where we can attempt to create a copy of
  // `T`, then no-throw move it into place if the copy was successful.
  template <class U = T, detail::enable_if_t<!std::is_nothrow_copy_constructible<U>::value &&
                                             std::is_nothrow_move_constructible<U>::value> * = nullptr>
  void assign(const expected_operations_base &rhs) noexcept {
    if (!this->m_has_val && rhs.m_has_val) {
      T tmp = rhs.get();
      geterr().~unexpected<E>();
      construct(std::move(tmp));
    } else {
      assign_common(rhs);
    }
  }

  // This overload is the worst-case, where we have to move-construct the
  // unexpected value into temporary storage, then try to copy the T into place.
  // If the construction succeeds, then everything is fine, but if it throws,
  // then we move the old unexpected value back into place before rethrowing the
  // exception.
  template <class U = T, detail::enable_if_t<!std::is_nothrow_copy_constructible<U>::value &&
                                             !std::is_nothrow_move_constructible<U>::value> * = nullptr>
  void assign(const expected_operations_base &rhs) {
    if (!this->m_has_val && rhs.m_has_val) {
      auto tmp = std::move(geterr());
      geterr().~unexpected<E>();

#ifdef TL_EXPECTED_EXCEPTIONS_ENABLED
      try {
        construct(rhs.get());
      } catch (...) {
        geterr() = std::move(tmp);
        throw;
      }
#else
      construct(rhs.get());
#endif
    } else {
      assign_common(rhs);
    }
  }

  // These overloads do the same as above, but for rvalues
  template <class U = T, detail::enable_if_t<std::is_nothrow_move_constructible<U>::value> * = nullptr>
  void assign(expected_operations_base &&rhs) noexcept {
    if (!this->m_has_val && rhs.m_has_val) {
      geterr().~unexpected<E>();
      construct(std::move(rhs).get());
    } else {
      assign_common(std::move(rhs));
    }
  }

  template <class U = T, detail::enable_if_t<!std::is_nothrow_move_constructible<U>::value> * = nullptr>
  void assign(expected_operations_base &&rhs) {
    if (!this->m_has_val && rhs.m_has_val) {
      auto tmp = std::move(geterr());
      geterr().~unexpected<E>();
#ifdef TL_EXPECTED_EXCEPTIONS_ENABLED
      try {
        construct(std::move(rhs).get());
      } catch (...) {
        geterr() = std::move(tmp);
        throw;
      }
#else
      construct(std::move(rhs).get());
#endif
    } else {
      assign_common(std::move(rhs));
    }
  }

#else

  // If exceptions are disabled then we can just copy-construct
  void assign(const expected_operations_base &rhs) noexcept {
    if (!this->m_has_val && rhs.m_has_val) {
      geterr().~unexpected<E>();
      construct(rhs.get());
    } else {
      assign_common(rhs);
    }
  }

  void assign(expected_operations_base &&rhs) noexcept {
    if (!this->m_has_val && rhs.m_has_val) {
      geterr().~unexpected<E>();
      construct(std::move(rhs).get());
    } else {
      assign_common(std::move(rhs));
    }
  }

#endif

  // The common part of move/copy assigning
  template <class Rhs>
  void assign_common(Rhs &&rhs) {
    if (this->m_has_val) {
      if (rhs.m_has_val) {
        get() = std::forward<Rhs>(rhs).get();
      } else {
        destroy_val();
        construct_error(std::forward<Rhs>(rhs).geterr());
      }
    } else {
      if (!rhs.m_has_val) {
        geterr() = std::forward<Rhs>(rhs).geterr();
      }
    }
  }

  bool has_value() const { return this->m_has_val; }

  TL_EXPECTED_11_CONSTEXPR T &get() & { return this->m_val; }
  constexpr const T &get() const & { return this->m_val; }
  TL_EXPECTED_11_CONSTEXPR T &&get() && { return std::move(this->m_val); }
#ifndef TL_EXPECTED_NO_CONSTRR
  constexpr const T &&get() const && { return std::move(this->m_val); }
#endif

  TL_EXPECTED_11_CONSTEXPR unexpected<E> &geterr() & { return this->m_unexpect; }
  constexpr const unexpected<E> &geterr() const & { return this->m_unexpect; }
  TL_EXPECTED_11_CONSTEXPR unexpected<E> &&geterr() && { return std::move(this->m_unexpect); }
#ifndef TL_EXPECTED_NO_CONSTRR
  constexpr const unexpected<E> &&geterr() const && { return std::move(this->m_unexpect); }
#endif

  TL_EXPECTED_11_CONSTEXPR void destroy_val() { get().~T(); }
};

// This base class provides some handy member functions which can be used in
// further derived classes
template <class E>
struct expected_operations_base<void, E> : expected_storage_base<void, E> {
  using expected_storage_base<void, E>::expected_storage_base;

  template <class... Args>
  void construct() noexcept {
    this->m_has_val = true;
  }

  // This function doesn't use its argument, but needs it so that code in
  // levels above this can work independently of whether T is void
  template <class Rhs>
  void construct_with(Rhs &&) noexcept {
    this->m_has_val = true;
  }

  template <class... Args>
  void construct_error(Args &&...args) noexcept {
    new (std::addressof(this->m_unexpect)) unexpected<E>(std::forward<Args>(args)...);
    this->m_has_val = false;
  }

  template <class Rhs>
  void assign(Rhs &&rhs) noexcept {
    if (!this->m_has_val) {
      if (rhs.m_has_val) {
        geterr().~unexpected<E>();
        construct();
      } else {
        geterr() = std::forward<Rhs>(rhs).geterr();
      }
    } else {
      if (!rhs.m_has_val) {
        construct_error(std::forward<Rhs>(rhs).geterr());
      }
    }
  }

  bool has_value() const { return this->m_has_val; }

  TL_EXPECTED_11_CONSTEXPR unexpected<E> &geterr() & { return this->m_unexpect; }
  constexpr const unexpected<E> &geterr() const & { return this->m_unexpect; }
  TL_EXPECTED_11_CONSTEXPR unexpected<E> &&geterr() && { return std::move(this->m_unexpect); }
#ifndef TL_EXPECTED_NO_CONSTRR
  constexpr const unexpected<E> &&geterr() const && { return std::move(this->m_unexpect); }
#endif

  TL_EXPECTED_11_CONSTEXPR void destroy_val() {
    // no-op
  }
};

// This class manages conditionally having a trivial copy constructor
// This specialization is for when T and E are trivially copy constructible
template <class T, class E,
          bool = is_void_or<T, TL_EXPECTED_IS_TRIVIALLY_COPY_CONSTRUCTIBLE(T)>::value &&
                 TL_EXPECTED_IS_TRIVIALLY_COPY_CONSTRUCTIBLE(E)::value>
struct expected_copy_base : expected_operations_base<T, E> {
  using expected_operations_base<T, E>::expected_operations_base;
};

// This specialization is for when T or E are not trivially copy constructible
template <class T, class E>
struct expected_copy_base<T, E, false> : expected_operations_base<T, E> {
  using expected_operations_base<T, E>::expected_operations_base;

  expected_copy_base() = default;
  expected_copy_base(const expected_copy_base &rhs) : expected_operations_base<T, E>(no_init) {
    if (rhs.has_value()) {
      this->construct_with(rhs);
    } else {
      this->construct_error(rhs.geterr());
    }
  }

  expected_copy_base(expected_copy_base &&rhs) = default;
  expected_copy_base &operator=(const expected_copy_base &rhs) = default;
  expected_copy_base &operator=(expected_copy_base &&rhs) = default;
};

// This class manages conditionally having a trivial move constructor
// Unfortunately there's no way to achieve this in GCC < 5 AFAIK, since it
// doesn't implement an analogue to std::is_trivially_move_constructible. We
// have to make do with a non-trivial move constructor even if T is trivially
// move constructible
#ifndef TL_EXPECTED_GCC49
template <class T, class E,
          bool = is_void_or<T, std::is_trivially_move_constructible<T>>::value &&
                 std::is_trivially_move_constructible<E>::value>
struct expected_move_base : expected_copy_base<T, E> {
  using expected_copy_base<T, E>::expected_copy_base;
};
#else
template <class T, class E, bool = false>
struct expected_move_base;
#endif
template <class T, class E>
struct expected_move_base<T, E, false> : expected_copy_base<T, E> {
  using expected_copy_base<T, E>::expected_copy_base;

  expected_move_base() = default;
  expected_move_base(const expected_move_base &rhs) = default;

  expected_move_base(expected_move_base &&rhs) noexcept(std::is_nothrow_move_constructible<T>::value)
      : expected_copy_base<T, E>(no_init) {
    if (rhs.has_value()) {
      this->construct_with(std::move(rhs));
    } else {
      this->construct_error(std::move(rhs.geterr()));
    }
  }
  expected_move_base &operator=(const expected_move_base &rhs) = default;
  expected_move_base &operator=(expected_move_base &&rhs) = default;
};

// This class manages conditionally having a trivial copy assignment operator
template <class T, class E,
          bool = is_void_or<T, conjunction<TL_EXPECTED_IS_TRIVIALLY_COPY_ASSIGNABLE(T),
                                           TL_EXPECTED_IS_TRIVIALLY_COPY_CONSTRUCTIBLE(T),
                                           TL_EXPECTED_IS_TRIVIALLY_DESTRUCTIBLE(T)>>::value &&
                 TL_EXPECTED_IS_TRIVIALLY_COPY_ASSIGNABLE(E)::value &&
                 TL_EXPECTED_IS_TRIVIALLY_COPY_CONSTRUCTIBLE(E)::value &&
                 TL_EXPECTED_IS_TRIVIALLY_DESTRUCTIBLE(E)::value>
struct expected_copy_assign_base : expected_move_base<T, E> {
  using expected_move_base<T, E>::expected_move_base;
};

template <class T, class E>
struct expected_copy_assign_base<T, E, false> : expected_move_base<T, E> {
  using expected_move_base<T, E>::expected_move_base;

  expected_copy_assign_base() = default;
  expected_copy_assign_base(const expected_copy_assign_base &rhs) = default;

  expected_copy_assign_base(expected_copy_assign_base &&rhs) = default;
  expected_copy_assign_base &operator=(const expected_copy_assign_base &rhs) {
    this->assign(rhs);
    return *this;
  }
  expected_copy_assign_base &operator=(expected_copy_assign_base &&rhs) = default;
};

// This class manages conditionally having a trivial move assignment operator
// Unfortunately there's no way to achieve this in GCC < 5 AFAIK, since it
// doesn't implement an analogue to std::is_trivially_move_assignable. We have
// to make do with a non-trivial move assignment operator even if T is trivially
// move assignable
#ifndef TL_EXPECTED_GCC49
template <class T, class E,
          bool = is_void_or<T, conjunction<std::is_trivially_destructible<T>, std::is_trivially_move_constructible<T>,
                                           std::is_trivially_move_assignable<T>>>::value &&
                 std::is_trivially_destructible<E>::value && std::is_trivially_move_constructible<E>::value &&
                 std::is_trivially_move_assignable<E>::value>
struct expected_move_assign_base : expected_copy_assign_base<T, E> {
  using expected_copy_assign_base<T, E>::expected_copy_assign_base;
};
#else
template <class T, class E, bool = false>
struct expected_move_assign_base;
#endif

template <class T, class E>
struct expected_move_assign_base<T, E, false> : expected_copy_assign_base<T, E> {
  using expected_copy_assign_base<T, E>::expected_copy_assign_base;

  expected_move_assign_base() = default;
  expected_move_assign_base(const expected_move_assign_base &rhs) = default;

  expected_move_assign_base(expected_move_assign_base &&rhs) = default;

  expected_move_assign_base &operator=(const expected_move_assign_base &rhs) = default;

  expected_move_assign_base &
  operator=(expected_move_assign_base &&rhs) noexcept(std::is_nothrow_move_constructible<T>::value &&
                                                      std::is_nothrow_move_assignable<T>::value) {
    this->assign(std::move(rhs));
    return *this;
  }
};

// expected_delete_ctor_base will conditionally delete copy and move
// constructors depending on whether T is copy/move constructible
template <class T, class E,
          bool EnableCopy = (is_copy_constructible_or_void<T>::value && std::is_copy_constructible<E>::value),
          bool EnableMove = (is_move_constructible_or_void<T>::value && std::is_move_constructible<E>::value)>
struct expected_delete_ctor_base {
  expected_delete_ctor_base() = default;
  expected_delete_ctor_base(const expected_delete_ctor_base &) = default;
  expected_delete_ctor_base(expected_delete_ctor_base &&) noexcept = default;
  expected_delete_ctor_base &operator=(const expected_delete_ctor_base &) = default;
  expected_delete_ctor_base &operator=(expected_delete_ctor_base &&) noexcept = default;
};

template <class T, class E>
struct expected_delete_ctor_base<T, E, true, false> {
  expected_delete_ctor_base() = default;
  expected_delete_ctor_base(const expected_delete_ctor_base &) = default;
  expected_delete_ctor_base(expected_delete_ctor_base &&) noexcept = delete;
  expected_delete_ctor_base &operator=(const expected_delete_ctor_base &) = default;
  expected_delete_ctor_base &operator=(expected_delete_ctor_base &&) noexcept = default;
};

template <class T, class E>
struct expected_delete_ctor_base<T, E, false, true> {
  expected_delete_ctor_base() = default;
  expected_delete_ctor_base(const expected_delete_ctor_base &) = delete;
  expected_delete_ctor_base(expected_delete_ctor_base &&) noexcept = default;
  expected_delete_ctor_base &operator=(const expected_delete_ctor_base &) = default;
  expected_delete_ctor_base &operator=(expected_delete_ctor_base &&) noexcept = default;
};

template <class T, class E>
struct expected_delete_ctor_base<T, E, false, false> {
  expected_delete_ctor_base() = default;
  expected_delete_ctor_base(const expected_delete_ctor_base &) = delete;
  expected_delete_ctor_base(expected_delete_ctor_base &&) noexcept = delete;
  expected_delete_ctor_base &operator=(const expected_delete_ctor_base &) = default;
  expected_delete_ctor_base &operator=(expected_delete_ctor_base &&) noexcept = default;
};

// expected_delete_assign_base will conditionally delete copy and move
// constructors depending on whether T and E are copy/move constructible +
// assignable
template <class T, class E,
          bool EnableCopy = (is_copy_constructible_or_void<T>::value && std::is_copy_constructible<E>::value &&
                             is_copy_assignable_or_void<T>::value && std::is_copy_assignable<E>::value),
          bool EnableMove = (is_move_constructible_or_void<T>::value && std::is_move_constructible<E>::value &&
                             is_move_assignable_or_void<T>::value && std::is_move_assignable<E>::value)>
struct expected_delete_assign_base {
  expected_delete_assign_base() = default;
  expected_delete_assign_base(const expected_delete_assign_base &) = default;
  expected_delete_assign_base(expected_delete_assign_base &&) noexcept = default;
  expected_delete_assign_base &operator=(const expected_delete_assign_base &) = default;
  expected_delete_assign_base &operator=(expected_delete_assign_base &&) noexcept = default;
};

template <class T, class E>
struct expected_delete_assign_base<T, E, true, false> {
  expected_delete_assign_base() = default;
  expected_delete_assign_base(const expected_delete_assign_base &) = default;
  expected_delete_assign_base(expected_delete_assign_base &&) noexcept = default;
  expected_delete_assign_base &operator=(const expected_delete_assign_base &) = default;
  expected_delete_assign_base &operator=(expected_delete_assign_base &&) noexcept = delete;
};

template <class T, class E>
struct expected_delete_assign_base<T, E, false, true> {
  expected_delete_assign_base() = default;
  expected_delete_assign_base(const expected_delete_assign_base &) = default;
  expected_delete_assign_base(expected_delete_assign_base &&) noexcept = default;
  expected_delete_assign_base &operator=(const expected_delete_assign_base &) = delete;
  expected_delete_assign_base &operator=(expected_delete_assign_base &&) noexcept = default;
};

template <class T, class E>
struct expected_delete_assign_base<T, E, false, false> {
  expected_delete_assign_base() = default;
  expected_delete_assign_base(const expected_delete_assign_base &) = default;
  expected_delete_assign_base(expected_delete_assign_base &&) noexcept = default;
  expected_delete_assign_base &operator=(const expected_delete_assign_base &) = delete;
  expected_delete_assign_base &operator=(expected_delete_assign_base &&) noexcept = delete;
};

// This is needed to be able to construct the expected_default_ctor_base which
// follows, while still conditionally deleting the default constructor.
struct default_constructor_tag {
  explicit constexpr default_constructor_tag() = default;
};

// expected_default_ctor_base will ensure that expected has a deleted default
// consturctor if T is not default constructible.
// This specialization is for when T is default constructible
template <class T, class E, bool Enable = std::is_default_constructible<T>::value || std::is_void<T>::value>
struct expected_default_ctor_base {
  constexpr expected_default_ctor_base() noexcept = default;
  constexpr expected_default_ctor_base(expected_default_ctor_base const &) noexcept = default;
  constexpr expected_default_ctor_base(expected_default_ctor_base &&) noexcept = default;
  expected_default_ctor_base &operator=(expected_default_ctor_base const &) noexcept = default;
  expected_default_ctor_base &operator=(expected_default_ctor_base &&) noexcept = default;

  constexpr explicit expected_default_ctor_base(default_constructor_tag) {}
};

// This specialization is for when T is not default constructible
template <class T, class E>
struct expected_default_ctor_base<T, E, false> {
  constexpr expected_default_ctor_base() noexcept = delete;
  constexpr expected_default_ctor_base(expected_default_ctor_base const &) noexcept = default;
  constexpr expected_default_ctor_base(expected_default_ctor_base &&) noexcept = default;
  expected_default_ctor_base &operator=(expected_default_ctor_base const &) noexcept = default;
  expected_default_ctor_base &operator=(expected_default_ctor_base &&) noexcept = default;

  constexpr explicit expected_default_ctor_base(default_constructor_tag) {}
};
} // namespace detail

template <class E>
class bad_expected_access : public std::exception {
public:
  explicit bad_expected_access(E e) : m_val(std::move(e)) {}

  virtual const char *what() const noexcept override { return "Bad expected access"; }

  const E &error() const & { return m_val; }
  E &error() & { return m_val; }
  const E &&error() const && { return std::move(m_val); }
  E &&error() && { return std::move(m_val); }

private:
  E m_val;
};

/// An `expected<T, E>` object is an object that contains the storage for
/// another object and manages the lifetime of this contained object `T`.
/// Alternatively it could contain the storage for another unexpected object
/// `E`. The contained object may not be initialized after the expected object
/// has been initialized, and may not be destroyed before the expected object
/// has been destroyed. The initialization state of the contained object is
/// tracked by the expected object.
template <class T, class E>
class expected : private detail::expected_move_assign_base<T, E>,
                 private detail::expected_delete_ctor_base<T, E>,
                 private detail::expected_delete_assign_base<T, E>,
                 private detail::expected_default_ctor_base<T, E> {
  static_assert(!std::is_reference<T>::value, "T must not be a reference");
  static_assert(!std::is_same<T, std::remove_cv<in_place_t>::type>::value, "T must not be in_place_t");
  static_assert(!std::is_same<T, std::remove_cv<unexpect_t>::type>::value, "T must not be unexpect_t");
  static_assert(!std::is_same<T, typename std::remove_cv<unexpected<E>>::type>::value, "T must not be unexpected<E>");
  static_assert(!std::is_reference<E>::value, "E must not be a reference");

  T *valptr() { return std::addressof(this->m_val); }
  const T *valptr() const { return std::addressof(this->m_val); }
  unexpected<E> *errptr() { return std::addressof(this->m_unexpect); }
  const unexpected<E> *errptr() const { return std::addressof(this->m_unexpect); }

  template <class U = T, detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  TL_EXPECTED_11_CONSTEXPR U &val() {
    return this->m_val;
  }
  TL_EXPECTED_11_CONSTEXPR unexpected<E> &err() { return this->m_unexpect; }

  template <class U = T, detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr const U &val() const {
    return this->m_val;
  }
  constexpr const unexpected<E> &err() const { return this->m_unexpect; }

  using impl_base = detail::expected_move_assign_base<T, E>;
  using ctor_base = detail::expected_default_ctor_base<T, E>;

public:
  typedef T value_type;
  typedef E error_type;
  typedef unexpected<E> unexpected_type;

#if defined(TL_EXPECTED_CXX14) && !defined(TL_EXPECTED_GCC49) && !defined(TL_EXPECTED_GCC54) &&                        \
    !defined(TL_EXPECTED_GCC55)
  template <class F>
  TL_EXPECTED_11_CONSTEXPR auto and_then(F &&f) & {
    return and_then_impl(*this, std::forward<F>(f));
  }
  template <class F>
  TL_EXPECTED_11_CONSTEXPR auto and_then(F &&f) && {
    return and_then_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F>
  constexpr auto and_then(F &&f) const & {
    return and_then_impl(*this, std::forward<F>(f));
  }

#ifndef TL_EXPECTED_NO_CONSTRR
  template <class F>
  constexpr auto and_then(F &&f) const && {
    return and_then_impl(std::move(*this), std::forward<F>(f));
  }
#endif

#else
  template <class F>
  TL_EXPECTED_11_CONSTEXPR auto and_then(F &&f) & -> decltype(and_then_impl(std::declval<expected &>(),
                                                                            std::forward<F>(f))) {
    return and_then_impl(*this, std::forward<F>(f));
  }
  template <class F>
  TL_EXPECTED_11_CONSTEXPR auto and_then(F &&f) && -> decltype(and_then_impl(std::declval<expected &&>(),
                                                                             std::forward<F>(f))) {
    return and_then_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F>
  constexpr auto and_then(F &&f) const & -> decltype(and_then_impl(std::declval<expected const &>(),
                                                                   std::forward<F>(f))) {
    return and_then_impl(*this, std::forward<F>(f));
  }

#ifndef TL_EXPECTED_NO_CONSTRR
  template <class F>
  constexpr auto and_then(F &&f) const && -> decltype(and_then_impl(std::declval<expected const &&>(),
                                                                    std::forward<F>(f))) {
    return and_then_impl(std::move(*this), std::forward<F>(f));
  }
#endif
#endif

#if defined(TL_EXPECTED_CXX14) && !defined(TL_EXPECTED_GCC49) && !defined(TL_EXPECTED_GCC54) &&                        \
    !defined(TL_EXPECTED_GCC55)
  template <class F>
  TL_EXPECTED_11_CONSTEXPR auto map(F &&f) & {
    return expected_map_impl(*this, std::forward<F>(f));
  }
  template <class F>
  TL_EXPECTED_11_CONSTEXPR auto map(F &&f) && {
    return expected_map_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F>
  constexpr auto map(F &&f) const & {
    return expected_map_impl(*this, std::forward<F>(f));
  }
  template <class F>
  constexpr auto map(F &&f) const && {
    return expected_map_impl(std::move(*this), std::forward<F>(f));
  }
#else
  template <class F>
  TL_EXPECTED_11_CONSTEXPR decltype(expected_map_impl(std::declval<expected &>(), std::declval<F &&>())) map(F &&f) & {
    return expected_map_impl(*this, std::forward<F>(f));
  }
  template <class F>
  TL_EXPECTED_11_CONSTEXPR decltype(expected_map_impl(std::declval<expected>(), std::declval<F &&>())) map(F &&f) && {
    return expected_map_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F>
  constexpr decltype(expected_map_impl(std::declval<const expected &>(), std::declval<F &&>())) map(F &&f) const & {
    return expected_map_impl(*this, std::forward<F>(f));
  }

#ifndef TL_EXPECTED_NO_CONSTRR
  template <class F>
  constexpr decltype(expected_map_impl(std::declval<const expected &&>(), std::declval<F &&>())) map(F &&f) const && {
    return expected_map_impl(std::move(*this), std::forward<F>(f));
  }
#endif
#endif

#if defined(TL_EXPECTED_CXX14) && !defined(TL_EXPECTED_GCC49) && !defined(TL_EXPECTED_GCC54) &&                        \
    !defined(TL_EXPECTED_GCC55)
  template <class F>
  TL_EXPECTED_11_CONSTEXPR auto transform(F &&f) & {
    return expected_map_impl(*this, std::forward<F>(f));
  }
  template <class F>
  TL_EXPECTED_11_CONSTEXPR auto transform(F &&f) && {
    return expected_map_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F>
  constexpr auto transform(F &&f) const & {
    return expected_map_impl(*this, std::forward<F>(f));
  }
  template <class F>
  constexpr auto transform(F &&f) const && {
    return expected_map_impl(std::move(*this), std::forward<F>(f));
  }
#else
  template <class F>
  TL_EXPECTED_11_CONSTEXPR decltype(expected_map_impl(std::declval<expected &>(), std::declval<F &&>()))
  transform(F &&f) & {
    return expected_map_impl(*this, std::forward<F>(f));
  }
  template <class F>
  TL_EXPECTED_11_CONSTEXPR decltype(expected_map_impl(std::declval<expected>(), std::declval<F &&>()))
  transform(F &&f) && {
    return expected_map_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F>
  constexpr decltype(expected_map_impl(std::declval<const expected &>(), std::declval<F &&>()))
  transform(F &&f) const & {
    return expected_map_impl(*this, std::forward<F>(f));
  }

#ifndef TL_EXPECTED_NO_CONSTRR
  template <class F>
  constexpr decltype(expected_map_impl(std::declval<const expected &&>(), std::declval<F &&>()))
  transform(F &&f) const && {
    return expected_map_impl(std::move(*this), std::forward<F>(f));
  }
#endif
#endif

#if defined(TL_EXPECTED_CXX14) && !defined(TL_EXPECTED_GCC49) && !defined(TL_EXPECTED_GCC54) &&                        \
    !defined(TL_EXPECTED_GCC55)
  template <class F>
  TL_EXPECTED_11_CONSTEXPR auto map_error(F &&f) & {
    return map_error_impl(*this, std::forward<F>(f));
  }
  template <class F>
  TL_EXPECTED_11_CONSTEXPR auto map_error(F &&f) && {
    return map_error_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F>
  constexpr auto map_error(F &&f) const & {
    return map_error_impl(*this, std::forward<F>(f));
  }
  template <class F>
  constexpr auto map_error(F &&f) const && {
    return map_error_impl(std::move(*this), std::forward<F>(f));
  }
#else
  template <class F>
  TL_EXPECTED_11_CONSTEXPR decltype(map_error_impl(std::declval<expected &>(), std::declval<F &&>()))
  map_error(F &&f) & {
    return map_error_impl(*this, std::forward<F>(f));
  }
  template <class F>
  TL_EXPECTED_11_CONSTEXPR decltype(map_error_impl(std::declval<expected &&>(), std::declval<F &&>()))
  map_error(F &&f) && {
    return map_error_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F>
  constexpr decltype(map_error_impl(std::declval<const expected &>(), std::declval<F &&>())) map_error(F &&f) const & {
    return map_error_impl(*this, std::forward<F>(f));
  }

#ifndef TL_EXPECTED_NO_CONSTRR
  template <class F>
  constexpr decltype(map_error_impl(std::declval<const expected &&>(), std::declval<F &&>()))
  map_error(F &&f) const && {
    return map_error_impl(std::move(*this), std::forward<F>(f));
  }
#endif
#endif
#if defined(TL_EXPECTED_CXX14) && !defined(TL_EXPECTED_GCC49) && !defined(TL_EXPECTED_GCC54) &&                        \
    !defined(TL_EXPECTED_GCC55)
  template <class F>
  TL_EXPECTED_11_CONSTEXPR auto transform_error(F &&f) & {
    return map_error_impl(*this, std::forward<F>(f));
  }
  template <class F>
  TL_EXPECTED_11_CONSTEXPR auto transform_error(F &&f) && {
    return map_error_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F>
  constexpr auto transform_error(F &&f) const & {
    return map_error_impl(*this, std::forward<F>(f));
  }
  template <class F>
  constexpr auto transform_error(F &&f) const && {
    return map_error_impl(std::move(*this), std::forward<F>(f));
  }
#else
  template <class F>
  TL_EXPECTED_11_CONSTEXPR decltype(map_error_impl(std::declval<expected &>(), std::declval<F &&>()))
  transform_error(F &&f) & {
    return map_error_impl(*this, std::forward<F>(f));
  }
  template <class F>
  TL_EXPECTED_11_CONSTEXPR decltype(map_error_impl(std::declval<expected &&>(), std::declval<F &&>()))
  transform_error(F &&f) && {
    return map_error_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F>
  constexpr decltype(map_error_impl(std::declval<const expected &>(), std::declval<F &&>()))
  transform_error(F &&f) const & {
    return map_error_impl(*this, std::forward<F>(f));
  }

#ifndef TL_EXPECTED_NO_CONSTRR
  template <class F>
  constexpr decltype(map_error_impl(std::declval<const expected &&>(), std::declval<F &&>()))
  transform_error(F &&f) const && {
    return map_error_impl(std::move(*this), std::forward<F>(f));
  }
#endif
#endif
  template <class F>
  expected TL_EXPECTED_11_CONSTEXPR or_else(F &&f) & {
    return or_else_impl(*this, std::forward<F>(f));
  }

  template <class F>
  expected TL_EXPECTED_11_CONSTEXPR or_else(F &&f) && {
    return or_else_impl(std::move(*this), std::forward<F>(f));
  }

  template <class F>
  expected constexpr or_else(F &&f) const & {
    return or_else_impl(*this, std::forward<F>(f));
  }

#ifndef TL_EXPECTED_NO_CONSTRR
  template <class F>
  expected constexpr or_else(F &&f) const && {
    return or_else_impl(std::move(*this), std::forward<F>(f));
  }
#endif
  constexpr expected() = default;
  constexpr expected(const expected &rhs) = default;
  constexpr expected(expected &&rhs) = default;
  expected &operator=(const expected &rhs) = default;
  expected &operator=(expected &&rhs) = default;

  template <class... Args, detail::enable_if_t<std::is_constructible<T, Args &&...>::value> * = nullptr>
  constexpr expected(in_place_t, Args &&...args)
      : impl_base(in_place, std::forward<Args>(args)...), ctor_base(detail::default_constructor_tag{}) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr expected(in_place_t, std::initializer_list<U> il, Args &&...args)
      : impl_base(in_place, il, std::forward<Args>(args)...), ctor_base(detail::default_constructor_tag{}) {}

  template <class G = E, detail::enable_if_t<std::is_constructible<E, const G &>::value> * = nullptr,
            detail::enable_if_t<!std::is_convertible<const G &, E>::value> * = nullptr>
  explicit constexpr expected(const unexpected<G> &e)
      : impl_base(unexpect, e.value()), ctor_base(detail::default_constructor_tag{}) {}

  template <class G = E, detail::enable_if_t<std::is_constructible<E, const G &>::value> * = nullptr,
            detail::enable_if_t<std::is_convertible<const G &, E>::value> * = nullptr>
  constexpr expected(unexpected<G> const &e)
      : impl_base(unexpect, e.value()), ctor_base(detail::default_constructor_tag{}) {}

  template <class G = E, detail::enable_if_t<std::is_constructible<E, G &&>::value> * = nullptr,
            detail::enable_if_t<!std::is_convertible<G &&, E>::value> * = nullptr>
  explicit constexpr expected(unexpected<G> &&e) noexcept(std::is_nothrow_constructible<E, G &&>::value)
      : impl_base(unexpect, std::move(e.value())), ctor_base(detail::default_constructor_tag{}) {}

  template <class G = E, detail::enable_if_t<std::is_constructible<E, G &&>::value> * = nullptr,
            detail::enable_if_t<std::is_convertible<G &&, E>::value> * = nullptr>
  constexpr expected(unexpected<G> &&e) noexcept(std::is_nothrow_constructible<E, G &&>::value)
      : impl_base(unexpect, std::move(e.value())), ctor_base(detail::default_constructor_tag{}) {}

  template <class... Args, detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * = nullptr>
  constexpr explicit expected(unexpect_t, Args &&...args)
      : impl_base(unexpect, std::forward<Args>(args)...), ctor_base(detail::default_constructor_tag{}) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected(unexpect_t, std::initializer_list<U> il, Args &&...args)
      : impl_base(unexpect, il, std::forward<Args>(args)...), ctor_base(detail::default_constructor_tag{}) {}

  template <class U, class G,
            detail::enable_if_t<!(std::is_convertible<U const &, T>::value && std::is_convertible<G const &, E>::value)>
                * = nullptr,
            detail::expected_enable_from_other<T, E, U, G, const U &, const G &> * = nullptr>
  explicit TL_EXPECTED_11_CONSTEXPR expected(const expected<U, G> &rhs) : ctor_base(detail::default_constructor_tag{}) {
    if (rhs.has_value()) {
      this->construct(*rhs);
    } else {
      this->construct_error(rhs.error());
    }
  }

  template <class U, class G,
            detail::enable_if_t<(std::is_convertible<U const &, T>::value && std::is_convertible<G const &, E>::value)>
                * = nullptr,
            detail::expected_enable_from_other<T, E, U, G, const U &, const G &> * = nullptr>
  TL_EXPECTED_11_CONSTEXPR expected(const expected<U, G> &rhs) : ctor_base(detail::default_constructor_tag{}) {
    if (rhs.has_value()) {
      this->construct(*rhs);
    } else {
      this->construct_error(rhs.error());
    }
  }

  template <
      class U, class G,
      detail::enable_if_t<!(std::is_convertible<U &&, T>::value && std::is_convertible<G &&, E>::value)> * = nullptr,
      detail::expected_enable_from_other<T, E, U, G, U &&, G &&> * = nullptr>
  explicit TL_EXPECTED_11_CONSTEXPR expected(expected<U, G> &&rhs) : ctor_base(detail::default_constructor_tag{}) {
    if (rhs.has_value()) {
      this->construct(std::move(*rhs));
    } else {
      this->construct_error(std::move(rhs.error()));
    }
  }

  template <
      class U, class G,
      detail::enable_if_t<(std::is_convertible<U &&, T>::value && std::is_convertible<G &&, E>::value)> * = nullptr,
      detail::expected_enable_from_other<T, E, U, G, U &&, G &&> * = nullptr>
  TL_EXPECTED_11_CONSTEXPR expected(expected<U, G> &&rhs) : ctor_base(detail::default_constructor_tag{}) {
    if (rhs.has_value()) {
      this->construct(std::move(*rhs));
    } else {
      this->construct_error(std::move(rhs.error()));
    }
  }

  template <class U = T, detail::enable_if_t<!std::is_convertible<U &&, T>::value> * = nullptr,
            detail::expected_enable_forward_value<T, E, U> * = nullptr>
  explicit TL_EXPECTED_MSVC2015_CONSTEXPR expected(U &&v) : expected(in_place, std::forward<U>(v)) {}

  template <class U = T, detail::enable_if_t<std::is_convertible<U &&, T>::value> * = nullptr,
            detail::expected_enable_forward_value<T, E, U> * = nullptr>
  TL_EXPECTED_MSVC2015_CONSTEXPR expected(U &&v) : expected(in_place, std::forward<U>(v)) {}

  template <class U = T, class G = T, detail::enable_if_t<std::is_nothrow_constructible<T, U &&>::value> * = nullptr,
            detail::enable_if_t<!std::is_void<G>::value> * = nullptr,
            detail::enable_if_t<(!std::is_same<expected<T, E>, detail::decay_t<U>>::value &&
                                 !detail::conjunction<std::is_scalar<T>, std::is_same<T, detail::decay_t<U>>>::value &&
                                 std::is_constructible<T, U>::value && std::is_assignable<G &, U>::value &&
                                 std::is_nothrow_move_constructible<E>::value)> * = nullptr>
  expected &operator=(U &&v) {
    if (has_value()) {
      val() = std::forward<U>(v);
    } else {
      err().~unexpected<E>();
      ::new (valptr()) T(std::forward<U>(v));
      this->m_has_val = true;
    }

    return *this;
  }

  template <class U = T, class G = T, detail::enable_if_t<!std::is_nothrow_constructible<T, U &&>::value> * = nullptr,
            detail::enable_if_t<!std::is_void<U>::value> * = nullptr,
            detail::enable_if_t<(!std::is_same<expected<T, E>, detail::decay_t<U>>::value &&
                                 !detail::conjunction<std::is_scalar<T>, std::is_same<T, detail::decay_t<U>>>::value &&
                                 std::is_constructible<T, U>::value && std::is_assignable<G &, U>::value &&
                                 std::is_nothrow_move_constructible<E>::value)> * = nullptr>
  expected &operator=(U &&v) {
    if (has_value()) {
      val() = std::forward<U>(v);
    } else {
      auto tmp = std::move(err());
      err().~unexpected<E>();

#ifdef TL_EXPECTED_EXCEPTIONS_ENABLED
      try {
        ::new (valptr()) T(std::forward<U>(v));
        this->m_has_val = true;
      } catch (...) {
        err() = std::move(tmp);
        throw;
      }
#else
      ::new (valptr()) T(std::forward<U>(v));
      this->m_has_val = true;
#endif
    }

    return *this;
  }

  template <class G = E, detail::enable_if_t<std::is_nothrow_copy_constructible<G>::value &&
                                             std::is_assignable<G &, G>::value> * = nullptr>
  expected &operator=(const unexpected<G> &rhs) {
    if (!has_value()) {
      err() = rhs;
    } else {
      this->destroy_val();
      ::new (errptr()) unexpected<E>(rhs);
      this->m_has_val = false;
    }

    return *this;
  }

  template <class G = E, detail::enable_if_t<std::is_nothrow_move_constructible<G>::value &&
                                             std::is_move_assignable<G>::value> * = nullptr>
  expected &operator=(unexpected<G> &&rhs) noexcept {
    if (!has_value()) {
      err() = std::move(rhs);
    } else {
      this->destroy_val();
      ::new (errptr()) unexpected<E>(std::move(rhs));
      this->m_has_val = false;
    }

    return *this;
  }

  template <class... Args, detail::enable_if_t<std::is_nothrow_constructible<T, Args &&...>::value> * = nullptr>
  void emplace(Args &&...args) {
    if (has_value()) {
      val().~T();
    } else {
      err().~unexpected<E>();
      this->m_has_val = true;
    }
    ::new (valptr()) T(std::forward<Args>(args)...);
  }

  template <class... Args, detail::enable_if_t<!std::is_nothrow_constructible<T, Args &&...>::value> * = nullptr>
  void emplace(Args &&...args) {
    if (has_value()) {
      val().~T();
      ::new (valptr()) T(std::forward<Args>(args)...);
    } else {
      auto tmp = std::move(err());
      err().~unexpected<E>();

#ifdef TL_EXPECTED_EXCEPTIONS_ENABLED
      try {
        ::new (valptr()) T(std::forward<Args>(args)...);
        this->m_has_val = true;
      } catch (...) {
        err() = std::move(tmp);
        throw;
      }
#else
      ::new (valptr()) T(std::forward<Args>(args)...);
      this->m_has_val = true;
#endif
    }
  }

  template <
      class U, class... Args,
      detail::enable_if_t<std::is_nothrow_constructible<T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  void emplace(std::initializer_list<U> il, Args &&...args) {
    if (has_value()) {
      T t(il, std::forward<Args>(args)...);
      val() = std::move(t);
    } else {
      err().~unexpected<E>();
      ::new (valptr()) T(il, std::forward<Args>(args)...);
      this->m_has_val = true;
    }
  }

  template <
      class U, class... Args,
      detail::enable_if_t<!std::is_nothrow_constructible<T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  void emplace(std::initializer_list<U> il, Args &&...args) {
    if (has_value()) {
      T t(il, std::forward<Args>(args)...);
      val() = std::move(t);
    } else {
      auto tmp = std::move(err());
      err().~unexpected<E>();

#ifdef TL_EXPECTED_EXCEPTIONS_ENABLED
      try {
        ::new (valptr()) T(il, std::forward<Args>(args)...);
        this->m_has_val = true;
      } catch (...) {
        err() = std::move(tmp);
        throw;
      }
#else
      ::new (valptr()) T(il, std::forward<Args>(args)...);
      this->m_has_val = true;
#endif
    }
  }

private:
  using t_is_void = std::true_type;
  using t_is_not_void = std::false_type;
  using t_is_nothrow_move_constructible = std::true_type;
  using move_constructing_t_can_throw = std::false_type;
  using e_is_nothrow_move_constructible = std::true_type;
  using move_constructing_e_can_throw = std::false_type;

  void swap_where_both_have_value(expected & /*rhs*/, t_is_void) noexcept {
    // swapping void is a no-op
  }

  void swap_where_both_have_value(expected &rhs, t_is_not_void) {
    using std::swap;
    swap(val(), rhs.val());
  }

  void swap_where_only_one_has_value(expected &rhs, t_is_void) noexcept(std::is_nothrow_move_constructible<E>::value) {
    ::new (errptr()) unexpected_type(std::move(rhs.err()));
    rhs.err().~unexpected_type();
    std::swap(this->m_has_val, rhs.m_has_val);
  }

  void swap_where_only_one_has_value(expected &rhs, t_is_not_void) {
    swap_where_only_one_has_value_and_t_is_not_void(rhs, typename std::is_nothrow_move_constructible<T>::type{},
                                                    typename std::is_nothrow_move_constructible<E>::type{});
  }

  void swap_where_only_one_has_value_and_t_is_not_void(expected &rhs, t_is_nothrow_move_constructible,
                                                       e_is_nothrow_move_constructible) noexcept {
    auto temp = std::move(val());
    val().~T();
    ::new (errptr()) unexpected_type(std::move(rhs.err()));
    rhs.err().~unexpected_type();
    ::new (rhs.valptr()) T(std::move(temp));
    std::swap(this->m_has_val, rhs.m_has_val);
  }

  void swap_where_only_one_has_value_and_t_is_not_void(expected &rhs, t_is_nothrow_move_constructible,
                                                       move_constructing_e_can_throw) {
    auto temp = std::move(val());
    val().~T();
#ifdef TL_EXPECTED_EXCEPTIONS_ENABLED
    try {
      ::new (errptr()) unexpected_type(std::move(rhs.err()));
      rhs.err().~unexpected_type();
      ::new (rhs.valptr()) T(std::move(temp));
      std::swap(this->m_has_val, rhs.m_has_val);
    } catch (...) {
      val() = std::move(temp);
      throw;
    }
#else
    ::new (errptr()) unexpected_type(std::move(rhs.err()));
    rhs.err().~unexpected_type();
    ::new (rhs.valptr()) T(std::move(temp));
    std::swap(this->m_has_val, rhs.m_has_val);
#endif
  }

  void swap_where_only_one_has_value_and_t_is_not_void(expected &rhs, move_constructing_t_can_throw,
                                                       e_is_nothrow_move_constructible) {
    auto temp = std::move(rhs.err());
    rhs.err().~unexpected_type();
#ifdef TL_EXPECTED_EXCEPTIONS_ENABLED
    try {
      ::new (rhs.valptr()) T(std::move(val()));
      val().~T();
      ::new (errptr()) unexpected_type(std::move(temp));
      std::swap(this->m_has_val, rhs.m_has_val);
    } catch (...) {
      rhs.err() = std::move(temp);
      throw;
    }
#else
    ::new (rhs.valptr()) T(std::move(val()));
    val().~T();
    ::new (errptr()) unexpected_type(std::move(temp));
    std::swap(this->m_has_val, rhs.m_has_val);
#endif
  }

public:
  template <class OT = T, class OE = E>
  detail::enable_if_t<detail::is_swappable<OT>::value && detail::is_swappable<OE>::value &&
                      (std::is_nothrow_move_constructible<OT>::value || std::is_nothrow_move_constructible<OE>::value)>
  swap(expected &rhs) noexcept(std::is_nothrow_move_constructible<T>::value && detail::is_nothrow_swappable<T>::value &&
                               std::is_nothrow_move_constructible<E>::value && detail::is_nothrow_swappable<E>::value) {
    if (has_value() && rhs.has_value()) {
      swap_where_both_have_value(rhs, typename std::is_void<T>::type{});
    } else if (!has_value() && rhs.has_value()) {
      rhs.swap(*this);
    } else if (has_value()) {
      swap_where_only_one_has_value(rhs, typename std::is_void<T>::type{});
    } else {
      using std::swap;
      swap(err(), rhs.err());
    }
  }

  constexpr const T *operator->() const {
    TL_ASSERT(has_value());
    return valptr();
  }
  TL_EXPECTED_11_CONSTEXPR T *operator->() {
    TL_ASSERT(has_value());
    return valptr();
  }

  template <class U = T, detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr const U &operator*() const & {
    TL_ASSERT(has_value());
    return val();
  }
  template <class U = T, detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  TL_EXPECTED_11_CONSTEXPR U &operator*() & {
    TL_ASSERT(has_value());
    return val();
  }
  template <class U = T, detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr const U &&operator*() const && {
    TL_ASSERT(has_value());
    return std::move(val());
  }
  template <class U = T, detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  TL_EXPECTED_11_CONSTEXPR U &&operator*() && {
    TL_ASSERT(has_value());
    return std::move(val());
  }

  constexpr bool has_value() const noexcept { return this->m_has_val; }
  constexpr explicit operator bool() const noexcept { return this->m_has_val; }

  template <class U = T, detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  TL_EXPECTED_11_CONSTEXPR const U &value() const & {
    if (!has_value())
      detail::throw_exception(bad_expected_access<E>(err().value()));
    return val();
  }
  template <class U = T, detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  TL_EXPECTED_11_CONSTEXPR U &value() & {
    if (!has_value())
      detail::throw_exception(bad_expected_access<E>(err().value()));
    return val();
  }
  template <class U = T, detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  TL_EXPECTED_11_CONSTEXPR const U &&value() const && {
    if (!has_value())
      detail::throw_exception(bad_expected_access<E>(std::move(err()).value()));
    return std::move(val());
  }
  template <class U = T, detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  TL_EXPECTED_11_CONSTEXPR U &&value() && {
    if (!has_value())
      detail::throw_exception(bad_expected_access<E>(std::move(err()).value()));
    return std::move(val());
  }

  constexpr const E &error() const & {
    TL_ASSERT(!has_value());
    return err().value();
  }
  TL_EXPECTED_11_CONSTEXPR E &error() & {
    TL_ASSERT(!has_value());
    return err().value();
  }
  constexpr const E &&error() const && {
    TL_ASSERT(!has_value());
    return std::move(err().value());
  }
  TL_EXPECTED_11_CONSTEXPR E &&error() && {
    TL_ASSERT(!has_value());
    return std::move(err().value());
  }

  template <class U>
  constexpr T value_or(U &&v) const & {
    static_assert(std::is_copy_constructible<T>::value && std::is_convertible<U &&, T>::value,
                  "T must be copy-constructible and convertible to from U&&");
    return bool(*this) ? **this : static_cast<T>(std::forward<U>(v));
  }
  template <class U>
  TL_EXPECTED_11_CONSTEXPR T value_or(U &&v) && {
    static_assert(std::is_move_constructible<T>::value && std::is_convertible<U &&, T>::value,
                  "T must be move-constructible and convertible to from U&&");
    return bool(*this) ? std::move(**this) : static_cast<T>(std::forward<U>(v));
  }
};

namespace detail {
template <class Exp>
using exp_t = typename detail::decay_t<Exp>::value_type;
template <class Exp>
using err_t = typename detail::decay_t<Exp>::error_type;
template <class Exp, class Ret>
using ret_t = expected<Ret, err_t<Exp>>;

#ifdef TL_EXPECTED_CXX14
template <class Exp, class F, detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), *std::declval<Exp>()))>
constexpr auto and_then_impl(Exp &&exp, F &&f) {
  static_assert(detail::is_expected<Ret>::value, "F must return an expected");

  return exp.has_value() ? detail::invoke(std::forward<F>(f), *std::forward<Exp>(exp))
                         : Ret(unexpect, std::forward<Exp>(exp).error());
}

template <class Exp, class F, detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>()))>
constexpr auto and_then_impl(Exp &&exp, F &&f) {
  static_assert(detail::is_expected<Ret>::value, "F must return an expected");

  return exp.has_value() ? detail::invoke(std::forward<F>(f)) : Ret(unexpect, std::forward<Exp>(exp).error());
}
#else
template <class>
struct TC;
template <class Exp, class F, class Ret = decltype(detail::invoke(std::declval<F>(), *std::declval<Exp>())),
          detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr>
auto and_then_impl(Exp &&exp, F &&f) -> Ret {
  static_assert(detail::is_expected<Ret>::value, "F must return an expected");

  return exp.has_value() ? detail::invoke(std::forward<F>(f), *std::forward<Exp>(exp))
                         : Ret(unexpect, std::forward<Exp>(exp).error());
}

template <class Exp, class F, class Ret = decltype(detail::invoke(std::declval<F>())),
          detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr>
constexpr auto and_then_impl(Exp &&exp, F &&f) -> Ret {
  static_assert(detail::is_expected<Ret>::value, "F must return an expected");

  return exp.has_value() ? detail::invoke(std::forward<F>(f)) : Ret(unexpect, std::forward<Exp>(exp).error());
}
#endif

#ifdef TL_EXPECTED_CXX14
template <class Exp, class F, detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), *std::declval<Exp>())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
constexpr auto expected_map_impl(Exp &&exp, F &&f) {
  using result = ret_t<Exp, detail::decay_t<Ret>>;
  return exp.has_value() ? result(detail::invoke(std::forward<F>(f), *std::forward<Exp>(exp)))
                         : result(unexpect, std::forward<Exp>(exp).error());
}

template <class Exp, class F, detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), *std::declval<Exp>())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
auto expected_map_impl(Exp &&exp, F &&f) {
  using result = expected<void, err_t<Exp>>;
  if (exp.has_value()) {
    detail::invoke(std::forward<F>(f), *std::forward<Exp>(exp));
    return result();
  }

  return result(unexpect, std::forward<Exp>(exp).error());
}

template <class Exp, class F, detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
constexpr auto expected_map_impl(Exp &&exp, F &&f) {
  using result = ret_t<Exp, detail::decay_t<Ret>>;
  return exp.has_value() ? result(detail::invoke(std::forward<F>(f)))
                         : result(unexpect, std::forward<Exp>(exp).error());
}

template <class Exp, class F, detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
auto expected_map_impl(Exp &&exp, F &&f) {
  using result = expected<void, err_t<Exp>>;
  if (exp.has_value()) {
    detail::invoke(std::forward<F>(f));
    return result();
  }

  return result(unexpect, std::forward<Exp>(exp).error());
}
#else
template <class Exp, class F, detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), *std::declval<Exp>())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>

constexpr auto expected_map_impl(Exp &&exp, F &&f) -> ret_t<Exp, detail::decay_t<Ret>> {
  using result = ret_t<Exp, detail::decay_t<Ret>>;

  return exp.has_value() ? result(detail::invoke(std::forward<F>(f), *std::forward<Exp>(exp)))
                         : result(unexpect, std::forward<Exp>(exp).error());
}

template <class Exp, class F, detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), *std::declval<Exp>())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>

auto expected_map_impl(Exp &&exp, F &&f) -> expected<void, err_t<Exp>> {
  if (exp.has_value()) {
    detail::invoke(std::forward<F>(f), *std::forward<Exp>(exp));
    return {};
  }

  return unexpected<err_t<Exp>>(std::forward<Exp>(exp).error());
}

template <class Exp, class F, detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>

constexpr auto expected_map_impl(Exp &&exp, F &&f) -> ret_t<Exp, detail::decay_t<Ret>> {
  using result = ret_t<Exp, detail::decay_t<Ret>>;

  return exp.has_value() ? result(detail::invoke(std::forward<F>(f)))
                         : result(unexpect, std::forward<Exp>(exp).error());
}

template <class Exp, class F, detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>

auto expected_map_impl(Exp &&exp, F &&f) -> expected<void, err_t<Exp>> {
  if (exp.has_value()) {
    detail::invoke(std::forward<F>(f));
    return {};
  }

  return unexpected<err_t<Exp>>(std::forward<Exp>(exp).error());
}
#endif

#if defined(TL_EXPECTED_CXX14) && !defined(TL_EXPECTED_GCC49) && !defined(TL_EXPECTED_GCC54) &&                        \
    !defined(TL_EXPECTED_GCC55)
template <class Exp, class F, detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), std::declval<Exp>().error())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
constexpr auto map_error_impl(Exp &&exp, F &&f) {
  using result = expected<exp_t<Exp>, detail::decay_t<Ret>>;
  return exp.has_value() ? result(*std::forward<Exp>(exp))
                         : result(unexpect, detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error()));
}
template <class Exp, class F, detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), std::declval<Exp>().error())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
auto map_error_impl(Exp &&exp, F &&f) {
  using result = expected<exp_t<Exp>, monostate>;
  if (exp.has_value()) {
    return result(*std::forward<Exp>(exp));
  }

  detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error());
  return result(unexpect, monostate{});
}
template <class Exp, class F, detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), std::declval<Exp>().error())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
constexpr auto map_error_impl(Exp &&exp, F &&f) {
  using result = expected<exp_t<Exp>, detail::decay_t<Ret>>;
  return exp.has_value() ? result()
                         : result(unexpect, detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error()));
}
template <class Exp, class F, detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), std::declval<Exp>().error())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
auto map_error_impl(Exp &&exp, F &&f) {
  using result = expected<exp_t<Exp>, monostate>;
  if (exp.has_value()) {
    return result();
  }

  detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error());
  return result(unexpect, monostate{});
}
#else
template <class Exp, class F, detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), std::declval<Exp>().error())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
constexpr auto map_error_impl(Exp &&exp, F &&f) -> expected<exp_t<Exp>, detail::decay_t<Ret>> {
  using result = expected<exp_t<Exp>, detail::decay_t<Ret>>;

  return exp.has_value() ? result(*std::forward<Exp>(exp))
                         : result(unexpect, detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error()));
}

template <class Exp, class F, detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), std::declval<Exp>().error())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
auto map_error_impl(Exp &&exp, F &&f) -> expected<exp_t<Exp>, monostate> {
  using result = expected<exp_t<Exp>, monostate>;
  if (exp.has_value()) {
    return result(*std::forward<Exp>(exp));
  }

  detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error());
  return result(unexpect, monostate{});
}

template <class Exp, class F, detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), std::declval<Exp>().error())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
constexpr auto map_error_impl(Exp &&exp, F &&f) -> expected<exp_t<Exp>, detail::decay_t<Ret>> {
  using result = expected<exp_t<Exp>, detail::decay_t<Ret>>;

  return exp.has_value() ? result()
                         : result(unexpect, detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error()));
}

template <class Exp, class F, detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(), std::declval<Exp>().error())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
auto map_error_impl(Exp &&exp, F &&f) -> expected<exp_t<Exp>, monostate> {
  using result = expected<exp_t<Exp>, monostate>;
  if (exp.has_value()) {
    return result();
  }

  detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error());
  return result(unexpect, monostate{});
}
#endif

#ifdef TL_EXPECTED_CXX14
template <class Exp, class F, class Ret = decltype(detail::invoke(std::declval<F>(), std::declval<Exp>().error())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
constexpr auto or_else_impl(Exp &&exp, F &&f) {
  static_assert(detail::is_expected<Ret>::value, "F must return an expected");
  return exp.has_value() ? std::forward<Exp>(exp) : detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error());
}

template <class Exp, class F, class Ret = decltype(detail::invoke(std::declval<F>(), std::declval<Exp>().error())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
detail::decay_t<Exp> or_else_impl(Exp &&exp, F &&f) {
  return exp.has_value() ? std::forward<Exp>(exp)
                         : (detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error()), std::forward<Exp>(exp));
}
#else
template <class Exp, class F, class Ret = decltype(detail::invoke(std::declval<F>(), std::declval<Exp>().error())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
auto or_else_impl(Exp &&exp, F &&f) -> Ret {
  static_assert(detail::is_expected<Ret>::value, "F must return an expected");
  return exp.has_value() ? std::forward<Exp>(exp) : detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error());
}

template <class Exp, class F, class Ret = decltype(detail::invoke(std::declval<F>(), std::declval<Exp>().error())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
detail::decay_t<Exp> or_else_impl(Exp &&exp, F &&f) {
  return exp.has_value() ? std::forward<Exp>(exp)
                         : (detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error()), std::forward<Exp>(exp));
}
#endif
} // namespace detail

template <class T, class E, class U, class F>
constexpr bool operator==(const expected<T, E> &lhs, const expected<U, F> &rhs) {
  return (lhs.has_value() != rhs.has_value()) ? false : (!lhs.has_value() ? lhs.error() == rhs.error() : *lhs == *rhs);
}
template <class T, class E, class U, class F>
constexpr bool operator!=(const expected<T, E> &lhs, const expected<U, F> &rhs) {
  return (lhs.has_value() != rhs.has_value()) ? true : (!lhs.has_value() ? lhs.error() != rhs.error() : *lhs != *rhs);
}
template <class E, class F>
constexpr bool operator==(const expected<void, E> &lhs, const expected<void, F> &rhs) {
  return (lhs.has_value() != rhs.has_value()) ? false : (!lhs.has_value() ? lhs.error() == rhs.error() : true);
}
template <class E, class F>
constexpr bool operator!=(const expected<void, E> &lhs, const expected<void, F> &rhs) {
  return (lhs.has_value() != rhs.has_value()) ? true : (!lhs.has_value() ? lhs.error() == rhs.error() : false);
}

template <class T, class E, class U>
constexpr bool operator==(const expected<T, E> &x, const U &v) {
  return x.has_value() ? *x == v : false;
}
template <class T, class E, class U>
constexpr bool operator==(const U &v, const expected<T, E> &x) {
  return x.has_value() ? *x == v : false;
}
template <class T, class E, class U>
constexpr bool operator!=(const expected<T, E> &x, const U &v) {
  return x.has_value() ? *x != v : true;
}
template <class T, class E, class U>
constexpr bool operator!=(const U &v, const expected<T, E> &x) {
  return x.has_value() ? *x != v : true;
}

template <class T, class E>
constexpr bool operator==(const expected<T, E> &x, const unexpected<E> &e) {
  return x.has_value() ? false : x.error() == e.value();
}
template <class T, class E>
constexpr bool operator==(const unexpected<E> &e, const expected<T, E> &x) {
  return x.has_value() ? false : x.error() == e.value();
}
template <class T, class E>
constexpr bool operator!=(const expected<T, E> &x, const unexpected<E> &e) {
  return x.has_value() ? true : x.error() != e.value();
}
template <class T, class E>
constexpr bool operator!=(const unexpected<E> &e, const expected<T, E> &x) {
  return x.has_value() ? true : x.error() != e.value();
}

template <class T, class E,
          detail::enable_if_t<(std::is_void<T>::value || std::is_move_constructible<T>::value) &&
                              detail::is_swappable<T>::value && std::is_move_constructible<E>::value &&
                              detail::is_swappable<E>::value> * = nullptr>
void swap(expected<T, E> &lhs, expected<T, E> &rhs) noexcept(noexcept(lhs.swap(rhs))) {
  lhs.swap(rhs);
}
} // namespace tl

/// field_types.h
namespace hpp::proto {

#if defined(__cpp_lib_expected)
using std::expected;
using std::unexpected;
#else
using tl::expected;
using tl::unexpected;
#endif


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

#if defined(__clang__)
#define HPP_PROTO_WRAP_FLOAT(v)                                                                                        \
  hpp::proto::float_wrapper<std::bit_cast<int32_t>(v)> {}
#define HPP_PROTO_WRAP_DOUBLE(v)                                                                                       \
  hpp::proto::double_wrapper<std::bit_cast<int64_t>(v)> {}
#else
#define HPP_PROTO_WRAP_FLOAT(v) v
#define HPP_PROTO_WRAP_DOUBLE(v) v
#endif


template <int64_t x>
static constexpr auto unwrap(double_wrapper<x>) {
  return std::bit_cast<double>(x);
}

template <int32_t x>
static constexpr auto unwrap(float_wrapper<x>) {
  return std::bit_cast<float>(x);
}

template <typename T>
static constexpr auto unwrap(T v) {
  return v;
}

template <typename T, auto Default = std::monostate{}>
constexpr bool is_default_value(const T &val) {
  if constexpr (std::is_same_v<std::remove_cvref_t<decltype(Default)>, std::monostate>) {
    if constexpr (requires { val.empty(); }) {
      return val.empty();
    }
    if constexpr (requires { val.has_value(); }) {
      return !val.has_value();
    }
    if constexpr (std::is_class_v<T>) {
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

struct boolean {
  bool value = false;
  constexpr boolean() = default;
  constexpr boolean(bool v) : value(v) {}
  constexpr operator bool() const { return value; }
};

template <typename T, auto Default = std::monostate{}>
class optional {
  std::optional<T> impl;

public:
  using value_type = T;

  constexpr optional() noexcept = default;
  constexpr optional(std::nullopt_t) noexcept : impl(std::nullopt) {}

  constexpr optional(optional &&) = default;
  constexpr optional(const optional &) = default;

  template <class U>
  constexpr optional(const optional<U> &other) : impl(other.impl) {}
  template <class U>
  constexpr optional(optional<U> &&other) : impl(std::move(other.impl)) {}

  constexpr optional(const std::optional<T> &other) : impl(other) {}
  constexpr optional(std::optional<T> &&other) : impl(std::move(other)) {}
  template <class U>
  constexpr optional(const std::optional<U> &other) : impl(other) {}
  template <class U>
  constexpr optional(std::optional<U> &&other) : impl(std::move(other)) {}

  template <class... Args>
  constexpr explicit optional(std::in_place_t, Args &&...args) : impl(std::in_place, forward<Args>(args)...) {}

  template <class U, class... Args>
  constexpr explicit optional(std::in_place_t, std::initializer_list<U> ilist, Args &&...args)
      : impl(std::in_place, ilist, forward<Args>(args)...) {}

  template <typename U>
    requires std::convertible_to<U, T>
  constexpr optional(U &&value) : impl(std::forward<U>(value)) {}

  constexpr optional &operator=(std::nullopt_t) noexcept {
    impl = std::nullopt;
    return *this;
  }

  template <typename U>
    requires std::convertible_to<U, T>
  constexpr optional &operator=(U &&value) {
    impl = std::forward<U>(value);
    return *this;
  }

  constexpr optional &operator=(const optional &) = default;
  constexpr optional &operator=(optional &&) = default;

  template <class U>
  constexpr optional &operator=(const optional<U> &other) {
    impl = other.imp;
    return *this;
  }
  template <class U>
  constexpr optional &operator=(optional<U> &&other) {
    impl = std::move(other.imp);
    return *this;
  }

  constexpr optional &operator=(const std::optional<T> &v) {
    impl = v;
    return *this;
  }

  constexpr optional &operator=(std::optional<T> &&v) {
    impl = move(v);
    return *this;
  }

  constexpr bool has_value() const noexcept { return impl.has_value(); }
  constexpr operator bool() const noexcept { return has_value(); }

  constexpr T &value() & { return impl.value(); }
  constexpr const T &value() const & { return impl.value(); }
  constexpr T &&value() && { return std::move(impl.value()); }
  constexpr const T &&value() const && { return std::move(impl.value()); }

  template <class U>
  constexpr T value_or(U &&default_value) const & {
    return impl.value_or(static_cast<T>(default_value));
  }
  template <class U>
  constexpr T value_or(U &&default_value) && {
    return impl.value_or(default_value);
  }

  constexpr T *operator->() noexcept { return impl.operator->(); }
  constexpr const T *operator->() const noexcept { return impl.operator->(); }

  constexpr T &operator*() & noexcept { return *impl; }
  constexpr const T &operator*() const & noexcept { return *impl; }
  constexpr T &&operator*() && noexcept { return *impl; }
  constexpr const T &&operator*() const && noexcept { return *impl; }

  template <typename... Args>
  constexpr T &emplace(Args &&...args) {
    return impl.emplace(std::forward<Args>(args)...);
  }
  constexpr void swap(optional &other) noexcept { impl.swap(other.impl); }
  constexpr void reset() noexcept { impl.reset(); }

  constexpr T value_or_default() const {
    if constexpr (std::is_same_v<std::remove_cvref_t<decltype(Default)>, std::monostate>) {
      return this->value_or(T{});
    } else if constexpr (requires { T{Default.data(), Default.size()}; }) {
      return this->value_or(T{Default.data(), Default.size()});
    } else if constexpr (requires {
                           requires sizeof(typename T::value_type) == sizeof(typename decltype(Default)::value_type);
                           T{(const typename T::value_type *)Default.data(),
                             (const typename T::value_type *)Default.data() + Default.size()};
                         }) {
      return this->value_or(T{(const typename T::value_type *)Default.data(),
                              (const typename T::value_type *)Default.data() + Default.size()});
    } else {
      return this->value_or(unwrap(Default));
    }
  }

  constexpr bool operator==(const optional &other) const = default;
};

template <typename T>
class heap_based_optional {
  T *obj = nullptr;

public:
  using value_type = T;
  constexpr heap_based_optional() noexcept {}
  constexpr heap_based_optional(std::nullopt_t) noexcept {}
  constexpr ~heap_based_optional() { delete obj; }

  constexpr heap_based_optional(const T &object) : obj(new T(object)) {}
  constexpr heap_based_optional(heap_based_optional &&other) noexcept { std::swap(obj, other.obj); }
  constexpr heap_based_optional(const heap_based_optional &other) : obj(other.obj ? new T(*other.obj) : nullptr) {}

  template <class... Args>
  constexpr explicit heap_based_optional(std::in_place_t, Args &&...args)
      : obj(new T{std::forward<Args &&>(args)...}) {}

  constexpr heap_based_optional &operator=(heap_based_optional &&other) noexcept {
    std::swap(obj, other.obj);
    return *this;
  }

  constexpr heap_based_optional &operator=(const heap_based_optional &other) {
    heap_based_optional tmp(other);
    std::swap(obj, tmp.obj);
    return *this;
  }

  constexpr bool has_value() const noexcept { return obj; }
  constexpr operator bool() const noexcept { return has_value(); }

  constexpr T &value() {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *obj;
  }
  constexpr const T &value() const {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *obj;
  }

  constexpr T &operator*() noexcept { return *obj; }
  constexpr const T &operator*() const noexcept { return *obj; }

  constexpr T *operator->() noexcept { return obj; }
  constexpr const T *operator->() const noexcept { return obj; }

  constexpr T &emplace() {
    heap_based_optional tmp;
    tmp.obj = new T;
    std::swap(obj, tmp.obj);
    return *obj;
  }

  constexpr void swap(heap_based_optional &other) noexcept { std::swap(obj, other.obj); }
  constexpr void reset() noexcept {
    delete obj;
    obj == nullptr;
  }

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

  constexpr bool operator==(std::nullopt_t) const { return !has_value(); }

#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARATOR

  constexpr std::strong_ordering operator<=>(const heap_based_optional &rhs) const {
    if (has_value() && rhs.has_value()) {
      return **this <=> *rhs;
    } else {
      return has_value() <=> rhs.has_value();
    }
  }

  constexpr std::strong_ordering operator<=>(const T &rhs) const {
    if (has_value()) {
      return **this <=> rhs;
    } else {
      return std::strong_ordering::less;
    }
  }

  constexpr std::strong_ordering operator<=>(std::nullopt_t) const {
    return has_value() ? std::strong_ordering::greater : std::strong_ordering::equal;
  }
#endif
};

/////////////////////////////////////////////////////////////////////////////////

enum class varint_encoding {
  normal,
  zig_zag,
};

template <typename Type, varint_encoding Encoding = varint_encoding::normal>
struct varint {
  varint() = default;
  using value_type = Type;
  static constexpr auto encoding = Encoding;
  constexpr varint(Type value) : value(value) {}
  constexpr operator Type &() & { return value; }
  constexpr operator Type() const { return value; }
  constexpr decltype(auto) operator*() & { return (value); }
  constexpr auto operator*() const & { return value; }
  Type value{};
};
template <typename Type>
constexpr auto varint_max_size = sizeof(Type) * CHAR_BIT / (CHAR_BIT - 1) + 1;

using vint64_t = varint<int64_t>;
using vint32_t = varint<int32_t>;

using vuint64_t = varint<uint64_t>;
using vuint32_t = varint<uint32_t>;

using vsint64_t = varint<int64_t, varint_encoding::zig_zag>;
using vsint32_t = varint<int32_t, varint_encoding::zig_zag>;

template <varint_encoding Encoding = varint_encoding::normal>
inline constexpr auto varint_size(auto value) {
  if constexpr (Encoding == varint_encoding::zig_zag) {
    return varint_size(std::make_unsigned_t<decltype(value)>((value << 1) ^ (value >> (sizeof(value) * CHAR_BIT - 1))));
  } else {
    return ((sizeof(value) * CHAR_BIT) - std::countl_zero(std::make_unsigned_t<decltype(value)>(value | 0x1)) +
            (CHAR_BIT - 2)) /
           (CHAR_BIT - 1);
  }
}

namespace concepts {

template <typename Type>
concept varint = requires { requires std::same_as<Type, varint<typename Type::value_type, Type::encoding>>; };

template <typename Type>
concept container = requires(Type container) {
  typename std::remove_cvref_t<Type>::value_type;
  container.size();
  container.begin();
  container.end();
};

template <typename Type>
concept associative_container =
    container<Type> && requires(Type container) { typename std::remove_cvref_t<Type>::key_type; };

template <typename Type>
concept tuple = !container<Type> && requires(Type tuple) { sizeof(std::tuple_size<std::remove_cvref_t<Type>>); } &&
                !requires(Type tuple) { tuple.index(); };

template <typename Type>
concept variant = requires(Type variant) {
  variant.index();
  std::get_if<0>(&variant);
  std::variant_size_v<std::remove_cvref_t<Type>>;
};

template <typename Type>
concept has_local_meta = concepts::tuple<typename Type::pb_meta>;

template <typename Type>
concept has_explicit_meta = concepts::tuple<decltype(pb_meta(std::declval<Type>()))>;

template <typename Type>
concept has_meta = has_local_meta<Type> || has_explicit_meta<Type>;

template <typename T>
concept numeric =
    std::is_arithmetic_v<T> || concepts::varint<T> || std::is_enum_v<T> || std::same_as<hpp::proto::boolean, T>;

template <typename T>
concept numeric_or_byte = numeric<T> || std::same_as<std::byte, T>;

template <typename Type>
concept optional = requires(Type optional) {
  optional.value();
  optional.has_value();
  // optional.operator bool(); // this operator is deliberately removed to fit
  // our specialization for optional<bool> which removed this operation
  optional.operator*();
};

template <typename Type>
concept oneof_type = concepts::variant<Type>;

template <typename Type>
concept string_or_bytes = concepts::container<Type> && (std::same_as<char, typename Type::value_type> ||
                                                        std::same_as<std::byte, typename Type::value_type>);

template <typename Type>
concept scalar = numeric_or_byte<Type> || string_or_bytes<Type> || std::same_as<Type, boolean>;

template <typename Type>
concept pb_extension = requires(Type value) { typename Type::pb_extension; };

template <typename Type>
concept is_map_entry = requires {
  typename Type::key_type;
  typename Type::mapped_type;
};

template <typename Type>
concept is_option = requires { typename std::remove_cvref_t<Type>::zpp_bits_option; };

template <typename T>
concept span = requires {
  typename T::value_type;
  requires std::same_as<T, std::span<typename T::value_type>>;
};

template <typename T>
concept is_oneof_field_meta = requires { typename T::alternatives_meta; };

template <typename T>
concept contiguous_range = requires(T &t) {
  { t.data() } -> std::same_as<std::add_pointer_t<std::iter_reference_t<decltype(std::begin(std::declval<T &>()))>>>;
  t.size();
};

template <typename Type>
concept byte_type = std::same_as<std::remove_cv_t<Type>, char> || std::same_as<std::remove_cv_t<Type>, unsigned char> ||
                    std::same_as<std::remove_cv_t<Type>, std::byte>;

template <typename T>
concept contiguous_byte_range = byte_type<typename std::remove_cvref_t<T>::value_type> && contiguous_range<T>;

template <typename T>
concept byte_serializable =
    std::is_arithmetic_v<T> || std::same_as<hpp::proto::boolean, T> || std::same_as<std::byte, T>;

template <typename T>
concept is_size_cache = std::same_as<T, uint32_t *> || requires(T v) {
  { v++ } -> std::same_as<T>;
  *v = 0U;
};

template <typename T>
concept memory_resource = requires(T &object) {
  { object.allocate(8, 8) } -> std::same_as<void *>;
};

template <typename T>
concept has_memory_resource = requires(T &object) {
  object.memory_resource;
  requires memory_resource<std::remove_cvref_t<decltype(object.memory_resource)>>;
};

template <typename T>
concept resizable = requires {
  std::declval<T &>().resize(1);
  std::declval<T>()[0];
};

template <typename T>
concept resizable_or_reservable =
    resizable<T> || requires { std::declval<T &>().reserve(1); } || requires { reserve(std::declval<T &>(), 1); };

template <typename Type>
concept has_extension = has_meta<Type> && requires(Type value) {
  value.extensions;
  typename decltype(Type::extensions)::pb_extension;
};

template <typename Type>
concept unique_ptr = requires {
  typename Type::element_type;
  typename Type::deleter_type;
  requires std::same_as<Type, std::unique_ptr<typename Type::element_type, typename Type::deleter_type>>;
};

} // namespace concepts

enum class encoding_rule {
  defaulted = 0,
  explicit_presence = 1,
  unpacked_repeated = 2,
  group = 3,
  packed_repeated = 4
};

template <auto Accessor>
struct accesor_type {
  inline constexpr auto &operator()(auto &&item) const {
    if constexpr (std::is_member_pointer_v<decltype(Accessor)>)
      return item.*Accessor;
    else
      return Accessor(std::forward<decltype(item)>(item));
  }
};

template <uint32_t Number, auto Accessor, encoding_rule Encoding = encoding_rule::defaulted, typename Type = void,
          auto DefaultValue = std::monostate{}>
struct field_meta {
  constexpr static uint32_t number = Number;
  constexpr static encoding_rule encoding = Encoding;
  constexpr static auto access = accesor_type<Accessor>{};
  using type = Type;

  template <typename T>
  inline static constexpr bool omit_value(const T &v) {
    if constexpr (Encoding == encoding_rule::defaulted) {
      return is_default_value<T, DefaultValue>(v);
    } else if constexpr (requires { v.has_value(); }) {
      return !v.has_value();
    } else if constexpr (std::is_pointer_v<std::remove_cvref_t<T>>) {
      return v == nullptr;
    } else if constexpr (requires {
                           typename T::element_type;
                           v.get();
                         }) {
      return v.get() == nullptr;
    }

    return false;
  }
};

template <auto Accessor, typename... AlternativeMeta>
struct oneof_field_meta {
  constexpr static auto access = accesor_type<Accessor>{};
  using alternatives_meta = std::tuple<AlternativeMeta...>;
  using type = void;
  template <typename T>
  inline static constexpr bool omit_value(const T &v) {
    return v.index() == 0;
  }
};

template <typename T>
struct extension_meta_base {

  struct accesor_type {
    inline constexpr auto &operator()(auto &&item) const {
      auto &[e] = item;
      return e;
    }
  };

  constexpr static auto access = accesor_type{};

  static constexpr void check(const concepts::pb_extension auto &extensions) {
    static_assert(std::same_as<typename std::remove_cvref_t<decltype(extensions)>::pb_extension, typename T::extendee>);
  }

  static auto read(const concepts::pb_extension auto &extensions, auto &&mr);
  static std::error_code write(concepts::pb_extension auto &extensions, auto &&value);
  static std::error_code write(concepts::pb_extension auto &extensions, auto &&value,
                               concepts::memory_resource auto &mr);
  static bool element_of(const concepts::pb_extension auto &extensions) {
    check(extensions);
    if constexpr (requires { extensions.fields.count(T::number); }) {
      return extensions.fields.count(T::number) > 0;
    } else {
      return std::find_if(extensions.fields.begin(), extensions.fields.end(),
                          [](const auto &item) { return item.first == T::number; }) != extensions.fields.end();
    }
  }
};

template <typename Extendee, uint32_t Number, encoding_rule Encoding, typename Type, typename ValueType,
          auto DefaultValue = std::monostate{}>
struct extension_meta : extension_meta_base<extension_meta<Extendee, Number, Encoding, Type, ValueType, DefaultValue>> {

  constexpr static uint32_t number = Number;
  constexpr static encoding_rule encoding = Encoding;
  using type = Type;
  constexpr static auto default_value = unwrap(DefaultValue);
  constexpr static bool has_default_value = !std::same_as<std::remove_const_t<decltype(DefaultValue)>, std::monostate>;
  static constexpr bool is_repeated = false;
  using extendee = Extendee;

  using get_result_type = ValueType;
  using set_value_type = ValueType;

  template <typename T>
  static constexpr bool omit_value(const T &v) {
    if constexpr (Encoding == encoding_rule::defaulted) {
      return is_default_value<T, DefaultValue>(v);
    } else if constexpr (requires { v.has_value(); }) {
      return !v.has_value();
    } else if constexpr (std::is_pointer_v<std::remove_cvref_t<T>>) {
      return v == nullptr;
    } else if constexpr (requires {
                           typename T::element_type;
                           v.get();
                         }) {
      return v.get() == nullptr;
    }

    return false;
  }
};

template <typename Extendee, uint32_t Number, encoding_rule Encoding, typename Type, typename ValueType>
struct repeated_extension_meta
    : extension_meta_base<repeated_extension_meta<Extendee, Number, Encoding, Type, ValueType>> {
  constexpr static uint32_t number = Number;
  constexpr static encoding_rule encoding = Encoding;
  using type = Type;
  constexpr static bool has_default_value = false;
  static constexpr bool is_repeated = true;
  using extendee = Extendee;
  static constexpr bool non_owning = concepts::span<decltype(std::declval<typename extendee::extension_t>().fields)>;
  using element_type = std::conditional_t<std::is_same_v<ValueType, bool> && !non_owning, boolean, ValueType>;
  using get_result_type = std::conditional_t<non_owning, std::span<const element_type>, std::vector<element_type>>;
  using set_value_type = std::span<const element_type>;

  template <typename T>
  static constexpr bool omit_value(const T & /* unused */) {
    return false;
  }
};

template <std::size_t Len>
struct compile_time_string {
  using value_type = char;
  char data_[Len];
  constexpr size_t size() const { return Len - 1; }
  constexpr compile_time_string(const char (&init)[Len]) { std::copy_n(init, Len, data_); }
  constexpr const char *data() const { return data_; }
};

template <std::size_t Len>
struct compile_time_bytes {
  using value_type = char;
  std::byte data_[Len];
  constexpr size_t size() const { return Len - 1; }
  constexpr compile_time_bytes(const char (&init)[Len]) {
    std::transform(init, init + Len, data_, [](char c) { return static_cast<std::byte>(c); });
  }
  constexpr const std::byte *data() const { return data_; }
};

template <compile_time_string cts>
struct ctb_wrapper {
  static constexpr compile_time_bytes bytes{cts.data_};

  constexpr size_t size() const { return bytes.size(); }
  constexpr const std::byte *data() const { return bytes.data(); }
  constexpr const std::byte *begin() const { return bytes.data(); }
  constexpr const std::byte *end() const { return bytes.data() + size(); }

  constexpr operator std::span<const std::byte>() const { return std::span<const std::byte>{data(), size()}; }
  explicit operator std::vector<std::byte>() const { return std::vector<std::byte>{begin(), end()}; }
};

template <compile_time_string cts>
struct cts_wrapper {
  static constexpr compile_time_string str{cts};
  constexpr size_t size() const { return str.size(); }
  constexpr const char *data() const { return str.data(); }
  constexpr const char *c_str() const { return str.data(); }
  constexpr const char *begin() const { return str.data(); }
  constexpr const char *end() const { return str.data() + size(); }

  explicit operator std::string() const { return std::string{data()}; }
  explicit operator std::vector<std::byte>() const {
    return std::vector<std::byte>{std::bit_cast<const std::byte *>(data()),
                                  std::bit_cast<const std::byte *>(data()) + size()};
  }

  explicit operator std::vector<char>() const { return std::vector<char>{data(), data() + size()}; }

  constexpr operator std::string_view() const { return std::string_view(data(), size()); }

  constexpr operator std::span<const std::byte>() const { return ctb_wrapper<cts>{}; }

  constexpr operator std::span<const char>() const { return std::span<const char>{data(), size()}; }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::string &rhs) {
    return static_cast<std::string_view>(lhs) == rhs;
  }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::string_view &rhs) {
    return static_cast<std::string_view>(lhs) == rhs;
  }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::span<const std::byte> &rhs) {
    return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(),
                      [](char a, std::byte b) { return static_cast<std::byte>(a) == b; });
  }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::span<const char> &rhs) {
    return std::equal(rhs.begin(), rhs.end(), lhs.data(), lhs.data() + lhs.size());
  }
};

using bytes_view = std::span<const std::byte>;
template <compile_time_string str>
constexpr auto operator""_cts() {
  return cts_wrapper<str>{};
}

template <compile_time_string str>
constexpr auto operator""_bytes_view() {
  return static_cast<bytes_view>(ctb_wrapper<str>{});
}

template <compile_time_string str>
constexpr auto operator""_bytes() {
  return static_cast<std::vector<std::byte>>(ctb_wrapper<str>{});
}

enum class wire_type : unsigned int {
  varint = 0,
  fixed_64 = 1,
  length_delimited = 2,
  sgroup = 3,
  egroup = 4,
  fixed_32 = 5,
};

template <typename Type>
constexpr auto tag_type() {
  using type = std::remove_cvref_t<Type>;
  if constexpr (concepts::varint<type> || (std::is_enum_v<type> && !std::same_as<type, std::byte>) ||
                std::same_as<type, bool>) {
    return wire_type::varint;
  } else if constexpr (std::is_integral_v<type> || std::is_floating_point_v<type>) {
    if constexpr (sizeof(type) == 4) {
      return wire_type::fixed_32;
    } else if constexpr (sizeof(type) == 8) {
      return wire_type::fixed_64;
    } else {
      static_assert(!sizeof(type));
    }
  } else {
    return wire_type::length_delimited;
  }
}

constexpr auto make_tag(uint32_t number, wire_type type) {
  return varint{(number << 3) | std::underlying_type_t<wire_type>(type)};
}

template <typename Type, typename Meta>
constexpr auto make_tag(Meta meta) {
  // check if Meta::number is static or not
  if constexpr (requires { *&Meta::number; }) {
    return make_tag(Meta::number, tag_type<Type>());
  } else {
    return make_tag(meta.number, tag_type<Type>());
  }
}

constexpr auto tag_type(auto tag) { return wire_type(tag.value & 0x7); }

constexpr auto tag_number(auto tag) { return (unsigned int)(tag >> 3); }

template <typename Meta>
constexpr bool has_field_num(Meta meta, uint32_t num) {
  if constexpr (requires { meta.number; }) {
    return meta.number == num;
  } else if constexpr (concepts::is_oneof_field_meta<Meta>) {
    return std::apply([num](auto... elem) { return (has_field_num(elem, num) || ...); },
                      typename Meta::alternatives_meta{});
  } else {
    return false;
  }
}

template <typename Type>
constexpr void set_as_default(Type &value) {
  using type = std::remove_cvref_t<Type>;
  if constexpr (concepts::scalar<type>) {
    value = type{};
  }
}

template <typename T>
struct serialize_type {
  using type = T;
  using read_type = const T &;
  using convertible_type = const T &;
};

template <typename T>
  requires std::is_enum_v<T>
struct serialize_type<T> {
  using type = vint64_t;
  using read_type = vint64_t;
  using convertible_type = std::underlying_type_t<T>;
};

template <concepts::varint T>
struct serialize_type<T> {
  using type = T;
  using read_type = T;
  using convertible_type = T;
};

template <>
struct serialize_type<bool> {
  using type = boolean;
  using read_type = boolean;
  using convertible_type = boolean;
};

template <typename KeyType, typename MappedType>
struct map_entry {
  using key_type = KeyType;
  using mapped_type = MappedType;
  struct mutable_type {
    typename serialize_type<KeyType>::type key;
    typename serialize_type<MappedType>::type value;
    constexpr static bool allow_inline_visit_members_lambda = true;
    using pb_meta = std::tuple<field_meta<1, &mutable_type::key, encoding_rule::explicit_presence>,
                               field_meta<2, &mutable_type::value, encoding_rule::explicit_presence>>;

    template <typename Target, typename Source>
    constexpr static auto move_or_copy(Source &&src) {
      if constexpr (requires(Target target) { target = std::move(src); }) {
        return std::move(src);
      } else if constexpr (std::is_enum_v<Target> && std::is_same_v<std::remove_cvref_t<Source>, vint64_t>) {
        return static_cast<Target>(src.value);
      } else {
        return static_cast<Target>(src);
      }
    }

    template <concepts::associative_container Container>
    constexpr void insert_to(Container &container) && {
      container.insert_or_assign(move_or_copy<typename Container::key_type>(key),
                                 move_or_copy<typename Container::mapped_type>(value));
    }

    template <typename K, typename V>
    constexpr void to(std::pair<K, V> &target) && {
      target.first = move_or_copy<K>(key);
      target.second = move_or_copy<V>(value);
    }
  };

  struct read_only_type {
    typename serialize_type<KeyType>::read_type key;
    typename serialize_type<MappedType>::read_type value;
    constexpr static bool allow_inline_visit_members_lambda = true;

    constexpr read_only_type(auto &&k, auto &&v)
        : key((typename serialize_type<KeyType>::convertible_type)k),
          value((typename serialize_type<MappedType>::convertible_type)v) {}

    struct key_accessor {
      constexpr const auto &operator()(const read_only_type &entry) const { return entry.key; }
    };

    struct value_accessor {
      constexpr const auto &operator()(const read_only_type &entry) const { return entry.value; }
    };

    using pb_meta = std::tuple<field_meta<1, key_accessor{}, encoding_rule::explicit_presence>,
                               field_meta<2, value_accessor{}, encoding_rule::explicit_presence>>;
  };
};

namespace traits {
template <typename Type>
struct meta_of;

template <concepts::has_local_meta Type>
struct meta_of<Type> {
  using type = typename Type::pb_meta;
};

template <concepts::has_explicit_meta Type>
struct meta_of<Type> {
  using type = decltype(pb_meta(std::declval<Type>()));
};

template <concepts::has_meta Type, std::size_t Index>
struct field_meta_of {
  using type = typename std::tuple_element<Index, typename meta_of<Type>::type>::type;
};

template <typename Meta, typename Type>
struct get_serialize_type;

template <typename Meta, typename Type>
  requires requires { typename Meta::type; }
struct get_serialize_type<Meta, Type> {
  using type = std::conditional_t<std::is_same_v<typename Meta::type, void>, Type, typename Meta::type>;
};

template <typename Meta, typename Type>
using get_map_entry = typename Meta::type;

template <typename T, std::size_t M, std::size_t N>
constexpr std::array<T, M + N> operator<<(std::array<T, M> lhs, std::array<T, N> rhs) {
  std::array<T, M + N> result;
  std::copy(lhs.begin(), lhs.end(), result.begin());
  std::copy(rhs.begin(), rhs.end(), result.begin() + M);
  return result;
}

template <concepts::has_meta Type>
struct reverse_indices {

  template <typename T>
    requires requires { T::number; }
  constexpr static auto get_numbers(T meta) {
    return std::array{meta.number};
  }

  template <typename... T>
  constexpr static auto get_numbers(std::tuple<T...> metas) {
    return std::apply([](auto... elem) { return (... << get_numbers(elem)); }, metas);
  }

  template <concepts::is_oneof_field_meta Meta>
  constexpr static auto get_numbers(Meta /* unused */) {
    return std::apply([](auto... elem) { return (... << get_numbers(elem)); }, typename Meta::alternatives_meta{});
  }
  template <typename T>
    requires requires { T::encoding; }
  constexpr static auto is_unpacked_repeated(T meta) {
    return std::array{meta.encoding == encoding_rule::unpacked_repeated};
  }

  template <typename... T>
  constexpr static auto is_unpacked_repeated(std::tuple<T...> metas) {
    return std::apply([](auto... elem) { return (... << is_unpacked_repeated(elem)); }, metas);
  }

  template <concepts::is_oneof_field_meta Meta>
  constexpr static auto is_unpacked_repeated(Meta /* unused */) {
    return std::apply([](auto... elem) { return (... << is_unpacked_repeated(elem)); },
                      typename Meta::alternatives_meta{});
  }

  template <std::size_t I, typename T>
    requires requires { T::number; }
  constexpr static auto index(T) {
    return std::array{I};
  }

  template <std::size_t I, concepts::is_oneof_field_meta Meta>
  constexpr static auto index(Meta) {
    std::array<std::size_t, std::tuple_size_v<typename Meta::alternatives_meta>> result;
    std::fill(result.begin(), result.end(), I);
    return result;
  }

  constexpr static auto get_indices(std::index_sequence<>) { return std::array<std::size_t, 0>{}; }

  template <std::size_t FirstIndex, std::size_t... Indices>
  constexpr static auto get_indices(std::index_sequence<FirstIndex, Indices...>, auto first_elem, auto... elems) {
    return index<FirstIndex>(first_elem) << get_indices(std::index_sequence<Indices...>{}, elems...);
  }

  template <typename... T>
  constexpr static auto get_indices(std::tuple<T...> metas) {
    return std::apply([](auto... elem) { return get_indices(std::make_index_sequence<sizeof...(T)>(), elem...); },
                      metas);
  }

  constexpr static std::optional<std::size_t> number_to_index(uint32_t number) {
    constexpr typename traits::meta_of<Type>::type metas;
    constexpr auto numbers = get_numbers(metas);
    constexpr auto indices = get_indices(metas);

    for (std::size_t i = 0; i < numbers.size(); ++i) {
      if (numbers[i] == number) {
        return indices[i];
      }
    }
    return {};
  }
};

template <typename Type>
inline constexpr auto number_of_members = std::tuple_size_v<typename meta_of<Type>::type>;
} // namespace traits

template <typename T, bool condition>
struct assert_type {
  static constexpr bool value = condition;
  static_assert(value, "Assertion failed <see below for more information>");
};

#if defined(__cpp_lib_constexpr_vector)
template <typename T>
using constexpr_vector = std::vector<T>;
#else
template <typename T>
class constexpr_vector {
  T *m_data;

public:
  constexpr explicit constexpr_vector(std::size_t n) { m_data = new T[n]; }
  constexpr ~constexpr_vector() { delete[] m_data; }
  constexpr T *data() noexcept { return m_data; }
  constexpr const T *data() const noexcept { return data; }
};
#endif

namespace detail {

template <typename T, concepts::memory_resource MemoryResource>
class growable_span {
public:
  using value_type = std::remove_const_t<T>;

  growable_span(std::span<T> &base, MemoryResource &mr) : base_(base), mr(mr) {}

  void resize(std::size_t n) {
    if (data_ == nullptr || n > base_.size()) {
      data_ = static_cast<value_type *>(mr.allocate(n * sizeof(value_type), alignof(value_type)));
      assert(data_ != nullptr);
      std::uninitialized_copy(base_.begin(), base_.end(), data_);

      if constexpr (!std::is_trivial_v<T>) {
        std::uninitialized_default_construct(data_ + base_.size(), data_ + n);
      } else {
#ifdef __cpp_lib_start_lifetime_as
        std::start_lifetime_as_array(data_ + base.size(), n);
#endif
      }
      base_ = std::span<T>{data_, n};
    } else {
      base_ = std::span<T>(base_.data(), n);
    }
  }

  value_type *data() const { return data_; }
  value_type &operator[](std::size_t n) { return data_[n]; }
  std::size_t size() const { return base_.size(); }
  value_type *begin() const { return data_; }
  value_type *end() const { return data_ + size(); }

  void clear() {
    base_ = std::span<T>{};
    data_ = nullptr;
  }

private:
  std::span<T> &base_;
  value_type *data_ = nullptr;
  MemoryResource &mr;
};
} // namespace detail

struct pb_serializer {
  template <typename Byte>
  struct basic_out {
    using byte_type = Byte;
    constexpr static bool endian_swapped = std::endian::little != std::endian::native;
    std::span<byte_type> m_data;

    inline constexpr void serialize(auto &&item) {
      using type = std::remove_cvref_t<decltype(item)>;
      if constexpr (concepts::byte_serializable<type>) {
        if (std::is_constant_evaluated()) {
          auto value = std::bit_cast<std::array<std::remove_const_t<byte_type>, sizeof(item)>>(item);
          if constexpr (endian_swapped) {
            std::copy(value.rbegin(), value.rend(), m_data.begin());
          } else {
            std::copy(value.begin(), value.end(), m_data.begin());
          }
        } else {
          if constexpr (endian_swapped && sizeof(type) != 1) {
            std::reverse_copy(reinterpret_cast<const byte_type *>(&item),
                              reinterpret_cast<const byte_type *>(&item) + sizeof(item), m_data.begin());
          } else {
            std::memcpy(m_data.data(), &item, sizeof(item));
          }
        }
        m_data = m_data.subspan(sizeof(item));
      } else if constexpr (std::is_enum_v<type>) {
        serialize(varint{static_cast<int64_t>(item)});
      } else if constexpr (concepts::varint<type>) {
        auto orig_value = item.value;
        auto value = std::make_unsigned_t<typename type::value_type>(orig_value);
        if constexpr (varint_encoding::zig_zag == type::encoding) {
          value = (value << 1) ^ (orig_value >> (sizeof(value) * CHAR_BIT - 1));
        }

        std::size_t position = 0;
        while (value >= 0x80) {
          m_data[position++] = byte_type((value & 0x7f) | 0x80);
          value >>= (CHAR_BIT - 1);
        }
        m_data[position++] = byte_type(value);
        m_data = m_data.subspan(position);
      } else if constexpr (concepts::contiguous_range<type> && concepts::byte_serializable<typename type::value_type>) {
        if constexpr (concepts::byte_serializable<typename type::value_type>) {
          if (!std::is_constant_evaluated() && (!endian_swapped || sizeof(typename type::value_type) == 1)) {
            auto bytes_to_copy = item.size() * sizeof(typename type::value_type);
            std::memcpy(m_data.data(), item.data(), bytes_to_copy);
            m_data = m_data.subspan(bytes_to_copy);
          } else {
            for (auto x : item) {
              this->serialize(x);
            }
          }
        }
      } else {
        static_assert(!sizeof(type));
      }
    }

    inline constexpr void operator()(auto &&...item) { (serialize(item), ...); }
  };
  constexpr static std::size_t len_size(std::size_t len) { return varint_size(len) + len; }

  template <typename Range, typename UnaryOperation>
  constexpr static std::size_t transform_accumulate(Range &&range, UnaryOperation &&unary_op) {
    return std::accumulate(range.begin(), range.end(), std::size_t{0},
                           [&unary_op](std::size_t acc, const auto &elem) constexpr { return acc + unary_op(elem); });
  }

  constexpr static std::size_t cache_count(concepts::has_meta auto &&item) {
    using type = std::remove_cvref_t<decltype(item)>;
    return std::apply([&item](auto &&...meta) constexpr { return (cache_count(meta, meta.access(item)) + ...); },
                      typename traits::meta_of<type>::type{});
  }

  template <typename Meta>
  constexpr static std::size_t cache_count(Meta meta, auto &&item) {
    using type = std::remove_cvref_t<decltype(item)>;

    if (meta.omit_value(item))
      return 0;

    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    if constexpr (concepts::oneof_type<type>) {
      return oneof_cache_count<0, typename Meta::alternatives_meta>(item);
    } else if constexpr (requires { *item; }) {
      return cache_count(meta, *item);
    } else if constexpr (concepts::has_meta<type>) {
      return cache_count(item) + (meta.encoding != encoding_rule::group);
    } else if constexpr (concepts::container<type>) {
      if (item.empty())
        return 0;
      if constexpr (Meta::encoding == encoding_rule::unpacked_repeated || Meta::encoding == encoding_rule::group) {
        return transform_accumulate(item, [](const auto &elem) constexpr { return cache_count(Meta{}, elem); });
      } else {
        using value_type = typename type::value_type;
        using element_type =
            std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::string_or_bytes<type>, value_type,
                               typename Meta::type>;

        if constexpr (std::is_enum_v<element_type> || concepts::varint<element_type>) {
          return 1;
        }
      }
    } else if constexpr (concepts::is_map_entry<serialize_type>) {
      using mapped_type = typename serialize_type::mapped_type;
      if constexpr (concepts::has_meta<mapped_type>) {
        return cache_count(item.second) + 1;
      } else {
        return 1;
      }
    }
    return 0;
  }

  template <std::size_t I, typename Meta>
  constexpr static std::size_t oneof_cache_count(auto &&item) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return cache_count(typename std::tuple_element<I, Meta>::type{},
                           std::get<I + 1>(std::forward<decltype(item)>(item)));
      }
      return oneof_cache_count<I + 1, Meta>(std::forward<decltype(item)>(item));
    }
    return 0;
  }

  constexpr static std::size_t message_size(concepts::has_meta auto &&item) {
    struct null_size_cache {
      struct null_assignable {
        constexpr void operator=(uint32_t) const {}
      };
      uint32_t storage = 0;
      constexpr null_assignable operator*() { return null_assignable{}; }
      constexpr null_size_cache operator++(int) { return *this; }
    } cache;
    return message_size(item, cache);
  }

  constexpr static std::size_t message_size(concepts::has_meta auto &&item, std::span<uint32_t> cache) {
    uint32_t *c = cache.data();
    return message_size(item, c);
  }

  template <concepts::is_size_cache T>
  constexpr static std::size_t message_size(concepts::has_meta auto &&item, T &cache) {
    using type = std::remove_cvref_t<decltype(item)>;
    return std::apply(
        [&item, &cache](auto &&...meta) constexpr { return (field_size(meta, meta.access(item), cache) + ...); },
        typename traits::meta_of<type>::type{});
  }

  template <typename Meta>
  constexpr static std::size_t field_size(Meta meta, auto &&item, concepts::is_size_cache auto &cache) {
    using type = std::remove_cvref_t<decltype(item)>;

    if (meta.omit_value(item))
      return 0;

    if constexpr (concepts::oneof_type<type>) {
      return oneof_size<0, typename Meta::alternatives_meta>(item, cache);
    } else if constexpr (concepts::pb_extension<type>) {
      return transform_accumulate(item.fields, [](const auto &e) constexpr { return e.second.size(); });
    } else {
      using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

      constexpr std::size_t tag_size = varint_size(meta.number << 3);
      if constexpr (std::is_enum_v<type> && !std::same_as<type, std::byte>) {
        return tag_size + varint_size(static_cast<int64_t>(std::underlying_type_t<type>(item)));
      } else if constexpr (concepts::byte_serializable<type>) {
        if constexpr (concepts::byte_serializable<serialize_type>) {
          return tag_size + sizeof(serialize_type);
        } else {
          static_assert(concepts::varint<serialize_type>);
          return tag_size + varint_size<serialize_type::encoding, typename serialize_type::value_type>(item);
        }
      } else if constexpr (concepts::varint<type>) {
        return tag_size + varint_size<type::encoding, typename type::value_type>(item.value);
      } else if constexpr (concepts::string_or_bytes<type>) {
        return tag_size + len_size(item.size());
      } else if constexpr (requires { *item; }) {
        return field_size(meta, *item, cache);
      } else if constexpr (concepts::has_meta<type>) {
        if constexpr (meta.encoding != encoding_rule::group) {
          decltype(auto) msg_size = *cache++;
          auto s = static_cast<uint32_t>(message_size(item, cache));
          msg_size = s;
          return tag_size + len_size(s);
        } else {
          return 2 * tag_size + message_size(item, cache);
        }
      } else if constexpr (concepts::container<type>) {
        if (item.empty())
          return 0;
        if constexpr (Meta::encoding == encoding_rule::unpacked_repeated || Meta::encoding == encoding_rule::group) {
          return transform_accumulate(item,
                                      [&cache](const auto &elem) constexpr { return field_size(Meta{}, elem, cache); });
        } else {
          using value_type = typename type::value_type;
          using element_type =
              std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::string_or_bytes<type>,
                                 value_type, typename Meta::type>;

          if constexpr (concepts::byte_serializable<element_type>) {
            return tag_size + len_size(item.size() * sizeof(value_type));
          } else {
            auto s = transform_accumulate(item, [](auto elem) constexpr {
              if constexpr (std::is_enum_v<element_type>) {
                return varint_size(static_cast<int64_t>(elem));
              } else {
                static_assert(concepts::varint<element_type>);
                return varint_size<element_type::encoding, typename element_type::value_type>(elem);
              }
            });
            decltype(auto) msg_size = *cache++;
            msg_size = static_cast<uint32_t>(s);
            return tag_size + len_size(s);
          }
        }
      } else if constexpr (concepts::is_map_entry<serialize_type>) {
        using value_type = typename serialize_type::read_only_type;
        auto &[key, value] = item;
        decltype(auto) msg_size = *cache++;
        auto s = message_size(value_type{key, value}, cache);
        msg_size = s;
        return tag_size + len_size(s);
      } else {
        static_assert(!sizeof(type));
        return 0;
      }
    }
  }

  template <std::size_t I, typename Meta>
  constexpr static std::size_t oneof_size(auto &&item, concepts::is_size_cache auto &cache) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return field_size(typename std::tuple_element<I, Meta>::type{},
                          std::get<I + 1>(std::forward<decltype(item)>(item)), cache);
      }
      return oneof_size<I + 1, Meta>(std::forward<decltype(item)>(item), cache);
    }
    return 0;
  }

  template <std::size_t MAX_CACHE_COUNT = 128, concepts::contiguous_byte_range Buffer>
  constexpr static std::errc serialize(concepts::has_meta auto &&item, Buffer &buffer) {
    std::size_t n = cache_count(item);

    auto do_serialize = [&item, &buffer](uint32_t *cache) constexpr {
      auto cache_end = cache;
      std::size_t sz = message_size(item, cache_end);
      if constexpr (requires { buffer.resize(1); }) {
        buffer.resize(sz);
      } else {
        if (sz < buffer.size()) {
          return std::errc::not_enough_memory;
        }
      }
      basic_out<typename std::remove_cvref_t<decltype(buffer)>::value_type> archive{buffer};
      serialize(item, cache, archive);
      if constexpr (requires { buffer.subspan(0, 1); }) {
        buffer = buffer.subspan(0, sz);
      }
      return std::errc{};
    };

    if (std::is_constant_evaluated() || n > MAX_CACHE_COUNT) {
      constexpr_vector<uint32_t> cache(n);
      return do_serialize(cache.data());
    } else {
#if defined(_MSC_VER)
      uint32_t *cache = static_cast<uint32_t *>(_alloca(n * sizeof(uint32_t)));
#elif defined(__GNUC__)
      uint32_t *cache =
          static_cast<uint32_t *>(__builtin_alloca_with_align(n * sizeof(uint32_t), CHAR_BIT * sizeof(uint32_t)));
#else
      uint32_t cache[MAX_CACHE_COUNT];
#endif
      return do_serialize(cache);
    }
  }

  constexpr static void serialize(concepts::has_meta auto &&item, uint32_t *&cache, auto &archive) {
    using type = std::remove_cvref_t<decltype(item)>;
    using metas = typename traits::meta_of<type>::type;
    return std::apply([&](auto... meta) { (serialize_field(meta, meta.access(item), cache, archive), ...); }, metas{});
  }

  template <typename Meta>
  constexpr static void serialize_field(Meta meta, auto &&item, uint32_t *&cache, auto &archive) {
    using type = std::remove_cvref_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    if (meta.omit_value(item)) {
      return;
    }

    if constexpr (concepts::oneof_type<type>) {
      return serialize_oneof<0, typename Meta::alternatives_meta>(std::forward<decltype(item)>(item), cache, archive);
    } else if constexpr (std::is_same_v<type, boolean>) {
      constexpr auto tag = make_tag<bool>(meta);
      out(tag, item.value);
    } else if constexpr (concepts::pb_extension<type>) {
      for (const auto &f : item.fields) {
        archive(f.second);
      }
    } else if constexpr (std::is_enum_v<type> && !std::same_as<type, std::byte>) {
      archive(make_tag<type>(meta), item);
    } else if constexpr (concepts::numeric<type>) {
      archive(make_tag<serialize_type>(meta), serialize_type{item});
    } else if constexpr (concepts::string_or_bytes<type>) {
      archive(make_tag<type>(meta), varint{item.size()}, item);
    } else if constexpr (requires { *item; }) {
      return serialize_field(meta, *item, cache, archive);
    } else if constexpr (concepts::has_meta<type>) {
      if constexpr (meta.encoding != encoding_rule::group) {
        archive(make_tag<type>(meta), varint{*cache++});
        serialize(std::forward<decltype(item)>(item), cache, archive);
      } else {
        archive(varint{(meta.number << 3) | std::underlying_type_t<wire_type>(wire_type::sgroup)});
        serialize(std::forward<decltype(item)>(item), cache, archive);
        archive(varint{(meta.number << 3) | std::underlying_type_t<wire_type>(wire_type::egroup)});
      }
    } else if constexpr (concepts::container<type>) {
      if (item.empty()) {
        return;
      }
      using value_type = typename type::value_type;
      using element_type =
          std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::string_or_bytes<type>, value_type,
                             typename Meta::type>;

      if constexpr (Meta::encoding == encoding_rule::group || Meta::encoding == encoding_rule::unpacked_repeated) {
        for (const auto &element : item) {
          if constexpr (std::same_as<element_type, std::remove_cvref_t<decltype(element)>> ||
                        concepts::is_map_entry<typename Meta::type>) {
            serialize_field(meta, element, cache, archive);
          } else {
            serialize_field(meta, static_cast<element_type>(element), cache, archive);
          }
        }
      } else if constexpr (requires {
                             requires std::is_arithmetic_v<element_type> ||
                                          std::same_as<typename type::value_type, std::byte>;
                           }) {
        // packed fundamental types or bytes
        archive(make_tag<type>(meta), varint{item.size() * sizeof(typename type::value_type)},
                std::forward<decltype(item)>(item));
      } else {
        // packed varint or packed enum
        archive(make_tag<type>(meta), varint{*cache++});
        for (auto element : item) {
          archive(element_type{element});
        }
      }
    } else if constexpr (concepts::is_map_entry<typename Meta::type>) {
      constexpr auto tag = make_tag<type>(meta);
      auto &&[key, value] = item;
      archive(tag, varint{*cache++});
      using value_type = typename traits::get_map_entry<Meta, type>::read_only_type;
      static_assert(concepts::has_meta<value_type>);
      serialize(value_type{key, value}, cache, archive);
    } else {
      static_assert(!sizeof(type));
    }
  }

  template <std::size_t I, concepts::tuple Meta>
  constexpr static void serialize_oneof(auto &&item, uint32_t *&cache, auto &archive) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return serialize_field(typename std::tuple_element<I, Meta>::type{},
                               std::get<I + 1>(std::forward<decltype(item)>(item)), cache, archive);
      }
      return serialize_oneof<I + 1, Meta>(std::forward<decltype(item)>(item), cache, archive);
    }
  }

  struct basic_in {
    constexpr static bool endian_swapped = std::endian::little != std::endian::native;
    std::span<const std::byte> m_data;
    constexpr basic_in(std::span<const std::byte> data) : m_data(data) {}

    constexpr std::errc deserialize(auto &&item) {
      using type = std::remove_cvref_t<decltype(item)>;
      if constexpr (concepts::byte_serializable<type>) {
        if (m_data.size() < sizeof(item)) [[unlikely]] {
          return std::errc::result_out_of_range;
        }
        if (std::is_constant_evaluated()) {
          std::array<std::remove_const_t<std::byte>, sizeof(item)> value;
          if constexpr (endian_swapped) {
            std::reverse_copy(m_data.begin(), m_data.begin() + sizeof(item), value.begin());
          } else {
            std::copy(m_data.begin(), m_data.begin() + sizeof(item), value.begin());
          }
          item = std::bit_cast<type>(value);
        } else {
          if constexpr (endian_swapped && sizeof(type) != 1) {
            std::reverse_copy(m_data.begin(), m_data.begin() + sizeof(item), std::bit_cast<const std::byte *>(&item));
          } else {
            std::memcpy(&item, m_data.data(), sizeof(item));
          }
        }
        m_data = m_data.subspan(sizeof(item));
      } else if constexpr (std::is_enum_v<type>) {
        deserialize(varint{static_cast<int64_t>(item)});
      } else if constexpr (concepts::varint<type>) {
        using value_type = typename type::value_type;

        auto commit = [&item, this](auto value, std::size_t byte_count) {
          if constexpr (varint_encoding::zig_zag == type::encoding) {
            item = ((value >> 1) ^ -(value & 0x1));
          } else {
            item = value;
          }

          m_data = m_data.subspan(byte_count);
          return std::errc{};
        };

        value_type value = 0;
        if (m_data.size() < varint_max_size<value_type>) [[unlikely]] {
          std::size_t shift = 0;
          for (auto &byte_value : m_data) {
            auto next_byte = value_type(byte_value);
            value |= (next_byte & 0x7f) << shift;
            if (next_byte >= 0x80) [[unlikely]] {
              shift += CHAR_BIT - 1;
              continue;
            }
            return commit(value, 1 + std::distance(m_data.data(), &byte_value));
            m_data = m_data.subspan(1 + std::distance(m_data.data(), &byte_value));
            return {};
          }
          return std::errc::result_out_of_range;
        } else {
          auto p = m_data.data();
          do {
            // clang-format off
                        value_type next_byte;
                        next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 0)); if (next_byte < 0x80) [[likely]] { break; }
                        next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 1)); if (next_byte < 0x80) [[likely]] { break; }
                        if constexpr (varint_max_size<value_type> > 2) {
                        next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 2)); if (next_byte < 0x80) [[likely]] { break; }
                        if constexpr (varint_max_size<value_type> > 3) {
                        next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 3)); if (next_byte < 0x80) [[likely]] { break; }
                        next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 4)); if (next_byte < 0x80) [[likely]] { break; }
                        if constexpr (varint_max_size<value_type> > 5) {
                        next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 5)); if (next_byte < 0x80) [[likely]] { break; }
                        next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 6)); if (next_byte < 0x80) [[likely]] { break; }
                        next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 7)); if (next_byte < 0x80) [[likely]] { break; }
                        next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 8)); if (next_byte < 0x80) [[likely]] { break; }
                        next_byte = value_type(*p++); value |= ((next_byte & 0x01) << ((CHAR_BIT - 1) * 9)); if (next_byte < 0x80) [[likely]] { break; } }}}
                        return std::errc::value_too_large;
            // clang-format on
          } while (false);

          return commit(value, std::distance(m_data.data(), p));
        }
      } else if constexpr (concepts::contiguous_range<type> && concepts::byte_serializable<typename type::value_type>) {
        if constexpr (concepts::byte_serializable<typename type::value_type>) {
          if (!std::is_constant_evaluated() && (!endian_swapped || sizeof(typename type::value_type) == 1)) {
            auto bytes_to_copy = item.size() * sizeof(typename type::value_type);
            std::memcpy(item.data(), m_data.data(), bytes_to_copy);
            m_data = m_data.subspan(bytes_to_copy);
          } else {
            for (auto &x : item) {
              this->deserialize(x);
            }
          }
        }
      } else {
        static_assert(!sizeof(type));
      }
      return {};
    }

    constexpr std::errc skip_length_delimited() {
      vuint64_t len;
      std::errc result = deserialize(len);
      return skip(len.value);
    }

    constexpr std::errc skip(std::size_t length) {
      if (m_data.size() < length) [[unlikely]] {
        return std::errc::result_out_of_range;
      }
      m_data = m_data.subspan(length);
      return {};
    }

    constexpr std::errc operator()(auto &&...item) {
      std::errc result;
      (void)(((result = deserialize(item)) == std::errc{}) && ...);
      return result;
    }
  };

  template <typename T>
  constexpr static auto make_growable(concepts::has_memory_resource auto &&context, std::span<T> &base) {
    return detail::growable_span<T, std::remove_cvref_t<decltype(context.memory_resource)>>{base,
                                                                                            context.memory_resource};
  }

  template <typename T>
  constexpr static T &make_growable(auto &&context, T &base) {
    return base;
  }

  constexpr static std::errc skip_field(uint32_t field_num, wire_type field_wire_type, concepts::has_extension auto &item, auto &context,
                       basic_in &archive) {
    auto tag = make_tag(field_num, field_wire_type);
    auto start_pos = archive.m_data.data() - varint_size<varint_encoding::normal>(tag.value);

    if (auto result = do_skip_field(field_num, field_wire_type, archive); result != std::errc{}) [[unlikely]] {
      return result;
    }

    const std::byte *data = std::bit_cast<const std::byte *>(archive.m_data.data());
    if constexpr (concepts::associative_container<std::remove_cvref_t<decltype(item.extensions.fields)>>) {
      auto &value = item.extensions.fields[field_num];
      value.insert(value.end(), start_pos, archive.m_data.data());
    } else {
      static_assert(concepts::span<std::remove_cvref_t<decltype(item.extensions.fields)>>);
      auto &fields = item.extensions.fields;

      auto old_size = fields.size();
      if (old_size > 0 && fields[old_size - 1].first == field_num) {
        auto &entry = fields[old_size - 1].second;
        if (entry.data() + entry.size() == start_pos) {
          entry = {entry.data(), archive.m_data.data()};
          return {};
        }
      }

      auto itr =
          std::find_if(fields.begin(), fields.end(), [field_num](const auto &e) { return e.first == field_num; });
      if (itr == fields.end()) [[likely]] {
        decltype(auto) growable_fields = make_growable(context, fields);
        growable_fields.resize(old_size + 1);
        growable_fields[old_size] = {field_num, {start_pos, archive.m_data.data()}};
      } else {
        decltype(auto) v = make_growable(context, itr->second);
        auto s = v.size();
        v.resize(v.size() + archive.m_data.data() - start_pos);
        std::copy(start_pos, archive.m_data.data(), v.data() + s);
      }
    }

    return {};
  }

  constexpr static std::errc skip_field(uint32_t field_num, wire_type field_wire_type, concepts::has_meta auto &,
                                        auto &context, basic_in &archive) {
    return do_skip_field(field_num, field_wire_type, archive);
  }

  constexpr static std::errc do_skip_field(uint32_t field_num, wire_type field_wire_type, basic_in &archive) {
    vuint64_t length = 0;
    switch (field_wire_type) {
    case wire_type::varint:
      return archive(length);
    case wire_type::length_delimited:
      return archive.skip_length_delimited();
    case wire_type::fixed_64:
      return archive.skip(8);
    case wire_type::sgroup:
      return do_skip_group(field_num, archive);
    case wire_type::fixed_32:
      return archive.skip(4);
    default:
      return std::errc::result_out_of_range;
    }
  }

  constexpr static std::errc do_skip_group(uint32_t field_num, basic_in &archive) {
    while (archive.m_data.size()) {
      vuint32_t tag;
      if (auto result = archive(tag); result != std::errc{}) [[unlikely]] {
        return result;
      }
      const uint32_t next_field_num = tag_number(tag);
      const wire_type next_type = proto::tag_type(tag);

      if (next_type == wire_type::egroup && field_num == next_field_num) {
        return {};
      } else {
        return do_skip_field(next_field_num, next_type, archive);
      }
    }
    return std::errc::result_out_of_range;
  }

  constexpr static std::errc skip_tag(uint32_t tag, basic_in &archive) {
    vuint32_t t;
    if (auto result = archive(t); result != std::errc{}) [[unlikely]] {
      return result;
    }
    if (t != tag) [[unlikely]] {
      return std::errc::result_out_of_range;
    }
    return {};
  }

  template <typename T>
  constexpr static std::size_t count_packed_elements(uint32_t length, basic_in &archive) {

    if constexpr (concepts::byte_serializable<T>) {
      return length / sizeof(T);
    } else if constexpr (std::is_enum_v<T> || concepts::varint<T>) {
      auto data = archive.m_data.subspan(0, length);
      return std::count_if(data.begin(), data.end(), [](auto c) { return (static_cast<char>(c) & 0x80) == 0; });
    } else {
      static_assert(!sizeof(T));
    }
  }

  constexpr static std::errc count_unpacked_elements(uint32_t number, wire_type field_type, std::size_t &count,
                                                     basic_in archive) {
    const vuint32_t input_tag = make_tag(number, field_type);
    vuint32_t tag;

    do {
      if (auto result = do_skip_field(number, field_type, archive); result != std::errc{}) {
        return result;
      }

      ++count;

      if (archive.m_data.empty()) {
        return {};
      }

      if (auto result = archive(tag); result != std::errc{}) [[unlikely]] {
        return result;
      }
    } while (tag == input_tag);
    return {};
  }

  template <typename Meta>
  constexpr static std::errc deserialize_packed_repeated(Meta, wire_type, uint32_t, auto &&item, auto &context,
                                                         basic_in &archive) {
    using type = std::remove_reference_t<decltype(item)>;
    using value_type = typename type::value_type;

    decltype(auto) growable = make_growable(context, item);
    using element_type =
        std::conditional_t<std::same_as<typename Meta::type, void> || std::same_as<value_type, char> ||
                               std::same_as<value_type, std::byte> || std::same_as<typename Meta::type, type>,
                           value_type, typename Meta::type>;

    vuint64_t length;
    if (auto result = archive(length); result != std::errc{}) [[unlikely]] {
      return result;
    }

    if constexpr (requires { growable.resize(1); }) {
      // packed repeated vector,
      std::size_t size = count_packed_elements<element_type>(length, archive);
      growable.resize(size);

      using serialize_type = std::conditional_t<std::is_enum_v<value_type> && !std::same_as<value_type, std::byte>,
                                                vint64_t, element_type>;

      if constexpr (concepts::byte_serializable<serialize_type>) {
        return archive(growable);
      } else {
        for (auto &value : growable) {
          serialize_type underlying;
          if (auto result = archive(underlying); result != std::errc{}) [[unlikely]] {
            return result;
          }
          value = static_cast<element_type>(underlying.value);
        }
        return {};
      }
    } else if constexpr (std::is_same_v<type, std::string_view>) {
      // handling string_view
      auto data = archive.m_data;
      if (data.size() < length) {
        return std::errc::result_out_of_range;
      }
      item = std::string_view((const char *)data.data(), length);
      archive.skip(length);
    } else if constexpr ((std::is_same_v<value_type, char> ||
                          std::is_same_v<value_type, std::byte>)&&std::is_same_v<type, std::span<const value_type>>) {
      // handling bytes
      auto data = archive.m_data;
      if (data.size() < length) {
        return std::errc::result_out_of_range;
      }
      item = std::span<const value_type>((const value_type *)data.data(), length);
      archive.skip(length);
    } else if constexpr (requires { item.insert(value_type{}); }) {
      // packed repeated set
      auto fetch = [&]() constexpr {
        element_type value;

        if constexpr (std::is_enum_v<element_type>) {
          vint64_t underlying;
          if (auto result = archive(underlying); result != std::errc{}) [[unlikely]] {
            return result;
          }
          value = static_cast<element_type>(underlying.value);
        } else {
          // varint
          if (auto result = archive(value); result != std::errc{}) [[unlikely]] {
            return result;
          }
        }
        item.insert(value_type(value));
        return std::errc{};
      };

      auto end_position = length + archive.m_data.data();
      while (archive.m_data.data() < end_position) {
        if (auto result = fetch(); result != std::errc{}) [[unlikely]] {
          return result;
        }
      }
    } else {
      static_assert(concepts::has_memory_resource<decltype(context)>, "memory resource is required");
    }
    return {};
  }

  template <typename Meta, typename Container>
  struct unpacked_element_inserter {

    template <typename MetaType>
    struct get_base_value_type {
      using type = typename Container::value_type;
    };

    template <concepts::is_map_entry MetaType>
    struct get_base_value_type<MetaType> {
      using type = typename Meta::type::mutable_type;
    };

    using base_value_type = typename get_base_value_type<typename Meta::type>::type;

    template <typename C>
    struct element_type {
      C &item;
      base_value_type value;
      constexpr element_type(C &item, std::size_t) : item(item) {}

      constexpr ~element_type() {
        if constexpr (concepts::is_map_entry<typename Meta::type>) {
          std::move(value).insert_to(item);
        } else if constexpr (requires { item.insert(value); }) {
          item.insert(std::move(value));
        } else {
          static_assert(!sizeof(base_value_type), "memory resource is required");
        }
      }
    };

    template <concepts::resizable C>
      requires std::same_as<std::remove_const_t<typename C::value_type>, base_value_type>
    struct element_type<C> {
      base_value_type &value;
      constexpr element_type(C &item, std::size_t i) : value(item[i]) {}
    };

    template <concepts::resizable C>
      requires(!std::same_as<std::remove_const_t<typename C::value_type>, base_value_type>)
    struct element_type<C> {
      std::remove_const_t<typename C::value_type> &target;
      base_value_type value;

      constexpr element_type(C &item, std::size_t i) : target(item[i]) {}
      constexpr ~element_type() {
        if constexpr (requires { std::move(value).to(target); }) {
          std::move(value).to(target);
        } else {
          target = std::move(value);
        }
      }
    };

    element_type<Container> element;

    constexpr unpacked_element_inserter(Container &item, std::size_t i = 0) : element(item, i) {}

    constexpr std::errc deserialize(wire_type field_type, uint32_t field_num, auto &context, basic_in &archive) {
      if constexpr (concepts::scalar<base_value_type>) {
        return pb_serializer::deserialize_field(Meta{}, field_type, field_num, element.value, context, archive);
      } else {
        return pb_serializer::deserialize_sized(element.value, context, archive);
      }
    }
  };

  constexpr static void resize_or_reserve(concepts::resizable_or_reservable auto &growable, std::size_t size) {
    if constexpr (requires { growable.resize(1); }) {
      growable.resize(size);
    } else if constexpr (requires { growable.reserve(size); }) { // e.g. boost::flat_map
      growable.reserve(size);
    } else { // e.g. std::flat_map
      reserve(growable, size);
    }
  }

  template <typename Meta>
  constexpr static std::errc deserialize_unpacked_repeated(Meta, wire_type field_type, uint32_t field_num, auto &&item,
                                                           auto &context, basic_in &archive) {
    using type = std::remove_reference_t<decltype(item)>;

    decltype(auto) growable = make_growable(context, item);

    if constexpr (concepts::resizable_or_reservable<decltype(growable)>) {
      std::size_t count = 0;
      if (auto result = count_unpacked_elements(field_num, field_type, count, archive); result != std::errc{})
          [[unlikely]] {
        return result;
      }
      auto old_size = item.size();
      const std::size_t new_size = item.size() + count;

      resize_or_reserve(growable, new_size);

      for (auto i = old_size; i < new_size; ++i) {
        unpacked_element_inserter<Meta, std::remove_cvref_t<decltype(growable)>> inserter(growable, i);
        if (auto result = inserter.deserialize(field_type, field_num, context, archive); result != std::errc{})
            [[unlikely]] {
          return result;
        }

        if (i < new_size - 1) {
          if (auto result = skip_tag((field_num << 3 | (uint32_t)field_type), archive); result != std::errc{})
              [[unlikely]] {
            return result;
          }
        }
      }
    } else {
      unpacked_element_inserter<Meta, type> inserter{item};
      return inserter.deserialize(field_type, field_num, context, archive);
    }
    return {};
  }

  template <typename Meta>
  constexpr static std::errc deserialize_field(Meta meta, wire_type field_type, uint32_t field_num, auto &&item,
                                               auto &context, basic_in &archive) {
    using type = std::remove_reference_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    if constexpr (std::is_enum_v<type>) {
      vint64_t value;
      if (auto result = archive(value); result != std::errc{}) [[unlikely]] {
        return result;
      }
      item = static_cast<type>(value.value);
    } else if constexpr (std::is_same_v<type, boolean>) {
      return archive(item.value);
    } else if constexpr (concepts::optional<type>) {
      if constexpr (requires { item.emplace(); }) {
        return deserialize_field(meta, field_type, field_num, item.emplace(), context, archive);
      } else {
        item = typename type::value_type{};
        return deserialize_field(meta, field_type, field_num, *item, context, archive);
      }
    } else if constexpr (concepts::unique_ptr<type>) {
      using element_type = std::remove_reference_t<decltype(*item)>;
      auto loaded = std::make_unique<element_type>();
      if (auto result = deserialize_field(meta, field_type, field_num, *loaded, context, archive);
          result != std::errc{}) [[unlikely]] {
        return result;
      }
      item.reset(loaded.release());
    } else if constexpr (std::is_pointer_v<type>) {
      static_assert(concepts::has_memory_resource<decltype(context)>, "memory resource is required");
      using element_type = std::remove_cvref_t<decltype(*item)>;
      void *buffer = context.memory_resource.allocate(sizeof(element_type), alignof(element_type));
      if (buffer == nullptr) [[unlikely]] {
        return std::errc::not_enough_memory;
      }
      auto loaded = new (buffer) element_type;
      if (auto result = deserialize_field(meta, field_type, field_num, *loaded, context, archive);
          result != std::errc{}) [[unlikely]] {
        return result;
      }
      item = loaded;
    } else if constexpr (concepts::oneof_type<type>) {
      static_assert(std::is_same_v<std::remove_cvref_t<decltype(std::get<0>(type{}))>, std::monostate>);
      return deserialize_oneof<0, typename Meta::alternatives_meta>(
          field_type, field_num, std::forward<decltype(item)>(item), context, archive);
    } else if constexpr (!std::is_same_v<type, serialize_type> && concepts::scalar<serialize_type> &&
                         !concepts::container<type>) {
      serialize_type value;
      if (auto result = deserialize_field(meta, field_type, field_num, value, context, archive); result != std::errc{})
          [[unlikely]] {
        return result;
      }
      if constexpr (std::is_arithmetic_v<type>) {
        item = static_cast<type>(value);
      } else {
        item = std::move(value);
      }
    } else if constexpr (concepts::numeric_or_byte<type>) {
      return archive(item);
    } else if constexpr (concepts::has_meta<type>) {
      if constexpr (meta.encoding != encoding_rule::group) {
        return deserialize_sized(item, context, archive);
      } else {
        return deserialize_group(field_num, item, context, archive);
      }
    } else if constexpr (meta.encoding == encoding_rule::group) {
      // repeated group
      if constexpr (requires { item.emplace_back(); }) {
        return deserialize_group(field_num, item.emplace_back(), context, archive);
      } else {
        decltype(auto) growable = make_growable(context, item);
        auto old_size = item.size();
        growable.resize(old_size + 1);
        return deserialize_group(field_num, growable[old_size], context, archive);
      }
    } else if constexpr (concepts::string_or_bytes<type>) {
      return deserialize_packed_repeated(meta, field_type, field_num, std::forward<type>(item), context, archive);
    } else { // repeated non-group
      using value_type = typename type::value_type;
      if constexpr (concepts::numeric<value_type> && meta.encoding != encoding_rule::unpacked_repeated) {
        if (field_type != wire_type::length_delimited) {
          return deserialize_unpacked_repeated(meta, field_type, field_num, std::forward<type>(item), context, archive);
        }
        return deserialize_packed_repeated(meta, field_type, field_num, std::forward<type>(item), context, archive);
      } else {
        return deserialize_unpacked_repeated(meta, field_type, field_num, std::forward<type>(item), context, archive);
      }
    }
    return {};
  }

  constexpr static std::errc deserialize_group(uint32_t field_num, auto &&item, auto &context, basic_in &archive) {

    while (!archive.m_data.empty()) {
      vuint32_t tag;
      if (auto result = archive(tag); result != std::errc{}) [[unlikely]] {
        return result;
      }

      if (proto::tag_type(tag) == wire_type::egroup && field_num == tag_number(tag)) {
        return {};
      }

      if (auto result = deserialize_field_by_num(tag_number(tag), proto::tag_type(tag), item, context, archive);
          result != std::errc{}) [[unlikely]] {
        return result;
      }
    }

    return std::errc::result_out_of_range;
  }

  template <std::size_t Index, concepts::tuple Meta>
  constexpr static std::errc deserialize_oneof(wire_type field_type, uint32_t field_num, auto &&item, auto &context,
                                               basic_in &archive) {
    if constexpr (Index < std::tuple_size_v<Meta>) {
      using meta = typename std::tuple_element<Index, Meta>::type;
      if (meta::number == field_num) {
        if constexpr (requires { item.template emplace<Index + 1>(); }) {
          return deserialize_field(meta{}, field_type, field_num, item.template emplace<Index + 1>(), context, archive);
        } else {
          item = std::variant_alternative_t<Index + 1, std::decay_t<decltype(item)>>{};
          return deserialize_field(meta{}, field_type, field_num, std::get<Index + 1>(item), context, archive);
        }
      } else {
        return deserialize_oneof<Index + 1, Meta>(field_type, field_num, std::forward<decltype(item)>(item), context,
                                                  archive);
      }
    }
    return {};
  }

  template <std::size_t Index>
  constexpr static std::errc deserialize_field_by_index(uint32_t field_num, wire_type field_wire_type, auto &item,
                                                        auto &context, basic_in &archive) {
    using type = std::remove_reference_t<decltype(item)>;
    using Meta = typename traits::field_meta_of<type, Index>::type;
    if constexpr (requires { requires Meta::number == UINT32_MAX; }) {
      // this is extension, not a regular field
      return {};
    } else {
      return deserialize_field(Meta(), field_wire_type, field_num, Meta::access(item), context, archive);
    }
  }

  template <typename Type, typename Context, std::size_t... I>
  constexpr static auto deserialize_funs(std::index_sequence<I...>) {
    using deserialize_fun_ptr = std::errc (*)(uint32_t, wire_type, Type &, Context &, basic_in &);
    return std::array<deserialize_fun_ptr, sizeof...(I)>{&deserialize_field_by_index<I>...};
  }

  template <typename Type, typename Context>
  constexpr static auto deserialize_funs() {
    constexpr std::size_t num_members = traits::number_of_members<Type>;
    return deserialize_funs<Type, Context>(std::make_index_sequence<num_members>());
  }

  constexpr static std::errc deserialize_field_by_num(uint32_t field_num, wire_type field_wire_type, auto &item,
                                                      auto &context, basic_in &archive) {
    using type = std::remove_cvref_t<decltype(item)>;
    using context_type = std::remove_cvref_t<decltype(context)>;
    constexpr auto fun_ptrs = deserialize_funs<type, context_type>();
    auto index = traits::reverse_indices<type>::number_to_index(field_num);
    if (index) {
      return (*fun_ptrs[*index])(field_num, field_wire_type, item, context, archive);
    } else [[unlikely]] {
      return skip_field(field_num, field_wire_type, item, context, archive);
    }
  }

  constexpr static std::errc deserialize(concepts::has_meta auto &item, auto &context, basic_in &archive) {

    while (!archive.m_data.empty()) {
      vuint32_t tag;
      if (auto result = archive(tag); result != std::errc{}) [[unlikely]] {
        return result;
      }

      if (auto result = deserialize_field_by_num(tag_number(tag), proto::tag_type(tag), item, context, archive);
          result != std::errc{}) {
        [[unlikely]] return result;
      }
    }

    return {};
  }

  constexpr static std::errc deserialize_sized(auto &&item, auto &context, basic_in &archive) {
    vint64_t len;
    if (auto result = archive(len); result != std::errc{}) [[unlikely]] {
      return result;
    }
    if (len <= archive.m_data.size()) [[likely]] {
      basic_in new_archive{archive.m_data.subspan(0, len)};
      archive.skip(len);
      return deserialize(item, context, new_archive);
    }
    return std::errc::result_out_of_range;
  }

  constexpr static std::errc deserialize(concepts::has_meta auto &item, concepts::contiguous_byte_range auto &&buffer) {
    std::monostate context;
    basic_in archive(buffer);
    return deserialize(item, context, archive);
  }
};

template <typename FieldType, typename MetaType>
struct serialize_wrapper_type {
  FieldType value;
  using pb_meta = std::tuple<MetaType>;
};

template <typename ExtensionMeta>
inline auto extension_meta_base<ExtensionMeta>::read(const concepts::pb_extension auto &extensions, auto &&mr) {
  check(extensions);
  decltype(extensions.fields.begin()) itr;

  if constexpr (requires { extensions.fields.find(ExtensionMeta::number); }) {
    itr = extensions.fields.find(ExtensionMeta::number);
  } else {
    itr = std::find_if(extensions.fields.begin(), extensions.fields.end(),
                       [](const auto &item) { return item.first == ExtensionMeta::number; });
  }

  using value_type = typename ExtensionMeta::get_result_type;
  using return_type = expected<value_type, std::error_code>;

  serialize_wrapper_type<value_type, ExtensionMeta> wrapper;
  if (itr != extensions.fields.end()) {
    std::errc ec;
    if constexpr (std::same_as<std::remove_cvref_t<decltype(mr)>, std::monostate>) {
      ec = pb_serializer::deserialize(wrapper, itr->second);
    } else {
      ec = pb_serializer::deserialize(wrapper, itr->second, std::forward<decltype(mr)>(mr));
    }

    if (ec != std::errc{}) [[unlikely]] {
      return return_type{unexpected(std::make_error_code(ec))};
    }
    return return_type{wrapper.value};
  }

  if constexpr (ExtensionMeta::has_default_value) {
    return return_type(value_type(ExtensionMeta::default_value));
  } else if constexpr (concepts::scalar<value_type>) {
    return return_type{value_type{}};
  } else {
    return return_type{unexpected(std::make_error_code(std::errc::no_message))};
  }
}

template <typename ExtensionMeta>
inline std::error_code extension_meta_base<ExtensionMeta>::write(concepts::pb_extension auto &extensions,
                                                                 auto &&value) {
  check(extensions);
  using extension_type = std::remove_cvref_t<decltype(extensions)>;
  using value_type = std::remove_cvref_t<decltype(value)>;

  serialize_wrapper_type<const value_type &, ExtensionMeta> wrapper(value);
  typename extension_type::mapped_type data;

  if (auto ec = pb_serializer::serialize(wrapper, data); ec != std::errc{}) [[unlikely]] {
    return std::make_error_code(ec);
  }
  extensions.fields[ExtensionMeta::number] = std::move(data);
  return {};
}

template <typename ExtensionMeta>
inline std::error_code extension_meta_base<ExtensionMeta>::write(concepts::pb_extension auto &extensions, auto &&value,
                                                                 concepts::memory_resource auto &mr) {
  check(extensions);

  std::span<std::byte> buf;
  using memory_resource_type = std::remove_cvref_t<decltype(mr)>;
  detail::growable_span<std::byte, memory_resource_type> data{buf, mr};

  using extension_type = std::remove_cvref_t<decltype(extensions)>;
  using value_type = std::remove_cvref_t<decltype(value)>;

  serialize_wrapper_type<const value_type &, ExtensionMeta> wrapper(value);

  if (auto ec = pb_serializer::serialize(wrapper, data); ec != std::errc{}) [[unlikely]] {
    return std::make_error_code(ec);
  }

  if (data.size()) {
    auto old_size = extensions.fields.size();
    detail::growable_span<typename decltype(extensions.fields)::value_type, memory_resource_type> growable_fields{
        extensions.fields, mr};
    growable_fields.resize(old_size + 1);
    extensions.fields[old_size] = {ExtensionMeta::number, {data.data(), data.size()}};
  }
  return {};
}

} // namespace hpp::proto

struct GoogleMessage1SubMessage {
  int32_t field1 = {};
  int32_t field2 = {};
  int32_t field3 = {};
  std::string field15 = {};
  bool field12 = {};
  int64_t field13 = {};
  int64_t field14 = {};
  int32_t field16 = {};
  int32_t field19 = {};
  bool field20 = {};
  bool field28 = {};
  uint64_t field21 = {};
  int32_t field22 = {};
  bool field23 = {};
  bool field206 = {};
  uint32_t field203 = {};
  int32_t field204 = {};
  std::string field205 = {};
  uint64_t field207 = {};
  uint64_t field300 = {};

  bool operator==(const GoogleMessage1SubMessage &) const = default;
};

auto pb_meta(const GoogleMessage1SubMessage &) -> std::tuple<
    hpp::proto::field_meta<1, &GoogleMessage1SubMessage::field1, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<2, &GoogleMessage1SubMessage::field2, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<3, &GoogleMessage1SubMessage::field3, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<15, &GoogleMessage1SubMessage::field15, hpp::proto::encoding_rule::defaulted>,
    hpp::proto::field_meta<12, &GoogleMessage1SubMessage::field12, hpp::proto::encoding_rule::defaulted, bool>,
    hpp::proto::field_meta<13, &GoogleMessage1SubMessage::field13, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<14, &GoogleMessage1SubMessage::field14, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<16, &GoogleMessage1SubMessage::field16, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<19, &GoogleMessage1SubMessage::field19, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<20, &GoogleMessage1SubMessage::field20, hpp::proto::encoding_rule::defaulted, bool>,
    hpp::proto::field_meta<28, &GoogleMessage1SubMessage::field28, hpp::proto::encoding_rule::defaulted, bool>,
    hpp::proto::field_meta<21, &GoogleMessage1SubMessage::field21, hpp::proto::encoding_rule::defaulted>,
    hpp::proto::field_meta<22, &GoogleMessage1SubMessage::field22, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<23, &GoogleMessage1SubMessage::field23, hpp::proto::encoding_rule::defaulted, bool>,
    hpp::proto::field_meta<206, &GoogleMessage1SubMessage::field206, hpp::proto::encoding_rule::defaulted, bool>,
    hpp::proto::field_meta<203, &GoogleMessage1SubMessage::field203, hpp::proto::encoding_rule::defaulted>,
    hpp::proto::field_meta<204, &GoogleMessage1SubMessage::field204, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<205, &GoogleMessage1SubMessage::field205, hpp::proto::encoding_rule::defaulted>,
    hpp::proto::field_meta<207, &GoogleMessage1SubMessage::field207, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vuint64_t>,
    hpp::proto::field_meta<300, &GoogleMessage1SubMessage::field300, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vuint64_t>>;

void expect_impl(bool predicate, const char *filename, int lineno) {
  if (!predicate) {
    std::cerr << "expectation failed: " << filename << '(' << lineno << ") `\n";
  }
}

#define expect(...) expect_impl(__VA_ARGS__, __FILE__, __LINE__)

// void verify_basic_out() {
//     using namespace hpp::proto;
//     {
//         std::array<std::byte, 4> data1;
//         basic_out<std::byte> out{data1};
//         out(1);
//         expect(out.m_data.empty());
//         expect("\x01\x00\x00\x00"_cts == data1);
//     }
//     {
//         std::array<std::byte, 2> data1;
//         basic_out<std::byte> out{data1};
//         out(varint{150});
//         expect(out.m_data.empty());
//         expect("\x96\x01"_cts == data1);
//     }
//     {
//         std::array<std::byte, 8> data1;
//         basic_out<std::byte> out{data1};
//         out(std::array{1, 2});
//         expect(out.m_data.empty());
//         expect("\x01\x00\x00\x00\x02\x00\x00\x00"_cts == data1);
//     }

//     constexpr std::string_view a = "abc"_cts;
//     constexpr std::span<const std::byte> b = "abc"_cts;
//     std::span<const std::byte> c = "abc"_cts;
// }
using namespace hpp::proto;

struct example {
  int32_t i; // field number == 1

  constexpr bool operator==(const example &) const = default;
};
auto pb_meta(const example &) -> std::tuple<hpp::proto::field_meta<1, &example::i, encoding_rule::defaulted, vint64_t>>;

struct nested_example {
  example nested; // field number == 1
  constexpr bool operator==(const nested_example &) const = default;
};
auto pb_meta(const nested_example &) -> std::tuple<hpp::proto::field_meta<1, &nested_example::nested>>;

struct example_default_type {
  int32_t i = 1; // field number == 1

  constexpr bool operator==(const example_default_type &) const = default;
};

auto pb_meta(const example_default_type &)
    -> std::tuple<hpp::proto::field_meta<1, &example_default_type::i, encoding_rule::defaulted, vint64_t, 1>>;

struct example_optional_type {
  hpp::proto::optional<int32_t, 1> i; // field number == 1

  constexpr bool operator==(const example_optional_type &) const = default;
};

auto pb_meta(const example_optional_type &)
    -> std::tuple<hpp::proto::field_meta<1, &example_optional_type::i, encoding_rule::explicit_presence, vint64_t>>;

struct repeated_enum {
  enum class NestedEnum { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
  std::vector<NestedEnum> values;
  bool operator==(const repeated_enum &) const = default;
};

auto pb_meta(const repeated_enum &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_enum::values, encoding_rule::packed_repeated>>;

struct repeated_enum_unpacked {
  enum class NestedEnum { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
  std::vector<NestedEnum> values;
  bool operator==(const repeated_enum_unpacked &) const = default;
};

auto pb_meta(const repeated_enum_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_enum_unpacked::values, encoding_rule::unpacked_repeated>>;

struct repeated_fixed {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed &) const = default;
};

auto pb_meta(const repeated_fixed &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_fixed::integers, encoding_rule::packed_repeated>>;

struct repeated_fixed_unpacked {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed_unpacked &) const = default;
};

auto pb_meta(const repeated_fixed_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_fixed_unpacked::integers, encoding_rule::unpacked_repeated>>;
struct repeated_integers {
  std::vector<int32_t> integers;
  bool operator==(const repeated_integers &) const = default;
};

auto pb_meta(const repeated_integers &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_integers::integers, encoding_rule::packed_repeated, vsint32_t>>;

struct repeated_integers_unpacked {
  std::vector<vsint32_t> integers;
  bool operator==(const repeated_integers_unpacked &) const = default;
};

auto pb_meta(const repeated_integers_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_integers_unpacked::integers, encoding_rule::unpacked_repeated>>;

struct repeated_bool {
  std::vector<hpp::proto::boolean> booleans;
  bool operator==(const repeated_bool &) const = default;
};

auto pb_meta(const repeated_bool &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_bool::booleans, encoding_rule::packed_repeated, bool>>;

struct repeated_bool_unpacked {
  std::vector<hpp::proto::boolean> booleans;
  bool operator==(const repeated_bool_unpacked &) const = default;
};

auto pb_meta(const repeated_bool_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_bool_unpacked::booleans, encoding_rule::unpacked_repeated, bool>>;

enum class color_t { red, blue, green };

struct map_example {
  std::map<int32_t, color_t> dict;
  bool operator==(const map_example &) const = default;
};

auto pb_meta(const map_example &)
    -> std::tuple<hpp::proto::field_meta<1, &map_example::dict, encoding_rule::unpacked_repeated,
                                         hpp::proto::map_entry<vint64_t, color_t>>>;

struct oneof_example {
  std::variant<std::monostate, std::string, int32_t, color_t> value;
  bool operator==(const oneof_example &) const = default;
};

auto pb_meta(const oneof_example &) -> std::tuple<
    hpp::proto::oneof_field_meta<&oneof_example::value, hpp::proto::field_meta<1, 1, encoding_rule::explicit_presence>,
                                 hpp::proto::field_meta<2, 2, encoding_rule::explicit_presence, vint64_t>,
                                 hpp::proto::field_meta<3, 3, encoding_rule::explicit_presence>>>;

struct recursive_type1 {
  hpp::proto::heap_based_optional<recursive_type1> child;
  uint32_t payload = {};

  bool operator==(const recursive_type1 &other) const = default;

#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARATOR
  friend auto operator<=>(const recursive_type1 &, const recursive_type1 &) = default;
#endif
};

auto pb_meta(const recursive_type1 &)
    -> std::tuple<hpp::proto::field_meta<1, &recursive_type1::child>,
                  hpp::proto::field_meta<2, &recursive_type1::payload, encoding_rule::defaulted, vint64_t>>;

struct group {
  uint32_t a;
  bool operator==(const group &) const = default;
};

auto pb_meta(const group &) -> std::tuple<hpp::proto::field_meta<2, &group::a, encoding_rule::defaulted, vint64_t>>;

struct repeated_group {
  std::vector<group> repeatedgroup;
  bool operator==(const repeated_group &) const = default;
};

auto pb_meta(const repeated_group &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_group::repeatedgroup, encoding_rule::group>>;

struct string_example {
  std::string value;
  bool operator==(const string_example &) const = default;
};

auto pb_meta(const string_example &)
    -> std::tuple<hpp::proto::field_meta<1, &string_example::value, encoding_rule::defaulted>>;

struct string_with_default {
  std::string value = "test";
  bool operator==(const string_with_default &) const = default;
};
auto pb_meta(const string_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, &string_with_default::value, encoding_rule::defaulted, void, "test"_cts>>;

struct string_with_optional {
  hpp::proto::optional<std::string, "test"_cts> value;
  bool operator==(const string_with_optional &) const = default;
};
auto pb_meta(const string_with_optional &)
    -> std::tuple<hpp::proto::field_meta<1, &string_with_optional::value, encoding_rule::explicit_presence>>;

struct repeated_examples {
  std::vector<example> examples;
  bool operator==(const repeated_examples &) const = default;
};

auto pb_meta(const repeated_examples &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_examples::examples, encoding_rule::unpacked_repeated>>;

struct extension_example {
  int32_t int_value = {};
  struct extension_t {
    using pb_extension = extension_example;
    std::map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) { return meta.read(extensions, std::monostate{}); }

  template <typename Meta>
  [[nodiscard]] std::error_code set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }

  template <typename Meta>
    requires Meta::is_repeated
  [[nodiscard]] std::error_code set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
  }

  [[nodiscard]] bool has_extension(auto meta) const { return meta.element_of(extensions); }

  bool operator==(const extension_example &other) const = default;
};

auto pb_meta(const extension_example &) -> std::tuple<
    hpp::proto::field_meta<1, &extension_example::int_value, encoding_rule::defaulted, hpp::proto::vint64_t>,
    hpp::proto::field_meta<UINT32_MAX, &extension_example::extensions>>;

constexpr auto i32_ext() {
  return hpp::proto::extension_meta<extension_example, 10, encoding_rule::explicit_presence, hpp::proto::vint64_t,
                                    int32_t>{};
}

constexpr auto string_ext() {
  return hpp::proto::extension_meta<extension_example, 11, encoding_rule::explicit_presence, std::string,
                                    std::string>{};
}

constexpr auto i32_defaulted_ext() {
  return hpp::proto::extension_meta<extension_example, 13, encoding_rule::defaulted, hpp::proto::vint64_t, int32_t,
                                    hpp::proto::vint64_t{10}>{};
}

constexpr auto i32_unset_ext() {
  return hpp::proto::extension_meta<extension_example, 14, encoding_rule::explicit_presence, hpp::proto::vint64_t,
                                    int32_t>{};
}

constexpr auto example_ext() {
  return hpp::proto::extension_meta<extension_example, 15, encoding_rule::explicit_presence, example, example>{};
}

constexpr auto repeated_i32_ext() {
  return hpp::proto::repeated_extension_meta<extension_example, 20, encoding_rule::unpacked_repeated,
                                             hpp::proto::vint64_t, int32_t>{};
}

constexpr auto repeated_string_ext() {
  return hpp::proto::repeated_extension_meta<extension_example, 21, encoding_rule::unpacked_repeated, void,
                                             std::string>{};
}

constexpr auto repeated_packed_i32_ext() {
  return hpp::proto::repeated_extension_meta<extension_example, 22, encoding_rule::defaulted, hpp::proto::vint64_t,
                                             int32_t>{};
}

template <typename T>
std::string to_hex(const T &data) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string result;
  result.resize(data.size() * 2);
  int index = 0;
  for (auto b : data) {
    unsigned char c = static_cast<unsigned char>(b);
    result[index++] = qmap[c >> 4];
    result[index++] = qmap[c & '\x0F'];
  }
  return result;
}

consteval auto to_pb_bytes(auto ObjectLambda) {
  constexpr auto sz = hpp::proto::pb_serializer::message_size(ObjectLambda());
  if constexpr (sz == 0) {
    return std::span<std::byte>{};
  } else {
    std::array<std::byte, sz> buffer;
    hpp::proto::pb_serializer::serialize(ObjectLambda(), buffer);
    return buffer;
  }
}

template <typename T>
constexpr auto from_pb_bytes(auto &&buffer) {
  T obj;
  auto ec = pb_serializer::deserialize(obj, buffer);
  if (ec != std::errc{})
    throw std::system_error(std::make_error_code(ec));
  return obj;
}

#define carg(...) ([]() constexpr -> decltype(auto) { return __VA_ARGS__; })

void verify_basic_in() {
  using namespace hpp::proto;

  auto verify = [](auto expected_value, std::span<const std::byte> data) {
    pb_serializer::basic_in in{data};
    decltype(expected_value) value;
    expect(in(value) == std::errc{});
    if constexpr (requires { expected_value.size(); }) {
      expect(std::ranges::equal(value, expected_value));
    } else {
      expect(value == expected_value);
    }
    expect(in.m_data.empty());
  };

  verify(1, "\x01\x00\x00\x00"_cts);
  verify(varint{150}, "\x96\x01"_cts);
  verify(std::array{1, 2}, "\x01\x00\x00\x00\x02\x00\x00\x00"_cts);
}

constexpr void constexpr_verify(auto buffer, auto object_fun) {
  static_assert(std::ranges::equal(buffer(), to_pb_bytes(object_fun)));
  static_assert(object_fun() == from_pb_bytes<decltype(object_fun())>(buffer()));
}

int main() {
  verify_basic_in();

  GoogleMessage1SubMessage msg;
  msg.field1 = 1;
  msg.field15 = "abc";
  msg.field206 = true;

  hpp::proto::pb_serializer ser;
  expect(ser.message_size(msg) == 10);

  constexpr_verify(carg("\x08\x96\x01"_bytes_view), carg(example{150}));
  static_assert(to_pb_bytes(carg(example{})).empty());

  constexpr_verify(carg("\x0a\x03\x08\x96\x01"_bytes_view), carg(nested_example{.nested = example{150}}));

  static_assert(to_pb_bytes(carg(example_default_type{})).empty());

#if defined(__cpp_lib_constexpr_vector) && (__cpp_lib_constexpr_vector >= 201907L)
  {
    using enum repeated_enum::NestedEnum;
    constexpr_verify(carg("\x0a\x0d\x01\x02\x03\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_view),
                     carg(repeated_enum{{FOO, BAR, BAZ, NEG}}));
  }
  {
    using enum repeated_enum_unpacked::NestedEnum;
    constexpr_verify(carg("\x08\x01\x08\x02\x08\x03\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_view),
                     carg(repeated_enum_unpacked{{FOO, BAR, BAZ, NEG}}));
  }

  constexpr_verify(
      carg(
          "\x0a\x18\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_view),
      carg(repeated_fixed{{1, 2, 3}}));

  constexpr_verify(
      carg(
          "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_view),
      carg(repeated_fixed_unpacked{{1, 2, 3}}));

  constexpr_verify(carg("\x0a\x09\x00\x02\x04\x06\x08\x01\x03\x05\x07"_bytes_view),
                   carg(repeated_integers{{0, 1, 2, 3, 4, -1, -2, -3, -4}}));

  constexpr_verify(carg("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x00\x08\x01\x08\x03\x08\x05\x08\x07"_bytes_view),
                   carg(repeated_integers_unpacked{{1, 2, 3, 4, 0, -1, -2, -3, -4}}));

  constexpr_verify(carg("\x0a\x03\x01\x00\x01"_bytes_view), carg(repeated_bool{{true, false, true}}));

  constexpr_verify(carg("\x08\x01\x08\x00\x08\x01"_bytes_view), carg(repeated_bool_unpacked{{true, false, true}}));

  constexpr_verify(carg("\x0b\x10\x01\x0c\x0b\x10\x02\x0c"_bytes_view),
                   carg(repeated_group{.repeatedgroup = {{1}, {2}}}));

  constexpr_verify(carg("\x0a\x02\x08\x01\x0a\x02\x08\x02\x0a\x02\x08\x03\x0a\x02\x08\x04"
                        "\x0a\x0b\x08\xff\xff\xff\xff\xff\xff"
                        "\xff\xff\xff\x01\x0a\x0b\x08\xfe\xff\xff\xff\xff\xff\xff\xff\xff"
                        "\x01\x0a\x0b\x08\xfd\xff\xff\xff\xff"
                        "\xff\xff\xff\xff\x01\x0a\x0b\x08\xfc\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_view),
                   carg(repeated_examples{.examples = {{1}, {2}, {3}, {4}, {-1}, {-2}, {-3}, {-4}}}));
#endif
#if defined(__cpp_lib_constexpr_string) && (__cpp_lib_constexpr_string >= 201907L)

  constexpr_verify(carg(""_bytes_view), carg(string_example{}));
#if defined(__cpp_lib_variant) && (__cpp_lib_variant >= 202106L)
  constexpr_verify(carg("\x0a\x04\x74\x65\x73\x74"_bytes_view), carg(string_with_optional{.value = "test"}));

  constexpr_verify(carg(""_bytes_view), carg(oneof_example{}));

  constexpr_verify(carg("\x0a\x04\x74\x65\x73\x74"_bytes_view), carg(oneof_example{.value = "test"}));
  constexpr_verify(carg("\x10\x05"_bytes_view), carg(oneof_example{.value = 5}));
  constexpr_verify(carg("\x10\x00"_bytes_view), carg(oneof_example{.value = 0}));
  constexpr_verify(carg("\x18\x02"_bytes_view), carg(oneof_example{.value = color_t::green}));
#endif
#endif
  {
    recursive_type1 child;
    child.payload = 2;
    recursive_type1 value, value2;
    value.child = child;
    value.payload = 1;

    std::vector<std::byte> data;
    ser.serialize(value, data);

    expect("\x0a\x02\x10\x02\x10\x01"_cts == data);

    expect(pb_serializer::deserialize(value2, "\x0a\x02\x10\x02\x10\x01"_bytes_view) == std::errc{});
    expect(value == value2);
  }

  {
    std::vector<std::byte> data;
    map_example value{{{1, color_t::red}, {2, color_t::blue}, {3, color_t::green}}};
    const auto encoded = "\x0a\x04\x08\x01\x10\x00\x0a\x04\x08\x02\x10\x01\x0a\x04\x08\x03\x10\x02"_bytes_view;

    ser.serialize(value, data);
    expect(std::ranges::equal(encoded, data));

    map_example value2;
    expect(pb_serializer::deserialize(value2, encoded) == std::errc{});
    expect(value == value2);
  }
  {

    auto encoded_data =
        "\x08\x96\x01\x50\x01\x5a\x04\x74\x65\x73\x74\x7a\x03\x08\x96\x01\xa0\x01\x01\xa0\x01\x02\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66\xb2\x01\x03\01\02\03"_bytes_view;
    const extension_example expected_value{
        .int_value = 150,
        .extensions = {.fields = {{10U, "\x50\x01"_bytes},
                                  {11U, "\x5a\x04\x74\x65\x73\x74"_bytes},
                                  {15U, "\x7a\x03\x08\x96\x01"_bytes},
                                  {20U, "\xa0\x01\x01\xa0\x01\x02"_bytes},
                                  {21U, "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes},
                                  {22U, "\xb2\x01\x03\01\02\03"_bytes}}}};
    extension_example value;
    expect((hpp::proto::pb_serializer::deserialize(value, encoded_data) == std::errc{}));
    expect(value == expected_value);

    expect(value.has_extension(i32_ext()));
    expect(value.has_extension(string_ext()));
    expect(!value.has_extension(i32_defaulted_ext()));
    expect(!value.has_extension(i32_unset_ext()));
    expect(value.has_extension(example_ext()));

    {
      auto v = value.get_extension(i32_ext());
      expect(v.has_value());
      expect(v.value() == 1);
    }
    {
      auto v = value.get_extension(string_ext());
      expect(v.has_value());
      expect(v.value() == "test");
    }
    {
      auto v = value.get_extension(example_ext());
      expect(v.has_value());
      expect(v.value() == example{.i = 150});
    }
    {
      auto v = value.get_extension(repeated_i32_ext());
      expect(v.has_value());
      expect(v.value() == std::vector<int32_t>{1, 2});
    }
    {
      auto v = value.get_extension(repeated_string_ext());
      expect(v.has_value());
      expect(v == std::vector<std::string>{"abc", "def"});
    }
    {
      auto v = value.get_extension(repeated_packed_i32_ext());
      expect(v.has_value());
      expect(v == std::vector<int32_t>{1, 2, 3});
    }

    std::vector<std::byte> new_data;
    expect((hpp::proto::pb_serializer::serialize(value, new_data) == std::errc{}));

    expect(std::ranges::equal(encoded_data, new_data));
  }
}