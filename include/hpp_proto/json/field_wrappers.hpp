// MIT License
//
// Copyright (c) 2024 Huang-Ming Huang
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once
#include <cstddef>
#include <tuple>

#include <hpp_proto/memory_resource_utils.hpp>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"
#endif
#include <glaze/glaze.hpp>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

namespace hpp::proto {

template <typename T, std::size_t Index>
struct oneof_wrapper {
  static constexpr auto glaze_reflect = false;
  T *value;
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  operator bool() const { return value->index() == Index; }
  auto &operator*() const { return std::get<Index>(*value); }
};

template <std::size_t Index, typename T>
constexpr oneof_wrapper<T, Index> wrap_oneof(T &v) {
  return oneof_wrapper<T, Index>{&v};
}

template <typename T>
struct map_wrapper {
  static constexpr auto glaze_reflect = false;
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  T &value;
};

namespace concepts {
template <typename T>
concept integral_64_bits = std::same_as<std::decay_t<T>, uint64_t> || std::same_as<std::decay_t<T>, int64_t>;

template <typename T>
concept is_map = std::ranges::range<T> && glz::pair_t<std::ranges::range_value_t<T>>;

template <typename T>
concept map_with_integral_64_bits_mapped_type = is_map<T> && integral_64_bits<typename T::value_type::second_type>;

template <typename T>
concept jsonfy_need_quote =
    integral_64_bits<std::decay_t<T>> || map_with_integral_64_bits_mapped_type<std::decay_t<T>> || requires(T val) {
      val.size();
      requires integral_64_bits<typename T::value_type>;
    };

template <typename T>
concept is_non_owning_context = glz::is_context<T> && requires(T &v) {
  { v.memory_resource() } -> concepts::memory_resource;
};

} // namespace concepts

// NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members,hicpp-explicit-conversions,modernize-use-nodiscard)
template <typename T, auto Default = std::monostate{}>
struct optional_ref {
  static constexpr auto glaze_reflect = false;
  static constexpr bool has_default_value = true;
  using value_type = std::decay_t<T>;
  T &val;
  operator bool() const { return !is_default_value<T, Default>(val); }
  template <typename U>
  static U &deref(U &v) {
    // NOLINTNEXTLINE(bugprone-return-const-ref-from-parameter)
    return v;
  }

  template <concepts::jsonfy_need_quote U>
  static glz::opts_wrapper_t<U, &glz::opts::quoted_num> deref(U &v) {
    return glz::opts_wrapper_t<U, &glz::opts::quoted_num>{v};
  }

  auto operator*() const -> decltype(deref(val)) { return deref(val); }

  void reset() {
    if constexpr (std::same_as<std::remove_cvref_t<decltype(Default)>, std::monostate>) {
      if constexpr (requires { val.clear(); }) {
        val.clear();
      } else {
        val = T{};
      }
    } else {
      val = static_cast<T>(Default);
    }
  }

  constexpr optional_ref &operator=(glz::empty) { return *this; }

  struct glaze {
    static constexpr auto construct = [] { return glz::empty{}; };
  };
};

template <auto Default>
struct optional_ref<hpp::proto::optional<bool, Default>, std::monostate{}> {
  static constexpr auto glaze_reflect = false;
  hpp::proto::optional<bool, Default> &val;
  operator bool() const { return val.has_value(); }

  bool &emplace() const { return val.emplace(); }
  bool operator*() const { return *val; }
};

template <auto Default>
struct optional_ref<const hpp::proto::optional<bool, Default>, std::monostate{}> {
  static constexpr auto glaze_reflect = false;
  const hpp::proto::optional<bool, Default> &val;
  operator bool() const { return val.has_value(); }
  bool operator*() const { return *val; }
};
// NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members,hicpp-explicit-conversions,modernize-use-nodiscard)

template <auto MemPtr, auto Default>
constexpr decltype(auto) as_optional_ref_impl() noexcept {
  return [](auto &&val) { return optional_ref<std::remove_reference_t<decltype(val.*MemPtr)>, Default>{val.*MemPtr}; };
}

template <auto MemPtr, auto Default = std::monostate{}>
constexpr auto as_optional_ref = as_optional_ref_impl<MemPtr, Default>();

template <auto MemPtr, int Index>
constexpr decltype(auto) as_oneof_member_impl() noexcept {
  return [](auto &&val) -> auto { return wrap_oneof<Index>(val.*MemPtr); };
}

template <auto MemPtr, int Index>
constexpr auto as_oneof_member = as_oneof_member_impl<MemPtr, Index>();

template <typename T>
struct optional_message_view_ref {
  static constexpr auto glaze_reflect = false;
  T &ref; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
  void set_null() { ref.reset(); }
};

template <auto MemPtr>
constexpr decltype(auto) as_optional_message_view_ref_impl() noexcept {
  return
      [](auto &&val) { return optional_message_view_ref<std::remove_reference_t<decltype(val.*MemPtr)>>{val.*MemPtr}; };
}

template <auto MemPtr>
constexpr auto as_optional_message_view_ref = as_optional_message_view_ref_impl<MemPtr>();

} // namespace hpp::proto