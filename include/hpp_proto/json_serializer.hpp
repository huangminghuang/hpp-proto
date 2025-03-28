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
#include <bit>
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"
#endif
#include <glaze/glaze.hpp>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include <hpp_proto/memory_resource_utils.hpp>

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
concept map_with_integral_64_bits_mapped_type =
    glz::writable_map_t<T> && integral_64_bits<typename T::value_type::second_type>;

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
template <typename... AuxContext>
struct json_context : glz::context, pb_context<AuxContext...> {
  const char *error_message_name = nullptr;
  template <typename... U>
  explicit json_context(U &&...ctx) : pb_context<AuxContext...>(std::forward<U>(ctx)...) {}
};

template <typename... U>
json_context(U &&...u) -> json_context<std::remove_cvref_t<U>...>;

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
    if constexpr (std::is_same_v<std::remove_cvref_t<decltype(Default)>, std::monostate>) {
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
};

template <auto MemPtr>
constexpr decltype(auto) as_optional_message_view_ref_impl() noexcept {
  return
      [](auto &&val) { return optional_message_view_ref<std::remove_reference_t<decltype(val.*MemPtr)>>{val.*MemPtr}; };
}

template <auto MemPtr>
constexpr auto as_optional_message_view_ref = as_optional_message_view_ref_impl<MemPtr>();

struct base64 {
  constexpr static std::size_t
  max_encode_size(hpp::proto::concepts::contiguous_byte_range auto const &source) noexcept {
    std::size_t n = source.size();
    return (n / 3 + (n % 3 > 0 ? 1 : 0)) * 4;
  }

  // @returns The number bytes written to b, -1 for error
  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-not-moved)
  constexpr static int64_t encode(hpp::proto::concepts::contiguous_byte_range auto const &source, auto &&b) noexcept {
    const auto n = source.size();
    using V = std::decay_t<decltype(b[0])>;
    constexpr char const base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                          "abcdefghijklmnopqrstuvwxyz"
                                          "0123456789+/";

    std::size_t i = 0;
    std::size_t ix = 0;

    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
    if (n >= 3) {
      for (i = 0; i <= n - 3; i += 3) {
        uint32_t x = 0;

        std::memcpy(&x, &source[i], 3);

        if constexpr (std::endian::native == std::endian::little) {
          b[ix++] = static_cast<V>(base64_chars[(x >> 2U) & 0x3FU]);
          b[ix++] = static_cast<V>(base64_chars[((x << 4U) & 0x30U) | ((x >> 12U) & 0x0FU)]);
          b[ix++] = static_cast<V>(base64_chars[((x >> 6U) & 0x3CU) | (x >> 22U)]);
          b[ix++] = static_cast<V>(base64_chars[(x >> 16U) & 0x3FU]);
        } else {
          x >>= 8U;
          b[ix + 3] = static_cast<V>(base64_chars[x & 0x3FU]);
          x >>= 6U;
          b[ix + 2] = static_cast<V>(base64_chars[x & 0x3FU]);
          x >>= 6U;
          b[ix + 1] = static_cast<V>(base64_chars[x & 0x3FU]);
          x >>= 6U;
          b[ix] = static_cast<V>(base64_chars[x & 0x3FU]);
          ix += 4;
        }
      }
    }

    if (i != n) {
      b[ix++] = static_cast<V>(base64_chars[((static_cast<unsigned>(source[i]) >> 2U) & 0x3FU)]);
      unsigned const next = (i + 1 < n) ? static_cast<unsigned>(source[i + 1]) : 0U;
      b[ix++] = static_cast<V>(base64_chars[(static_cast<unsigned>(source[i]) << 4U & 0x3FU) | ((next >> 4U) & 0x0FU)]);
      if (i + 1 < n) {
        b[ix++] = static_cast<V>(base64_chars[(next << 2U & 0x3FU)]);
      } else {
        b[ix++] = static_cast<V>('=');
      }
      b[ix++] = static_cast<V>('=');
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
    return static_cast<int64_t>(ix);
  }

  constexpr static bool decode(hpp::proto::concepts::contiguous_byte_range auto const &source, auto &value) {
    std::size_t n = source.size();
    if (n == 0) {
      value.resize(0);
      return true;
    }

    if (n % 4 != 0) {
      return false;
    }

    size_t len = n / 4 * 3;
    if (static_cast<char>(source[n - 1]) == '=') {
      len--;
    }
    if (static_cast<char>(source[n - 2]) == '=') {
      len--;
    }
    value.resize(len);
    constexpr unsigned char decode_table[] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
        13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32,
        33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};
    auto start = source.begin();

    size_t j = 0;
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
    while (start != source.end()) {
      uint32_t const a = decode_table[static_cast<uint8_t>(*start++)];
      uint32_t const b = decode_table[static_cast<uint8_t>(*start++)];
      uint32_t const c = decode_table[static_cast<uint8_t>(*start++)];
      uint32_t const d = decode_table[static_cast<uint8_t>(*start++)];
      uint32_t const triple = (a << 3U * 6) + (b << 2U * 6) + (c << 1U * 6) + (d << 0U * 6);

      using byte = std::ranges::range_value_t<decltype(value)>;

      value[j++] = static_cast<byte>((triple >> 2U * 8) & 0xFFU);
      if (j < value.size()) {
        value[j++] = static_cast<byte>((triple >> 1U * 8) & 0xFFU);
      }
      if (j < value.size()) {
        value[j++] = static_cast<byte>((triple >> 0U * 8) & 0xFFU);
      }
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
    return true;
  }
};

template <typename T>
struct json_codec;

namespace concepts {
template <typename T>
concept has_codec = requires { typename json_codec<T>::type; };
} // namespace concepts
struct use_base64 {
  constexpr static bool glaze_reflect = false;
};

template <>
struct json_codec<use_base64> {
  using type = base64;
};

} // namespace hpp::proto

namespace glz {

using base64 = hpp::proto::base64;

template <hpp::proto::concepts::has_codec T>
struct to<JSON, T> {
  template <auto Opts, class B>
  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  GLZ_ALWAYS_INLINE static void op(auto const &value, is_context auto &ctx, B &b, auto &ix) noexcept {
    using codec = typename hpp::proto::json_codec<T>::type;
    if constexpr (resizable<B>) {
      std::size_t const encoded_size = codec::max_encode_size(value);
      if ((ix + 2 + encoded_size) >= b.size()) {
        b.resize(std::max(b.size() * 2, ix + 2 + encoded_size));
      }
    }

    dump<'"', false>(b, ix);
    auto bytes_written = codec::encode(value, std::span{b}.subspan(ix));
    if (bytes_written < 0) {
      ctx.error = glz::error_code::syntax_error;
      if constexpr (requires {
                      hpp::proto::message_name(value);
                      ctx.error_message_name;
                    }) {
        ctx.error_message_name = hpp::proto::message_name(value);
      }
      return;
    }
    ix += static_cast<std::size_t>(bytes_written);
    dump<'"', false>(b, ix);
  }
};

template <>
struct to<JSON, hpp::proto::bytes_view> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto &&...args) noexcept {
    to<JSON, hpp::proto::use_base64>::template op<Opts>(std::forward<decltype(args)>(args)...);
  }
};

template <>
struct to<JSON, hpp::proto::bytes> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto &&...args) noexcept {
    to<JSON, hpp::proto::use_base64>::template op<Opts>(std::forward<decltype(args)>(args)...);
  }
};

template <hpp::proto::concepts::has_codec T>
struct from<JSON, T> {
  template <auto Opts, class It, class End>
  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  GLZ_ALWAYS_INLINE static void op(auto &value, is_context auto &ctx, It &it, End &end) {
    std::string_view encoded;
    from<JSON, std::string_view>::op<Opts>(encoded, ctx, it, end);
    if (static_cast<bool>(ctx.error)) [[unlikely]] {
      return;
    }

    using codec = typename hpp::proto::json_codec<T>::type;
    if (!codec::decode(encoded, hpp::proto::detail::as_modifiable(ctx, value))) {
      ctx.error = error_code::syntax_error;
      return;
    }
  }
};

template <>
struct from<JSON, hpp::proto::bytes> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto &&...args) {
    from<JSON, hpp::proto::use_base64>::template op<Opts>(std::forward<decltype(args)>(args)...);
  }
};

template <typename Type, auto Default>
struct to<JSON, hpp::proto::optional<Type, Default>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto const &value, Args &&...args) noexcept {
    if (value.has_value()) {
      if constexpr (std::is_integral_v<Type> && sizeof(Type) > 4) {
        to<JSON, glz::quoted_t<const Type>>::template op<Opts>(glz::quoted_t<const Type>{*value},
                                                               std::forward<Args>(args)...);
      } else {
        to<JSON, Type>::template op<Opts>(*value, std::forward<Args>(args)...);
      }
    }
  }
};

template <typename Type, auto Default>
struct from<JSON, hpp::proto::optional<Type, Default>> {
  template <auto Options, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &value, Args &&...args) noexcept {
    auto do_from_json = [](auto &&v, auto &&...args) noexcept {
      using type = std::remove_cvref_t<decltype(v)>;
      constexpr bool requires_quote = std::is_integral_v<type> && sizeof(type) > 4;
      if constexpr (requires_quote) {
        from<JSON, glz::quoted_t<type>>::template op<Options>(glz::quoted_t<type>{v}, std::forward<Args>(args)...);
      } else {
        from<JSON, type>::template op<Options>(v, std::forward<Args>(args)...);
      }
    };

    if constexpr (requires { value.emplace(); }) {
      do_from_json(value.emplace(), std::forward<Args>(args)...);
    } else {
      Type v;
      do_from_json(v, std::forward<Args>(args)...);
      value = v;
    }
  }
};

template <typename Type, auto Default>
struct to<JSON, hpp::proto::optional_ref<Type, Default>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    if constexpr (std::is_same_v<Type, uint64_t>) {
      static_assert(
          std::is_same_v<std::decay_t<decltype(*value)>, glz::opts_wrapper_t<const uint64_t, &glz::opts::quoted_num>>);
    }
    if (bool(value)) {
      to<JSON, std::decay_t<decltype(*value)>>::template op<Opts>(*value, std::forward<Args>(args)...);
    }
  }
};

template <typename Type, auto Default>
struct from<JSON, hpp::proto::optional_ref<Type, Default>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    if constexpr (requires { value.emplace(); }) {
      parse<JSON>::template op<Opts>(value.emplace(), std::forward<decltype(args)>(args)...);
    } else if constexpr (writable_map_t<Type> && resizable<Type>) {
      hpp::proto::map_wrapper<std::decay_t<decltype(*value)>> wrapped{*value};
      parse<JSON>::template op<Opts>(wrapped, std::forward<decltype(args)>(args)...);
    } else {
      parse<JSON>::template op<Opts>(*value, std::forward<decltype(args)>(args)...);
    }
  }
};

template <typename Type>
struct to<JSON, hpp::proto::heap_based_optional<Type>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto const &value, Args &&...args) noexcept {
    to<JSON, Type>::template op<Opts>(*value, std::forward<Args>(args)...);
  }
};

template <typename Type>
struct from<JSON, hpp::proto::heap_based_optional<Type>> {
  template <auto Options, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &value, Args &&...args) noexcept {
    value.emplace();
    from<JSON, Type>::template op<Options>(*value, std::forward<Args>(args)...);
  }
};

template <typename Type, std::size_t Index>
struct to<JSON, hpp::proto::oneof_wrapper<Type, Index>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto const &value, Args &&...args) noexcept {
    auto v = std::get_if<Index>(value.value);
    serialize<JSON>::template op<Opts>(*v, std::forward<decltype(args)>(args)...);
  }
};

template <typename Type, std::size_t Index>
struct from<JSON, hpp::proto::oneof_wrapper<Type, Index>> {
  template <auto Options, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    using alt_type = std::variant_alternative_t<Index, Type>;
    if constexpr (requires { value.value->template emplace<Index>(); }) {
      auto &v = value.value->template emplace<Index>();
      from<JSON, alt_type>::template op<Options>(v, std::forward<Args>(args)...);
    } else {
      *value.value = alt_type{};
      from<JSON, alt_type>::template op<Options>(std::get<Index>(*value.value), std::forward<Args>(args)...);
    }
  }
};

template <>
struct to<JSON, hpp::proto::boolean> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto value, Args &&...args) noexcept {
    to<JSON, bool>::template op<Opts>(value.value, std::forward<Args>(args)...);
  }
};

template <>
struct from<JSON, hpp::proto::boolean> {
  template <auto Options, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &value, Args &&...args) noexcept {
    from<JSON, bool>::template op<Options>(value.value, std::forward<Args>(args)...);
  }
};

template <typename Type>
struct from<JSON, hpp::proto::equality_comparable_span<Type>> {
  template <auto Options>
  GLZ_ALWAYS_INLINE static void op(hpp::proto::equality_comparable_span<Type> &value,
                                   hpp::proto::concepts::is_non_owning_context auto &ctx, auto &it, auto &end) {
    auto v = hpp::proto::detail::as_modifiable(ctx, value);
    if constexpr (hpp::proto::concepts::byte_type<Type>) {
      from<JSON, hpp::proto::use_base64>::template op<Options>(v, ctx, it, end);
    } else if constexpr (pair_t<std::remove_cvref_t<Type>>) {
      hpp::proto::map_wrapper<decltype(v)> wrapped{v};
      parse<JSON>::template op<Options>(wrapped, ctx, it, end);
    } else {
      from<JSON, decltype(v)>::template op<Options>(v, ctx, it, end);
    }
  }
};

template <auto Opts>
[[nodiscard]] GLZ_ALWAYS_INLINE size_t number_of_map_elements(is_context auto &ctx, auto it, auto &end) noexcept {
  skip_ws<Opts>(ctx, it, end);
  if (bool(ctx.error)) [[unlikely]] {
    return {};
  }

  if (*it == '}') [[unlikely]] {
    return 0;
  }
  size_t count = 1;
  while (true) {
    switch (*it) {
    case ',': {
      ++count;
      ++it;
      break;
    }
    case '/': {
      skip_comment(ctx, it, end);
      if (bool(ctx.error)) [[unlikely]] {
        return {};
      }
      break;
    }
    case '{':
      skip_until_closed<Opts, '{', '}'>(ctx, it, end);
      if (bool(ctx.error)) [[unlikely]] {
        return {};
      }
      break;
    case '[':
      skip_until_closed<Opts, '[', ']'>(ctx, it, end);
      if (bool(ctx.error)) [[unlikely]] {
        return {};
      }
      break;
    case '"': {
      skip_string<Opts>(ctx, it, end);
      if (bool(ctx.error)) [[unlikely]] {
        return {};
      }
      break;
    }
    case '}': {
      return count;
    }
    case '\0': {
      ctx.error = error_code::unexpected_end;
      return {};
    }
    default:
      ++it;
    }
  }
  unreachable();
}

template <typename T>
struct from<JSON, hpp::proto::map_wrapper<T>> {
  template <auto Options>
  static void op(auto &v, is_context auto &ctx, auto &it, auto &end) {
    auto &value = v.value;
    if constexpr (!has_ws_handled(Options)) {
      if (skip_ws<Options>(ctx, it, end)) [[unlikely]] {
        return;
      }
    }
    static constexpr auto Opts = ws_handled_off<Options>();

    if (match<'{'>(ctx, it)) [[unlikely]] {
      return;
    }
    const auto n = number_of_map_elements<Opts>(ctx, it, end);
    if (bool(ctx.error)) [[unlikely]] {
      return;
    }
    value.resize(n);
    size_t i = 0;
    using k_t = typename T::value_type::first_type;
    for (auto &x : value) {
      if constexpr (std::is_arithmetic_v<k_t>) {
        parse<JSON>::op<opt_true<Opts, &opts::quoted_num>>(x.first, ctx, it, end);
      } else {
        parse<JSON>::op<Opts>(x.first, ctx, it, end);
      }
      if (bool(ctx.error)) [[unlikely]] {
        return;
      }

      if (skip_ws<Opts>(ctx, it, end)) [[unlikely]] {
        return;
      }
      if (match<':'>(ctx, it)) [[unlikely]] {
        return;
      }
      if (skip_ws<Opts>(ctx, it, end)) [[unlikely]] {
        return;
      }

      parse<JSON>::op<ws_handled<Opts>()>(x.second, ctx, it, end);
      if (bool(ctx.error)) [[unlikely]] {
        return;
      }

      skip_ws<Opts>(ctx, it, end);
      if (i < n - 1) {
        if (match<','>(ctx, it)) [[unlikely]] {
          return;
        }
      }
      ++i;
    }
    match<'}'>(ctx, it);
  }
};

template <typename T>
struct from<JSON, hpp::proto::optional_message_view_ref<T>> {
  template <auto Options>
  static void op(auto value, hpp::proto::concepts::is_non_owning_context auto &ctx, auto &it, auto &end) {
    if constexpr (!has_ws_handled(Options)) {
      if (skip_ws<Options>(ctx, it, end)) [[unlikely]] {
        return;
      }
    }
    static constexpr auto Opts = ws_handled_off<Options>();
    using type = std::remove_const_t<typename T::value_type>;

    if (*it == 'n') {
      ++it; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      match<"ull", Opts>(ctx, it, end);
      if (bool(ctx.error)) [[unlikely]] {
        return;
      }
      value.ref.reset();
    } else {
      void *addr = ctx.memory_resource().allocate(sizeof(type), alignof(type));
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      type *obj = new (addr) type;
      parse<JSON>::op<Opts>(*obj, ctx, it, end);
      value.ref = obj;
    }
  }
};

template <typename Type>
struct to<JSON, hpp::proto::optional_message_view_ref<Type>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto value, Args &&...args) noexcept {
    if (value.ref.has_value()) {
      to<JSON, std::decay_t<decltype(*value.ref)>>::template op<Opts>(*value.ref, std::forward<Args>(args)...);
    }
  }
};

} // namespace glz

namespace hpp::proto {

template <glz::opts options>
struct glz_opts_t {
  using option_type = glz_opts_t<options>;
  static constexpr glz::opts glz_opts_value = options;
};

namespace concepts {
template <typename T>
concept glz_opts_t = requires { requires std::same_as<std::decay_t<decltype(T::glz_opts_value)>, glz::opts>; };

template <typename T>
concept write_json_supported = glz::write_supported<glz::JSON, T>;

template <typename T>
concept read_json_supported = glz::read_supported<glz::JSON, T>;
} // namespace concepts
namespace detail {
template <typename Context, typename... Rest>
constexpr glz::opts get_glz_opts_impl() {
  if constexpr (requires { std::decay_t<Context>::glz_opts_value; }) {
    return std::decay_t<Context>::glz_opts_value;
  } else if constexpr (sizeof...(Rest)) {
    return get_glz_opts_impl<Rest...>();
  } else {
    return glz::opts{};
  }
}

template <typename... Context>
constexpr glz::opts get_glz_opts() {
  if constexpr (sizeof...(Context)) {
    return get_glz_opts_impl<Context...>();
  }
  return glz::opts{};
}
} // namespace detail

template <uint8_t width = 3>
constexpr auto indent_level =
    glz_opts_t<glz::opts{.prettify = static_cast<uint8_t>(width > 0), .indentation_width = width}>{};

struct [[nodiscard]] json_status final {
  glz::error_ctx ctx;
  [[nodiscard]] bool ok() const { return !static_cast<bool>(ctx); }
  [[nodiscard]] std::string message(const auto &buffer) const { return glz::format_error(ctx, buffer); }
};

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
inline json_status read_json(concepts::read_json_supported auto &value,
                             concepts::contiguous_byte_range auto const &buffer,
                             concepts::is_option_type auto &&...option) {
  using buffer_type = std::remove_cvref_t<decltype(buffer)>;
  static_assert(std::is_trivially_destructible_v<buffer_type> || std::is_lvalue_reference_v<decltype(buffer)> ||
                    ((concepts::has_memory_resource<decltype(option)> || ...)),
                "temporary buffer cannot be used for non-owning object parsing");
  value = {};
  constexpr auto opts = detail::get_glz_opts<decltype(option)...>();
  json_context ctx{std::forward<decltype(option)>(option)...};
  return {glz::read<opts>(value, std::forward<decltype(buffer)>(buffer), ctx)};
}

template <concepts::read_json_supported T>
inline auto read_json(concepts::contiguous_byte_range auto const &buffer,
                      concepts::is_option_type auto &&...option) -> std::expected<T, json_status> {
  T value;
  if (auto result = read_json(value, std::forward<decltype(buffer)>(buffer), std::forward<decltype(option)>(option)...);
      !result.ok()) {
    return std::unexpected(result);
  } else {
    return value;
  }
}

inline json_status write_json(concepts::write_json_supported auto const &value,
                              concepts::contiguous_byte_range auto &buffer,
                              concepts::is_option_type auto &&...option) noexcept {
  constexpr auto opts = detail::get_glz_opts<decltype(option)...>();
  json_context ctx{std::forward<decltype(option)>(option)...};
  return {glz::write<opts>(value, detail::as_modifiable(ctx, buffer), ctx)};
}

template <concepts::contiguous_byte_range Buffer = std::string>
inline auto write_json(concepts::write_json_supported auto const &value,
                       concepts::is_option_type auto &&...option) noexcept -> std::expected<Buffer, json_status> {
  Buffer buffer;
  auto ec = write_json(value, buffer, std::forward<decltype(option)>(option)...);
  if (!ec.ok()) {
    return std::unexpected(ec);
  }
  return buffer;
}

} // namespace hpp::proto