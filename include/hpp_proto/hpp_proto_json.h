#pragma once
#include <glaze/glaze.hpp>
#include <hpp_proto/msg_base.h>
#include <bit>

namespace hpp::proto {

namespace concepts {
template <typename Type>
concept integer_64bits = (sizeof(Type) == 8) && std::integral<Type>;
}

template <concepts::integer_64bits T> struct int_wrapper {
  T value;
};

template <concepts::integer_64bits T> int_wrapper<T> &wrap_int64(T &v) { return *std::bit_cast<int_wrapper<T> *>(&v); }
template <concepts::integer_64bits T> const int_wrapper<T> &wrap_int64(const T &v) {
  return *std::bit_cast<const int_wrapper<T> *>(&v);
}

template <concepts::integer_64bits T, auto Default> std::optional<int_wrapper<T>> &wrap_int64(optional<T, Default> &v) {
  return *std::bit_cast<std::optional<int_wrapper<T>> *>(&v);
}

template <concepts::integer_64bits T, auto Default>
const std::optional<int_wrapper<T>> &wrap_int64(const optional<T, Default> &v) {
  return *std::bit_cast<const std::optional<int_wrapper<T>> *>(&v);
}

template <concepts::integer_64bits T> std::vector<int_wrapper<T>> &wrap_int64(std::vector<T> &v) {
  return *std::bit_cast<std::vector<int_wrapper<T>> *>(&v);
}

template <concepts::integer_64bits T> const std::vector<int_wrapper<T>> &wrap_int64(const std::vector<T> &v) {
  return *std::bit_cast<const std::vector<int_wrapper<T>> *>(&v);
}

template <concepts::integer_64bits T, std::size_t N> std::span<int_wrapper<T>, N> &wrap_int64(std::span<T, N> &v) {
  return *std::bit_cast<std::span<int_wrapper<T>> *>(&v);
}

template <concepts::integer_64bits T, std::size_t N>
const std::span<int_wrapper<T>, N> &wrap_int64(const std::span<T, N> &v) {
  return *std::bit_cast<const std::span<int_wrapper<T>, N> *>(&v);
}

template <typename T, std::size_t Index> struct oneof_wrapper {
  T *value;
  operator bool() const { return value->index() == Index; }
  auto &operator*() const { return std::get<Index>(*value); }
};

template <std::size_t Index, typename T> oneof_wrapper<T, Index> wrap_oneof(T &v) {
  return oneof_wrapper<T, Index>{&v};
}

} // namespace hpp::proto

namespace glz {
namespace detail {
template <> struct to_json<hpp::proto::bytes> {
  template <auto Opts, class B>
  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, B &&b, auto &&ix) noexcept {

    const auto n = value.size();

    if constexpr (detail::resizeable<B>) {
      std::size_t encoded_size = (n / 3 + (n % 3 ? 1 : 0)) * 4;
      if ((ix + 2 + encoded_size) >= b.size()) [[unlikely]] {
        b.resize(std::max(b.size() * 2, ix + 2 + encoded_size));
      }
    }

    dump_unchecked<'"'>(b, ix);

    using V = std::decay_t<decltype(b[0])>;
    static char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "abcdefghijklmnopqrstuvwxyz"
                                 "0123456789+/";

    std::size_t i = 0;
    if (n >= 3) {
      for (i = 0; i <= n - 3; i += 3) {
        uint32_t x = 0;

        memcpy(&x, &value[i], 3);

        if constexpr (std::endian::native == std::endian::little) {
          b[ix++] = static_cast<V>(base64_chars[(x >> 2) & 0x3F]);
          b[ix++] = static_cast<V>(base64_chars[((x << 4) & 0x30) | ((x >> 12) & 0x0F)]);
          b[ix++] = static_cast<V>(base64_chars[((x >> 6) & 0x3C) | (x >> 22)]);
          b[ix++] = static_cast<V>(base64_chars[(x >> 16) & 0x3F]);
        } else {
          x >>= 8;
          b[ix + 3] = static_cast<V>(base64_chars[x & 0x3F]);
          x >>= 6;
          b[ix + 2] = static_cast<V>(base64_chars[x & 0x3F]);
          x >>= 6;
          b[ix + 1] = static_cast<V>(base64_chars[x & 0x3F]);
          x >>= 6;
          b[ix] = static_cast<V>(base64_chars[x & 0x3F]);
          ix += 4;
        }
      }
    }

    if (i != n) {

      b[ix++] = static_cast<V>(base64_chars[std::to_integer<int>((value[i] >> 2) & std::byte{0x3F})]);
      std::byte next = (i + 1 < n) ? value[i + 1] : std::byte{0};
      b[ix++] = static_cast<V>(
          base64_chars[std::to_integer<int>((value[i] << 4 & std::byte{0x3F}) | ((next >> 4) & std::byte{0x0F}))]);
      if (i + 1 < n) {
        b[ix++] = static_cast<V>(base64_chars[std::to_integer<int>((next << 2 & std::byte{0x3F}))]);
      } else {
        b[ix++] = static_cast<V>('=');
      }
      b.at(ix++) = static_cast<V>('=');
    }
    dump_unchecked<'"'>(b, ix);
  }
};

template <> struct from_json<hpp::proto::bytes> {
  template <auto Opts, class It, class End>
  GLZ_ALWAYS_INLINE static void op(auto &value, is_context auto &&ctx, It &&it, End &&end) noexcept {
    if (static_cast<bool>(ctx.error)) [[unlikely]] {
      return;
    }

    if constexpr (!Opts.opening_handled) {
      if constexpr (!Opts.ws_handled) {
        skip_ws<Opts>(ctx, it, end);
      }

      match<'"'>(ctx, it);
    }

    static constexpr unsigned char decode_table[] = {
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

    // growth portion
    auto start = it;
    skip_till_quote(ctx, it, end);
    auto n = it - start;
    if (n == 0) {
      value.clear();
      match<'"'>(ctx, it);
      return;
    }

    if (n % 4 != 0) {
      ctx.error = error_code::syntax_error;
      return;
    }

    size_t out_len = n / 4 * 3;
    if (*(start + n - 1) == '=')
      out_len--;
    if (*(start + n - 2) == '=')
      out_len--;

    value.resize(out_len);
    size_t j = 0;
    while (start != it) {
      uint32_t a = decode_table[static_cast<int>(*start++)];
      uint32_t b = decode_table[static_cast<int>(*start++)];
      uint32_t c = decode_table[static_cast<int>(*start++)];
      uint32_t d = decode_table[static_cast<int>(*start++)];
      uint32_t triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);

      value[j++] = std::byte((triple >> 2 * 8) & 0xFF);
      if (j < out_len)
        value[j++] = std::byte((triple >> 1 * 8) & 0xFF);
      if (j < out_len)
        value[j++] = std::byte((triple >> 0 * 8) & 0xFF);
    }
    match<'"'>(ctx, it);
  }
};

template <typename Type> struct to_json<hpp::proto::int_wrapper<Type>> {
  template <auto Opts, class B>
  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, B &&b, auto &&ix) noexcept {
    if constexpr (detail::resizeable<B>) {
      std::size_t encoded_size = 20;
      if ((ix + 2 + encoded_size) >= b.size()) [[unlikely]] {
        b.resize(std::max(b.size() * 2, ix + 2 + encoded_size));
      }
    }
    dump_unchecked<'"'>(b, ix);
    write_chars::op<Opts>(value.value, ctx, b, ix);
    dump_unchecked<'"'>(b, ix);
  }
};

template <typename Type> struct from_json<hpp::proto::int_wrapper<Type>> {
  template <auto Options, class It>
  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, It &&it, auto &&end) noexcept {
    if (static_cast<bool>(ctx.error)) [[unlikely]] {
      return;
    }

    if constexpr (!Options.ws_handled) {
      skip_ws<Options>(ctx, it, end);
    }
    match<'"'>(ctx, it);
    using X = std::conditional_t<std::is_const_v<std::remove_pointer_t<std::remove_reference_t<decltype(it)>>>,
                                 const uint8_t *, uint8_t *>;
#if defined(__cpp_lib_bit_cast)
    using namespace std;
#else
    using namespace hpp::proto::std;
#endif
    auto cur = bit_cast<X>(it);
    auto s = parse_number<std::decay_t<Type>, Options.force_conformance>(value.value, cur);
    if (!s) [[unlikely]] {
      ctx.error = error_code::parse_number_failure;
      return;
    }
    it = bit_cast<std::remove_reference_t<decltype(it)>>(cur);
    match<'"'>(ctx, it);
  }
};

template <typename Type, auto Default> struct to_json<hpp::proto::optional<Type, Default>> {
  template <auto Opts, class... Args> GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    to_json<Type>::template op<Opts>(value.value_or_default(), std::forward<Args>(args)...);
  }
};

template <typename Type, auto Default> struct from_json<hpp::proto::optional<Type, Default>> {
  template <auto Options, class... Args> GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    value.emplace();
    from_json<Type>::template op<Options>(*value, std::forward<Args>(args)...);
  }
};

template <typename Type> struct to_json<hpp::proto::heap_based_optional<Type>> {
  template <auto Opts, class... Args> GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    to_json<Type>::template op<Opts>(*value, std::forward<Args>(args)...);
  }
};

template <typename Type> struct from_json<hpp::proto::heap_based_optional<Type>> {
  template <auto Options, class... Args> GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    value.emplace();
    from_json<Type>::template op<Options>(*value, std::forward<Args>(args)...);
  }
};

template <typename Type, std::size_t Index> struct to_json<hpp::proto::oneof_wrapper<Type, Index>> {
  template <auto Opts, class... Args> GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    auto v = std::get_if<Index>(value.value);
    to_json<std::remove_pointer_t<decltype(v)>>::template op<Opts>(*v, std::forward<Args>(args)...);
  }
};

template <typename Type, std::size_t Index> struct from_json<hpp::proto::oneof_wrapper<Type, Index>> {
  template <auto Options, class... Args> GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    auto &v = value.value->template emplace<Index>();
    from_json<std::remove_cvref_t<decltype(v)>>::template op<Options>(v, std::forward<Args>(args)...);
  }
};

template <> struct to_json<hpp::proto::boolean> {
  template <auto Opts, class... Args> GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    to_json<bool>::template op<Opts>(value.value, std::forward<Args>(args)...);
  }
};

template <> struct from_json<hpp::proto::boolean> {
  template <auto Options, class... Args> GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    from_json<bool>::template op<Options>(value.value, std::forward<Args>(args)...);
  }
};

} // namespace detail
} // namespace glz