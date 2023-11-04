#pragma once
#include <bit>
#include <glaze/glaze.hpp>
#include <hpp_proto/field_types.h>

namespace hpp::proto {

template <typename T, std::size_t Index>
struct oneof_wrapper {
  T *value;
  operator bool() const { return value->index() == Index; }
  auto &operator*() const { return std::get<Index>(*value); }
};

template <std::size_t Index, typename T>
oneof_wrapper<T, Index> wrap_oneof(T &v) {
  return oneof_wrapper<T, Index>{&v};
}

namespace concepts {
template <typename T>
concept integral_64_bits = std::same_as<std::decay_t<T>, uint64_t> || std::same_as<std::decay_t<T>, int64_t>;

template <typename T>
concept map_with_integral_64_bits_mapped_type =
    glz::detail::writable_map_t<T> && integral_64_bits<typename T::value_type::second_type>;

template <typename T>
concept jsonfy_need_quote = integral_64_bits<T> || map_with_integral_64_bits_mapped_type<T> || requires(T val) {
  val.size();
  requires integral_64_bits<typename T::value_type>;
};

template <typename T>
concept is_non_owning_context = glz::is_context<T> && requires(T &v) {
  { v.mr } -> concepts::memory_resource;
};

} // namespace concepts

template <concepts::memory_resource MemoryResource>
struct non_owning_context : glz::context {
  MemoryResource &mr;

  non_owning_context(MemoryResource &mr) : mr(mr) {}
};
template <typename T, auto Default = std::monostate{}>
struct optional_ref {
  T &val;
  operator bool() const { return !is_default_value<T, Default>(val); }

  template <typename U>
  static U &deref(U &v) {
    return v;
  }

  template <concepts::jsonfy_need_quote U>
  static glz::quoted_num_t<U> deref(U &v) {
    return glz::quoted_num_t<U>{v};
  }

  auto operator*() const -> decltype(deref(val)) { return deref(val); }
};

template <auto Default>
struct optional_ref<hpp::proto::optional<bool, Default>, std::monostate{}> {
  hpp::proto::optional<bool, Default> &val;
  operator bool() const { return val.has_value(); }
  bool &emplace() const { return val.emplace(); }
  bool operator*() const { return *val; }
};

template <auto Default>
struct optional_ref<const hpp::proto::optional<bool, Default>, std::monostate{}> {
  const hpp::proto::optional<bool, Default> &val;
  operator bool() const { return val.has_value(); }
  bool operator*() const { return *val; }
};

template <auto MemPtr, auto Default = std::monostate{}>
constexpr decltype(auto) as_optional_ref() {
  return [](auto &&val) { return optional_ref<std::remove_reference_t<decltype(val.*MemPtr)>, Default>{val.*MemPtr}; };
}

} // namespace hpp::proto

namespace glz {
namespace detail {

struct base64 {
  constexpr static std::size_t max_encode_size(hpp::proto::concepts::contiguous_byte_range auto &&source) noexcept {
    std::size_t n = source.size();
    return (n / 3 + (n % 3 ? 1 : 0)) * 4;
  }

  constexpr static std::size_t encode(hpp::proto::concepts::contiguous_byte_range auto &&source, auto &&b) noexcept {

    const auto n = source.size();
    using V = std::decay_t<decltype(b[0])>;
    constexpr char const base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                          "abcdefghijklmnopqrstuvwxyz"
                                          "0123456789+/";

    std::size_t i = 0, ix = 0;
    if (n >= 3) {
      for (i = 0; i <= n - 3; i += 3) {
        uint32_t x = 0;

        memcpy(&x, &source[i], 3);

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

      b[ix++] = static_cast<V>(base64_chars[std::to_integer<int>((source[i] >> 2) & std::byte{0x3F})]);
      std::byte const next = (i + 1 < n) ? source[i + 1] : std::byte{0};
      b[ix++] = static_cast<V>(
          base64_chars[std::to_integer<int>((source[i] << 4 & std::byte{0x3F}) | ((next >> 4) & std::byte{0x0F}))]);
      if (i + 1 < n) {
        b[ix++] = static_cast<V>(base64_chars[std::to_integer<int>((next << 2 & std::byte{0x3F}))]);
      } else {
        b[ix++] = static_cast<V>('=');
      }
      b[ix++] = static_cast<V>('=');
    }
    return ix;
  }

  constexpr static bool decode(hpp::proto::concepts::contiguous_byte_range auto &&source, auto &&value) {

    std::size_t n = source.size();
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
    while (start != source.end()) {
      uint32_t const a = decode_table[static_cast<int>(*start++)];
      uint32_t const b = decode_table[static_cast<int>(*start++)];
      uint32_t const c = decode_table[static_cast<int>(*start++)];
      uint32_t const d = decode_table[static_cast<int>(*start++)];
      uint32_t const triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);

      using byte = std::ranges::range_value_t<decltype(value)>;

      value[j++] = static_cast<byte>((triple >> 2 * 8) & 0xFF);
      if (j < value.size()) {
        value[j++] = static_cast<byte>((triple >> 1 * 8) & 0xFF);
      }
      if (j < value.size()) {
        value[j++] = static_cast<byte>((triple >> 0 * 8) & 0xFF);
      }
    }
    return true;
  }
};

template <>
struct to_json<hpp::proto::bytes_view> {
  template <auto Opts, class B>
  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&, B &&b, auto &&ix) noexcept {
    if constexpr (detail::resizeable<B>) {
      std::size_t const encoded_size = base64::max_encode_size(value);
      if ((ix + 2 + encoded_size) >= b.size()) [[unlikely]] {
        b.resize(std::max(b.size() * 2, ix + 2 + encoded_size));
      }
    }

    dump_unchecked<'"'>(b, ix);
    ix += base64::encode(value, std::span{b}.subspan(ix));
    dump_unchecked<'"'>(b, ix);
  }
};

template <>
struct to_json<hpp::proto::bytes> {
  template <auto Opts, class B>
  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, B &&b, auto &&ix) noexcept {
    return to_json<hpp::proto::bytes_view>::op<Opts, B>(
        std::span<const typename hpp::proto::bytes::value_type>{value.data(), value.size()}, ctx, b, ix);
  }
};

template <auto Opts, class It, class End>
GLZ_ALWAYS_INLINE void read_json_bytes(auto &&value, is_context auto &&ctx, It &&it, End &&end) noexcept {
  if (static_cast<bool>(ctx.error)) [[unlikely]] {
    return;
  }

  if constexpr (!Opts.opening_handled) {
    if constexpr (!Opts.ws_handled) {
      skip_ws<Opts>(ctx, it, end);
    }

    match<'"'>(ctx, it, end);
  }

  // growth portion
  auto start = it;
  skip_till_quote(ctx, it, end);
  auto n = it - start;
  if (n == 0) {
    value.clear();
    match<'"'>(ctx, it, end);
    return;
  }

  if (!base64::decode(std::span{start, start + n}, value)) {
    ctx.error = error_code::syntax_error;
    return;
  }
  match<'"'>(ctx, it, end);
}

template <>
struct from_json<hpp::proto::bytes> {
  template <auto Opts, class It, class End>
  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, It &&it, End &&end) {
    read_json_bytes<Opts, It, End>(value, ctx, it, end);
  }
};

template <typename Type, auto Default>
struct to_json<hpp::proto::optional<Type, Default>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    if (value.has_value()) {
      if constexpr (std::is_integral_v<Type> && sizeof(Type) > 4) {
        to_json<glz::quoted_t<const Type>>::template op<Opts>(glz::quoted_t<const Type>{*value},
                                                              std::forward<Args>(args)...);
      } else {
        to_json<Type>::template op<Opts>(*value, std::forward<Args>(args)...);
      }
    }
  }
};

template <typename Type, auto Default>
struct from_json<hpp::proto::optional<Type, Default>> {
  template <auto Options, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    auto do_from_json = [](auto &&v, auto &&...args) noexcept {
      using type = std::remove_cvref_t<decltype(v)>;
      constexpr bool requires_quote = std::is_integral_v<type> && sizeof(type) > 4;
      if constexpr (requires_quote) {
        from_json<glz::quoted_t<type>>::template op<Options>(glz::quoted_t<type>{v}, std::forward<Args>(args)...);
      } else {
        from_json<type>::template op<Options>(v, std::forward<Args>(args)...);
      }
    };

    if constexpr (requires { value.emplace(); }) {
      do_from_json(value.emplace(), std::forward<Args>(args)...);
    } else {
      Type v;
      do_from_json(v, std::forward<Args>(args)...);
      value = v;
    }
  } // namespace detail
};  // namespace glz

template <typename Type, auto Default>
struct to_json<hpp::proto::optional_ref<Type, Default>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    if constexpr (std::is_same_v<Type, uint64_t>) {
      static_assert(std::is_same_v<std::decay_t<decltype(*value)>, glz::quoted_num_t<uint64_t>>);
    }
    if (bool(value)) {
      to_json<std::decay_t<decltype(*value)>>::template op<Opts>(*value, std::forward<Args>(args)...);
    }
  }
};

template <typename Type, auto Default>
struct from_json<hpp::proto::optional_ref<Type, Default>> {
  template <auto Options, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    if constexpr (requires { value.emplace(); }) {
      from_json<std::decay_t<decltype(*value)>>::template op<Options>(value.emplace(), std::forward<Args>(args)...);
    } else {
      from_json<std::decay_t<decltype(*value)>>::template op<Options>(*value, std::forward<Args>(args)...);
    }
  }
};

template <typename Type>
struct to_json<hpp::proto::heap_based_optional<Type>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    to_json<Type>::template op<Opts>(*value, std::forward<Args>(args)...);
  }
};

template <typename Type>
struct from_json<hpp::proto::heap_based_optional<Type>> {
  template <auto Options, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    value.emplace();
    from_json<Type>::template op<Options>(*value, std::forward<Args>(args)...);
  }
};

template <typename Type, std::size_t Index>
struct to_json<hpp::proto::oneof_wrapper<Type, Index>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    auto v = std::get_if<Index>(value.value);
    to_json<std::remove_pointer_t<decltype(v)>>::template op<Opts>(*v, std::forward<Args>(args)...);
  }
};

template <typename Type, std::size_t Index>
struct from_json<hpp::proto::oneof_wrapper<Type, Index>> {
  template <auto Options, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    using alt_type = std::variant_alternative_t<Index, Type>;
    if constexpr (requires { value.value->template emplace<Index>(); }) {
      auto &v = value.value->template emplace<Index>();
      from_json<alt_type>::template op<Options>(v, std::forward<Args>(args)...);
    } else {
      *value.value = alt_type{};
      from_json<alt_type>::template op<Options>(std::get<Index>(*value.value), std::forward<Args>(args)...);
    }
  }
};

template <>
struct to_json<hpp::proto::boolean> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    to_json<bool>::template op<Opts>(value.value, std::forward<Args>(args)...);
  }
};

template <>
struct from_json<hpp::proto::boolean> {
  template <auto Options, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    from_json<bool>::template op<Options>(value.value, std::forward<Args>(args)...);
  }
};

template <typename Type>
struct from_json<std::span<Type>> {
  template <auto Options>
  GLZ_ALWAYS_INLINE static void op(std::span<Type> &value, hpp::proto::concepts::is_non_owning_context auto &&ctx,
                                   auto &&it, auto &&end) {
    hpp::proto::detail::growable_span growable{value, ctx.mr};
    using type = std::remove_const_t<Type>;
    if constexpr (std::same_as<type, std::byte> || std::same_as<type, char>) {
      read_json_bytes<Options>(growable, ctx, it, end);
    } else {
      from_json<decltype(growable)>::template op<Options>(growable, ctx, it, end);
    }
  }
};

template <auto Opts>
[[nodiscard]] GLZ_ALWAYS_INLINE size_t number_of_map_elements(is_context auto &&ctx, auto it, auto &&end) noexcept {
  skip_ws<Opts>(ctx, it, end);
  if (bool(ctx.error)) {
    [[unlikely]] return {};
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
      if (bool(ctx.error)) {
        [[unlikely]] return {};
      }
      break;
    }
    case '{':
      skip_until_closed<'{', '}'>(ctx, it, end);
      if (bool(ctx.error)) {
        [[unlikely]] return {};
      }
      break;
    case '[':
      skip_until_closed<'[', ']'>(ctx, it, end);
      if (bool(ctx.error)) {
        [[unlikely]] return {};
      }
      break;
    case '"': {
      skip_string<Opts>(ctx, it, end);
      if (bool(ctx.error)) {
        [[unlikely]] return {};
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
  requires writable_map_t<T> && resizeable<T>
struct from_json<T> {
  template <auto Options>
  GLZ_FLATTEN static void op(auto &value, is_context auto &&ctx, auto &&it, auto &&end) {
    if constexpr (!Options.ws_handled) {
      skip_ws<Options>(ctx, it, end);
      if (bool(ctx.error)) {
        [[unlikely]] return;
      }
    }
    static constexpr auto Opts = ws_handled_off<Options>();

    match<'{'>(ctx, it, end);
    if (bool(ctx.error)) {
      [[unlikely]] return;
    }
    const auto n = number_of_map_elements<Opts>(ctx, it, end);
    if (bool(ctx.error)) {
      [[unlikely]] return;
    }
    value.resize(n);
    size_t i = 0;
    using k_t = typename T::value_type::first_type;
    for (auto &x : value) {
      if constexpr (std::is_arithmetic_v<k_t>) {
        read<json>::op<opt_true<Opts, &opts::quoted_num>>(x.first, ctx, it, end);
      } else {
        read<json>::op<Opts>(x.first, ctx, it, end);
      }
      if (bool(ctx.error)) {
        [[unlikely]] return;
      }

      skip_ws<Opts>(ctx, it, end);
      if (bool(ctx.error)) {
        [[unlikely]] return;
      }
      match<':'>(ctx, it, end);
      if (bool(ctx.error)) {
        [[unlikely]] return;
      }
      skip_ws<Opts>(ctx, it, end);
      if (bool(ctx.error)) {
        [[unlikely]] return;
      }

      read<json>::op<ws_handled<Opts>()>(x.second, ctx, it, end);
      if (bool(ctx.error)) {
        [[unlikely]] return;
      }

      skip_ws<Opts>(ctx, it, end);
      if (i < n - 1) {
        match<','>(ctx, it, end);
      }
      ++i;
    }
    match<'}'>(ctx, it, end);
  }
};

template <typename T>
struct from_json<T *> {
  template <auto Options>
  GLZ_FLATTEN static void op(auto &value, hpp::proto::concepts::is_non_owning_context auto &&ctx, auto &&it,
                             auto &&end) {
    if constexpr (!Options.ws_handled) {
      skip_ws<Options>(ctx, it, end);
      if (bool(ctx.error)) {
        [[unlikely]] return;
      }
    }
    static constexpr auto Opts = ws_handled_off<Options>();
    using type = std::remove_const_t<T>;

    if constexpr (!std::is_trivially_destructible_v<type>) {
      if (value) {
        value->~type();
      }
    }

    if (*it == 'n') {
      ++it;
      match<"ull">(ctx, it, end);
      if (bool(ctx.error)) {
        [[unlikely]] return;
      }
      value = nullptr;
    } else {
      void *addr = ctx.mr.allocate(sizeof(type), alignof(type));
      type *obj = new (addr) type;
      read<json>::op<Opts>(*obj, ctx, it, end);
      value = obj;
    }
  }
};
} // namespace detail
} // namespace glz

namespace hpp::proto {

struct json_parse_error {
  uint64_t ec : 8;
  uint64_t location : 56;

  operator bool() const { return ec != 0; }

  std::string format(const auto &buffer) {
    static constexpr auto arr = glz::detail::make_enum_to_string_array<glz::error_code>();
    const auto error_type_str = arr[ec];
    const auto info = glz::detail::get_source_info(buffer, location);
    if (info) {
      return glz::detail::generate_error_string(error_type_str, *info);
    }
    return std::string(error_type_str);
  }
};

template <typename T, typename Buffer, glz::is_context Context>
[[nodiscard]] inline json_parse_error read_json(T &value, Buffer &&buffer, Context &&ctx) {
  using buffer_type = std::remove_cvref_t<Buffer>;
  static_assert(std::is_trivially_destructible_v<buffer_type> || std::is_lvalue_reference_v<Buffer> ||
                    std::same_as<Context, glz::context>,
                "temporary buffer cannot be used for non-owning object parsing");
  constexpr glz::opts options{};
  const char *b = buffer.data();
  const char *e = b + buffer.size();
  glz::detail::read<glz::json>::template op<options>(value, ctx, b, e);

  if constexpr (options.force_conformance) {
    if (b < e) {
      glz::detail::skip_ws<options>(ctx, b, e);
      if (b != e) {
        ctx.error = glz::error_code::syntax_error;
      }
    }
  }

  return json_parse_error{.ec = static_cast<uint8_t>(ctx.error),
                          .location = static_cast<size_t>(std::distance(std::as_const(buffer).data(), b))};
}

template <class T, typename Buffer, concepts::memory_resource MemoryResource>
[[nodiscard]] inline json_parse_error read_json(T &value, Buffer &&buffer, MemoryResource &mr) {
  return read_json(value, std::forward<Buffer>(buffer), non_owning_context<MemoryResource>{mr});
}

template <class T>
[[nodiscard]] inline json_parse_error read_json(T &value, std::string_view buffer) {
  return read_json(value, buffer, glz::context{});
}

template <class T>
[[nodiscard]] inline auto write_json(T &&value) noexcept {
  std::string buffer{};
  glz::write<glz::opts{}>(std::forward<T>(value), buffer);
  return buffer;
}

template <class T, class Buffer>
inline void write_jsonc(T &&value, Buffer &&buffer) noexcept {
  glz::write<glz::opts{}>(std::forward<T>(value), std::forward<Buffer>(buffer));
}

} // namespace hpp::proto