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
#include <cctype>
#include <iterator>

#include <hpp_proto/json/base64.hpp>
#include <hpp_proto/json/field_wrappers.hpp>
#include <hpp_proto/json/util.hpp>

namespace hpp::proto {
namespace concepts {
template <typename T>
concept is_json_context = requires { typename T::is_json_context; };
} // namespace concepts
template <typename... AuxContext>
struct json_context : glz::context, pb_context<AuxContext...> {
  using is_json_context = void;
  const char *error_message_name = nullptr;
  template <typename... U>
  explicit json_context(U &&...ctx) : pb_context<AuxContext...>(std::forward<U>(ctx)...) {}
};

template <typename... U>
json_context(U &&...u) -> json_context<std::remove_cvref_t<U>...>;
template <typename T>
struct json_codec;

namespace concepts {
template <typename T>
concept has_codec = requires { typename json_codec<T>::type; };

template <typename T>
concept has_nested_codec = requires { typename T::json_codec; };

} // namespace concepts

template <concepts::has_nested_codec T>
struct json_codec<T> {
  using type = typename T::json_codec;
};

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
    from<JSON, std::string_view>::op<opt_true<Opts, &opts::null_terminated>>(encoded, ctx, it, end);
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

template <>
struct from<JSON, hpp::proto::bytes_view> {
template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto& v, auto& ctx, auto& it, auto& end) {
    decltype(auto) mutable_v = hpp::proto::detail::as_modifiable(ctx, v);
    from<JSON, hpp::proto::use_base64>::template op<Opts>(mutable_v, ctx, it, end);
  }
};

namespace detail {

template <auto Opts, typename T>
  requires std::is_enum_v<T>
void from_json(T &v, auto &ctx, auto &it, auto &end) {
  if constexpr (!check_ws_handled(Opts)) {
    if (skip_ws<Opts>(ctx, it, end)) {
      return;
    }
  }
  auto parse_enum = [&](bool is_number) {
    if (is_number) {
      int32_t number;
      from<JSON, int32_t>::template op<ws_handled<Opts>()>(number, ctx, it, end);
      v = static_cast<T>(number);
    } else {
      from<JSON, T>::template op<ws_handled<Opts>()>(v, ctx, it, end);
    }
  };

  if constexpr (!Opts.quoted_num) {
    parse_enum(*it != '"');
  } else {
    // For map keys, enums may be quoted as a name or as a number.
    // Peek past the opening quote to decide which parser to use.

    if constexpr (!Opts.null_terminated) {
      if (std::next(it) == end) {
        ctx.error = error_code::end_reached;
        return;
      }
    }

    parse_enum(std::isdigit(*std::next(it)));
  }
}

template <auto Opts, typename T>
  requires(!std::is_enum_v<T>)
void from_json(T &v, auto &ctx, auto &it, auto &end) {
  if constexpr (std::same_as<T, std::string_view>) {
    decltype(auto) mutable_v = hpp::proto::detail::as_modifiable(ctx, v);
    from<JSON, decltype(mutable_v)>::template op<Opts>(mutable_v, ctx, it, end);
  } else if constexpr (::hpp::proto::concepts::integral_64_bits<T>) {
    from<JSON, T>::template op<opt_true<Opts, &opts::quoted_num>>(v, ctx, it, end);
  } else if constexpr (pair_t<T>) {
    util::parse_key_and_colon<Opts>(::hpp::proto::detail::as_modifiable(ctx, v.first), ctx, it, end);
    if (bool(ctx.error)) [[unlikely]] {
      return;
    }
    from_json<Opts>(v.second, ctx, it, end);
  } else {
    from<JSON, T>::template op<Opts>(v, ctx, it, end);
  }
}
} // namespace detail



template <typename Type, auto Default>
struct to<JSON, hpp::proto::optional<Type, Default>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto const &value, auto &ctx, auto &it, auto &end) noexcept {
    if (value.has_value()) {
      if constexpr (::hpp::proto::concepts::integral_64_bits<Type>) {
        to<JSON, Type>::template op<opt_true<Opts, &opts::quoted_num>>(*value, ctx, it, end);
      } else {
        to<JSON, Type>::template op<Opts>(*value, ctx, it, end);
      }
    }
  }
};

template <typename Type, auto Default>
struct from<JSON, hpp::proto::optional<Type, Default>> {
  template <auto Options, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &value, Args &&...args) noexcept {
    if constexpr (requires { value.emplace(); }) {
      detail::from_json<Options>(value.emplace(), std::forward<Args>(args)...);
    } else {
      Type v;
      detail::from_json<Options>(v, std::forward<Args>(args)...);
      value = v;
    }
  }
};

template <typename Type, auto Default>
struct to<JSON, hpp::proto::optional_ref<Type, Default>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    if (bool(value)) {
      if constexpr (::hpp::proto::concepts::jsonfy_need_quote<Type>) {
        to<JSON, std::decay_t<decltype(*value)>>::template op<opt_true<Opts, &opts::quoted_num>>(
            *value, std::forward<Args>(args)...);
      } else {
        to<JSON, std::decay_t<decltype(*value)>>::template op<Opts>(*value, std::forward<Args>(args)...);
      }
    }
  }
};

template <typename Type, auto Default>
struct from<JSON, hpp::proto::optional_ref<Type, Default>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, auto &ctx, auto &it, auto &end) noexcept {
    if constexpr (requires { value.emplace(); }) {
      detail::from_json<Opts>(value.emplace(), ctx, it, end);
    } else if constexpr (hpp::proto::concepts::repeated_or_map<Type>) {
      constexpr bool is_map = pair_t<std::ranges::range_value_t<Type>>;
      util::parse_repeated<Opts>(is_map, hpp::proto::detail::as_modifiable(ctx, *value), ctx, it, end,
                                 [](auto &element, auto &ctx, auto &it, auto &end) {
                                   detail::from_json<ws_handled_off<Opts>()>(element, ctx, it, end);
                                 });
    } else {
      detail::from_json<Opts>(*value, ctx, it, end);
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
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    using alt_type = std::variant_alternative_t<Index, Type>;
    if constexpr (requires { value.value->template emplace<Index>(); }) {
      detail::from_json<Opts>(value.value->template emplace<Index>(), std::forward<Args>(args)...);
    } else {
      *value.value = alt_type{};
      detail::from_json<Opts>(std::get<Index>(*value.value), std::forward<Args>(args)...);
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

template <typename T>
struct from<JSON, hpp::proto::optional_message_view_ref<T>> {

  template <auto Options>
  static void op(auto value, hpp::proto::concepts::is_non_owning_context auto &ctx, auto &it, auto &end) {
    if (!util::parse_null<Options>(value, ctx, it, end)) {
      using type = std::remove_const_t<typename T::value_type>;
      void *addr = ctx.memory_resource().allocate(sizeof(type), alignof(type));
      auto *obj = new (addr) type; // NOLINT(cppcoreguidelines-owning-memory)
      constexpr auto Opts = ws_handled_off<Options>();
      parse<JSON>::op<Options>(*obj, ctx, it, end);
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

struct proto_json_opts : glz::opts {
  constexpr proto_json_opts() : glz::opts{} {}
  constexpr proto_json_opts(glz::opts op) : glz::opts(op) {}
  bool append_arrays = true;
};

template <proto_json_opts options>
struct glz_opts_t {
  using option_type = glz_opts_t<options>;
  static constexpr proto_json_opts glz_opts_value = options;
};

class message_value_cref;
class message_value_mref;
namespace concepts {
template <typename T>
concept glz_opts_t = requires { requires std::same_as<std::decay_t<decltype(T::glz_opts_value)>, proto_json_opts>; };

template <typename T>
concept write_json_supported = glz::write_supported<T, glz::JSON>;

template <typename T>
concept read_json_supported = glz::read_supported<T, glz::JSON>;

template <typename T>
concept null_terminated_str =
    // Case 1: Raw pointers (const char*) or String Literals (const char[N])
    std::convertible_to<T, const char *> ||
    // Case 2: Classes with a .c_str() member function
    requires(const T &t) {
      { t.c_str() } -> std::convertible_to<const char *>;
    };
} // namespace concepts
namespace detail {
template <typename Context, typename... Rest>
constexpr auto get_glz_opts_impl() {
  if constexpr (requires { std::decay_t<Context>::glz_opts_value; }) {
    return std::decay_t<Context>::glz_opts_value;
  } else if constexpr (sizeof...(Rest)) {
    return get_glz_opts_impl<Rest...>();
  } else {
    return proto_json_opts{};
  }
}

template <typename... Context>
constexpr auto get_glz_opts() {
  if constexpr (sizeof...(Context)) {
    return get_glz_opts_impl<Context...>();
  }
  return proto_json_opts{};
}
} // namespace detail

template <uint8_t width = 3>
constexpr auto indent_level = glz_opts_t<proto_json_opts{
    glz::opts{.error_on_unknown_keys = false, .prettify = (width > 0), .indentation_width = width}}>{};

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

  if constexpr (std::is_aggregate_v<std::decay_t<decltype(value)>>) {
    value = {};
  }
  constexpr auto opts = ::glz::set_opt<detail::get_glz_opts<decltype(option)...>(), &glz::opts::null_terminated>(
      concepts::null_terminated_str<decltype(buffer)>);

  json_context ctx{std::forward<decltype(option)>(option)...};
  return {glz::read<opts>(value, std::forward<decltype(buffer)>(buffer), ctx)};
}

inline json_status read_json(concepts::read_json_supported auto &value, const char *str,
                             concepts::is_option_type auto &&...option) {

  if constexpr (std::is_aggregate_v<std::decay_t<decltype(value)>>) {
    value = {};
  }
  constexpr auto opts = ::glz::set_opt<detail::get_glz_opts<decltype(option)...>(), &glz::opts::null_terminated>(true);
  json_context ctx{std::forward<decltype(option)>(option)...};
  return {glz::read<opts>(value, str, ctx)};
}

template <concepts::read_json_supported T>
inline auto read_json(auto &&buffer, concepts::is_option_type auto &&...option) -> std::expected<T, json_status> {
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
