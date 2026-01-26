// MIT License
//
// Copyright (c) Huang-Ming Huang
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
#include <cstddef>
#include <iterator>
#include <ranges>
#include <string>
#include <string_view>
#include <type_traits>

#include <hpp_proto/field_types.hpp>
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
struct to<JSON, std::pmr::vector<std::byte>> {
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
    if constexpr (not Opts.null_terminated) {
      if (ctx.error == error_code::end_reached) {
        ctx.error = error_code::none;
      }
    }

    if (static_cast<bool>(ctx.error)) [[unlikely]] {
      return;
    }

    using codec = typename hpp::proto::json_codec<T>::type;
    if (!codec::decode(encoded, value, ctx)) {
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
struct from<JSON, std::pmr::vector<std::byte>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto &&...args) {
    from<JSON, hpp::proto::use_base64>::template op<Opts>(std::forward<decltype(args)>(args)...);
  }
};

template <>
struct from<JSON, hpp::proto::bytes_view> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto &v, auto &ctx, auto &it, auto &end) {
    decltype(auto) mutable_v = hpp::proto::detail::as_modifiable(ctx, v);
    from<JSON, hpp::proto::use_base64>::template op<Opts>(mutable_v, ctx, it, end);
  }
};

namespace detail {
template <auto Opts>
void from_json(hpp::proto::bool_proxy value, auto &ctx, auto &it, auto &end) {
  bool v; // NOLINT(cppcoreguidelines-init-variables)
  parse<JSON>::op<Opts>(v, ctx, it, end);
  value = v;
}

template <auto Opts, typename T>
  requires std::is_enum_v<T>
void from_json(T &v, auto &ctx, auto &it, auto &end) {
  if constexpr (!check_ws_handled(Opts)) {
    if (skip_ws<Opts>(ctx, it, end)) {
      return;
    }
  }
  if (*it != '"') {
    int32_t number = 0;
    from<JSON, int32_t>::template op<ws_handled<Opts>()>(number, ctx, it, end);
    v = static_cast<T>(number);
  } else {
    from<JSON, T>::template op<ws_handled<Opts>()>(v, ctx, it, end);
  }
}

template <auto Opts, typename T>
  requires(!std::is_enum_v<T>)
void from_json(T &v, auto &ctx, auto &it, auto &end) {
  if constexpr (std::same_as<T, std::string_view>) {
    decltype(auto) mutable_v = hpp::proto::detail::as_modifiable(ctx, v);
    from<JSON, decltype(mutable_v)>::template op<Opts>(mutable_v, ctx, it, end);
  } else if constexpr (::hpp::proto::concepts::integral_64_bits<T>) {
    if constexpr (!check_ws_handled(Opts)) {
      if (skip_ws<Opts>(ctx, it, end)) {
        return;
      }
    }

    from<JSON, T>::template op<opt_true<ws_handled<Opts>(), quoted_num_opt_tag{}>>(v, ctx, it, end);
  } else if constexpr (pair_t<T>) {
    util::parse_key_and_colon<Opts>(::hpp::proto::detail::as_modifiable(ctx, v.first), ctx, it, end);
    if (bool(ctx.error)) [[unlikely]] {
      return;
    }
    from_json<ws_handled<Opts>()>(v.second, ctx, it, end);
  } else {
    from<JSON, T>::template op<Opts>(v, ctx, it, end);
  }
}
} // namespace detail

template <typename Type, auto Default>
struct to<JSON, hpp::proto::optional<Type, Default>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto const &value, auto &ctx, auto &it, auto &end) noexcept {
    if (value.has_value()) {
      if constexpr (::hpp::proto::concepts::integral_64_bits<Type>) {
        to<JSON, Type>::template op<opt_true<Opts, quoted_num_opt_tag{}>>(*value, ctx, it, end);
      } else {
        to<JSON, Type>::template op<Opts>(*value, ctx, it, end);
      }
    }
  }
};

template <typename Type, auto Default>
struct from<JSON, hpp::proto::optional<Type, Default>> {
  template <auto Options>
  GLZ_ALWAYS_INLINE static void op(auto &value, auto &ctx, auto &it, auto &end) noexcept {
    if (!util::parse_null<Options>(value, ctx, it, end)) {
      if constexpr (requires { value.emplace(); }) {
        detail::from_json<Options>(value.emplace(), ctx, it, end);
      } else {
        Type v;
        detail::from_json<Options>(v, ctx, it, end);
        value = v;
      }
    }
  }
};

template <typename Type, auto Default>
struct to<JSON, hpp::proto::optional_ref<Type, Default>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    if (bool(value)) {
      if constexpr (::hpp::proto::concepts::jsonfy_need_quote<Type>) {
        to<JSON, std::decay_t<decltype(*value)>>::template op<opt_true<Opts, quoted_num_opt_tag{}>>(
            *value, std::forward<Args>(args)...);
      } else {
        to<JSON, std::decay_t<decltype(*value)>>::template op<Opts>(*value, std::forward<Args>(args)...);
      }
    }
  }
};

template <typename Type, auto Default>
struct from<JSON, hpp::proto::optional_ref<Type, Default>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto &&value, auto &ctx, auto &it, auto &end) noexcept {
    if (!util::parse_null<Opts>(value, ctx, it, end)) {
      if constexpr (requires { value.emplace(); }) {
        detail::from_json<Opts>(value.emplace(), ctx, it, end);
      } else if constexpr (hpp::proto::concepts::repeated_or_map<Type>) {
        constexpr bool is_map = pair_t<std::ranges::range_value_t<Type>>;
        decltype(auto) v = hpp::proto::detail::as_modifiable(ctx, *value);
        util::parse_repeated<Opts>(is_map, v, ctx, it, end, [](auto &element, auto &ctx, auto &it, auto &end) {
          detail::from_json<ws_handled_off<Opts>()>(element, ctx, it, end);
        });
      } else {
        detail::from_json<Opts>(*value, ctx, it, end);
      }
    }
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
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto &&value, auto &ctx, auto &it, auto &end) noexcept {
    if (!util::parse_null<Opts>(value, ctx, it, end)) {
      using alt_type = std::variant_alternative_t<Index, Type>;
      if constexpr (requires { value.value->template emplace<Index>(); }) {
        detail::from_json<Opts>(value.value->template emplace<Index>(), ctx, it, end);
      } else {
        *value.value = alt_type{};
        detail::from_json<Opts>(std::get<Index>(*value.value), ctx, it, end);
      }
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
struct from<JSON, hpp::proto::optional_indirect_view_ref<T>> {
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
struct to<JSON, hpp::proto::optional_indirect_view_ref<Type>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto value, Args &&...args) noexcept {
    if (value.ref.has_value()) {
      to<JSON, std::decay_t<decltype(*value.ref)>>::template op<Opts>(*value.ref, std::forward<Args>(args)...);
    }
  }
};

template <typename Type, typename Alloc>
struct from<JSON, hpp::proto::indirect<Type, Alloc>> {
  template <auto Opts>
  static void op(auto &value, auto &ctx, auto &it, auto &end) {
    from<JSON, Type>::template op<Opts>(*value, ctx, it, end);
  }
};

template <typename Type, typename Alloc>
struct to<JSON, hpp::proto::indirect<Type, Alloc>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    to<JSON, Type>::template op<Opts>(*value, std::forward<Args>(args)...);
  }
};

template <typename Type>
struct from<JSON, hpp::proto::indirect_view<Type>> {
  template <auto Opts>
  static void op(auto &value, auto &ctx, auto &it, auto &end) {
    void *addr = ctx.memory_resource().allocate(sizeof(Type), alignof(Type));
    auto *obj = new (addr) Type; // NOLINT(cppcoreguidelines-owning-memory)
    value = obj;
    from<JSON, Type>::template op<Opts>(*obj, ctx, it, end);
  }
};

template <typename Type>
struct to<JSON, hpp::proto::indirect_view<Type>> {
  template <auto Opts, class... Args>
  GLZ_ALWAYS_INLINE static void op(auto &&value, Args &&...args) noexcept {
    to<JSON, Type>::template op<Opts>(*value, std::forward<Args>(args)...);
  }
};

} // namespace glz

namespace hpp::proto {
struct json_opts : glz::opts {
  bool escape_control_characters = true;
  bool prettify = false;
};

class message_value_cref;
class message_value_mref;

namespace concepts {
template <typename T>
concept write_json_supported = glz::write_supported<T, glz::JSON>;

template <typename T>
concept read_json_supported = glz::read_supported<T, glz::JSON>;

template <typename T>
concept null_terminated_str =
    std::convertible_to<T, const char *> || std::convertible_to<T, const char8_t *> || requires(T value) {
      { value.c_str() } -> std::convertible_to<const char *>;
    } || requires(T value) {
      { value.c_str() } -> std::convertible_to<const char8_t *>;
    };

template <typename T>
concept non_null_terminated_str = std::ranges::contiguous_range<T> &&
                                  (std::same_as<std::remove_cvref_t<std::ranges::range_value_t<T>>, char> ||
                                   std::same_as<std::remove_cvref_t<std::ranges::range_value_t<T>>, char8_t>) &&
                                  (!null_terminated_str<T>);
} // namespace concepts

struct [[nodiscard]] json_status final {
  glz::error_ctx ctx;
  [[nodiscard]] bool ok() const { return !static_cast<bool>(ctx); }
  [[nodiscard]] std::string message(const auto &buffer) const { return glz::format_error(ctx, buffer); }
};

/// @brief Deserializes JSON from a buffer into a message object.
/// @details Compared to glz::read, this wrapper:
///          - initializes aggregate types with default values before parsing
///          - uses hpp::proto::json_context options
///          - validates that the full buffer is consumed (trailing non-whitespace becomes syntax_error)
/// @param value The message object to populate.
/// @param buffer The input buffer containing JSON bytes.
/// @param option Optional configuration parameters.
/// @return json_status indicating success or failure.
template <auto Opts>
inline json_status read_json_buffer(concepts::read_json_supported auto &value, auto const &buffer,
                                    concepts::is_option_type auto &&...option) {
  using value_type = std::remove_cvref_t<decltype(value)>;
  static_assert(!hpp::proto::is_hpp_generated<value_type>::value || hpp::proto::has_glz<value_type>::value,
                "the generated .glz.hpp is required for hpp_gen messages");

  json_context ctx{std::forward<decltype(option)>(option)...};
  if constexpr (std::is_aggregate_v<std::decay_t<decltype(value)>>) {
    value = std::decay_t<decltype(value)>{};
  }
  json_status status = {glz::read<Opts>(value, buffer, ctx)};
  if (status.ok() && status.ctx.count < buffer.size()) {
    auto it = std::next(buffer.begin(), static_cast<std::ptrdiff_t>(status.ctx.count));
    glz::context ctx;
    glz::skip_ws<Opts>(ctx, it, buffer.end());
    status.ctx.count = static_cast<std::size_t>(std::distance(buffer.begin(), it));
    if (it < buffer.end()) {
      status.ctx.ec = glz::error_code::syntax_error;
    }
  }
  return status;
}

/// @brief Deserializes JSON from a contiguous char/char8_t range that is not null-terminated.
/// @details Unlike glz::read, this wrapper forces null_terminated=false and validates full-buffer consumption.
/// @param value The message object to populate.
/// @param buffer Contiguous range of char or char8_t that is not null-terminated.
/// @param option Optional configuration parameters.
/// @return json_status indicating success or failure.
template <auto Opts = glz::opts{}>
inline json_status read_json(concepts::read_json_supported auto &value,
                             concepts::non_null_terminated_str auto const &buffer,
                             concepts::is_option_type auto &&...option) {
  constexpr auto opts = ::glz::set_opt<Opts, &glz::opts::null_terminated>(false);
  using char_type = std::remove_cvref_t<std::ranges::range_value_t<decltype(buffer)>>;
  auto view = std::basic_string_view<char_type>{std::ranges::data(buffer), std::ranges::size(buffer)};
  return read_json_buffer<opts>(value, view, std::forward<decltype(option)>(option)...);
}

/// @brief Deserializes JSON from a null-terminated string or pointer into a message object.
/// @details Unlike glz::read, this wrapper forces null_terminated=true and validates full-buffer consumption.
/// @param value The message object to populate.
/// @param str The null-terminated string or pointer containing the JSON.
/// @param option Optional configuration parameters.
/// @return json_status indicating success or failure.
template <auto Opts = glz::opts{}>
inline json_status read_json(concepts::read_json_supported auto &value, concepts::null_terminated_str auto const& str,
                             concepts::is_option_type auto &&...option) {
  constexpr auto opts = ::glz::set_opt<Opts, &glz::opts::null_terminated>(true);
  if constexpr (requires { str.c_str(); }) {
    using char_type = std::remove_cvref_t<decltype(*str.c_str())>;
    std::basic_string_view<char_type> view{str};
    return read_json_buffer<opts>(value, view, std::forward<decltype(option)>(option)...);
  } else if constexpr (std::is_pointer_v<std::remove_cvref_t<decltype(str)>>) {
    using char_type = std::remove_cv_t<std::remove_pointer_t<std::remove_cvref_t<decltype(str)>>>;
    std::basic_string_view<char_type> view{str};
    return read_json_buffer<opts>(value, view, std::forward<decltype(option)>(option)...);
  } else {
    using char_type = std::remove_cvref_t<std::ranges::range_value_t<decltype(str)>>;
    std::basic_string_view<char_type> view{std::ranges::data(str), std::ranges::size(str)};
    return read_json_buffer<opts>(value, view, std::forward<decltype(option)>(option)...);
  }
}

/// @brief Deserializes a JSON string and returns the message object.
/// @details Unlike glz::read, this wrapper returns std::expected with json_status on failure and validates full-buffer
///          consumption.
/// @tparam T Type of the message to deserialize, must satisfy concepts::read_json_supported.
/// @param buffer The input buffer containing the JSON string.
/// @param option Optional configuration parameters.
/// @return A std::expected containing the deserialized message on success, or a json_status on failure.
template <auto Opts = glz::opts{}, concepts::read_json_supported T>
inline auto read_json(auto &&buffer, concepts::is_option_type auto &&...option) -> std::expected<T, json_status> {
  std::expected<T, json_status> result;
  if (auto status =
          read_json<Opts>(*result, std::forward<decltype(buffer)>(buffer), std::forward<decltype(option)>(option)...);
      !status.ok()) {
    result = std::unexpected(status);
  }
  return result;
}

/// @brief Serializes a message object to a JSON string in the provided buffer.
/// @details Compared to glz::write, this wrapper uses json_context, writes via detail::as_modifiable, and defaults to
///          json_opts (escape_control_characters=true) instead of glz::opts.
/// @param value The message object to serialize.
/// @param buffer The buffer to write the JSON string into.
/// @param option Optional configuration parameters.
/// @return json_status indicating success or failure.
template <auto Opts = json_opts{}>
inline json_status write_json(concepts::write_json_supported auto const &value,
                              concepts::contiguous_byte_range auto &buffer,
                              concepts::is_option_type auto &&...option) noexcept {
  using value_type = std::remove_cvref_t<decltype(value)>;
  static_assert(!hpp::proto::is_hpp_generated<value_type>::value || hpp::proto::has_glz<value_type>::value,
                "the generated .glz.hpp is required for hpp_gen messages");
  json_context ctx{std::forward<decltype(option)>(option)...};
  return {glz::write<Opts>(value, detail::as_modifiable(ctx, buffer), ctx)};
}

/// @brief Serializes a message object to a JSON string and returns the buffer.
/// @details Unlike glz::write, this wrapper returns std::expected with json_status on failure and defaults to
///          json_opts (escape_control_characters=true) instead of glz::opts.
/// @tparam Buffer The type of the buffer to return, defaults to std::string.
/// @param value The message object to serialize.
/// @param option Optional configuration parameters.
/// @return A std::expected containing the buffer on success, or a json_status on failure.
template <auto Opts = json_opts{}, concepts::contiguous_byte_range Buffer = std::string>
inline auto write_json(concepts::write_json_supported auto const &value,
                       concepts::is_option_type auto &&...option) noexcept -> std::expected<Buffer, json_status> {
  std::expected<Buffer, json_status> result;
  auto ec = write_json<Opts>(value, *result, std::forward<decltype(option)>(option)...);
  if (!ec.ok()) {
    result = std::unexpected(ec);
  }
  return result;
}

} // namespace hpp::proto
