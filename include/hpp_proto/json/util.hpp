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

#include <cassert>
#include <cstddef>
#include <hpp_proto/binpb/concepts.hpp>
#include <hpp_proto/binpb/utf8.hpp>
#include <string_view>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"
#endif
#include <glaze/glaze.hpp>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

namespace glz::util {

template <auto Opts>
bool parse_null(auto &&value, auto &ctx, auto &it, auto &end) {
  if constexpr (!check_ws_handled(Opts)) {
    if (skip_ws<Opts>(ctx, it, end)) {
      return true;
    }
  }

  if (*it == 'n') {
    ++it; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    if constexpr (not Opts.null_terminated) {
      if (it == end) [[unlikely]] {
        ctx.error = error_code::unexpected_end;
        return true;
      }
    }
    match<"ull", Opts>(ctx, it, end);
    if (bool(ctx.error)) [[unlikely]] {
      return true;
    }

    if constexpr (requires { value.set_null(); }) {
      value.set_null();
    } else {
      value.reset();
    }
    return true;
  }
  return false;
}

template <auto Opts> // NOLINTNEXTLINE(readability-function-cognitive-complexity)
[[nodiscard]] bool parse_opening(char c, glz::is_context auto &ctx, auto &it,
                                 auto &end) { // NOLINT(readability-function-cognitive-complexity)
  assert(c == '{' || c == '[');

  if constexpr (!check_opening_handled(Opts)) {
    if constexpr (!check_ws_handled(Opts)) {
      if (skip_ws<Opts>(ctx, it, end)) {
        return false;
      }
    }

    auto match_invalid_end = [](char c, auto &ctx, auto &it, [[maybe_unused]] auto &end) {
      if (*it != c) [[unlikely]] {
        if (c == '[') {
          ctx.error = error_code::expected_bracket;
        } else {
          ctx.error = error_code::expected_brace;
        }
        return true;
      } else [[likely]] {
        ++it; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      }
      if constexpr (not Opts.null_terminated) {
        if (it == end) [[unlikely]] {
          ctx.error = error_code::unexpected_end;
          return true;
        }
      }
      return false;
    };

    if (match_invalid_end(c, ctx, it, end)) {
      return false;
    }

    if constexpr (not Opts.null_terminated) {
      ++ctx.depth;
    }
  }
  return true;
}

template <auto Opts, bool ConsumeEnd = true>
bool match_ending(char c, glz::is_context auto &ctx, auto &it, auto &) {
  if (*it == c) {
    if constexpr (ConsumeEnd) {
      ++it; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      if constexpr (not Opts.null_terminated) {
        --ctx.depth;
      }
    }
    return true;
  }
  return false;
}

template <auto Opts>
void parse_integral_map_key(auto &key, glz::is_context auto &ctx, auto &it, auto &end) {
  // In google's ProtoJSON implementation, leading spaces/tabs are allowed for integer map key but not bool key.
  using key_type = std::remove_reference_t<decltype(key)>;
  if constexpr (std::same_as<key_type, bool> || std::same_as<key_type, hpp_proto::boolean>) {
    parse<JSON>::op<opt_true<ws_handled<Opts>(), quoted_num_opt_tag{}>>(key, ctx, it, end);
  } else {
    parse<JSON>::op<opt_true<ws_handled_off<Opts>(), quoted_num_opt_tag{}>>(key, ctx, it, end);
  }
}

template <auto Opts>
void parse_key_and_colon(auto &&key, glz::is_context auto &ctx, auto &it, auto &end) {
  using key_type = std::decay_t<decltype(key)>;
  if constexpr (std::is_integral_v<key_type> || std::same_as<hpp_proto::boolean, key_type>) {
    parse_integral_map_key<Opts>(key, ctx, it, end);
  } else {
    parse<JSON>::op<opt_true<Opts, quoted_num_opt_tag{}>>(key, ctx, it, end);
  }

  if (bool(ctx.error)) [[unlikely]] {
    return;
  }
  parse_ws_colon<Opts>(ctx, it, end);
}

template <auto Opts, bool ConsumeEnd = true>
/**
 * @brief Match an object end or consume a field separator, skipping whitespace as needed.
 *
 * @tparam Opts Glaze parsing options controlling whitespace, comments, and termination behavior.
 * @tparam ConsumeEnd Whether to consume the closing '}' via match_ending.
 * @param ws_start Iterator to the start of the initial whitespace after the opening '{'.
 * @param ws_size Size of that initial whitespace span; reused for a fast-path skip when unchanged.
 * @param first Tracks whether this is the first field in the object.
 * @param ctx Parsing context for error reporting.
 * @param it Current input iterator.
 * @param end Input end iterator.
 * @return true if the object ended or a terminal/error condition was encountered; false to continue parsing fields.
 */
bool match_ending_or_consume_comma(auto ws_start, size_t ws_size, bool &first, glz::is_context auto &ctx, auto &it,
                                   auto &end) {
  if (util::match_ending<Opts, ConsumeEnd>('}', ctx, it, end)) {
    if constexpr (not Opts.null_terminated) {
      if (it == end) {
        ctx.error = error_code::end_reached;
      }
    }
    return true;
  } else if (first) {
    first = false;
  } else {
    if (match_invalid_end<',', Opts>(ctx, it, end)) {
      return true;
    }

    if constexpr ((not Opts.minified) && (!Opts.comments)) {
      if (ws_size && ws_size < size_t(end - it)) {
        skip_matching_ws(ws_start, it, ws_size);
      }
    }

    if (skip_ws<Opts>(ctx, it, end)) {
      return true;
    }
  }
  return false;
}

/**
 * @brief Scan an object field list, invoking callbacks around each key.
 *
 * @tparam Opts Glaze parsing options controlling whitespace, comments, and termination behavior.
 * @tparam ConsumeEnd Whether to consume the closing '}' via match_ending_or_consume_comma.
 * @param ws_start Iterator to the start of the initial whitespace after the opening '{'.
 * @param ws_size Size of that initial whitespace span; reused for a fast-path skip when unchanged.
 * @param ctx Parsing context for error reporting.
 * @param it Current input iterator.
 * @param end Input end iterator.
 * @param key The key
 * @param on_key_start Invoked before key parsing; can update iterator-related state.
 * @param on_key Invoked after key parsing; return true to terminate scanning.
 * @param on_after_ws Invoked after trailing whitespace is skipped.
 * @return None; scanning stops by returning from the function.
 */
template <auto Options, bool ConsumeEnd>
void scan_object_fields(glz::is_context auto &ctx, auto &it, auto &end, auto &&key, auto &&on_key_start, auto &&on_key,
                        auto &&on_after_ws) {
  if (!util::parse_opening<Options>('{', ctx, it, end)) [[unlikely]] {
    return;
  }

  static constexpr auto Opts = opening_handled_off<ws_handled_off<Options>()>();
  const auto ws_start = it; // Snapshot of initial whitespace after '{' for later fast-path skipping.
  if (skip_ws<Opts>(ctx, it, end)) [[unlikely]] {
    return;
  }
  const auto ws_size = size_t(it - ws_start);
  bool first = true;
  while (true) {
    if (util::match_ending_or_consume_comma<Opts, ConsumeEnd>(ws_start, ws_size, first, ctx, it, end)) {
      return;
    }
    on_key_start(it, end);
    util::parse_key_and_colon<Opts>(key, ctx, it, end);
    if (bool(ctx.error)) [[unlikely]] {
      return;
    }
    if (on_key(it, end)) {
      return;
    }
    if (skip_ws<Opts>(ctx, it, end)) {
      return;
    }
    on_after_ws(it, end);
  }
}

template <auto Opts>
[[nodiscard]] size_t number_of_elements(char stop_token, is_context auto &ctx, auto it, auto &end) noexcept {
  skip_ws<Opts>(ctx, it, end);
  if (bool(ctx.error)) [[unlikely]] {
    return {};
  }

  if (*it == stop_token) [[unlikely]] {
    return 0;
  }
  size_t count = 1;
  while (true) {
    switch (*it) {
    case ',': {
      ++count;
      ++it; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
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
      ++it; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      skip_until_closed<Opts, '{', '}'>(ctx, it, end);
      if (bool(ctx.error)) [[unlikely]] {
        return {};
      }
      break;
    case '[':
      ++it; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
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
    case '\0': {
      ctx.error = error_code::unexpected_end;
      return {};
    }
    default:
      if (*it == stop_token) {
        return count;
      }
      ++it; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    if constexpr (!Opts.null_terminated) {
      if (it == end) {
        ctx.error = error_code::end_reached;
        return {};
      }
    }
  }
  unreachable();
}

template <auto Opts>
void from_json(hpp_proto::bool_proxy value, auto &ctx, auto &it, auto &end) {
  bool v = false;
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

void validate_utf8_if_string(auto &ctx, const auto &v) {
  if constexpr (hpp_proto::concepts::string_like<std::decay_t<decltype(v)>>) {
    if (bool(ctx.error)) [[unlikely]] {
      return;
    }
    if (!is_utf8(v.data(), v.size())) {
      ctx.error = error_code::syntax_error;
    }
  }
}

template <auto Opts, typename T>
  requires(!std::is_enum_v<T>)
void from_json(T &&v, auto &ctx, auto &it, auto &end) {

  using value_t = std::decay_t<T>;
  if constexpr (std::same_as<value_t, std::string_view>) {
    decltype(auto) mutable_v = hpp_proto::detail::as_modifiable(ctx, v);
    from<JSON, decltype(mutable_v)>::template op<Opts>(mutable_v, ctx, it, end);
  } else if constexpr (::hpp_proto::concepts::integral_64_bits<T>) {
    from<JSON, value_t>::template op<opt_true<ws_handled<Opts>(), quoted_num_opt_tag{}>>(v, ctx, it, end);
  } else if constexpr (pair_t<value_t>) {
    util::parse_key_and_colon<Opts>(::hpp_proto::detail::as_modifiable(ctx, v.first), ctx, it, end);
    validate_utf8_if_string(ctx, v.first);
    if (bool(ctx.error)) [[unlikely]] {
      return;
    }
    from_json<ws_handled<Opts>()>(v.second, ctx, it, end);
  } else {
    from<JSON, value_t>::template op<Opts>(std::forward<T>(v), ctx, it, end);
  }
  validate_utf8_if_string(ctx, v);
}

template <auto Options, typename T>
  requires(!::hpp_proto::concepts::associative_container<T>)
void parse_repeated(bool is_map, T &value, auto &ctx, auto &it, auto &end) {
  constexpr auto Opts = ws_handled_off<Options>();

  const auto opening_token = is_map ? '{' : '[';
  const auto ending_token = is_map ? '}' : ']';

  if (!util::parse_opening<Options>(opening_token, ctx, it, end)) {
    return;
  }

  if (skip_ws<Opts>(ctx, it, end)) {
    return;
  }

  const auto n = util::number_of_elements<Opts>(ending_token, ctx, it, end);
  if (bool(ctx.error)) [[unlikely]] {
    return;
  }

  auto old_size = value.size();
  const std::size_t new_size = value.size() + n;
  value.resize(new_size);

  for (auto i = old_size; i < new_size; ++i) {
    from_json<Opts>(value[i], ctx, it, end);
    if (bool(ctx.error)) [[unlikely]] {
      return;
    }

    if (skip_ws<Opts>(ctx, it, end)) {
      return;
    }

    if (i < new_size - 1) {
      if (match_invalid_end<',', Opts>(ctx, it, end)) {
        return;
      }
    }
  }

  util::match_ending<Opts>(ending_token, ctx, it, end);
}

template <auto Options, ::hpp_proto::concepts::associative_container T>
void parse_repeated(bool, T &value, auto &ctx, auto &it, auto &end) {
  typename T::key_type key;
  auto hint = value.end();
  scan_object_fields<Options, true>(
      ctx, it, end, hpp_proto::detail::as_modifiable(ctx, key), [](auto &, auto &) {},
      [&](auto &it_ref, auto &end_ref) {
        validate_utf8_if_string(ctx, key);
        if (bool(ctx.error)){
          return true;
        }
        static constexpr auto Opts = opening_handled_off<ws_handled<Options>()>();
        std::size_t size_before = value.size();
        auto it = value.try_emplace(hint, std::move(key));
        if (size_before == value.size()) {
          if constexpr (hpp_proto::concepts::indirect<typename T::mapped_type>) {
            it->second.value() = {};
          } else {
            it->second = {};
          }
        }
        from_json<Opts>(it->second, ctx, it_ref, end_ref);
        hint = it;
        return bool(ctx.error);
      },
      [](auto &, auto &) {});
}

} // namespace glz::util
