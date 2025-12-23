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

#include <cassert>
#include <cstddef>
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
    value.set_null();
    return true;
  }
  return false;
}

template <auto Opts> // NOLINTNEXTLINE(readability-function-cognitive-complexity)
GLZ_ALWAYS_INLINE bool parse_opening(char c, glz::is_context auto &ctx, auto &it,
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
      ++ctx.indentation_level;
    }
  }
  return true;
}

template <auto Opts>
bool match_ending(char c, glz::is_context auto &ctx, auto &it, auto &) {
  if (*it == c) {
    ++it; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    if constexpr (not Opts.null_terminated) {
      --ctx.indentation_level;
    }
    return true;
  }
  return false;
}

template <auto Opts>
std::string_view parse_key_and_colon(glz::is_context auto &ctx, auto &it, auto &end) {
  std::string_view key;
  parse<JSON>::op<Opts>(key, ctx, it, end);
  if (bool(ctx.error)) [[unlikely]] {
    return {};
  }

  if (parse_ws_colon<Opts>(ctx, it, end)) {
    return {};
  }
  return key;
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

template <auto Options>
GLZ_ALWAYS_INLINE void parse_repeated(bool is_map, auto &&value, auto &ctx, auto &it, auto &end,
                                      const auto &element_parser) {
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
  value.resize(n);
  size_t i = 0;

  for (auto &&x : value) {
    element_parser(x, ctx, it, end);
    if (bool(ctx.error)) [[unlikely]] {
      return;
    }

    if (skip_ws<Opts>(ctx, it, end)) {
      return;
    }
    if (i < n - 1) {
      if (match_invalid_end<',', Opts>(ctx, it, end)) {
        return;
      }
    }
    ++i;
  }

  util::match_ending<Opts>(ending_token, ctx, it, end);
}

} // namespace glz::util
