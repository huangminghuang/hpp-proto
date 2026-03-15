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
#include <array>
#include <cstdint>
#include <glaze/util/parse.hpp>
#include <hpp_proto/memory_resource_utils.hpp>
#include <iterator>
#include <memory>
#include <numeric>
#include <span>
namespace hpp_proto {

struct field_mask_codec {
  using encoded_storage = std::string;
  static constexpr std::size_t escaped_char_size(unsigned char c) noexcept {
    if (c < 0x20U) {
      return 6;
    }
    if (c == '"' || c == '\\') {
      return 2;
    }
    return 1;
  }

  static constexpr char hex_digit(unsigned char value) noexcept {
    constexpr std::string_view hex = "0123456789abcdef";
    return hex[value]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
  }

  template <typename Out, typename It>
  static void append_char(Out value, It &cur) noexcept {
    *cur = value;
    cur = std::next(cur);
  }

  template <typename Out, typename It>
  static void append_escaped_char(unsigned char c, It &cur) noexcept {
    const auto escaped = *std::next(glz::char_escape_table.begin(), c);
    if (escaped) {
      std::memcpy(std::to_address(cur), &escaped, 2);
      cur = std::next(cur, 2);
      return;
    }
    if (c < 0x20U) {
      append_char<Out>('\\', cur);
      append_char<Out>('u', cur);
      append_char<Out>('0', cur);
      append_char<Out>('0', cur);
      append_char<Out>(hex_digit(static_cast<unsigned char>(c >> 4U)), cur);
      append_char<Out>(hex_digit(static_cast<unsigned char>(c & 0x0FU)), cur);
      return;
    }
    append_char<Out>(static_cast<Out>(c), cur);
  }

  template <typename Out, std::ranges::input_range Range, typename It>
  static void append_escaped_path(const Range &path, It &cur) noexcept {
    for (auto c : path) {
      append_escaped_char<Out>(static_cast<unsigned char>(c), cur);
    }
  }

  constexpr static std::size_t max_encode_size(auto const &value) noexcept {
    return std::transform_reduce(value.paths.begin(), value.paths.end(), value.paths.size(), std::plus{}, [](auto &p) {
      return std::transform_reduce(p.begin(), p.end(), 0ULL, std::plus{},
                                   [](auto c) { return escaped_char_size(static_cast<unsigned char>(c)); });
    });
  }
  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  static int64_t encode(auto const &value, auto &&b) noexcept {
    if (value.paths.empty()) {
      return 0;
    }
    auto buffer = std::span{std::forward<decltype(b)>(b)};
    auto cur = buffer.begin();
    using out_type = std::remove_cvref_t<decltype(*cur)>;
    append_escaped_path<out_type>(value.paths[0], cur);
    const auto rest = std::span{value.paths}.subspan(1);
    for (const auto &p : rest) {
      append_char<out_type>(',', cur);
      append_escaped_path<out_type>(p, cur);
    }
    return std::ranges::distance(buffer.begin(), cur);
  }

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  static bool decode(auto const &json, auto &value, auto &ctx) {
    if (json.empty()) {
      decltype(auto) mpaths = hpp_proto::detail::as_modifiable(ctx, value.paths);
      mpaths.resize(0);
      return true;
    }
    auto is_comma = [](auto c) { return c == ','; };
    auto num_commas = std::count_if(json.begin(), json.end(), is_comma);
    decltype(auto) mpaths = hpp_proto::detail::as_modifiable(ctx, value.paths);
    mpaths.resize(static_cast<std::size_t>(num_commas + 1));
    auto cur = json.begin();
    for (auto &p : mpaths) {
      auto comma_pos = std::find_if(cur, json.end(), is_comma);
      decltype(auto) path = hpp_proto::detail::as_modifiable(ctx, p);
      path.assign(cur, comma_pos);
      if (comma_pos != json.end()) {
        cur = std::next(comma_pos);
      }
    }
    return true;
  }
};
} // namespace hpp_proto
