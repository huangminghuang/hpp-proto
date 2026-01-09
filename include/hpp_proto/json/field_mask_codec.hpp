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
#include <cstdint>
#include <hpp_proto/memory_resource_utils.hpp>
#include <iterator>
#include <numeric>
#include <span>
namespace hpp::proto {

struct field_mask_codec {
  constexpr static std::size_t max_encode_size(auto const &value) noexcept {
    return value.paths.size() + std::transform_reduce(value.paths.begin(), value.paths.end(), 0ULL, std::plus{},
                                                      [](auto &p) { return p.size(); });
  }
  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  static int64_t encode(auto const &value, auto &&b) noexcept {
    if (value.paths.empty()) {
      return 0;
    }
    auto *buf = std::data(std::forward<decltype(b)>(b));
    auto *cur = std::copy(std::begin(value.paths[0]), std::end(value.paths[0]), buf);
    const auto rest = std::span{value.paths}.subspan(1);
    for (const auto &p : rest) {
      *cur = ',';
      cur = std::copy(std::begin(p), std::end(p), std::next(cur));
    }
    return std::distance(buf, cur);
  }

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  static bool decode(auto const &json, auto &value, auto& ctx) {
    if (json.empty()) {
      return true;
    }
    auto is_comma = [](auto c) { return c == ','; };
    auto num_commas = std::count_if(json.begin(), json.end(), is_comma);
    decltype(auto) mpaths = hpp::proto::detail::as_modifiable(ctx, value.paths);
    mpaths.resize(static_cast<std::size_t>(num_commas + 1));
    auto cur = json.begin();
    for (auto &p : mpaths) {
      auto comma_pos = std::find_if(cur, json.end(), is_comma);
      decltype(auto) path = hpp::proto::detail::as_modifiable(ctx, p);
      path.assign(cur, comma_pos);
      if (comma_pos != json.end()) {
        cur = std::next(comma_pos);
      }
    }
    return true;
  }
};
} // namespace hpp::proto
