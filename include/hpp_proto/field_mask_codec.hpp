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
#include <cstdint>
#include <hpp_proto/memory_resource_utils.hpp>
#include <numeric>
namespace hpp::proto {

struct field_mask_codec {
  constexpr static std::size_t max_encode_size(auto const &value) noexcept {
    return value.paths.size() + std::transform_reduce(value.paths.begin(), value.paths.end(), 0ULL, std::plus{},
                                                      [](auto &p) { return p.size(); });
  }
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  static int64_t encode(auto const &value, auto &&b) noexcept {
    if (value.paths.empty()) {
      return 0;
    }
    auto *buf = std::data(std::forward<decltype(b)>(b));
    char *cur = buf;
    cur = std::copy(std::begin(value.paths[0]), std::end(value.paths[0]), cur);
    auto rest = std::span{ value.paths.data() + 1, value.paths.size() - 1 };
    for (auto &p : rest) {
      *cur++ = ',';
      cur = std::copy(std::begin(p), std::end(p), cur);
    }
    return cur - buf;
  }

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  static bool decode(auto const &json, auto &value) {
    if (json.empty()) {
      return true;
    }
    auto is_comma = [](auto c) { return c == ','; };
    auto num_commas = std::count_if(json.begin(), json.end(), is_comma);
    value.paths.resize(static_cast<std::size_t>(num_commas + 1));
    auto cur = json.begin();
    for (auto &p : value.paths) {
      auto comma_pos = std::find_if(cur, json.end(), is_comma);
      auto &path = hpp::proto::detail::as_modifiable(value, p);
      path.assign(cur, comma_pos);
#if defined(_MSC_VER)
      if (comma_pos != json.end())
#endif
        cur = comma_pos + 1;
    }
    return true;
  }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
};
} // namespace hpp::proto