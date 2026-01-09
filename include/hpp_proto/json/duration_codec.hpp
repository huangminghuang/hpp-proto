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
#include <cstdlib>
#include <hpp_proto/json.hpp>
#include <iterator>

namespace hpp::proto {
struct duration_codec {
  constexpr static std::size_t max_encode_size(const auto &) noexcept { return 32; }

  static int64_t encode(auto const &value, auto &&b) noexcept {
    auto has_same_sign = [](auto x, auto y) { return y == 0 || (x < 0) == (y < 0); };
    if (value.nanos > 999999999 || !has_same_sign(value.seconds, value.nanos)) [[unlikely]] {
      return -1;
    }

    assert(b.size() >= max_encode_size(value));

    auto *buf = std::data(b);
    auto ix = static_cast<std::size_t>(std::distance(buf, glz::to_chars(buf, value.seconds)));

    if (value.nanos != 0) {
      int32_t nanos = std::abs(value.nanos);
      glz::dump<'.'>(b, ix);
      const auto hi = nanos / 100000000;
      b[ix++] = '0' + hi;
      auto *pos = std::next(buf, static_cast<std::ptrdiff_t>(ix));
      glz::to_chars_u64_len_8(pos, uint32_t(nanos % 100000000));
      ix += 8;
    }
    glz::dump<'s'>(b, ix);
    return static_cast<int64_t>(ix);
  }

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  static bool decode(auto const &json, auto &value, [[maybe_unused]] auto& ctx) {
    std::string_view s = json;
    if (s.empty() || s.back() != 's') {
      return false;
    }
    s.remove_suffix(1); // Remove the 's'

    bool is_negative = false;
    if (s.starts_with('-')) {
      is_negative = true;
      s.remove_prefix(1);
    }

    auto from_str_view = [](std::string_view s, auto &value) noexcept {
      const auto *begin = s.data();
      const auto *end = std::next(begin, static_cast<std::ptrdiff_t>(s.size()));
      auto r = std::from_chars(begin, end, value);
      return r.ptr == end && r.ec == std::errc();
    };

    auto point_pos = s.find('.');
    if (!from_str_view(s.substr(0, point_pos), value.seconds)) {
      return false;
    }

    if (point_pos == std::string_view::npos) {
      value.nanos = 0;
    } else {
      std::string_view nanos_str = s.substr(point_pos + 1);
      if (nanos_str.starts_with('-') || nanos_str.length() > 9) {
        return false;
      }
      if (!from_str_view(nanos_str, value.nanos)) {
        return false;
      }
      // Scale nanos to 9 digits
      for (size_t i = nanos_str.length(); i < 9; ++i) {
        value.nanos *= 10;
      }
    }

    if (is_negative) {
      value.seconds = -value.seconds;
      value.nanos = -value.nanos;
    }
    return true;
  }
};
} // namespace hpp::proto
