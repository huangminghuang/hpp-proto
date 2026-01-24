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
#include <span>

namespace hpp::proto {
struct duration_codec {
  constexpr static std::size_t max_encode_size(const auto &) noexcept { return 32; }

  static int64_t encode(auto const &value, auto &&b) noexcept {
    auto has_same_sign = [](auto x, auto y) { return x == 0 || y == 0 || ((x > 0) == (y > 0)); };

    if (!has_same_sign(value.seconds, value.nanos) || std::abs(value.seconds) > 315'576'000'000LL ||
        std::abs(value.nanos) > 999'999'999) {
      return -1;
    }

    assert(b.size() >= max_encode_size(value));
    bool is_negative = (value.nanos < 0 || value.seconds < 0);

    auto buffer = std::span<char>(std::data(b), b.size());
    auto* it = buffer.data();
    if (is_negative) {
      buffer[0] = '-';
      it = std::next(it);
    }

    auto positive_seconds = static_cast<uint64_t>(std::abs(value.seconds));
    it = glz::to_chars(it, positive_seconds);
    auto ix = static_cast<std::size_t>(std::distance(buffer.data(), it));

    if (value.nanos != 0) {
      auto nanos = static_cast<uint32_t>(std::abs(value.nanos));
      const auto write_3_digits = [](std::span<char> out, std::size_t &pos, uint32_t val) {
        out[pos] = static_cast<char>('0' + (val / 100));
        out[pos + 1] = static_cast<char>('0' + ((val / 10) % 10));
        out[pos + 2] = static_cast<char>('0' + (val % 10));
        pos += 3;
      };
      uint32_t ms_component = nanos / 1'000'000;
      uint32_t us_component = (nanos / 1'000) % 1'000;
      uint32_t ns_component = nanos % 1'000;

      glz::dump<'.'>(b, ix);
      std::size_t pos = ix;
      write_3_digits(buffer, pos, ms_component);
      if (ns_component != 0) {
        write_3_digits(buffer, pos, us_component);
        write_3_digits(buffer, pos, ns_component);
      } else if (us_component != 0) {
        write_3_digits(buffer, pos, us_component);
      }
      ix = pos;
    }
    glz::dump<'s'>(b, ix);
    return static_cast<int64_t>(ix);
  }

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  static bool decode(auto const &json, auto &value, [[maybe_unused]] auto &ctx) {
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

    if (value.seconds > 315'576'000'000LL) {
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
