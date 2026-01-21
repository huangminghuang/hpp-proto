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
#include <algorithm>
#include <cstdint>
#include <chrono>
#include <iterator>
#include <ranges>
#include <span>

namespace hpp::proto {

struct timestamp_codec {
  constexpr static std::size_t max_encode_size(auto &&) noexcept { return std::size("yyyy-mm-ddThh:mm:ss.000000000Z"); }
  template <int Len, char sep>
  static char *fixed_len_to_chars(char *buf, auto val) {
    static_assert(Len == 2 || Len == 4 || Len == 9);
    assert(val >= 0);
    if constexpr (Len == 9) {
      auto nanos = static_cast<uint32_t>(val);
      const auto write_3_digits = [](char *out, uint32_t v) {
        out[0] = static_cast<char>('0' + (v / 100));
        out[1] = static_cast<char>('0' + ((v / 10) % 10));
        out[2] = static_cast<char>('0' + (v % 10));
        return out + 3;
      };
      uint32_t ms_component = nanos / 1'000'000;
      uint32_t us_component = (nanos / 1'000) % 1'000;
      uint32_t ns_component = nanos % 1'000;
      auto *pos = buf;
      pos = write_3_digits(pos, ms_component);
      if (ns_component != 0) {
        pos = write_3_digits(pos, us_component);
        pos = write_3_digits(pos, ns_component);
      } else if (us_component != 0) {
        pos = write_3_digits(pos, us_component);
      }
      buf = pos;
    } else if constexpr (Len == 4) {
      const auto v = static_cast<uint32_t>(val);
      buf[0] = static_cast<char>('0' + (v / 1000));
      buf[1] = static_cast<char>('0' + ((v / 100) % 10));
      buf[2] = static_cast<char>('0' + ((v / 10) % 10));
      buf[3] = static_cast<char>('0' + (v % 10));
      buf = std::next(buf, 4);
    } else if constexpr (Len == 2) {
      const auto v = static_cast<uint32_t>(val);
      buf[0] = static_cast<char>('0' + (v / 10));
      buf[1] = static_cast<char>('0' + (v % 10));
      buf = std::next(buf, 2);
    }
    *buf = sep;
    return std::next(buf);
  }

  static int64_t encode(auto &&value, auto &&b) noexcept {
    if (value.nanos > 999999999 || value.nanos < 0) [[unlikely]] {
      return -1;
    }
    using namespace std::chrono;
    auto tp = sys_seconds{seconds(value.seconds)};
    auto ymd = year_month_day{floor<days>(tp)};
    auto hms = hh_mm_ss{floor<seconds>(tp) - floor<days>(tp)};

    char *buf = static_cast<char *>(std::data(b));
    buf = fixed_len_to_chars<4, '-'>(buf, (int)ymd.year());
    buf = fixed_len_to_chars<2, '-'>(buf, (unsigned)ymd.month());
    buf = fixed_len_to_chars<2, 'T'>(buf, (unsigned)ymd.day());
    buf = fixed_len_to_chars<2, ':'>(buf, hms.hours().count());
    buf = fixed_len_to_chars<2, ':'>(buf, hms.minutes().count());

    if (value.nanos > 0) {
      buf = fixed_len_to_chars<2, '.'>(buf, hms.seconds().count());
      buf = fixed_len_to_chars<9, 'Z'>(buf, value.nanos);
    } else {
      buf = fixed_len_to_chars<2, 'Z'>(buf, hms.seconds().count());
    }
    return std::distance(static_cast<char *>(std::data(b)), buf);
  }

  static bool decode(auto &&json, auto &&value, [[maybe_unused]] auto &ctx) {
    std::string_view sv = json;
    if (sv.empty() || sv.back() != 'Z') [[unlikely]] {
      return false;
    }
    sv.remove_suffix(1); // Remove 'Z'

    const char *ptr = sv.data();
    const char *end = std::next(ptr, static_cast<std::ptrdiff_t>(sv.size()));

    // NOLINTNEXTLINE(readability-isolate-declaration,cppcoreguidelines-init-variables)
    int32_t yy, mm, dd, hh, mn, ss;

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    auto parse_with_separator = [&](int32_t &val, std::ptrdiff_t width, char sep) -> bool {
      const auto remaining = std::distance(ptr, end);
      if (remaining < width) {
        return false;
      }
      const auto *const next = std::next(ptr, width);
      auto res = std::from_chars(ptr, next, val);
      if (res.ec != std::errc{} || res.ptr != next) {
        return false;
      }
      ptr = next;
      if (sep != '\0') {
        if (ptr >= end || *ptr != sep) {
          return false;
        }
        ptr = std::next(ptr);
      }
      return true;
    };

    if (!parse_with_separator(yy, 4, '-') || !parse_with_separator(mm, 2, '-') || !parse_with_separator(dd, 2, 'T') ||
        !parse_with_separator(hh, 2, ':') || !parse_with_separator(mn, 2, ':') || !parse_with_separator(ss, 2, '\0'))
        [[unlikely]] {
      return false;
    }

    using namespace std::chrono;
    value.seconds =
        (sys_days(year_month_day(year(yy), month(static_cast<unsigned>(mm)), day(static_cast<unsigned>(dd)))) +
         hours(hh) + minutes(mn) + seconds(ss))
            .time_since_epoch()
            .count();

    if (ptr == end) {
      value.nanos = 0;
      return true;
    }

    if (*ptr != '.') [[unlikely]] {
      return false;
    }
    ptr = std::next(ptr);

    std::string_view nanos_sv{ptr, static_cast<std::size_t>(std::distance(ptr, end))};
    if (nanos_sv.empty() || nanos_sv.length() > 9) [[unlikely]] {
      return false;
    }

    auto from_str_view = [](std::string_view s, auto &value) noexcept {
      const auto *begin = s.data();
      const auto *end = std::next(begin, static_cast<std::ptrdiff_t>(s.size()));
      auto r = std::from_chars(begin, end, value);
      return r.ptr == end && r.ec == std::errc();
    };

    if (!from_str_view(nanos_sv, value.nanos)) [[unlikely]] {
      return false;
    }

    // Scale nanos to 9 digits
    for (size_t i = nanos_sv.length(); i < 9; ++i) {
      value.nanos *= 10;
    }

    return true;
  }
};

} // namespace hpp::proto
