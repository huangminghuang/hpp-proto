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
#include <chrono>
#include <cstdint>
#include <iterator>
#include <ranges>
#include <span>

namespace hpp::proto {

struct timestamp_codec {
  constexpr static std::size_t max_encode_size(auto &&) noexcept { return std::size("yyyy-mm-ddThh:mm:ss.000000000Z"); }
private:
  struct separator {
    char value;
  };

  static bool parse_with_separator(const char *&ptr, const char *end, int32_t &val, std::ptrdiff_t width,
                                   separator sep) {
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
    if (sep.value != '\0') {
      if (ptr >= end || *ptr != sep.value) {
        return false;
      }
      ptr = std::next(ptr);
    }
    return true;
  }

  static bool parse_datetime(const char *&ptr, const char *end, int32_t &yy, int32_t &mm, int32_t &dd, int32_t &hh,
                             int32_t &mn, int32_t &ss) {
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    return parse_with_separator(ptr, end, yy, 4, separator{'-'}) && parse_with_separator(ptr, end, mm, 2, separator{'-'}) &&
           parse_with_separator(ptr, end, dd, 2, separator{'T'}) && parse_with_separator(ptr, end, hh, 2, separator{':'}) &&
           parse_with_separator(ptr, end, mn, 2, separator{':'}) && parse_with_separator(ptr, end, ss, 2, separator{'\0'});
  }

  static bool validate_datetime(int32_t yy, int32_t mm, int32_t dd, int32_t hh, int32_t mn, int32_t ss) {
    if (yy == 0 || mm <= 0 || dd <= 0 || hh < 0 || mn < 0 || ss < 0) {
      return false;
    }
    if (mm > 12 || hh > 23 || mn > 59 || ss > 59) {
      return false;
    }
    return true;
  }

  static bool parse_fractional_nanos(const char *ptr, const char *end, int32_t &nanos) {
    if (ptr == end) {
      nanos = 0;
      return true;
    }
    if (*ptr != '.') {
      return false;
    }
    ptr = std::next(ptr);

    std::string_view nanos_sv{ptr, static_cast<std::size_t>(std::distance(ptr, end))};
    if (nanos_sv.empty() || nanos_sv.length() > 9) {
      return false;
    }

    const auto *begin = nanos_sv.data();
    const auto *parse_end = std::next(begin, static_cast<std::ptrdiff_t>(nanos_sv.size()));
    auto r = std::from_chars(begin, parse_end, nanos);
    if (r.ptr != parse_end || r.ec != std::errc() || nanos < 0) {
      return false;
    }

    // Scale nanos to 9 digits
    for (size_t i = nanos_sv.length(); i < 9; ++i) {
      nanos *= 10;
    }
    return true;
  }

public:
  template <int Len, char sep>
  static void fixed_len_to_chars(std::span<char> buf, std::size_t &pos, auto val) {
    static_assert(Len == 2 || Len == 4 || Len == 9);
    assert(val >= 0);
    if constexpr (Len == 9) {
      auto nanos = static_cast<uint32_t>(val);
      const auto write_3_digits = [](std::span<char> out, std::size_t &pos, uint32_t v) {
        out[pos] = static_cast<char>('0' + (v / 100));
        out[pos + 1] = static_cast<char>('0' + ((v / 10) % 10));
        out[pos + 2] = static_cast<char>('0' + (v % 10));
        pos += 3;
      };
      uint32_t ms_component = nanos / 1'000'000;
      uint32_t us_component = (nanos / 1'000) % 1'000;
      uint32_t ns_component = nanos % 1'000;
      write_3_digits(buf, pos, ms_component);
      if (ns_component != 0) {
        write_3_digits(buf, pos, us_component);
        write_3_digits(buf, pos, ns_component);
      } else if (us_component != 0) {
        write_3_digits(buf, pos, us_component);
      }
    } else if constexpr (Len == 4) {
      const auto v = static_cast<uint32_t>(val);
      buf[pos] = static_cast<char>('0' + (v / 1000));
      buf[pos + 1] = static_cast<char>('0' + ((v / 100) % 10));
      buf[pos + 2] = static_cast<char>('0' + ((v / 10) % 10));
      buf[pos + 3] = static_cast<char>('0' + (v % 10));
      pos += 4;
    } else if constexpr (Len == 2) {
      const auto v = static_cast<uint32_t>(val);
      buf[pos] = static_cast<char>('0' + (v / 10));
      buf[pos + 1] = static_cast<char>('0' + (v % 10));
      pos += 2;
    }
    buf[pos] = sep;
    ++pos;
  }

  static int64_t encode(auto &&value, auto &&b) noexcept {
    if (value.nanos > 999'999'999 || value.nanos < 0) [[unlikely]] {
      return -1;
    }

    if (value.seconds < -62'135'596'800LL || value.seconds > 253'402'300'799LL) {
      return -1;
    }

    using namespace std::chrono;
    auto tp = sys_seconds{seconds(value.seconds)};
    auto ymd = year_month_day{floor<days>(tp)};
    auto hms = hh_mm_ss{floor<seconds>(tp) - floor<days>(tp)};

    auto buffer = std::span<char>(static_cast<char *>(std::data(b)), b.size());
    std::size_t pos = 0;
    fixed_len_to_chars<4, '-'>(buffer, pos, (int)ymd.year());
    fixed_len_to_chars<2, '-'>(buffer, pos, (unsigned)ymd.month());
    fixed_len_to_chars<2, 'T'>(buffer, pos, (unsigned)ymd.day());
    fixed_len_to_chars<2, ':'>(buffer, pos, hms.hours().count());
    fixed_len_to_chars<2, ':'>(buffer, pos, hms.minutes().count());

    if (value.nanos > 0) {
      fixed_len_to_chars<2, '.'>(buffer, pos, hms.seconds().count());
      fixed_len_to_chars<9, 'Z'>(buffer, pos, value.nanos);
    } else {
      fixed_len_to_chars<2, 'Z'>(buffer, pos, hms.seconds().count());
    }
    return static_cast<int64_t>(pos);
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

    if (!parse_datetime(ptr, end, yy, mm, dd, hh, mn, ss)) [[unlikely]] {
      return false;
    }

    if (!validate_datetime(yy, mm, dd, hh, mn, ss)) {
      return false;
    }

    using namespace std::chrono;
    const auto ymd = year_month_day(year(yy), month(static_cast<unsigned>(mm)), day(static_cast<unsigned>(dd)));
    if (!ymd.ok()) {
      return false;
    }
    value.seconds = (sys_days(ymd) + hours(hh) + minutes(mn) + seconds(ss)).time_since_epoch().count();

    return parse_fractional_nanos(ptr, end, value.nanos);
  }
};

} // namespace hpp::proto
