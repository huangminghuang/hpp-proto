#pragma once
#include <chrono>

namespace hpp::proto {

struct timestamp_codec {
  constexpr static std::size_t max_encode_size(auto &&) noexcept { return std::size("yyyy-mm-ddThh:mm:ss.000000000Z"); }
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)

  template <int Len, char sep>
  static char *fixed_len_to_chars(char *buf, auto val) {
    static_assert(Len == 2 || Len == 4 || Len == 9);

    assert(val >= 0);
    if constexpr (Len == 9) {
      const uint64_t hi = val / 100000000;
      assert(hi < 10);
      *buf++ = '0' + hi;
      buf = glz::to_chars_u64_len_8(buf, uint32_t(val % 100000000));
    } else if constexpr (Len == 4) {
      buf = glz::to_chars_u64_len_4(buf, uint32_t(val));
    } else if constexpr (Len == 2) {
      std::memcpy(buf, &glz::char_table[val * 2], 2);
      buf += 2;
    } 
    *buf++ = sep;
    return buf;
  }

  static int64_t encode(auto &&value, auto &&b) noexcept {
    if (value.nanos > 999999999 || value.nanos < 0) [[unlikely]] {
      return -1;
    }
    using namespace std::chrono;
    const auto seconds_in_a_day = seconds(24h).count();

    hh_mm_ss hms{seconds(value.seconds % seconds_in_a_day) + (value.seconds < 0 ? 24h : 0h)};
    year_month_day ymd{time_point<system_clock, days>(days(value.seconds / seconds_in_a_day)) -
                       (value.seconds < 0 ? days(1) : days(0))};

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
    return buf - static_cast<char *>(std::data(b));
  }

  // returns number of digits parsed
  static bool parse_decimal(int32_t &v, std::string_view str) {
    v = 0;
    for (char digit : str) {
      if (digit < '0' || digit > '9') [[unlikely]] {
        return false;
      }
      v = (v * 10) + (digit - '0');
    }
    return true;
  }

  static bool decode(auto &&json, auto &&value) {

    if (json.size() < std::size("yyyy-mm-ddThh:mm:ss") || json.size() > std::size("yyyy-mm-ddThh:mm:ss.000000000") ||
        json.back() != 'Z') [[unlikely]] {
      return false;
    }

    const char *cur = json.data();
    const char *end = json.data() + json.size() - 1;

    // NOLINTBEGIN(readability-isolate-declaration,cppcoreguidelines-init-variables)
    int32_t yy, mm, dd, hh, mn, ss;
    // NOLINTEND(readability-isolate-declaration,cppcoreguidelines-init-variables)

    // NOLINTBEGIN(bugprone-easily-swappable-parameters)
    auto parse_digits_with_separator = [&cur](int32_t &v, std::size_t sz, char separator) {
      if (!parse_decimal(v, std::string_view{cur, sz})) [[unlikely]] {
        return false;
      }
      cur += sz;
      return separator == '\0' || *cur++ == separator;
    };
    // NOLINTEND(bugprone-easily-swappable-parameters)

    if (!parse_digits_with_separator(yy, 4, '-') || !parse_digits_with_separator(mm, 2, '-') ||
        !parse_digits_with_separator(dd, 2, 'T') || !parse_digits_with_separator(hh, 2, ':') ||
        !parse_digits_with_separator(mn, 2, ':') || !parse_digits_with_separator(ss, 2, '\0')) [[unlikely]] {
      return false;
    }

    using namespace std::chrono;
    value.seconds = (sys_days(year_month_day(year(yy), month(mm), day(dd))) + hours(hh) + minutes(mn) + seconds(ss))
                        .time_since_epoch()
                        .count();

    if (cur == end) {
      return true;
    }

    if (*cur++ != '.') [[unlikely]] {
      return false;
    }

    std::string_view nanos_digits{cur, static_cast<std::size_t>(end - cur)};

    if (nanos_digits.size() > 9 || !parse_decimal(value.nanos, nanos_digits)) [[unlikely]] {
      return false;
    }

    static int pow10[9] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
    value.nanos *= pow10[9 - nanos_digits.size()];
    // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
    return true;
  }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
};

} // namespace hpp::proto
