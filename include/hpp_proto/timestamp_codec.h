#pragma once
#include <chrono>

namespace hpp::proto {

struct timestamp_codec {
  constexpr static std::size_t max_encode_size(auto &&) noexcept { return std::size("yyyy-mm-ddThh:mm:ss.000000000Z"); }

  static int64_t encode(auto &&value, auto &&b) noexcept {
    if (value.nanos > 999999999) [[unlikely]]
      return -1;
    using namespace std::chrono;
    const auto seconds_in_a_day = seconds(24h).count();

    hh_mm_ss hms{seconds(value.seconds % seconds_in_a_day) + (value.seconds < 0 ? 24h : 0h)};
    year_month_day ymd{time_point<system_clock, days>(days(value.seconds / seconds_in_a_day)) -
                       (value.seconds < 0 ? days(1) : days(0))};

    char *buf = static_cast<char *>(std::data(b));
    auto dump_number_with_separator = [&buf](auto number, int number_of_digits, char separator) {
      char *cur = buf + number_of_digits;
      *cur-- = separator;
      while (cur >= buf) {
        *cur-- = '0' + (number % 10);
        number /= 10;
      }
      buf += number_of_digits + (separator != '\0');
    };

    dump_number_with_separator((int)ymd.year(), 4, '-');
    dump_number_with_separator((unsigned)ymd.month(), 2, '-');
    dump_number_with_separator((unsigned)ymd.day(), 2, 'T');
    dump_number_with_separator(hms.hours().count(), 2, ':');
    dump_number_with_separator(hms.minutes().count(), 2, ':');
    dump_number_with_separator(hms.seconds().count(), 2, '\0');

    if (value.nanos > 0) {
      *buf++ = '.';
      dump_number_with_separator(value.nanos, 9, 'Z');
    } else {
      *buf++ = 'Z';
    }
    return buf - static_cast<char *>(std::data(b));
  }

  // returns number of digits parsed
  static bool parse_decimal(int32_t &v, std::string_view str) {
    v = 0;
    for (char digit : str) {
      if (digit < '0' || digit > '9')
        return false;
      v = (v * 10) + (digit - '0');
    }
    return true;
  }

  static bool decode(auto &&json, auto &&value) {

    if (json.size() < std::size("yyyy-mm-ddThh:mm:ss") || json.size() > std::size("yyyy-mm-ddThh:mm:ss.000000000") ||
        json.back() != 'Z')
      return false;

    const char *cur = json.data();
    const char *end = json.data() + json.size() - 1;

    int32_t yy, mm, dd, hh, mn, ss;

    auto parse_digits_with_separator = [&cur](int32_t &v, std::size_t sz, char separator) {
      if (!parse_decimal(v, std::string_view{cur, sz})) [[unlikely]]
        return false;
      cur += sz;
      return separator == '\0' || *cur++ == separator;
    };

    if (!parse_digits_with_separator(yy, 4, '-') || !parse_digits_with_separator(mm, 2, '-') ||
        !parse_digits_with_separator(dd, 2, 'T') || !parse_digits_with_separator(hh, 2, ':') ||
        !parse_digits_with_separator(mn, 2, ':') || !parse_digits_with_separator(ss, 2, '\0')) [[unlikely]]
      return false;

    using namespace std::chrono;
    value.seconds = (sys_days(year_month_day(year(yy), month(mm), day(dd))) + hours(hh) + minutes(mn) + seconds(ss))
                        .time_since_epoch()
                        .count();

    if (cur == end)
      return true;

    if (*cur++ != '.') [[unlikely]]
      return false;

    std::string_view nanos_digits{cur, static_cast<std::size_t>(end - cur)};

    if (nanos_digits.size() > 9 || !parse_decimal(value.nanos, nanos_digits)) [[unlikely]]
      return false;

    static int pow10[9] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
    value.nanos *= pow10[9 - nanos_digits.size()];
    return true;
  }
};

} // namespace hpp::proto
