#pragma once
#include <ctime>

#if defined(_WIN32)
#include <iomanip>
#include <sstream>
#endif

#if defined(_WIN32)
inline struct tm *gmtime_r(const time_t *timer, struct tm *buf) {
  if (gmtime_s(buf, timer) == 0)
    return buf;
  return nullptr;
}

inline char *strptime(const char *s, const char *f, struct tm *tm) {
  static auto c_cocale = std::locale(setlocale(LC_ALL, nullptr));
  std::istringstream input(s);
  input.imbue(c_cocale);
  input >> std::get_time(tm, f);
  if (input.fail()) {
    return nullptr;
  }
  return (char *)(s + input.tellg());
}
#endif

namespace hpp::proto {

struct timestamp_codec {
  constexpr static std::size_t max_encode_size(auto &&) noexcept { return std::size("yyyy-mm-ddThh:mm:ss.000000000Z"); }

  static int64_t encode(auto &&value, auto &&b) noexcept {
    if (value.nanos > 999999999) [[unlikely]]
      return -1;
    time_t sec = value.seconds;
    struct tm tm;

    if (gmtime_r(&sec, &tm) == nullptr) [[unlikely]]
      return -1;
    char *buf = static_cast<char *>(std::data(b));
    int64_t bytes_written = std::strftime(buf, std::size("yyyy-mm-ddThh:mm:ss"), "%FT%T", &tm);
    if (value.nanos > 0) {
      bytes_written +=
          snprintf(buf + bytes_written, std::size(".000000000Z"), ".%09zuZ", static_cast<std::size_t>(value.nanos));
    } else {
      buf[bytes_written++] = 'Z';
    }
    return bytes_written;
  }

  static bool decode(auto &&josn, auto &&value) {
    if (josn.empty() || josn.front() == ' ' || josn.back() != 'Z')
      return false;

    const char *cur = josn.data();
    const char *end = josn.data() + josn.size() - 1;

    struct tm tm;
    memset(&tm, 0, sizeof(tm));

    cur = strptime(cur, "%FT%T", &tm);
    if (cur == nullptr) [[unlikely]]
      return false;
    tm.tm_isdst = 0; // Not daylight saving
    value.seconds = std::mktime(&tm);
    value.seconds += tm.tm_gmtoff;
    if (cur == end) {
      value.nanos = 0;
      return true;
    }
    if (*cur++ != '.' || (end - cur) > 9 || *cur < '0' || *cur > '9') [[unlikely]]
      return false;
    char *it;
    if ((end - cur) == 9) [[likely]] {
      value.nanos = std::strtol(cur, &it, 10);
      return it == end;
    } else {
      char nanos_buf[10] = "000000000";
      std::copy(cur, end, std::begin(nanos_buf));
      value.nanos = std::strtol(nanos_buf, &it, 10);
      return it == std::end(nanos_buf) -1 ;
    }
    
  }
};

} // namespace hpp::proto
