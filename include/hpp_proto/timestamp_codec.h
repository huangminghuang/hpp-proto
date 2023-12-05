#pragma once
#include <ctime>

#if defined(_WIN32)
#include <sstream>
#include <iomanip>
#endif

#if defined(_WIN32)
  inline struct tm *gmtime_r( const time_t *timer, struct tm *buf ) {
    if(gmtime_s(buf, timer) == 0) return buf;
    return nullptr;
  }

  inline char* strptime(const char* s,
                          const char* f,
                          struct tm* tm) {
  static auto c_cocale = std::locale(setlocale(LC_ALL, nullptr));
  std::istringstream input(s);
  input.imbue(c_cocale);
  input >> std::get_time(tm, f);
  if (input.fail()) {
    return nullptr;
  }
  return (char*)(s + input.tellg());
}
#endif

struct timestamp_codec {
  constexpr static std::size_t max_encode_size(auto &&) noexcept { return std::size("yyyy-mm-ddThh:mm:ss.000000000Z"); }

  static int64_t encode(auto &&source, auto &&b) noexcept {
    if (source.nanos > 999999999) [[unlikely]]
      return -1;
    time_t sec = source.seconds;
    struct tm tm;

    if (gmtime_r(&sec, &tm) == nullptr) [[unlikely]]
      return -1;
    char *buf = static_cast<char *>(std::data(b));
    int64_t bytes_written = std::strftime(buf, std::size("yyyy-mm-ddThh:mm:ss"), "%FT%T", &tm);
    if (source.nanos > 0) {
        bytes_written += snprintf(buf + bytes_written, std::size(".000000000Z"), ".%09zuZ", static_cast<std::size_t>(source.nanos));
    } else {
        buf[bytes_written++] = 'Z';
    }
    return bytes_written;
  }

  static bool decode(auto &&source, auto &&value) {
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    const char *p = strptime(source.data(), "%FT%T", &tm);
    if (p == nullptr) [[unlikely]]
      return false;
    tm.tm_isdst = 0; // Not daylight saving
    value.seconds = std::mktime(&tm);
    value.seconds += tm.tm_gmtoff;

    auto bytes_left = source.size() - (p - source.data());

    if (source.back() != 'Z' || bytes_left > 11)
      return false;

    if (bytes_left == 1) {
      value.nanos = 0;
      return true;
    }

    if (*p++ != '.') [[unlikely]]
      return false;

    std::array<char, 10> nanos_buf;
    auto it = std::copy(p, &*(source.end() - 1), nanos_buf.begin());
    std::fill(it, nanos_buf.end() - 1, '0');
    nanos_buf.back() = '\0';
    uint64_t nanos;

    auto ix = std::find_if_not(nanos_buf.begin(), nanos_buf.end(), [](auto c) { return c == '0'; });
    auto e = glz::detail::stoui64(nanos, ix);
    if (!e || ix != nanos_buf.end()-1) [[unlikely]] {
      return false;
    }
    value.nanos = static_cast<int32_t>(nanos);
    return true;
  }
};
