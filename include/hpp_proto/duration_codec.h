#pragma once
#include <cstdint>
#include <cstdlib>

namespace hpp::proto {
struct duration_codec {
  constexpr static std::size_t max_encode_size(auto &&) noexcept { return 32; }

  static int64_t encode(auto &&value, auto &&b) noexcept {
    auto has_same_sign = [](auto x, auto y) { return (x ^ y) >= 0; };
    if (value.nanos > 999999999 || !has_same_sign(value.seconds, value.nanos)) [[unlikely]]
      return -1;
    char *buf = static_cast<char *>(std::data(b));
    auto ix = glz::to_chars(buf, value.seconds) - buf;
    if (value.nanos != 0) {
      int32_t nanos = std::abs(value.nanos);
      glz::detail::dump<'.'>(b, ix);
      char nanos_buf[18] = "00000000";
      char *p = nanos_buf + 8;
      p = glz::to_chars(p, nanos);
      std::memcpy(buf + ix, p - 9, 9);
      ix += 9;
    }
    glz::detail::dump<'s'>(b, ix);
    return ix;
  }

  static bool decode(auto &&josn, auto &&value) {
    if (josn.empty() || josn.front() == ' ' || josn.back() != 's')
      return false;
    const char *beg = std::data(josn);
    const char *end = beg + std::size(josn) - 1;
    char *it;

    value.seconds = std::strtoll(beg, &it, 10);
    if (it == beg) [[unlikely]] {
      return false;
    }

    if (it == end) {
      value.nanos = 0;
      return true;
    }
    if (*it++ != '.' || (end - it) > 9 || *it < '0' || *it > '9') [[unlikely]]
      return false;


    if ((end - it) == 9) [[likely]] {
      value.nanos = std::strtoul(it, &it, 10);
      if (it != end)
        return false;
    } else {
      char nanos_buf[10] = "000000000";
      std::copy(const_cast<const char *>(it), end, nanos_buf);
      value.nanos = std::strtoul(nanos_buf, &it, 10);
      if (it != std::end(nanos_buf) - 1)
        return false;
    }

    if (value.seconds < 0)
      value.nanos = -value.nanos;
    return true;
  }
};
} // namespace hpp::proto