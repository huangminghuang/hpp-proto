#pragma once
#include <cstdint>
#include <cstdlib>
#include <hpp_proto/json_serializer.hpp>

namespace hpp::proto {
struct duration_codec {
  constexpr static std::size_t max_encode_size(const auto &) noexcept { return 32; }

  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  static int64_t encode(auto const &value, auto &&b) noexcept {
    // NOLINTBEGIN(hicpp-signed-bitwise)
    auto has_same_sign = [](auto x, auto y) { return (x ^ y) >= 0; };
    // NOLINTEND(hicpp-signed-bitwise)
    if (value.nanos > 999999999 || !has_same_sign(value.seconds, value.nanos)) [[unlikely]] {
      return -1;
    }

    assert(b.size() >= max_encode_size(value));

    auto *buf = std::data(b);
    auto ix = std::distance(buf, glz::to_chars(buf, value.seconds));

    if (value.nanos != 0) {
      int32_t nanos = std::abs(value.nanos);
      glz::detail::dump_unchecked<'.'>(b, ix);
      const auto hi = nanos / 100000000;
      b[ix++] = '0' + hi;
      glz::to_chars_u64_len_8(&b[ix], uint32_t(nanos % 100000000));
      ix += 8;
    }
    glz::detail::dump_unchecked<'s'>(b, ix);
    return ix;
  }

  static bool decode(auto const &json, auto &value) {
    if (json.empty() || json.front() == ' ' || json.back() != 's') {
      return false;
    }
    const char *beg = std::data(json);
    const char *end = beg + std::size(json) - 1;
    char *it = nullptr;

    value.seconds = std::strtoll(beg, &it, 10);
    if (it == beg) [[unlikely]] {
      return false;
    }

    if (it == end) {
      value.nanos = 0;
      return true;
    }
    
    if (*it != '.'){
      return false;
    }

    ++it;

    if ((end - it) > 9 || *it < '0' || *it > '9') [[unlikely]] {
      return false;
    }

    if ((end - it) == 9) [[likely]] {
      value.nanos = std::strtoul(it, &it, 10);
      if (it != end) {
        return false;
      }
    } else {
      char nanos_buf[10] = "000000000";
      std::copy(const_cast<const char *>(it), end, std::begin(nanos_buf));
      value.nanos = std::strtoul(&nanos_buf[0], &it, 10);
      if (it != std::end(nanos_buf) - 1) {
        return false;
      }
    }

    if (value.seconds < 0) {
      value.nanos = -value.nanos;
    }
    return true;
  }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
};
} // namespace hpp::proto