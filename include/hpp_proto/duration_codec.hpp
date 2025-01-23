// MIT License
//
// Copyright (c) 2024 Huang-Ming Huang
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
#include <hpp_proto/json_serializer.hpp>

namespace hpp::proto {
struct duration_codec {
  constexpr static std::size_t max_encode_size(const auto &) noexcept { return 32; }

  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-rvalue-reference-param-not-moved)
  static int64_t encode(auto const &value, auto &&b) noexcept {
    // NOLINTNEXTLINE(hicpp-signed-bitwise)
    auto has_same_sign = [](auto x, auto y) { return (x ^ y) >= 0; };
    if (value.nanos > 999999999 || !has_same_sign(value.seconds, value.nanos)) [[unlikely]] {
      return -1;
    }

    assert(b.size() >= max_encode_size(value));

    auto *buf = std::data(b);
    auto ix = static_cast<std::size_t>(std::distance(buf, glz::to_chars(buf, value.seconds)));

    if (value.nanos != 0) {
      int32_t nanos = std::abs(value.nanos);
      glz::detail::dump_unchecked<'.'>(b, ix);
      const auto hi = nanos / 100000000;
      b[ix++] = '0' + hi;
      glz::to_chars_u64_len_8(&b[ix], uint32_t(nanos % 100000000));
      ix += 8;
    }
    glz::detail::dump_unchecked<'s'>(b, ix);
    return static_cast<int64_t>(ix);
  }

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  static bool decode(auto const &json, auto &value) {
    if (json.empty() || json.front() == ' ' || json.back() != 's') {
      return false;
    }
    const char *beg = std::data(json);
    const char *end = beg + std::size(json) - 1; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    char *it = nullptr;

    value.seconds = std::strtoll(beg, &it, 10);
    if (it == beg) [[unlikely]] {
      return false;
    }

    if (it == end) {
      value.nanos = 0;
      return true;
    }

    if (*it != '.') {
      return false;
    }

    ++it; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

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
      if (it != std::end(nanos_buf) - 1) { // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        return false;
      }
    }

    if (value.seconds < 0) {
      value.nanos = -value.nanos;
    }
    return true;
  }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-rvalue-reference-param-not-moved)
};
} // namespace hpp::proto