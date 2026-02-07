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

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <ranges>
#include <vector>

#include <hpp_proto/memory_resource_utils.hpp>

namespace hpp_proto {

struct base64 {
  constexpr static std::size_t
  max_encode_size(hpp_proto::concepts::contiguous_byte_range auto const &source) noexcept {
    std::size_t n = source.size();
    return (n / 3 + (n % 3 > 0 ? 1 : 0)) * 4;
  }

  // @returns The number bytes written to b, -1 for error
  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-not-moved)
  constexpr static int64_t encode(hpp_proto::concepts::contiguous_byte_range auto const &source, auto &&b) noexcept {
    const auto n = source.size();
    using V = std::decay_t<decltype(b[0])>;
    constexpr char const base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                          "abcdefghijklmnopqrstuvwxyz"
                                          "0123456789+/";

    std::size_t i = 0;
    std::size_t ix = 0;

    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
    // Unroll loop to process 24 bytes at a time for performance
    if (n >= 24) {
      for (i = 0; i <= n - 24; i += 24) {
        // Process 8 chunks of 3 bytes
        for (std::size_t j = 0; j < 8U; ++j) {
          uint32_t x = 0;
          std::memcpy(&x, &source[i + (j * 3)], 3);

          if constexpr (std::endian::native == std::endian::little) {
            b[ix++] = static_cast<V>(base64_chars[(x >> 2U) & 0x3FU]);
            b[ix++] = static_cast<V>(base64_chars[((x << 4U) & 0x30U) | ((x >> 12U) & 0x0FU)]);
            b[ix++] = static_cast<V>(base64_chars[((x >> 6U) & 0x3CU) | ((x >> 22U) & 0x3FU)]);
            b[ix++] = static_cast<V>(base64_chars[(x >> 16U) & 0x3FU]);
          } else {
            x >>= 8U;
            b[ix + 3] = static_cast<V>(base64_chars[x & 0x3FU]);
            x >>= 6U;
            b[ix + 2] = static_cast<V>(base64_chars[x & 0x3FU]);
            x >>= 6U;
            b[ix + 1] = static_cast<V>(base64_chars[x & 0x3FU]);
            x >>= 6U;
            b[ix] = static_cast<V>(base64_chars[x & 0x3FU]);
            ix += 4;
          }
        }
      }
    }

    // Process remaining chunks of 3 bytes
    for (; i + 2 < n; i += 3) {
      uint32_t x = 0;
      std::memcpy(&x, &source[i], 3);

      if constexpr (std::endian::native == std::endian::little) {
        b[ix++] = static_cast<V>(base64_chars[(x >> 2U) & 0x3FU]);
        b[ix++] = static_cast<V>(base64_chars[((x << 4U) & 0x30U) | ((x >> 12U) & 0x0FU)]);
        b[ix++] = static_cast<V>(base64_chars[((x >> 6U) & 0x3CU) | ((x >> 22U) & 0x3FU)]);
        b[ix++] = static_cast<V>(base64_chars[(x >> 16U) & 0x3FU]);
      } else {
        x >>= 8U;
        b[ix + 3] = static_cast<V>(base64_chars[x & 0x3FU]);
        x >>= 6U;
        b[ix + 2] = static_cast<V>(base64_chars[x & 0x3FU]);
        x >>= 6U;
        b[ix + 1] = static_cast<V>(base64_chars[x & 0x3FU]);
        x >>= 6U;
        b[ix] = static_cast<V>(base64_chars[x & 0x3FU]);
        ix += 4;
      }
    }

    // Handle remaining bytes
    if (i < n) {
      auto ub1 = static_cast<uint32_t>(static_cast<unsigned char>(source[i]));
      b[ix++] = static_cast<V>(base64_chars[ub1 >> 2U]);
      if (i + 1 < n) { // 2 bytes left
        auto ub2 = static_cast<uint32_t>(static_cast<unsigned char>(source[i + 1]));
        b[ix++] = static_cast<V>(base64_chars[((ub1 & 0x03U) << 4U) | (ub2 >> 4U)]);
        b[ix++] = static_cast<V>(base64_chars[(ub2 & 0x0fU) << 2U]);
        b[ix++] = '=';
      } else { // 1 byte left
        b[ix++] = static_cast<V>(base64_chars[(ub1 & 0x03U) << 4U]);
        b[ix++] = '=';
        b[ix++] = '=';
      }
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
    return static_cast<int64_t>(ix);
  }

  constexpr static bool decode(hpp_proto::concepts::contiguous_byte_range auto const &source, auto &value, auto &ctx) {
    std::size_t n = source.size();
    decltype(auto) mref = hpp_proto::detail::as_modifiable(ctx, value);
    if (n == 0) {
      mref.resize(0);
      return true;
    }

    if (n % 4 != 0) {
      return false;
    }

    size_t len = n / 4 * 3;
    if (static_cast<char>(source[n - 1]) == '=') {
      len--;
    }
    if (static_cast<char>(source[n - 2]) == '=') {
      len--;
    }
    mref.resize(len);
    std::span decoded{mref.data(), mref.size()};
    constexpr unsigned char decode_table[] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
        13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32,
        33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};
    auto start = source.begin();
    const auto end = source.end();
    const auto read_next = [&]() {
      auto ch = static_cast<uint8_t>(*start);
      start = std::next(start);
      return ch;
    };

    size_t j = 0;
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
    while (start != end) {
      auto ch_a = read_next();
      auto ch_b = read_next();
      auto ch_c = read_next();
      auto ch_d = read_next();

      uint32_t const a = decode_table[ch_a];
      uint32_t const b = decode_table[ch_b];
      uint32_t const c = decode_table[ch_c];
      uint32_t const d = decode_table[ch_d];

      if (!validate_and_decode_quartet(a, b, c, d, ch_c, ch_d, start, end)) {
        return false;
      }

      uint32_t const triple = (a << 18U) + (b << 12U) + (c << 6U) + d;
      write_decoded_bytes(triple, decoded, j, len);
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
    return j == len;
  }

  // Helper function to validate and decode a single base64 quartet
  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  constexpr static bool validate_and_decode_quartet(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint8_t ch_c,
                                                    uint8_t ch_d, auto &source_begin, auto const &source_end) noexcept {
    if ((a | b | c | d) >= 64) {
      // Invalid character found. It might be padding.
      if (ch_d == '=' && ch_c == '=') { // XY==
        if (source_begin != source_end) {
          return false; // padding must be at the end
        }
        if (c != 64 || d != 64) {
          return false; // should not happen with '='
        }
      } else if (ch_d == '=') { // XYZ=
        if (source_begin != source_end) {
          return false;
        }
        if (d != 64) {
          return false;
        }
      } else {
        return false; // Not a valid padding sequence or invalid char
      }
    }
    return true;
  }

  // Helper function to write decoded bytes to output
  constexpr static void write_decoded_bytes(uint32_t triple, auto &value, size_t &j, size_t len) noexcept {
    using byte = std::ranges::range_value_t<decltype(value)>;

    if (j < len) {
      value[j++] = static_cast<byte>((triple >> 16U) & 0xFFU);
    }
    if (j < len) {
      value[j++] = static_cast<byte>((triple >> 8U) & 0xFFU);
    }
    if (j < len) {
      value[j++] = static_cast<byte>((triple >> 0U) & 0xFFU);
    }
  }
};

} // namespace hpp_proto
