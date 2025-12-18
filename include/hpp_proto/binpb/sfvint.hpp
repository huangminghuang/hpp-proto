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

#if defined(__x86_64__) || defined(_M_AMD64) // x64

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <bit>
#include <compare>
#include <algorithm>
#include <hpp_proto/field_types.hpp>
#include <utility>

#include <hpp_proto/binpb/concepts.hpp>
#include <hpp_proto/binpb/varint.hpp>

#if defined(__GNUC__)
#define HPP_PROTO_INLINE [[gnu::always_inline]] inline
#elifdef _MSC_VER
#pragma warning(error : 4714)
#define HPP_PROTO_INLINE __forceinline
#else
#define HPP_PROTO_INLINE inline
#endif

namespace hpp::proto {

template <concepts::varint T, typename Result>
class sfvint_parser {
  constexpr static unsigned mask_length = 6;
  constexpr static unsigned max_effective_bits = 10 * 7;
  Result *res;
  unsigned shift_bits = 0;
  uint64_t pt_val = 0;

public:
  explicit sfvint_parser(Result *data) : res(data) {}

  static consteval unsigned calc_shift_bits(unsigned sign_bits) {
    unsigned mask = 1U << (mask_length - 1);
    unsigned result = 0;
    for (; mask != 0 && static_cast<bool>(sign_bits & mask); mask >>= 1U) {
      result += 1;
    }
    return result * 7;
  }

  static consteval uint64_t calc_word_mask() {
    uint64_t result = 0x80ULL;
    for (unsigned i = 0; i < mask_length - 1; ++i) {
      result = (result << CHAR_BIT | 0x80ULL);
    }
    return result;
  }

  static constexpr auto word_mask = calc_word_mask();
  static consteval uint64_t calc_extract_mask(uint64_t sign_bits) {
    uint64_t extract_mask = 0x7fULL;
    for (int i = 0; i < std::countr_one(sign_bits); ++i) {
      extract_mask <<= CHAR_BIT;
      extract_mask |= 0x7fULL;
    }
    return extract_mask;
  }

  HPP_PROTO_INLINE void output(uint64_t v) {
    auto r = (varint_encoding::zig_zag == T::encoding) ? (v >> 1U) ^ static_cast<uint64_t>(-static_cast<int64_t>(v & 1U)) : v;
    *res++ = static_cast<Result>(r); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  }

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  static uint64_t pext_u64(uint64_t a, uint64_t mask) {
#if defined(__GNUC__) || defined(__clang__)
    uint64_t result;                                           // NOLINT(cppcoreguidelines-init-variables)
    asm("pext %2, %1, %0" : "=r"(result) : "r"(a), "r"(mask)); // NOLINT(hicpp-no-assembler)
    return result;
#else
    return _pext_u64(a, mask);
#endif
  }

  template <uint64_t SignBits, unsigned I>
  void output(uint64_t word, uint64_t &extract_mask) {
    if constexpr (I < mask_length) {
      extract_mask |= 0x7fULL << (CHAR_BIT * I);
      // NOLINTBEGIN(misc-redundant-expression)
      if constexpr ((SignBits & (0x01ULL << I)) == 0) {
        output(pext_u64(word, extract_mask));
        extract_mask = 0;
      }
      // NOLINTEND(misc-redundant-expression)
      output<SignBits, I + 1>(word, extract_mask);
    }
  }

  template <uint64_t SignBits>
  HPP_PROTO_INLINE bool fixed_masked_parse(uint64_t word) {
    uint64_t extract_mask = calc_extract_mask(SignBits);
    if constexpr (std::cmp_less(std::countr_one(SignBits), mask_length)) {
      output((pext_u64(word, extract_mask) << shift_bits) | pt_val);
      constexpr unsigned bytes_processed = std::countr_one(SignBits) + 1;
      extract_mask = 0x7fULL << (CHAR_BIT * bytes_processed);
      output<SignBits, bytes_processed>(word, extract_mask);
      pt_val = 0;
      shift_bits = 0;
    }

    if constexpr (SignBits & (0x01ULL << (mask_length - 1))) {
      pt_val |= pext_u64(word, extract_mask) << shift_bits;
    }

    shift_bits += calc_shift_bits(SignBits);
    return shift_bits < std::min<unsigned>(max_effective_bits, sizeof(uint64_t) * CHAR_BIT);
  }

  template <std::size_t... I>
  HPP_PROTO_INLINE bool parse_word(uint64_t masked_bits, uint64_t word, std::index_sequence<I...>) {
    return ((masked_bits == I && fixed_masked_parse<I>(word)) || ...);
  }

  auto parse_partial(concepts::contiguous_byte_range auto const &r) -> decltype(std::ranges::cdata(r)) {
    auto begin = std::ranges::cdata(r);
    auto end = std::ranges::cend(r);
    end -= (std::ranges::size(r) % mask_length);
    for (; begin < end; begin += mask_length) {
      uint64_t word = 0;
      std::memcpy(&word, begin, mask_length);
      auto mval = pext_u64(word, word_mask);
      if (!parse_word(mval, word, std::make_index_sequence<1U << mask_length>())) {
        return nullptr;
      }
    }
    return begin;
  }

  auto parse(concepts::contiguous_byte_range auto const &r) -> decltype(std::ranges::cdata(r)) {
    auto end = std::ranges::cend(r);

    auto begin = parse_partial(r);
    if (begin == nullptr) [[unlikely]] {
      return nullptr;
    }

    std::ptrdiff_t bytes_left = end - begin;
    uint64_t word = 0;
    std::memcpy(&word, begin, static_cast<std::size_t>(bytes_left));

    for (; bytes_left > 0; --bytes_left, word >>= CHAR_BIT) {
      pt_val |= ((word & 0x7fULL) << shift_bits);
      if ((word & 0x80ULL) != 0) {
        shift_bits += (CHAR_BIT - 1);
        if (shift_bits >= std::min<unsigned>(max_effective_bits, sizeof(uint64_t) * CHAR_BIT)) [[unlikely]] {
          return nullptr;
        }
      } else {
        output(pt_val);
        pt_val = 0;
        shift_bits = 0;
      }
    }
    return end;
  }
};

template <bool v>
struct enable_sfvint_parser_t {
  using option_type = enable_sfvint_parser_t<v>;
  static constexpr auto enable_sfvint_parser = v;
};

template <bool v>
constexpr auto enable_sfvint_parser = enable_sfvint_parser_t<v>{};

template <concepts::is_pb_context Context>
constexpr bool sfvint_parser_allowed() {
  if constexpr (requires { Context::enable_sfvint_parser; }) {
    return Context::enable_sfvint_parser;
  } else {
    return true;
  }
}

} // namespace hpp::proto
#undef HPP_PROTO_INLINE
#endif

