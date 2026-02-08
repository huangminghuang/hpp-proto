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
#include <climits>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ranges>
#include <type_traits>

#include <hpp_proto/memory_resource_utils.hpp>

namespace hpp_proto {
enum class varint_encoding : uint8_t {
  normal,
  zig_zag,
};

template <varint_encoding Encoding = varint_encoding::normal>
constexpr auto varint_size(auto value) {
  if constexpr (Encoding == varint_encoding::zig_zag) {
    // NOLINTNEXTLINE(hicpp-signed-bitwise)
    return varint_size(std::make_unsigned_t<decltype(value)>((value << 1) ^ (value >> (sizeof(value) * CHAR_BIT - 1))));
  } else {
    return ((sizeof(value) * CHAR_BIT) -
            static_cast<unsigned>(std::countl_zero(std::make_unsigned_t<decltype(value)>(value) | 1U)) +
            (CHAR_BIT - 2)) /
           (CHAR_BIT - 1);
  }
}
template <std::integral Type, varint_encoding Encoding = varint_encoding::normal>
struct varint {
  varint() = default;
  using value_type = Type;
  using encode_type =
      std::conditional_t<std::same_as<Type, int32_t> && Encoding == varint_encoding::normal, int64_t, value_type>;
  static constexpr auto encoding = Encoding;
  // NOLINTBEGIN(hicpp-explicit-conversions)
  constexpr varint(Type value) : value(value) {}
  constexpr operator Type &() & { return value; }
  constexpr operator Type() const { return value; }
  // NOLINTEND(hicpp-explicit-conversions)

  template <typename E>
    requires(std::is_enum_v<E> && std::same_as<encode_type, int64_t> && Encoding == varint_encoding::normal)
  constexpr explicit operator E() const {
    return static_cast<E>(value);
  }

  [[nodiscard]] constexpr std::size_t encode_size() const {
    return varint_size<Encoding>(static_cast<encode_type>(value));
  }
  Type value{};
};

using vint64_t = varint<int64_t>;
using vint32_t = varint<int32_t>;

using vuint64_t = varint<uint64_t>;
using vuint32_t = varint<uint32_t>;

using vsint64_t = varint<int64_t, varint_encoding::zig_zag>;
using vsint32_t = varint<int32_t, varint_encoding::zig_zag>;

namespace concepts {
template <typename T>
concept varint = requires { requires std::same_as<T, hpp_proto::varint<typename T::value_type, T::encoding>>; };
} // namespace concepts

template <concepts::varint VarintType, concepts::byte_type Byte>
constexpr Byte *unchecked_pack_varint(VarintType item, Byte *data) {
  auto value = std::make_unsigned_t<typename VarintType::encode_type>(item.value);
  if constexpr (varint_encoding::zig_zag == decltype(item)::encoding) {
    // NOLINTNEXTLINE(hicpp-signed-bitwise)
    value = (value << 1U) ^ static_cast<decltype(value)>(item.value >> (sizeof(value) * CHAR_BIT - 1U));
  }

  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  while (value >= 0x80) {
    *data++ = Byte((value & 0x7fU) | 0x80U);
    value >>= static_cast<unsigned>(CHAR_BIT - 1);
  }
  *data++ = Byte(value);
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  return data;
}

// This function is adapted from
// https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/varint_shuffle.h
//
// It requires the input to be at least 10 valid bytes (see input buffer slope/patch invariant).
// If it is an unterminated varint,
// the function return `std::ranges::cdata(input) + std::ranges::size(input) +1`; otherwise, the function returns the
// pointer passed the consumed input data.
// NOLINTBEGIN
template <typename Type, int MAX_BYTES = ((sizeof(Type) * 8 + 6) / 7)>
constexpr auto shift_mix_parse_varint(concepts::contiguous_byte_range auto const &input,
                                      int64_t &res1) -> decltype(std::ranges::cdata(input)) {
  // The algorithm relies on sign extension for each byte to set all high bits
  // when the varint continues. It also relies on asserting all of the lower
  // bits for each successive byte read. This allows the result to be aggregated
  // using a bitwise AND. For example:
  //
  //          8       1          64     57 ... 24     17  16      9  8       1
  // ptr[0] = 1aaa aaaa ; res1 = 1111 1111 ... 1111 1111  1111 1111  1aaa aaaa
  // ptr[1] = 1bbb bbbb ; res2 = 1111 1111 ... 1111 1111  11bb bbbb  b111 1111
  // ptr[2] = 0ccc cccc ; res3 = 0000 0000 ... 000c cccc  cc11 1111  1111 1111
  //                             ---------------------------------------------
  //        res1 & res2 & res3 = 0000 0000 ... 000c cccc  ccbb bbbb  baaa aaaa
  //
  // On x86-64, a shld from a single register filled with enough 1s in the high
  // bits can accomplish all this in one instruction. It so happens that res1
  // has 57 high bits of ones, which is enough for the largest shift done.
  //
  // Just as importantly, by keeping results in res1, res2, and res3, we take
  // advantage of the superscalar abilities of the CPU.
  auto p = std::ranges::cdata(input);
  const auto next = [&p] { return static_cast<const int8_t>(*p++); };
  const auto last = [&p] { return static_cast<const int8_t>(p[-1]); };

  // Shifts "byte" left by n * 7 bits, filling vacated bits from `ones`.
  constexpr auto shl_byte = [](int n, int8_t byte, int64_t ones) constexpr -> int64_t {
    return static_cast<int64_t>((static_cast<uint64_t>(byte) << n * 7) | (static_cast<uint64_t>(ones) >> (64 - n * 7)));
  };

  constexpr auto shl_and = [shl_byte](int n, int8_t byte, int64_t ones, int64_t &res) {
    res &= shl_byte(n, byte, ones);
    return res >= 0;
  };

  constexpr auto shl = [shl_byte](int n, int8_t byte, int64_t ones, int64_t &res) {
    res = shl_byte(n, byte, ones);
    return res >= 0;
  };

  int64_t res2, res3; // accumulated result chunks

  const auto done1 = [&] {
    res1 &= res2;
    return p;
  };

  const auto done2 = [&] {
    res2 &= res3;
    return done1();
  };

  res1 = next();
  if (res1 >= 0) [[likely]] {
    return p;
  }

  // Densify all ops with explicit FALSE predictions from here on, except that
  // we predict length = 5 as a common length for fields like timestamp.
  if (shl(1, next(), res1, res2)) [[unlikely]] {
    return done1();
  }

  if (shl(2, next(), res1, res3)) [[unlikely]] {
    return done2();
  }

  if (shl_and(3, next(), res1, res2)) [[unlikely]] {
    return done2();
  }

  if constexpr (MAX_BYTES > 4) {
    if (shl_and(4, next(), res1, res3)) [[likely]] {
      return done2();
    }
  }

  if constexpr (sizeof(Type) == 8) {
    // 64 bits integers
    if (shl_and(5, next(), res1, res2)) [[unlikely]] {
      return done2();
    }

    if (shl_and(6, next(), res1, res3)) [[unlikely]] {
      return done2();
    }

    if (shl_and(7, next(), res1, res2)) [[unlikely]] {
      return done2();
    }

    if (shl_and(8, next(), res1, res3)) [[unlikely]] {
      return done2();
    }
  } else if constexpr (std::same_as<Type, int32_t>) {
    // An overlong int32 is expected to span the full 10 bytes
    if (!(next() & 0x80)) [[unlikely]] {
      return done2();
    }

    if (!(next() & 0x80)) [[unlikely]] {
      return done2();
    }

    if (!(next() & 0x80)) [[unlikely]] {
      return done2();
    }

    if (!(next() & 0x80)) [[unlikely]] {
      return done2();
    }
  }

  // For valid 64bit varints, the 10th byte/ptr[9] should be exactly 1. In this
  // case, the continuation bit of ptr[8] already set the top bit of res3
  // correctly, so all we have to do is check that the expected case is true.
  if (next() == 1) [[likely]]
    return done2();

  if (last() & 0x80) [[likely]] {
    // If the continue bit is set, it is an unterminated varint.
    return std::ranges::cdata(input) + std::ranges::size(input) + 1;
  }

  // A zero value of the first bit of the 10th byte represents an
  // over-serialized varint. This case should not happen, but if does (say, due
  // to a nonconforming serializer), deassert the continuation bit that came
  // from ptr[8].
  if (sizeof(Type) == 8 && (last() & 1) == 0) {
    constexpr int bits = 64 - 1;
    res3 ^= int64_t{1} << bits;
  }
  return done2();
}

constexpr auto unchecked_parse_bool(concepts::contiguous_byte_range auto const &input,
                                    bool &value) -> decltype(std::ranges::cdata(input)) {
  // This function is adapted from
  // https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/generated_message_tctable_lite.cc
  auto p = std::ranges::cdata(input);
  const auto next = [&p] { return static_cast<unsigned char>(*p++); };
  unsigned char byte = next();
  if (byte == 0 || byte == 1) [[likely]] {
    // This is the code path almost always taken,
    // so we take care to make it very efficient.
    if constexpr (sizeof(byte) == sizeof(value)) {
      std::memcpy(&value, &byte, 1);
    } else {
      // The C++ standard does not specify that a `bool` takes only one byte
      value = byte;
    }
    return p;
  }
  // This part, we just care about code size.
  // Although it's almost never used, we have to support it because we guarantee
  // compatibility for users who change a field from an int32 or int64 to a bool
  if (byte & 0x80) [[unlikely]] {
    byte = (byte - 0x80) | next();
    if (byte & 0x80) [[unlikely]] {
      byte = (byte - 0x80) | next();
      if (byte & 0x80) [[unlikely]] {
        byte = (byte - 0x80) | next();
        if (byte & 0x80) [[unlikely]] {
          byte = (byte - 0x80) | next();
          if (byte & 0x80) [[unlikely]] {
            byte = (byte - 0x80) | next();
            if (byte & 0x80) [[unlikely]] {
              byte = (byte - 0x80) | next();
              if (byte & 0x80) [[unlikely]] {
                byte = (byte - 0x80) | next();
                if (byte & 0x80) [[unlikely]] {
                  byte = (byte - 0x80) | next();
                  if (byte & 0x80) [[unlikely]] {
                    // We only care about the continuation bit and the first bit
                    // of the 10th byte.
                    byte = (byte - 0x80) | (next() & 0x81);
                    if (byte & 0x80) [[unlikely]] {
                      return std::ranges::cdata(input) + std::ranges::size(input) + 1;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  value = byte;
  return p;
}
// NOLINTEND

constexpr auto unchecked_parse_bool(concepts::contiguous_byte_range auto const &input,
                                    boolean &value) -> decltype(std::ranges::cdata(input)) {
  return unchecked_parse_bool(input, value.value);
}

template <concepts::varint VarintType>
constexpr auto unchecked_parse_varint(concepts::contiguous_byte_range auto const &input, VarintType &item) {
  int64_t res; // NOLINT(cppcoreguidelines-init-variables)
  if constexpr (varint_encoding::zig_zag == VarintType::encoding) {
    auto p = shift_mix_parse_varint<typename VarintType::value_type>(input, res);
    auto ures = static_cast<uint64_t>(res);
    auto sign = static_cast<int64_t>(ures & 0x1ULL);
    item = static_cast<typename VarintType::value_type>((ures >> 1U) ^ static_cast<uint64_t>(-sign));
    return p;
  } else {
    auto p = shift_mix_parse_varint<typename VarintType::value_type>(input, res);
    item = static_cast<typename VarintType::value_type>(res);
    return p;
  }
}
} // namespace hpp_proto
