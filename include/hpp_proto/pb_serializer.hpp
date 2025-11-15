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
#include <array>
#include <bit>
#include <cassert>
#include <climits>
#include <concepts>
#include <cstddef>
#include <cstring>

#include <expected>
#include <iterator>
#include <map>
#include <memory>
#include <numeric>
#include <system_error>
#include <type_traits>
#include <utility>

#include <hpp_proto/memory_resource_utils.hpp>

#if defined(__x86_64__) || defined(_M_AMD64) // x64
#ifdef _WIN32
#include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif
#endif

#ifdef __GNUC__
#define HPP_PROTO_INLINE [[gnu::always_inline]] inline
#elifdef _MSC_VER
#pragma warning(error : 4714)
#define HPP_PROTO_INLINE __forceinline
#else
#define HPP_PROTO_INLINE inline
#endif

extern "C" {
bool is_utf8(const char *src, size_t len);
}

namespace hpp::proto {
using std::expected;
using std::unexpected;

constexpr bool utf8_validation_failed(auto meta, const auto &str) {
#if HPP_PROTO_NO_UTF8_VALIDATION
  [[maybe_unused]] meta;
  [[maybe_unused]] str;
#else
  if constexpr (meta.requires_utf8_validation()) {
    if (!std::is_constant_evaluated()) {
      return !::is_utf8(str.data(), str.size());
    }
  }
#endif
  return false;
}

/////////////////////////////////////////////////////

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
      std::conditional_t<std::is_same_v<Type, int32_t> && Encoding == varint_encoding::normal, int64_t, value_type>;
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

template <template <typename Traits> class Message, typename Traits>
auto rebind_traits(Message<Traits>) -> Message<default_traits>;

////////////////////////////////////////////////////
namespace concepts {

template <typename T>
concept is_enum = std::is_enum_v<T> && !std::same_as<std::byte, T>;

template <typename T>
concept is_boolean = std::same_as<hpp::proto::boolean, T>;

template <typename T>
concept is_empty = std::is_empty_v<T>;

template <typename T>
concept varint = requires { requires std::same_as<T, hpp::proto::varint<typename T::value_type, T::encoding>>; };

template <typename T>
concept associative_container =
    std::ranges::range<T> && requires(T container) { typename std::remove_cvref_t<T>::key_type; };

template <typename T>
concept tuple = !std::ranges::range<T> && requires(T tuple) { sizeof(std::tuple_size<std::remove_cvref_t<T>>); };

template <typename T>
concept variant = requires(T variant) {
  variant.index();
  std::get_if<0>(&variant);
  std::variant_size_v<std::remove_cvref_t<T>>;
};

template <typename T>
concept string_value_type = std::same_as<T, char> || std::same_as<T, char8_t>;

template <typename T>
concept repeated = std::ranges::contiguous_range<T> && !byte_type<typename T::value_type>;

template <typename T>
concept basic_string_view = requires {
  typename T::value_type;
  requires string_value_type<typename T::value_type>;
  requires std::same_as<T, std::basic_string_view<typename T::value_type, std::char_traits<typename T::value_type>>>;
};

template <typename T>
concept basic_string = requires {
  typename T::value_type;
  typename T::allocator_type;
  requires string_value_type<typename T::value_type>;
  requires std::same_as<T, std::basic_string<typename T::value_type, std::char_traits<typename T::value_type>,
                                             typename T::allocator_type>>;
};

template <typename T>
concept string_like = basic_string_view<T> || basic_string<T>;

template <typename T>
concept has_local_meta = concepts::tuple<typename std::decay_t<T>::pb_meta>;

template <typename T>
concept has_explicit_meta = concepts::tuple<decltype(pb_meta(std::declval<T>()))>;

template <typename T>
concept has_meta = has_local_meta<T> || has_explicit_meta<T>;

template <typename T>
concept dereferenceable = requires(T item) { *item; };

template <typename T>
concept optional_message_view = std::same_as<T, ::hpp::proto::optional_message_view<typename T::value_type>>;

template <typename T>
concept oneof_type = concepts::variant<T>;

template <typename T>
concept arithmetic = std::is_arithmetic_v<T> || concepts::varint<T>;

template <typename T>
concept singular = arithmetic<T> || is_enum<T> || basic_string<T> || contiguous_byte_range<T>;

template <typename T>
concept is_map_entry = requires {
  typename T::key_type;
  typename T::mapped_type;
};

template <typename T>
concept is_pair = std::same_as<T, std::pair<typename T::first_type, typename T::second_type>>;

template <typename T>
concept span = requires {
  typename T::element_type;
  requires std::derived_from<T, std::span<typename T::element_type>> || concepts::basic_string_view<T>;
};

template <typename T>
concept is_oneof_field_meta = requires { typename T::alternatives_meta; };

template <typename T>
concept byte_deserializable = (std::is_arithmetic_v<T> && !std::same_as<T, bool>) || std::same_as<std::byte, T>;

template <typename T>
concept is_size_cache_iterator = requires(T v) {
  { v++ } -> std::same_as<T>;
  *v;
};

template <typename T>
concept non_owning_bytes =
    basic_string_view<std::remove_cvref_t<T>> ||
    (concepts::dynamic_sized_view<std::remove_cvref_t<T>> && concepts::byte_type<typename T::value_type>);

template <typename T>
concept has_extension = has_meta<T> && requires(T value) { value.extensions; };

template <typename T>
concept pb_extensions = requires {
  typename T::unknown_fields_range_t::value_type;
  requires is_pair<typename T::unknown_fields_range_t::value_type>;
};

template <typename T>
concept pb_unknown_fields = requires { typename T::unknown_fields_range_t; } && !pb_extensions<T>;

template <typename T>
concept has_unknown_fields_or_extensions = has_meta<T> && requires(T value) {
  value.pb_unknown_fields_;
  requires pb_unknown_fields<decltype(value.pb_unknown_fields_)> || pb_extensions<decltype(value.pb_unknown_fields_)>;
};

template <typename T>
concept no_cached_size = is_enum<T> || byte_serializable<T> || concepts::varint<T> || pb_unknown_fields<T> ||
                         pb_extensions<T> || std::is_empty_v<T>;

template <typename T>
concept is_basic_in = requires { typename T::is_basic_in; };

template <typename T>
concept is_basic_out = requires { typename T::is_basic_out; };

template <typename Range>
concept segmented_byte_range =
    std::ranges::random_access_range<Range> && contiguous_byte_range<std::ranges::range_value_t<Range>>;

template <typename Range>
concept input_byte_range = segmented_byte_range<Range> || contiguous_byte_range<Range>;

template <typename R>
concept uint32_pair_contiguous_range = std::ranges::contiguous_range<R> && is_pair<std::ranges::range_value_t<R>> &&
                                       std::same_as<typename std::ranges::range_value_t<R>::first_type, std::uint32_t>;

template <typename T, typename U>
concept isomorphic_message =
    requires(T t, U u) { requires std::same_as<decltype(rebind_traits(t)), decltype(rebind_traits(u))>; };
} // namespace concepts

template <concepts::is_size_cache_iterator Iterator>
constexpr decltype(auto) consume_size_cache_entry(Iterator &iterator) {
  decltype(auto) entry = *iterator;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  iterator++;
  return entry;
}

////////////////////

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
// It requires the input to be at least 10 valid bytes. If it is an unterminated varint,
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

///////////////////

enum class field_option : uint8_t {
  none = 0,
  explicit_presence = 1,
  is_packed = 2,
  group = 4,
  utf8_validation = 8,
  closed_enum = 16
};

constexpr uint8_t option_mask(field_option option) { return static_cast<uint8_t>(option); }

template <typename T>
constexpr bool has_option(T value, field_option option) {
  using unsigned_value_t = std::make_unsigned_t<std::remove_cv_t<T>>;
  return (static_cast<unsigned_value_t>(value) & option_mask(option)) != 0U;
}

constexpr field_option operator|(field_option lhs, field_option rhs) {
  return static_cast<field_option>(option_mask(lhs) | option_mask(rhs));
}

constexpr field_option operator&(field_option lhs, field_option rhs) {
  return static_cast<field_option>(option_mask(lhs) & option_mask(rhs));
}

constexpr field_option &operator|=(field_option &lhs, field_option rhs) {
  lhs = lhs | rhs;
  return lhs;
}

template <auto Accessor>
struct accessor_type {
  constexpr decltype(auto) operator()(auto &&item) const {
    if constexpr (std::is_member_pointer_v<decltype(Accessor)>) {
      return std::forward<decltype(item)>(item).*Accessor;
    } else {
      return Accessor(std::forward<decltype(item)>(item));
    }
  }
};

template <uint32_t Number, uint8_t FieldOptions, typename Type, auto DefaultValue>
struct field_meta_base {
  constexpr static uint32_t number = Number;
  constexpr static auto default_value = unwrap(DefaultValue);

  using type = Type;

  constexpr static bool is_packed() { return has_option(FieldOptions, field_option::is_packed); }
  constexpr static bool explicit_presence() { return has_option(FieldOptions, field_option::explicit_presence); }
  constexpr static bool requires_utf8_validation() { return has_option(FieldOptions, field_option::utf8_validation); }
  constexpr static bool is_delimited() { return has_option(FieldOptions, field_option::group); }
  constexpr static bool closed_enum() { return has_option(FieldOptions, field_option::closed_enum); }

  constexpr static bool valid_enum_value(auto value) {
    if constexpr (closed_enum()) {
      return is_valid(value);
    }
    return false;
  }

  template <typename T>
  static constexpr bool omit_value(const T &v) {
    if constexpr (!has_option(FieldOptions, field_option::explicit_presence)) {
      return is_default_value<T, DefaultValue>(v);
    } else if constexpr (requires { v.has_value(); }) {
      return !v.has_value();
    } else if constexpr (requires {
                           typename T::element_type;
                           v.get();
                         }) {
      return v.get() == nullptr;
    } else {
      return false;
    }
  }
};

template <uint32_t Number, auto Accessor, auto FieldOptions = option_mask(field_option::none), typename Type = void,
          auto DefaultValue = std::monostate{}>
struct field_meta : field_meta_base<Number, static_cast<uint8_t>(FieldOptions), Type, DefaultValue> {
  constexpr static auto access = accessor_type<Accessor>{};
};

template <auto Accessor, typename... AlternativeMeta>
struct oneof_field_meta {
  constexpr static auto access = accessor_type<Accessor>{};
  constexpr static bool explicit_presence() { return false; }
  using alternatives_meta = std::tuple<AlternativeMeta...>;
  using type = void;
  template <typename T>
  static constexpr bool omit_value(const T &v) {
    return v.index() == 0;
  }
  static alternatives_meta alternatives() { return alternatives_meta{}; }
};

struct [[nodiscard]] status {
  std::errc ec = {};

  constexpr status() noexcept = default;
  constexpr ~status() noexcept = default;
  constexpr status(const status &) noexcept = default;
  constexpr status(status &&) noexcept = default;

  // NOLINTBEGIN(hicpp-explicit-conversions)
  constexpr status(std::errc e) noexcept : ec(e) {}
  constexpr operator std::errc() const noexcept { return ec; }
  // NOLINTEND(hicpp-explicit-conversions)

  constexpr status &operator=(const status &) noexcept = default;
  constexpr status &operator=(status &&) noexcept = default;

  [[nodiscard]] constexpr bool ok() const noexcept { return ec == std::errc{}; }
};

enum class wire_type : uint8_t {
  varint = 0,
  fixed_64 = 1,
  length_delimited = 2,
  sgroup = 3,
  egroup = 4,
  fixed_32 = 5,
};

template <typename Type>
constexpr auto tag_type() {
  using type = std::remove_cvref_t<Type>;
  if constexpr (concepts::varint<type> || concepts::is_enum<type> || std::same_as<type, bool> ||
                std::same_as<type, boolean>) {
    return wire_type::varint;
  } else if constexpr (std::is_integral_v<type> || std::is_floating_point_v<type>) {
    if constexpr (sizeof(type) == 4) {
      return wire_type::fixed_32;
    } else if constexpr (sizeof(type) == 8) {
      return wire_type::fixed_64;
    } else {
      static_assert(!sizeof(type));
    }
  } else {
    return wire_type::length_delimited;
  }
}

constexpr auto make_tag(uint32_t number, wire_type type) {
  return varint{(number << 3U) | std::underlying_type_t<wire_type>(type)};
}

template <typename Type, typename Meta>
constexpr auto make_tag(const Meta &meta) {
  return make_tag(meta.number, tag_type<Type>());
}

constexpr auto tag_type(uint32_t tag) { return wire_type(tag & 7U); }

constexpr auto tag_number(uint32_t tag) { return (tag >> 3U); }

template <typename Meta>
constexpr bool has_field_num(Meta meta, uint32_t num) {
  if constexpr (requires { meta.number; }) {
    return meta.number == num;
  } else if constexpr (concepts::is_oneof_field_meta<Meta>) {
    return std::apply([num](auto... elem) { return (has_field_num(elem, num) || ...); },
                      typename Meta::alternatives_meta{});
  } else {
    return false;
  }
}

template <typename T>
struct serialize_type {
  using type = T;
  using read_type = const T &;
  using convertible_type = const T &;
};

template <concepts::is_enum T>
struct serialize_type<T> {
  using type = vint64_t;
  using read_type = vint64_t;
  using convertible_type = std::underlying_type_t<T>;
};

template <concepts::varint T>
struct serialize_type<T> {
  using type = T;
  using read_type = T;
  using convertible_type = T;
};

template <>
struct serialize_type<bool> {
  using type = boolean;
  using read_type = boolean;
  using convertible_type = boolean;
};

template <typename KeyType, typename MappedType, field_option KeyOptions = field_option::none,
          field_option MappedOptions = field_option::none>
struct map_entry {
  using key_type = KeyType;
  using mapped_type = MappedType;
  struct mutable_type {
    typename serialize_type<KeyType>::type key = {};
    typename serialize_type<MappedType>::type value = {};
    constexpr static bool allow_inline_visit_members_lambda = true;
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
    using pb_meta = std::tuple<field_meta<1, &mutable_type::key, field_option::explicit_presence | KeyOptions>,
                               field_meta<2, &mutable_type::value, field_option::explicit_presence | MappedOptions>>;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4244)
#endif
    template <typename K, typename V>
    explicit operator std::pair<K, V>() && {
      return {std::move(static_cast<K>(key)), std::move(static_cast<V>(value))};
    }
#ifdef _MSC_VER
#pragma warning(pop)
#endif
  };

  struct read_only_type {
    typename serialize_type<KeyType>::read_type key;
    typename serialize_type<MappedType>::read_type value;
    constexpr static bool allow_inline_visit_members_lambda = true;

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    constexpr read_only_type(auto &k, auto &v)
        : key((typename serialize_type<KeyType>::convertible_type)k),
          value((typename serialize_type<MappedType>::convertible_type)v) {}
    ~read_only_type() = default;
    read_only_type(const read_only_type &) = delete;
    read_only_type(read_only_type &&) = delete;
    read_only_type &operator=(const read_only_type &) = delete;
    read_only_type &operator=(read_only_type &&) = delete;

    struct key_accessor {
      constexpr const auto &operator()(const read_only_type &entry) const { return entry.key; }
    };

    struct value_accessor {
      constexpr const auto &operator()(const read_only_type &entry) const { return entry.value; }
    };
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
    using pb_meta = std::tuple<field_meta<1, key_accessor{}, field_option::explicit_presence | KeyOptions>,
                               field_meta<2, value_accessor{}, field_option::explicit_presence | MappedOptions>>;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
  };
};

namespace traits {
template <typename Type>
struct meta_of;

template <concepts::has_local_meta Type>
struct meta_of<Type> {
  using type = typename Type::pb_meta;
};

template <concepts::has_explicit_meta Type>
struct meta_of<Type> {
  using type = decltype(pb_meta(std::declval<Type>()));
};

template <concepts::has_meta Type, std::size_t Index>
struct field_meta_of {
  using type = typename std::tuple_element_t<Index, typename meta_of<Type>::type>;
};

template <typename Meta, typename Type>
struct get_serialize_type;

template <typename Meta, typename Type>
  requires requires { typename Meta::type; }
struct get_serialize_type<Meta, Type> {
  using type = std::conditional_t<std::is_same_v<typename Meta::type, void>, Type, typename Meta::type>;
};

template <typename Meta, typename Type>
using get_map_entry = typename Meta::type;

template <typename T, std::size_t M, std::size_t N>
constexpr std::array<T, M + N> operator<<(std::array<T, M> lhs, std::array<T, N> rhs) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
  std::array<T, M + N> result;
  std::copy(lhs.begin(), lhs.end(), result.begin());
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  std::copy(rhs.begin(), rhs.end(), result.begin() + M);
  return result;
}

template <auto Num>
constexpr auto make_integral_constant() {
  return std::integral_constant<decltype(Num), Num>();
}

template <concepts::has_meta Type>
struct reverse_indices {
  template <typename T>
    requires requires { T::number; }
  constexpr static auto get_numbers(T meta) {
    if constexpr (meta.number != UINT32_MAX) {
      return std::array<std::uint32_t, 1>{meta.number};
    } else {
      return std::array<std::uint32_t, 0>{};
    }
  }

  template <typename... T>
  constexpr static auto get_numbers(std::tuple<T...> metas) {
    if constexpr (sizeof...(T) > 0) {
      return std::apply([](auto... elem) { return (... << get_numbers(elem)); }, metas);
    } else {
      return std::array<std::uint32_t, 0>{};
    }
  }

  template <concepts::is_oneof_field_meta Meta>
  constexpr static auto get_numbers(Meta /* unused */) {
    return std::apply([](auto... elem) { return (... << get_numbers(elem)); }, typename Meta::alternatives_meta{});
  }

  template <std::size_t I, typename T>
    requires requires { T::number; }
  constexpr static auto index(T) {
    return std::array{I};
  }

  template <std::size_t I, concepts::is_oneof_field_meta Meta>
  constexpr static auto index(Meta) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
    std::array<std::size_t, std::tuple_size_v<typename Meta::alternatives_meta>> result;
    std::fill(result.begin(), result.end(), I);
    return result;
  }

  constexpr static auto get_indices(std::index_sequence<>) { return std::array<std::size_t, 0>{}; }

  template <std::size_t FirstIndex, std::size_t... Indices>
  constexpr static auto get_indices(std::index_sequence<FirstIndex, Indices...>, auto first_elem, auto... elems) {
    return index<FirstIndex>(first_elem) << get_indices(std::index_sequence<Indices...>{}, elems...);
  }

  template <typename... T>
  constexpr static auto get_indices(std::tuple<T...> metas) {
    return std::apply([](auto... elem) { return get_indices(std::make_index_sequence<sizeof...(T)>(), elem...); },
                      metas);
  }

  // field_numbers is an array of field numbers in the order of the fields declared in the respective protobuf message.
  // Notice that members of oneof fields will be included; therefore field_numbers.size() > number_of_fields when there
  // are oneof fields in the respective protobuf message.
  constexpr static auto field_numbers = get_numbers(typename traits::meta_of<Type>::type{});

  // the field indices corresponding to field_numbers. For example, given the following message definition
  //
  //  message SampleMessage {
  //    int32 id = 1;
  //    oneof test_oneof {
  //      string name = 4;
  //      SubMessage sub_message = 9;
  //    }
  //    bytes data = 20;
  //  }
  //
  //  number_of_fields will be 3.
  //  field_numbers will be { 1, 4, 9, 20}
  //  field_indices will be { 0, 1, 1,  2}
  //
  constexpr static auto field_indices = get_indices(typename traits::meta_of<Type>::type{});
  // the number of fields in a message
  constexpr static auto number_of_fields = field_indices.size() ? field_indices.back() + 1 : 0;

  // During protobuf deserialization, it is necessary to find the field index associated with a given field number. To
  // achieve efficient lookup, a two-level lookup table is created and indexed by "masked numbers". The "masked number"
  // is computed by performing a bitwise OR operation between the field number and a mask. This mask is determined by
  // finding the smallest power of 2 that is greater than the number of fields and then subtracting 1. For instance,
  // given the field numbers in SampleMessage as {1, 4, 9, 20}, the resulting masked numbers would be {1, 0, 1, 0}.
  //
  // Following this, a masked_lookup_table is constructed, consisting of pairs of field numbers and their corresponding
  // field indices, sorted based on the masked numbers. For SampleMessage, the masked_lookup_table would appear as
  // {{1, 0}, {9, 1}, {4, 1}, {20, 2}}.
  //
  // Additionally, the masked_lookup_table_offsets are created as an array that points to
  // the indices of the masked_lookup_table, indexed by the "masked numbers". In the SampleMessage example, the
  // masked_lookup_table_offsets would be {0, 2, 4, 4, 4}.

  constexpr static auto mask = (1U << static_cast<unsigned>(std::bit_width(field_numbers.size()))) - 1;
  consteval static auto build_masked_lookup_table_offsets() {
    std::array<std::uint32_t, mask + 1> masked_number_occurrences = {};

    for (auto num : field_numbers) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
      ++masked_number_occurrences[num & mask];
    }

    std::array<std::uint32_t, mask + 2> table_offsets = {0};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::partial_sum(masked_number_occurrences.begin(), masked_number_occurrences.end(), table_offsets.begin() + 1);
    return table_offsets;
  }

  // the masked_lookup_table is an array of field_number, field_index pairs sorted by (field_number & mask)
  consteval static auto build_masked_lookup_table() {
    if constexpr (field_numbers.empty()) {
      return std::span<std::pair<std::uint32_t, std::uint32_t>>{};
    } else {
      std::array<std::uint32_t, mask + 1> counts = {};
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      std::copy(lookup_table_offsets.begin(), lookup_table_offsets.end() - 1, counts.begin());

      std::array<std::pair<std::uint32_t, std::uint32_t>, field_numbers.size()> result;
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
      for (uint32_t i = 0; i < field_numbers.size(); ++i) {
        auto num = field_numbers[i];
        auto masked_num = num & mask;
        result[counts[masked_num]++] = {num, static_cast<uint32_t>(field_indices[i])};
      }
      // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
      return result;
    }
  }

  constexpr static auto lookup_table_offsets = build_masked_lookup_table_offsets();
  constexpr static auto lookup_table = build_masked_lookup_table();

  template <auto MaskedNum, std::uint32_t I>
  constexpr static auto dispatch_by_masked_num(std::uint32_t field_number, auto &&f) {
    constexpr auto begin_id = lookup_table_offsets[MaskedNum] + I;
    constexpr auto end_id = lookup_table_offsets[MaskedNum + 1];
    if constexpr (begin_id == end_id) {
      return f(make_integral_constant<UINT32_MAX>());
    } else {
      constexpr auto entry = lookup_table[begin_id];
      if (field_number == entry.first) {
        return f(make_integral_constant<entry.second>());
      } else [[unlikely]] {
        return dispatch_by_masked_num<MaskedNum, I + 1>(field_number, std::forward<decltype(f)>(f));
      }
    }
  }

  template <uint32_t... MaskNum>
  constexpr static status dispatch(std::uint32_t field_number, auto &&f,
                                   std::integer_sequence<std::uint32_t, MaskNum...>) {
    status r;
    (void)((((field_number & mask) == MaskNum) &&
            (r = dispatch_by_masked_num<MaskNum, 0>(field_number, std::forward<decltype(f)>(f)), true)) ||
           ...);
    return r;
  }

  constexpr static auto dispatch(std::uint32_t field_number, auto &&f) {
    return dispatch(field_number, std::forward<decltype(f)>(f), std::make_integer_sequence<std::uint32_t, mask + 1>());
  }
};
} // namespace traits

#ifdef __cpp_lib_constexpr_vector
template <typename T>
using constexpr_vector = std::vector<T>;
#else
template <typename T>
// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
class constexpr_vector {
  T *data_;
  std::size_t sz;

public:
  constexpr explicit constexpr_vector(std::size_t n) : data_(new T[n]), sz(n) {}
  constexpr ~constexpr_vector() { delete[] data_; }
  constexpr T *data() noexcept { return data_; }
  constexpr const T *data() const noexcept { return data_; }
  constexpr operator std::span<T>() const { return std::span{data_, sz}; }
};
#endif

#if defined(__x86_64__) || defined(_M_AMD64) // x64
template <concepts::varint T, typename Result>
class sfvint_parser {
  // This class implements the variable-length integer decoding algorithm from https://arxiv.org/html/2403.06898v1
  constexpr static unsigned mask_length = 6;
  // google implementation only treat more than 10 bytes encoded value as error; i.e. a 6 bytes
  // encoded value does not treated as error for uint32
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
    auto r = (varint_encoding::zig_zag == T::encoding)
                 ? (v >> 1U) ^ static_cast<uint64_t>(-static_cast<int64_t>(v & 1U))
                 : v;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    *res++ = static_cast<Result>(r);
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
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
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
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
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
#endif

[[noreturn]] inline void unreachable() {
#if __cpp_lib_unreachable
  std::unreachable();
#else
#if defined(_MSC_VER) && !defined(__clang__) // MSVC
  __assume(false);
#else                                        // GCC, Clang
  __builtin_unreachable();
#endif
#endif
}

namespace util {
template <typename Range, typename UnaryOperation>
constexpr uint32_t transform_accumulate(const Range &range, const UnaryOperation &unary_op) {
  // **DO NOT** use std::transform_reduce() because it would apply unary_op in **unspecified** order
  auto total =
      std::accumulate(range.begin(), range.end(), std::size_t{0},
                      [&unary_op](std::size_t acc, const auto &elem) constexpr { return acc + unary_op(elem); });
  return static_cast<uint32_t>(total);
}

template <typename T, typename Range>
void append_range(T &v, const Range &range) {
  if constexpr (requires { v.append_range(range); }) {
    v.append_range(range);
  } else {
    v.insert(v.end(), range.begin(), range.end());
  }
}
} // namespace util

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
namespace pb_serializer {
template <typename Byte, typename Context>
struct basic_out {
  using byte_type = Byte;
  using is_basic_out = void;
  constexpr static bool endian_swapped = std::endian::little != std::endian::native;
  std::span<byte_type> _data;
  Context &_context;

  constexpr basic_out(std::span<byte_type> data, Context &context) : _data(data), _context(context) {}
  constexpr ~basic_out() = default;
  basic_out(const basic_out &) = delete;
  basic_out(basic_out &&) = delete;
  basic_out &operator=(const basic_out &) = delete;
  basic_out &operator=(basic_out &&) = delete;

  constexpr bool serialize(concepts::byte_serializable auto item) {
    auto value = std::bit_cast<std::array<std::remove_const_t<byte_type>, sizeof(item)>>(item);
    if constexpr (endian_swapped && sizeof(item) != 1) {
      std::copy(value.rbegin(), value.rend(), _data.begin());
    } else {
      std::copy(value.begin(), value.end(), _data.begin());
    }
    _data = _data.subspan(sizeof(item));
    return true;
  }

  constexpr bool serialize(concepts::varint auto item) {
    auto p = unchecked_pack_varint(item, _data.data());
    _data = _data.subspan(static_cast<std::size_t>(std::distance(_data.data(), p)));
    return true;
  }

  template <std::ranges::contiguous_range T>
  constexpr bool serialize(const T &item) {
    using type = std::remove_cvref_t<T>;
    using value_type = typename type::value_type;
    static_assert(concepts::byte_serializable<value_type>);
    if (!std::is_constant_evaluated() && (!endian_swapped || sizeof(value_type) == 1)) {
      auto bytes_to_copy = item.size() * sizeof(value_type);
      std::memcpy(_data.data(), item.data(), bytes_to_copy);
      _data = _data.subspan(bytes_to_copy);
      return true;
    } else {
      return std::ranges::all_of(item, [this](auto e) { return this->serialize(e); });
    }
  }

  constexpr bool serialize(concepts::is_enum auto item) { return serialize(varint{static_cast<int64_t>(item)}); }

  template <typename... Args>
  constexpr bool operator()(Args &&...item) {
    return (serialize(std::forward<Args>(item)) && ...);
  }
};

template <concepts::contiguous_byte_range Range, typename Context>
basic_out(Range &&, Context &) -> basic_out<std::ranges::range_value_t<Range>, Context>;

constexpr std::size_t len_size(std::size_t len) { return varint_size(len) + len; }

/**
 * @struct size_cache_counter
 * @brief Calculate the number of variable size integers needed for the serialized protobuf stream of a given message.
 *
 * This struct contains overloaded `count` methods that recursively compute the number of variable size integers needed.
 * It is used to cache the size of fields in protobuf messages, which can help optimize serialization performance.
 */

template <typename T>
struct size_cache_counter;

template <concepts::has_meta T>
struct size_cache_counter<T> {
  constexpr static std::size_t count(concepts::has_meta auto const &item) {
    using type = std::remove_cvref_t<decltype(item)>;
    using meta_type = typename traits::meta_of<type>::type;
    if constexpr (std::tuple_size_v<meta_type> == 0) {
      return 0;
    } else {
      return std::apply(
          [&item](auto &&...meta) constexpr {
            return ((meta.omit_value(meta.access(item)) ? 0 : count(meta.access(item), meta)) + ...);
          },
          meta_type{});
    }
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t count(concepts::oneof_type auto const &item, Meta) {
    return count_oneof<0, typename Meta::alternatives_meta>(item);
  }

  HPP_PROTO_INLINE constexpr static std::size_t count(concepts::dereferenceable auto const &item, auto meta) {
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    return count(*item, meta);
  }

  HPP_PROTO_INLINE constexpr static std::size_t count(concepts::has_meta auto const &item, auto meta) {
    return count(item) + (!meta.is_delimited());
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t count(std::ranges::input_range auto const &item, Meta meta) {
    using type = std::remove_cvref_t<decltype(item)>;
    using value_type = typename std::ranges::range_value_t<type>;
    if constexpr (concepts::has_meta<value_type> || !meta.is_packed() || meta.is_delimited()) {
      return util::transform_accumulate(item, [](const auto &elem) constexpr { return count(elem, Meta{}); });
    } else {
      using element_type =
          std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::contiguous_byte_range<type>,
                             value_type, typename Meta::type>;

      if constexpr (std::is_enum_v<element_type> || concepts::varint<element_type>) {
        return 1;
      } else {
        return 0;
      }
    }
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t count(concepts::is_pair auto const &item, Meta) {
    using type = std::remove_cvref_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    static_assert(concepts::is_map_entry<serialize_type>);
    using mapped_type = typename serialize_type::mapped_type;
    if constexpr (concepts::has_meta<mapped_type>) {
      auto r = count(item.second) + 2;
      return r;
    } else {
      return 1;
    }
  }

  HPP_PROTO_INLINE constexpr static std::size_t count(concepts::no_cached_size auto const &, auto) { return 0; }

  template <std::size_t I, typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t count_oneof(auto const &item) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return count(std::get<I + 1>(item), typename std::tuple_element_t<I, Meta>{});
      }
      return count_oneof<I + 1, Meta>(item);
    } else {
      return 0;
    }
  }
};

/**
 * @struct message_size_calculator
 * @brief Calculates the serialized size of a message and cache the size of each field.
 */
template <typename T>
struct message_size_calculator;

template <concepts::has_meta T>
struct message_size_calculator<T> {
  constexpr static std::size_t message_size(concepts::has_meta auto const &item) {
    struct null_size_cache {
      struct null_assignable {
        constexpr null_assignable &operator=(uint32_t) { return *this; }
      };
      constexpr null_assignable operator*() const { return null_assignable{}; }
      // NOLINTNEXTLINE(cert-dcl21-cpp)
      constexpr null_size_cache operator++(int) const { return *this; }
    } cache;
    return message_size(item, cache);
  }

  constexpr static uint32_t message_size(concepts::has_meta auto const &item, std::span<uint32_t> cache) {
    uint32_t *c = cache.data();
    return message_size(item, c);
  }

  template <concepts::is_size_cache_iterator Itr>
  struct field_size_accumulator {
    Itr &cache_itr;
    uint32_t sum = 0;
    explicit constexpr field_size_accumulator(Itr &itr) : cache_itr(itr) {}
    constexpr void operator()(auto const &field, auto meta) {
      const auto size = meta.omit_value(field) ? 0u : static_cast<uint32_t>(field_size(field, meta, cache_itr));
      sum += size;
    }
    constexpr ~field_size_accumulator() = default;
    field_size_accumulator(const field_size_accumulator &) = delete;
    field_size_accumulator(field_size_accumulator &&) = delete;
    field_size_accumulator &operator=(const field_size_accumulator &) = delete;
    field_size_accumulator &operator=(field_size_accumulator &&) = delete;
  };

  HPP_PROTO_INLINE constexpr static uint32_t message_size(concepts::has_meta auto const &item,
                                                          concepts::is_size_cache_iterator auto &cache_itr) {
    using type = std::remove_cvref_t<decltype(item)>;
    return std::apply(
        [&item, &cache_itr](auto &&...meta) {
          // we cannot directly use fold expression with '+' operator because it has undefined evaluation order.
          field_size_accumulator accumulator(cache_itr);
          (accumulator(meta.access(item), meta), ...);
          return accumulator.sum;
        },
        typename traits::meta_of<type>::type{});
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static uint32_t field_size(concepts::oneof_type auto const &item, Meta,
                                                        concepts::is_size_cache_iterator auto &cache_itr) {
    return oneof_size<0, typename Meta::alternatives_meta>(item, cache_itr);
  }

  HPP_PROTO_INLINE constexpr static uint32_t field_size(concepts::pb_extensions auto const &item, auto,
                                                        concepts::is_size_cache_iterator auto &) {
    return util::transform_accumulate(item.fields, [](const auto &e) constexpr { return e.second.size(); });
  }

  HPP_PROTO_INLINE constexpr static uint32_t field_size(concepts::pb_unknown_fields auto const &item, auto,
                                                        concepts::is_size_cache_iterator auto &) {
    using range_t = typename std::remove_reference_t<decltype(item)>::unknown_fields_range_t;
    if constexpr (requires { item.fields.size(); }) {
      return static_cast<uint32_t>(item.fields.size());
    } else if constexpr (concepts::contiguous_byte_range<range_t>) {
      return static_cast<uint32_t>(std::ranges::size(item.fields));
    } else {
      return 0;
    }
  }

  HPP_PROTO_INLINE constexpr static uint32_t field_size(concepts::is_empty auto const &, auto,
                                                        concepts::is_size_cache_iterator auto &) {
    return 0;
  }

  HPP_PROTO_INLINE constexpr static uint32_t field_size(concepts::is_enum auto item, auto meta,
                                                        concepts::is_size_cache_iterator auto &) {
    using type = decltype(item);
    return static_cast<uint32_t>(varint_size(meta.number << 3U) +
                                 varint_size(static_cast<int64_t>(std::underlying_type_t<type>(item))));
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static uint32_t field_size(concepts::byte_serializable auto item, Meta meta,
                                                        concepts::is_size_cache_iterator auto &) {
    using type = decltype(item);
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    constexpr uint32_t tag_size = static_cast<uint32_t>(varint_size(meta.number << 3U));
    if constexpr (concepts::byte_serializable<serialize_type>) {
      return static_cast<uint32_t>(tag_size + sizeof(serialize_type));
    } else {
      static_assert(concepts::varint<serialize_type>);
      return static_cast<uint32_t>(tag_size + serialize_type(item).encode_size());
    }
  }

  HPP_PROTO_INLINE constexpr static uint32_t field_size(concepts::varint auto item, auto meta,
                                                        concepts::is_size_cache_iterator auto &) {
    return static_cast<uint32_t>(varint_size(meta.number << 3U) + item.encode_size());
  }

  HPP_PROTO_INLINE constexpr static uint32_t field_size(concepts::dereferenceable auto const &item, auto meta,
                                                        concepts::is_size_cache_iterator auto &cache_itr) {
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    return static_cast<uint32_t>(field_size(*item, meta, cache_itr));
  }

  HPP_PROTO_INLINE constexpr static uint32_t field_size(concepts::has_meta auto const &item, auto meta,
                                                        concepts::is_size_cache_iterator auto &cache_itr) {
    constexpr uint32_t tag_size = static_cast<uint32_t>(varint_size(meta.number << 3U));
    if constexpr (!meta.is_delimited()) {
      decltype(auto) msg_size = consume_size_cache_entry(cache_itr);
      auto s = static_cast<uint32_t>(message_size(item, cache_itr));
      msg_size = s;
      return static_cast<uint32_t>(tag_size + len_size(s));
    } else {
      return (2 * tag_size) + message_size(item, cache_itr);
    }
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static uint32_t field_size(concepts::is_pair auto const &item, Meta meta,
                                                        concepts::is_size_cache_iterator auto &cache_itr) {
    using type = std::remove_cvref_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;
    using value_type = typename serialize_type::read_only_type;

    constexpr uint32_t tag_size = static_cast<uint32_t>(varint_size(meta.number << 3U));
    auto &[key, value] = item;
    decltype(auto) msg_size = consume_size_cache_entry(cache_itr);
    auto s = message_size(value_type{key, value}, cache_itr);
    msg_size = static_cast<uint32_t>(s);
    return static_cast<uint32_t>(tag_size + len_size(s));
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t field_size(std::ranges::input_range auto const &item, Meta meta,
                                                           concepts::is_size_cache_iterator auto &cache_itr) {
    using type = std::remove_cvref_t<decltype(item)>;
    constexpr uint32_t tag_size = static_cast<uint32_t>(varint_size(meta.number << 3U));
    if constexpr (concepts::contiguous_byte_range<type>) {
      return tag_size + len_size(item.size());
    } else {
      using value_type = typename std::ranges::range_value_t<type>;
      if constexpr (concepts::has_meta<value_type> || !meta.is_packed() || meta.is_delimited()) {
        return util::transform_accumulate(
            item, [&cache_itr](const auto &elem) constexpr { return field_size(elem, Meta{}, cache_itr); });
      } else {
        using element_type =
            std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::contiguous_byte_range<type>,
                               value_type, typename Meta::type>;

        if constexpr (concepts::byte_serializable<element_type>) {
          return tag_size + len_size(item.size() * sizeof(value_type));
        } else {
          auto s = util::transform_accumulate(item, [](auto elem) constexpr {
            if constexpr (concepts::is_enum<element_type>) {
              return varint_size(static_cast<int64_t>(elem));
            } else {
              static_assert(concepts::varint<element_type>);
              return element_type(elem).encode_size();
            }
          });
          decltype(auto) msg_size = consume_size_cache_entry(cache_itr);
          msg_size = static_cast<uint32_t>(s);
          return tag_size + len_size(s);
        }
      }
    }
  }

  template <std::size_t I, typename Meta>
  HPP_PROTO_INLINE constexpr static uint32_t oneof_size(auto const &item,
                                                        concepts::is_size_cache_iterator auto &cache_itr) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return static_cast<uint32_t>(
            field_size(std::get<I + 1>(item), typename std::tuple_element_t<I, Meta>{}, cache_itr));
      }
      return oneof_size<I + 1, Meta>(item, cache_itr);
    } else {
      return 0;
    }
  }
};

#ifdef _WIN32
struct freea {
  void operator()(void *p) { _freea(p); }
};
#endif

template <bool overwrite_buffer = true, typename T, concepts::contiguous_byte_range Buffer>
constexpr status serialize(const T &item, Buffer &buffer, [[maybe_unused]] concepts::is_pb_context auto &context) {
  std::size_t n = size_cache_counter<T>::count(item);

  auto do_serialize = [&item, &buffer, &context](std::span<uint32_t> cache) constexpr -> status {
    std::size_t msg_sz = message_size_calculator<T>::message_size(item, cache);
    std::size_t old_size = overwrite_buffer ? 0 : buffer.size();
    std::size_t new_size = old_size + msg_sz;
    if constexpr (requires { buffer.resize(1); }) {
      buffer.resize(new_size);
    } else if (new_size > buffer.size()) {
      return std::errc::not_enough_memory;
    }

    basic_out archive{buffer, context};
    auto cache_itr = cache.begin();
    if (!serialize(item, cache_itr, archive)) {
      return std::errc::bad_message;
    }
    return {};
  };

  using context_type = decltype(context);
  constexpr std::size_t max_stack_cache_count = [] {
    if constexpr (requires { context_type::max_size_cache_on_stack; }) {
      return context_type::max_size_cache_on_stack;
    } else {
      return hpp::proto::max_size_cache_on_stack<>.max_size_cache_on_stack;
    }
  }() / sizeof(uint32_t);

  if (std::is_constant_evaluated() || n > max_stack_cache_count) {
    if constexpr (concepts::has_memory_resource<decltype(context)>) {
      auto cache = std::span{
          static_cast<uint32_t *>(context.memory_resource().allocate(n * sizeof(uint32_t), sizeof(uint32_t))), n};
      return do_serialize(cache);
    } else {
      constexpr_vector<uint32_t> cache(n);
      return do_serialize(cache);
    }
  } else if (n > 0) {
#ifdef _WIN32
    std::unique_ptr<uint32_t, freea> ptr{static_cast<uint32_t *>(_malloca(n * sizeof(uint32_t)))};
    auto *cache = ptr.get();
#elifdef __GNUC__
    auto *cache =
        static_cast<uint32_t *>(__builtin_alloca_with_align(n * sizeof(uint32_t), CHAR_BIT * sizeof(uint32_t)));
#else
    uint32_t cache[max_stack_cache_count];
#endif
    return do_serialize({cache, n});
  } else {
    uint32_t *cache = nullptr;
    return do_serialize({cache, n});
  }
}

template <concepts::has_meta T>
[[nodiscard]] constexpr bool serialize(const T &item, concepts::is_size_cache_iterator auto &cache_itr, auto &archive) {
  using type = std::remove_cvref_t<decltype(item)>;
  using metas = typename traits::meta_of<type>::type;
  auto serialize_field_if_not_empty = [&](auto meta) {
    return meta.omit_value(meta.access(item)) || serialize_field(meta.access(item), meta, cache_itr, archive);
  };
  return std::apply([&](auto... meta) { return (serialize_field_if_not_empty(meta) && ...); }, metas{});
}

template <typename Meta>
[[nodiscard]] HPP_PROTO_INLINE constexpr bool serialize_field(concepts::oneof_type auto const &item, Meta,
                                                              concepts::is_size_cache_iterator auto &cache_itr,
                                                              auto &archive) {
  return serialize_oneof<0, typename Meta::alternatives_meta>(item, cache_itr, archive);
}

[[nodiscard]] HPP_PROTO_INLINE constexpr bool serialize_field(boolean item, auto meta,
                                                              concepts::is_size_cache_iterator auto &, auto &archive) {
  return archive(make_tag<bool>(meta), item.value);
}

[[nodiscard]] HPP_PROTO_INLINE constexpr bool serialize_field(concepts::pb_extensions auto const &item, auto,
                                                              concepts::is_size_cache_iterator auto &, auto &archive) {
  return std::ranges::all_of(item.fields, [&](const auto &f) { return archive(f.second); });
}

[[nodiscard]] HPP_PROTO_INLINE constexpr bool serialize_field(concepts::pb_unknown_fields auto const &item, auto,
                                                              concepts::is_size_cache_iterator auto &, auto &archive) {
  using range_t = typename std::remove_reference_t<decltype(item)>::unknown_fields_range_t;
  if constexpr (concepts::contiguous_byte_range<range_t>) {
    return archive(item.fields);
  } else {
    return true;
  }
}

[[nodiscard]] HPP_PROTO_INLINE constexpr bool serialize_field(concepts::is_empty auto const &, auto,
                                                              concepts::is_size_cache_iterator auto &, auto &) {
  return true;
}

[[nodiscard]] HPP_PROTO_INLINE constexpr bool serialize_field(concepts::is_enum auto item, auto meta,
                                                              concepts::is_size_cache_iterator auto &, auto &archive) {
  return archive(make_tag<decltype(item)>(meta), item);
}

[[nodiscard]] HPP_PROTO_INLINE constexpr bool serialize_field(concepts::arithmetic auto item, auto meta,
                                                              concepts::is_size_cache_iterator auto &, auto &archive) {
  using serialize_type = typename traits::get_serialize_type<decltype(meta), decltype(item)>::type;
  return archive(make_tag<serialize_type>(meta), serialize_type{item});
}

[[nodiscard]] HPP_PROTO_INLINE constexpr bool serialize_field(concepts::contiguous_byte_range auto const &item,
                                                              auto meta, concepts::is_size_cache_iterator auto &,
                                                              auto &archive) {
  using type = std::remove_cvref_t<decltype(item)>;
  return !utf8_validation_failed(meta, item) && archive(make_tag<type>(meta), varint{item.size()}, item);
}

[[nodiscard]] HPP_PROTO_INLINE constexpr bool serialize_field(concepts::dereferenceable auto const &item, auto meta,
                                                              concepts::is_size_cache_iterator auto &cache_itr,
                                                              auto &archive) {
  // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
  return serialize_field(*item, meta, cache_itr, archive);
}

[[nodiscard]] HPP_PROTO_INLINE constexpr bool serialize_field(concepts::has_meta auto const &item, auto meta,
                                                              concepts::is_size_cache_iterator auto &cache_itr,
                                                              auto &archive) {
  if constexpr (!meta.is_delimited()) {
    auto len = varint{consume_size_cache_entry(cache_itr)};
    return archive(make_tag<decltype(item)>(meta), len) && serialize(item, cache_itr, archive);
  } else {
    return archive(varint{(meta.number << 3U) | std::underlying_type_t<wire_type>(wire_type::sgroup)}) &&
           serialize(item, cache_itr, archive) &&
           archive(varint{(meta.number << 3U) | std::underlying_type_t<wire_type>(wire_type::egroup)});
  }
}

[[nodiscard]] HPP_PROTO_INLINE constexpr bool serialize_field(std::ranges::range auto const &item, auto meta,
                                                              concepts::is_size_cache_iterator auto &cache_itr,
                                                              auto &archive) {
  using Meta = decltype(meta);
  using type = std::remove_cvref_t<decltype(item)>;
  using value_type = typename std::ranges::range_value_t<type>;
  using element_type =
      std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::contiguous_byte_range<type>, value_type,
                         typename Meta::type>;

  if constexpr (concepts::has_meta<value_type> || !meta.is_packed() || meta.is_delimited()) {
    return std::ranges::all_of(item, [&](const auto &element) {
      using serialize_element_type =
          std::conditional_t<concepts::is_map_entry<typename Meta::type>, decltype(element), element_type>;
      return serialize_field(static_cast<serialize_element_type>(element), meta, cache_itr, archive);
    });
  } else if constexpr (concepts::byte_serializable<element_type>) {
    // packed fundamental types or bytes
    return archive(make_tag<type>(meta), varint{item.size() * sizeof(typename type::value_type)}, item);
  } else {
    // packed varint or packed enum
    return archive(make_tag<type>(meta), varint{consume_size_cache_entry(cache_itr)}) &&
           std::ranges::all_of(item, [&](auto element) { return archive(element_type{element}); });
  }
}

template <typename Meta>
[[nodiscard]] HPP_PROTO_INLINE constexpr bool serialize_field(concepts::is_pair auto const &item, Meta meta,
                                                              concepts::is_size_cache_iterator auto &cache_itr,
                                                              auto &archive) {
  using type = std::remove_cvref_t<decltype(item)>;
  constexpr auto tag = make_tag<type>(meta);
  using value_type = typename traits::get_map_entry<Meta, type>::read_only_type;
  static_assert(concepts::has_meta<value_type>);
  auto &&[key, value] = item;
  auto len = varint{consume_size_cache_entry(cache_itr)};
  return archive(tag, len) && serialize(value_type{key, value}, cache_itr, archive);
}

template <std::size_t I, concepts::tuple Meta>
[[nodiscard]] HPP_PROTO_INLINE constexpr static bool
serialize_oneof(auto const &item, concepts::is_size_cache_iterator auto &cache_itr, auto &archive) {
  if constexpr (I < std::tuple_size_v<Meta>) {
    if (I == item.index() - 1) {
      return serialize_field(std::get<I + 1>(item), typename std::tuple_element_t<I, Meta>{}, cache_itr, archive);
    }
    return serialize_oneof<I + 1, Meta>(item, cache_itr, archive);
  }
  return true;
}

template <typename T>
struct input_span {
  using value_type = T;
  const value_type *_begin = nullptr;
  const value_type *_end = nullptr;

  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  constexpr input_span() = default;
  constexpr input_span(const value_type *b, const value_type *e) : _begin(b), _end(e) {}
  constexpr input_span(const value_type *b, std::size_t n) : _begin(b), _end(b + n) {}
  [[nodiscard]] constexpr const value_type *data() const { return _begin; }
  [[nodiscard]] constexpr std::size_t size() const { return static_cast<std::size_t>(_end - _begin); }
  [[nodiscard]] constexpr bool empty() const { return _begin == _end; }

  [[nodiscard]] constexpr const value_type *begin() const { return _begin; }
  [[nodiscard]] constexpr const value_type *end() const { return _end; }

  constexpr const value_type &operator[](std::size_t n) const { return *(_begin + n); }
  constexpr const value_type &next() { return *_begin++; }
  [[nodiscard]] constexpr input_span<T> subspan(std::size_t offset, std::size_t count) const {
    return {_begin + offset, _begin + offset + count};
  }

  [[nodiscard]] constexpr std::pair<input_span<value_type>, input_span<T>> split(std::size_t n) const {
    return std::make_pair(input_span<value_type>{_begin, _begin + n}, input_span<value_type>{_begin + n, _end});
  }

  constexpr input_span<T> consume(std::size_t n) {
    const T *old_begin = _begin;
    _begin += n;
    return {old_begin, _begin};
  }

  template <typename U, std::size_t N>
  constexpr void consume(std::array<U, N> &arr) {
    std::copy(_begin, _begin + N, arr.data());
    _begin += N;
  }

  void revert(std::size_t n) { _begin -= n; }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

  constexpr void advance_to(const value_type *new_pos) { _begin = new_pos; }
};

constexpr static std::size_t slope_size = 16;
constexpr static std::size_t patch_buffer_size = 2 * slope_size;

template <typename Byte>
struct input_buffer_region : input_span<Byte> {
  const Byte *_slope_begin = nullptr;
  constexpr input_buffer_region() = default;
  constexpr input_buffer_region(input_span<Byte> range, const Byte *s) : input_span<Byte>{range}, _slope_begin(s) {}

  [[nodiscard]] constexpr std::ptrdiff_t slope_distance() const { return this->_begin - _slope_begin; }
  [[nodiscard]] constexpr bool has_next_region() const { return this->_end > _slope_begin; }

  constexpr input_span<Byte> consume_packed_varints(std::size_t max_size) {
    if (this->size() >= max_size) {
      return this->consume(max_size);
    } else if (has_next_region()) {
      // find the last position where a varint terminated in the slope area. If the position is not found,
      // we have at least a non-terminated varint, just return a empty range to indicate error.
      auto slope_area = std::span{_slope_begin, this->_end};
      auto it = std::ranges::find_if(slope_area | std::views::reverse,
                                     [](auto v) { return std::bit_cast<std::int8_t>(v) > 0; });
      if (it == slope_area.rend()) {
        return {};
      }
      return this->consume(this->size() - std::distance(slope_area.rbegin(), it));
    } else {
      return {};
    }
  }
};

///
/// We adopt the same optimization technique as
/// [EpsCopyInputStream](https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/parse_context.h)
/// for protobuf deserialization. Input buffers are structured into a sequence of overlapping regions, where
/// each consecutive region overlaps by slope_size bytes. For a sequence of input buffers (b_1, b_2, ..., b_n), patch
/// buffers are inserted between chunks to create a new sequence (b_1, p_1, b_2, p_2, ..., b_n, p_n). Each patch
/// buffer p_i contains the last slope_size bytes of b_i and the first slope_size bytes of b_{i+1}.
///

// NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
template <typename Byte, typename Context, bool Contiguous>
struct basic_in {
  using byte_type = Byte;
  input_buffer_region<Byte> current;
  input_span<input_buffer_region<Byte>> rest;
  ptrdiff_t size_exclude_current = 0; // the remaining size excluding those in current
  Context &context;                   // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

  constexpr static bool endian_swapped = std::endian::little != std::endian::native;

  constexpr void set_current_region(const input_buffer_region<Byte> &next_region) {
    current._begin = next_region._begin;
    current._end = next_region._end;
    size_exclude_current += (next_region.slope_distance());
    if (size_exclude_current < 0) {
      current._end += size_exclude_current;
      size_exclude_current = 0;
    }
    current._slope_begin = std::min(next_region._slope_begin, current._end);
  }

  constexpr void maybe_advance_region() {
    std::ptrdiff_t offset = 0;
    while ((offset = current.slope_distance()) > 0 && !rest.empty()) {
      set_current_region(rest.next());
      current.consume(static_cast<std::size_t>(offset));
    }
  }

public:
  using is_basic_in = void;
  constexpr static bool contiguous = Contiguous;
  [[nodiscard]] constexpr ptrdiff_t region_size() const { return current._end - current._begin; }
  [[nodiscard]] constexpr ptrdiff_t in_avail() const {
    if constexpr (contiguous) {
      return region_size();
    } else {
      return size_exclude_current - current.slope_distance();
    }
  }
  [[nodiscard]] constexpr const byte_type *data() const { return current.data(); }

  constexpr basic_in(input_buffer_region<Byte> cur, const input_span<input_buffer_region<Byte>> &rest,
                     ptrdiff_t size_exclude_current, Context &ctx)
      : current(cur), rest(rest), size_exclude_current(size_exclude_current), context(ctx) {}

  constexpr basic_in(concepts::segmented_byte_range auto const &source, std::span<input_buffer_region<Byte>> regions,
                     std::span<Byte> patch_buffer_cache, Context &ctx)
      : context(ctx) {
    // pre (std::size(source) > 0 && regions.size() == std::size(source) * 2)
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    Byte *patch_buffer = patch_buffer_cache.data();
    std::size_t region_index = 0;
    bool first_segment = true;
    for (auto &segment : source) {
      const auto segment_size = std::ranges::size(segment);
      if (!first_segment && segment_size == 0) {
        continue;
      }
      size_exclude_current += static_cast<std::ptrdiff_t>(segment_size);
      if (segment_size <= slope_size) {
        auto &seg_region = regions[region_index];
        if (first_segment) {
          seg_region._begin = patch_buffer;
        }
        patch_buffer = std::copy(std::begin(segment), std::end(segment), patch_buffer);
        seg_region._slope_begin = patch_buffer;
      } else {
        if (!first_segment) {
          patch_buffer = std::copy_n(std::begin(segment), slope_size, patch_buffer);
          regions[region_index]._end = patch_buffer;
          ++region_index;
        }
        auto &seg_region = regions[region_index];
        seg_region._begin = std::ranges::data(segment);
        seg_region._end = seg_region._begin + segment_size;
        seg_region._slope_begin = seg_region._end - slope_size;

        auto &patch_region = regions[++region_index];
        patch_region._begin = patch_buffer;
        patch_buffer = std::copy(seg_region._slope_begin, seg_region._end, patch_buffer);
        patch_region._slope_begin = patch_buffer;
      }
      first_segment = false;
    }
    if (!regions.empty()) {
      // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      regions[region_index]._end = patch_buffer;
      regions[region_index]._slope_begin = patch_buffer;
      std::fill_n(patch_buffer, slope_size, Byte{0});
      rest = input_span{regions.data(), region_index + 1};
      set_current_region(rest.next());
    }
  }

  basic_in(const basic_in &) = default;
  basic_in(basic_in &&) = default;
  basic_in &operator=(const basic_in &) = default;
  basic_in &operator=(basic_in &&) = default;
  ~basic_in() = default;

  [[nodiscard]] basic_in copy() const { return *this; }

  constexpr status deserialize(bool &item) {
    if (auto p = unchecked_parse_bool(current, item); p <= current._end) [[likely]] {
      current.advance_to(p);
      return {};
    }
    return std::errc::bad_message;
  }

  constexpr status deserialize(boolean &item) { return deserialize(item.value); }

  template <concepts::byte_deserializable T>
  constexpr status deserialize(T &item) {
    std::array<std::remove_const_t<byte_type>, sizeof(item)> value = {};
    if constexpr (endian_swapped) {
      std::ranges::reverse_copy(current.consume(sizeof(item)), value.begin());
    } else {
      std::ranges::copy(current.consume(sizeof(item)), value.begin());
    }
    item = std::bit_cast<T>(value);
    return {};
  }

  template <typename T>
    requires concepts::is_enum<T> && (sizeof(T) > 1)
  constexpr status deserialize(T &item) {
    return deserialize(varint{static_cast<int64_t>(item)});
  }

  template <concepts::varint T>
  constexpr status deserialize(T &item) {
    if (auto p = unchecked_parse_varint(current, item); p <= current._end) [[likely]] {
      current.advance_to(p);
      return {};
    }
    return std::errc::bad_message;
  }

  // Helper: append raw data path for packed deserialization (no byte-swap required)
  template <typename ValueType>
  constexpr status do_deserialize_packed_append_raw(std::size_t n, auto &item, std::size_t nbytes,
                                                    std::size_t new_size) {
    item.reserve(new_size);
    if constexpr (contiguous) {
      item.append_raw_data(current.consume(nbytes));
      return {};
    } else {
      while (n > 0) {
        maybe_advance_region();
        auto k = std::min<std::ptrdiff_t>(n, region_size() / static_cast<std::ptrdiff_t>(sizeof(ValueType)));
        item.append_raw_data(current.consume(static_cast<std::size_t>(k) * sizeof(ValueType)));
        n -= k;
      }
      return {};
    }
  }

  // Helper: resize-and-copy path for packed deserialization (handles byte-swap and constant evaluation)
  template <typename ValueType>
  constexpr status do_deserialize_packed_resize(std::size_t n, auto &item, std::size_t old_size, std::size_t new_size,
                                                std::size_t nbytes) {
    item.resize(new_size);
    auto target = std::span{item.data() + old_size, n};
    constexpr bool requires_byteswap = (sizeof(ValueType) > 1 && endian_swapped);
    if (std::is_constant_evaluated() || requires_byteswap) {
      std::array<byte_type, sizeof(ValueType)> v{};
      for (auto &elem : target) {
        maybe_advance_region();
        current.consume(v);
        if constexpr (requires_byteswap) {
          std::ranges::reverse(v);
        }
        elem = std::bit_cast<ValueType>(v);
      }
    } else {
      void *ptr = target.data();
      if constexpr (contiguous) {
        std::memcpy(ptr, current.consume(nbytes).data(), nbytes);
      } else {
        while (nbytes > 0) {
          maybe_advance_region();
          std::size_t k = std::min(nbytes, static_cast<std::size_t>(region_size()));
          std::memcpy(ptr, current.consume(k).data(), k);
          ptr = static_cast<char *>(ptr) + k;
          nbytes -= k;
        }
      }
    }
    return {};
  }

  constexpr status deserialize_packed(std::size_t n, auto &&item) {
    using value_type = typename std::remove_cvref_t<decltype(item)>::value_type;
    std::size_t nbytes = n * sizeof(value_type);
    if (std::cmp_less(in_avail(), nbytes)) [[unlikely]] {
      return std::errc::bad_message;
    }
    constexpr bool requires_byteswap = (sizeof(value_type) > 1 && endian_swapped);

    auto old_size = item.size();
    auto new_size = old_size + n;
    if constexpr (requires { item.append_raw_data(std::span<byte_type>{}); } && !requires_byteswap) {
      return do_deserialize_packed_append_raw<value_type>(n, item, nbytes, new_size);
    } else {
      return do_deserialize_packed_resize<value_type>(n, item, old_size, new_size, nbytes);
    }
  }

#if defined(__x86_64__) || defined(_M_AMD64) // x64
  // workaround for C++20 doesn't support static in constexpr function
  static bool has_bmi2() {
    auto check = [] {
#ifdef _WIN32
      int cpuInfo[4];
      __cpuidex(cpuInfo, 7, 0);
      return (cpuInfo[1] & (1 << 8)) != 0; // Check BMI2 bit
#elif defined(__GNUC__) || defined(__clang__)
      return __builtin_cpu_supports("bmi2");
#else
      return false;
#endif
    };
    static bool result = check();
    return result;
  }
#endif // x64
  template <typename Item>
  constexpr status deserialize_packed_boolean(std::size_t size, Item &item) {
    item.resize(size);
    for (auto &v : item) {
      if constexpr (!contiguous) {
        maybe_advance_region();
      }
      if (auto r = deserialize(v); !r.ok()) [[unlikely]] {
        return r;
      }
    }
    return {};
  }

  template <concepts::varint T>
  constexpr status parse_packed_varints_in_a_region(auto current, auto &&it) {
    using value_type = std::decay_t<decltype(*it)>;
    while (current.size()) {
      T underlying;
      auto p = unchecked_parse_varint(current, underlying);
      if (p > current._end) [[unlikely]] {
        return std::errc::bad_message;
      }
      current.advance_to(p);
      *it = static_cast<value_type>(underlying.value);
      ++it;
    }
    return std::errc{};
  };

  template <concepts::varint T>
  constexpr status parse_packed_varints_in_regions(std::uint32_t bytes_count, auto &item) {
    auto it = item.data();
    while (bytes_count > 0) {
      maybe_advance_region();
      auto data = current.consume_packed_varints(bytes_count);
      if (data.empty()) [[unlikely]] {
        return std::errc::bad_message;
      }
      bytes_count -= static_cast<std::uint32_t>(data.size());
      if (auto result = parse_packed_varints_in_a_region<T>(data, it); !result.ok()) [[unlikely]] {
        return result;
      }
    }
    return {};
  }

  template <concepts::varint T, typename Item>
  constexpr status deserialize_packed_varint([[maybe_unused]] std::uint32_t bytes_count, std::size_t size, Item &item) {
    item.resize(size);
#if defined(__x86_64__) || defined(_M_AMD64) // x64
    if constexpr (sfvint_parser_allowed<Context>()) {
      if (!std::is_constant_evaluated() && has_bmi2()) {
        using value_type = typename Item::value_type;
        sfvint_parser<T, value_type> parser(item.data());
        if constexpr (!contiguous) {
          while (bytes_count > region_size()) {
            auto saved_begin = current.begin();
            auto p = parser.parse_partial(current);
            if (p == nullptr) [[unlikely]] {
              return std::errc::bad_message;
            }
            current.advance_to(p);
            bytes_count -= static_cast<std::uint32_t>(current.begin() - saved_begin);
            maybe_advance_region();
          }
        }
        if (bytes_count > 0) {
          if (parser.parse(current.consume(bytes_count)) == nullptr) [[unlikely]] {
            return std::errc::bad_message;
          }
        }
        return {};
      }
    }
#endif

    if constexpr (contiguous) {
      return parse_packed_varints_in_a_region<T>(current.consume(bytes_count), item.data());
    } else {
      return parse_packed_varints_in_regions<T>(bytes_count, item);
    }
  }

  constexpr status skip_varint() {
    // varint must terminated in 10 bytes
    const auto *last = std::min(current.begin() + 10, current.end());
    const auto *pos = std::find_if(current.begin(), last, [](auto v) { return static_cast<int8_t>(v) >= 0; });
    if (pos == last) [[unlikely]] {
      return std::errc::bad_message;
    }
    current.advance_to(pos + 1);
    return {};
  }

  constexpr status skip_length_delimited() {
    vuint32_t len;
    if (auto result = deserialize(len); !result.ok()) [[unlikely]] {
      return result;
    }
    return skip(len.value);
  }

  constexpr status skip(std::size_t length) {
    if (std::cmp_less(in_avail(), length)) [[unlikely]] {
      return std::errc::bad_message;
    }
    current.consume(length);
    return {};
  }

  // split the object at the specified length;
  // return the first half and set the current
  // object as the second half.
  constexpr auto split(std::size_t length) {
    assert(std::cmp_greater_equal(in_avail(), length));
    auto new_slope_distance = current.slope_distance() + static_cast<std::ptrdiff_t>(length);
    std::ptrdiff_t new_size_exclude_current = 0;
    if constexpr (contiguous) {
      if (new_slope_distance > 0) {
        new_size_exclude_current = new_slope_distance;
      }
      const auto *new_slope_begin = std::min(current._begin + length, current._slope_begin);
      return basic_in<byte_type, Context, contiguous>{
          input_buffer_region<Byte>{current.consume(length), new_slope_begin}, rest, new_size_exclude_current, context};
    } else {
      if (new_slope_distance > 0) {
        if (std::cmp_less_equal(new_slope_distance, slope_size)) {
          new_size_exclude_current = new_slope_distance;
        } else {
          new_size_exclude_current = size_exclude_current - new_slope_distance;
        }
      }
      auto new_begin = current._begin;
      auto new_end = std::min(current._end, current._begin + length);
      auto new_slope_begin = std::min(new_end, current._slope_begin);
      current.consume(length);
      auto new_region = input_buffer_region<Byte>{{new_begin, new_end}, new_slope_begin};
      return basic_in<byte_type, Context, contiguous>{new_region, rest, new_size_exclude_current, context};
    }
  }

  template <concepts::non_owning_bytes T>
  constexpr status read_bytes(uint32_t length, T &item) {
    assert(std::cmp_greater_equal(region_size(), length));
    auto data = current.consume(length);
    item = T{(const typename T::value_type *)data.data(), length};
    return {};
  }

  constexpr auto unwind_tag(uint32_t tag) {
    auto tag_len = varint_size<varint_encoding::normal>(tag);
    basic_in<byte_type, Context, contiguous> dup(*this);
    dup.current.revert(tag_len);
    return dup;
  }

  constexpr status operator()(auto &&...item) {
    status result;
    (void)(((result = deserialize(item)).ok()) && ...);
    return result;
  }

  constexpr std::size_t count_number_of_varints_in_region(std::size_t n) {
    auto [data, remaining] = current.subspan(0, n).split(n - (n % 8));

    std::size_t result = 0;
    auto popcount = [](uint64_t v) -> int {
#if defined(__x86_64__) && defined(__GNUC__) && !defined(__clang__)
      if (!std::is_constant_evaluated()) {
        if (__builtin_cpu_supports("popcnt")) {
          int64_t count;
          __asm__("popcntq %1, %0" : "=r"(count) : "rm"(v));
          return count;
        }
      }
#endif
      return std::popcount(v);
    };

    while (data.size()) {
      uint64_t v = 0;
      auto bytes = data.consume(sizeof(v));
      std::memcpy(&v, bytes.data(), sizeof(v));
      result += static_cast<std::size_t>(popcount(~v & 0x8080808080808080ULL));
    }

    if (remaining.size()) {
      uint64_t v = UINT64_MAX;
      std::memcpy(&v, remaining.data(), remaining.size());
      result += static_cast<std::size_t>(popcount(~v & 0x8080808080808080ULL));
    }
    return result;
  }

  // Given the fact that the next n bytes are all variable length integers,
  // find the number of integers in the range.
  constexpr std::optional<std::size_t> number_of_varints(std::uint32_t bytes_count) {
    std::ptrdiff_t num_bytes = bytes_count;
    if (region_size() >= num_bytes) [[likely]] {
      if (std::bit_cast<int8_t>(current[bytes_count - 1]) < 0) [[unlikely]] {
        // if the last element is unterminated, just return empty to indicate error
        return {};
      }
      return count_number_of_varints_in_region(bytes_count);
    } else if (num_bytes <= in_avail()) {
      if constexpr (!contiguous) {
        basic_in archive(*this);
        std::size_t result = 0;
        while (num_bytes > 0 && in_avail() > 0) {
          archive.maybe_advance_region();
          if (num_bytes > archive.region_size()) {
            auto n = archive.region_size();
            result += archive.count_number_of_varints_in_region(n);
            archive.current.consume(n);
            num_bytes -= static_cast<uint32_t>(n);
          } else {
            if (std::bit_cast<int8_t>(archive.current[num_bytes - 1]) < 0) [[unlikely]] {
              // if the last element is unterminated, just return empty to indicate error
              return {};
            }
            return result + archive.count_number_of_varints_in_region(num_bytes);
          }
        }
      }
    }
    return {};
  }

  constexpr std::uint32_t read_tag() {
    maybe_advance_region();
    std::int64_t res; // NOLINT(cppcoreguidelines-init-variables)
    if (auto p = shift_mix_parse_varint<std::uint32_t, 4>(current, res); p <= current._end) {
      current.advance_to(p);
      return static_cast<std::uint32_t>(res);
    }
    return 0;
  }

  constexpr bool match_tag(std::uint32_t tag) {
    maybe_advance_region();
    std::int64_t res; // NOLINT(cppcoreguidelines-init-variables)
    if (auto p = shift_mix_parse_varint<std::uint32_t, 4>(current, res); p <= current._end) {
      if (std::cmp_equal(res, tag)) {
        current.advance_to(p);
        return true;
      }
    }
    return false;
  }
};
// NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

constexpr status deserialize_unknown_fields(concepts::associative_container auto &unknown_fields, uint32_t field_num,
                                            std::size_t field_len, concepts::is_basic_in auto &archive) {
  return archive.deserialize_packed(field_len, unknown_fields[field_num]);
}

constexpr status deserialize_unknown_fields(concepts::uint32_pair_contiguous_range auto &unknown_fields,
                                            uint32_t field_num, std::size_t field_len,
                                            concepts::is_basic_in auto &archive) {
  auto itr = std::find_if(unknown_fields.begin(), unknown_fields.end(),
                          [field_num](const auto &e) { return e.first == field_num; });

  using fields_type = std::remove_cvref_t<decltype(unknown_fields)>;
  using bytes_type = typename fields_type::value_type::second_type;

  if (itr == unknown_fields.end() && archive.in_avail() == archive.region_size()) [[likely]] {
    bytes_type field_span;
    if (auto result = archive.deserialize_packed(field_len, detail::as_modifiable(archive.context, field_span));
        !result.ok()) {
      return result;
    }
    unknown_fields.push_back({field_num, field_span});
    return {};
  }
  // the extension with the same field number exists, append the content to the previously parsed.
  return archive.deserialize_packed(field_len,
                                    detail::as_modifiable(archive.context, const_cast<bytes_type &>(itr->second)));
}

constexpr status deserialize_unknown_fields(concepts::contiguous_byte_range auto &unknown_fields, uint32_t,
                                            std::size_t field_len, concepts::is_basic_in auto &archive) {
  return archive.deserialize_packed(field_len, unknown_fields);
}

constexpr void deserialize_unknown_enum(auto &unknown_fields, uint32_t field_num, int64_t value,
                                        concepts::is_basic_in auto &archive) {
  std::array<std::byte, 16> data{};
  auto tag = make_tag(field_num, wire_type::varint);
  auto *p = unchecked_pack_varint(varint{tag}, data.data());
  p = unchecked_pack_varint(varint{value}, p);
  std::span field_span{data.data(), static_cast<std::size_t>(p - data.data())};
  using unknown_fields_t = std::remove_cvref_t<decltype(unknown_fields)>;
  if constexpr (concepts::contiguous_byte_range<unknown_fields_t>) {
    util::append_range(unknown_fields, field_span);
  } else if constexpr (concepts::associative_container<unknown_fields_t>) {
    util::append_range(unknown_fields[field_num], field_span);
  } else if constexpr (concepts::uint32_pair_contiguous_range<unknown_fields_t>) {
    auto itr = std::find_if(unknown_fields.begin(), unknown_fields.end(),
                            [field_num](const auto &e) { return e.first == field_num; });
    if (itr == unknown_fields.end()) {
      unknown_fields.push_back({field_num, field_span});
    } else {
      using bytes_type = typename unknown_fields_t::value_type::second_type;
      decltype(auto) v = detail::as_modifiable(archive.context, const_cast<bytes_type &>(itr->second));
      util::append_range(v, field_span);
    }
  }
}

template <typename T>
constexpr status skip_field(uint32_t tag, concepts::is_basic_in auto &archive, T &unknown_fields) {
  if constexpr (std::is_empty_v<T>) {
    return do_skip_field(tag, archive);
  } else {
    auto unwound_archive = archive.unwind_tag(tag);
    if (auto result = skip_fields_match_tag(tag, archive); !result.ok()) [[unlikely]] {
      return result;
    }

    auto field_len = static_cast<std::size_t>(unwound_archive.in_avail() - archive.in_avail());
    auto field_archive = unwound_archive.split(field_len);

    return deserialize_unknown_fields(unknown_fields, tag_number(tag), field_len, field_archive);
  }
}

constexpr status do_skip_field(uint32_t tag, concepts::is_basic_in auto &archive) {
  if (tag == 0) [[unlikely]] {
    return std::errc::bad_message;
  }
  switch (proto::tag_type(tag)) {
  case wire_type::varint:
    return archive.skip_varint();
  case wire_type::length_delimited:
    return archive.skip_length_delimited();
  case wire_type::fixed_64:
    return archive.skip(8);
  case wire_type::sgroup:
    return do_skip_group(tag_number(tag), archive);
  case wire_type::fixed_32:
    return archive.skip(4);
  default:
    return std::errc::bad_message;
  }
}

constexpr status skip_fields_match_tag(uint32_t tag, concepts::is_basic_in auto &archive) {
  if (auto result = do_skip_field(tag, archive); !result.ok()) {
    return result;
  }

  while (archive.match_tag(tag)) {
    if (auto result = do_skip_field(tag, archive); !result.ok()) {
      return result;
    }
  }
  return {};
}

constexpr status do_skip_group(uint32_t field_num, concepts::is_basic_in auto &archive) {
  while (archive.in_avail() > 0) {
    auto tag = archive.read_tag();

    const uint32_t next_field_num = tag_number(tag);
    const wire_type next_type = proto::tag_type(tag);

    if (next_type == wire_type::egroup && field_num == next_field_num) {
      return {};
    } else if (archive.in_avail() <= 0) [[unlikely]] {
      return std::errc::bad_message;
    }
    if (auto result = do_skip_field(tag, archive); !result.ok()) {
      return result;
    }
  }
  return std::errc::bad_message;
}

template <typename T>
constexpr std::optional<std::size_t> count_packed_elements(uint32_t length, concepts::is_basic_in auto &archive) {
  if constexpr (concepts::byte_deserializable<T>) {
    if (length % sizeof(T) == 0) [[likely]] {
      return length / sizeof(T);
    } else {
      return {};
    }
  } else if constexpr (std::same_as<T, bool> || std::same_as<T, boolean> || concepts::is_enum<T> ||
                       concepts::varint<T>) {
    return archive.number_of_varints(length);
  } else {
    static_assert(!sizeof(T));
  }
}

constexpr status count_unpacked_elements(uint32_t input_tag, std::size_t &count, concepts::is_basic_in auto &archive) {
  auto new_archive = archive.copy();
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-do-while)
  do {
    if (auto result = do_skip_field(input_tag, new_archive); !result.ok()) {
      return result;
    }

    ++count;

    if (new_archive.in_avail() == 0) {
      return {};
    }
  } while (new_archive.read_tag() == input_tag);
  return {};
}

constexpr status count_groups(uint32_t input_tag, std::size_t &count, concepts::is_basic_in auto &archive) {
  auto new_archive = archive.copy();
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-do-while)
  do {
    if (auto result = do_skip_group(tag_number(input_tag), new_archive); !result.ok()) {
      return result;
    }

    ++count;

    if (new_archive.in_avail() == 0) {
      return {};
    }
  } while (new_archive.read_tag() == input_tag);
  return {};
}

template <typename Meta>
constexpr status deserialize_packed_repeated(Meta, auto &&item, concepts::is_basic_in auto &archive,
                                             auto &unknown_fields) {
  using type = std::remove_reference_t<decltype(item)>;
  using value_type = typename type::value_type;

  using encode_type =
      std::conditional_t<std::same_as<typename Meta::type, void> || std::same_as<value_type, char> ||
                             std::same_as<value_type, std::byte> || std::same_as<typename Meta::type, type>,
                         value_type, typename Meta::type>;

  vuint32_t byte_count;
  if (auto result = archive(byte_count); !result.ok()) [[unlikely]] {
    return result;
  }
  if (byte_count == 0) {
    return {};
  }

  decltype(auto) v = detail::as_modifiable(archive.context, item);
  if constexpr (requires { v.resize(1); }) {
    [[maybe_unused]] auto old_size = std::ssize(v);
    auto result = deserialize_packed_repeated_with_byte_count<encode_type>(v, byte_count, archive);
    if constexpr (Meta::closed_enum()) {
      auto start_itr = std::next(v.begin(), old_size);
      auto itr = std::remove_if(start_itr, v.end(), [&](auto v) {
        if (!Meta::valid_enum_value(v)) {
          deserialize_unknown_enum(unknown_fields, Meta::number, std::to_underlying(v), archive);
          return true;
        }
        return false;
      });
      v.resize(static_cast<std::size_t>(std::distance(v.begin(), itr)));
    }
    return result;
  } else {
    using context_t = std::decay_t<decltype(archive.context)>;
    static_assert(concepts::has_memory_resource<context_t>, "memory resource is required");
    return {};
  }
}

template <typename EncodeType>
constexpr status deserialize_packed_repeated_with_byte_count(concepts::resizable auto &&v, vuint32_t byte_count,
                                                             concepts::is_basic_in auto &archive) {

  // packed repeated vector,
  auto n = count_packed_elements<EncodeType>(static_cast<uint32_t>(byte_count), archive);
  if (!n.has_value()) {
    return std::errc::bad_message;
  }
  std::size_t size = *n;
  if constexpr (std::same_as<EncodeType, boolean> || std::same_as<EncodeType, bool>) {
    return archive.deserialize_packed_boolean(size, v);
  } else if constexpr (concepts::byte_deserializable<EncodeType>) {
    v.resize(0);
    return archive.deserialize_packed(size, v);
  } else if constexpr (concepts::is_enum<EncodeType>) {
    return archive.template deserialize_packed_varint<vint64_t>(byte_count, size, v);
  } else {
    static_assert(concepts::varint<EncodeType>);
    return archive.template deserialize_packed_varint<EncodeType>(byte_count, size, v);
  }
}

template <typename MetaType, typename ValueType>
struct deserialize_element_type {
  using type = ValueType;
};

template <concepts::is_map_entry MetaType, typename ValueType>
struct deserialize_element_type<MetaType, ValueType> {
  using type = typename MetaType::mutable_type;
};

// NOLINTBEGIN(readability-function-cognitive-complexity)
template <typename Meta>
constexpr status deserialize_unpacked_repeated(Meta meta, uint32_t tag, auto &&item,
                                               concepts::is_basic_in auto &archive, auto &unknown_fields) {
  using type = std::remove_reference_t<decltype(item)>;
  using value_type = typename type::value_type;

  decltype(auto) v = detail::as_modifiable(archive.context, item);
  if (tag_type(tag) !=
      tag_type<std::conditional_t<std::is_same_v<typename Meta::type, void>, value_type, typename Meta::type>>()) {
    return std::errc::bad_message;
  }

  std::size_t count = 0;
  if (auto result = count_unpacked_elements(tag, count, archive); !result.ok()) [[unlikely]] {
    return result;
  }
  auto old_size = item.size();
  const std::size_t new_size = item.size() + count;
  using element_type = typename deserialize_element_type<typename Meta::type, value_type>::type;
  auto deserialize_element = [&](element_type &element) {
    if constexpr (concepts::has_meta<element_type>) {
      return deserialize_sized(element, archive);
    } else {
      return deserialize_field(element, meta, tag, archive, unknown_fields);
    }
  };

  if constexpr (concepts::associative_container<type>) {
    if constexpr (concepts::flat_map<type>) {
      reserve(v, new_size);
    } else if constexpr (requires { v.reserve(new_size); }) {
      v.reserve(new_size);
    }
  } else {
    if constexpr (meta.closed_enum()) {
      v.reserve(new_size);
    } else if constexpr (requires { v.resize(new_size); }) {
      v.resize(new_size);
    }
  }

  for (auto i = old_size; i < new_size; ++i) {
    if constexpr (concepts::associative_container<type>) {
      element_type element;

      if (auto result = deserialize_element(element); !result.ok()) {
        return result;
      }

      auto val = static_cast<value_type>(std::move(element));
      if constexpr (requires { v.insert_or_assign(std::move(val.first), std::move(val.second)); }) {
        v.insert_or_assign(std::move(val.first), std::move(val.second));
      } else { // pre-C++23 std::map
        v[std::move(val.first)] = std::move(val.second);
      }
    } else if constexpr (std::same_as<element_type, value_type> && !meta.closed_enum()) {
      if (auto result = deserialize_element(v[i]); !result.ok()) [[unlikely]] {
        return result;
      }
    } else {
      element_type element;
      if (auto result = deserialize_element(element); !result.ok()) [[unlikely]] {
        return result;
      }
      if constexpr (meta.closed_enum()) {
        if (meta.valid_enum_value(element)) {
          v.push_back(element);
        } else {
          deserialize_unknown_enum(unknown_fields, tag_number(tag), std::to_underlying(element), archive);
        }
      } else {
        v[i] = std::move(static_cast<value_type>(std::move(element)));
      }
    }

    if (i < new_size - 1) {
      // no error handling here, because  `count_unpacked_elements()` already checked the tag
      archive.maybe_advance_region();
      (void)archive.read_tag();
    }
  }
  return {};
}
// NOLINTEND(readability-function-cognitive-complexity)

template <typename Meta>
constexpr status deserialize_repeated_group(Meta, uint32_t tag, auto &&item, concepts::is_basic_in auto &archive) {
  decltype(auto) v = detail::as_modifiable(archive.context, item);

  std::size_t count = 0;
  if (auto result = count_groups(tag, count, archive); !result.ok()) [[unlikely]] {
    return result;
  }
  auto old_size = item.size();
  const std::size_t new_size = item.size() + count;

  v.resize(new_size);

  for (auto i = old_size; i < new_size; ++i) {
    if (auto result = deserialize_group(tag_number(tag), v[i], archive); !result.ok()) [[unlikely]] {
      return result;
    }

    if (i < new_size - 1) {
      // no error handling here, because  `count_groups()` already checked the tag
      archive.maybe_advance_region();
      (void)archive.read_tag();
    }
  }
  return {};
}

constexpr status deserialize_field(boolean &item, auto, uint32_t, concepts::is_basic_in auto &archive,
                                   auto & /* unknown_fields*/) {
  return archive(item.value);
}

template <typename Meta>
constexpr status deserialize_field(concepts::is_enum auto &item, Meta, uint32_t, concepts::is_basic_in auto &archive,
                                   auto &unknown_fields) {
  vint64_t value;
  if (auto result = archive(value); !result.ok()) [[unlikely]] {
    return result;
  }
  using enum_type = std::remove_reference_t<decltype(item)>;

  if constexpr (Meta::closed_enum() && Meta::explicit_presence()) {
    if (!Meta::valid_enum_value(static_cast<enum_type>(value.value))) [[unlikely]] {
      deserialize_unknown_enum(unknown_fields, Meta::number, value, archive);
      return std::errc::value_too_large;
    }
  }

  item = static_cast<enum_type>(value.value);

  return {};
}

constexpr status deserialize_field(concepts::optional_message_view auto &item, auto meta, uint32_t tag,
                                   concepts::is_basic_in auto &archive, auto &unknown_fields) {
  using context_t = std::decay_t<decltype(archive.context)>;
  static_assert(concepts::has_memory_resource<context_t>, "memory resource is required");
  using element_type = std::remove_cvref_t<decltype(*item)>;
  void *buffer = archive.context.memory_resource().allocate(sizeof(element_type), alignof(element_type));
  auto loaded = new (buffer) element_type; // NOLINT(cppcoreguidelines-owning-memory)
  if (auto result = deserialize_field(*loaded, meta, tag, archive, unknown_fields); !result.ok()) [[unlikely]] {
    return result;
  }
  item = loaded;
  return {};
}

template <concepts::optional T>
  requires(!concepts::optional_message_view<T>)
constexpr status deserialize_field(T &item, auto meta, uint32_t tag, concepts::is_basic_in auto &archive,
                                   auto &unknown_fields) {
  status result;
  using type = std::remove_reference_t<T>;
  if constexpr (meta.closed_enum()) {
    typename type::value_type tmp;
    result = deserialize_field(tmp, meta, tag, archive, unknown_fields);
    if (result.ok()) [[likely]] {
      item = tmp;
    } else if (result == std::errc::value_too_large) {
      return {};
    }
  } else if constexpr (requires { item.emplace(); }) {
    result = deserialize_field(item.emplace(), meta, tag, archive, unknown_fields);

  } else {
    item = typename type::value_type{};
    result = deserialize_field(*item, meta, tag, archive, unknown_fields);
  }

  return result;
}

template <typename Meta>
constexpr status deserialize_field(concepts::oneof_type auto &item, Meta, uint32_t tag,
                                   concepts::is_basic_in auto &archive, auto &unknown_fields) {
  using type = std::remove_reference_t<decltype(item)>;
  static_assert(std::is_same_v<std::remove_cvref_t<decltype(std::get<0>(type{}))>, std::monostate>);
  return deserialize_oneof<0, typename Meta::alternatives_meta>(tag, item, archive, unknown_fields);
}

template <typename Meta>
constexpr status deserialize_field(concepts::arithmetic auto &item, Meta meta, uint32_t tag,
                                   concepts::is_basic_in auto &archive, auto &unknown_fields) {
  using type = std::remove_reference_t<decltype(item)>;
  using serialize_type = typename traits::get_serialize_type<Meta, type>::type;
  if constexpr (!std::is_same_v<type, serialize_type>) {
    serialize_type value;
    if (auto result = deserialize_field(value, meta, tag, archive, unknown_fields); !result.ok()) [[unlikely]] {
      return result;
    }
    item = static_cast<type>(value);
    return {};
  } else {
    return archive(item);
  }
}

constexpr status deserialize_field(concepts::has_meta auto &item, auto meta, uint32_t tag,
                                   concepts::is_basic_in auto &archive, auto & /* unknown_fields*/) {
  if constexpr (!meta.is_delimited()) {
    return deserialize_sized(item, archive);
  } else {
    return deserialize_group(tag_number(tag), item, archive);
  }
}

template <typename Meta>
constexpr status deserialize_field(std::ranges::range auto &item, Meta meta, uint32_t tag,
                                   concepts::is_basic_in auto &archive, auto &unknown_fields) {
  using type = std::remove_reference_t<decltype(item)>;

  if constexpr (concepts::contiguous_byte_range<type>) {
    if (auto result = deserialize_packed_repeated(meta, item, archive, unknown_fields); !result.ok()) {
      return result;
    }
    return utf8_validation_failed(meta, item) ? std::errc::bad_message : std::errc{};
  } else if constexpr (meta.is_delimited()) {
    // repeated group
    return deserialize_repeated_group(meta, tag, item, archive);
  } else { // repeated non-group
    if constexpr (meta.is_packed()) {
      if (tag_type(tag) != wire_type::length_delimited) {
        return deserialize_unpacked_repeated(meta, tag, item, archive, unknown_fields);
      }
      return deserialize_packed_repeated(meta, item, archive, unknown_fields);
    } else {
      return deserialize_unpacked_repeated(meta, tag, item, archive, unknown_fields);
    }
  }
}

template <std::size_t Index, concepts::tuple Meta>
constexpr status deserialize_oneof(uint32_t tag, auto &&item, concepts::is_basic_in auto &archive,
                                   auto &unknown_fields) {
  if constexpr (Index < std::tuple_size_v<Meta>) {
    using meta = typename std::tuple_element_t<Index, Meta>;
    if (meta::number == tag_number(tag)) {
      if constexpr (meta::closed_enum()) {
        std::variant_alternative_t<Index + 1, std::decay_t<decltype(item)>> v;
        auto result = deserialize_field(v, meta{}, tag, archive, unknown_fields);
        if (result.ok()) [[likely]] {
          std::get<Index + 1>(item) = v;
          return {};
        } else if (result == std::errc::value_too_large) {
          return {};
        }
        return result;
      } else if constexpr (requires { item.template emplace<Index + 1>(); }) {
        return deserialize_field(item.template emplace<Index + 1>(), meta{}, tag, archive, unknown_fields);
      } else {
        item = std::variant_alternative_t<Index + 1, std::decay_t<decltype(item)>>{};
        return deserialize_field(std::get<Index + 1>(item), meta{}, tag, archive, unknown_fields);
      }
    } else {
      return deserialize_oneof<Index + 1, Meta>(tag, std::forward<decltype(item)>(item), archive, unknown_fields);
    }
  } else {
    unreachable();
    return {};
  }
}

template <std::uint32_t Index>
constexpr status deserialize_field_by_index(uint32_t tag, concepts::has_meta auto &item,
                                            concepts::is_basic_in auto &archive, auto &&unknown_fields) {
  if constexpr (Index != UINT32_MAX) {
    using type = std::remove_reference_t<decltype(item)>;
    using Meta = typename traits::field_meta_of<type, Index>::type;
    return deserialize_field(Meta::access(item), Meta(), tag, archive, unknown_fields);
  } else if (archive.in_avail() > 0) {
    return skip_field(tag, archive, unknown_fields);
  } else {
    return std::errc::bad_message;
  }
}

constexpr status deserialize_field_by_tag(uint32_t tag, concepts::has_meta auto &item,
                                          concepts::is_basic_in auto &archive, auto &&unknown_fields) {
  using type = std::remove_cvref_t<decltype(item)>;
  using dispatcher_t = traits::reverse_indices<type>;
  if (tag == 0) {
    return std::errc::bad_message;
  }
  return dispatcher_t::dispatch(tag_number(tag), [&](auto index) {
    return deserialize_field_by_index<decltype(index)::value>(tag, item, archive, unknown_fields);
  });
}

constexpr auto &get_unknown_fields(auto &item)
  requires requires { item.unknown_fields_.fields; }
{
  return item.unknown_fields_.fields;
}

constexpr auto &get_unknown_fields(auto &item)
  requires requires { item.extensions; }
{
  return item.extensions.fields;
}

constexpr std::monostate get_unknown_fields(auto &) { return {}; }

constexpr status deserialize_group(uint32_t field_num, auto &&item, concepts::is_basic_in auto &archive) {
  decltype(auto) unknown_fields = get_unknown_fields(item);
  decltype(auto) modifiable_unknown_fields = detail::as_modifiable(archive.context, unknown_fields);
  while (archive.in_avail() > 0) {
    auto tag = archive.read_tag();
    if (proto::tag_type(tag) == wire_type::egroup && field_num == tag_number(tag)) {
      return {};
    }
    if (auto result = deserialize_field_by_tag(tag, item, archive, modifiable_unknown_fields); !result.ok())
        [[unlikely]] {
      return result;
    }
  }

  return std::errc::bad_message;
}

constexpr status deserialize(auto &&item, concepts::is_basic_in auto &archive) {
  decltype(auto) unknow_fields = get_unknown_fields(item);
  decltype(auto) modifiable_unknown_fields = detail::as_modifiable(archive.context, unknow_fields);
  while (archive.in_avail() > 0) {
    auto tag = archive.read_tag();
    if (auto result = deserialize_field_by_tag(tag, item, archive, modifiable_unknown_fields); !result.ok()) {
      [[unlikely]] return result;
    }
  }
  return archive.in_avail() == 0 ? std::errc{} : std::errc::bad_message;
}

constexpr status deserialize_sized(auto &&item, concepts::is_basic_in auto &archive) {
  vuint32_t len;
  if (auto result = archive(len); !result.ok() || len == 0) [[unlikely]] {
    return result;
  }

  if (len < archive.in_avail()) [[likely]] {
    auto new_archive = archive.split(len);
    return deserialize(item, new_archive);
  } else if (len == archive.in_avail()) {
    return deserialize(item, archive);
  }
  return std::errc::bad_message;
}

constexpr status extract_length_delimited_field(uint32_t number, bytes_view &bytes, concepts::is_basic_in auto &archive)
  requires(std::remove_cvref_t<decltype(archive)>::contiguous)
{
  while (archive.in_avail() > 0) {
    auto tag = archive.read_tag();
    if (tag_type(tag) != wire_type::length_delimited) {
      return std::errc::bad_message;
    }
    if (tag_number(tag) == number) {
      vuint32_t len;
      if (auto result = archive(len); !result.ok() || len == 0) [[unlikely]] {
        return result;
      }

      if (len <= archive.in_avail()) [[likely]] {
        return archive.read_bytes(len, bytes);
      }
      return std::errc::bad_message;
    } else if (auto result = do_skip_field(tag, archive); !result.ok()) {
      return result;
    }
  }
  return archive.in_avail() == 0 ? std::errc{} : std::errc::bad_message;
}

template <typename Context, typename Byte>
struct contiguous_input_archive_base {
  std::array<Byte, patch_buffer_size> patch_buffer;
  std::array<input_buffer_region<Byte>, 2> regions = {};
  constexpr explicit contiguous_input_archive_base(Context &) {}
};

// when memory resource is used, the patch buffer must come from it because
// the decoded string or bytes may refer to the memory in patch buffer
template <concepts::has_memory_resource Context, typename Byte>
struct contiguous_input_archive_base<Context, Byte> {
  std::span<Byte> patch_buffer;
  std::array<input_buffer_region<Byte>, 2> regions = {};
  constexpr explicit contiguous_input_archive_base(Context &context)
      : patch_buffer(static_cast<Byte *>(context.memory_resource().allocate(patch_buffer_size, 1)), patch_buffer_size) {
  }
};

template <concepts::is_pb_context Context, typename Byte>
struct contiguous_input_archive : contiguous_input_archive_base<Context, Byte>, basic_in<Byte, Context, true> {
  constexpr contiguous_input_archive(const auto &buffer, Context &context) noexcept
      : contiguous_input_archive_base<Context, Byte>(context),
        basic_in<Byte, Context, true>(std::span{&buffer, 1}, this->regions, this->patch_buffer, context) {}

  constexpr ~contiguous_input_archive() noexcept = default;
  contiguous_input_archive(const contiguous_input_archive &) = delete;
  contiguous_input_archive(contiguous_input_archive &&) = delete;
  contiguous_input_archive &operator=(const contiguous_input_archive &) = delete;
  contiguous_input_archive &operator=(contiguous_input_archive &&) = delete;
};

template <concepts::contiguous_byte_range Buffer, concepts::is_pb_context Context>
contiguous_input_archive(const Buffer &,
                         Context &) -> contiguous_input_archive<Context, std::ranges::range_value_t<Buffer>>;

constexpr status deserialize(auto &item, concepts::contiguous_byte_range auto const &buffer) {
  pb_context ctx;
  return deserialize(item, buffer, ctx);
}

constexpr status deserialize(auto &item, concepts::contiguous_byte_range auto const &buffer,
                             concepts::is_pb_context auto &context) {
  contiguous_input_archive archive{buffer, context};
  return deserialize(item, archive);
}

template <typename Byte>
constexpr status deserialize(auto &item, concepts::is_pb_context auto &context,
                             concepts::segmented_byte_range auto const &buffer,
                             std::span<input_buffer_region<Byte>> regions, std::span<Byte> patch_buffer_cache) {
  constexpr bool is_contiguous = false;
  auto archive =
      basic_in<Byte, std::decay_t<decltype(context)>, is_contiguous>(buffer, regions, patch_buffer_cache, context);
  return deserialize(item, archive);
}

constexpr status deserialize(auto &item, concepts::segmented_byte_range auto const &buffer,
                             concepts::is_pb_context auto &context) {
  const auto num_segments = std::size(buffer);
  const auto num_regions = num_segments * 2;
  const auto patch_buffer_bytes_count = num_segments * patch_buffer_size;
  const auto regions_bytes_count = num_regions * sizeof(input_buffer_region<char>);
  using buffer_type = std::remove_cvref_t<decltype(buffer)>;
  using segment_type = std::ranges::range_value_t<buffer_type>;
  using byte_type = std::ranges::range_value_t<segment_type>;

  if constexpr (requires { context.memory_resource(); }) {
    auto patch_buffer =
        std::span{static_cast<byte_type *>(context.memory_resource().allocate(patch_buffer_bytes_count, 1)),
                  patch_buffer_bytes_count};
    auto regions = std::span{static_cast<input_buffer_region<byte_type> *>(context.memory_resource().allocate(
                                 regions_bytes_count, alignof(input_buffer_region<byte_type>))),
                             num_regions};
    return deserialize(item, context, buffer, regions, patch_buffer);
  } else {
    if (num_segments > 8) {
      std::vector<byte_type> patch_buffer(patch_buffer_bytes_count);
      std::vector<input_buffer_region<byte_type>> regions(num_regions);
      return deserialize(item, context, buffer, std::span{regions.data(), regions.size()},
                         std::span{patch_buffer.data(), patch_buffer.size()});
    } else {
#ifdef _WIN32
      std::unique_ptr<byte_type, freea> patch_buffer_ptr{static_cast<byte_type *>(_malloca(patch_buffer_bytes_count))};
      auto patch_buffer = std::span{patch_buffer_ptr.get(), patch_buffer_bytes_count};
      std::unique_ptr<input_buffer_region<byte_type>, freea> regions_ptr{
          static_cast<input_buffer_region<byte_type> *>(_malloca(regions_bytes_count))};
      auto regions = std::span{regions_ptr.get(), num_regions};
#else
      auto patch_buffer =
          std::span{static_cast<byte_type *>(alloca(patch_buffer_bytes_count)), patch_buffer_bytes_count};
      auto regions = std::span{static_cast<input_buffer_region<byte_type> *>(alloca(regions_bytes_count)), num_regions};
#endif
      return deserialize(item, context, buffer, regions, patch_buffer);
    }
  }
}
} // namespace pb_serializer
// NOLINTEND(bugprone-easily-swappable-parameters)

template <typename F>
  requires std::regular_invocable<F>
consteval auto write_proto(F make_object) {
  constexpr auto obj = make_object();
  constexpr auto sz = pb_serializer::message_size_calculator<decltype(obj)>::message_size(obj);
  if constexpr (sz == 0) {
    return std::span<std::byte>{};
  } else {
    pb_context ctx;
    std::array<std::byte, sz> buffer = {};
    if (auto result = pb_serializer::serialize(obj, buffer, ctx); !result.ok()) {
      throw std::system_error(std::make_error_code(result.ec));
    }
    return buffer;
  }
}

template <concepts::has_meta T, concepts::contiguous_byte_range Buffer>
status write_proto(T &&msg, Buffer &buffer, concepts::is_pb_context auto &ctx) {
  decltype(auto) v = detail::as_modifiable(ctx, buffer);
  return pb_serializer::serialize(std::forward<T>(msg), v, ctx);
}

template <concepts::has_meta T, concepts::contiguous_byte_range Buffer>
status write_proto(T &&msg, Buffer &buffer, concepts::is_option_type auto &&...option) {
  pb_context ctx{std::forward<decltype(option)>(option)...};
  return write_proto(std::forward<T>(msg), buffer, ctx);
}

template <concepts::contiguous_byte_range Buffer = std::vector<std::byte>>
expected<Buffer, std::errc> write_proto(concepts::has_meta auto const &msg, concepts::is_option_type auto &&...option) {
  Buffer buffer;
  if (auto result = write_proto(msg, buffer, std::forward<decltype(option)>(option)...); !result.ok()) {
    return unexpected(result.ec);
  } else {
    return buffer;
  }
}

/// @brief serialize a message to the end of the supplied buffer
template <concepts::has_meta T>
status append_proto(T &&msg, concepts::resizable_contiguous_byte_container auto &buffer) {
  constexpr bool overwrite_buffer = false;
  pb_context ctx;
  return pb_serializer::serialize<overwrite_buffer>(std::forward<T>(msg), buffer, ctx);
}

template <concepts::has_meta T>
constexpr static expected<T, std::errc> read_proto(concepts::input_byte_range auto const &buffer,
                                                   concepts::is_option_type auto &&...option) {
  T msg{};
  pb_context ctx{std::forward<decltype(option)>(option)...};
  if (auto result = pb_serializer::deserialize(msg, buffer, ctx); !result.ok()) {
    return unexpected(result.ec);
  }
  return msg;
}

template <concepts::has_meta T, concepts::input_byte_range Buffer>
status read_proto(T &msg, const Buffer &buffer, concepts::is_pb_context auto &ctx) {
  msg = {};
  return pb_serializer::deserialize(msg, buffer, ctx);
}

template <concepts::has_meta T, concepts::input_byte_range Buffer>
status read_proto(T &msg, const Buffer &buffer, concepts::is_option_type auto &&...option) {
  pb_context ctx{std::forward<decltype(option)>(option)...};
  return read_proto(msg, buffer, ctx);
}

template <typename T, template <typename Traits> class Extendee>
struct extension_base {
  constexpr static auto number() {
    using field_meta_t = std::tuple_element_t<0, typename hpp::proto::traits::meta_of<T>::type>;
    return field_meta_t::number;
  }

  template <typename Traits>
  status get_from(const Extendee<Traits> &extendee, concepts::is_option_type auto &&...option) {
    auto &fields = pb_serializer::get_unknown_fields(extendee);
    decltype(fields.begin()) itr;

    if constexpr (requires { fields.find(number()); }) {
      itr = fields.find(number());
    } else {
      itr = std::find_if(fields.begin(), fields.end(), [](const auto &item) { return item.first == number(); });
    }

    if (itr != fields.end()) {
      return read_proto(*static_cast<T *>(this), itr->second, std::forward<decltype(option)>(option)...);
    }

    return {};
  }

  template <typename Traits>
  status set_to(Extendee<Traits> &extendee, concepts::is_option_type auto &&...option) const {
    auto &fields = pb_serializer::get_unknown_fields(extendee);
    using fields_type = std::decay_t<decltype(fields)>;
    using bytes_type = typename fields_type::value_type::second_type;
    bytes_type data;

    pb_context ctx{std::forward<decltype(option)>(option)...};
    if (auto result = write_proto(*static_cast<const T *>(this), data, ctx); !result.ok()) [[unlikely]] {
      return result;
    }

    if (data.size()) {
      if constexpr (concepts::associative_container<fields_type>) {
        fields[number()] = std::move(data);
      } else {
        detail::as_modifiable(ctx, fields).emplace_back(number(), data);
      }
    }
    return {};
  }

  template <typename Traits>
  static bool in(const Extendee<Traits> &extendee) {
    auto &fields = pb_serializer::get_unknown_fields(extendee);
    if constexpr (requires { fields.count(number()); }) {
      return fields.count(number()) > 0;
    } else {
      return std::find_if(fields.begin(), fields.end(), [](const auto &item) { return item.first == number(); }) !=
             fields.end();
    }
  }
};

namespace concepts {
template <typename T>
concept is_any = requires(T &obj) {
  { obj.type_url };
  requires concepts::string_like<std::remove_reference_t<decltype(obj.type_url)>>;
  { obj.value } -> concepts::contiguous_byte_range;
};
} // namespace concepts

status pack_any(concepts::is_any auto &any, concepts::has_meta auto const &msg) {
  any.type_url = message_type_url(msg);
  return write_proto(msg, any.value);
}

status pack_any(concepts::is_any auto &any, concepts::has_meta auto const &msg,
                concepts::is_option_type auto &&...option) {
  any.type_url = message_type_url(msg);
  auto ctx = pb_context{std::forward<decltype(option)>(option)...};
  decltype(auto) v = detail::as_modifiable(ctx, any.value);
  return write_proto(msg, v);
}

status unpack_any(concepts::is_any auto const &any, concepts::has_meta auto &msg,
                  concepts::is_option_type auto &&...option) {
  if (std::string_view{any.type_url}.ends_with(message_name(msg))) {
    return read_proto(msg, any.value, std::forward<decltype(option)>(option)...);
  }
  return std::errc::invalid_argument;
}

template <concepts::has_meta T>
expected<T, std::errc> unpack_any(concepts::is_any auto const &any, concepts::is_option_type auto &&...option) {
  T msg;
  if (auto result = unpack_any(any, msg, std::forward<decltype(option)>(option)...); !result.ok()) {
    return unexpected(result.ec);
  } else {
    return msg;
  }
}
namespace detail {
template <typename Tuple1, typename Tuple2, std::size_t... I>
constexpr auto zip_tuples_impl(const Tuple1 &t1, const Tuple2 &t2, std::index_sequence<I...>) -> decltype(auto) {
  // Use the index sequence (I...) to expand a pack of std::pair constructions.
  // std::get<I>(t1) accesses the I-th element of t1.
  return std::make_tuple(std::make_pair(std::get<I>(t1), std::get<I>(t2))...);
}

template <typename... T1, typename... T2>
constexpr auto zip_tuples(const std::tuple<T1...> &t1, const std::tuple<T2...> &t2) -> decltype(auto) {
  // Ensure the tuples are the same size at compile time
  static_assert(sizeof...(T1) == sizeof...(T2), "Tuples must have the same size.");

  // Generate an index sequence from 0 up to the size of the tuples.
  return zip_tuples_impl(t1, t2, std::make_index_sequence<sizeof...(T1)>{});
}

} // namespace detail

namespace concepts {

template <typename T>
concept string_view_or_bytes_view = std::same_as<T, bytes_view> || concepts::basic_string_view<T>;

template <typename T>
concept arithmetic_pair =
    is_pair<T> && std::is_arithmetic_v<typename T::first_type> && std::is_arithmetic_v<typename T::second_type>;
} // namespace concepts

template <concepts::is_pb_context Context>
struct message_merger {
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  Context &ctx;
  template <concepts::has_meta T, typename U>
    requires concepts::isomorphic_message<T, std::decay_t<U>>
  constexpr void perform(T &dest, U &&source) {
    return std::apply(
        [this, &dest, &source](auto &&...metas) {
          // NOLINTNEXTLINE(bugprone-use-after-move,hicpp-invalid-access-moved)
          (this->perform(metas, metas.first.access(dest), metas.second.access(std::forward<U>(source))), ...);
        },
        detail::zip_tuples(typename traits::meta_of<T>::type{}, typename traits::meta_of<std::decay_t<U>>::type{}));
  }

  template <typename MetaT, typename MetaU, typename T, typename U>
  void perform(std::pair<MetaT, MetaU>, T &dest, U &&source) {
    if constexpr (concepts::variant<T>) {
      if (source.index() > 0) {
        if (dest.index() == source.index()) {
          using alt_metas =
              decltype(detail::zip_tuples(typename MetaT::alternatives_meta{}, typename MetaU::alternatives_meta{}));
          perform(alt_metas(), dest, std::forward<U>(source), std::make_index_sequence<std::tuple_size_v<alt_metas>>());
          return;
        }

        if constexpr (std::same_as<T, std::decay_t<U>>) {
          dest = std::forward<U>(source);
        } else {
          assign(dest, std::forward<U>(source),
                 std::make_index_sequence<std::tuple_size_v<typename MetaU::alternatives_meta>>());
        }
      }
    } else if constexpr (MetaT::explicit_presence() || !concepts::singular<T>) {
      perform(dest, std::forward<U>(source));
    } else {
      if (!MetaU::omit_value(source)) {
        perform(dest, source);
      }
    }
  }

  template <typename MetaPairs, concepts::variant T, typename U, std::size_t FirstIndex, std::size_t... Indices>
  void perform(MetaPairs metas, T &dest, U &&source, std::index_sequence<FirstIndex, Indices...>) {
    if (dest.index() == FirstIndex + 1) {
      perform(std::get<FirstIndex>(metas), std::get<FirstIndex + 1>(dest),
              std::get<FirstIndex + 1>(std::forward<U>(source)));
    } else {
      perform(metas, dest, std::forward<U>(source), std::index_sequence<Indices...>());
    }
  }

  template <typename MetaPairs, concepts::variant T, concepts::variant U>
  constexpr void perform(MetaPairs, T &, const U &, std::index_sequence<>) {}

  template <concepts::variant T, typename U, std::size_t FirstIndex, std::size_t... Indices>
  void assign(T &dest, const U &source, std::index_sequence<FirstIndex, Indices...>) {
    if (source.index() == FirstIndex + 1) {
      perform(dest.template emplace<FirstIndex + 1>(), std::get<FirstIndex + 1>(source));
    } else {
      assign(dest, source, std::index_sequence<Indices...>());
    }
  }

  template <concepts::variant T, typename U>
  void assign(T &, const U &, std::index_sequence<>) {}

  template <concepts::optional T, typename U>
  constexpr void perform(T &dest, U &&source) {
    if constexpr (concepts::has_meta<typename T::value_type>) {
      if (source.has_value()) {
        if (!dest.has_value()) {
          perform(dest.emplace(), *std::forward<U>(source));
        } else {
          perform(*dest, *std::forward<U>(source));
        }
      }
    } else {
      if (source.has_value()) {
        perform(dest.emplace(), *std::forward<U>(source));
      }
    }
  }

  template <concepts::repeated T, typename U>
    requires(std::assignable_from<typename T::value_type &, typename U::value_type>)
  constexpr void perform(T &dest, const U &source) {
    if constexpr (std::ranges::contiguous_range<U>) {
      if (dest.empty()) {
        if constexpr (std::assignable_from<T &, U>) {
          dest = source;
        } else {
          dest.assign(source.begin(), source.end());
        }
        return;
      }
    }
    decltype(auto) v = detail::as_modifiable(ctx, dest);
    util::append_range(v, source);
  }

  template <concepts::repeated T, typename U>
    requires(!std::assignable_from<typename T::value_type &, typename U::value_type>)
  constexpr void perform(T &dest, auto const &source) {
    decltype(auto) x = detail::as_modifiable(ctx, dest);
    auto orig_size = dest.size();
    x.resize(dest.size() + source.size());
    for (std::size_t i = 0; i < source.size(); ++i) {
      perform(dest[i + orig_size], source[i]);
    }
  }

  template <concepts::is_pair T, typename U>
  constexpr void perform(T &dest, const U &source) {
    dest.first = source.first;
    perform(dest.second, source.second);
  }

  template <concepts::associative_container T, typename U>
  constexpr void perform(T &dest, U &&source) {
    if (!source.empty()) {
      if constexpr (std::same_as<T, std::decay_t<U>>) {
        if (dest.empty()) {
          dest = std::forward<U>(source);
          return;
        }
      }
      insert_or_replace(dest, std::forward<U>(source));
    }
  }

  template <typename T, typename U>
    requires requires { typename T::mapped_type; }
  constexpr void insert_or_replace(T &dest, const U &source) {
    T tmp;
    tmp.swap(dest);
    if constexpr (std::same_as<T, U>) {
      dest = source;
    } else {
      dest.insert(source.begin(), source.end());
    }
    if constexpr (requires { dest.insert(sorted_unique, tmp.begin(), tmp.end()); }) {
      dest.insert(sorted_unique, tmp.begin(), tmp.end());
    } else {
      dest.insert(tmp.begin(), tmp.end());
    }
  }

  template <typename T>
    requires requires { typename T::mapped_type; }
  // NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
  constexpr void insert_or_replace(T &dest, T &&source) {
    source.swap(dest);
    if constexpr (requires { dest.insert(sorted_unique, source.begin(), source.end()); }) {
      // flat_map
      dest.insert(sorted_unique, source.begin(), source.end());
    } else if constexpr (requires { dest.merge(source); }) {
      // std::map, std::unordered_map
      dest.merge(source);
    } else {
      dest.insert(source.begin(), source.end());
    }
  }

  template <typename T>
    requires(concepts::pb_unknown_fields<T> || concepts::pb_extensions<T>)
  constexpr void perform(T &dest, const T &source) {
    perform(dest.fields, source.fields);
  }

  template <concepts::singular T, typename U>
  constexpr void perform(T &dest, U &&source) {
    if constexpr (std::assignable_from<T &, U>) {
      dest = std::forward<U>(source);
    } else if constexpr (requires { dest.assign_range(source); }) {
      dest.assign_range(source);
    } else if constexpr (requires { dest.assign(source.begin(), source.end()); }) {
      dest.assign(source.begin(), source.end());
    } else {
      static_assert(false, "invalid operation");
    }
  }
};

/// @brief Merge the fields from the `source` message into `dest` message.
/// @details Singular fields supplied in `source` overwrite those in `dest`, except embedded messages which merge.
/// Repeated fields append the values from `source`. For non-owning traits, map fields behave like repeated fields;
/// entries are appended without deduplication, so if a key appears multiple times only the last value should be
/// considered authoritative. Both messages must share the same concrete type.
template <concepts::has_meta T, typename U>
  requires concepts::isomorphic_message<T, std::decay_t<U>>
constexpr void merge(T &dest, U &&source, concepts::is_option_type auto &&...option) {
  pb_context ctx{std::forward<decltype(option)>(option)...};
  message_merger merger{ctx};
  merger.perform(dest, std::forward<U>(source));
}

} // namespace hpp::proto
#undef HPP_PROTO_INLINE
