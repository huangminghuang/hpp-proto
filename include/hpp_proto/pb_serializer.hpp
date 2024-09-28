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

#ifndef HPP_PROTO_H
#define HPP_PROTO_H
#include <array>
#include <bit>
#include <cassert>
#include <climits>
#include <concepts>
#include <cstddef>
#include <cstring>

#include <map>
#include <memory>
#include <numeric>
#include <system_error>

#include <execution>
#include <glaze/util/expected.hpp>
#include <hpp_proto/memory_resource_utils.hpp>

#if defined(__x86_64__) || defined(_M_AMD64) // x64
#if defined(_WIN32)
#include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif
#endif

#if defined(__GNUC__)
#define HPP_PROTO_INLINE [[gnu::always_inline]] inline
#elif defined(_MSC_VER)
#pragma warning(error : 4714)
#define HPP_PROTO_INLINE __forceinline
#else
#define HPP_PROTO_INLINE inline
#endif

extern "C" {
  bool is_utf8(const char *src, size_t len);
}

namespace hpp::proto {
using glz::expected;
using glz::unexpected;

#if HPP_PROTO_NO_UTF8_VALIDATION
constexpr bool is_string_and_not_utf8(const auto &str) { return false; }
#else
template <typename T>
constexpr bool is_string_and_not_utf8(const T &str) {
  if constexpr (std::same_as<T, std::string> || std::same_as<T, std::string_view>) {
    if (!std::is_constant_evaluated()) {
      return !::is_utf8(str.data(), str.size());
    }
  }
  return false;
}
#endif

// Always allocate memory for string and bytes fields when
// deserializing non-owning messages.
struct always_allocate_memory {
  using auxiliary_context_type = always_allocate_memory;
};

/////////////////////////////////////////////////////

enum class varint_encoding : uint8_t {
  normal,
  zig_zag,
};

template <varint_encoding Encoding = varint_encoding::normal>
constexpr auto varint_size(auto value) {
  // NOLINTBEGIN(hicpp-signed-bitwise)
  if constexpr (Encoding == varint_encoding::zig_zag) {
    return varint_size(std::make_unsigned_t<decltype(value)>((value << 1) ^ (value >> (sizeof(value) * CHAR_BIT - 1))));
  } else {
    return ((sizeof(value) * CHAR_BIT) - std::countl_zero(std::make_unsigned_t<decltype(value)>(value) | 1U) +
            (CHAR_BIT - 2)) /
           (CHAR_BIT - 1);
  }
  // NOLINTEND(hicpp-signed-bitwise)
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

////////////////////////////////////////////////////

namespace concepts {

template <typename T>
concept is_enum = std::is_enum_v<T> && !std::same_as<std::byte, T> && !std::same_as<hpp::proto::boolean, T>;

template <typename T>
concept is_boolean = std::same_as<hpp::proto::boolean, T>;

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
concept string =
    std::same_as<std::remove_cvref_t<T>, std::string> || std::same_as<std::remove_cvref_t<T>, std::string_view>;

template <typename T>
concept has_local_meta = concepts::tuple<typename T::pb_meta>;

template <typename T>
concept has_explicit_meta = concepts::tuple<decltype(pb_meta(std::declval<T>()))>;

template <typename T>
concept has_meta = has_local_meta<std::remove_cvref_t<T>> || has_explicit_meta<T>;

template <typename T>
concept dereferenceable = requires(T item) { *item; };

template <typename T>
concept optional_message_view = std::same_as<T, ::hpp::proto::optional_message_view<typename T::value_type>>;

template <typename T>
concept optional = requires(T optional) {
  optional.value();
  optional.has_value();
  // optional.operator bool(); // this operator is deliberately removed to fit
  // our specialization for optional<bool> which removed this operation
  optional.operator*();
} && !optional_message_view<T>;

template <typename T>
concept oneof_type = concepts::variant<T>;

template <typename T>
concept arithmetic = std::is_arithmetic_v<T> || concepts::varint<T>;

template <typename T>
concept byte_serializable =
    std::is_arithmetic_v<T> || std::same_as<hpp::proto::boolean, T> || std::same_as<std::byte, T>;

template <typename T>
concept pb_extension = requires(T value) { typename T::pb_extension; };

template <typename T>
concept no_cached_size = is_enum<T> || byte_serializable<T> || concepts::varint<T> || pb_extension<T>;

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
  requires std::derived_from<T, std::span<typename T::element_type>>;
};

template <typename T>
concept is_oneof_field_meta = requires { typename T::alternatives_meta; };

template <typename T>
concept is_size_cache_iterator = requires(T v) {
  // NOLINTBEGIN(bugprone-inc-dec-in-conditions)
  { v++ } -> std::same_as<T>;
  // NOLINTEND(bugprone-inc-dec-in-conditions)
  *v;
};

template <typename T>
concept non_owning_bytes = std::same_as<std::remove_cvref_t<T>, std::string_view> ||
                           (concepts::span<std::remove_cvref_t<T>> && concepts::byte_type<typename T::value_type>);

template <typename T>
concept has_extension = has_meta<T> && requires(T value) {
  value.extensions;
  typename decltype(T::extensions)::pb_extension;
};

template <typename T>
concept unique_ptr = requires {
  typename T::element_type;
  typename T::deleter_type;
  requires std::same_as<T, std::unique_ptr<typename T::element_type, typename T::deleter_type>>;
};

template <typename T>
concept is_basic_in = requires { typename T::is_basic_in; };

template <typename T>
concept is_basic_out = requires { typename T::is_basic_out; };

template <typename Range>
concept segmented_byte_range =
    std::ranges::random_access_range<Range> && contiguous_byte_range<std::ranges::range_value_t<Range>>;

template <typename Range>
concept input_byte_range = segmented_byte_range<Range> || contiguous_byte_range<Range>;

} // namespace concepts

////////////////////

template <concepts::varint VarintType, concepts::byte_type Byte>
constexpr Byte *unchecked_pack_varint(VarintType item, Byte *data) {
  auto value = std::make_unsigned_t<typename VarintType::encode_type>(item.value);

  if constexpr (varint_encoding::zig_zag == decltype(item)::encoding) {
    // NOLINTBEGIN(hicpp-signed-bitwise)
    value = (value << 1U) ^ (item.value >> (sizeof(value) * CHAR_BIT - 1));
    // NOLINTEND(hicpp-signed-bitwise)
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
// It requires p points to at least 10 valid bytes. If it is an unterminated varint,
// the function return end + 1; otherwise, the function returns the pointer passed
// the consumed input data.
// NOLINTBEGIN
template <typename Type, int MAX_BYTES = ((sizeof(Type) * 8 + 6) / 7), concepts::byte_type Byte>
constexpr const Byte *shift_mix_parse_varint(const Byte *p, const Byte *end, int64_t &res1) {

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
    return end + 1;
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

template <concepts::byte_type Byte>
constexpr const Byte *unchecked_parse_bool(const Byte *p, bool &value) {
  // This function is adapted from
  // https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/generated_message_tctable_lite.cc
  const auto next = [&p] { return static_cast<unsigned char>(*p++); };
  unsigned char byte = next();
  if (byte == 0 || byte == 1) [[likely]] {
    // This is the code path almost always taken,
    // so we take care to make it very efficient.
    if (sizeof(byte) == sizeof(value)) {
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
                      return p;
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

template <concepts::byte_type Byte, concepts::varint VarintType>
constexpr const Byte *unchecked_parse_varint(const Byte *p, const Byte *end, VarintType &item) {
  // NOLINTBEGIN(cppcoreguidelines-init-variables)
  int64_t res;
  // NOLINTEND(cppcoreguidelines-init-variables)
  if constexpr (varint_encoding::zig_zag == VarintType::encoding) {
    p = shift_mix_parse_varint<typename VarintType::value_type>(p, end, res);
    // NOLINTBEGIN(hicpp-signed-bitwise)
    item = static_cast<typename VarintType::value_type>((static_cast<uint64_t>(res) >> 1) ^ -(res & 0x1));
    // NOLINTEND(hicpp-signed-bitwise)
  } else {
    p = shift_mix_parse_varint<typename VarintType::value_type>(p, end, res);
    item = static_cast<typename VarintType::value_type>(res);
  }
  return p;
}

///////////////////

enum field_option : uint8_t { none = 0, explicit_presence = 1, unpacked_repeated = 2, group = 4 };

template <auto Accessor>
struct accessor_type {
  constexpr auto &operator()(auto &&item) const {
    if constexpr (std::is_member_pointer_v<decltype(Accessor)>) {
      return item.*Accessor;
    } else {
      return Accessor(std::forward<decltype(item)>(item));
    }
  }
};

template <uint32_t Number, uint8_t options, typename Type, auto DefaultValue>
struct field_meta_base {

  constexpr static uint32_t number = Number;
  using type = Type;

  constexpr static bool is_explicit_presence = static_cast<bool>(options & field_option::explicit_presence);
  constexpr static bool is_unpacked_repeated = static_cast<bool>(options & field_option::unpacked_repeated);
  constexpr static bool is_group = static_cast<bool>(options & field_option::group);

  template <typename T>
  static constexpr bool omit_value(const T &v) {
    if constexpr (options == field_option::none) {
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

template <uint32_t Number, auto Accessor, int options = field_option::none, typename Type = void,
          auto DefaultValue = std::monostate{}>
struct field_meta : field_meta_base<Number, options, Type, DefaultValue> {
  constexpr static auto access = accessor_type<Accessor>{};
};

template <auto Accessor, typename... AlternativeMeta>
struct oneof_field_meta {
  constexpr static auto access = accessor_type<Accessor>{};
  using alternatives_meta = std::tuple<AlternativeMeta...>;
  using type = void;
  template <typename T>
  static constexpr bool omit_value(const T &v) {
    return v.index() == 0;
  }
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

template <typename T>
struct extension_meta_base {

  struct accessor_type {
    constexpr auto &operator()(auto &&item) const {
      auto &[e] = item;
      return e;
    }
  };

  constexpr static auto access = accessor_type{};

  static constexpr void check(const concepts::pb_extension auto &extensions) {
    static_assert(std::same_as<typename std::remove_cvref_t<decltype(extensions)>::pb_extension, typename T::extendee>);
  }

  static auto read(const concepts::pb_extension auto &extensions, concepts::is_pb_context auto &&...ctx);
  static status write(concepts::pb_extension auto &extensions, auto &&value);
  static status write(concepts::pb_extension auto &extensions, auto &&value, concepts::is_pb_context auto &&ctx);
  static bool element_of(const concepts::pb_extension auto &extensions) {
    check(extensions);
    if constexpr (requires { extensions.fields.count(T::number); }) {
      return extensions.fields.count(T::number) > 0;
    } else {
      return std::find_if(extensions.fields.begin(), extensions.fields.end(),
                          [](const auto &item) { return item.first == T::number; }) != extensions.fields.end();
    }
  }
};

template <typename Extendee, uint32_t Number, int options, typename Type, typename ValueType,
          auto DefaultValue = std::monostate{}>
struct extension_meta : field_meta_base<Number, options, Type, DefaultValue>,
                        extension_meta_base<extension_meta<Extendee, Number, options, Type, ValueType, DefaultValue>> {
  constexpr static auto default_value = unwrap(DefaultValue);
  constexpr static bool has_default_value = !std::same_as<std::remove_const_t<decltype(DefaultValue)>, std::monostate>;
  static constexpr bool is_repeated = false;
  using extendee = Extendee;

  using get_result_type = ValueType;
  using set_value_type = ValueType;
};

template <typename Extendee, uint32_t Number, int options, typename Type, typename ValueType>
struct repeated_extension_meta
    : field_meta_base<Number, options, Type, std::monostate{}>,
      extension_meta_base<repeated_extension_meta<Extendee, Number, options, Type, ValueType>> {
  constexpr static bool has_default_value = false;
  static constexpr bool is_repeated = true;
  using extendee = Extendee;
  static constexpr bool non_owning = concepts::span<decltype(std::declval<typename extendee::extension_t>().fields)>;
  using element_type = std::conditional_t<std::is_same_v<ValueType, bool> && !non_owning, boolean, ValueType>;
  using get_result_type = std::conditional_t<non_owning, std::span<const element_type>, std::vector<element_type>>;
  using set_value_type = std::span<const element_type>;

  template <typename T>
  static constexpr bool omit_value(const T & /* unused */) {
    return false;
  }
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
  if constexpr (concepts::varint<type> || (std::is_enum_v<type> && !std::same_as<type, std::byte>) ||
                std::same_as<type, bool>) {
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
constexpr auto make_tag(Meta meta) {
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

template <typename KeyType, typename MappedType>
struct map_entry {
  using key_type = KeyType;
  using mapped_type = MappedType;
  struct mutable_type {
    typename serialize_type<KeyType>::type key = {};
    typename serialize_type<MappedType>::type value = {};
    constexpr static bool allow_inline_visit_members_lambda = true;
    using pb_meta = std::tuple<field_meta<1, &mutable_type::key, field_option::explicit_presence>,
                               field_meta<2, &mutable_type::value, field_option::explicit_presence>>;

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
    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    typename serialize_type<KeyType>::read_type key;
    typename serialize_type<MappedType>::read_type value;
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
    constexpr static bool allow_inline_visit_members_lambda = true;

    constexpr read_only_type(auto &&k, auto &&v)
        : key((typename serialize_type<KeyType>::convertible_type)k),
          value((typename serialize_type<MappedType>::convertible_type)v) {}

    struct key_accessor {
      constexpr const auto &operator()(const read_only_type &entry) const { return entry.key; }
    };

    struct value_accessor {
      constexpr const auto &operator()(const read_only_type &entry) const { return entry.value; }
    };

    using pb_meta = std::tuple<field_meta<1, key_accessor{}, field_option::explicit_presence>,
                               field_meta<2, value_accessor{}, field_option::explicit_presence>>;
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
  using type = typename std::tuple_element<Index, typename meta_of<Type>::type>::type;
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
  // NOLINTBEGIN(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
  std::array<T, M + N> result;
  // NOLINTEND(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
  std::copy(lhs.begin(), lhs.end(), result.begin());
  std::copy(rhs.begin(), rhs.end(), result.begin() + M);
  return result;
}

template <typename T, std::size_t M>
constexpr std::array<T, M> operator<<(std::array<T, M> lhs, std::span<uint32_t>) {
  return lhs;
}

template <concepts::has_meta Type>
struct reverse_indices {

  template <typename T>
    requires requires { T::number; }
  constexpr static auto get_numbers(T meta) {
    if constexpr (meta.number != UINT32_MAX) {
      return std::array<uint32_t, 1>{meta.number};
    } else {
      return std::span<uint32_t>{};
    }
  }

  template <typename... T>
  constexpr static auto get_numbers(std::tuple<T...> metas) {
    return std::apply([](auto... elem) { return (... << get_numbers(elem)); }, metas);
  }

  template <concepts::is_oneof_field_meta Meta>
  constexpr static auto get_numbers(Meta /* unused */) {
    return std::apply([](auto... elem) { return (... << get_numbers(elem)); }, typename Meta::alternatives_meta{});
  }

  constexpr static auto numbers = get_numbers(typename traits::meta_of<Type>::type{});
  constexpr static unsigned max_number = numbers.size() > 0 ? *std::max_element(numbers.begin(), numbers.end()) : 0;

  constexpr static auto mask = (1U << static_cast<unsigned>(std::bit_width(numbers.size()))) - 1;

  template <std::size_t I, typename T>
    requires requires { T::number; }
  constexpr static auto index(T) {
    return std::array{I};
  }

  template <std::size_t I, concepts::is_oneof_field_meta Meta>
  constexpr static auto index(Meta) {
    // NOLINTBEGIN(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
    std::array<std::size_t, std::tuple_size_v<typename Meta::alternatives_meta>> result;
    // NOLINTEND(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
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

  constexpr static auto indices = get_indices(typename traits::meta_of<Type>::type{});

  consteval static auto build_lookup_table_indices() {
    std::array<uint32_t, mask + 1> masked_number_occurrences = {};

    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
    for (auto num : numbers) {
      ++masked_number_occurrences[num & mask];
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)

    std::array<uint32_t, mask + 2> table_indices = {0};
    std::partial_sum(masked_number_occurrences.begin(), masked_number_occurrences.end(), table_indices.begin() + 1);
    return table_indices;
  }

  consteval static auto build_lookup_table() {
    constexpr auto lookup_table_indices = build_lookup_table_indices();
    if constexpr (numbers.empty()) {
      return std::span<std::pair<uint32_t, uint32_t>>{};
    } else {
      std::array<uint32_t, mask + 1> counts = {};
      std::copy(lookup_table_indices.begin(), lookup_table_indices.end() - 1, counts.begin());

      std::array<std::pair<uint32_t, uint32_t>, numbers.size()> result;
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
      for (uint32_t i = 0; i < numbers.size(); ++i) {
        auto num = numbers[i];
        auto masked_num = num & mask;
        result[counts[masked_num]++] = {num, static_cast<uint32_t>(indices[i])};
      }
      // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
      return result;
    }
  }

  template <uint32_t masked_number>
  consteval static auto lookup_table_for_masked_number() {
    constexpr auto lookup_table_indices = build_lookup_table_indices();
    constexpr auto lookup_table = build_lookup_table();
    constexpr auto size = lookup_table_indices[masked_number + 1] - lookup_table_indices[masked_number];
    if constexpr (size > 0) {
      std::array<std::pair<uint32_t, uint32_t>, size> result;
      std::copy(lookup_table.begin() + lookup_table_indices[masked_number],
                lookup_table.begin() + lookup_table_indices[masked_number + 1], result.begin());
      return result;
    } else {
      return std::span<std::pair<uint32_t, uint32_t>>{};
    }
  }
};

template <typename Type>
inline constexpr auto number_of_members = std::tuple_size_v<typename meta_of<Type>::type>;
} // namespace traits

#if defined(__cpp_lib_constexpr_vector)
template <typename T>
using constexpr_vector = std::vector<T>;
#else
template <typename T>
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
  bool has_error = false;
  explicit sfvint_parser(Result *data) : res(data) {}

  static consteval int calc_shift_bits(unsigned sign_bits) {
    unsigned mask = 1U << (mask_length - 1);
    int result = 0;
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
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic,hicpp-signed-bitwise)
    auto r = (varint_encoding::zig_zag == T::encoding) ? (v >> 1U) ^ -static_cast<int64_t>(v & 1U) : v;
    *res++ = static_cast<Result>(r);
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic,hicpp-signed-bitwise)
  }

  // NOLINTBEGIN(bugprone-easily-swappable-parameters)
  static uint64_t pext_u64(uint64_t a, uint64_t mask) {
#if defined(__GNUC__) || defined(__clang__)
    // NOLINTBEGIN(cppcoreguidelines-init-variables,hicpp-no-assembler)
    uint64_t result;
    asm("pext %2, %1, %0" : "=r"(result) : "r"(a), "r"(mask));
    // NOLINTEND(cppcoreguidelines-init-variables,hicpp-no-assembler)
    return result;
#else
    return _pext_u64(a, mask);
#endif
  }
  // NOLINTEND(bugprone-easily-swappable-parameters)

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
  HPP_PROTO_INLINE void fixed_masked_parse(uint64_t word) {
    uint64_t extract_mask = calc_extract_mask(SignBits);
    if constexpr (std::countr_one(SignBits) < mask_length) {
      output((pext_u64(word, extract_mask) << shift_bits) | pt_val);
      constexpr unsigned bytes_processed = std::countr_one(SignBits) + 1;
      has_error |= ((bytes_processed * 7 + shift_bits) > max_effective_bits);
      extract_mask = 0x7fULL << (CHAR_BIT * bytes_processed);
      output<SignBits, bytes_processed>(word, extract_mask);
      pt_val = 0;
      shift_bits = 0;
    }

    if constexpr (SignBits & (0x01ULL << (mask_length - 1))) {
      pt_val |= pext_u64(word, extract_mask) << shift_bits;
    }

    shift_bits += calc_shift_bits(SignBits);
  }

  template <std::size_t... I>
  HPP_PROTO_INLINE void parse_word(uint64_t masked_bits, uint64_t word, std::index_sequence<I...>) {
    (void)((masked_bits == I && (fixed_masked_parse<I>(word), true)) || ...);
  }

  template <concepts::byte_type Byte>
  const Byte *parse_partial(const Byte *begin, const Byte *end) {
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    end -= ((end - begin) % mask_length);
    for (; begin < end; begin += mask_length) {
      uint64_t word = 0;
      memcpy(&word, begin, sizeof(word));
      auto mval = pext_u64(word, word_mask);
      parse_word(mval, word, std::make_index_sequence<1U << mask_length>());
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return begin;
  }

  template <concepts::byte_type Byte>
  const Byte *parse(const Byte *begin, const Byte *end) {
    begin = parse_partial(begin, end);
    ptrdiff_t bytes_left = end - begin;
    uint64_t word = 0;
    memcpy(&word, begin, bytes_left);
    for (; bytes_left > 0; --bytes_left, word >>= CHAR_BIT) {
      pt_val |= ((word & 0x7fULL) << shift_bits);
      has_error |= (shift_bits >= max_effective_bits);
      if (word & 0x80ULL) {
        shift_bits += (CHAR_BIT - 1);
      } else {
        output(pt_val);
        pt_val = 0;
        shift_bits = 0;
      }
    }

    return end;
  }
};
#endif

struct pb_serializer {
  template <typename Byte>
  struct basic_out {
    using byte_type = Byte;
    using is_basic_out = void;
    constexpr static bool endian_swapped = std::endian::little != std::endian::native;
    std::span<byte_type> m_data;

    HPP_PROTO_INLINE constexpr void serialize(concepts::byte_serializable auto item) {
      auto value = std::bit_cast<std::array<std::remove_const_t<byte_type>, sizeof(item)>>(item);
      if constexpr (endian_swapped && sizeof(item) != 1) {
        std::copy(value.rbegin(), value.rend(), m_data.begin());
      } else {
        std::copy(value.begin(), value.end(), m_data.begin());
      }
      m_data = m_data.subspan(sizeof(item));
    }

    HPP_PROTO_INLINE constexpr void serialize(concepts::varint auto item) {
      auto p = unchecked_pack_varint(item, m_data.data());
      m_data = m_data.subspan(std::distance(m_data.data(), p));
    }

    template <std::ranges::contiguous_range T>
    HPP_PROTO_INLINE constexpr void serialize(const T &item) {
      using type = std::remove_cvref_t<T>;
      using value_type = typename type::value_type;
      static_assert(concepts::byte_serializable<value_type>);
      if (!std::is_constant_evaluated() && (!endian_swapped || sizeof(value_type) == 1)) {
        auto bytes_to_copy = item.size() * sizeof(value_type);
        std::memcpy(m_data.data(), item.data(), bytes_to_copy);
        m_data = m_data.subspan(bytes_to_copy);
      } else {
        for (auto x : item) {
          this->serialize(x);
        }
      }
    }

    HPP_PROTO_INLINE constexpr void serialize(concepts::is_enum auto item) {
      serialize(varint{static_cast<int64_t>(item)});
    }

    template <typename... Args>
    HPP_PROTO_INLINE constexpr void operator()(Args &&...item) {
      (serialize(std::forward<Args>(item)), ...);
    }
  };

  template <concepts::contiguous_byte_range Range>
  basic_out(Range &&) -> basic_out<std::ranges::range_value_t<Range>>;

  constexpr static std::size_t len_size(std::size_t len) { return varint_size(len) + len; }

  template <typename Range, typename UnaryOperation>
  constexpr static std::size_t transform_accumulate(const Range &range, const UnaryOperation &unary_op) {
    return std::accumulate(range.begin(), range.end(), std::size_t{0},
                           [&unary_op](std::size_t acc, const auto &elem) constexpr { return acc + unary_op(elem); });
  }

  constexpr static std::size_t cache_count(concepts::has_meta auto const &item) {
    using type = std::remove_cvref_t<decltype(item)>;
    using meta_type = typename traits::meta_of<type>::type;
    if constexpr (std::tuple_size_v<meta_type> == 0) {
      return 0;
    } else {
      return std::apply(
          [&item](auto &&...meta) constexpr {
            return ((meta.omit_value(meta.access(item)) ? 0 : cache_count(meta.access(item), meta)) + ...);
          },
          meta_type{});
    }
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t cache_count(concepts::oneof_type auto const &item, Meta) {
    return oneof_cache_count<0, typename Meta::alternatives_meta>(item);
  }

  HPP_PROTO_INLINE constexpr static std::size_t cache_count(concepts::dereferenceable auto const &item, auto meta) {
    // NOLINTBEGIN(bugprone-unchecked-optional-access)
    return cache_count(*item, meta);
    // NOLINTEND(bugprone-unchecked-optional-access)
  }

  HPP_PROTO_INLINE constexpr static std::size_t cache_count(concepts::has_meta auto const &item, auto meta) {
    return cache_count(item) + (!meta.is_group);
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t cache_count(std::ranges::input_range auto const &item, Meta meta) {
    using type = std::remove_cvref_t<decltype(item)>;
    using value_type = typename std::ranges::range_value_t<type>;
    if constexpr (concepts::has_meta<value_type> || meta.is_unpacked_repeated || meta.is_group) {
      return transform_accumulate(item, [](const auto &elem) constexpr { return cache_count(elem, Meta{}); });
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
  HPP_PROTO_INLINE constexpr static std::size_t cache_count(concepts::is_pair auto const &item, Meta) {
    using type = std::remove_cvref_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    static_assert(concepts::is_map_entry<serialize_type>);
    using mapped_type = typename serialize_type::mapped_type;
    if constexpr (concepts::has_meta<mapped_type>) {
      auto r = cache_count(item.second) + 2;
      return r;
    } else {
      return 1;
    }
  }

  HPP_PROTO_INLINE constexpr static std::size_t cache_count(concepts::no_cached_size auto const &, auto) { return 0; }

  template <std::size_t I, typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t oneof_cache_count(auto const &item) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return cache_count(std::get<I + 1>(item), typename std::tuple_element<I, Meta>::type{});
      }
      return oneof_cache_count<I + 1, Meta>(item);
    } else {
      return 0;
    }
  }

  constexpr static std::size_t message_size(concepts::has_meta auto const &item) {
    struct null_size_cache {
      struct null_assignable {
        constexpr null_assignable &operator=(uint32_t) { return *this; }
      };
      uint32_t storage = 0;
      constexpr null_assignable operator*() const { return null_assignable{}; }
      // NOLINTBEGIN(cert-dcl21-cpp)
      constexpr null_size_cache operator++(int) const { return *this; }
      // NOLINTEND(cert-dcl21-cpp)
    } cache;
    return message_size(item, cache);
  }

  constexpr static std::size_t message_size(concepts::has_meta auto &&item, std::span<uint32_t> cache) {
    uint32_t *c = cache.data();
    return message_size(item, c);
  }

  template <concepts::is_size_cache_iterator Itr>
  struct field_size_accumulator {
    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    Itr &cache_itr;
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
    std::size_t sum = 0;
    explicit constexpr field_size_accumulator(Itr &itr) : cache_itr(itr) {}
    constexpr void operator()(auto const &field, auto meta) {
      sum += meta.omit_value(field) ? 0 : field_size(field, meta, cache_itr);
    }
  };

  template <concepts::is_size_cache_iterator T>
  HPP_PROTO_INLINE constexpr static std::size_t message_size(concepts::has_meta auto const &item, T &cache_itr) {
    using type = std::remove_cvref_t<decltype(item)>;
    return std::apply(
        [&item, &cache_itr](auto &&...meta) {
          // we cannot directly use fold expression with '+' operator because it has undefined evaluation order.
          field_size_accumulator<T> accumulator(cache_itr);
          (accumulator(meta.access(item), meta), ...);
          return accumulator.sum;
        },
        typename traits::meta_of<type>::type{});
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t field_size(concepts::oneof_type auto const &item, Meta,
                                                           concepts::is_size_cache_iterator auto &cache_itr) {
    return oneof_size<0, typename Meta::alternatives_meta>(item, cache_itr);
  }

  HPP_PROTO_INLINE constexpr static std::size_t field_size(concepts::pb_extension auto const &item, auto,
                                                           concepts::is_size_cache_iterator auto &) {
    return transform_accumulate(item.fields, [](const auto &e) constexpr { return e.second.size(); });
  }

  HPP_PROTO_INLINE constexpr static std::size_t field_size(concepts::is_enum auto item, auto meta,
                                                           concepts::is_size_cache_iterator auto &) {
    using type = decltype(item);
    return varint_size(meta.number << 3U) + varint_size(static_cast<int64_t>(std::underlying_type_t<type>(item)));
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t field_size(concepts::byte_serializable auto item, Meta meta,
                                                           concepts::is_size_cache_iterator auto &) {
    using type = decltype(item);
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    constexpr std::size_t tag_size = varint_size(meta.number << 3U);
    if constexpr (concepts::byte_serializable<serialize_type>) {
      return tag_size + sizeof(serialize_type);
    } else {
      static_assert(concepts::varint<serialize_type>);
      return tag_size + serialize_type(item).encode_size();
    }
  }

  HPP_PROTO_INLINE constexpr static std::size_t field_size(concepts::varint auto item, auto meta,
                                                           concepts::is_size_cache_iterator auto &) {
    return varint_size(meta.number << 3U) + item.encode_size();
  }

  HPP_PROTO_INLINE constexpr static std::size_t field_size(concepts::dereferenceable auto const &item, auto meta,
                                                           concepts::is_size_cache_iterator auto &cache_itr) {
    // NOLINTBEGIN(bugprone-unchecked-optional-access)
    return field_size(*item, meta, cache_itr);
    // NOLINTEND(bugprone-unchecked-optional-access)
  }

  HPP_PROTO_INLINE constexpr static std::size_t field_size(concepts::has_meta auto const &item, auto meta,
                                                           concepts::is_size_cache_iterator auto &cache_itr) {
    constexpr std::size_t tag_size = varint_size(meta.number << 3U);
    if constexpr (!meta.is_group) {
      decltype(auto) msg_size = *cache_itr++;
      auto s = static_cast<uint32_t>(message_size(item, cache_itr));
      msg_size = s;
      return tag_size + len_size(s);
    } else {
      return 2 * tag_size + message_size(item, cache_itr);
    }
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t field_size(concepts::is_pair auto const &item, Meta meta,
                                                           concepts::is_size_cache_iterator auto &cache_itr) {
    using type = std::remove_cvref_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;
    using value_type = typename serialize_type::read_only_type;

    constexpr std::size_t tag_size = varint_size(meta.number << 3U);
    auto &[key, value] = item;
    decltype(auto) msg_size = *cache_itr++;
    auto s = message_size(value_type{key, value}, cache_itr);
    msg_size = static_cast<uint32_t>(s);
    return tag_size + len_size(s);
  }

  template <typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t field_size(std::ranges::input_range auto const &item, Meta meta,
                                                           concepts::is_size_cache_iterator auto &cache_itr) {
    using type = std::remove_cvref_t<decltype(item)>;
    constexpr std::size_t tag_size = varint_size(meta.number << 3U);
    if constexpr (concepts::contiguous_byte_range<type>) {
      return tag_size + len_size(item.size());
    } else {
      using value_type = typename std::ranges::range_value_t<type>;
      if constexpr (concepts::has_meta<value_type> || meta.is_unpacked_repeated || meta.is_group) {
        return transform_accumulate(
            item, [&cache_itr](const auto &elem) constexpr { return field_size(elem, Meta{}, cache_itr); });
      } else {
        using element_type =
            std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::contiguous_byte_range<type>,
                               value_type, typename Meta::type>;

        if constexpr (concepts::byte_serializable<element_type>) {
          return tag_size + len_size(item.size() * sizeof(value_type));
        } else {
          auto s = transform_accumulate(item, [](auto elem) constexpr {
            if constexpr (std::is_enum_v<element_type>) {
              return varint_size(static_cast<int64_t>(elem));
            } else {
              static_assert(concepts::varint<element_type>);
              return element_type(elem).encode_size();
            }
          });
          decltype(auto) msg_size = *cache_itr++;
          msg_size = static_cast<uint32_t>(s);
          return tag_size + len_size(s);
        }
      }
    }
  }

  template <std::size_t I, typename Meta>
  HPP_PROTO_INLINE constexpr static std::size_t oneof_size(auto const &item,
                                                           concepts::is_size_cache_iterator auto &cache_itr) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return field_size(std::get<I + 1>(item), typename std::tuple_element<I, Meta>::type{}, cache_itr);
      }
      return oneof_size<I + 1, Meta>(item, cache_itr);
    } else {
      return 0;
    }
  }

  template <bool overwrite_buffer = true, std::size_t MAX_CACHE_COUNT = 128, concepts::contiguous_byte_range Buffer>
  constexpr static status serialize(concepts::has_meta auto const &item, Buffer &buffer) {
    std::size_t n = cache_count(item);

    auto do_serialize = [&item, &buffer](std::span<uint32_t> cache) constexpr -> status {
      std::size_t msg_sz = message_size(item, cache);
      std::size_t old_size = overwrite_buffer ? 0 : buffer.size();
      std::size_t new_size = old_size + msg_sz;
      if constexpr (requires { buffer.resize(1); }) {
        buffer.resize(new_size);
      } else if (new_size > buffer.size()) {
        return std::errc::not_enough_memory;
      }

      basic_out archive{buffer};
      auto cache_itr = cache.begin();
      if (!serialize(item, cache_itr, archive)) {
        return std::errc::bad_message;
      }
      if constexpr (requires { buffer.subspan(0, 1); }) {
        buffer = buffer.subspan(old_size, msg_sz);
      }
      return {};
    };

    if (std::is_constant_evaluated() || n > MAX_CACHE_COUNT) {
      constexpr_vector<uint32_t> cache(n);
      return do_serialize(cache);
    } else if (n > 0) {
#if defined(_MSC_VER)
      auto *cache = static_cast<uint32_t *>(_alloca(n * sizeof(uint32_t)));
#elif defined(__GNUC__)
      auto *cache =
          static_cast<uint32_t *>(__builtin_alloca_with_align(n * sizeof(uint32_t), CHAR_BIT * sizeof(uint32_t)));
#else
      uint32_t cache[MAX_CACHE_COUNT];
#endif
      return do_serialize({cache, n});
    } else {
      uint32_t *cache = nullptr;
      return do_serialize({cache, n});
    }
  }

  [[nodiscard]] constexpr static bool serialize(concepts::has_meta auto &&item,
                                                concepts::is_size_cache_iterator auto &cache_itr, auto &archive) {
    using type = std::remove_cvref_t<decltype(item)>;
    using metas = typename traits::meta_of<type>::type;
    auto serialize_field_if_not_empty = [&](auto meta) {
      return meta.omit_value(meta.access(item)) || serialize_field(meta.access(item), meta, cache_itr, archive);
    };
    return std::apply([&](auto... meta) { return (serialize_field_if_not_empty(meta) && ...); }, metas{});
  }

  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)

  template <typename Meta>
  [[nodiscard]] HPP_PROTO_INLINE constexpr static bool serialize_field(concepts::oneof_type auto const &item, Meta,
                                                                       concepts::is_size_cache_iterator auto &cache_itr,
                                                                       auto &archive) {
    return serialize_oneof<0, typename Meta::alternatives_meta>(item, cache_itr, archive);
  }

  [[nodiscard]] HPP_PROTO_INLINE constexpr static bool
  serialize_field(boolean item, auto meta, concepts::is_size_cache_iterator auto &, auto &archive) {
    archive(make_tag<bool>(meta), item.value);
    return true;
  }

  [[nodiscard]] HPP_PROTO_INLINE constexpr static bool serialize_field(concepts::pb_extension auto const &item, auto,
                                                                       concepts::is_size_cache_iterator auto &,
                                                                       auto &archive) {
    for (const auto &f : item.fields) {
      archive(f.second);
    }
    return true;
  }

  [[nodiscard]] HPP_PROTO_INLINE constexpr static bool
  serialize_field(concepts::is_enum auto item, auto meta, concepts::is_size_cache_iterator auto &, auto &archive) {
    archive(make_tag<decltype(item)>(meta), item);
    return true;
  }

  [[nodiscard]] HPP_PROTO_INLINE constexpr static bool
  serialize_field(concepts::arithmetic auto item, auto meta, concepts::is_size_cache_iterator auto &, auto &archive) {
    using serialize_type = typename traits::get_serialize_type<decltype(meta), decltype(item)>::type;
    archive(make_tag<serialize_type>(meta), serialize_type{item});
    return true;
  }

  [[nodiscard]] HPP_PROTO_INLINE constexpr static bool serialize_field(concepts::contiguous_byte_range auto const &item,
                                                                       auto meta,
                                                                       concepts::is_size_cache_iterator auto &,
                                                                       auto &archive) {
    using type = std::remove_cvref_t<decltype(item)>;
    if (is_string_and_not_utf8(item)) {
      return false;
    }
    archive(make_tag<type>(meta), varint{item.size()}, item);
    return true;
  }

  [[nodiscard]] HPP_PROTO_INLINE constexpr static bool serialize_field(concepts::dereferenceable auto &&item, auto meta,
                                                                       concepts::is_size_cache_iterator auto &cache_itr,
                                                                       auto &archive) {
    // NOLINTBEGIN(bugprone-unchecked-optional-access)
    return serialize_field(*item, meta, cache_itr, archive);
    // NOLINTEND(bugprone-unchecked-optional-access)
  }

  [[nodiscard]] HPP_PROTO_INLINE constexpr static bool serialize_field(concepts::has_meta auto const &item, auto meta,
                                                                       concepts::is_size_cache_iterator auto &cache_itr,
                                                                       auto &archive) {
    if constexpr (!meta.is_group) {
      archive(make_tag<decltype(item)>(meta), varint{*cache_itr++});
      return serialize(item, cache_itr, archive);
    } else {
      archive(varint{(meta.number << 3U) | std::underlying_type_t<wire_type>(wire_type::sgroup)});
      if (!serialize(item, cache_itr, archive)) {
        return false;
      }
      archive(varint{(meta.number << 3U) | std::underlying_type_t<wire_type>(wire_type::egroup)});
    }
    return true;
  }

  [[nodiscard]] HPP_PROTO_INLINE constexpr static bool serialize_field(std::ranges::range auto const &item, auto meta,
                                                                       concepts::is_size_cache_iterator auto &cache_itr,
                                                                       auto &archive) {
    using Meta = decltype(meta);
    using type = std::remove_cvref_t<decltype(item)>;
    using value_type = typename std::ranges::range_value_t<type>;
    using element_type =
        std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::contiguous_byte_range<type>,
                           value_type, typename Meta::type>;

    if constexpr (concepts::has_meta<value_type> || meta.is_unpacked_repeated || meta.is_group) {
      for (const auto &element : item) {
        if constexpr (std::same_as<element_type, std::remove_cvref_t<decltype(element)>> ||
                      concepts::is_map_entry<typename Meta::type>) {
          if (!serialize_field(element, meta, cache_itr, archive)) {
            return false;
          }
        } else {
          if (!serialize_field(static_cast<element_type>(element), meta, cache_itr, archive)) {
            return false;
          }
        }
      }
    } else if constexpr (requires {
                           requires std::is_arithmetic_v<element_type> ||
                                        std::same_as<typename type::value_type, std::byte>;
                         }) {
      // packed fundamental types or bytes
      archive(make_tag<type>(meta), varint{item.size() * sizeof(typename type::value_type)}, item);
    } else {
      // packed varint or packed enum
      archive(make_tag<type>(meta), varint{*cache_itr++});
      for (auto element : item) {
        archive(element_type{element});
      }
    }
    return true;
  }

  template <typename Meta>
  [[nodiscard]] HPP_PROTO_INLINE constexpr static bool serialize_field(concepts::is_pair auto const &item, Meta meta,
                                                                       concepts::is_size_cache_iterator auto &cache_itr,
                                                                       auto &archive) {
    static_assert(concepts::is_map_entry<typename Meta::type>);
    using type = std::remove_cvref_t<decltype(item)>;
    constexpr auto tag = make_tag<type>(meta);
    auto &&[key, value] = item;
    archive(tag, varint{*cache_itr++});
    using value_type = typename traits::get_map_entry<Meta, type>::read_only_type;
    static_assert(concepts::has_meta<value_type>);
    return serialize(value_type{key, value}, cache_itr, archive);
  }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

  template <std::size_t I, concepts::tuple Meta>
  [[nodiscard]] HPP_PROTO_INLINE constexpr static bool
  serialize_oneof(auto const &item, concepts::is_size_cache_iterator auto &cache_itr, auto &archive) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return serialize_field(std::get<I + 1>(item), typename std::tuple_element<I, Meta>::type{}, cache_itr, archive);
      }
      return serialize_oneof<I + 1, Meta>(item, cache_itr, archive);
    }
    return true;
  }

  template <typename Byte>
  struct input_buffer_region_base {
    const Byte *begin;
    const Byte *end;
    const Byte *slope_begin;
  };
  template <typename Byte>
  struct input_buffer_region : input_buffer_region_base<Byte> {
    std::size_t effective_size;
  };

  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  template <typename Byte, bool Contiguous>
  struct basic_in {
    using byte_type = Byte;
    input_buffer_region_base<Byte> current;
    const input_buffer_region<Byte> *next_region;
    ptrdiff_t size_exclude_current = 0; // the remaining size excluding those in current

    constexpr static bool endian_swapped = std::endian::little != std::endian::native;

    constexpr void maybe_advance_region() {
      std::ptrdiff_t offset = 0;
      while ((offset = current.begin - current.slope_begin) >= 0 && current.end > current.slope_begin) {
        auto len = in_avail();
        current.begin = next_region->begin + offset;
        current.end = std::min(current.begin + len, next_region->end);
        current.slope_begin = next_region->slope_begin;
        size_exclude_current -= (next_region->effective_size);
        ++next_region;
      }
    }

    template <typename T, typename ByteT>
    constexpr void append_raw_data(T &container, const ByteT *start_pos, std::size_t num_elements) {
      using value_type = typename T::value_type;
      if constexpr (requires { container.append_raw_data(start_pos, num_elements); }) {
        container.append_raw_data(start_pos, num_elements);
      } else if (std::is_constant_evaluated() ||
                 (sizeof(value_type) > 1 && std::endian::little != std::endian::native)) {
        using input_it = detail::raw_data_iterator<value_type, ByteT>;
        container.insert(container.end(), input_it{start_pos}, input_it{start_pos + num_elements * sizeof(value_type)});
      } else {
        auto n = container.size();
        container.resize(n + num_elements);
        std::memcpy(container.data() + n, start_pos, num_elements * sizeof(value_type));
      }
    }

  public:
    using is_basic_in = void;
    constexpr static bool contiguous = Contiguous;
    [[nodiscard]] constexpr ptrdiff_t region_size() const { return current.end - current.begin; }
    [[nodiscard]] constexpr ptrdiff_t in_avail() const { return region_size() + size_exclude_current; }
    [[nodiscard]] constexpr const byte_type *data() const { return current.begin; }

    // NOLINTBEGIN(cppcoreguidelines-slicing)
    constexpr explicit basic_in(const input_buffer_region<Byte> *regions, ptrdiff_t size_exclude_first_region)
        : current(*regions), next_region(++regions), size_exclude_current(size_exclude_first_region) {}
    // NOLINTEND(cppcoreguidelines-slicing)

    constexpr basic_in(input_buffer_region_base<Byte> cur, const input_buffer_region<Byte> *regions,
                       ptrdiff_t size_exclude_current)
        : current(cur), next_region(regions), size_exclude_current(size_exclude_current) {}

    constexpr status deserialize(bool &item) {
      current.begin = unchecked_parse_bool(current.begin, item);
      return {};
    }

    template <concepts::byte_serializable T>
    constexpr status deserialize(T &item) {

      std::array<std::remove_const_t<byte_type>, sizeof(item)> value = {};
      if constexpr (endian_swapped) {
        std::reverse_copy(current.begin, current.begin + sizeof(item), value.begin());
      } else {
        std::copy(current.begin, current.begin + sizeof(item), value.begin());
      }
      item = std::bit_cast<T>(value);
      current.begin += sizeof(item);
      return {};
    }

    template <typename T>
      requires std::is_enum_v<T> && (sizeof(T) > 1)
    constexpr status deserialize(T &item) {
      return deserialize(varint{static_cast<int64_t>(item)});
    }

    template <concepts::varint T>
    constexpr status deserialize(T &item) {
      current.begin = unchecked_parse_varint(current.begin, current.end + 1, item);
      return {};
    }

    template <typename T>
    constexpr status deserialize_packed(std::size_t n, T &item) {
      using value_type = typename T::value_type;
      item.reserve(n);
      if constexpr (contiguous) {
        append_raw_data(item, current.begin, n);
        current.begin += n * sizeof(value_type);
      } else {
        while (n) {
          maybe_advance_region();
          auto k = std::min<std::size_t>(n, region_size() / sizeof(value_type));
          append_raw_data(item, current.begin, k);
          n -= k;
          current.begin += k * sizeof(value_type);
        }
      }
      return {};
    }

#if defined(__x86_64__) || defined(_M_AMD64) // x64
    // workaround for C++20 doesn't support static in constexpr function
    static bool has_bmi2() {
      auto check = [] {
#if defined(_WIN32)
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

    // NOLINTBEGIN(bugprone-easily-swappable-parameters)
    template <concepts::varint T, typename Item>
    constexpr status deserialize_packed_varint(uint32_t bytes_count, std::size_t size, Item &item) {
      using value_type = typename Item::value_type;
      item.resize(size);
#if defined(__x86_64__) || defined(_M_AMD64) // x64
      if (!std::is_constant_evaluated() && has_bmi2()) {

        sfvint_parser<T, value_type> parser(item.data());
        if constexpr (!contiguous) {
          while (bytes_count > region_size()) {
            auto saved_begin = current.begin;
            current.begin = parser.parse_partial(current.begin, current.end);
            bytes_count -= static_cast<uint32_t>(current.begin - saved_begin);
            maybe_advance_region();
          }
        }
        auto end = current.begin + bytes_count;
        current.begin = parser.parse(current.begin, end);
        if (end != current.begin || parser.has_error) [[unlikely]] {
          return std::errc::bad_message;
        }
        return {};
      }
#endif
      (void)bytes_count; // avoid unused parameter warning
      for (unsigned i = 0; i < size; ++i) {
        T underlying;
        if (auto result = this->deserialize(underlying); !result.ok()) [[unlikely]] {
          return result;
        }
        item[i] = static_cast<value_type>(underlying.value);
      }
      return {};
    }
    // NOLINTEND(bugprone-easily-swappable-parameters)

    constexpr status skip_varint() {
      current.begin = std::find_if(current.begin, current.end, [](auto v) { return static_cast<int8_t>(v) >= 0; }) + 1;
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
      current.begin += length;
      return {};
    }

    // split the object at the specified length;
    // return the first half and set the current
    // object as the second half.
    constexpr auto split(ptrdiff_t length) {
      assert(in_avail() >= length);
      auto old_current_begin = current.begin;
      static_cast<void>(skip(length));
      return basic_in<byte_type, contiguous>{
          input_buffer_region_base<Byte>{old_current_begin, old_current_begin + length, current.slope_begin},
          next_region, size_exclude_current};
    }

    //////////////////
    template <concepts::non_owning_bytes T>
    constexpr status read_bytes(uint32_t length, T &item) {
      assert(in_avail() >= static_cast<int32_t>(length));
      item = T{(const typename T::value_type *)current.begin, length};
      static_cast<void>(skip(length));
      return {};
    }

    constexpr auto unwind_tag(uint32_t tag) {
      auto tag_len = varint_size<varint_encoding::normal>(tag);
      return basic_in<byte_type, contiguous>{
          input_buffer_region_base<Byte>{current.begin - tag_len, current.end, current.slope_begin}, next_region,
          size_exclude_current};
    }
    //////////////////

    constexpr status operator()(auto &&...item) {
      status result;
      (void)(((result = deserialize(item)).ok()) && ...);
      return result;
    }

    constexpr std::size_t count_number_of_varints_in_region(std::size_t n) {
      auto begin = current.begin;
      auto end = begin + n;
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
      auto remaining = (end - begin) % 8;
      end -= remaining;

      for (; begin < end; begin += sizeof(uint64_t)) {
        uint64_t v = 0;
        std::memcpy(&v, begin, sizeof(v));
        result += popcount(~v & 0x8080808080808080ULL);
      }
      if (remaining > 0) {
        uint64_t v = UINT64_MAX;
        std::memcpy(&v, begin, remaining);
        result += popcount(~v & 0x8080808080808080ULL);
      }
      return result;
    }

    // Given the fact that the next n bytes are all variable length integers,
    // find the number of integers in the range.
    constexpr std::optional<std::size_t> number_of_varints(uint32_t num_bytes) {
      if (in_avail() >= static_cast<int32_t>(num_bytes)) [[likely]] {
        return count_number_of_varints_in_region(num_bytes);
      } else {
        if constexpr (!contiguous) {
          basic_in archive(*this);
          std::size_t result = 0;
          while (num_bytes > 0 && in_avail() > 0) {
            archive.maybe_advance_region();
            auto n = std::min<ptrdiff_t>(num_bytes, archive.region_size());
            result += count_number_of_varints_in_region(n);
            archive.current.begin += n;
            num_bytes -= static_cast<uint32_t>(n);
          }
          if (num_bytes == 0) [[likely]] {
            return result;
          }
        }

        return {};
      }
    }

    constexpr uint32_t read_tag() {
      maybe_advance_region();
      // NOLINTBEGIN(cppcoreguidelines-init-variables)
      int64_t res;
      // NOLINTEND(cppcoreguidelines-init-variables)
      current.begin = shift_mix_parse_varint<uint32_t, 4>(current.begin, current.end, res);
      return static_cast<uint32_t>(res);
    }
  };
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

  static status skip_field(uint32_t tag, concepts::has_extension auto &item, auto &context,
                           concepts::is_basic_in auto &archive) {

    auto field_archive = archive.unwind_tag(tag);
    if (auto result = do_skip_field(tag, archive); !result.ok()) [[unlikely]] {
      return result;
    }
    using fields_type = std::remove_cvref_t<decltype(item.extensions.fields)>;
    using bytes_type = typename fields_type::value_type::second_type;
    using byte_type = std::remove_const_t<typename bytes_type::value_type>;
    std::size_t field_len = field_archive.in_avail() - archive.in_avail();
    field_archive = field_archive.split(field_len);

    const uint32_t field_num = tag_number(tag);

    if constexpr (concepts::associative_container<fields_type>) {
      auto &value = item.extensions.fields[field_num];
      return field_archive.deserialize_packed(field_archive.in_avail(), value);
    } else {
      static_assert(concepts::span<fields_type>);
      auto &fields = item.extensions.fields;

      if (!fields.empty() && fields.back().first == field_num &&
          field_archive.in_avail() == field_archive.region_size()) {
        // if the newly parsed has the same field number with previously parsed, just extends the content
        auto &entry = fields.back().second;
        if (static_cast<const void *>(field_archive.data()) == entry.data() + entry.size()) {
          entry = std::span<const byte_type>{entry.data(), entry.size() + field_len};
          return {};
        }
      }

      auto itr =
          std::find_if(fields.begin(), fields.end(), [field_num](const auto &e) { return e.first == field_num; });

      if (itr == fields.end() && field_archive.in_avail() == field_archive.region_size()) [[likely]] {
        equality_comparable_span<const byte_type> field_span;
        if (auto result = field_archive.read_bytes(static_cast<uint32_t>(field_len), field_span); !result.ok())
            [[unlikely]] {
          return result;
        }
        as_modifiable(context, fields).push_back({field_num, field_span});
        return {};
      }
      // the extension with the same field number exists, append the content to the previously parsed.
      decltype(auto) v = as_modifiable(context, itr->second);
      return field_archive.deserialize_packed(field_archive.in_avail(), v);
    }
  }
  constexpr static status skip_field(uint32_t tag, concepts::has_meta auto &, auto & /* unused */,
                                     concepts::is_basic_in auto &archive) {
    return do_skip_field(tag, archive);
  }

  constexpr static status do_skip_field(uint32_t tag, concepts::is_basic_in auto &archive) {
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

  constexpr static status do_skip_group(uint32_t field_num, concepts::is_basic_in auto &archive) {
    while (archive.in_avail() > 0) {
      auto tag = archive.read_tag();

      const uint32_t next_field_num = tag_number(tag);
      const wire_type next_type = proto::tag_type(tag);

      if (next_type == wire_type::egroup && field_num == next_field_num) {
        return {};
      } else if (auto result = do_skip_field(tag, archive); !result.ok()) {
        return result;
      }
    }
    return std::errc::bad_message;
  }

  constexpr static status skip_tag(uint32_t tag, concepts::is_basic_in auto &archive) {
    auto t = archive.read_tag();
    if (t != tag) [[unlikely]] {
      return std::errc::bad_message;
    }
    return {};
  }

  template <typename T>
  constexpr static std::optional<std::size_t> count_packed_elements(uint32_t length,
                                                                    concepts::is_basic_in auto &archive) {

    if constexpr (concepts::byte_serializable<T>) {
      return length / sizeof(T);
    } else if constexpr (std::is_enum_v<T> || concepts::varint<T>) {
      return archive.number_of_varints(length);
    } else {
      static_assert(!sizeof(T));
    }
  }

  constexpr static status count_unpacked_elements(uint32_t input_tag, std::size_t &count,
                                                  concepts::is_basic_in auto archive) {
    // NOLINTBEGIN(cppcoreguidelines-avoid-do-while)
    do {
      if (auto result = do_skip_field(input_tag, archive); !result.ok()) {
        return result;
      }

      ++count;

      if (archive.in_avail() == 0) {
        return {};
      }
    } while (archive.read_tag() == input_tag);
    // NOLINTEND(cppcoreguidelines-avoid-do-while)
    return {};
  }

  template <typename Meta, typename Context>
  constexpr static status deserialize_packed_repeated(Meta, auto &&item, Context &context,
                                                      concepts::is_basic_in auto &archive) {
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

    if constexpr (concepts::byte_type<value_type> && concepts::not_resizable<type> &&
                  !std::is_base_of_v<always_allocate_memory, Context>) {
      static_assert(concepts::has_memory_resource<decltype(context)>, "memory resource is required");
      // handling string_view or span of byte
      if constexpr (std::remove_cvref_t<decltype(archive)>::contiguous) {
        if (archive.in_avail() >= byte_count) {
          return archive.read_bytes(byte_count, item);
        }
        return std::errc::bad_message;
      } else {
        decltype(auto) v = as_modifiable(context, item);
        v.resize(byte_count);
        return archive(v);
      }
    } else {
      decltype(auto) v = as_modifiable(context, item);

      if constexpr (requires { v.resize(1); }) {
        // packed repeated vector,
        auto n = count_packed_elements<encode_type>(static_cast<uint32_t>(byte_count), archive);
        if (!n.has_value()) {
          return std::errc::bad_message;
        }
        std::size_t size = *n;

        if constexpr (concepts::byte_serializable<encode_type>) {
          v.resize(0);
          return archive.deserialize_packed(size, v);
        } else if constexpr (std::is_enum_v<encode_type>) {
          return archive.template deserialize_packed_varint<vint64_t>(byte_count, size, v);
        } else {
          static_assert(concepts::varint<encode_type>);
          return archive.template deserialize_packed_varint<encode_type>(byte_count, size, v);
        }
      } else {
        static_assert(concepts::has_memory_resource<decltype(context)>, "memory resource is required");
        return {};
      }
    }
  }

  template <typename MetaType, typename ValueType>
  struct get_value_encode_type {
    using type = ValueType;
  };

  template <concepts::is_map_entry MetaType, typename ValueType>
  struct get_value_encode_type<MetaType, ValueType> {
    using type = typename MetaType::mutable_type;
  };

  // NOLINTBEGIN(readability-function-cognitive-complexity)
  template <typename Meta>
  constexpr static status deserialize_unpacked_repeated(Meta, uint32_t tag, auto &&item, auto &context,
                                                        concepts::is_basic_in auto &archive) {

    using type = std::remove_reference_t<decltype(item)>;
    using value_type = typename type::value_type;
    using value_encode_type = typename get_value_encode_type<typename Meta::type, value_type>::type;

    decltype(auto) v = as_modifiable(context, item);

    std::size_t count = 0;
    if (auto result = count_unpacked_elements(tag, count, archive); !result.ok()) [[unlikely]] {
      return result;
    }
    auto old_size = item.size();
    const std::size_t new_size = item.size() + count;

    auto deserialize_element = [&](value_encode_type &element) {
      if constexpr (concepts::has_meta<value_encode_type>) {
        return pb_serializer::deserialize_sized(element, context, archive);
      } else {
        return pb_serializer::deserialize_field(element, Meta{}, tag, context, archive);
      }
    };

    if constexpr (concepts::flat_map<type>) {
      reserve(v, new_size);
    } else if constexpr (requires { v.resize(new_size); }) {
      v.resize(new_size);
    }

    for (auto i = old_size; i < new_size; ++i) {
      if constexpr (concepts::associative_container<type>) {
        value_encode_type element;

        if (auto result = deserialize_element(element); !result.ok()) {
          return result;
        }

        auto val = static_cast<value_type>(std::move(element));
        if constexpr (requires { v.insert_or_assign(std::move(val.first), std::move(val.second)); }) {
          v.insert_or_assign(std::move(val.first), std::move(val.second));
        } else { // pre-C++23 std::map
          v[std::move(val.first)] = std::move(val.second);
        }
      } else if constexpr (std::same_as<value_encode_type, value_type>) {
        if (auto result = deserialize_element(v[i]); !result.ok()) [[unlikely]] {
          return result;
        }
      } else {
        value_encode_type element;
        if (auto result = deserialize_element(element); !result.ok()) [[unlikely]] {
          return result;
        }
        v[i] = std::move(static_cast<value_type>(std::move(element)));
      }

      if (i < new_size - 1) {
        if (auto result = skip_tag(tag, archive); !result.ok()) [[unlikely]] {
          return result;
        }
      }
    }
    return {};
  }
  // NOLINTEND(readability-function-cognitive-complexity)

  constexpr static status deserialize_field(boolean &item, auto, uint32_t, auto &,
                                            concepts::is_basic_in auto &archive) {
    return archive(item.value);
  }

  constexpr static status deserialize_field(concepts::is_enum auto &item, auto, uint32_t, auto &,
                                            concepts::is_basic_in auto &archive) {
    vint64_t value;
    if (auto result = archive(value); !result.ok()) [[unlikely]] {
      return result;
    }
    item = static_cast<std::remove_reference_t<decltype(item)>>(value.value);
    return {};
  }

  constexpr static status deserialize_field(concepts::optional_message_view auto &item, auto meta, uint32_t tag,
                                            auto &context, concepts::is_basic_in auto &archive) {
    static_assert(concepts::has_memory_resource<decltype(context)>, "memory resource is required");
    using element_type = std::remove_cvref_t<decltype(*item)>;
    void *buffer = context.memory_resource().allocate(sizeof(element_type), alignof(element_type));
    if (buffer == nullptr) [[unlikely]] {
      return std::errc::not_enough_memory;
    }
    // NOLINTBEGIN(cppcoreguidelines-owning-memory)
    auto loaded = new (buffer) element_type;
    // NOLINTEND(cppcoreguidelines-owning-memory)
    if (auto result = deserialize_field(*loaded, meta, tag, context, archive); !result.ok()) [[unlikely]] {
      return result;
    }
    item = loaded;
    return {};
  }

  constexpr static status deserialize_field(concepts::optional auto &item, auto meta, uint32_t tag, auto &context,
                                            concepts::is_basic_in auto &archive) {
    if constexpr (requires { item.emplace(); }) {
      return deserialize_field(item.emplace(), meta, tag, context, archive);
    } else {
      using type = std::remove_reference_t<decltype(item)>;
      item = typename type::value_type{};
      return deserialize_field(*item, meta, tag, context, archive);
    }
  }

  constexpr static status deserialize_field(concepts::unique_ptr auto &item, auto meta, uint32_t tag, auto &context,
                                            concepts::is_basic_in auto &archive) {
    using element_type = std::remove_reference_t<decltype(*item)>;
    auto loaded = std::make_unique<element_type>();
    if (auto result = deserialize_field(*loaded, meta, tag, context, archive); !result.ok()) [[unlikely]] {
      return result;
    }
    item.reset(loaded.release());
    return {};
  }

  template <typename Meta>
  constexpr static status deserialize_field(concepts::oneof_type auto &item, Meta, uint32_t tag, auto &context,
                                            concepts::is_basic_in auto &archive) {
    using type = std::remove_reference_t<decltype(item)>;
    static_assert(std::is_same_v<std::remove_cvref_t<decltype(std::get<0>(type{}))>, std::monostate>);
    return deserialize_oneof<0, typename Meta::alternatives_meta>(tag, item, context, archive);
  }

  template <typename Meta>
  constexpr static status deserialize_field(concepts::arithmetic auto &item, Meta meta, uint32_t tag, auto &context,
                                            concepts::is_basic_in auto &archive) {
    using type = std::remove_reference_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;
    if constexpr (!std::is_same_v<type, serialize_type>) {
      serialize_type value;
      if (auto result = deserialize_field(value, meta, tag, context, archive); !result.ok()) [[unlikely]] {
        return result;
      }
      item = static_cast<type>(value);
      return {};
    } else {
      return archive(item);
    }
  }

  constexpr static status deserialize_field(concepts::has_meta auto &item, auto meta, uint32_t tag, auto &context,
                                            concepts::is_basic_in auto &archive) {
    if constexpr (!meta.is_group) {
      return deserialize_sized(item, context, archive);
    } else {
      return deserialize_group(tag_number(tag), item, context, archive);
    }
  }

  template <typename Meta>
  constexpr static status deserialize_field(std::ranges::range auto &item, Meta meta, uint32_t tag, auto &context,
                                            concepts::is_basic_in auto &archive) {

    const uint32_t field_num = tag_number(tag);
    using type = std::remove_reference_t<decltype(item)>;

    if constexpr (concepts::contiguous_byte_range<type>) {
      if (auto result = deserialize_packed_repeated(meta, item, context, archive); !result.ok()) {
        return result;
      }
      return is_string_and_not_utf8(item) ? std::errc::bad_message : std::errc{};
    } else if constexpr (meta.is_group) {
      // repeated group
      decltype(auto) v = as_modifiable(context, item);
      return deserialize_group(field_num, v.emplace_back(), context, archive);
    } else { // repeated non-group
      if constexpr (!meta.is_unpacked_repeated) {
        if (tag_type(tag) != wire_type::length_delimited) {
          return deserialize_unpacked_repeated(meta, tag, item, context, archive);
        }
        return deserialize_packed_repeated(meta, item, context, archive);
      } else {
        return deserialize_unpacked_repeated(meta, tag, item, context, archive);
      }
    }
  }

  constexpr static status deserialize_group(uint32_t field_num, auto &&item, auto &context,
                                            concepts::is_basic_in auto &archive) {

    while (archive.in_avail() > 0) {
      auto tag = archive.read_tag();

      if (proto::tag_type(tag) == wire_type::egroup && field_num == tag_number(tag)) {
        return {};
      }

      if (auto result = deserialize_field_by_tag(tag, item, context, archive); !result.ok()) [[unlikely]] {
        return result;
      }
    }

    return std::errc::bad_message;
  }

  template <std::size_t Index, concepts::tuple Meta>
  constexpr static status deserialize_oneof(int32_t tag, auto &&item, auto &context,
                                            concepts::is_basic_in auto &archive) {
    if constexpr (Index < std::tuple_size_v<Meta>) {
      using meta = typename std::tuple_element<Index, Meta>::type;
      if (meta::number == tag_number(tag)) {
        if constexpr (requires { item.template emplace<Index + 1>(); }) {
          return deserialize_field(item.template emplace<Index + 1>(), meta{}, tag, context, archive);
        } else {
          item = std::variant_alternative_t<Index + 1, std::decay_t<decltype(item)>>{};
          return deserialize_field(std::get<Index + 1>(item), meta{}, tag, context, archive);
        }
      } else {
        return deserialize_oneof<Index + 1, Meta>(tag, std::forward<decltype(item)>(item), context, archive);
      }
    } else {
      return {};
    }
  }

  template <std::size_t Index>
  constexpr static status deserialize_field_by_index(uint32_t tag, auto &item, auto &context,
                                                     concepts::is_basic_in auto &archive) {
    using type = std::remove_reference_t<decltype(item)>;
    using Meta = typename traits::field_meta_of<type, Index>::type;
    if constexpr (requires { requires Meta::number == UINT32_MAX; }) {
      // this is extension, not a regular field
      return {};
    } else {
      return deserialize_field(Meta::access(item), Meta(), tag, context, archive);
    }
  }

  template <uint32_t MaskedNum, uint32_t I = 0>
  constexpr static status deserialize_field_by_masked_num(uint32_t tag, auto &item, auto &context,
                                                          concepts::is_basic_in auto &archive) {
    using type = std::remove_cvref_t<decltype(item)>;
    constexpr auto table = traits::reverse_indices<type>::template lookup_table_for_masked_number<MaskedNum>();
    if constexpr (table.empty() || I >= table.size()) {
      return skip_field(tag, item, context, archive);
    } else {
      if (tag_number(tag) == table[I].first) {
        return deserialize_field_by_index<table[I].second>(tag, item, context, archive);
      } else [[unlikely]] {
        return deserialize_field_by_masked_num<MaskedNum, I + 1>(tag, item, context, archive);
      }
    }
  }

  template <uint32_t... MaskNum>
  constexpr static status deserialize_field_by_masked_num(uint32_t tag, auto &item, auto &context,
                                                          concepts::is_basic_in auto &archive,
                                                          std::integer_sequence<uint32_t, MaskNum...>) {
    using type = std::remove_cvref_t<decltype(item)>;
    constexpr auto mask = traits::reverse_indices<type>::mask;
    status r;
    (void)((((tag_number(tag) & mask) == MaskNum) &&
            (r = deserialize_field_by_masked_num<MaskNum>(tag, item, context, archive), true)) ||
           ...);
    return r;
  }

  constexpr static status deserialize_field_by_tag(uint32_t tag, auto &item, auto &context,
                                                   concepts::is_basic_in auto &archive) {

    using type = std::remove_cvref_t<decltype(item)>;
    constexpr auto mask = traits::reverse_indices<type>::mask;
    return deserialize_field_by_masked_num(tag, item, context, archive,
                                           std::make_integer_sequence<uint32_t, mask + 1>());
  }

  constexpr static status deserialize(concepts::has_meta auto &item, concepts::is_pb_context auto &context,
                                      concepts::is_basic_in auto &archive) {

    while (archive.in_avail() > 0) {
      auto tag = archive.read_tag();

      if (auto result = deserialize_field_by_tag(tag, item, context, archive); !result.ok()) {
        [[unlikely]] return result;
      }
    }

    return archive.in_avail() == 0 ? std::errc{} : std::errc::bad_message;
  }

  constexpr static status deserialize_sized(auto &&item, auto &context, concepts::is_basic_in auto &archive) {
    vuint32_t len;
    if (auto result = archive(len); !result.ok()) [[unlikely]] {
      return result;
    }

    if (len < archive.in_avail()) [[likely]] {
      auto new_archive = archive.split(len);
      return deserialize(item, context, new_archive);
    } else if (len == archive.in_avail()) {
      return deserialize(item, context, archive);
    }

    return std::errc::bad_message;
  }

  constexpr static std::size_t slope_size = 16;
  constexpr static std::size_t patch_buffer_size = 2 * slope_size;

  template <typename Context, typename Byte>
  struct patch_buffer_type {
    std::array<Byte, patch_buffer_size> buffer = {Byte{0}};
    constexpr explicit patch_buffer_type(Context &) {}
    constexpr auto data() { return buffer.data(); }
  };

  // when memory resource is used, the patch buffer must come from it because
  // the decoded string or bytes may refer to the memory in patch buffer
  template <concepts::has_memory_resource Context, typename Byte>
  struct patch_buffer_type<Context, Byte> {
    Byte *buffer;
    constexpr explicit patch_buffer_type(Context &context)
        : buffer(static_cast<Byte *>(context.memory_resource().allocate(patch_buffer_size, 1))) {
      memset(buffer, 0, patch_buffer_size);
    }
    constexpr auto data() { return buffer; }
  };

  template <typename Byte>
  constexpr static std::ptrdiff_t setup_input_regions(concepts::segmented_byte_range auto &&source,
                                                      input_buffer_region<Byte> *regions, Byte *patch_buffer) {
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    bool is_first_segment = true;
    regions->effective_size = 0;
    ptrdiff_t total_size = 0;
    for (auto &segment : source) {
      const auto segment_size = std::ranges::size(segment);
      total_size += segment_size;
      if (segment_size <= slope_size) {
        if (is_first_segment) {
          regions->begin = patch_buffer;
        }
        patch_buffer = std::copy(std::begin(segment), std::end(segment), patch_buffer);
        regions->effective_size += segment_size;
        regions->slope_begin = patch_buffer;
      } else {
        if (!is_first_segment) {
          patch_buffer = std::copy_n(std::begin(segment), slope_size, patch_buffer);
          regions->end = patch_buffer;
          ++regions;
        }
        regions->begin = std::ranges::data(segment);
        regions->end = regions->begin + segment_size;
        regions->slope_begin = regions->end - slope_size;
        regions->effective_size = segment_size;
        ++regions;
        regions->begin = patch_buffer;
        patch_buffer = std::copy((regions - 1)->slope_begin, (regions - 1)->end, patch_buffer);
        regions->slope_begin = patch_buffer;
        regions->effective_size = 0;
      }
      is_first_segment = false;
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    regions->end = patch_buffer;
    *patch_buffer = Byte{0};
    return total_size;
  }

  template <concepts::contiguous_byte_range Buffer, concepts::is_pb_context Context>
  struct contiguous_input_stream {
    using byte_type = std::remove_const_t<std::ranges::range_value_t<Buffer>>;
    patch_buffer_type<Context, byte_type> patch_buffer;
    std::array<input_buffer_region<byte_type>, 2> regions;

    constexpr contiguous_input_stream(Buffer &buffer, Context &context) noexcept : patch_buffer(context) {
      setup_input_regions<byte_type>(std::span{&buffer, 1}, regions.data(), patch_buffer.data());
    }

    constexpr auto archive() { return basic_in<byte_type, true>(this->regions.data(), 0); }

    constexpr ~contiguous_input_stream() noexcept = default;
    contiguous_input_stream(const contiguous_input_stream &) = delete;
    contiguous_input_stream(contiguous_input_stream &&) = delete;
    contiguous_input_stream &operator=(const contiguous_input_stream &) = delete;
    contiguous_input_stream &operator=(contiguous_input_stream &&) = delete;
  };

  constexpr static status deserialize(concepts::has_meta auto &item, concepts::contiguous_byte_range auto &&buffer) {
    pb_context ctx;
    return deserialize(item, buffer, ctx);
  }

  constexpr static status deserialize(concepts::has_meta auto &item, concepts::contiguous_byte_range auto &&buffer,
                                      concepts::is_pb_context auto &&context) {
    contiguous_input_stream strm{buffer, context};
    auto archive = strm.archive();
    return deserialize(item, context, archive);
  }

  template <typename Byte>
  constexpr static status deserialize(concepts::has_meta auto &item, concepts::is_pb_context auto &&context,
                                      concepts::segmented_byte_range auto &&buffer, input_buffer_region<Byte> *regions,
                                      Byte *patch_buffer) {
    auto total_size = setup_input_regions(buffer, regions, patch_buffer);
    constexpr bool is_contiguous = false;
    auto archive = basic_in<Byte, is_contiguous>(regions, total_size - regions->effective_size);
    return deserialize(item, context, archive);
  }

  constexpr static status deserialize(concepts::has_meta auto &item, concepts::segmented_byte_range auto &&buffer,
                                      concepts::is_pb_context auto &&context) {
    const auto num_segments = std::size(buffer);
    const auto num_regions = num_segments * 2;
    const auto patch_buffer_bytes_count = num_segments * patch_buffer_size;
    const auto regions_bytes_count = num_regions * sizeof(input_buffer_region<char>);
    using buffer_type = std::remove_cvref_t<decltype(buffer)>;
    using segment_type = std::ranges::range_value_t<buffer_type>;
    using byte_type = std::ranges::range_value_t<segment_type>;

    if constexpr (requires { context.memory_resource(); }) {
      auto patch_buffer = static_cast<byte_type *>(context.memory_resource().allocate(patch_buffer_bytes_count, 1));
      if (num_segments > 16) {
        std::vector<input_buffer_region<byte_type>> regions(num_regions);
        return deserialize(item, context, buffer, regions.data(), patch_buffer);
      } else {
        auto *regions = static_cast<input_buffer_region<byte_type> *>(alloca(regions_bytes_count));
        return deserialize(item, context, buffer, regions, patch_buffer);
      }
    } else {
      if (num_segments > 8) {
        std::vector<byte_type> patch_buffer(patch_buffer_bytes_count);
        std::vector<input_buffer_region<byte_type>> regions(num_regions);
        return deserialize(item, context, buffer, regions.data(), patch_buffer.data());
      } else {
        auto patch_buffer = static_cast<byte_type *>(alloca(patch_buffer_bytes_count));
        auto *regions = static_cast<input_buffer_region<byte_type> *>(alloca(regions_bytes_count));
        return deserialize(item, context, buffer, regions, patch_buffer);
      }
    }
  }
};

template <typename FieldType, typename MetaType>
struct serialize_wrapper_type {
  // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
  FieldType value = {};
  // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
  using pb_meta = std::tuple<MetaType>;
};

template <typename ExtensionMeta>
inline auto extension_meta_base<ExtensionMeta>::read(const concepts::pb_extension auto &extensions,
                                                     concepts::is_pb_context auto &&...ctx) {
  check(extensions);
  decltype(extensions.fields.begin()) itr;

  if constexpr (requires { extensions.fields.find(ExtensionMeta::number); }) {
    itr = extensions.fields.find(ExtensionMeta::number);
  } else {
    itr = std::find_if(extensions.fields.begin(), extensions.fields.end(),
                       [](const auto &item) { return item.first == ExtensionMeta::number; });
  }

  using value_type = typename ExtensionMeta::get_result_type;
  using return_type = expected<value_type, status>;

  serialize_wrapper_type<value_type, ExtensionMeta> wrapper;
  if (itr != extensions.fields.end()) {
    if (auto result = pb_serializer::deserialize(wrapper, itr->second, ctx...); !result.ok()) [[unlikely]] {
      return return_type{unexpected(result)};
    }
    return return_type{wrapper.value};
  }

  if constexpr (ExtensionMeta::has_default_value) {
    return return_type(value_type(ExtensionMeta::default_value));
  } else if constexpr (!concepts::has_meta<value_type>) {
    return return_type{value_type{}};
  } else {
    return return_type{unexpected(std::errc::no_message)};
  }
}

template <typename ExtensionMeta>
inline status extension_meta_base<ExtensionMeta>::write(concepts::pb_extension auto &extensions, auto &&value) {
  check(extensions);

  serialize_wrapper_type<decltype(value), ExtensionMeta> wrapper{std::forward<decltype(value)>(value)};
  typename decltype(extensions.fields)::mapped_type data;

  if (auto result = pb_serializer::serialize(wrapper, data); !result.ok()) [[unlikely]] {
    return result;
  }
  if (data.size()) {
    extensions.fields[ExtensionMeta::number] = std::move(data);
  }
  return {};
}

template <typename ExtensionMeta>
inline status extension_meta_base<ExtensionMeta>::write(concepts::pb_extension auto &extensions, auto &&value,
                                                        concepts::is_pb_context auto &&ctx) {
  check(extensions);

  std::span<std::byte> buf;
  auto data = as_modifiable(ctx, buf);

  serialize_wrapper_type<decltype(value), ExtensionMeta> wrapper{std::forward<decltype(value)>(value)};

  if (auto result = pb_serializer::serialize(wrapper, data); !result.ok()) [[unlikely]] {
    return result;
  }

  if (data.size()) {
    using fields_mapped_type = std::remove_cvref_t<decltype(extensions.fields)>::value_type::second_type;
    auto fields = as_modifiable(ctx, extensions.fields);
    fields.emplace_back(ExtensionMeta::number, fields_mapped_type{data.data(), data.size()});
  }
  return {};
}

template <typename F>
  requires std::regular_invocable<F>
consteval auto write_proto(F make_object) {
  constexpr auto obj = make_object();
  constexpr auto sz = pb_serializer::message_size(obj);
  if constexpr (sz == 0) {
    return std::span<std::byte>{};
  } else {
    std::array<std::byte, sz> buffer = {};
    if (auto result = pb_serializer::serialize(obj, buffer); !result.ok()) {
      throw std::system_error(std::make_error_code(result.ec));
    }
    return buffer;
  }
}

template <concepts::contiguous_output_byte_range Buffer = std::vector<std::byte>>
expected<Buffer, std::errc> write_proto(concepts::has_meta auto const &msg) {
  Buffer buffer;
  auto r = pb_serializer::serialize(msg, buffer);
  if (auto result = pb_serializer::serialize(msg, buffer); !result.ok()) {
    return unexpected(r.ec);
  } else {
    return buffer;
  }
}

template <concepts::has_meta T, concepts::contiguous_output_byte_range Buffer>
status write_proto(T &&msg, Buffer &buffer) {
  return pb_serializer::serialize(std::forward<T>(msg), buffer);
}

/// @brief serialize a message to the end of the supplied buffer
template <concepts::has_meta T, concepts::resizable_contiguous_byte_container Buffer>
status append_proto(T &&msg, Buffer &buffer) {
  constexpr bool overwrite_buffer = false;
  return pb_serializer::serialize<overwrite_buffer>(std::forward<T>(msg), buffer);
}

template <concepts::has_meta T>
constexpr static expected<T, std::errc> read_proto(concepts::input_byte_range auto const &buffer,
                                                   concepts::is_pb_context auto &&...ctx) {
  static_assert(sizeof...(ctx) <= 1);
  T msg;
  if (auto result = pb_serializer::deserialize(msg, buffer, ctx...); !result.ok()) {
    return unexpected(result.ec);
  }
  return msg;
}

template <concepts::has_meta T, concepts::input_byte_range Buffer>
status read_proto(T &msg, const Buffer &buffer, concepts::is_pb_context auto &&...ctx) {
  static_assert(sizeof...(ctx) <= 1);
  msg = {};
  return pb_serializer::deserialize(msg, buffer, ctx...);
}

/// @brief  deserialize from the buffer and merge the content with the existing msg
template <concepts::has_meta T, concepts::input_byte_range Buffer>
status merge_proto(T &msg, const Buffer &buffer, concepts::is_pb_context auto &&...ctx) {
  static_assert(sizeof...(ctx) <= 1);
  return pb_serializer::deserialize(msg, buffer, ctx...);
}

namespace concepts {
template <typename T>
concept is_any = requires(T &obj) {
  { obj.type_url } -> concepts::string;
  { obj.value } -> concepts::contiguous_byte_range;
};
} // namespace concepts

status pack_any(concepts::is_any auto &any, concepts::has_meta auto const &msg) {
  any.type_url = message_type_url(msg);
  return write_proto(msg, any.value);
}

status pack_any(concepts::is_any auto &any, concepts::has_meta auto const &msg, concepts::is_pb_context auto &&ctx) {
  any.type_url = message_type_url(msg);
  decltype(auto) v = as_modifiable(ctx, any.value);
  return write_proto(msg, v);
}

status unpack_any(concepts::is_any auto const &any, concepts::has_meta auto &msg,
                  concepts::is_pb_context auto &&...ctx) {
  static_assert(sizeof...(ctx) <= 1);
  if (std::string_view{any.type_url}.ends_with(message_name(msg))) {
    return read_proto(msg, any.value, ctx...);
  }
  return std::errc::invalid_argument;
}

template <concepts::has_meta T>
expected<T, std::errc> unpack_any(concepts::is_any auto const &any, concepts::is_pb_context auto &&...ctx) {
  T msg;
  if (auto result = unpack_any(any, msg, ctx...); !result.ok()) {
    return unexpected(result.ec);
  } else {
    return msg;
  }
}
} // namespace hpp::proto

#undef HPP_PROTO_INLINE

#endif
