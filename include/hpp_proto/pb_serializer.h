// MIT License
//
// Copyright (c) 2023 Huang-Ming Huang
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
#include <cstring>
#include <map>
#include <memory>
#include <numeric>
#include <system_error>

#include <hpp_proto/expected.h>
#include <hpp_proto/memory_resource_utils.h>

namespace hpp {
namespace proto {
/////////////////////////////////////////////////////////////////
// varint code is based on https://github.com/eyalz800/zpp_bits
/////////////////////////////////////////////////////////////////
enum class varint_encoding {
  normal,
  zig_zag,
};

template <typename Type, varint_encoding Encoding = varint_encoding::normal>
struct varint {
  varint() = default;
  using value_type = Type;
  static constexpr auto encoding = Encoding;
  constexpr varint(Type value) : value(value) {}
  constexpr operator Type &() & { return value; }
  constexpr operator Type() const { return value; }
  constexpr decltype(auto) operator*() & { return (value); }
  constexpr auto operator*() const & { return value; }
  Type value{};
};

template <typename Type>
constexpr auto varint_max_size = sizeof(Type) * CHAR_BIT / (CHAR_BIT - 1) + 1;

using vint64_t = varint<int64_t>;
using vint32_t = varint<int32_t>;

using vuint64_t = varint<uint64_t>;
using vuint32_t = varint<uint32_t>;

using vsint64_t = varint<int64_t, varint_encoding::zig_zag>;
using vsint32_t = varint<int32_t, varint_encoding::zig_zag>;

template <varint_encoding Encoding = varint_encoding::normal>
inline constexpr auto varint_size(auto value) {
  if constexpr (Encoding == varint_encoding::zig_zag) {
    return varint_size(std::make_unsigned_t<decltype(value)>((value << 1) ^ (value >> (sizeof(value) * CHAR_BIT - 1))));
  } else {
    return ((sizeof(value) * CHAR_BIT) - std::countl_zero(std::make_unsigned_t<decltype(value)>(value | 0x1)) +
            (CHAR_BIT - 2)) /
           (CHAR_BIT - 1);
  }
}
/////////////////////////////////////////////////////

namespace concepts {

template <typename Type>
concept varint = requires { requires std::same_as<Type, varint<typename Type::value_type, Type::encoding>>; };

template <typename Type>
concept associative_container =
    std::ranges::range<Type> && requires(Type container) { typename std::remove_cvref_t<Type>::key_type; };

template <typename Type>
concept tuple = !std::ranges::range<Type> && requires(Type tuple) { sizeof(std::tuple_size<std::remove_cvref_t<Type>>); };

template <typename Type>
concept variant = requires(Type variant) {
  variant.index();
  std::get_if<0>(&variant);
  std::variant_size_v<std::remove_cvref_t<Type>>;
};

template <typename Type>
concept string =
    std::same_as<std::remove_cvref_t<Type>, std::string> || std::same_as<std::remove_cvref_t<Type>, std::string_view>;

template <typename Type>
concept has_local_meta = concepts::tuple<typename Type::pb_meta>;

template <typename Type>
concept has_explicit_meta = concepts::tuple<decltype(pb_meta(std::declval<Type>()))>;

template <typename Type>
concept has_meta = has_local_meta<std::remove_cvref_t<Type>> || has_explicit_meta<Type>;

template <typename T>
concept numeric =
    std::is_arithmetic_v<T> || concepts::varint<T> || std::is_enum_v<T> || std::same_as<hpp::proto::boolean, T>;

template <typename T>
concept numeric_or_byte = numeric<T> || std::same_as<std::byte, T>;

template <typename Type>
concept optional = requires(Type optional) {
  optional.value();
  optional.has_value();
  // optional.operator bool(); // this operator is deliberately removed to fit
  // our specialization for optional<bool> which removed this operation
  optional.operator*();
};

template <typename Type>
concept oneof_type = concepts::variant<Type>;

template <typename Type>
concept scalar = numeric_or_byte<Type> || contiguous_byte_range<Type> || std::same_as<Type, boolean>;

template <typename Type>
concept pb_extension = requires(Type value) { typename Type::pb_extension; };

template <typename Type>
concept is_map_entry = requires {
  typename Type::key_type;
  typename Type::mapped_type;
};

template <typename T>
concept span = requires {
  typename T::value_type;
  requires std::same_as<T, std::span<typename T::value_type>>;
};

template <typename T>
concept is_oneof_field_meta = requires { typename T::alternatives_meta; };

template <typename T>
concept byte_serializable =
    std::is_arithmetic_v<T> || std::same_as<hpp::proto::boolean, T> || std::same_as<std::byte, T>;

template <typename T>
concept is_size_cache = std::same_as<T, uint32_t *> || requires(T v) {
  { v++ } -> std::same_as<T>;
  *v = 0U;
};

template <typename T>
concept resizable = requires {
  std::declval<T &>().resize(1);
  std::declval<T>()[0];
};

template <typename T>
concept resizable_or_reservable =
    resizable<T> || requires { std::declval<T &>().reserve(1); } || requires { reserve(std::declval<T &>(), 1); };

template <typename Type>
concept has_extension = has_meta<Type> && requires(Type value) {
  value.extensions;
  typename decltype(Type::extensions)::pb_extension;
};

template <typename Type>
concept unique_ptr = requires {
  typename Type::element_type;
  typename Type::deleter_type;
  requires std::same_as<Type, std::unique_ptr<typename Type::element_type, typename Type::deleter_type>>;
};

template <typename Type>
concept is_basic_in = requires { typename Type::is_basic_in; };

template <typename Type>
concept is_basic_out = requires { typename Type::is_basic_out; };

} // namespace concepts

enum class encoding_rule {
  defaulted = 0,
  explicit_presence = 1,
  unpacked_repeated = 2,
  group = 3,
  packed_repeated = 4
};

template <auto Accessor>
struct accesor_type {
  inline constexpr auto &operator()(auto &&item) const {
    if constexpr (std::is_member_pointer_v<decltype(Accessor)>)
      return item.*Accessor;
    else
      return Accessor(std::forward<decltype(item)>(item));
  }
};

template <uint32_t Number, auto Accessor, encoding_rule Encoding = encoding_rule::defaulted, typename Type = void,
          auto DefaultValue = std::monostate{}>
struct field_meta {
  constexpr static uint32_t number = Number;
  constexpr static encoding_rule encoding = Encoding;
  constexpr static auto access = accesor_type<Accessor>{};
  using type = Type;

  template <typename T>
  inline static constexpr bool omit_value(const T &v) {
    if constexpr (Encoding == encoding_rule::defaulted) {
      return is_default_value<T, DefaultValue>(v);
    } else if constexpr (requires { v.has_value(); }) {
      return !v.has_value();
    } else if constexpr (std::is_pointer_v<std::remove_cvref_t<T>>) {
      return v == nullptr;
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

template <auto Accessor, typename... AlternativeMeta>
struct oneof_field_meta {
  constexpr static auto access = accesor_type<Accessor>{};
  using alternatives_meta = std::tuple<AlternativeMeta...>;
  using type = void;
  template <typename T>
  inline static constexpr bool omit_value(const T &v) {
    return v.index() == 0;
  }
};

struct errc {
  std::errc ec = {};
  constexpr errc() = default;
  constexpr errc(const errc &) = default;

  constexpr errc(std::errc e) : ec(e) {}
  constexpr operator std::errc() { return ec; }

  constexpr errc &operator=(const errc &) = default;

  constexpr bool success() { return ec == std::errc{}; }
  constexpr bool failure() { return !success(); }
};

template <typename T>
struct extension_meta_base {

  struct accesor_type {
    inline constexpr auto &operator()(auto &&item) const {
      auto &[e] = item;
      return e;
    }
  };

  constexpr static auto access = accesor_type{};

  static constexpr void check(const concepts::pb_extension auto &extensions) {
    static_assert(std::same_as<typename std::remove_cvref_t<decltype(extensions)>::pb_extension, typename T::extendee>);
  }

  static auto read(const concepts::pb_extension auto &extensions, concepts::is_pb_context auto &&...ctx);
  static errc write(concepts::pb_extension auto &extensions, auto &&value);
  static errc write(concepts::pb_extension auto &extensions, auto &&value, concepts::is_pb_context auto &&ctx);
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

template <typename Extendee, uint32_t Number, encoding_rule Encoding, typename Type, typename ValueType,
          auto DefaultValue = std::monostate{}>
struct extension_meta : extension_meta_base<extension_meta<Extendee, Number, Encoding, Type, ValueType, DefaultValue>> {

  constexpr static uint32_t number = Number;
  constexpr static encoding_rule encoding = Encoding;
  using type = Type;
  constexpr static auto default_value = unwrap(DefaultValue);
  constexpr static bool has_default_value = !std::same_as<std::remove_const_t<decltype(DefaultValue)>, std::monostate>;
  static constexpr bool is_repeated = false;
  using extendee = Extendee;

  using get_result_type = ValueType;
  using set_value_type = ValueType;

  template <typename T>
  static constexpr bool omit_value(const T &v) {
    if constexpr (Encoding == encoding_rule::defaulted) {
      return is_default_value<T, DefaultValue>(v);
    } else if constexpr (requires { v.has_value(); }) {
      return !v.has_value();
    } else if constexpr (std::is_pointer_v<std::remove_cvref_t<T>>) {
      return v == nullptr;
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

template <typename Extendee, uint32_t Number, encoding_rule Encoding, typename Type, typename ValueType>
struct repeated_extension_meta
    : extension_meta_base<repeated_extension_meta<Extendee, Number, Encoding, Type, ValueType>> {
  constexpr static uint32_t number = Number;
  constexpr static encoding_rule encoding = Encoding;
  using type = Type;
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

enum class wire_type : unsigned int {
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
  return varint{(number << 3) | std::underlying_type_t<wire_type>(type)};
}

template <typename Type, typename Meta>
constexpr auto make_tag(Meta meta) {
  // check if Meta::number is static or not
  if constexpr (requires { *&Meta::number; }) {
    return make_tag(Meta::number, tag_type<Type>());
  } else {
    return make_tag(meta.number, tag_type<Type>());
  }
}

constexpr auto tag_type(uint32_t tag) { return wire_type(tag & 0x7); }

constexpr auto tag_number(uint32_t tag) { return (tag >> 3); }

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

template <typename T>
  requires std::is_enum_v<T>
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
    typename serialize_type<KeyType>::type key;
    typename serialize_type<MappedType>::type value;
    constexpr static bool allow_inline_visit_members_lambda = true;
    using pb_meta = std::tuple<field_meta<1, &mutable_type::key, encoding_rule::explicit_presence>,
                               field_meta<2, &mutable_type::value, encoding_rule::explicit_presence>>;

    template <typename Target, typename Source>
    constexpr static auto move_or_copy(Source &&src) {
      if constexpr (requires(Target target) { target = std::move(src); }) {
        return std::move(src);
      } else if constexpr (std::is_enum_v<Target> && std::is_same_v<std::remove_cvref_t<Source>, vint64_t>) {
        return static_cast<Target>(src.value);
      } else {
        return static_cast<Target>(src);
      }
    }
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4244)
#endif
    template <concepts::associative_container Container>
    constexpr void insert_to(Container &container) && {
      container.insert_or_assign(move_or_copy<typename Container::key_type>(key),
                                 move_or_copy<typename Container::mapped_type>(value));
    }

    template <typename K, typename V>
    constexpr void to(std::pair<K, V> &target) && {
      target.first = move_or_copy<K>(key);
      target.second = move_or_copy<V>(value);
    }
#ifdef _MSC_VER
#pragma warning(pop)
#endif
  };

  struct read_only_type {
    typename serialize_type<KeyType>::read_type key;
    typename serialize_type<MappedType>::read_type value;
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

    using pb_meta = std::tuple<field_meta<1, key_accessor{}, encoding_rule::explicit_presence>,
                               field_meta<2, value_accessor{}, encoding_rule::explicit_presence>>;
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
  std::array<T, M + N> result;
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
  constexpr static auto mask = (1 << std::bit_width(numbers.size())) - 1;

  template <std::size_t I, typename T>
    requires requires { T::number; }
  constexpr static auto index(T) {
    return std::array{I};
  }

  template <std::size_t I, concepts::is_oneof_field_meta Meta>
  constexpr static auto index(Meta) {
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

  constexpr static auto indices = get_indices(typename traits::meta_of<Type>::type{});

  consteval static auto build_lookup_table_indices() {
    std::array<uint32_t, mask + 1> masked_number_occurances;
    masked_number_occurances.fill(0U);
    for (auto num : numbers) {
      ++masked_number_occurances[num & mask];
    }
    std::array<uint32_t, mask + 2> table_indices = {0};
    std::partial_sum(masked_number_occurances.begin(), masked_number_occurances.end(), table_indices.begin() + 1);
    return table_indices;
  }

  consteval static auto build_lookup_table() {
    constexpr auto lookup_table_indices = build_lookup_table_indices();
    if constexpr (numbers.empty()) {
      return std::span<std::pair<uint32_t, uint32_t>>{};
    } else {
      std::array<uint32_t, mask + 1> counts;
      std::copy(lookup_table_indices.begin(), lookup_table_indices.end() - 1, counts.begin());

      std::array<std::pair<uint32_t, uint32_t>, numbers.size()> result;
      for (uint32_t i = 0; i < numbers.size(); ++i) {
        auto num = numbers[i];
        auto masked_num = num & mask;
        result[counts[masked_num]++] = {num, static_cast<uint32_t>(indices[i])};
      }
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

struct pb_serializer {
  template <typename Byte>
  struct basic_out {
    using byte_type = Byte;
    using is_basic_out = void;
    constexpr static bool endian_swapped = std::endian::little != std::endian::native;
    std::span<byte_type> m_data;

    constexpr void serialize(auto &&item) {
      using type = std::remove_cvref_t<decltype(item)>;
      if constexpr (concepts::byte_serializable<type>) {
        if (std::is_constant_evaluated()) {
          auto value = std::bit_cast<std::array<std::remove_const_t<byte_type>, sizeof(item)>>(item);
          if constexpr (endian_swapped) {
            std::copy(value.rbegin(), value.rend(), m_data.begin());
          } else {
            std::copy(value.begin(), value.end(), m_data.begin());
          }
        } else {
          if constexpr (endian_swapped && sizeof(type) != 1) {
            std::reverse_copy(reinterpret_cast<const byte_type *>(&item),
                              reinterpret_cast<const byte_type *>(&item) + sizeof(item), m_data.begin());
          } else {
            std::memcpy(m_data.data(), &item, sizeof(item));
          }
        }
        m_data = m_data.subspan(sizeof(item));
      } else if constexpr (std::is_enum_v<type>) {
        serialize(varint{static_cast<int64_t>(item)});
      } else if constexpr (concepts::varint<type>) {
        auto orig_value = item.value;
        auto value = std::make_unsigned_t<typename type::value_type>(orig_value);
        if constexpr (varint_encoding::zig_zag == type::encoding) {
          value = (value << 1) ^ (orig_value >> (sizeof(value) * CHAR_BIT - 1));
        }

        std::size_t position = 0;
        while (value >= 0x80) {
          m_data[position++] = byte_type((value & 0x7f) | 0x80);
          value >>= (CHAR_BIT - 1);
        }
        m_data[position++] = byte_type(value);
        m_data = m_data.subspan(position);
      } else if constexpr (std::ranges::contiguous_range<type> &&
                           concepts::byte_serializable<typename type::value_type>) {
        if constexpr (concepts::byte_serializable<typename type::value_type>) {
          if (!std::is_constant_evaluated() && (!endian_swapped || sizeof(typename type::value_type) == 1)) {
            auto bytes_to_copy = item.size() * sizeof(typename type::value_type);
            std::memcpy(m_data.data(), item.data(), bytes_to_copy);
            m_data = m_data.subspan(bytes_to_copy);
          } else {
            for (auto x : item) {
              this->serialize(x);
            }
          }
        }
      } else {
        static_assert(!sizeof(type));
      }
    }

    constexpr void operator()(auto &&...item) { (serialize(item), ...); }
  };

  template <concepts::contiguous_byte_range Range>
  basic_out(Range &&) -> basic_out<std::ranges::range_value_t<Range>>;

  constexpr static std::size_t len_size(std::size_t len) { return varint_size(len) + len; }

  template <typename Range, typename UnaryOperation>
  constexpr static std::size_t transform_accumulate(Range &&range, UnaryOperation &&unary_op) {
    return std::accumulate(range.begin(), range.end(), std::size_t{0},
                           [&unary_op](std::size_t acc, const auto &elem) constexpr { return acc + unary_op(elem); });
  }

  constexpr static std::size_t cache_count(concepts::has_meta auto &&item) {
    using type = std::remove_cvref_t<decltype(item)>;
    using meta_type = typename traits::meta_of<type>::type;
    if constexpr (std::tuple_size_v<meta_type> == 0) {
      return 0;
    } else {
      return std::apply([&item](auto &&...meta) constexpr { return (cache_count(meta, meta.access(item)) + ...); },
                        meta_type{});
    }
  }

  template <typename Meta>
  constexpr static std::size_t cache_count(Meta meta, auto &&item) {
    using type = std::remove_cvref_t<decltype(item)>;

    if (meta.omit_value(item))
      return 0;

    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    if constexpr (concepts::oneof_type<type>) {
      return oneof_cache_count<0, typename Meta::alternatives_meta>(item);
    } else if constexpr (requires { *item; }) {
      return cache_count(meta, *item);
    } else if constexpr (concepts::has_meta<type>) {
      return cache_count(item) + (meta.encoding != encoding_rule::group);
    } else if constexpr (std::ranges::input_range<type>) {
      if (item.empty())
        return 0;
      using value_type = typename std::ranges::range_value_t<type>;
      if constexpr (concepts::has_meta<value_type> || Meta::encoding == encoding_rule::unpacked_repeated ||
                    Meta::encoding == encoding_rule::group) {
        return transform_accumulate(item, [](const auto &elem) constexpr { return cache_count(Meta{}, elem); });
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
    } else if constexpr (concepts::is_map_entry<serialize_type>) {
      using mapped_type = typename serialize_type::mapped_type;
      if constexpr (concepts::has_meta<mapped_type>) {
        auto r = cache_count(item.second) + 2;
        return r;
      } else {
        return 1;
      }
    } else {
      return 0;
    }
  }

  template <std::size_t I, typename Meta>
  constexpr static std::size_t oneof_cache_count(auto &&item) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return cache_count(typename std::tuple_element<I, Meta>::type{},
                           std::get<I + 1>(std::forward<decltype(item)>(item)));
      }
      return oneof_cache_count<I + 1, Meta>(std::forward<decltype(item)>(item));
    } else {
      return 0;
    }
  }

  constexpr static std::size_t message_size(concepts::has_meta auto &&item) {
    struct null_size_cache {
      struct null_assignable {
        constexpr void operator=(uint32_t) const {}
      };
      uint32_t storage = 0;
      constexpr null_assignable operator*() { return null_assignable{}; }
      constexpr null_size_cache operator++(int) { return *this; }
    } cache;
    return message_size(item, cache);
  }

  constexpr static std::size_t message_size(concepts::has_meta auto &&item, std::span<uint32_t> cache) {
    uint32_t *c = cache.data();
    return message_size(item, c);
  }

  template <concepts::is_size_cache T>
  constexpr static std::size_t message_size(concepts::has_meta auto &&item, T &cache) {
    using type = std::remove_cvref_t<decltype(item)>;
    return std::apply(
        [&item, &cache](auto &&...meta) constexpr {
          std::size_t sum = 0;
          [[maybe_unused]] auto sum_field_size = [&sum](auto &&...args) constexpr {
            sum += field_size(std::forward<decltype(args)>(args)...);
          };
          // we cannot directly use fold expression with '+' operator because it has undefined evaluation order.
          (sum_field_size(meta, meta.access(item), cache), ...);
          return sum;
        },
        typename traits::meta_of<type>::type{});
  }

  template <typename Meta>
  constexpr static std::size_t field_size(Meta meta, auto &&item, concepts::is_size_cache auto &cache) {
    using type = std::remove_cvref_t<decltype(item)>;

    if (meta.omit_value(item))
      return 0;

    if constexpr (concepts::oneof_type<type>) {
      return oneof_size<0, typename Meta::alternatives_meta>(item, cache);
    } else if constexpr (concepts::pb_extension<type>) {
      return transform_accumulate(item.fields, [](const auto &e) constexpr { return e.second.size(); });
    } else {
      using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

      constexpr std::size_t tag_size = varint_size(meta.number << 3);
      if constexpr (std::is_enum_v<type> && !std::same_as<type, std::byte>) {
        return tag_size + varint_size(static_cast<int64_t>(std::underlying_type_t<type>(item)));
      } else if constexpr (concepts::byte_serializable<type>) {
        if constexpr (concepts::byte_serializable<serialize_type>) {
          return tag_size + sizeof(serialize_type);
        } else {
          static_assert(concepts::varint<serialize_type>);
          return tag_size + varint_size<serialize_type::encoding, typename serialize_type::value_type>(item);
        }
      } else if constexpr (concepts::varint<type>) {
        return tag_size + varint_size<type::encoding, typename type::value_type>(item.value);
      } else if constexpr (concepts::contiguous_byte_range<type>) {
        return tag_size + len_size(item.size());
      } else if constexpr (requires { *item; }) {
        return field_size(meta, *item, cache);
      } else if constexpr (concepts::has_meta<type>) {
        if constexpr (meta.encoding != encoding_rule::group) {
          decltype(auto) msg_size = *cache++;
          auto s = static_cast<uint32_t>(message_size(item, cache));
          msg_size = s;
          return tag_size + len_size(s);
        } else {
          return 2 * tag_size + message_size(item, cache);
        }
      } else if constexpr (std::ranges::input_range<type>) {
        if (item.empty())
          return 0;
        using value_type = typename std::ranges::range_value_t<type>;
        if constexpr (concepts::has_meta<value_type> || Meta::encoding == encoding_rule::unpacked_repeated ||
                      Meta::encoding == encoding_rule::group) {
          return transform_accumulate(item,
                                      [&cache](const auto &elem) constexpr { return field_size(Meta{}, elem, cache); });
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
                return varint_size<element_type::encoding, typename element_type::value_type>(elem);
              }
            });
            decltype(auto) msg_size = *cache++;
            msg_size = static_cast<uint32_t>(s);
            return tag_size + len_size(s);
          }
        }
      } else if constexpr (concepts::is_map_entry<serialize_type>) {
        using value_type = typename serialize_type::read_only_type;
        auto &[key, value] = item;
        decltype(auto) msg_size = *cache++;
        auto s = message_size(value_type{key, value}, cache);
        msg_size = static_cast<uint32_t>(s);
        return tag_size + len_size(s);
      } else {
        static_assert(!sizeof(type));
        return 0;
      }
    }
  }

  template <std::size_t I, typename Meta>
  constexpr static std::size_t oneof_size(auto &&item, concepts::is_size_cache auto &cache) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return field_size(typename std::tuple_element<I, Meta>::type{},
                          std::get<I + 1>(std::forward<decltype(item)>(item)), cache);
      }
      return oneof_size<I + 1, Meta>(std::forward<decltype(item)>(item), cache);
    } else {
      return 0;
    }
  }

  template <bool overwrite_buffer = true, std::size_t MAX_CACHE_COUNT = 128, concepts::contiguous_byte_range Buffer>
  constexpr static errc serialize(concepts::has_meta auto &&item, Buffer &buffer) {
    std::size_t n = cache_count(item);

    auto do_serialize = [&item, &buffer](std::span<uint32_t> cache) constexpr -> errc {
      std::size_t msg_sz = message_size(item, cache);
      std::size_t old_size = overwrite_buffer ? 0 : buffer.size();
      std::size_t new_size = old_size + msg_sz;
      if constexpr (requires { buffer.resize(1); }) {
        buffer.resize(new_size);
      } else if (new_size > buffer.size()) {
        return std::errc::not_enough_memory;
      }
      basic_out<typename std::remove_cvref_t<decltype(buffer)>::value_type> archive{buffer};
      auto cache_data = cache.data();
      serialize(item, cache_data, archive);
      if constexpr (requires { buffer.subspan(0, 1); }) {
        buffer = buffer.subspan(old_size, msg_sz);
      }
      return {};
    };

    if (std::is_constant_evaluated() || n > MAX_CACHE_COUNT) {
      constexpr_vector<uint32_t> cache(n);
      return do_serialize(cache);
    } else {
#if defined(_MSC_VER)
      uint32_t *cache = static_cast<uint32_t *>(_alloca(n * sizeof(uint32_t)));
#elif defined(__GNUC__)
      uint32_t *cache =
          static_cast<uint32_t *>(__builtin_alloca_with_align(n * sizeof(uint32_t), CHAR_BIT * sizeof(uint32_t)));
#else
      uint32_t cache[MAX_CACHE_COUNT];
#endif
      return do_serialize({cache, n});
    }
  }

  constexpr static void serialize(concepts::has_meta auto &&item, uint32_t *&cache, auto &archive) {
    using type = std::remove_cvref_t<decltype(item)>;
    using metas = typename traits::meta_of<type>::type;
    return std::apply([&](auto... meta) { (serialize_field(meta, meta.access(item), cache, archive), ...); }, metas{});
  }

  template <typename Meta>
  constexpr static void serialize_field(Meta meta, auto &&item, uint32_t *&cache, auto &archive) {
    using type = std::remove_cvref_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    if (meta.omit_value(item)) {
      return;
    }

    if constexpr (concepts::oneof_type<type>) {
      return serialize_oneof<0, typename Meta::alternatives_meta>(std::forward<decltype(item)>(item), cache, archive);
    } else if constexpr (std::is_same_v<type, boolean>) {
      constexpr auto tag = make_tag<bool>(meta);
      archive(tag, item.value);
    } else if constexpr (concepts::pb_extension<type>) {
      for (const auto &f : item.fields) {
        archive(f.second);
      }
    } else if constexpr (std::is_enum_v<type> && !std::same_as<type, std::byte>) {
      archive(make_tag<type>(meta), item);
    } else if constexpr (concepts::numeric<type>) {
      archive(make_tag<serialize_type>(meta), serialize_type{item});
    } else if constexpr (concepts::contiguous_byte_range<type>) {
      archive(make_tag<type>(meta), varint{item.size()}, item);
    } else if constexpr (requires { *item; }) {
      return serialize_field(meta, *item, cache, archive);
    } else if constexpr (concepts::has_meta<type>) {
      if constexpr (meta.encoding != encoding_rule::group) {
        archive(make_tag<type>(meta), varint{*cache++});
        serialize(std::forward<decltype(item)>(item), cache, archive);
      } else {
        archive(varint{(meta.number << 3) | std::underlying_type_t<wire_type>(wire_type::sgroup)});
        serialize(std::forward<decltype(item)>(item), cache, archive);
        archive(varint{(meta.number << 3) | std::underlying_type_t<wire_type>(wire_type::egroup)});
      }
    } else if constexpr (std::ranges::range<type>) {
      if (item.empty()) {
        return;
      }
      using value_type = typename std::ranges::range_value_t<type>;
      using element_type =
          std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::contiguous_byte_range<type>,
                             value_type, typename Meta::type>;

      if constexpr (concepts::has_meta<value_type> || Meta::encoding == encoding_rule::group ||
                    Meta::encoding == encoding_rule::unpacked_repeated) {
        for (const auto &element : item) {
          if constexpr (std::same_as<element_type, std::remove_cvref_t<decltype(element)>> ||
                        concepts::is_map_entry<typename Meta::type>) {
            serialize_field(meta, element, cache, archive);
          } else {
            serialize_field(meta, static_cast<element_type>(element), cache, archive);
          }
        }
      } else if constexpr (requires {
                             requires std::is_arithmetic_v<element_type> ||
                                          std::same_as<typename type::value_type, std::byte>;
                           }) {
        // packed fundamental types or bytes
        archive(make_tag<type>(meta), varint{item.size() * sizeof(typename type::value_type)},
                std::forward<decltype(item)>(item));
      } else {
        // packed varint or packed enum
        archive(make_tag<type>(meta), varint{*cache++});
        for (auto element : item) {
          archive(element_type{element});
        }
      }
    } else if constexpr (concepts::is_map_entry<typename Meta::type>) {
      constexpr auto tag = make_tag<type>(meta);
      auto &&[key, value] = item;
      archive(tag, varint{*cache++});
      using value_type = typename traits::get_map_entry<Meta, type>::read_only_type;
      static_assert(concepts::has_meta<value_type>);
      serialize(value_type{key, value}, cache, archive);
    } else {
      static_assert(!sizeof(type));
    }
  }

  template <std::size_t I, concepts::tuple Meta>
  constexpr static void serialize_oneof(auto &&item, uint32_t *&cache, auto &archive) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return serialize_field(typename std::tuple_element<I, Meta>::type{},
                               std::get<I + 1>(std::forward<decltype(item)>(item)), cache, archive);
      }
      return serialize_oneof<I + 1, Meta>(std::forward<decltype(item)>(item), cache, archive);
    }
  }

  template <typename Byte>
  struct basic_in {
    using byte_type = Byte;
    using is_basic_in = void;
    constexpr static bool endian_swapped = std::endian::little != std::endian::native;
    std::span<const Byte> m_data;

    constexpr bool empty() const { return m_data.empty(); }
    constexpr std::size_t size() const { return m_data.size(); }

    template <concepts::contiguous_byte_range Range>
    constexpr explicit basic_in(Range &&range) : m_data(std::data(range), std::size(range)) {}

    constexpr errc deserialize(auto &&item) {
      using type = std::remove_cvref_t<decltype(item)>;
      if constexpr (concepts::byte_serializable<type>) {
        if (m_data.size() < sizeof(item)) [[unlikely]] {
          return std::errc::result_out_of_range;
        }
        if (std::is_constant_evaluated()) {
          std::array<std::remove_const_t<byte_type>, sizeof(item)> value;
          if constexpr (endian_swapped) {
            std::reverse_copy(m_data.begin(), m_data.begin() + sizeof(item), value.begin());
          } else {
            std::copy(m_data.begin(), m_data.begin() + sizeof(item), value.begin());
          }
          item = std::bit_cast<type>(value);
        } else {
          if constexpr (endian_swapped && sizeof(type) != 1) {
            std::reverse_copy(m_data.begin(), m_data.begin() + sizeof(item), std::bit_cast<const std::byte *>(&item));
          } else {
            std::memcpy(&item, m_data.data(), sizeof(item));
          }
        }
        m_data = m_data.subspan(sizeof(item));
        return {};
      } else if constexpr (std::is_enum_v<type>) {
        deserialize(varint{static_cast<int64_t>(item)});
        return {};
      } else if constexpr (concepts::varint<type>) {
        using value_type = std::make_unsigned_t<typename type::value_type>;

        auto commit = [&item, this](auto value, std::size_t byte_count) {
          if constexpr (varint_encoding::zig_zag == type::encoding) {
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4146)
#endif
            item = ((value >> 1) ^ -(value & 0x1));
#ifdef _MSC_VER
#pragma warning(pop)
#endif
          } else {
            item = value;
          }

          m_data = m_data.subspan(byte_count);
          return errc{};
        };

        value_type value = 0;
        if (m_data.size() < varint_max_size<value_type>) [[unlikely]] {
          std::size_t shift = 0;
          for (auto &byte_value : m_data) {
            auto next_byte = value_type(byte_value);
            value |= (next_byte & 0x7f) << shift;
            if (next_byte >= 0x80) [[unlikely]] {
              shift += CHAR_BIT - 1;
              continue;
            }
            return commit(value, 1 + std::distance(m_data.data(), &byte_value));
          }
          return std::errc::result_out_of_range;
        } else {
          auto p = m_data.data();
          do {
            // clang-format off
            value_type next_byte; 
            next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 0)); if (next_byte < 0x80) [[likely]] { break; }
            next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 1)); if (next_byte < 0x80) [[likely]] { break; }
            if constexpr (varint_max_size<value_type> > 2) {
            next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 2)); if (next_byte < 0x80) [[likely]] { break; }
            if constexpr (varint_max_size<value_type> > 3) {
            next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 3)); if (next_byte < 0x80) [[likely]] { break; }
            next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 4)); if (next_byte < 0x80) [[likely]] { break; }
            if constexpr (varint_max_size<value_type> > 5) {
            next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 5)); if (next_byte < 0x80) [[likely]] { break; }
            next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 6)); if (next_byte < 0x80) [[likely]] { break; }
            next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 7)); if (next_byte < 0x80) [[likely]] { break; }
            next_byte = value_type(*p++); value |= ((next_byte & 0x7f) << ((CHAR_BIT - 1) * 8)); if (next_byte < 0x80) [[likely]] { break; }
            next_byte = value_type(*p++); value |= ((next_byte & 0x01) << ((CHAR_BIT - 1) * 9)); if (next_byte < 0x80) [[likely]] { break; } }}}
            return std::errc::value_too_large;
            // clang-format on
          } while (false);

          return commit(value, std::distance(m_data.data(), p));
        }
      } else if constexpr (std::ranges::contiguous_range<type> &&
                           concepts::byte_serializable<typename type::value_type>) {
        if constexpr (concepts::byte_serializable<typename type::value_type>) {
          if (!std::is_constant_evaluated() && (!endian_swapped || sizeof(typename type::value_type) == 1)) {
            auto bytes_to_copy = item.size() * sizeof(typename type::value_type);
            std::memcpy(item.data(), m_data.data(), bytes_to_copy);
            m_data = m_data.subspan(bytes_to_copy);
          } else {
            for (auto &x : item) {
              this->deserialize(x);
            }
          }
        }
        return {};
      } else {
        static_assert(!sizeof(type));
        return {};
      }
    }

    constexpr errc skip_length_delimited() {
      vuint64_t len;
      if (auto result = deserialize(len); result.failure()) [[unlikely]] {
        return result;
      }
      return skip(len.value);
    }

    constexpr errc skip(std::size_t length) {
      if (m_data.size() < length) [[unlikely]] {
        return std::errc::result_out_of_range;
      }
      m_data = m_data.subspan(length);
      return {};
    }

    constexpr std::span<const byte_type> peek(std::size_t length) const {
      if (m_data.size() < length) [[unlikely]] {
        return {};
      }
      return m_data.subspan(0, length);
    }

    constexpr std::span<const byte_type> read(std::size_t length) {
      auto r = peek(length);
      m_data = m_data.subspan(length);
      return r;
    }

    std::span<const byte_type> unwind_tag(uint32_t tag) {
      auto tag_len = varint_size<varint_encoding::normal>(tag);
      return {m_data.data() - tag_len, m_data.size() + tag_len};
    }

    constexpr errc operator()(auto &&...item) {
      errc result;
      (void)(((result = deserialize(item)).success()) && ...);
      return result;
    }
  };

  template <concepts::contiguous_byte_range Range>
  basic_in(Range &&) -> basic_in<std::ranges::range_value_t<Range>>;

  static errc skip_field(uint32_t tag, concepts::has_extension auto &item, auto &context,
                         concepts::is_basic_in auto &archive) {

    auto unwound = archive.unwind_tag(tag);

    if (auto result = do_skip_field(tag, archive); result.failure()) [[unlikely]] {
      return result;
    }

    using fields_type = std::remove_cvref_t<decltype(item.extensions.fields)>;
    using bytes_type = typename fields_type::value_type::second_type;
    using byte_type = typename bytes_type::value_type;

    unwound = unwound.subspan(0, unwound.size() - archive.size());

    std::span<const byte_type> field_span{std::bit_cast<const byte_type *>(unwound.data()), unwound.size()};
    const uint32_t field_num = tag_number(tag);

    if constexpr (concepts::associative_container<fields_type>) {
      auto &value = item.extensions.fields[field_num];
      value.insert(value.end(), field_span.begin(), field_span.end());
    } else {
      static_assert(concepts::span<fields_type>);
      auto &fields = item.extensions.fields;

      if (!fields.empty() && fields.back().first == field_num) {
        // if the newly parsed has the same field number with previously parsed, just extends the content
        auto &entry = fields.back().second;
        if (entry.data() + entry.size() == field_span.data()) {
          entry = std::span{entry.data(), entry.size() + field_span.size()};
          return {};
        }
      }

      auto itr =
          std::find_if(fields.begin(), fields.end(), [field_num](const auto &e) { return e.first == field_num; });
      if (itr == fields.end()) [[likely]] {
        make_growable(context, fields).push_back({field_num, field_span});
      } else {
        // the extension with the same field number exists, append the content to the previously parsed.
        decltype(auto) v = make_growable(context, itr->second);
        auto s = v.size();
        v.resize(v.size() + field_span.size());
        std::copy(field_span.begin(), field_span.end(), v.data() + s);
      }
    }

    return {};
  }

  constexpr static errc skip_field(uint32_t tag, concepts::has_meta auto &, auto & /* unused */,
                                   concepts::is_basic_in auto &archive) {
    return do_skip_field(tag, archive);
  }

  constexpr static errc do_skip_field(uint32_t tag, concepts::is_basic_in auto &archive) {
    switch (proto::tag_type(tag)) {
    case wire_type::varint: {
      vuint64_t length = 0;
      return archive(length);
    }
    case wire_type::length_delimited:
      return archive.skip_length_delimited();
    case wire_type::fixed_64:
      return archive.skip(8);
    case wire_type::sgroup:
      return do_skip_group(tag_number(tag), archive);
    case wire_type::fixed_32:
      return archive.skip(4);
    default:
      return std::errc::result_out_of_range;
    }
  }

  constexpr static errc do_skip_group(uint32_t field_num, concepts::is_basic_in auto &archive) {
    while (!archive.empty()) {
      vuint32_t tag;
      if (auto result = archive(tag); result.failure()) [[unlikely]] {
        return result;
      }
      const uint32_t next_field_num = tag_number(tag);
      const wire_type next_type = proto::tag_type(tag);

      if (next_type == wire_type::egroup && field_num == next_field_num) {
        return {};
      } else if (auto result = do_skip_field(tag, archive); result.failure()) {
        return result;
      }
    }
    return std::errc::result_out_of_range;
  }

  constexpr static errc skip_tag(uint32_t tag, concepts::is_basic_in auto &archive) {
    vuint32_t t;
    if (auto result = archive(t); result.failure()) [[unlikely]] {
      return result;
    }
    if (t != tag) [[unlikely]] {
      return std::errc::result_out_of_range;
    }
    return {};
  }

  template <typename T>
  constexpr static std::size_t count_packed_elements(uint32_t length, concepts::is_basic_in auto &archive) {

    if constexpr (concepts::byte_serializable<T>) {
      return length / sizeof(T);
    } else if constexpr (std::is_enum_v<T> || concepts::varint<T>) {
      auto data = archive.peek(length);
      return std::count_if(data.begin(), data.end(), [](auto c) { return (static_cast<char>(c) & 0x80) == 0; });
    } else {
      static_assert(!sizeof(T));
    }
  }

  constexpr static errc count_unpacked_elements(uint32_t input_tag, std::size_t &count,
                                                concepts::is_basic_in auto archive) {
    vuint32_t parsed_tag;

    do {
      if (auto result = do_skip_field(input_tag, archive); result.failure()) {
        return result;
      }

      ++count;

      if (archive.empty()) {
        return {};
      }

      if (auto result = archive(parsed_tag); result.failure()) [[unlikely]] {
        return result;
      }
    } while (parsed_tag == input_tag);
    return {};
  }

  template <typename Meta>
  constexpr static errc deserialize_packed_repeated(Meta, auto &&item, auto &context,
                                                    concepts::is_basic_in auto &archive) {
    using type = std::remove_reference_t<decltype(item)>;
    using value_type = typename type::value_type;

    using element_type =
        std::conditional_t<std::same_as<typename Meta::type, void> || std::same_as<value_type, char> ||
                               std::same_as<value_type, std::byte> || std::same_as<typename Meta::type, type>,
                           value_type, typename Meta::type>;

    vuint64_t length;
    if (auto result = archive(length); result.failure()) [[unlikely]] {
      return result;
    }

    if constexpr (std::is_same_v<type, std::string_view>) {
      // handling string_view
      auto data = archive.read(length);
      if (data.size() != length) {
        return std::errc::result_out_of_range;
      }
      item = std::string_view((const char *)data.data(), length);
      return {};
    } else {
      decltype(auto) growable = make_growable(context, item);

      if constexpr (requires { growable.resize(1); }) {
        // packed repeated vector,
        std::size_t size = count_packed_elements<element_type>(static_cast<uint32_t>(length), archive);

        using serialize_type = std::conditional_t<std::is_enum_v<value_type> && !std::same_as<value_type, std::byte>,
                                                  vint64_t, element_type>;

        if constexpr (concepts::byte_serializable<serialize_type>) {
          growable.resize(size);
          return archive(growable);
        } else {
          std::size_t old_size = item.size();
          growable.resize(old_size + size);
          for (auto &value : std::span<value_type>{growable.data() + old_size, size}) {
            serialize_type underlying;
            if (auto result = archive(underlying); result.failure()) [[unlikely]] {
              return result;
            }
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4244)
#endif
            value = static_cast<element_type>(underlying.value);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
          }
          return {};
        }
      } else if constexpr ((std::is_same_v<value_type, char> ||
                            std::is_same_v<value_type, std::byte>)&&std::is_same_v<type, std::span<const value_type>>) {
        // handling bytes
        auto data = archive.read(length);
        if (data.size() != length) {
          return std::errc::result_out_of_range;
        }
        item = std::span<const value_type>((const value_type *)data.data(), length);
        return {};
      } else if constexpr (requires { item.insert(value_type{}); }) {
        // packed repeated set
        auto fetch = [&item](auto &archive) constexpr {
          element_type value;

          if constexpr (std::is_enum_v<element_type>) {
            vint64_t underlying;
            if (auto result = archive(underlying); result.failure()) [[unlikely]] {
              return result;
            }
            value = static_cast<element_type>(underlying.value);
          } else {
            // varint
            if (auto result = archive(value); result.failure()) [[unlikely]] {
              return result;
            }
          }
          item.insert(value_type(value));
          return std::errc{};
        };

        basic_in new_archive{archive.read(length)};
        while (!new_archive.empty()) {
          if (auto result = fetch(new_archive); result.failure()) [[unlikely]] {
            return result;
          }
        }
        return {};
      } else {
        static_assert(concepts::has_memory_resource<decltype(context)>, "memory resource is required");
        return {};
      }
    }
  }

  template <typename Meta, typename Container>
  struct unpacked_element_inserter {

    template <typename MetaType>
    struct get_base_value_type {
      using type = typename Container::value_type;
    };

    template <concepts::is_map_entry MetaType>
    struct get_base_value_type<MetaType> {
      using type = typename Meta::type::mutable_type;
    };

    using base_value_type = typename get_base_value_type<typename Meta::type>::type;

    template <typename C>
    struct element_type {
      C &item;
      base_value_type value;
      constexpr element_type(C &item, std::size_t) : item(item) {}

      constexpr ~element_type() {
        if constexpr (concepts::is_map_entry<typename Meta::type>) {
          std::move(value).insert_to(item);
        } else if constexpr (requires { item.insert(value); }) {
          item.insert(std::move(value));
        } else {
          static_assert(!sizeof(base_value_type), "memory resource is required");
        }
      }
    };

    template <concepts::resizable C>
      requires std::same_as<std::remove_const_t<typename C::value_type>, base_value_type>
    struct element_type<C> {
      base_value_type &value;
      constexpr element_type(C &item, std::size_t i) : value(item[i]) {}
    };

    template <concepts::resizable C>
      requires(!std::same_as<std::remove_const_t<typename C::value_type>, base_value_type>)
    struct element_type<C> {
      std::remove_const_t<typename C::value_type> &target;
      base_value_type value;

      constexpr element_type(C &item, std::size_t i) : target(item[i]) {}
      constexpr ~element_type() {
        if constexpr (requires { std::move(value).to(target); }) {
          std::move(value).to(target);
        } else {
          target = std::move(value);
        }
      }
    };

    element_type<Container> element;

    constexpr unpacked_element_inserter(Container &item, std::size_t i = 0) : element(item, i) {}

    constexpr errc deserialize(uint32_t tag, auto &context, concepts::is_basic_in auto &archive) {
      if constexpr (concepts::scalar<base_value_type>) {
        return pb_serializer::deserialize_field(Meta{}, tag, element.value, context, archive);
      } else {
        return pb_serializer::deserialize_sized(element.value, context, archive);
      }
    }
  };

  constexpr static void resize_or_reserve(concepts::resizable_or_reservable auto &growable, std::size_t size) {
    if constexpr (requires { growable.resize(1); }) {
      growable.resize(size);
    } else if constexpr (requires { growable.reserve(size); }) { // e.g. boost::flat_map
      growable.reserve(size);
    } else { // e.g. std::flat_map
      reserve(growable, size);
    }
  }

  template <typename Meta>
  constexpr static errc deserialize_unpacked_repeated(Meta, uint32_t tag, auto &&item, auto &context,
                                                      concepts::is_basic_in auto &archive) {

    using type = std::remove_reference_t<decltype(item)>;

    decltype(auto) growable = make_growable(context, item);

    if constexpr (concepts::resizable_or_reservable<decltype(growable)>) {
      std::size_t count = 0;
      if (auto result = count_unpacked_elements(tag, count, archive); result.failure()) [[unlikely]] {
        return result;
      }
      auto old_size = item.size();
      const std::size_t new_size = item.size() + count;

      resize_or_reserve(growable, new_size);

      for (auto i = old_size; i < new_size; ++i) {
        unpacked_element_inserter<Meta, std::remove_cvref_t<decltype(growable)>> inserter(growable, i);
        if (auto result = inserter.deserialize(tag, context, archive); result.failure()) [[unlikely]] {
          return result;
        }

        if (i < new_size - 1) {
          if (auto result = skip_tag(tag, archive); result.failure()) [[unlikely]] {
            return result;
          }
        }
      }
      return {};
    } else {
      unpacked_element_inserter<Meta, type> inserter{item};
      return inserter.deserialize(tag, context, archive);
    }
  }

  template <typename Meta>
  constexpr static errc deserialize_field(Meta meta, uint32_t tag, auto &&item, auto &context,
                                          concepts::is_basic_in auto &archive) {

    const uint32_t field_num = tag_number(tag);

    using type = std::remove_reference_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    if constexpr (std::is_enum_v<type>) {
      vint64_t value;
      if (auto result = archive(value); result.failure()) [[unlikely]] {
        return result;
      }
      item = static_cast<type>(value.value);
      return {};
    } else if constexpr (std::is_same_v<type, boolean>) {
      return archive(item.value);
    } else if constexpr (concepts::optional<type>) {
      if constexpr (requires { item.emplace(); }) {
        return deserialize_field(meta, tag, item.emplace(), context, archive);
      } else {
        item = typename type::value_type{};
        return deserialize_field(meta, tag, *item, context, archive);
      }
    } else if constexpr (concepts::unique_ptr<type>) {
      using element_type = std::remove_reference_t<decltype(*item)>;
      auto loaded = std::make_unique<element_type>();
      if (auto result = deserialize_field(meta, tag, *loaded, context, archive); result.failure()) [[unlikely]] {
        return result;
      }
      item.reset(loaded.release());
      return {};
    } else if constexpr (std::is_pointer_v<type>) {
      static_assert(concepts::has_memory_resource<decltype(context)>, "memory resource is required");
      using element_type = std::remove_cvref_t<decltype(*item)>;
      void *buffer = context.memory_resource().allocate(sizeof(element_type), alignof(element_type));
      if (buffer == nullptr) [[unlikely]] {
        return std::errc::not_enough_memory;
      }
      auto loaded = new (buffer) element_type;
      if (auto result = deserialize_field(meta, tag, *loaded, context, archive); result.failure()) [[unlikely]] {
        return result;
      }
      item = loaded;
      return {};
    } else if constexpr (concepts::oneof_type<type>) {
      static_assert(std::is_same_v<std::remove_cvref_t<decltype(std::get<0>(type{}))>, std::monostate>);
      return deserialize_oneof<0, typename Meta::alternatives_meta>(tag, std::forward<decltype(item)>(item), context,
                                                                    archive);
    } else if constexpr (!std::is_same_v<type, serialize_type> && concepts::scalar<serialize_type> &&
                         !std::ranges::range<type>) {
      serialize_type value;
      if (auto result = deserialize_field(meta, tag, value, context, archive); result.failure()) [[unlikely]] {
        return result;
      }
      if constexpr (std::is_arithmetic_v<type>) {
        item = static_cast<type>(value);
      } else {
        item = std::move(value);
      }
      return {};
    } else if constexpr (concepts::numeric_or_byte<type>) {
      return archive(item);
    } else if constexpr (concepts::has_meta<type>) {
      if constexpr (meta.encoding != encoding_rule::group) {
        return deserialize_sized(item, context, archive);
      } else {
        return deserialize_group(field_num, item, context, archive);
      }
    } else if constexpr (meta.encoding == encoding_rule::group) {
      // repeated group
      if constexpr (requires { item.emplace_back(); }) {
        return deserialize_group(field_num, item.emplace_back(), context, archive);
      } else {
        decltype(auto) growable = make_growable(context, item);
        auto old_size = item.size();
        growable.resize(old_size + 1);
        return deserialize_group(field_num, growable[old_size], context, archive);
      }
    } else if constexpr (concepts::contiguous_byte_range<type>) {
      return deserialize_packed_repeated(meta, std::forward<type>(item), context, archive);
    } else { // repeated non-group
      using value_type = typename type::value_type;
      if constexpr (concepts::numeric<value_type> && meta.encoding != encoding_rule::unpacked_repeated) {
        if (tag_type(tag) != wire_type::length_delimited) {
          return deserialize_unpacked_repeated(meta, tag, std::forward<type>(item), context, archive);
        }
        return deserialize_packed_repeated(meta, std::forward<type>(item), context, archive);
      } else {
        return deserialize_unpacked_repeated(meta, tag, std::forward<type>(item), context, archive);
      }
    }
  }

  constexpr static errc deserialize_group(uint32_t field_num, auto &&item, auto &context,
                                          concepts::is_basic_in auto &archive) {

    while (!archive.empty()) {
      vuint32_t tag;
      if (auto result = archive(tag); result.failure()) [[unlikely]] {
        return result;
      }

      if (proto::tag_type(tag) == wire_type::egroup && field_num == tag_number(tag)) {
        return {};
      }

      if (auto result = deserialize_field_by_tag(tag, item, context, archive); result.failure()) [[unlikely]] {
        return result;
      }
    }

    return std::errc::result_out_of_range;
  }

  template <std::size_t Index, concepts::tuple Meta>
  constexpr static errc deserialize_oneof(int32_t tag, auto &&item, auto &context,
                                          concepts::is_basic_in auto &archive) {
    if constexpr (Index < std::tuple_size_v<Meta>) {
      using meta = typename std::tuple_element<Index, Meta>::type;
      if (meta::number == tag_number(tag)) {
        if constexpr (requires { item.template emplace<Index + 1>(); }) {
          return deserialize_field(meta{}, tag, item.template emplace<Index + 1>(), context, archive);
        } else {
          item = std::variant_alternative_t<Index + 1, std::decay_t<decltype(item)>>{};
          return deserialize_field(meta{}, tag, std::get<Index + 1>(item), context, archive);
        }
      } else {
        return deserialize_oneof<Index + 1, Meta>(tag, std::forward<decltype(item)>(item), context, archive);
      }
    } else {
      return {};
    }
  }

  template <std::size_t Index>
  constexpr static errc deserialize_field_by_index(uint32_t tag, auto &item, auto &context,
                                                   concepts::is_basic_in auto &archive) {
    using type = std::remove_reference_t<decltype(item)>;
    using Meta = typename traits::field_meta_of<type, Index>::type;
    if constexpr (requires { requires Meta::number == UINT32_MAX; }) {
      // this is extension, not a regular field
      return {};
    } else {
      return deserialize_field(Meta(), tag, Meta::access(item), context, archive);
    }
  }

  template <uint32_t MaskedNum, uint32_t I = 0>
  constexpr static errc deserialize_field_by_masked_num(uint32_t tag, auto &item, auto &context,
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

  template <typename Type, typename Context, concepts::is_basic_in Archive, std::size_t... I>
  constexpr static auto deserialize_by_masked_num_funs(std::index_sequence<I...>) {
    using deserialize_fun_ptr = errc (*)(uint32_t, Type &, Context &, Archive &);
    return std::array<deserialize_fun_ptr, sizeof...(I)>{&deserialize_field_by_masked_num<I>...};
  }

  constexpr static errc deserialize_field_by_tag(uint32_t tag, auto &item, auto &context,
                                                 concepts::is_basic_in auto &archive) {

    using type = std::remove_cvref_t<decltype(item)>;
    using context_type = std::remove_cvref_t<decltype(context)>;
    using archive_type = std::remove_cvref_t<decltype(archive)>;
    constexpr auto mask = traits::reverse_indices<type>::mask;
    constexpr auto fun_ptrs =
        deserialize_by_masked_num_funs<type, context_type, archive_type>(std::make_index_sequence<mask + 1>());
    return (*fun_ptrs[tag_number(tag) & mask])(tag, item, context, archive);
  }

  constexpr static errc deserialize(concepts::has_meta auto &item, concepts::is_pb_context auto &context,
                                    concepts::is_basic_in auto &archive) {

    while (!archive.empty()) {
            vuint32_t tag;
            if (auto result = archive(tag); result.failure()) [[unlikely]] {
        return result;
      }

      if (auto result = deserialize_field_by_tag(tag, item, context, archive); result.failure()) {
        [[unlikely]] return result;
      }
    }

    return {};
  }

  constexpr static errc deserialize_sized(auto &&item, auto &context, concepts::is_basic_in auto &archive) {
    vuint64_t len;
    if (auto result = archive(len); result.failure()) [[unlikely]] {
      return result;
    }

    if (len <= archive.size()) [[likely]] {
      basic_in new_archive{archive.read(len)};
      return deserialize(item, context, new_archive);
    }

    return std::errc::result_out_of_range;
  }

  constexpr static errc deserialize(concepts::has_meta auto &item, concepts::contiguous_byte_range auto &&buffer) {

    basic_in<std::ranges::range_value_t<decltype(buffer)>> archive(buffer);
    pb_context ctx;
    return deserialize(item, ctx, archive);
  }

  constexpr static errc deserialize(concepts::has_meta auto &item, concepts::contiguous_byte_range auto &&buffer,
                                    concepts::is_pb_context auto &&context) {

    basic_in<std::ranges::range_value_t<decltype(buffer)>> archive(buffer);
    return deserialize(item, context, archive);
  }

  consteval static auto to_bytes(auto ObjectLambda) {
    constexpr auto sz = message_size(ObjectLambda());
    if constexpr (sz == 0) {
      return std::span<std::byte>{};
    } else {
      std::array<std::byte, sz> buffer;
      serialize(ObjectLambda(), buffer);
      return buffer;
    }
  }

  template <typename T>
  constexpr static auto from_bytes(auto &&buffer) {
    T obj = {};
    auto ec = deserialize(obj, buffer, pb_context{});
    if (ec.failure())
      throw std::system_error(std::make_error_code(ec));
    return obj;
  }
};

template <typename FieldType, typename MetaType>
struct serialize_wrapper_type {
  FieldType value;
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
  using return_type = expected<value_type, errc>;

  serialize_wrapper_type<value_type, ExtensionMeta> wrapper;
  if (itr != extensions.fields.end()) {
    if (auto ec = pb_serializer::deserialize(wrapper, itr->second, ctx...); ec.failure()) [[unlikely]] {
      return return_type{unexpected(ec)};
    }
    return return_type{wrapper.value};
  }

  if constexpr (ExtensionMeta::has_default_value) {
    return return_type(value_type(ExtensionMeta::default_value));
  } else if constexpr (concepts::scalar<value_type>) {
    return return_type{value_type{}};
  } else {
    return return_type{unexpected(std::errc::no_message)};
  }
}

template <typename ExtensionMeta>
inline errc extension_meta_base<ExtensionMeta>::write(concepts::pb_extension auto &extensions, auto &&value) {
  check(extensions);

  serialize_wrapper_type<decltype(value), ExtensionMeta> wrapper{std::forward<decltype(value)>(value)};
  typename decltype(extensions.fields)::mapped_type data;

  if (auto ec = pb_serializer::serialize(wrapper, data); ec.failure()) [[unlikely]] {
    return ec;
  }
  if (data.size()) {
    extensions.fields[ExtensionMeta::number] = std::move(data);
  }
  return {};
}

template <typename ExtensionMeta>
inline errc extension_meta_base<ExtensionMeta>::write(concepts::pb_extension auto &extensions, auto &&value,
                                                      concepts::is_pb_context auto && ctx) {
  check(extensions);

  std::span<std::byte> buf;
  auto data = make_growable(ctx, buf);

  serialize_wrapper_type<decltype(value), ExtensionMeta> wrapper{std::forward<decltype(value)>(value)};

  if (auto ec = pb_serializer::serialize(wrapper, data); ec.failure()) [[unlikely]] {
    return ec;
  }

  if (data.size()) {
    auto old_size = extensions.fields.size();
    auto growable_fields = make_growable(ctx, extensions.fields);
    growable_fields.resize(old_size + 1);
    extensions.fields[old_size] = {ExtensionMeta::number, {data.data(), data.size()}};
  }
  return {};
}

template <typename T, concepts::contiguous_output_byte_range Buffer>
[[nodiscard]] errc write_proto(T &&msg, Buffer &buffer) {
  return pb_serializer::serialize(std::forward<T>(msg), buffer);
}

/// @brief serialize a message to the end of the supplied buffer
template <typename T, concepts::resizable_contiguous_byte_container Buffer>
[[nodiscard]] errc append_proto(T &&msg, Buffer &buffer) {
  constexpr bool overwrite_buffer = false;
  return pb_serializer::serialize<overwrite_buffer>(std::forward<T>(msg), buffer);
}

template <typename T, concepts::contiguous_byte_range Buffer>
[[nodiscard]] errc read_proto(T &msg, Buffer &&buffer, concepts::is_pb_context auto &&...ctx) {
  static_assert(sizeof...(ctx) <= 1);
  msg = {};
  return pb_serializer::deserialize(msg, std::forward<Buffer>(buffer), ctx...);
}

/// @brief  deserialize from the buffer and merge the content with the existing msg
template <typename T, concepts::contiguous_byte_range Buffer>
[[nodiscard]] errc merge_proto(T &msg, Buffer &&buffer, concepts::is_pb_context auto &&...ctx) {
  static_assert(sizeof...(ctx) <= 1);
  return pb_serializer::deserialize(msg, std::forward<Buffer>(buffer), ctx...);
}

namespace concepts {
template <typename T>
concept is_any = requires(T &obj) {
  { obj.type_url } -> concepts::string;
  { obj.value } -> concepts::contiguous_byte_range;
};
}

[[nodiscard]] errc pack_any(concepts::is_any auto &any, auto &&msg) {
  any.type_url = message_type_url(msg);
  return write_proto(msg, any.value);
}

[[nodiscard]] errc pack_any(concepts::is_any auto &any, auto &&msg, concepts::is_pb_context auto &&ctx) {
  any.type_url = message_type_url(msg);
  decltype(auto) v = make_growable(ctx, any.value);
  return write_proto(msg, v);
}

[[nodiscard]] errc unpack_any(concepts::is_any auto &&any, auto &&msg, concepts::is_pb_context auto &&...ctx) {
  static_assert(sizeof...(ctx) <= 1);
  if (std::string_view{any.type_url}.ends_with(message_name(msg))) {
    return read_proto(msg, any.value, ctx...);
  }
  return std::errc::invalid_argument;
}

} // namespace proto
} // namespace hpp

#endif
