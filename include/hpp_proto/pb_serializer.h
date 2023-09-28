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
#include <bit>
#include <cassert>
#include <concepts>
#include <hpp_proto/field_types.h>
#include <map>
#include <zpp_bits.h>

#if __cplusplus >= 202302L
#include <expected>
#else
#include <tl/expected.hpp>
#endif

namespace hpp {
namespace proto {

#if defined(__cpp_lib_expected)
using std::expected;
using std::unexpected;
#else
using tl::expected;
using tl::unexpected;
#endif

enum class encoding_rule {
  defaulted = 0,
  explicit_presence = 1,
  unpacked_repeated = 2,
  group = 3,
  packed_repeated = 4
};

template <uint32_t Number, encoding_rule Encoding = encoding_rule::defaulted, typename Type = void,
          auto DefaultValue = std::monostate{}>
struct field_meta {
  constexpr static uint32_t number = Number;
  constexpr static encoding_rule encoding = Encoding;
  using type = Type;

  template <typename T>
  static constexpr bool omit_value(const T &v) {
    return (Encoding == encoding_rule::defaulted && is_default_value<T, DefaultValue>(v));
  }
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
struct field_meta_ext {
  constexpr static uint32_t number = Number;
  constexpr static encoding_rule encoding = Encoding;
  constexpr static auto access = accesor_type<Accessor>{};
  using type = Type;

  template <typename T>
  inline static constexpr bool omit_value(const T &v) {
    return (Encoding == encoding_rule::defaulted && is_default_value<T, DefaultValue>(v));
  }
};

template <auto Accessor, typename... AlternativeMeta>
struct oneof_field_meta {
  constexpr static auto access = accesor_type<Accessor>{};
  using alternatives_meta = std::tuple<AlternativeMeta...>;
};

using ::zpp::bits::errc;
using ::zpp::bits::failure;

namespace concepts {

template <typename Type>
concept has_local_meta = ::zpp::bits::concepts::tuple<typename Type::pb_meta>;

template <typename Type>
concept has_explicit_meta = ::zpp::bits::concepts::tuple<decltype(pb_meta(std::declval<Type>()))>;

template <typename Type>
concept has_meta = has_local_meta<Type> || has_explicit_meta<Type>;

template <typename T>
concept numeric = std::is_fundamental_v<T> || ::zpp::bits::concepts::varint<T> || std::is_enum_v<T> ||
                  std::same_as<hpp::proto::boolean, T>;

template <typename T>
concept numeric_or_byte = numeric<T> || std::same_as<std::byte, T>;

template <typename Type>
concept optional = requires(Type optional) {
  optional.value();
  optional.has_value();
  // optional.operator bool(); // this operator is deliberately removed to fit our specialization for optional<bool>
  // which removed this operation
  optional.operator*();
};

template <typename Type>
concept oneof_type = ::zpp::bits::concepts::variant<Type>;

template <typename Type>
concept string_or_bytes =
    ::zpp::bits::concepts::container<Type> &&
    (std::same_as<char, typename Type::value_type> || std::same_as<std::byte, typename Type::value_type>);

template <typename Type>
concept scalar = numeric_or_byte<Type> || string_or_bytes<Type> || std::same_as<Type, boolean>;

template <typename Type>
concept pb_extension = requires(Type value) { typename Type::pb_extension; };

template <typename Type>
concept is_map_entry = requires {
  typename Type::key_type;
  typename Type::mapped_type;
};

template <typename Type>
concept is_option = requires { typename std::remove_cvref_t<Type>::zpp_bits_option; };

template <typename T>
concept span = requires {
  typename T::value_type;
  requires std::same_as<T, std::span<typename T::value_type>>;
};

template <typename T>
concept is_oneof_field_meta = requires { typename T::alternatives_meta; };

} // namespace concepts

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

  static auto read(const concepts::pb_extension auto &extensions, auto &&mr);
  static std::error_code write(concepts::pb_extension auto &extensions, auto &&value);
  static std::error_code write(concepts::pb_extension auto &extensions, auto &&value,
                               concepts::memory_resource auto &mr);
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
    return (Encoding == encoding_rule::defaulted && is_default_value<T, DefaultValue>(v));
  }
};

template <typename Extendee, uint32_t Number, encoding_rule Encoding, typename Type, typename ValueType>
struct repeated_extension_meta
    : field_meta<Number, Encoding, Type>,
      extension_meta_base<repeated_extension_meta<Extendee, Number, Encoding, Type, ValueType>> {
  constexpr static bool has_default_value = false;
  static constexpr bool is_repeated = true;
  using extendee = Extendee;
  static constexpr bool non_owning = concepts::span<decltype(std::declval<typename extendee::extension_t>().fields)>;
  using element_type = std::conditional_t<std::is_same_v<ValueType, bool> && !non_owning, boolean, ValueType>;
  using get_result_type = std::conditional_t<non_owning, std::span<const element_type>, std::vector<element_type>>;
  using set_value_type = std::span<const element_type>;
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
  if constexpr (::zpp::bits::concepts::varint<type> || (std::is_enum_v<type> && !std::same_as<type, std::byte>) ||
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
  return ::zpp::bits::varint{(number << 3) | std::underlying_type_t<wire_type>(type)};
}

template <typename Type, typename Meta>
constexpr auto make_tag(Meta meta) {
  // check if Meta::number is static or not
  if constexpr ( requires { *&Meta::number; }) {
    return make_tag(Meta::number, tag_type<Type>());
  } else {
    return make_tag(meta.number, tag_type<Type>());
  }
}

constexpr auto tag_type(auto tag) { return wire_type(tag.value & 0x7); }

constexpr auto tag_number(auto tag) { return (unsigned int)(tag >> 3); }

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

template <typename Type>
constexpr void set_as_default(Type &value) {
  using type = std::remove_cvref_t<Type>;
  if constexpr (concepts::scalar<type>) {
    value = type{};
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
  using type = ::zpp::bits::vint64_t;
  using read_type = ::zpp::bits::vint64_t;
  using convertible_type = std::underlying_type_t<T>;
};

template <::zpp::bits::concepts::varint T>
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
struct map_entry_read_only_type {
  typename serialize_type<KeyType>::read_type key;
  typename serialize_type<MappedType>::read_type value;
  using serialize = ::zpp::bits::members<2>;
  constexpr static bool allow_inline_visit_members_lambda = true;

  ZPP_BITS_INLINE constexpr map_entry_read_only_type(auto &&k, auto &&v)
      : key((typename serialize_type<KeyType>::convertible_type)k),
        value((typename serialize_type<MappedType>::convertible_type)v) {}

  struct key_accessor {
    constexpr const auto &operator()(const map_entry_read_only_type &entry) const { return entry.key; }
  };

  struct value_accessor {
    constexpr const auto &operator()(const map_entry_read_only_type &entry) const { return entry.value; }
  };

  using pb_meta = std::tuple<field_meta_ext<1, key_accessor{}, encoding_rule::explicit_presence>,
                             field_meta_ext<2, value_accessor{}, encoding_rule::explicit_presence>>;
};

template <typename KeyType, typename MappedType>
struct map_entry {
  using key_type = KeyType;
  using mapped_type = MappedType;
  struct mutable_type {
    using serialize = ::zpp::bits::members<2>;
    typename serialize_type<KeyType>::type key;
    typename serialize_type<MappedType>::type value;
    constexpr static bool allow_inline_visit_members_lambda = true;
    using pb_meta = std::tuple<field_meta_ext<1, &mutable_type::key, encoding_rule::explicit_presence>,
                               field_meta_ext<2, &mutable_type::value, encoding_rule::explicit_presence>>;

    template <typename Target, typename Source>
    ZPP_BITS_INLINE constexpr static auto move_or_copy(Source &&src) {
      if constexpr (requires(Target target) { target = std::move(src); }) {
        return std::move(src);
      } else if constexpr (std::is_enum_v<Target> &&
                           std::is_same_v<std::remove_cvref_t<Source>, ::zpp::bits::vint64_t>) {
        return static_cast<Target>(src.value);
      } else {
        return static_cast<Target>(src);
      }
    }

    template <zpp::bits::concepts::associative_container Container>
    ZPP_BITS_INLINE constexpr void insert_to(Container &container) && {
      container.insert_or_assign(move_or_copy<typename Container::key_type>(key),
                                 move_or_copy<typename Container::mapped_type>(value));
    }

    template <typename K, typename V>
    ZPP_BITS_INLINE constexpr void to(std::pair<K, V> &target) && {
      target.first = move_or_copy<K>(key);
      target.second = move_or_copy<V>(value);
    }
  };

  using read_only_type = map_entry_read_only_type<KeyType, MappedType>;
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

template <typename Type, std::size_t Index>
struct field_meta_of {
  using type = field_meta<Index + 1>;
};

template <concepts::has_meta Type, std::size_t Index>
struct field_meta_of<Type, Index> {
  using type = typename std::tuple_element<Index, typename meta_of<Type>::type>::type;
};

constexpr auto get_default_size_type() { return std::monostate{}; }

constexpr auto get_default_size_type(auto option, auto... options) {
  if constexpr (requires { typename decltype(option)::default_size_type; }) {
    if constexpr (std::is_void_v<typename decltype(option)::default_size_type>) {
      return std::monostate{};
    } else {
      return typename decltype(option)::default_size_type{};
    }
  } else {
    return get_default_size_type(options...);
  }
}

template <typename... Options>
using default_size_type_t =
    std::conditional_t<std::same_as<std::monostate, decltype(get_default_size_type(std::declval<Options>()...))>, void,
                       decltype(get_default_size_type(std::declval<Options>()...))>;

template <typename Meta, typename Type>
using get_map_entry = typename Meta::type;

template <typename T, std::size_t M, std::size_t N>
constexpr std::array<T, M + N> operator<<(std::array<T, M> lhs, std::array<T, N> rhs) {
  std::array<T, M + N> result;
  std::copy(lhs.begin(), lhs.end(), result.begin());
  std::copy(rhs.begin(), rhs.end(), result.begin() + M);
  return result;
}

template <typename Type>
struct reverse_indices {
  static std::optional<std::size_t> number_to_index(uint32_t number, std::size_t) {
    if (number <= ::zpp::bits::access::number_of_members<Type>()) {
      return number - 1;
    } else {
      return {};
    }
  }
};

template <concepts::has_meta Type>
struct reverse_indices<Type> {

  template <typename T>
    requires requires { T::number; }
  constexpr static auto get_numbers(T meta) {
    return std::array{meta.number};
  }

  template <typename... T>
  constexpr static auto get_numbers(std::tuple<T...> metas) {
    return std::apply([](auto... elem) { return (... << get_numbers(elem)); }, metas);
  }

  template <concepts::is_oneof_field_meta Meta>
  constexpr static auto get_numbers(Meta /* unused */) {
    return std::apply([](auto... elem) { return (... << get_numbers(elem)); }, typename Meta::alternatives_meta{});
  }

  template <typename T>
    requires requires { T::encoding; }
  constexpr static auto is_unpacked_repeated(T meta) {
    return std::array{meta.encoding == encoding_rule::unpacked_repeated};
  }

  template <typename... T>
  constexpr static auto is_unpacked_repeated(std::tuple<T...> metas) {
    return std::apply([](auto... elem) { return (... << is_unpacked_repeated(elem)); }, metas);
  }

  template <concepts::is_oneof_field_meta Meta>
  constexpr static auto is_unpacked_repeated(Meta /* unused */) {
    return std::apply([](auto... elem) { return (... << is_unpacked_repeated(elem)); },
                      typename Meta::alternatives_meta{});
  }

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

  static std::optional<std::size_t> number_to_index(uint32_t number, std::size_t &hint) {
    const typename traits::meta_of<Type>::type metas;
    static auto numbers = get_numbers(metas);
    static auto indices = get_indices(metas);
    static auto unpacked = is_unpacked_repeated(metas);

    for (std::size_t i = 0; i < numbers.size(); ++i) {
      if (numbers[(i + hint) % numbers.size()] == number) {
        hint = i + (unpacked[i] == false);
        return indices[i];
      }
    }
    return {};
  }
};
template <typename Meta, typename Type>
struct get_serialize_type;

template <concepts::is_oneof_field_meta Meta, typename Type>
struct get_serialize_type<Meta, Type> {
  using type = Type;
};

template <typename Meta, typename Type>
  requires requires { typename Meta::type; }
struct get_serialize_type<Meta, Type> {
  using type = std::conditional_t<std::is_same_v<typename Meta::type, void>, Type, typename Meta::type>;
};

template <typename Type>
inline constexpr auto number_of_members = std::tuple_size_v<typename meta_of<Type>::type>;
} // namespace traits

namespace concepts {
template <typename Type>
concept has_extension = requires(Type value) {
  value.extensions;
  typename decltype(Type::extensions)::pb_extension;
};

template <typename Type>
concept reservable = requires(Type value) { value.reserve(1); } || requires(Type value) { reserve(value, 1); };
} // namespace concepts

template <typename Function, typename Iterable>
constexpr errc iterative_apply(Function &&fun, Iterable &iterable) {
  for (auto &&elem : iterable) {
    if (auto result = fun(std::forward<decltype(elem)>(elem)); failure(result)) [[unlikely]] {
      return result;
    }
  }
  return {};
}

template <typename... F>
inline constexpr std::errc execute_successively(F &&...f) {
  std::errc result;
  (void)(((result = f()) == std::errc{}) && ...);
  return result;
}

template <std::size_t FirstIndex, std::size_t... Indices>
ZPP_BITS_INLINE constexpr errc visit_many(auto &&visitor, std::index_sequence<FirstIndex, Indices...>,
                                          auto &&first_item, auto &&...items) {
  return execute_successively(
      [&]() constexpr { return visitor.template visit<FirstIndex>(std::forward<decltype(first_item)>(first_item)); },
      [&]() constexpr {
        return visit_many(visitor, std::index_sequence<Indices...>{}, std::forward<decltype(items)>(items)...);
      });
}

ZPP_BITS_INLINE constexpr errc visit_many(auto &&, std::index_sequence<>) { return {}; }

template <::zpp::bits::concepts::byte_view ByteView, typename... Options>
constexpr auto make_out_archive(ByteView &&view, Options &&...) {
  constexpr auto enlarger = ::zpp::bits::traits::enlarger<Options...>();
  constexpr auto no_enlarge_overflow =
      (... || std::same_as<std::remove_cvref_t<Options>, ::zpp::bits::options::no_enlarge_overflow>);

  return ::zpp::bits::out{
      std::forward<ByteView>(view),
      ::zpp::bits::size_varint{},
      ::zpp::bits::no_fit_size{},
      ::zpp::bits::endian::little{},
      ::zpp::bits::enlarger<std::get<0>(enlarger), std::get<1>(enlarger)>{},
      std::conditional_t<no_enlarge_overflow, ::zpp::bits::no_enlarge_overflow, ::zpp::bits::enlarge_overflow>{},
      ::zpp::bits::alloc_limit<::zpp::bits::traits::alloc_limit<Options...>()>{}};
}

template <typename SizeType = ::zpp::bits::vsize_t>
ZPP_BITS_INLINE constexpr errc serialize_sized(auto &archive, auto &&serialize_unsized) {
  auto size_position = archive.position();
  if (auto result = archive(SizeType{}); failure(result)) [[unlikely]] {
    return result;
  }

  if (auto result = serialize_unsized(); failure(result)) [[unlikely]] {
    return result;
  }

  auto current_position = archive.position();
  std::size_t message_size = current_position - size_position - sizeof(SizeType);

  using archive_type = std::decay_t<decltype(archive)>;

  if constexpr (::zpp::bits::concepts::varint<SizeType>) {
    constexpr auto preserialized_varint_size = 1;
    message_size = current_position - size_position - preserialized_varint_size;
    auto move_ahead_count = ::zpp::bits::varint_size(message_size) - preserialized_varint_size;
    if (move_ahead_count) {
      if constexpr (archive_type::resizable) {
        if (auto result = archive.enlarge_for(move_ahead_count); failure(result)) [[unlikely]] {
          return result;
        }
      } else if (move_ahead_count > archive.data().size() - current_position) [[unlikely]] {
        return std::errc::result_out_of_range;
      }
      auto data = archive.data().data();
      auto message_start = data + size_position + preserialized_varint_size;
      auto message_end = data + current_position;
      if (std::is_constant_evaluated()) {
        for (auto p = message_end - 1; p >= message_start; --p) {
          *(p + move_ahead_count) = *p;
        }
      } else {
        std::memmove(message_start + move_ahead_count, message_start, message_size);
      }
      archive.position() += move_ahead_count;
    }
  }

  auto message_length_span = std::span<typename archive_type::byte_type, sizeof(SizeType)>{
      archive.data().data() + size_position, sizeof(SizeType)};
  auto message_length_out =
      ::zpp::bits::out<std::span<typename archive_type::byte_type, sizeof(SizeType)>>{message_length_span};
  return message_length_out(SizeType(message_size));
}

template <::zpp::bits::concepts::byte_view ByteView = std::vector<std::byte>, typename... Options>
struct out {
  using archive_type = decltype(make_out_archive(std::declval<ByteView &>(), std::declval<Options &&>()...));

  archive_type m_archive;

  using default_size_type = traits::default_size_type_t<Options...>;

  constexpr explicit out(ByteView &&view, Options &&...options)
      : m_archive(make_out_archive(std::move(view), std::forward<Options>(options)...)) {}

  constexpr explicit out(ByteView &view, Options &&...options)
      : m_archive(make_out_archive(view, std::forward<Options>(options)...)) {}

  constexpr static auto kind() { return ::zpp::bits::kind::out; }
  constexpr static bool resizable = archive_type::resizable;

  constexpr std::size_t position() const { return m_archive.position(); }

  constexpr std::size_t &position() { return m_archive.position(); }

  constexpr auto remaining_data() { return m_archive.remaining_data(); }

  constexpr static auto no_fit_size =
      (... || std::same_as<std::remove_cvref_t<Options>, ::zpp::bits::options::no_fit_size>);

  ZPP_BITS_INLINE constexpr auto operator()(auto &&item) {
    if constexpr (archive_type::resizable && !no_fit_size && archive_type::enlarger != std::tuple{1, 1}) {
      auto end = m_archive.data().size();
      auto result = serialize_one<default_size_type>(std::forward<decltype(item)>(item));
      if (m_archive.position() >= end) {
        m_archive.data().resize(m_archive.position());
      }
      return result;
    } else {
      return serialize_one<default_size_type>(std::forward<decltype(item)>(item));
    }
  }

  ZPP_BITS_INLINE constexpr errc serialize_unsized(auto &&item) {
    using type = std::remove_cvref_t<decltype(item)>;
    using metas = typename traits::meta_of<type>::type;
    return std::apply(
        [&item, this](auto... meta) {
          errc result;
          (void)(((result = this->serialize_field(meta, meta.access(item))) == errc{}) && ...);
          return result;
        },
        metas{});
  }

  template <typename Meta>
  ZPP_BITS_INLINE constexpr errc serialize_field(Meta meta, auto &&item) {
    using type = std::remove_cvref_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    if constexpr (::zpp::bits::concepts::empty<type>) {
      return {};
    } else if constexpr (concepts::oneof_type<type>) {
      if (std::holds_alternative<std::monostate>(item)) {
        return {};
      }
      return serialize_oneof<0, Meta>(std::forward<decltype(item)>(item));
    } else {

      if (meta.omit_value(item)) {
        return {};
      }

      if constexpr (std::is_same_v<type, boolean>) {
        constexpr auto tag = make_tag<bool>(meta);
        return m_archive(tag, item.value);
      } else if constexpr (concepts::pb_extension<type>) {
        return iterative_apply([this](auto &&f) constexpr { return m_archive(::zpp::bits::bytes(f.second)); },
                               item.fields);
      } else if constexpr (concepts::optional<type>) {
        if (item.has_value()) {
          return serialize_field(meta, *item);
        }
        return {};
      } else if constexpr (::zpp::bits::concepts::owning_pointer<type> || std::is_pointer_v<type>) {
        if (item) {
          return serialize_field(meta, *item);
        }
        return {};
      } else if constexpr (!std::is_same_v<type, serialize_type> && concepts::scalar<serialize_type> &&
                           !::zpp::bits::concepts::container<type>) {
        return serialize_field(meta, serialize_type(item));
      } else if constexpr (std::is_enum_v<type> && !std::same_as<type, std::byte>) {
        constexpr auto tag = make_tag<type>(meta);
        return m_archive(tag, ::zpp::bits::vint64_t(std::underlying_type_t<type>(std::forward<decltype(item)>(item))));
      } else if constexpr (concepts::numeric_or_byte<type>) {
        constexpr auto tag = make_tag<type>(meta);
        return m_archive(tag, item);
      } else if constexpr (!::zpp::bits::concepts::container<type>) {
        if constexpr (meta.encoding != encoding_rule::group) {
          constexpr auto tag = make_tag<type>(meta);
          return execute_successively(
              [&, this]() constexpr { return m_archive(tag); },
              [&, this]() constexpr { return serialize_sized(std::forward<decltype(item)>(item)); });
        } else {
          return execute_successively(
              [&, this]() constexpr {
                auto tag =
                    ::zpp::bits::varint{(meta.number << 3) | std::underlying_type_t<wire_type>(wire_type::sgroup)};
                return m_archive(tag);
              },
              [&, this]() constexpr { return serialize_unsized(std::forward<decltype(item)>(item)); },
              [&, this]() constexpr {
                auto tag =
                    ::zpp::bits::varint{(meta.number << 3) | std::underlying_type_t<wire_type>(wire_type::egroup)};
                return m_archive(tag);
              });
        }
      } else if constexpr (::zpp::bits::concepts::associative_container<type> &&
                           requires { typename type::mapped_type; }) {
        return iterative_apply(
            [&, this](auto &&entry) constexpr {
              return execute_successively(
                  [&, this]() constexpr {
                    constexpr auto tag = make_tag<type>(meta);
                    return m_archive(tag);
                  },
                  [&, this]() constexpr {
                    auto &&[key, value] = entry;
                    using value_type = typename traits::get_map_entry<Meta, type>::read_only_type;
                    return serialize_sized(value_type(key, value));
                  });
            },
            item);
      } else {
        if (item.empty()) {
          return {};
        }
        using value_type = typename type::value_type;
        using element_type =
            std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::string_or_bytes<type>, value_type,
                               typename Meta::type>;

        if constexpr (Meta::encoding == encoding_rule::group) {
          return iterative_apply(
              [&](auto &&element) constexpr {
                return serialize_field(field_meta<meta.number, encoding_rule::group>{}, element);
              },
              item);
        } else if constexpr ((Meta::encoding == encoding_rule::unpacked_repeated ||
                              !concepts::numeric_or_byte<element_type>)&&!concepts::string_or_bytes<type>) {
          constexpr auto tag = make_tag<type>(meta);
          return iterative_apply(
              [&](auto &&element) constexpr {
                if constexpr (concepts::is_map_entry<typename Meta::type>) {
                  return execute_successively([&, this]() constexpr { return m_archive(tag); },
                                              [&, this]() constexpr {
                                                auto &[k, v] = element;
                                                return serialize_sized(typename Meta::type::read_only_type(k, v));
                                              });

                } else {
                  return serialize_field(meta, element);
                }
              },
              item);
        } else if constexpr (requires {
                               requires std::is_fundamental_v<element_type> ||
                                            std::same_as<typename type::value_type, std::byte>;
                             }) {
          // packed fundamental types or bytes
          constexpr auto tag = make_tag<type>(meta);
          auto size = item.size();
          if constexpr (std::is_same_v<value_type, boolean>) {
            return m_archive(
                tag, ::zpp::bits::varint{size},
                ::zpp::bits::unsized(std::span<const bool>{std::bit_cast<const bool *>(item.data()), size}));
          } else {
            return m_archive(tag, ::zpp::bits::varint{size * sizeof(typename type::value_type)},
                             ::zpp::bits::unsized(std::forward<decltype(item)>(item)));
          }
        } else {
          // packed varint or packed enum
          using varint_type = std::conditional_t<std::is_enum_v<value_type>, ::zpp::bits::vint64_t, element_type>;

          return execute_successively(
              [&, this]() constexpr {
                constexpr auto tag = make_tag<type>(meta);
                const std::size_t size =
                    std::transform_reduce(item.begin(), item.end(), 0u, std::plus{}, [](auto &element) {
                      return ::zpp::bits::varint_size<varint_type::encoding>(
                          static_cast<typename varint_type::value_type>(element));
                    });
                return m_archive(tag, ::zpp::bits::varint{size});
              },
              [&, this]() constexpr {
                return iterative_apply(
                    [&, this](auto &&element) constexpr {
                      return m_archive(varint_type{static_cast<typename varint_type::value_type>(element)});
                    },
                    item);
              });
        }
      }
    }
  }

  template <std::size_t I, ::zpp::bits::concepts::tuple Meta>
  ZPP_BITS_INLINE constexpr errc serialize_oneof(auto &&item) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return serialize_field(typename std::tuple_element<I, Meta>::type{},
                               std::get<I + 1>(std::forward<decltype(item)>(item)));
      }
      return serialize_oneof<I + 1, Meta>(std::forward<decltype(item)>(item));
    }
    return errc{};
  }

  template <std::size_t I, concepts::is_oneof_field_meta Meta>
  ZPP_BITS_INLINE constexpr errc serialize_oneof(auto &&item) {
    return serialize_oneof<I, typename Meta::alternatives_meta>(std::forward<decltype(item)>(item));
  }

  template <typename SizeType = ::zpp::bits::vsize_t>
  ZPP_BITS_INLINE constexpr errc serialize_sized(auto &&item) {
    return ::hpp::proto::serialize_sized<SizeType>(
        m_archive, [&item, this]() ZPP_BITS_CONSTEXPR_INLINE_LAMBDA { return serialize_unsized(item); });
  }

  template <typename SizeType = default_size_type>
  ZPP_BITS_INLINE constexpr errc serialize_one(auto &&item) {
    if constexpr (!std::is_void_v<SizeType>) {
      return serialize_sized<SizeType>(std::forward<decltype(item)>(item));
    } else {
      return serialize_unsized(std::forward<decltype(item)>(item));
    }
  }
};

template <::zpp::bits::concepts::byte_view ByteView, typename... Options>
constexpr auto make_in_archive(ByteView &&view, Options &&...) {
  if constexpr (std::same_as<std::decay_t<ByteView>, std::string_view>) {
    return ::zpp::bits::in{std::span{view.data(), view.size()}, ::zpp::bits::size_varint{},
                           ::zpp::bits::endian::little{},
                           ::zpp::bits::alloc_limit<::zpp::bits::traits::alloc_limit<Options...>()>{}};
  } else {
    return ::zpp::bits::in{std::forward<ByteView>(view), ::zpp::bits::size_varint{}, ::zpp::bits::endian::little{},
                           ::zpp::bits::alloc_limit<::zpp::bits::traits::alloc_limit<Options...>()>{}};
  }
}

template <class Key, class Mapped, class Compare, class KeyContainer, class MappedContainer>
void reserve(flat_map<Key, Mapped, Compare, KeyContainer, MappedContainer> &item, std::size_t size) {
  auto [keys, values] = std::move(item).extract();
  keys.reserve(size);
  values.reserve(size);
  item.replace(std::move(keys), std::move(values));
}

namespace concepts {

template <typename T>
concept resizable = requires { std::declval<T>().resize(1); };

template <typename T>
concept resizable_or_reservable =
    resizable<T> || requires { std::declval<T>().resize(1); } || requires { resize(std::declval<T>(), 1); };

} // namespace concepts
template <::zpp::bits::concepts::byte_view ByteView, typename MemoryResource, concepts::is_option... Options>
class in_base {
protected:
  MemoryResource &mem_resource;
  using archive_type = decltype(make_in_archive(std::declval<ByteView &>(), std::declval<Options &&>()...));
  archive_type m_archive;

public:
  using default_size_type = traits::default_size_type_t<Options...>;

  constexpr explicit in_base(ByteView &&view, MemoryResource &mr, Options &&...options)
      : mem_resource(mr), m_archive(make_in_archive(std::move(view), std::forward<Options>(options)...)) {
    static_assert(std::is_trivially_destructible_v<std::remove_cvref_t<ByteView>> ||
                      std::is_lvalue_reference_v<ByteView>,
                  "temporary buffer cannot be used for non-owning object parsing");
  }

  constexpr explicit in_base(ByteView &view, MemoryResource &mr, Options &&...options)
      : mem_resource(mr), m_archive(make_in_archive(view, std::forward<Options>(options)...)) {}

  template <typename T>
  auto make_growable(std::span<T> &base) {
    return detail::growable_span<T, MemoryResource>{base, mem_resource};
  }

  template <typename T>
  T &make_growable(T &base) {
    return base;
  }

  constexpr static bool has_memory_resource = true;
};

template <::zpp::bits::concepts::byte_view ByteView, concepts::is_option... Options>
class in_base<ByteView, std::monostate, Options...> {
protected:
  using archive_type = decltype(make_in_archive(std::declval<ByteView &>(), std::declval<Options &&>()...));
  archive_type m_archive;

public:
  using default_size_type = traits::default_size_type_t<Options...>;

  constexpr explicit in_base(ByteView &&view, Options &&...options)
      : m_archive(make_in_archive(std::move(view), std::forward<Options>(options)...)) {}

  constexpr explicit in_base(ByteView &view, Options &&...options)
      : m_archive(make_in_archive(view, std::forward<Options>(options)...)) {}

  template <typename T>
  T &make_growable(T &base) {
    return base;
  }

  constexpr static bool has_memory_resource = false;
};

template <typename T, bool condition>
struct assert_pointer_if {
  static constexpr bool value = condition && std::is_pointer_v<T>;
  static_assert(value, "Assertion failed <see below for more information>");
};

template <::zpp::bits::concepts::byte_view ByteView, typename MemoryResource = std::monostate,
          concepts::is_option... Options>
class in : public in_base<ByteView, MemoryResource, Options...> {

  std::size_t m_end_position = 0;
  bool m_has_unknown_fields = false;

  using base_type = in_base<ByteView, MemoryResource, Options...>;
  using archive_type = typename base_type::archive_type;

public:
  constexpr explicit in(ByteView &&view, Options &&...options)
    requires(std::same_as<MemoryResource, std::monostate>)
      : base_type(std::move(view), std::forward<Options>(options)...) {}

  constexpr explicit in(ByteView &view, Options &&...options)
    requires(std::same_as<MemoryResource, std::monostate>)
      : base_type(view, std::forward<Options>(options)...) {}

  constexpr explicit in(ByteView &&view, MemoryResource &mr, Options &&...options)
    requires(!std::same_as<MemoryResource, std::monostate>)
      : base_type(std::move(view), mr, std::forward<Options>(options)...) {}

  constexpr explicit in(ByteView &view, MemoryResource &mr, Options &&...options)
    requires(!std::same_as<MemoryResource, std::monostate>)
      : base_type(view, mr, std::forward<Options>(options)...) {}

  ZPP_BITS_INLINE constexpr errc operator()(auto &item) {
    using type = std::remove_cvref_t<decltype(item)>;
    item = type{};
    return serialize_one(item);
  }

  constexpr std::size_t position() const { return this->m_archive.position(); }

  constexpr std::size_t &position() { return this->m_archive.position(); }

  constexpr auto remaining_data() { return this->m_archive.remaining_data(); }

  constexpr static auto kind() { return ::zpp::bits::kind::in; }

  constexpr bool has_unknown_fields() const { return m_has_unknown_fields; }

  errc deserialize_tag(::zpp::bits::vuint32_t &tag) { return this->m_archive(tag); }

  ZPP_BITS_INLINE constexpr errc deserialize_fields(auto &item, std::size_t end_position) {

    const std::size_t hint = 0;

    while (this->m_archive.position() < end_position) {
      ::zpp::bits::vuint32_t tag;
      if (auto result = this->m_archive(tag); failure(result)) [[unlikely]] {
        return result;
      }

      m_end_position = end_position;

      if (std::is_constant_evaluated()) {
        if (auto result = deserialize_field_by_num<0>(item, tag_number(tag), proto::tag_type(tag)); failure(result))
            [[unlikely]] {
          return result;
        }
      } else {
        if (auto result = deserialize_field_by_num(item, tag_number(tag), proto::tag_type(tag), hint);
            failure(result)) {
          [[unlikely]] return result;
        }
      }
    }

    assert(this->m_archive.position() == end_position);

    return {};
  }

  ZPP_BITS_INLINE constexpr errc deserialize_group(auto &item, uint32_t field_num) {

    const std::size_t hint = 0;

    while (this->m_archive.remaining_data().size()) {
      ::zpp::bits::vuint32_t tag;
      if (auto result = this->m_archive(tag); failure(result)) [[unlikely]] {
        return result;
      }

      if (proto::tag_type(tag) == wire_type::egroup && field_num == tag_number(tag)) {
        return {};
      }

      if (std::is_constant_evaluated()) {
        if (auto result = deserialize_field_by_num<0>(item, tag_number(tag), proto::tag_type(tag)); failure(result))
            [[unlikely]] {
          return result;
        }
      } else {
        if (auto result = deserialize_field_by_num(item, tag_number(tag), proto::tag_type(tag), hint); failure(result))
            [[unlikely]] {
          return result;
        }
      }
    }

    return std::errc::result_out_of_range;
  }

  template <typename Type, std::size_t... I>
  constexpr auto deserialize_funs(std::index_sequence<I...>) {
    using deserialize_fun_ptr = errc (in::*)(Type &, uint32_t, wire_type);
    return std::array<deserialize_fun_ptr, sizeof...(I)>{&in::deserialize_field_by_index<I>...};
  }

  template <typename Type>
  constexpr auto deserialize_funs() {
    constexpr std::size_t num_members = traits::number_of_members<Type>;
    return deserialize_funs<Type>(std::make_index_sequence<num_members>());
  }

  ZPP_BITS_INLINE errc skip_field(concepts::has_extension auto &item, uint32_t field_num, wire_type field_wire_type) {
    auto tag = make_tag(field_num, field_wire_type);
    auto start_pos = position() - ::zpp::bits::varint_size<zpp::bits::varint_encoding::normal>(tag.value);

    if (auto result = do_skip_field(field_num, field_wire_type); failure(result)) [[unlikely]] {
      return result;
    }

    const std::byte *data = std::bit_cast<const std::byte *>(this->m_archive.data().data());
    if constexpr (zpp::bits::concepts::associative_container<std::remove_cvref_t<decltype(item.extensions.fields)>>) {
      auto &value = item.extensions.fields[field_num];
      value.insert(value.end(), data + start_pos, data + position());
    } else {
      static_assert(concepts::span<std::remove_cvref_t<decltype(item.extensions.fields)>>);
      auto &fields = item.extensions.fields;

      auto old_size = fields.size();
      if (old_size > 0 && fields[old_size - 1].first == field_num) {
        auto &entry = fields[old_size - 1].second;
        if (entry.data() + entry.size() == data + start_pos) {
          entry = {entry.data(), data + position()};
          return {};
        }
      }

      auto itr =
          std::find_if(fields.begin(), fields.end(), [field_num](const auto &e) { return e.first == field_num; });
      if (itr == fields.end()) [[likely]] {
        decltype(auto) growable_fields = this->make_growable(fields);
        growable_fields.resize(old_size + 1);
        growable_fields[old_size] = {field_num, {data + start_pos, data + position()}};
      } else {
        decltype(auto) v = this->make_growable(itr->second);
        auto s = v.size();
        v.resize(v.size() + position() - start_pos);
        std::copy(data + start_pos, data + position(), v.data() + s);
      }
    }

    return {};
  }

  ZPP_BITS_INLINE errc skip_field(auto &, uint32_t field_num, wire_type field_wire_type) {
    return do_skip_field(field_num, field_wire_type);
  }

  ZPP_BITS_INLINE errc do_skip_field(uint32_t field_num, wire_type field_wire_type) {
    ::zpp::bits::vsize_t length = 0;
    m_has_unknown_fields = true;
    switch (field_wire_type) {
    case wire_type::varint:
      return this->m_archive(length);
    case wire_type::length_delimited:
      if (auto result = this->m_archive(length); failure(result)) [[unlikely]] {
        return result;
      }
      break;
    case wire_type::fixed_64:
      length = 8;
      break;
    case wire_type::sgroup:
      if (auto result = do_skip_group(field_num); failure(result)) [[unlikely]] {
        return result;
      }
      break;
    case wire_type::fixed_32:
      length = 4;
      break;
    default:
      return std::errc::result_out_of_range;
    }
    if (remaining_data().size() < length) [[unlikely]] {
      return std::errc::result_out_of_range;
    }
    position() += length;
    return {};
  }

  // ZPP_BITS_INLINE
  inline constexpr errc do_skip_group(uint32_t field_num) {
    while (this->m_archive.remaining_data().size()) {
      ::zpp::bits::vuint32_t tag;
      if (auto result = this->m_archive(tag); failure(result)) [[unlikely]] {
        return result;
      }
      const uint32_t next_field_num = tag_number(tag);
      const wire_type next_type = proto::tag_type(tag);

      if (next_type == wire_type::egroup && field_num == next_field_num) {
        return {};
      } else if (auto result = do_skip_field(next_field_num, next_type); failure(result)) [[unlikely]] {
        return result;
      }
    }

    return std::errc::result_out_of_range;
  }

  inline errc deserialize_field_by_num(auto &item, uint32_t field_num, wire_type field_wire_type, std::size_t hint) {
    using type = std::remove_cvref_t<decltype(item)>;
    static auto fun_ptrs = deserialize_funs<type>();
    auto index = traits::reverse_indices<type>::number_to_index(field_num, hint);
    if (index) {
      auto p = fun_ptrs[*index];
      if (auto result = (this->*p)(item, field_num, field_wire_type); failure(result)) [[unlikely]] {
        return result;
      }
      return {};
    } else [[unlikely]] {
      return skip_field(item, field_num, field_wire_type);
    }
  }

  template <std::size_t Index = 0>
  ZPP_BITS_INLINE constexpr errc deserialize_field_by_num(auto &item, uint32_t field_num, wire_type field_wire_type) {
    using type = std::remove_reference_t<decltype(item)>;
    if constexpr (Index >= traits::number_of_members<type>) {
      return skip_field(item, field_num, field_wire_type);
    } else if (!has_field_num(typename traits::field_meta_of<type, Index>::type{}, field_num)) {
      return deserialize_field_by_num<Index + 1>(item, field_num, field_wire_type);
    } else {
      return deserialize_field_by_index<Index>(item, field_num, field_wire_type);
    }
  }

  template <std::size_t Index>
  inline constexpr errc deserialize_field_by_index(auto &item, uint32_t field_num, wire_type field_wire_type) {
    using type = std::remove_reference_t<decltype(item)>;
    using Meta = typename traits::field_meta_of<type, Index>::type;
    if constexpr (requires { requires Meta::number == UINT32_MAX; }) {
      // this is extension, not a regular field
      return errc{};
    } else {
      return deserialize_field(Meta(), field_wire_type, field_num, Meta::access(item));
    }
  }

  template <typename T>
  ZPP_BITS_INLINE bool exceed_allocation_limit(T &, std::size_t size) {
    if constexpr (requires { typename T::value_type; } &&
                  archive_type::allocation_limit != std::numeric_limits<std::size_t>::max()) {
      constexpr auto limit = archive_type::allocation_limit / sizeof(typename T::value_type);
      return size > limit;
    }
    return false;
  }

  ZPP_BITS_INLINE errc resize(concepts::resizable auto &growable, std::size_t size) {
    if (exceed_allocation_limit(growable, size)) [[unlikely]] {
      return errc{std::errc::message_size};
    }

    growable.resize(size);
    return {};
  }

  ZPP_BITS_INLINE errc resize_or_reserve(concepts::resizable_or_reservable auto &growable, std::size_t size) {
    if (exceed_allocation_limit(growable, size)) [[unlikely]] {
      return errc{std::errc::message_size};
    }

    if constexpr (requires { growable.resize(1); }) {
      growable.resize(size);
    } else if constexpr (requires { growable.reserve(size); }) { // e.g. boost::flat_map
      growable.reserve(size);
    } else { // e.g. std::flat_map
      reserve(growable, size);
    }

    return {};
  }

  errc skip_tag(uint32_t tag) {
    ::zpp::bits::vuint32_t t;
    if (auto result = this->m_archive(t); failure(result)) [[unlikely]] {
      return result;
    }
    if (t != tag) [[unlikely]] {
      return std::errc::result_out_of_range;
    }
    return {};
  }

  template <typename Meta>
  ZPP_BITS_INLINE constexpr errc deserialize_field(Meta meta, wire_type field_type, uint32_t field_num, auto &&item) {
    using type = std::remove_reference_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    if constexpr (std::is_enum_v<type>) {
      ::zpp::bits::vint64_t value;
      if (auto result = this->m_archive(value); failure(result)) [[unlikely]] {
        return result;
      }
      item = static_cast<type>(value.value);
    } else if constexpr (std::is_same_v<type, boolean>) {
      return this->m_archive(item.value);
    } else if constexpr (concepts::optional<type>) {
      if constexpr (requires { item.emplace(); }) {
        return deserialize_field(meta, field_type, field_num, item.emplace());
      } else {
        item = typename type::value_type{};
        return deserialize_field(meta, field_type, field_num, *item);
      }
    } else if constexpr (::zpp::bits::concepts::owning_pointer<type>) {
      using element_type = std::remove_reference_t<decltype(*item)>;
      auto loaded = ::zpp::bits::access::make_unique<element_type>();
      if (auto result = deserialize_field(meta, field_type, field_num, *loaded); failure(result)) [[unlikely]] {
        return result;
      }
      item.reset(loaded.release());
    } else if constexpr (std::is_pointer_v<type>) {
      static_assert(assert_pointer_if<type, base_type::has_memory_resource>::value, ": memory resource is required");
      using element_type = std::remove_cvref_t<decltype(*item)>;
      void *buffer = this->mem_resource.allocate(sizeof(element_type), alignof(element_type));
      if (buffer == nullptr) [[unlikely]] {
        return errc{std::errc::not_enough_memory};
      }
      auto loaded = new (buffer) element_type;
      if (auto result = deserialize_field(meta, field_type, field_num, *loaded); failure(result)) [[unlikely]] {
        return result;
      }
      item = loaded;
    } else if constexpr (concepts::oneof_type<type>) {
      static_assert(std::is_same_v<std::remove_cvref_t<decltype(std::get<0>(type{}))>, std::monostate>);
      return deserialize_oneof<0, Meta>(field_type, field_num, std::forward<decltype(item)>(item));
    } else if constexpr (!std::is_same_v<type, serialize_type> && concepts::scalar<serialize_type> &&
                         !::zpp::bits::concepts::container<type>) {
      serialize_type value;
      if (auto result = deserialize_field(meta, field_type, field_num, value); failure(result)) [[unlikely]] {
        return result;
      }
      if constexpr (std::is_arithmetic_v<type>) {
        item = static_cast<type>(value);
      } else {
        item = std::move(value);
      }
    } else if constexpr (concepts::numeric_or_byte<type>) {
      return this->m_archive(item);
    } else if constexpr (!::zpp::bits::concepts::container<type>) {
      if constexpr (meta.encoding != encoding_rule::group) {
        return serialize_one<::zpp::bits::varint<uint32_t>>(item);
      } else {
        return deserialize_group(item, field_num);
      }
    } else if constexpr (meta.encoding == encoding_rule::group) {
      // repeated group
      if constexpr (requires { item.emplace_back(); }) {
        return deserialize_group(item.emplace_back(), field_num);
      } else {
        decltype(auto) growable = this->make_growable(item);
        auto old_size = item.size();
        growable.resize(old_size + 1);
        return deserialize_group(growable[old_size], field_num);
      }
    } else if constexpr (concepts::string_or_bytes<type>) {
      return deserialize_packed_repeated(meta, field_type, field_num, std::forward<type>(item));
    } else { // repeated non-group
      using value_type = typename type::value_type;
      if constexpr (concepts::numeric<value_type> && meta.encoding != encoding_rule::unpacked_repeated) {
        if (field_type != wire_type::length_delimited) {
          return deserialize_unpacked_repeated(meta, field_type, field_num, std::forward<type>(item));
        }
        return deserialize_packed_repeated(meta, field_type, field_num, std::forward<type>(item));
      } else {
        return deserialize_unpacked_repeated(meta, field_type, field_num, std::forward<type>(item));
      }
    }
    return errc{};
  }

  template <typename Meta>
  ZPP_BITS_INLINE constexpr errc deserialize_packed_repeated(Meta, wire_type, uint32_t, auto &&item) {
    using type = std::remove_reference_t<decltype(item)>;
    using value_type = typename type::value_type;

    decltype(auto) growable = this->make_growable(item);
    using element_type =
        std::conditional_t<std::same_as<typename Meta::type, void> || std::same_as<value_type, char> ||
                               std::same_as<value_type, std::byte> || std::same_as<typename Meta::type, type>,
                           value_type, typename Meta::type>;

    ::zpp::bits::vsize_t length;
    if (auto result = this->m_archive(length); failure(result)) [[unlikely]] {
      return result;
    }

    if constexpr (requires { growable.resize(1); }) {
      // packed repeated vector,
      std::size_t size;

      if (auto result = count_packed_elements<element_type>(length, size); failure(result)) [[unlikely]] {
        return result;
      }

      if (auto result = resize(growable, size); failure(result)) [[unlikely]] {
        return result;
      }

      using serialize_type = std::conditional_t<std::is_enum_v<value_type> && !std::same_as<value_type, std::byte>,
                                                ::zpp::bits::vint64_t, element_type>;

      if constexpr (!zpp::bits::concepts::varint<serialize_type>) {
        return this->m_archive(::zpp::bits::unsized(
            std::span<element_type>{std::bit_cast<element_type *>(growable.data()), growable.size()}));
      } else {
        return iterative_apply(
            [this](auto &value) {
              serialize_type underlying;
              if (auto result = this->m_archive(underlying); failure(result)) [[unlikely]] {
                return result;
              }
              value = static_cast<element_type>(underlying.value);
              return errc{};
            },
            growable);
      }
    } else if constexpr (std::is_same_v<type, std::string_view>) {
      // handling string_view
      auto data = this->m_archive.remaining_data();
      if (data.size() < length) {
        return std::errc::result_out_of_range;
      }
      item = std::string_view((const char *)data.data(), length);
      this->m_archive.position() += length;
    } else if constexpr ((std::is_same_v<value_type, char> ||
                          std::is_same_v<value_type, std::byte>)&&std::is_same_v<type, std::span<const value_type>>) {
      // handling bytes
      auto data = this->m_archive.remaining_data();
      if (data.size() < length) {
        return std::errc::result_out_of_range;
      }
      item = std::span<const value_type>((const value_type *)data.data(), length);
      this->m_archive.position() += length;
    } else if constexpr (requires { item.insert(value_type{}); }) {
      // packed repeated set
      auto fetch = [&]() ZPP_BITS_CONSTEXPR_INLINE_LAMBDA {
        element_type value;

        if constexpr (std::is_enum_v<element_type>) {
          zpp::bits::vint64_t underlying;
          if (auto result = this->m_archive(underlying); failure(result)) [[unlikely]] {
            return result;
          }
          value = static_cast<element_type>(underlying.value);
        } else {
          // varint
          if (auto result = this->m_archive(value); failure(result)) [[unlikely]] {
            return result;
          }
        }
        item.insert(value_type(value));
        return errc{};
      };

      auto end_position = length + this->m_archive.position();
      while (this->m_archive.position() < end_position) {
        if (auto result = fetch(); failure(result)) [[unlikely]] {
          return result;
        }
      }
    } else {
      static_assert(base_type::has_memory_resource, "memory resource is required");
    }
    return {};
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
    struct impl_type {
      C &item;
      base_value_type value;
      ZPP_BITS_INLINE constexpr impl_type(C &item, std::size_t) : item(item) {}

      ZPP_BITS_INLINE constexpr ~impl_type() {
        if constexpr (concepts::is_map_entry<typename Meta::type>) {
          std::move(value).insert_to(item);
        } else if constexpr (requires { item.insert(value); }) {
          item.insert(std::move(value));
        } else {
          static_assert(base_type::has_memory_resource, "memory resource is required");
        }
      }
    };

    template <concepts::resizable C>
      requires std::same_as<std::remove_const_t<typename C::value_type>, base_value_type>
    struct impl_type<C> {
      base_value_type &value;
      ZPP_BITS_INLINE constexpr impl_type(C &item, std::size_t i) : value(item[i]) {}
    };

    template <concepts::resizable C>
      requires(!std::same_as<std::remove_const_t<typename C::value_type>, base_value_type>)
    struct impl_type<C> {
      std::remove_const_t<typename C::value_type> &target;
      base_value_type value;

      ZPP_BITS_INLINE constexpr impl_type(C &item, std::size_t i) : target(item[i]) {}
      ZPP_BITS_INLINE constexpr ~impl_type() {
        if constexpr (requires { std::move(value).to(target); }) {
          std::move(value).to(target);
        } else {
          target = std::move(value);
        }
      }
    };

    impl_type<Container> impl;

    ZPP_BITS_INLINE constexpr unpacked_element_inserter(Container &item, std::size_t i = 0) : impl(item, i) {}

    ZPP_BITS_INLINE constexpr errc deserialize(in &serializer, wire_type field_type, uint32_t field_num) {
      if constexpr (concepts::scalar<base_value_type>) {
        return serializer.deserialize_field(Meta{}, field_type, field_num, impl.value);
      } else {
        return serializer.serialize_one<::zpp::bits::varint<uint32_t>>(impl.value);
      }
    }
  };

  template <typename Meta>
  ZPP_BITS_INLINE constexpr errc deserialize_unpacked_repeated(Meta, wire_type field_type, uint32_t field_num,
                                                               auto &&item) {
    using type = std::remove_reference_t<decltype(item)>;

    decltype(auto) growable = this->make_growable(item);

    if constexpr (concepts::resizable_or_reservable<decltype(growable)>) {
      std::size_t count = 0;
      if (auto result = count_unpacked_elements(field_num, field_type, count); failure(result)) [[unlikely]] {
        return result;
      }
      auto old_size = item.size();
      const std::size_t new_size = item.size() + count;

      if (auto result = resize_or_reserve(growable, new_size); failure(result)) [[unlikely]] {
        return result;
      }

      for (auto i = old_size; i < new_size; ++i) {
        unpacked_element_inserter<Meta, std::remove_cvref_t<decltype(growable)>> inserter(growable, i);
        if (auto result = inserter.deserialize(*this, field_type, field_num); failure(result)) [[unlikely]] {
          return result;
        }

        if (i < new_size - 1) {
          if (auto result = skip_tag((field_num << 3 | (uint32_t)field_type)); failure(result)) [[unlikely]] {
            return result;
          }
        }
      }
    } else {
      unpacked_element_inserter<Meta, type> inserter{item};
      return inserter.deserialize(*this, field_type, field_num);
    }
    return {};
  }

  template <typename T>
  ZPP_BITS_INLINE constexpr errc count_packed_elements(uint32_t length, std::size_t &count) {
    auto data = std::span(this->m_archive.data().data() + this->m_archive.position(), length);
    if constexpr (std::is_fundamental_v<T> || std::same_as<T, std::byte> || std::same_as<T, boolean>) {
      count = length / sizeof(T);
    } else if constexpr (std::is_enum_v<T> || zpp::bits::concepts::varint<T>) {
      count = std::count_if(data.begin(), data.end(), [](auto c) { return (static_cast<char>(c) & 0x80) == 0; });
    } else {
      static_assert(requires {
        typename T::value_type;
        sizeof(typename T::value_type) == 1;
      });
      auto element_counting_archive = ::zpp::bits::in{data, ::zpp::bits::size_varint{}, ::zpp::bits::endian::little{}};
      while (element_counting_archive.position() < length) {
        ::zpp::bits::vsize_t len;
        if (auto result = element_counting_archive(len); failure(result)) [[unlikely]] {
          return result;
        }
        if (element_counting_archive.remaining_data().size() < len) [[unlikely]] {
          return std::errc::result_out_of_range;
        }
        element_counting_archive.position() += len;
        ++count;
      }
    }
    return {};
  }

  ZPP_BITS_INLINE constexpr errc count_unpacked_elements(uint32_t number, wire_type field_type, std::size_t &count) {
    auto remaining = std::span{this->m_archive.data().data() + this->m_archive.position(),
                               m_end_position - this->m_archive.position()};
    auto element_counting_archive =
        ::zpp::bits::in{remaining, ::zpp::bits::size_varint{}, ::zpp::bits::endian::little{}};
    const ::zpp::bits::vuint32_t input_tag = make_tag(number, field_type);
    ::zpp::bits::vuint32_t tag;

    do {
      ::zpp::bits::vsize_t length = 0;
      switch (field_type) {
      case wire_type::varint:
        if (auto result = element_counting_archive(length); failure(result)) [[unlikely]] {
          return result;
        }
        length = 0;
        break;
      case wire_type::length_delimited:
        if (auto result = element_counting_archive(length); failure(result)) [[unlikely]] {
          return result;
        }
        break;
      case wire_type::fixed_64:
        length = 8;
        break;
      case wire_type::fixed_32:
        length = 4;
        break;
      default:
        return std::errc::result_out_of_range;
      };

      if (element_counting_archive.remaining_data().size() < length) [[unlikely]] {
        return std::errc::result_out_of_range;
      }
      element_counting_archive.position() += length;

      ++count;

      if (element_counting_archive.remaining_data().size() == 0) {
        return {};
      }

      if (auto result = element_counting_archive(tag); failure(result)) [[unlikely]] {
        return result;
      }
    } while (tag == input_tag);
    return {};
  }

  template <std::size_t Index, ::zpp::bits::concepts::tuple Meta>
  ZPP_BITS_INLINE constexpr auto deserialize_oneof(wire_type field_type, uint32_t field_num, auto &&item) {
    if constexpr (Index < std::tuple_size_v<Meta>) {
      using meta = typename std::tuple_element<Index, Meta>::type;
      if (meta::number == field_num) {
        if constexpr (requires { item.template emplace<Index + 1>(); }) {
          return deserialize_field(meta{}, field_type, field_num, item.template emplace<Index + 1>());
        } else {
          item = std::variant_alternative_t<Index + 1, std::decay_t<decltype(item)>>{};
          return deserialize_field(meta{}, field_type, field_num, std::get<Index + 1>(item));
        }
      } else {
        return deserialize_oneof<Index + 1, Meta>(field_type, field_num, std::forward<decltype(item)>(item));
      }
    }
    return errc{};
  }

  template <std::size_t Index, concepts::is_oneof_field_meta Meta>
  ZPP_BITS_INLINE constexpr auto deserialize_oneof(wire_type field_type, uint32_t field_num, auto &&item) {
    return deserialize_oneof<Index, typename Meta::alternatives_meta>(field_type, field_num,
                                                                      std::forward<decltype(item)>(item));
  }

  template <typename SizeType = typename base_type::default_size_type>
  ZPP_BITS_INLINE constexpr errc serialize_one(auto &item) {
    if constexpr (!std::is_void_v<SizeType>) {
      SizeType size{};
      if (auto result = this->m_archive(size); failure(result)) [[unlikely]] {
        return result;
      }
      if (size > this->m_archive.remaining_data().size()) [[unlikely]] {
        return errc{std::errc::message_size};
      }

      return deserialize_fields(item, this->m_archive.position() + size);
    } else {
      return deserialize_fields(item, this->m_archive.data().size());
    }
  }
};

template <typename Type, std::size_t Size, concepts::is_option... Options>
in(Type (&)[Size], Options &&...) -> in<std::span<Type, Size>, std::monostate, Options...>;

template <typename Type, typename SizeType, concepts::is_option... Options>
in(::zpp::bits::sized_item<Type, SizeType> &, Options &&...) -> in<Type, std::monostate, Options...>;

template <typename Type, typename SizeType, concepts::is_option... Options>
in(const ::zpp::bits::sized_item<Type, SizeType> &, Options &&...) -> in<const Type, std::monostate, Options...>;

template <typename Type, typename SizeType, concepts::is_option... Options>
in(::zpp::bits::sized_item<Type, SizeType> &&, Options &&...) -> in<Type, std::monostate, Options...>;

template <typename Type, std::size_t Size, concepts::memory_resource MemoryResource, concepts::is_option... Options>
in(Type (&)[Size], MemoryResource &, Options &&...) -> in<std::span<Type, Size>, MemoryResource, Options...>;

template <typename Type, typename SizeType, concepts::memory_resource MemoryResource, concepts::is_option... Options>
in(::zpp::bits::sized_item<Type, SizeType> &, MemoryResource &, Options &&...) -> in<Type, MemoryResource, Options...>;

template <typename Type, typename SizeType, concepts::memory_resource MemoryResource, concepts::is_option... Options>
in(const ::zpp::bits::sized_item<Type, SizeType> &, MemoryResource &, Options &&...)
    -> in<const Type, MemoryResource, Options...>;

template <typename Type, typename SizeType, concepts::memory_resource MemoryResource, concepts::is_option... Options>
in(::zpp::bits::sized_item<Type, SizeType> &&, MemoryResource &, Options &&...) -> in<Type, MemoryResource, Options...>;

constexpr auto input(auto &&view, concepts::is_option auto &&...option) {
  return in(std::forward<decltype(view)>(view), std::forward<decltype(option)>(option)...);
}

constexpr auto output(auto &&view, concepts::is_option auto &&...option) {
  return out(std::forward<decltype(view)>(view), std::forward<decltype(option)>(option)...);
}

constexpr auto in_out(auto &&view, concepts::is_option auto &&...option) {
  return std::tuple{
      in<std::remove_reference_t<typename decltype(in{view})::view_type>, std::monostate, decltype(option) &...>(
          view, option...),
      out(std::forward<decltype(view)>(view), std::forward<decltype(option)>(option)...)};
}

template <typename ByteType = std::byte>
constexpr auto data_in_out(concepts::is_option auto &&...option) {
  struct data_in_out {
    data_in_out(decltype(option) &&...option)
        : input(data, option...), output(data, std::forward<decltype(option)>(option)...) {}

    std::vector<ByteType> data;
    in<decltype(data), std::monostate, decltype(option) &...> input;
    out<decltype(data), decltype(option)...> output;
  };
  return data_in_out{std::forward<decltype(option)>(option)...};
}

template <typename ByteType = std::byte>
constexpr auto data_in(concepts::is_option auto &&...option) {
  struct data_in {
    data_in(decltype(option) &&...option) : input(data, std::forward<decltype(option)>(option)...) {}

    std::vector<ByteType> data;
    in<decltype(data), decltype(option)...> input;
  };
  return data_in{std::forward<decltype(option)>(option)...};
}

template <typename ByteType = std::byte>
constexpr auto data_out(concepts::is_option auto &&...option) {
  struct data_out {
    data_out(decltype(option) &&...option) : output(data, std::forward<decltype(option)>(option)...) {}

    std::vector<ByteType> data;
    out<decltype(data), decltype(option)...> output;
  };
  return data_out{std::forward<decltype(option)>(option)...};
}

template <auto Object, std::size_t MaxSize = 0x1000>
constexpr auto to_bytes() {
  constexpr auto size = [] {
    std::array<std::byte, MaxSize> data;
    out out{data};
    out(Object).or_throw();
    return out.position();
  }();

  if constexpr (!size) {
    return ::zpp::bits::string_literal<std::byte, 0>{};
  } else {
    std::array<std::byte, size> data;
    out{data}(Object).or_throw();
    return data;
  }
}

template <auto Data, typename Type>
constexpr auto from_bytes() {
  Type object;
  in{Data}(object).or_throw();
  return object;
}

template <typename FieldType, typename MetaType>
struct deserialize_wrapper_type {
  FieldType value;
  using pb_meta = std::tuple<MetaType>;
  using serialize = ::zpp::bits::members<1>;
};

template <typename ExtensionMeta>
inline auto extension_meta_base<ExtensionMeta>::read(const concepts::pb_extension auto &extensions, auto &&mr) {
  check(extensions);
  decltype(extensions.fields.begin()) itr;

  if constexpr (requires { extensions.fields.find(ExtensionMeta::number); }) {
    itr = extensions.fields.find(ExtensionMeta::number);
  } else {
    itr = std::find_if(extensions.fields.begin(), extensions.fields.end(),
                       [](const auto &item) { return item.first == ExtensionMeta::number; });
  }

  using value_type = typename ExtensionMeta::get_result_type;
  using return_type = expected<value_type, std::error_code>;

  deserialize_wrapper_type<value_type, ExtensionMeta> wrapper;
  if (itr != extensions.fields.end()) {
    errc ec;
    if constexpr (std::same_as<std::remove_cvref_t<decltype(mr)>, std::monostate>) {
      ec = proto::in(itr->second)(wrapper);
    } else {
      ec = proto::in(itr->second, std::forward<decltype(mr)>(mr))(wrapper);
    }

    if (failure(ec)) [[unlikely]] {
      return return_type{unexpected(std::make_error_code(ec))};
    }
    return return_type{wrapper.value};
  }

  if constexpr (ExtensionMeta::has_default_value) {
    return return_type(value_type(ExtensionMeta::default_value));
  } else if constexpr (concepts::scalar<value_type>) {
    return return_type{value_type{}};
  } else {
    return return_type{unexpected(std::make_error_code(std::errc::no_message))};
  }
}

template <typename ExtensionMeta>
inline std::error_code extension_meta_base<ExtensionMeta>::write(concepts::pb_extension auto &extensions,
                                                                 auto &&value) {
  check(extensions);

  auto [data, out] = data_out();
  if (auto ec = out.serialize_field(ExtensionMeta{}, std::forward<typename ExtensionMeta::set_value_type>(value));
      failure(ec)) [[unlikely]] {
    return std::make_error_code(ec);
  }
  if (out.position()) {
    data.resize(out.position());
    extensions.fields[ExtensionMeta::number] = std::move(data);
  }
  return {};
}

template <typename ExtensionMeta>
inline std::error_code extension_meta_base<ExtensionMeta>::write(concepts::pb_extension auto &extensions, auto &&value,
                                                                 concepts::memory_resource auto &mr) {
  check(extensions);

  std::span<std::byte> buf;
  using memory_resource_type = std::remove_cvref_t<decltype(mr)>;
  detail::growable_span<std::byte, memory_resource_type> data{buf, mr};
  out out(data);
  if (auto ec = out.serialize_field(ExtensionMeta{}, std::forward<typename ExtensionMeta::set_value_type>(value));
      failure(ec)) [[unlikely]] {
    return std::make_error_code(ec);
  }
  if (out.position()) {
    auto old_size = extensions.fields.size();
    detail::growable_span<typename decltype(extensions.fields)::value_type, memory_resource_type> growable_fields{
        extensions.fields, mr};
    growable_fields.resize(old_size + 1);
    extensions.fields[old_size] = {ExtensionMeta::number, {data.data(), out.position()}};
  }
  return {};
}

template <typename T, typename Buffer>
[[nodiscard]] inline std::error_code write_proto(T &&msg, Buffer &buffer) {
  return std::make_error_code(out(buffer)(std::forward<T>(msg)));
}

template <typename T, ::zpp::bits::concepts::byte_view Buffer>
[[nodiscard]] inline std::error_code read_proto(T &msg, Buffer &&buffer) {
  return std::make_error_code(in(std::forward<Buffer>(buffer))(msg));
}

template <typename T, ::zpp::bits::concepts::byte_view Buffer, concepts::memory_resource MemoryResource>
[[nodiscard]] inline std::error_code read_proto(T &msg, Buffer &&buffer, MemoryResource &mr) {
  return std::make_error_code(in(std::forward<Buffer>(buffer), mr)(msg));
}

} // namespace proto
} // namespace hpp

#endif
