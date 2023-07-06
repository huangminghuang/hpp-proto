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
#include <concepts>
#include <hpp_proto/field_types.h>
#include <map>
#include <zpp_bits.h>

namespace hpp {
namespace proto {
enum class encoding_rule { defaulted = 0, explicit_presence = 1, unpacked_repeated = 2, group = 3 };

template <uint32_t Number, encoding_rule Encoding = encoding_rule::defaulted, typename Type = void,
          auto DefaultValue = std::monostate{}>
struct field_meta {
  constexpr static uint32_t number = Number;
  constexpr static encoding_rule encoding = Encoding;
  using type = Type;

  template <typename T>
  static constexpr bool omit_value(const T &v) {
    return Encoding != encoding_rule::explicit_presence && is_default_value<T, DefaultValue>(v);
  }
};

using ::zpp::bits::errc;
using ::zpp::bits::failure;

ZPP_BITS_INLINE constexpr decltype(auto) do_visit_members(auto &&object, auto &&visitor) {
  using namespace zpp::bits;
  return visit_members(object, visitor);
}

template <typename Type>
constexpr bool disallow_inline_visit_members_lambda() {
  if constexpr (::zpp::bits::number_of_members<Type>() > ::zpp::bits::access::max_visit_members)
    return true;
  else if constexpr (requires { Type::allow_inline_visit_members_lambda; })
    return !Type::allow_inline_visit_members_lambda;
  else
    return ::zpp::bits::access::self_referencing<Type>();
}

namespace concepts {

template <typename Type>
concept has_local_meta = ::zpp::bits::concepts::tuple<typename Type::pb_meta>;

template <typename Type>
concept has_explicit_meta = ::zpp::bits::concepts::tuple<decltype(pb_meta(std::declval<Type>()))>;

template <typename Type>
concept has_meta = has_local_meta<Type> || has_explicit_meta<Type>;

template <typename T>
concept numeric = std::is_fundamental_v<T> || ::zpp::bits::concepts::varint<T> || std::is_enum_v<T>;

template <typename T>
concept numeric_or_byte = numeric<T> || std::same_as<std::byte, T>;

template <typename Type>
concept oneof_type = ::zpp::bits::concepts::variant<Type>;

template <typename Type>
concept string_or_bytes =
    ::zpp::bits::concepts::container<Type> &&
    (std::same_as<char, typename Type::value_type> || std::same_as<std::byte, typename Type::value_type>);

template <typename Type>
concept scalar = numeric_or_byte<Type> || string_or_bytes<Type> || std::same_as<Type, boolean>;

template <typename Type>
concept pb_extension = requires(Type value) {
  typename Type::pb_extension;
  { value.fields[0] } -> std::same_as<std::vector<std::byte> &>;
  { value.fields.count(0) } -> std::same_as<std::size_t>;
};

} // namespace concepts

template <typename T>
struct extension_meta_base {

  static constexpr void check(const concepts::pb_extension auto &extensions) {
    static_assert(std::same_as<typename std::remove_cvref_t<decltype(extensions)>::pb_extension, typename T::extendee>);
  }

  static auto read(const concepts::pb_extension auto &extensions);

  static void write(concepts::pb_extension auto &extensions, auto &&value);
  static bool element_of(const concepts::pb_extension auto &extensions) {
    check(extensions);
    return extensions.fields.count(T::number) > 0;
  }
};

template <typename Extendee, uint32_t Number, encoding_rule Encoding, typename Type, typename ValueType,
          auto DefaultValue = std::monostate{}>
struct extension_meta : field_meta<Number, Encoding, Type>,
                        extension_meta_base<extension_meta<Extendee, Number, Encoding, Type, ValueType, DefaultValue>> {

  constexpr static auto default_value = unwrap(DefaultValue);

  static constexpr bool is_repeated = false;
  using extendee = Extendee;

  using get_result_type = std::conditional_t<std::is_same_v<decltype(DefaultValue), std::monostate>,
                                             std::optional<ValueType>, optional<ValueType, DefaultValue>>;
  using set_value_type = ValueType;
};

template <typename Extendee, uint32_t Number, encoding_rule Encoding, typename Type, typename ValueType>
struct repeated_extension_meta
    : field_meta<Number, Encoding, Type>,
      extension_meta_base<repeated_extension_meta<Extendee, Number, Encoding, Type, ValueType>> {

  static constexpr bool is_repeated = true;
  using extendee = Extendee;
  using element_type = std::conditional_t<std::is_same_v<ValueType, bool>, unsigned char, ValueType>;
  using get_result_type = std::vector<element_type>;
  using set_value_type = std::vector<element_type>;
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
  return make_tag(meta.number, tag_type<Type>());
}

constexpr auto tag_type(auto tag) { return wire_type(tag.value & 0x7); }

constexpr auto tag_number(auto tag) { return (unsigned int)(tag >> 3); }

template <typename Meta>
constexpr bool has_field_num(Meta meta, uint32_t num) {
  if constexpr (requires { meta.number; }) {
    return meta.number == num;
  } else if constexpr (requires { std::tuple_size_v<Meta>; }) {
    return std::apply([num](auto... elem) { return (has_field_num(elem, num) || ...); }, meta);
  } else {
    return false;
  }
}

template <typename Type>
constexpr void set_as_default(Type &value) {
  using type = std::remove_cvref_t<Type>;
  if constexpr (concepts::scalar<type>)
    value = type{};
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
struct map_entry {

  struct mutable_type {
    using serialize = ::zpp::bits::members<2>;
    typename serialize_type<KeyType>::type key;
    typename serialize_type<MappedType>::type value;
    constexpr static bool allow_inline_visit_members_lambda = true;
    using pb_meta =
        std::tuple<field_meta<1, encoding_rule::explicit_presence>, field_meta<2, encoding_rule::explicit_presence>>;

    template <typename Target, typename Source>
    static auto move_or_copy(Source &&src) {
      if constexpr (requires(Target target) { target = std::move(src); })
        return std::move(src);
      else if constexpr (std::is_enum_v<Target> && std::is_same_v<std::remove_cvref_t<Source>, ::zpp::bits::vint64_t>)
        return static_cast<Target>(src.value);
      else
        return static_cast<Target>(src);
    }

    template <typename Container>
    void insert_to(Container &container) {
      container.insert_or_assign(move_or_copy<typename Container::key_type>(key),
                                 move_or_copy<typename Container::mapped_type>(value));
    }
  };

  struct read_only_type {
    typename serialize_type<KeyType>::read_type key;
    typename serialize_type<MappedType>::read_type value;
    using serialize = ::zpp::bits::members<2>;
    constexpr static bool allow_inline_visit_members_lambda = true;

    read_only_type(auto &&k, auto &&v)
        : key((typename serialize_type<KeyType>::convertible_type)k),
          value((typename serialize_type<MappedType>::convertible_type)v) {}

    using pb_meta =
        std::tuple<field_meta<1, encoding_rule::explicit_presence>, field_meta<2, encoding_rule::explicit_presence>>;
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
using get_map_entry =
    std::conditional_t<std::is_same_v<typename Meta::type, void>,
                       map_entry<typename Type::key_type, typename Type::mapped_type>, typename Meta::type>;

template <typename T, std::size_t M, std::size_t N>
constexpr std::array<T, M + N> operator<<(std::array<T, M> lhs, std::array<T, N> rhs) {
  std::array<T, M + N> result;
  std::copy(lhs.begin(), lhs.end(), result.begin());
  std::copy(rhs.begin(), rhs.end(), result.begin() + M);
  return result;
}

template <typename Type>
struct reverse_indeces {
  static std::optional<std::size_t> number_to_index(uint32_t number, std::size_t) {
    if (number <= ::zpp::bits::access::number_of_members<Type>())
      return number - 1;
    else
      return {};
  }
};

template <concepts::has_meta Type>
struct reverse_indeces<Type> {

  template <typename T>
    requires requires { T::number; }
  constexpr static auto get_numbers(T meta) {
    return std::array{meta.number};
  }

  template <typename... T>
  constexpr static auto get_numbers(std::tuple<T...> metas) {
    return std::apply([](auto... elem) { return (... << get_numbers(elem)); }, metas);
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

  template <std::size_t I, typename T>
    requires requires { T::number; }
  constexpr static auto index(T meta) {
    return std::array{I};
  }

  template <std::size_t I, typename... T>
  constexpr static auto index(std::tuple<T...>) {
    std::array<std::size_t, sizeof...(T)> result;
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
    typename traits::meta_of<Type>::type metas;
    static auto numbers = get_numbers(metas);
    static auto indices = get_indices(metas);
    static auto unpacked = is_unpacked_repeated(metas);

    for (int i = 0; i < numbers.size(); ++i) {
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

template <::zpp::bits::concepts::tuple Meta, typename Type>
struct get_serialize_type<Meta, Type> {
  using type = Type;
};

template <typename Meta, typename Type>
  requires requires { typename Meta::type; }
struct get_serialize_type<Meta, Type> {
  using type = std::conditional_t<std::is_same_v<typename Meta::type, void>, Type, typename Meta::type>;
};

} // namespace traits

struct extensions {
  std::map<uint32_t, std::vector<std::byte>> fields;

  template <typename ExtensionMeta>
  errc set(ExtensionMeta meta, auto &&value);

  template <typename ExtensionMeta>
  errc get(ExtensionMeta meta, auto &);

  template <typename ExtensionMeta>
  bool has(ExtensionMeta meta) const {
    return fields.contains(meta.number);
  }

  template <typename ExtensionMeta>
  void clear(ExtensionMeta meta) {
    fields.erase(meta.number);
  }
};

namespace concepts {
template <typename Type>
concept has_extension = requires(Type value) {
  value.extensions;
  typename decltype(Type::extensions)::pb_extension;
};
} // namespace concepts

template <::zpp::bits::concepts::byte_view ByteView, typename... Options>
constexpr auto make_out_archive(ByteView &&view, Options &&...options) {
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
ZPP_BITS_INLINE constexpr errc serialize_sized(auto & archive, auto&& serialize_unsized ) {
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

    if constexpr (disallow_inline_visit_members_lambda<type>()) {
      return do_visit_members(std::forward<decltype(item)>(item), [&](auto &&...items) constexpr {
        return serialize_many<type>(std::make_index_sequence<sizeof...(items)>{},
                                    std::forward<decltype(items)>(items)...);
      });
    } else {
      return do_visit_members(item, [&](auto &&...items) ZPP_BITS_CONSTEXPR_INLINE_LAMBDA {
        return serialize_many<type>(std::make_index_sequence<sizeof...(items)>{},
                                    std::forward<decltype(items)>(items)...);
      });
    }
  }

  template <typename AggregateType, std::size_t FirstIndex, std::size_t... Indices>
  ZPP_BITS_INLINE constexpr errc serialize_many(std::index_sequence<FirstIndex, Indices...>, auto &&first_item,
                                                auto &&...items) {
    if (auto result = serialize_field(typename traits::field_meta_of<AggregateType, FirstIndex>::type{},
                                      std::forward<decltype(first_item)>(first_item));
        failure(result)) [[unlikely]] {
      return result;
    }

    return serialize_many<AggregateType>(std::index_sequence<Indices...>{}, std::forward<decltype(items)>(items)...);
  }

  template <typename AggregateType>
  ZPP_BITS_INLINE constexpr errc serialize_many(std::index_sequence<>) {
    return {};
  }

  template <typename Meta>
  ZPP_BITS_INLINE constexpr errc serialize_field(Meta meta, auto &&item) {
    using type = std::remove_cvref_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    if constexpr (::zpp::bits::concepts::empty<type>)
      return {};
    else if constexpr (concepts::oneof_type<type>) {
      if (std::holds_alternative<std::monostate>(item))
        return {};
      return serialize_oneof<0, Meta>(std::forward<decltype(item)>(item));
    } else {

      if (meta.omit_value(item))
        return {};

      if constexpr (std::is_same_v<type, boolean>) {
        constexpr auto tag = make_tag<bool>(meta);
        return m_archive(tag, item.value);
      } else if constexpr (concepts::pb_extension<type>) {
        for (auto &&f : item.fields) {
          if (auto result = m_archive(::zpp::bits::bytes(f.second)); failure(result)) [[unlikely]] {
            return result;
          }
        }
        return {};
      } else if constexpr (::zpp::bits::concepts::optional<type>) {
        if (item.has_value()) {
          return serialize_field(meta, *item);
        }
        return {};
      } else if constexpr (::zpp::bits::concepts::owning_pointer<type>) {
        if (item) {
          return serialize_field(meta, *item);
        }
        return {};

      } else if constexpr (!std::is_same_v<type, serialize_type> && concepts::scalar<serialize_type> &&
                           !::zpp::bits::concepts::container<type>) {
        return serialize_field(meta, serialize_type(item));
      } else if constexpr (std::is_enum_v<type> && !std::same_as<type, std::byte>) {
        constexpr auto tag = make_tag<type>(meta);
        if (auto result =
                m_archive(tag, ::zpp::bits::vint64_t(std::underlying_type_t<type>(std::forward<decltype(item)>(item))));
            failure(result)) [[unlikely]] {
          return result;
        }
        return {};
      } else if constexpr (concepts::numeric_or_byte<type>) {
        constexpr auto tag = make_tag<type>(meta);
        return m_archive(tag, item);
      } else if constexpr (!::zpp::bits::concepts::container<type>) {
        if constexpr (meta.encoding != encoding_rule::group) {
          constexpr auto tag = make_tag<type>(meta);
          if (auto result = m_archive(tag); failure(result)) [[unlikely]] {
            return result;
          }
          return serialize_sized(std::forward<decltype(item)>(item));
        } else {
          if (auto result = m_archive(
                  ::zpp::bits::varint{(meta.number << 3) | std::underlying_type_t<wire_type>(wire_type::sgroup)});
              failure(result)) [[unlikely]] {
            return result;
          }

          if (auto result = serialize_unsized(std::forward<decltype(item)>(item)); failure(result)) [[unlikely]] {
            return result;
          }

          return m_archive(
              ::zpp::bits::varint{(meta.number << 3) | std::underlying_type_t<wire_type>(wire_type::egroup)});
        }
      } else if constexpr (::zpp::bits::concepts::associative_container<type> &&
                           requires { typename type::mapped_type; }) {
        constexpr auto tag = make_tag<type>(meta);

        using value_type = typename traits::get_map_entry<Meta, type>::read_only_type;

        for (auto &&[key, value] : item) {
          if (auto result = m_archive(tag); failure(result)) [[unlikely]] {
            return result;
          }
          if (auto result = serialize_sized(value_type(key, value)); failure(result)) [[unlikely]] {
            return result;
          }
        }
        return {};
      } else {
        using value_type = typename type::value_type;
        using element_type =
            std::conditional_t<std::is_same_v<typename Meta::type, void> || std::is_same_v<value_type, char> ||
                                   std::is_same_v<value_type, std::byte>,
                               value_type, typename Meta::type>;

        if constexpr (Meta::encoding == encoding_rule::group) {
          for (auto &element : item) {
            if (auto result = serialize_field(field_meta<meta.number, encoding_rule::group>{}, element);
                failure(result)) [[unlikely]] {
              return result;
            }
          }
          return {};
        } else if constexpr ((Meta::encoding == encoding_rule::unpacked_repeated ||
                              !concepts::numeric_or_byte<element_type>)&&!(std::is_same_v<element_type, char> ||
                                                                           std::is_same_v<element_type, std::byte>)) {
          for (auto &element : item) {
            if (auto result = serialize_field(meta, element); failure(result)) [[unlikely]] {
              return result;
            }
          }
          return {};
        } else if constexpr (requires {
                               requires std::is_fundamental_v<element_type> ||
                                            std::same_as<typename type::value_type, std::byte>;
                             }) {
          constexpr auto tag = make_tag<type>(meta);
          auto size = item.size();
          if (!size) [[unlikely]] {
            return {};
          }
          if constexpr (std::is_same_v<value_type, boolean>) {
            if (auto result = m_archive(
                    tag, ::zpp::bits::varint{size},
                    ::zpp::bits::unsized(std::span<const bool>{reinterpret_cast<const bool *>(item.data()), size}));
                failure(result)) [[unlikely]] {
              return result;
            }
          } else {
            if (auto result = m_archive(tag, ::zpp::bits::varint{size * sizeof(typename type::value_type)},
                                        ::zpp::bits::unsized(std::forward<decltype(item)>(item)));
                failure(result)) [[unlikely]] {
              return result;
            }
          }
          return {};
        } else {
          if constexpr (requires { requires ::zpp::bits::concepts::varint<element_type>; }) {
            constexpr auto tag = make_tag<type>(meta);

            std::size_t size = {};
            for (auto &element : item) {
              size += ::zpp::bits::varint_size<element_type::encoding>(element_type{element}.value);
            }
            if (!size) [[unlikely]] {
              return {};
            }
            if (auto result = m_archive(tag, ::zpp::bits::varint{size}); failure(result)) [[unlikely]] {
              return result;
            }

            for (auto &element : item) {
              if (auto result = m_archive(element_type{element}); failure(result)) [[unlikely]] {
                return result;
              }
            }
            return {};
          } else if constexpr (requires { requires std::is_enum_v<typename type::value_type>; }) {
            constexpr auto tag = make_tag<type>(meta);
            using underlying_type = std::underlying_type_t<typename type::value_type>;
            std::size_t size = {};
            for (auto &element : item) {
              size += ::zpp::bits::varint_size(int64_t(element));
            }
            if (!size) [[unlikely]] {
              return {};
            }
            if (auto result = m_archive(tag, ::zpp::bits::varint{size}); failure(result)) [[unlikely]] {
              return result;
            }
            for (auto &element : item) {
              if (auto result = m_archive(::zpp::bits::vint64_t(underlying_type(element))); failure(result))
                  [[unlikely]] {
                return result;
              }
            }
            return {};
          } else {
            constexpr auto tag = make_tag<type>(meta);
            for (auto &element : item) {
              if (auto result = m_archive(tag); failure(result)) [[unlikely]] {
                return result;
              }
              if (auto result = serialize_sized(element); failure(result)) [[unlikely]] {
                return result;
              }
            }
            return {};
          }
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

  template <typename SizeType = ::zpp::bits::vsize_t>
  ZPP_BITS_INLINE constexpr errc serialize_sized(auto &&item) {
    using type = std::remove_cvref_t<decltype(item)>;

    return ::hpp::proto::serialize_sized<SizeType>(m_archive,
                                                   [&item, this]() ZPP_BITS_CONSTEXPR_INLINE_LAMBDA {
                                                     return serialize_unsized(item);
                                                   });
  }

  template <typename SizeType = default_size_type>
  constexpr errc ZPP_BITS_INLINE serialize_one(auto &&item) {
    if constexpr (!std::is_void_v<SizeType>) {
      return serialize_sized<SizeType>(std::forward<decltype(item)>(item));
    } else {
      return serialize_unsized(std::forward<decltype(item)>(item));
    }
  }
};

template <::zpp::bits::concepts::byte_view ByteView, typename... Options>
constexpr auto make_in_archive(ByteView &&view, Options &&...options) {
  if constexpr (std::same_as<std::decay_t<ByteView>, std::string_view>)
    return ::zpp::bits::in{std::span{view.data(), view.size()}, ::zpp::bits::size_varint{},
                           ::zpp::bits::endian::little{},
                           ::zpp::bits::alloc_limit<::zpp::bits::traits::alloc_limit<Options...>()>{}};
  else
    return ::zpp::bits::in{std::forward<ByteView>(view), ::zpp::bits::size_varint{}, ::zpp::bits::endian::little{},
                           ::zpp::bits::alloc_limit<::zpp::bits::traits::alloc_limit<Options...>()>{}};
}

template <::zpp::bits::concepts::byte_view ByteView = std::vector<std::byte>, typename... Options>
class in {

  using archive_type = decltype(make_in_archive(std::declval<ByteView &>(), std::declval<Options &&>()...));

  archive_type m_archive;
  bool m_has_unknown_fields = false;

public:
  using default_size_type = traits::default_size_type_t<Options...>;

  constexpr explicit in(ByteView &&view, Options &&...options)
      : m_archive(make_in_archive(std::move(view), std::forward<Options>(options)...)) {}

  constexpr explicit in(ByteView &view, Options &&...options)
      : m_archive(make_in_archive(view, std::forward<Options>(options)...)) {}

  ZPP_BITS_INLINE constexpr errc operator()(auto &item) {
    using type = std::remove_cvref_t<decltype(item)>;
    item = type{};
    return serialize_one(item);
  }

  constexpr std::size_t position() const { return m_archive.position(); }

  constexpr std::size_t &position() { return m_archive.position(); }

  constexpr auto remaining_data() { return m_archive.remaining_data(); }

  constexpr static auto kind() { return ::zpp::bits::kind::in; }

  constexpr bool has_unknown_fields() const { return m_has_unknown_fields; }

  template <typename AggregateType>
  ZPP_BITS_INLINE constexpr static void clear(AggregateType &item) {
    using type = std::remove_cvref_t<decltype(item)>;
    do_visit_members(item, [](auto &...members) ZPP_BITS_CONSTEXPR_INLINE_LAMBDA {
      reset_members<type>(std::make_index_sequence<sizeof...(members)>{}, members...);
    });
  }

  template <typename AggregateType, std::size_t FirstIndex, std::size_t... Indices>
  ZPP_BITS_INLINE constexpr static void reset_members(std::index_sequence<FirstIndex, Indices...>, auto &first_item,
                                                      auto &...items) {
    set_as_default(first_item);
    reset_members<AggregateType>(std::index_sequence<Indices...>{}, std::forward<decltype(items)>(items)...);
  }

  template <typename AggregateType>
  ZPP_BITS_INLINE constexpr static void reset_members(std::index_sequence<>) {}

  errc deserialize_tag(::zpp::bits::vuint32_t &tag) { return m_archive(tag); }

  ZPP_BITS_INLINE constexpr errc deserialize_fields(auto &item, std::size_t end_position) {
    using type = std::remove_cvref_t<decltype(item)>;
    // clear(item);

    std::size_t hint = 0;

    while (m_archive.position() < end_position) {
      ::zpp::bits::vuint32_t tag;
      if (auto result = m_archive(tag); failure(result)) [[unlikely]] {
        return result;
      }

      if (std::is_constant_evaluated()) {
        if (auto result = deserialize_field_by_num<0>(item, tag_number(tag), proto::tag_type(tag)); failure(result))
            [[unlikely]] {
          return result;
        }
      } else {
        if (auto result = deserialize_field_by_num(item, tag_number(tag), proto::tag_type(tag), hint); failure(result))
            [[unlikely]]
          return result;
      }
    }

    return {};
  }

  ZPP_BITS_INLINE constexpr errc deserialize_group(auto &item, uint32_t field_num) {
    using type = std::remove_cvref_t<decltype(item)>;
    // clear(item);

    std::size_t hint = 0;

    while (m_archive.remaining_data().size()) {
      ::zpp::bits::vuint32_t tag;
      if (auto result = m_archive(tag); failure(result)) [[unlikely]] {
        return result;
      }

      if (proto::tag_type(tag) == wire_type::egroup && field_num == tag_number(tag))
        return {};

      if (std::is_constant_evaluated()) {
        if (auto result = deserialize_field_by_num<0>(item, tag_number(tag), proto::tag_type(tag)); failure(result))
            [[unlikely]] {
          return result;
        }
      } else {
        if (auto result = deserialize_field_by_num(item, tag_number(tag), proto::tag_type(tag), hint); failure(result))
            [[unlikely]]
          return result;
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
    constexpr std::size_t num_members = ::zpp::bits::access::number_of_members<Type>();
    return deserialize_funs<Type>(std::make_index_sequence<num_members>());
  }

  ZPP_BITS_INLINE errc skip_field(concepts::has_extension auto &item, uint32_t field_num, wire_type field_wire_type) {
    ::zpp::bits::vsize_t length = 0;
    m_has_unknown_fields = true;
    auto &data = item.extensions.fields[field_num];
    auto out = ::zpp::bits::out(data, ::zpp::bits::no_size{}, ::zpp::bits::append{});
    if (auto result = out(::zpp::bits::vint32_t(field_num << 3 | (int)field_wire_type)); failure(result)) [[unlikely]] {
      return result;
    }

    switch (field_wire_type) {
    case wire_type::varint:
      if (auto result = m_archive(length); failure(result)) [[unlikely]] {
        return result;
      }
      return out(length);
    case wire_type::length_delimited:
      if (auto result = m_archive(length); failure(result)) [[unlikely]] {
        return result;
      }
      if (auto result = out(length); failure(result)) [[unlikely]] {
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
    }

    if (remaining_data().size() < length) [[unlikely]]
      return std::errc::result_out_of_range;
    if (auto result = out(::zpp::bits::bytes(remaining_data().subspan(0, length))); failure(result)) [[unlikely]] {
      return result;
    }
    position() += length;
    return {};
  }

  ZPP_BITS_INLINE errc skip_field(auto &item, uint32_t, wire_type field_wire_type) {
    ::zpp::bits::vsize_t length = 0;
    m_has_unknown_fields = true;
    switch (field_wire_type) {
    case wire_type::varint:
      return m_archive(length);
    case wire_type::length_delimited:
      if (auto result = m_archive(length); failure(result)) [[unlikely]] {
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
    }
    if (remaining_data().size() < length) [[unlikely]]
      return std::errc::result_out_of_range;
    position() += length;
    return {};
  }

  inline errc deserialize_field_by_num(auto &item, uint32_t field_num, wire_type field_wire_type, std::size_t hint) {
    using type = std::remove_cvref_t<decltype(item)>;
    static auto fun_ptrs = deserialize_funs<type>();
    auto index = traits::reverse_indeces<type>::number_to_index(field_num, hint);
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
    if constexpr (Index >= ::zpp::bits::number_of_members<type>()) {
      return skip_field(item, field_num, field_wire_type);
    } else if (!has_field_num(typename traits::field_meta_of<type, Index>::type{}, field_num)) {
      return deserialize_field_by_num<Index + 1>(item, field_num, field_wire_type);
    } else {
      return deserialize_field_by_index<Index>(item, field_num, field_wire_type);
    }
  }

  template <std::size_t Index>
  ZPP_BITS_INLINE constexpr errc deserialize_field_by_index(auto &item, uint32_t field_num, wire_type field_wire_type) {
    using type = std::remove_reference_t<decltype(item)>;

    if constexpr (disallow_inline_visit_members_lambda<type>()) {
      return do_visit_members(item, [&](auto &&...items) constexpr {
        std::tuple<decltype(items) &...> refs = {items...};
        auto &field = std::get<Index>(refs);
        using field_type = std::remove_reference_t<decltype(field)>;
        using Meta = typename traits::field_meta_of<type, Index>::type;
        return deserialize_field(Meta{}, field_wire_type, field_num, field);
      });
    } else {
      return do_visit_members(item, [&](auto &&...items) ZPP_BITS_CONSTEXPR_INLINE_LAMBDA {
        std::tuple<decltype(items) &...> refs = {items...};
        auto &field = std::get<Index>(refs);
        using field_type = std::remove_reference_t<decltype(field)>;
        using Meta = typename traits::field_meta_of<type, Index>::type;
        return deserialize_field(Meta(), field_wire_type, field_num, field);
      });
    }
  }

  template <typename Meta>
  ZPP_BITS_INLINE constexpr errc deserialize_field(Meta meta, wire_type field_type, uint32_t field_num, auto &&item) {
    using type = std::remove_reference_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    if constexpr (std::is_enum_v<type>) {
      ::zpp::bits::vint64_t value;
      if (auto result = m_archive(value); failure(result)) [[unlikely]] {
        return result;
      }
      item = static_cast<type>(value.value);
      return errc{};
    } else if constexpr (std::is_same_v<type, boolean>) {
      if (auto result = m_archive(item.value); failure(result)) [[unlikely]] {
        return result;
      }
      return errc{};
    } else if constexpr (::zpp::bits::concepts::optional<type>) {
      return deserialize_field(meta, field_type, field_num, item.emplace());
    } else if constexpr (::zpp::bits::concepts::owning_pointer<type>) {
      using element_type = std::remove_reference_t<decltype(*item)>;

      auto loaded = ::zpp::bits::access::make_unique<element_type>();
      if (auto result = deserialize_field(meta, field_type, field_num, *loaded); failure(result)) [[unlikely]] {
        return result;
      }

      item.reset(loaded.release());
      return errc{};
    } else if constexpr (concepts::oneof_type<type>) {
      static_assert(std::is_same_v<std::remove_cvref_t<decltype(std::get<0>(type{}))>, std::monostate>);
      return deserialize_oneof<0, Meta>(field_type, field_num, std::forward<decltype(item)>(item));
    } else if constexpr (!std::is_same_v<type, serialize_type> && concepts::scalar<serialize_type> &&
                         !::zpp::bits::concepts::container<type>) {
      serialize_type value;
      if (auto result = deserialize_field(meta, field_type, field_num, value); failure(result)) [[unlikely]] {
        return result;
      }
      item = std::move(value);
      return errc{};
    } else if constexpr (concepts::numeric_or_byte<type>) {
      if (auto result = m_archive(item); failure(result)) [[unlikely]] {
        return result;
      }
      return errc{};
    } else if constexpr (!::zpp::bits::concepts::container<type>) {
      if constexpr (meta.encoding != encoding_rule::group) {
        return serialize_one<::zpp::bits::varint<uint32_t>>(item);
      } else {
        return deserialize_group(item, field_num);
      }
    } else if constexpr (::zpp::bits::concepts::associative_container<type> &&
                         requires { typename type::mapped_type; }) {
      using value_type = typename traits::get_map_entry<Meta, type>::mutable_type;
      std::aligned_storage_t<sizeof(value_type), alignof(value_type)> storage;

      auto object = ::zpp::bits::access::placement_new<value_type>(std::addressof(storage));
      ::zpp::bits::destructor_guard guard{*object};
      if (auto result = serialize_one<::zpp::bits::varint<uint32_t>>(*object); failure(result)) [[unlikely]] {
        return result;
      }
      object->insert_to(item);
      return errc{};
    } else if constexpr (meta.encoding == encoding_rule::group) {
      // repeated group
      return deserialize_group(item.emplace_back(), field_num);
    } else {
      using value_type = typename type::value_type;

      if constexpr (concepts::scalar<value_type>) {
        if constexpr (!std::is_same_v<value_type, char> && !std::is_same_v<value_type, std::byte>) {
          if (field_type != wire_type::length_delimited || concepts::string_or_bytes<value_type>) {
            // unpacked repeated encoding
            value_type element;
            if (auto result = deserialize_field(meta, field_type, field_num, element); failure(result)) [[unlikely]] {
              return result;
            }
            if constexpr (requires { item.push_back(element); }) {
              item.push_back(element);
            } else {
              item.insert(element);
            }
            return errc{};
          }
        }
        // packed repeated encoding
        using element_type =
            std::conditional_t<std::is_same_v<typename Meta::type, void> || std::is_same_v<value_type, char> ||
                                   std::is_same_v<value_type, std::byte>,
                               value_type, typename Meta::type>;

        ::zpp::bits::vsize_t length;
        if (auto result = m_archive(length); failure(result)) [[unlikely]] {
          return result;
        }

        if constexpr (requires { item.resize(1); } &&
                      (std::is_fundamental_v<element_type> || std::same_as<value_type, std::byte> ||
                       std::same_as<value_type, boolean>)) {
          if constexpr (archive_type::allocation_limit != std::numeric_limits<std::size_t>::max()) {
            if (length > archive_type::allocation_limit) [[unlikely]] {
              return errc{std::errc::message_size};
            }
          }
          item.resize(length / sizeof(value_type));
          return m_archive(::zpp::bits::unsized(
              std::span<element_type>{reinterpret_cast<element_type *>(item.data()), item.size()}));
        } else if constexpr (std::is_same_v<type, std::string_view>) {
          // handling string_view
          auto data = m_archive.remaining_data();
          if (data.size() < length)
            return std::errc::result_out_of_range;
          item = std::string_view((const char *)data.data(), length);
          m_archive.position() += length;
          return {};
        } else if constexpr ((std::is_same_v<value_type, char> ||
                              std::is_same_v<value_type, std::byte>)&&std::is_same_v<type,
                                                                                     std::span<const value_type>>) {
          // handling span of bytes
          auto data = m_archive.remaining_data();
          if (data.size() < length)
            return std::errc::result_out_of_range;
          item = std::span<const value_type>((const value_type *)data.data(), length);
          m_archive.position() += length;
          return {};
        } else {
          if constexpr (requires { item.reserve(1); }) {
            item.reserve(length);
          }

          auto fetch = [&]() ZPP_BITS_CONSTEXPR_INLINE_LAMBDA {
            element_type value;

            if constexpr (std::is_enum_v<element_type>) {
              zpp::bits::vint64_t underlying;
              if (auto result = m_archive(underlying); failure(result)) [[unlikely]] {
                return result;
              }
              value = static_cast<element_type>(underlying.value);
            } else {
              if (auto result = m_archive(value); failure(result)) [[unlikely]] {
                return result;
              }
            }

            if constexpr (requires { item.push_back(value_type(value)); }) {
              item.push_back(value_type(value));
            } else {
              item.insert(value_type(value));
            }

            return errc{};
          };

          auto end_position = length + m_archive.position();
          while (m_archive.position() < end_position) {
            if (auto result = fetch(); failure(result)) [[unlikely]] {
              return result;
            }
          }

          return errc{};
        }
      } else {
        std::aligned_storage_t<sizeof(value_type), alignof(value_type)> storage;

        auto object = ::zpp::bits::access::placement_new<value_type>(std::addressof(storage));
        ::zpp::bits::destructor_guard guard{*object};
        if (auto result = serialize_one<::zpp::bits::varint<uint32_t>>(*object); failure(result)) [[unlikely]] {
          return result;
        }

        if constexpr (requires { item.push_back(std::move(*object)); }) {
          item.push_back(std::move(*object));
        } else {
          item.insert(std::move(*object));
        }

        return errc{};
      }
    }
  }

  template <std::size_t Index, ::zpp::bits::concepts::tuple Meta>
  ZPP_BITS_INLINE constexpr auto deserialize_oneof(wire_type field_type, uint32_t field_num, auto &&item) {
    if constexpr (Index < std::tuple_size_v<Meta>) {
      using meta = typename std::tuple_element<Index, Meta>::type;
      if (meta::number == field_num) {
        return deserialize_field(meta{}, field_type, field_num, item.template emplace<Index + 1>());
      } else {
        return deserialize_oneof<Index + 1, Meta>(field_type, field_num, std::forward<decltype(item)>(item));
      }
    }
    return errc{};
  }

  template <typename SizeType = default_size_type>
  ZPP_BITS_INLINE constexpr errc serialize_one(auto &item) {
    if constexpr (!std::is_void_v<SizeType>) {
      SizeType size{};
      if (auto result = m_archive(size); failure(result)) [[unlikely]] {
        return result;
      }
      if (size > m_archive.remaining_data().size()) [[unlikely]]
        return errc{std::errc::message_size};

      return deserialize_fields(item, m_archive.position() + size);
    } else
      return deserialize_fields(item, m_archive.data().size());
  }
};
template <typename Type, std::size_t Size, typename... Options>
in(Type (&)[Size], Options &&...) -> in<std::span<Type, Size>, Options...>;

template <typename Type, typename SizeType, typename... Options>
in(::zpp::bits::sized_item<Type, SizeType> &, Options &&...) -> in<Type, Options...>;

template <typename Type, typename SizeType, typename... Options>
in(const ::zpp::bits::sized_item<Type, SizeType> &, Options &&...) -> in<const Type, Options...>;

template <typename Type, typename SizeType, typename... Options>
in(::zpp::bits::sized_item<Type, SizeType> &&, Options &&...) -> in<Type, Options...>;

constexpr auto input(auto &&view, auto &&...option) {
  return in(std::forward<decltype(view)>(view), std::forward<decltype(option)>(option)...);
}

constexpr auto output(auto &&view, auto &&...option) {
  return out(std::forward<decltype(view)>(view), std::forward<decltype(option)>(option)...);
}

constexpr auto in_out(auto &&view, auto &&...option) {
  return std::tuple{
      in<std::remove_reference_t<typename decltype(in{view})::view_type>, decltype(option) &...>(view, option...),
      out(std::forward<decltype(view)>(view), std::forward<decltype(option)>(option)...)};
}

template <typename ByteType = std::byte>
constexpr auto data_in_out(auto &&...option) {
  struct data_in_out {
    data_in_out(decltype(option) &&...option)
        : input(data, option...), output(data, std::forward<decltype(option)>(option)...) {}

    std::vector<ByteType> data;
    in<decltype(data), decltype(option) &...> input;
    out<decltype(data), decltype(option)...> output;
  };
  return data_in_out{std::forward<decltype(option)>(option)...};
}

template <typename ByteType = std::byte>
constexpr auto data_in(auto &&...option) {
  struct data_in {
    data_in(decltype(option) &&...option) : input(data, std::forward<decltype(option)>(option)...) {}

    std::vector<ByteType> data;
    in<decltype(data), decltype(option)...> input;
  };
  return data_in{std::forward<decltype(option)>(option)...};
}

template <typename ByteType = std::byte>
constexpr auto data_out(auto &&...option) {
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
inline auto extension_meta_base<ExtensionMeta>::read(const concepts::pb_extension auto &extensions) {
  check(extensions);

  auto itr = extensions.fields.find(ExtensionMeta::number);

  deserialize_wrapper_type<typename ExtensionMeta::get_result_type, ExtensionMeta> wrapper;
  if (itr != extensions.fields.end()) {
    proto::in(itr->second)(wrapper).or_throw();
  }

  return wrapper.value;
}

template <typename ExtensionMeta>
inline void extension_meta_base<ExtensionMeta>::write(concepts::pb_extension auto &extensions, auto &&value) {
  check(extensions);

  auto [data, out] = data_out();
  out.serialize_field(ExtensionMeta{}, std::forward<typename ExtensionMeta::set_value_type>(value)).or_throw();
  data.resize(out.position());
  if (data.size())
    extensions.fields[ExtensionMeta::number] = std::move(data);
}

template <typename T, typename Buffer>
inline std::error_code write_proto(T &&msg, Buffer &buffer) {
  return std::make_error_code(out(buffer)(std::forward<T>(msg)));
}

template <typename T, ::zpp::bits::concepts::byte_view Buffer>
inline std::error_code read_proto(T &msg, Buffer &&buffer) {
  return std::make_error_code(in(std::forward<Buffer>(buffer))(msg));
}

} // namespace proto
} // namespace hpp

#endif
