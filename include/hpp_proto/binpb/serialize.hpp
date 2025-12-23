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
#include <system_error>

#include <hpp_proto/binpb/concepts.hpp>
#include <hpp_proto/binpb/meta.hpp>
#include <hpp_proto/binpb/utf8.hpp>
#include <hpp_proto/binpb/util.hpp>
#include <hpp_proto/binpb/varint.hpp>

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
namespace hpp::proto::pb_serializer {

template <concepts::is_size_cache_iterator Iterator>
constexpr decltype(auto) consume_size_cache_entry(Iterator &iterator) {
  decltype(auto) entry = *iterator;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  iterator++;
  return entry;
}

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
      if (!item.empty()) {
        auto bytes_to_copy = item.size() * sizeof(value_type);
        std::memcpy(_data.data(), item.data(), bytes_to_copy);
        _data = _data.subspan(bytes_to_copy);
      }
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
    using meta_type = typename util::meta_of<type>::type;
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
  constexpr static std::size_t count(concepts::oneof_type auto const &item, Meta) {
    return count_oneof<0, typename Meta::alternatives_meta>(item);
  }

  constexpr static std::size_t count(concepts::dereferenceable auto const &item, auto meta) {
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    return count(*item, meta);
  }

  constexpr static std::size_t count(concepts::has_meta auto const &item, auto meta) {
    return count(item) + (!meta.is_delimited());
  }

  template <typename Meta>
  constexpr static std::size_t count(std::ranges::input_range auto const &item, Meta meta) {
    using type = std::remove_cvref_t<decltype(item)>;
    using value_type = typename std::ranges::range_value_t<type>;
    if constexpr (concepts::has_meta<value_type> || !meta.is_packed() || meta.is_delimited()) {
      return util::transform_accumulate(item, [](const auto &elem) constexpr { return count(elem, Meta{}); });
    } else {
      using element_type =
          std::conditional_t<std::same_as<typename Meta::type, void> || concepts::contiguous_byte_range<type>,
                             value_type, typename Meta::type>;

      if constexpr (std::is_enum_v<element_type> || concepts::varint<element_type>) {
        return 1;
      } else {
        return 0;
      }
    }
  }

  template <typename Meta>
  constexpr static std::size_t count(concepts::is_pair auto const &item, Meta) {
    using type = std::remove_cvref_t<decltype(item)>;
    using serialize_type = typename util::get_serialize_type<Meta, type>::type;

    static_assert(concepts::is_map_entry<serialize_type>);
    using mapped_type = typename serialize_type::mapped_type;
    if constexpr (concepts::has_meta<mapped_type>) {
      auto r = count(item.second) + 2;
      return r;
    } else {
      return 1;
    }
  }

  constexpr static std::size_t count(concepts::no_cached_size auto const &, auto) { return 0; }

  template <std::size_t I, typename Meta>
  constexpr static std::size_t count_oneof(auto const &item) {
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
      const auto size = meta.omit_value(field) ? 0U : static_cast<uint32_t>(field_size(field, meta, cache_itr));
      sum += size;
    }
    constexpr ~field_size_accumulator() = default;
    field_size_accumulator(const field_size_accumulator &) = delete;
    field_size_accumulator(field_size_accumulator &&) = delete;
    field_size_accumulator &operator=(const field_size_accumulator &) = delete;
    field_size_accumulator &operator=(field_size_accumulator &&) = delete;
  };

  constexpr static uint32_t message_size(concepts::has_meta auto const &item,
                                         concepts::is_size_cache_iterator auto &cache_itr) {
    using type = std::remove_cvref_t<decltype(item)>;
    return std::apply(
        [&item, &cache_itr](auto &&...meta) {
          // we cannot directly use fold expression with '+' operator because it has undefined evaluation order.
          field_size_accumulator accumulator(cache_itr);
          (accumulator(meta.access(item), meta), ...);
          return accumulator.sum;
        },
        typename util::meta_of<type>::type{});
  }

  template <typename Meta>
  constexpr static uint32_t field_size(concepts::oneof_type auto const &item, Meta,
                                       concepts::is_size_cache_iterator auto &cache_itr) {
    return oneof_size<0, typename Meta::alternatives_meta>(item, cache_itr);
  }

  constexpr static uint32_t field_size(concepts::pb_extensions auto const &item, auto,
                                       concepts::is_size_cache_iterator auto &) {
    return util::transform_accumulate(item.fields, [](const auto &e) constexpr { return e.second.size(); });
  }

  constexpr static uint32_t field_size(concepts::pb_unknown_fields auto const &item, auto,
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

  constexpr static uint32_t field_size(concepts::is_empty auto const &, auto, concepts::is_size_cache_iterator auto &) {
    return 0;
  }

  constexpr static uint32_t field_size(concepts::is_enum auto item, auto meta,
                                       concepts::is_size_cache_iterator auto &) {
    using type = decltype(item);
    return static_cast<uint32_t>(varint_size(meta.number << 3U) +
                                 varint_size(static_cast<int64_t>(std::underlying_type_t<type>(item))));
  }

  template <typename Meta>
  constexpr static uint32_t field_size(concepts::byte_serializable auto item, Meta meta,
                                       concepts::is_size_cache_iterator auto &) {
    using type = decltype(item);
    using serialize_type = typename util::get_serialize_type<Meta, type>::type;

    constexpr auto tag_size = static_cast<uint32_t>(varint_size(meta.number << 3U));
    if constexpr (concepts::byte_serializable<serialize_type>) {
      return static_cast<uint32_t>(tag_size + sizeof(serialize_type));
    } else {
      static_assert(concepts::varint<serialize_type>);
      return static_cast<uint32_t>(tag_size + serialize_type(item).encode_size());
    }
  }

  constexpr static uint32_t field_size(concepts::varint auto item, auto meta, concepts::is_size_cache_iterator auto &) {
    return static_cast<uint32_t>(varint_size(meta.number << 3U) + item.encode_size());
  }

  constexpr static uint32_t field_size(concepts::dereferenceable auto const &item, auto meta,
                                       concepts::is_size_cache_iterator auto &cache_itr) {
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    return static_cast<uint32_t>(field_size(*item, meta, cache_itr));
  }

  constexpr static uint32_t field_size(concepts::has_meta auto const &item, auto meta,
                                       concepts::is_size_cache_iterator auto &cache_itr) {
    constexpr auto tag_size = static_cast<uint32_t>(varint_size(meta.number << 3U));
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
  constexpr static uint32_t field_size(concepts::is_pair auto const &item, Meta meta,
                                       concepts::is_size_cache_iterator auto &cache_itr) {
    using type = std::remove_cvref_t<decltype(item)>;
    using serialize_type = typename util::get_serialize_type<Meta, type>::type;
    using value_type = typename serialize_type::read_only_type;

    constexpr auto tag_size = static_cast<uint32_t>(varint_size(meta.number << 3U));
    auto &[key, value] = item;
    decltype(auto) msg_size = consume_size_cache_entry(cache_itr);
    auto s = message_size(value_type{key, value}, cache_itr);
    msg_size = static_cast<uint32_t>(s);
    return static_cast<uint32_t>(tag_size + len_size(s));
  }

  template <typename Meta>
  constexpr static std::size_t field_size(std::ranges::input_range auto const &item, Meta meta,
                                          concepts::is_size_cache_iterator auto &cache_itr) {
    using type = std::remove_cvref_t<decltype(item)>;
    constexpr auto tag_size = static_cast<uint32_t>(varint_size(meta.number << 3U));
    if constexpr (concepts::contiguous_byte_range<type>) {
      return tag_size + len_size(item.size());
    } else {
      using value_type = typename std::ranges::range_value_t<type>;
      if constexpr (concepts::has_meta<value_type> || !meta.is_packed() || meta.is_delimited()) {
        return util::transform_accumulate(
            item, [&cache_itr](const auto &elem) constexpr { return field_size(elem, Meta{}, cache_itr); });
      } else {
        using element_type =
            std::conditional_t<std::same_as<typename Meta::type, void> || concepts::contiguous_byte_range<type>,
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
  constexpr static uint32_t oneof_size(auto const &item, concepts::is_size_cache_iterator auto &cache_itr) {
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
      std::vector<uint32_t> cache(n);
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
  using metas = typename util::meta_of<type>::type;
  auto serialize_field_if_not_empty = [&](auto meta) {
    return meta.omit_value(meta.access(item)) || serialize_field(meta.access(item), meta, cache_itr, archive);
  };
  return std::apply([&](auto... meta) { return (serialize_field_if_not_empty(meta) && ...); }, metas{});
}

template <typename Meta>
[[nodiscard]] constexpr bool serialize_field(concepts::oneof_type auto const &item, Meta,
                                             concepts::is_size_cache_iterator auto &cache_itr, auto &archive) {
  return serialize_oneof<0, typename Meta::alternatives_meta>(item, cache_itr, archive);
}

[[nodiscard]] constexpr bool serialize_field(boolean item, auto meta, concepts::is_size_cache_iterator auto &,
                                             auto &archive) {
  return archive(make_tag<bool>(meta), item.value);
}

[[nodiscard]] constexpr bool serialize_field(concepts::pb_extensions auto const &item, auto,
                                             concepts::is_size_cache_iterator auto &, auto &archive) {
  return std::ranges::all_of(item.fields, [&](const auto &f) { return archive(f.second); });
}

[[nodiscard]] constexpr bool serialize_field(concepts::pb_unknown_fields auto const &item, auto,
                                             concepts::is_size_cache_iterator auto &, auto &archive) {
  using range_t = typename std::remove_reference_t<decltype(item)>::unknown_fields_range_t;
  if constexpr (concepts::contiguous_byte_range<range_t>) {
    return archive(item.fields);
  } else {
    return true;
  }
}

[[nodiscard]] constexpr bool serialize_field(concepts::is_empty auto const &, auto,
                                             concepts::is_size_cache_iterator auto &, auto &) {
  return true;
}

[[nodiscard]] constexpr bool serialize_field(concepts::is_enum auto item, auto meta,
                                             concepts::is_size_cache_iterator auto &, auto &archive) {
  return archive(make_tag<decltype(item)>(meta), item);
}

[[nodiscard]] constexpr bool serialize_field(concepts::arithmetic auto item, auto meta,
                                             concepts::is_size_cache_iterator auto &, auto &archive) {
  using serialize_type = typename util::get_serialize_type<decltype(meta), decltype(item)>::type;
  return archive(make_tag<serialize_type>(meta), serialize_type{item});
}

[[nodiscard]] constexpr bool serialize_field(concepts::contiguous_byte_range auto const &item, auto meta,
                                             concepts::is_size_cache_iterator auto &, auto &archive) {
  using type = std::remove_cvref_t<decltype(item)>;
  return !utf8_validation_failed(meta, item) && archive(make_tag<type>(meta), varint{item.size()}, item);
}

[[nodiscard]] constexpr bool serialize_field(concepts::dereferenceable auto const &item, auto meta,
                                             concepts::is_size_cache_iterator auto &cache_itr, auto &archive) {
  // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
  return serialize_field(*item, meta, cache_itr, archive);
}

[[nodiscard]] constexpr bool serialize_field(concepts::has_meta auto const &item, auto meta,
                                             concepts::is_size_cache_iterator auto &cache_itr, auto &archive) {
  if constexpr (!meta.is_delimited()) {
    auto len = varint{consume_size_cache_entry(cache_itr)};
    return archive(make_tag<decltype(item)>(meta), len) && serialize(item, cache_itr, archive);
  } else {
    return archive(varint{(meta.number << 3U) | std::underlying_type_t<wire_type>(wire_type::sgroup)}) &&
           serialize(item, cache_itr, archive) &&
           archive(varint{(meta.number << 3U) | std::underlying_type_t<wire_type>(wire_type::egroup)});
  }
}

[[nodiscard]] constexpr bool serialize_field(std::ranges::range auto const &item, auto meta,
                                             concepts::is_size_cache_iterator auto &cache_itr, auto &archive) {
  using Meta = decltype(meta);
  using type = std::remove_cvref_t<decltype(item)>;
  using value_type = typename std::ranges::range_value_t<type>;
  using element_type =
      std::conditional_t<std::same_as<typename Meta::type, void> || concepts::contiguous_byte_range<type>, value_type,
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
[[nodiscard]] constexpr bool serialize_field(concepts::is_pair auto const &item, Meta meta,
                                             concepts::is_size_cache_iterator auto &cache_itr, auto &archive) {
  using type = std::remove_cvref_t<decltype(item)>;
  constexpr auto tag = make_tag<type>(meta);
  using value_type = typename util::get_map_entry<Meta, type>::read_only_type;
  static_assert(concepts::has_meta<value_type>);
  auto &&[key, value] = item;
  auto len = varint{consume_size_cache_entry(cache_itr)};
  return archive(tag, len) && serialize(value_type{key, value}, cache_itr, archive);
}

template <std::size_t I, concepts::tuple Meta>
[[nodiscard]] constexpr static bool serialize_oneof(auto const &item, concepts::is_size_cache_iterator auto &cache_itr,
                                                    auto &archive) {
  if constexpr (I < std::tuple_size_v<Meta>) {
    if (I == item.index() - 1) {
      return serialize_field(std::get<I + 1>(item), typename std::tuple_element_t<I, Meta>{}, cache_itr, archive);
    }
    return serialize_oneof<I + 1, Meta>(item, cache_itr, archive);
  }
  return true;
}
} // namespace hpp::proto::pb_serializer
// NOLINTEND(bugprone-easily-swappable-parameters)
