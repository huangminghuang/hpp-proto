#pragma once
#include <numeric>
#include <system_error>
#include <type_traits>
#include <variant>

namespace hpp::proto {
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

namespace util {
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
  using type = std::conditional_t<std::same_as<typename Meta::type, void>, Type, typename Meta::type>;
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
  constexpr static auto field_numbers = get_numbers(typename util::meta_of<Type>::type{});

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
  constexpr static auto field_indices = get_indices(typename util::meta_of<Type>::type{});
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
} // namespace util
} // namespace hpp::proto