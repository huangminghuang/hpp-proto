// Type your code here, or load an example.
#include <algorithm>
#include <array>
#include <bit>
#include <climits>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <numeric>
#include <optional>
#include <ranges>
#include <span>
#include <tuple>
#include <variant>
#include <vector>

#ifndef __cpp_lib_bit_cast
namespace std {
using namespace ::std;
template <class ToType, class FromType,
          class = enable_if_t<sizeof(ToType) == sizeof(FromType) && is_trivially_copyable_v<ToType> &&
                              is_trivially_copyable_v<FromType>>>
constexpr ToType bit_cast(FromType const &from) noexcept {
  return __builtin_bit_cast(ToType, from);
}
} // namespace std
#endif

#if !defined(__cpp_lib_ranges)
namespace std {
namespace ranges {
template <typename Range1, typename Range2>
constexpr bool equal(Range1 &&r1, Range2 &&r2) {
  return std::equal(std::begin(r1), std::end(r1), std::begin(r2), std::end(r2));
}
} // namespace ranges
} // namespace std
#endif

namespace hpp::proto {
template <typename T, auto Default = std::monostate{}>
constexpr bool is_default_value(const T &val) {
  if constexpr (std::is_same_v<std::remove_cvref_t<decltype(Default)>, std::monostate>) {
    if constexpr (requires { val.empty(); }) {
      return val.empty();
    }
    if constexpr (requires { val.has_value(); }) {
      return !val.has_value();
    }
    if constexpr (std::is_class_v<T>) {
      return false;
    } else {
      return val == T{};
    }
  } else if constexpr (requires { val.has_value(); }) {
    return val.has_value() && Default == *val;
  } else {
    return Default == val;
  }
}

struct boolean {
  bool value = false;
  constexpr boolean() = default;
  constexpr boolean(bool v) : value(v) {}
  constexpr operator bool() const { return value; }
};

template <typename T, auto Default = std::monostate{}>
class optional {
  std::optional<T> impl;

public:
  using value_type = T;

  constexpr optional() noexcept = default;
  constexpr optional(std::nullopt_t) noexcept : impl(std::nullopt) {}

  constexpr optional(optional &&) = default;
  constexpr optional(const optional &) = default;

  template <class U>
  constexpr optional(const optional<U> &other) : impl(other.impl) {}
  template <class U>
  constexpr optional(optional<U> &&other) : impl(std::move(other.impl)) {}

  constexpr optional(const std::optional<T> &other) : impl(other) {}
  constexpr optional(std::optional<T> &&other) : impl(std::move(other)) {}
  template <class U>
  constexpr optional(const std::optional<U> &other) : impl(other) {}
  template <class U>
  constexpr optional(std::optional<U> &&other) : impl(std::move(other)) {}

  template <class... Args>
  constexpr explicit optional(std::in_place_t, Args &&...args) : impl(std::in_place, forward<Args>(args)...) {}

  template <class U, class... Args>
  constexpr explicit optional(std::in_place_t, std::initializer_list<U> ilist, Args &&...args)
      : impl(std::in_place, ilist, forward<Args>(args)...) {}

  template <typename U>
    requires std::convertible_to<U, T>
  constexpr optional(U &&value) : impl(std::forward<U>(value)) {}

  constexpr optional &operator=(std::nullopt_t) noexcept {
    impl = std::nullopt;
    return *this;
  }

  template <typename U>
    requires std::convertible_to<U, T>
  constexpr optional &operator=(U &&value) {
    impl = std::forward<U>(value);
    return *this;
  }

  constexpr optional &operator=(const optional &) = default;
  constexpr optional &operator=(optional &&) = default;

  template <class U>
  constexpr optional &operator=(const optional<U> &other) {
    impl = other.imp;
    return *this;
  }
  template <class U>
  constexpr optional &operator=(optional<U> &&other) {
    impl = std::move(other.imp);
    return *this;
  }

  constexpr optional &operator=(const std::optional<T> &v) {
    impl = v;
    return *this;
  }

  constexpr optional &operator=(std::optional<T> &&v) {
    impl = move(v);
    return *this;
  }

  constexpr bool has_value() const noexcept { return impl.has_value(); }
  constexpr operator bool() const noexcept { return has_value(); }

  constexpr T &value() & { return impl.value(); }
  constexpr const T &value() const & { return impl.value(); }
  constexpr T &&value() && { return std::move(impl.value()); }
  constexpr const T &&value() const && { return std::move(impl.value()); }

  template <class U>
  constexpr T value_or(U &&default_value) const & {
    return impl.value_or(static_cast<T>(default_value));
  }
  template <class U>
  constexpr T value_or(U &&default_value) && {
    return impl.value_or(default_value);
  }

  constexpr T *operator->() noexcept { return impl.operator->(); }
  constexpr const T *operator->() const noexcept { return impl.operator->(); }

  constexpr T &operator*() & noexcept { return *impl; }
  constexpr const T &operator*() const & noexcept { return *impl; }
  constexpr T &&operator*() && noexcept { return *impl; }
  constexpr const T &&operator*() const && noexcept { return *impl; }

  template <typename... Args>
  constexpr T &emplace(Args &&...args) {
    return impl.emplace(std::forward<Args>(args)...);
  }
  constexpr void swap(optional &other) noexcept { impl.swap(other.impl); }
  constexpr void reset() noexcept { impl.reset(); }

  constexpr T value_or_default() const {
    if constexpr (std::is_same_v<std::remove_cvref_t<decltype(Default)>, std::monostate>) {
      return this->value_or(T{});
    } else if constexpr (requires { T{Default.data(), Default.size()}; }) {
      return this->value_or(T{Default.data(), Default.size()});
    } else if constexpr (requires {
                           requires sizeof(typename T::value_type) == sizeof(typename decltype(Default)::value_type);
                           T{(const typename T::value_type *)Default.data(),
                             (const typename T::value_type *)Default.data() + Default.size()};
                         }) {
      return this->value_or(T{(const typename T::value_type *)Default.data(),
                              (const typename T::value_type *)Default.data() + Default.size()});
    } else {
      return this->value_or(unwrap(Default));
    }
  }

  constexpr bool operator==(const optional &other) const = default;
};

template <typename T>
class heap_based_optional {
  T *obj = nullptr;

public:
  using value_type = T;
  constexpr heap_based_optional() noexcept {}
  constexpr heap_based_optional(std::nullopt_t) noexcept {}
  constexpr ~heap_based_optional() { delete obj; }

  constexpr heap_based_optional(const T &object) : obj(new T(object)) {}
  constexpr heap_based_optional(heap_based_optional &&other) noexcept { std::swap(obj, other.obj); }
  constexpr heap_based_optional(const heap_based_optional &other) : obj(other.obj ? new T(*other.obj) : nullptr) {}

  template <class... Args>
  constexpr explicit heap_based_optional(std::in_place_t, Args &&...args)
      : obj(new T{std::forward<Args &&>(args)...}) {}

  constexpr heap_based_optional &operator=(heap_based_optional &&other) noexcept {
    std::swap(obj, other.obj);
    return *this;
  }

  constexpr heap_based_optional &operator=(const heap_based_optional &other) {
    heap_based_optional tmp(other);
    std::swap(obj, tmp.obj);
    return *this;
  }

  constexpr bool has_value() const noexcept { return obj; }
  constexpr operator bool() const noexcept { return has_value(); }

  constexpr T &value() {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *obj;
  }
  constexpr const T &value() const {
    if (!has_value()) {
      throw std::bad_optional_access();
    }
    return *obj;
  }

  constexpr T &operator*() noexcept { return *obj; }
  constexpr const T &operator*() const noexcept { return *obj; }

  constexpr T *operator->() noexcept { return obj; }
  constexpr const T *operator->() const noexcept { return obj; }

  constexpr T &emplace() {
    heap_based_optional tmp;
    tmp.obj = new T;
    std::swap(obj, tmp.obj);
    return *obj;
  }

  constexpr void swap(heap_based_optional &other) noexcept { std::swap(obj, other.obj); }
  constexpr void reset() noexcept {
    delete obj;
    obj == nullptr;
  }

  constexpr bool operator==(const T &rhs) const {
    if (has_value()) {
      return **this == rhs;
    } else {
      return false;
    }
  }

  constexpr bool operator==(const heap_based_optional &rhs) const {
    if (has_value() && rhs.has_value()) {
      return *obj == *rhs.obj;
    } else {
      return has_value() == rhs.has_value();
    }
  }

  constexpr bool operator==(std::nullopt_t) const { return !has_value(); }

#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARATOR

  constexpr std::strong_ordering operator<=>(const heap_based_optional &rhs) const {
    if (has_value() && rhs.has_value()) {
      return **this <=> *rhs;
    } else {
      return has_value() <=> rhs.has_value();
    }
  }

  constexpr std::strong_ordering operator<=>(const T &rhs) const {
    if (has_value()) {
      return **this <=> rhs;
    } else {
      return std::strong_ordering::less;
    }
  }

  constexpr std::strong_ordering operator<=>(std::nullopt_t) const {
    return has_value() ? std::strong_ordering::greater : std::strong_ordering::equal;
  }
#endif
};

/////////////////////////////////////////////////////////////////////////////////

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

namespace concepts {

template <typename Type>
concept varint = requires { requires std::same_as<Type, varint<typename Type::value_type, Type::encoding>>; };

template <typename Type>
concept container = requires(Type container) {
  typename std::remove_cvref_t<Type>::value_type;
  container.size();
  container.begin();
  container.end();
};

template <typename Type>
concept associative_container =
    container<Type> && requires(Type container) { typename std::remove_cvref_t<Type>::key_type; };

template <typename Type>
concept tuple = !container<Type> && requires(Type tuple) { sizeof(std::tuple_size<std::remove_cvref_t<Type>>); } &&
                !requires(Type tuple) { tuple.index(); };

template <typename Type>
concept variant = requires(Type variant) {
  variant.index();
  std::get_if<0>(&variant);
  std::variant_size_v<std::remove_cvref_t<Type>>;
};

template <typename Type>
concept has_local_meta = concepts::tuple<typename Type::pb_meta>;

template <typename Type>
concept has_explicit_meta = concepts::tuple<decltype(pb_meta(std::declval<Type>()))>;

template <typename Type>
concept has_meta = has_local_meta<Type> || has_explicit_meta<Type>;

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
concept string_or_bytes = concepts::container<Type> && (std::same_as<char, typename Type::value_type> ||
                                                        std::same_as<std::byte, typename Type::value_type>);

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

template <typename T>
concept contiguous_range = requires(T &t) {
  { t.data() } -> std::same_as<std::add_pointer_t<std::iter_reference_t<decltype(std::begin(std::declval<T &>()))>>>;
  t.size();
};

template <typename Type>
concept byte_type = std::same_as<std::remove_cv_t<Type>, char> || std::same_as<std::remove_cv_t<Type>, unsigned char> ||
                    std::same_as<std::remove_cv_t<Type>, std::byte>;

template <typename T>
concept contiguous_byte_range = byte_type<typename std::remove_cvref_t<T>::value_type> && contiguous_range<T>;

template <typename T>
concept byte_serializable =
    std::is_arithmetic_v<T> || std::same_as<hpp::proto::boolean, T> || std::same_as<std::byte, T>;

template <typename T>
concept is_size_cache = std::same_as<T, uint32_t *> || requires(T v) {
  { v++ } -> std::same_as<T>;
  *v = 0U;
};

template <typename T>
concept memory_resource = requires(T &object) {
  { object.allocate(8, 8) } -> std::same_as<void *>;
};

template <typename T>
concept has_memory_resource = requires(T &object) {
  object.memory_resource;
  requires memory_resource<std::remove_cvref_t<decltype(object.memory_resource)>>;
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
    }

    return false;
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
    }

    return false;
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

template <std::size_t Len>
struct compile_time_string {
  using value_type = char;
  char data_[Len];
  constexpr size_t size() const { return Len - 1; }
  constexpr compile_time_string(const char (&init)[Len]) { std::copy_n(init, Len, data_); }
  constexpr const char *data() const { return data_; }
};

template <std::size_t Len>
struct compile_time_bytes {
  using value_type = char;
  std::byte data_[Len];
  constexpr size_t size() const { return Len - 1; }
  constexpr compile_time_bytes(const char (&init)[Len]) {
    std::transform(init, init + Len, data_, [](char c) { return static_cast<std::byte>(c); });
  }
  constexpr const std::byte *data() const { return data_; }
};

template <compile_time_string cts>
struct ctb_wrapper {
  static constexpr compile_time_bytes bytes{cts.data_};

  constexpr size_t size() const { return bytes.size(); }
  constexpr const std::byte *data() const { return bytes.data(); }
  constexpr const std::byte *begin() const { return bytes.data(); }
  constexpr const std::byte *end() const { return bytes.data() + size(); }

  constexpr operator std::span<const std::byte>() const { return std::span<const std::byte>{bytes.data_, cts.size()}; }
};

template <compile_time_string cts>
struct cts_wrapper {
  static constexpr compile_time_string str{cts};
  constexpr size_t size() const { return str.size(); }
  constexpr const char *data() const { return str.data(); }
  constexpr const char *c_str() const { return str.data(); }
  constexpr const char *begin() const { return str.data(); }
  constexpr const char *end() const { return str.data() + size(); }

  explicit operator std::string() const { return std::string{data()}; }
  explicit operator std::vector<std::byte>() const {
    return std::vector<std::byte>{std::bit_cast<const std::byte *>(data()),
                                  std::bit_cast<const std::byte *>(data()) + size()};
  }

  explicit operator std::vector<char>() const { return std::vector<char>{data(), data() + size()}; }

  constexpr operator std::string_view() const { return std::string_view(data(), size()); }

  constexpr operator std::span<const std::byte>() const { return ctb_wrapper<cts>{}; }

  constexpr operator std::span<const char>() const { return std::span<const char>{data(), size()}; }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::string &rhs) {
    return static_cast<std::string_view>(lhs) == rhs;
  }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::string_view &rhs) {
    return static_cast<std::string_view>(lhs) == rhs;
  }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::span<const std::byte> &rhs) {
    return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(),
                      [](char a, std::byte b) { return static_cast<std::byte>(a) == b; });
  }

  friend constexpr bool operator==(const cts_wrapper &lhs, const std::span<const char> &rhs) {
    return std::equal(rhs.begin(), rhs.end(), lhs.data(), lhs.data() + lhs.size());
  }
};

using bytes_view = std::span<const std::byte>;
template <compile_time_string str>
constexpr auto operator""_cts() {
  return cts_wrapper<str>{};
}

template <compile_time_string str>
constexpr auto operator""_bytes_view() {
  return static_cast<bytes_view>(cts_wrapper<str>{});
}

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

template <concepts::has_meta Type>
struct reverse_indices {

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

  constexpr static std::optional<std::size_t> number_to_index(uint32_t number) {
    constexpr typename traits::meta_of<Type>::type metas;
    constexpr auto numbers = get_numbers(metas);
    constexpr auto indices = get_indices(metas);

    for (std::size_t i = 0; i < numbers.size(); ++i) {
      if (numbers[i] == number) {
        return indices[i];
      }
    }
    return {};
  }
};

template <typename Type>
inline constexpr auto number_of_members = std::tuple_size_v<typename meta_of<Type>::type>;
} // namespace traits

template <typename T, bool condition>
struct assert_type {
  static constexpr bool value = condition;
  static_assert(value, "Assertion failed <see below for more information>");
};

#if defined(__cpp_lib_constexpr_vector)
template <typename T>
using constexpr_vector = std::vector<T>;
#else
template <typename T>
class constexpr_vector {
  T *m_data;

public:
  constexpr explicit constexpr_vector(std::size_t n) { m_data = new T[n]; }
  constexpr ~constexpr_vector() { delete[] m_data; }
  constexpr T *data() noexcept { return m_data; }
  constexpr const T *data() const noexcept { return data; }
};
#endif

struct pb_serializer {
  template <typename Byte>
  struct basic_out {
    using byte_type = Byte;
    constexpr static bool endian_swapped = std::endian::little != std::endian::native;
    std::span<byte_type> m_data;

    inline constexpr void serialize(auto &&item) {
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
      } else if constexpr (concepts::contiguous_range<type> && concepts::byte_serializable<typename type::value_type>) {
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

    inline constexpr void operator()(auto &&...item) { (serialize(item), ...); }
  };
  constexpr static std::size_t len_size(std::size_t len) { return varint_size(len) + len; }

  template <typename Range, typename UnaryOperation>
  constexpr static std::size_t transform_accumulate(Range &&range, UnaryOperation &&unary_op) {
    return std::accumulate(range.begin(), range.end(), std::size_t{0},
                           [&unary_op](std::size_t acc, const auto &elem) constexpr { return acc + unary_op(elem); });
  }

  constexpr static std::size_t cache_count(concepts::has_meta auto &&item) {
    using type = std::remove_cvref_t<decltype(item)>;
    return std::apply([&item](auto &&...meta) constexpr { return (cache_count(meta, meta.access(item)) + ...); },
                      typename traits::meta_of<type>::type{});
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
    } else if constexpr (concepts::container<type>) {
      if (item.empty())
        return 0;
      if constexpr (Meta::encoding == encoding_rule::unpacked_repeated || Meta::encoding == encoding_rule::group) {
        return transform_accumulate(item, [](const auto &elem) constexpr { return cache_count(Meta{}, elem); });
      } else {
        using value_type = typename type::value_type;
        using element_type =
            std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::string_or_bytes<type>, value_type,
                               typename Meta::type>;

        if constexpr (std::is_enum_v<element_type> || concepts::varint<element_type>) {
          return 1;
        }
      }
    } else if constexpr (concepts::is_map_entry<serialize_type>) {
      using mapped_type = typename serialize_type::mapped_type;
      if constexpr (concepts::has_meta<mapped_type>) {
        return cache_count(item.second) + 1;
      } else {
        return 1;
      }
    }
    return 0;
  }

  template <std::size_t I, typename Meta>
  constexpr static std::size_t oneof_cache_count(auto &&item) {
    if constexpr (I < std::tuple_size_v<Meta>) {
      if (I == item.index() - 1) {
        return cache_count(typename std::tuple_element<I, Meta>::type{},
                           std::get<I + 1>(std::forward<decltype(item)>(item)));
      }
      return oneof_cache_count<I + 1, Meta>(std::forward<decltype(item)>(item));
    }
    return 0;
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
        [&item, &cache](auto &&...meta) constexpr { return (field_size(meta, meta.access(item), cache) + ...); },
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
      return transform_accumulate(item, [](const auto &e) constexpr { return e.second.size(); });
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
      } else if constexpr (concepts::string_or_bytes<type>) {
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
      } else if constexpr (concepts::container<type>) {
        if (item.empty())
          return 0;
        if constexpr (Meta::encoding == encoding_rule::unpacked_repeated || Meta::encoding == encoding_rule::group) {
          return transform_accumulate(item,
                                      [&cache](const auto &elem) constexpr { return field_size(Meta{}, elem, cache); });
        } else {
          using value_type = typename type::value_type;
          using element_type =
              std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::string_or_bytes<type>,
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
        msg_size = s;
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
    }
    return 0;
  }

  template <std::size_t MAX_CACHE_COUNT = 128, concepts::contiguous_byte_range Buffer>
  constexpr static std::errc serialize(concepts::has_meta auto &&item, Buffer &buffer) {
    std::size_t n = cache_count(item);

    auto do_serialize = [&item, &buffer](uint32_t *cache) constexpr {
      auto cache_end = cache;
      std::size_t sz = message_size(item, cache_end);
      if constexpr (requires { buffer.resize(1); }) {
        buffer.resize(sz);
      } else {
        if (sz < buffer.size()) {
          return std::errc::not_enough_memory;
        }
      }
      basic_out<typename std::remove_cvref_t<decltype(buffer)>::value_type> archive{buffer};
      serialize(item, cache, archive);
      return std::errc{};
    };

    if (std::is_constant_evaluated() || n > MAX_CACHE_COUNT) {
      constexpr_vector<uint32_t> cache(n);
      return do_serialize(cache.data());
    } else {
#if defined(_MSC_VER)
      uint32_t *cache = static_cast<uint32_t *>(_alloca(n * sizeof(uint32_t)));
#elif defined(__GNUC__)
      uint32_t *cache =
          static_cast<uint32_t *>(__builtin_alloca_with_align(n * sizeof(uint32_t), CHAR_BIT * sizeof(uint32_t)));
#else
      uint32_t cache[MAX_CACHE_COUNT];
#endif
      return do_serialize(cache);
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
      out(tag, item.value);
    } else if constexpr (concepts::pb_extension<type>) {
      for (const auto &f : item.fields) {
        archive(f.second);
      }
    } else if constexpr (std::is_enum_v<type> && !std::same_as<type, std::byte>) {
      archive(make_tag<type>(meta), item);
    } else if constexpr (concepts::numeric<type>) {
      archive(make_tag<serialize_type>(meta), serialize_type{item});
    } else if constexpr (concepts::string_or_bytes<type>) {
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
    } else if constexpr (concepts::container<type>) {
      if (item.empty()) {
        return;
      }
      using value_type = typename type::value_type;
      using element_type =
          std::conditional_t<std::is_same_v<typename Meta::type, void> || concepts::string_or_bytes<type>, value_type,
                             typename Meta::type>;

      if constexpr (Meta::encoding == encoding_rule::group || Meta::encoding == encoding_rule::unpacked_repeated) {
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
};

namespace concepts {} // namespace concepts

namespace detail {

template <typename T, concepts::memory_resource MemoryResource>
class growable_span {
public:
  using value_type = std::remove_const_t<T>;

  growable_span(std::span<T> &base, MemoryResource &mr) : base_(base), mr(mr) {}

  void resize(std::size_t n) {
    if (data_ == nullptr || n > base_.size()) {
      data_ = static_cast<value_type *>(mr.allocate(n * sizeof(value_type), alignof(value_type)));
      assert(data_ != nullptr);
      std::uninitialized_copy(base_.begin(), base_.end(), data_);

      if constexpr (!std::is_trivial_v<T>) {
        std::uninitialized_default_construct(data_ + base_.size(), data_ + n);
      } else {
#ifdef __cpp_lib_start_lifetime_as
        std::start_lifetime_as_array(data_ + base.size(), n);
#endif
      }
      base_ = std::span<T>{data_, n};
    } else {
      base_ = std::span<T>(base_.data(), n);
    }
  }

  value_type *data() const { return data_; }
  value_type &operator[](std::size_t n) { return data_[n]; }
  std::size_t size() const { return base_.size(); }
  value_type *begin() const { return data_; }
  value_type *end() const { return data_ + size(); }

  void clear() {
    base_ = std::span<T>{};
    data_ = nullptr;
  }

private:
  std::span<T> &base_;
  value_type *data_ = nullptr;
  MemoryResource &mr;
};
} // namespace detail

struct pb_deserializer {
  struct basic_in {
    constexpr static bool endian_swapped = std::endian::little != std::endian::native;
    std::span<const std::byte> m_data;
    constexpr basic_in(std::span<const std::byte> data) : m_data(data) {}

    constexpr std::errc deserialize(auto &&item) {
      using type = std::remove_cvref_t<decltype(item)>;
      if constexpr (concepts::byte_serializable<type>) {
        if (m_data.size() < sizeof(item)) [[unlikely]] {
          return std::errc::result_out_of_range;
        }
        if (std::is_constant_evaluated()) {
          std::array<std::remove_const_t<std::byte>, sizeof(item)> value;
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
      } else if constexpr (std::is_enum_v<type>) {
        deserialize(varint{static_cast<int64_t>(item)});
      } else if constexpr (concepts::varint<type>) {
        using value_type = typename type::value_type;

        auto commit = [&item, this](auto value, std::size_t byte_count) {
          if constexpr (varint_encoding::zig_zag == type::encoding) {
            item = ((value >> 1) ^ -(value & 0x1));
          } else {
            item = value;
          }

          m_data = m_data.subspan(byte_count);
          return std::errc{};
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
            m_data = m_data.subspan(1 + std::distance(m_data.data(), &byte_value));
            return {};
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
      } else if constexpr (concepts::contiguous_range<type> && concepts::byte_serializable<typename type::value_type>) {
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
      } else {
        static_assert(!sizeof(type));
      }
      return {};
    }

    constexpr std::errc skip_length_delimited() {
      vuint64_t len;
      std::errc result = deserialize(len);
      return skip(len.value);
    }

    constexpr std::errc skip(std::size_t length) {
      if (m_data.size() < length) [[unlikely]] {
        return std::errc::result_out_of_range;
      }
      m_data = m_data.subspan(length);
      return {};
    }

    constexpr std::errc operator()(auto &&...item) {
      std::errc result;
      (void)(((result = deserialize(item)) == std::errc{}) && ...);
      return result;
    }
  };

  template <typename T>
  constexpr static auto make_growable(concepts::has_memory_resource auto &&context, std::span<T> &base) {
    return detail::growable_span<T, std::remove_cvref_t<decltype(context.memory_resource)>>{base,
                                                                                            context.memory_resource};
  }

  template <typename T>
  constexpr static T &make_growable(auto &&context, T &base) {
    return base;
  }

  std::errc skip_field(uint32_t field_num, wire_type field_wire_type, concepts::has_extension auto &item, auto &context,
                       basic_in &archive) {
    auto tag = make_tag(field_num, field_wire_type);
    auto start_pos = archive.m_data.data() - varint_size<varint_encoding::normal>(tag.value);

    if (auto result = do_skip_field(field_num, field_wire_type, archive); result != std::errc{}) [[unlikely]] {
      return result;
    }

    const std::byte *data = std::bit_cast<const std::byte *>(archive.m_data.data());
    if constexpr (concepts::associative_container<std::remove_cvref_t<decltype(item.extensions.fields)>>) {
      auto &value = item.extensions.fields[field_num];
      value.insert(value.end(), start_pos, archive.m_data.data());
    } else {
      static_assert(concepts::span<std::remove_cvref_t<decltype(item.extensions.fields)>>);
      auto &fields = item.extensions.fields;

      auto old_size = fields.size();
      if (old_size > 0 && fields[old_size - 1].first == field_num) {
        auto &entry = fields[old_size - 1].second;
        if (entry.data() + entry.size() == start_pos) {
          entry = {entry.data(), archive.m_data.data()};
          return {};
        }
      }

      auto itr =
          std::find_if(fields.begin(), fields.end(), [field_num](const auto &e) { return e.first == field_num; });
      if (itr == fields.end()) [[likely]] {
        decltype(auto) growable_fields = make_growable(context, fields);
        growable_fields.resize(old_size + 1);
        growable_fields[old_size] = {field_num, {start_pos, archive.m_data.data()}};
      } else {
        decltype(auto) v = make_growable(context, itr->second);
        auto s = v.size();
        v.resize(v.size() + archive.m_data.data() - start_pos);
        std::copy(start_pos, archive.m_data.data(), v.data() + s);
      }
    }

    return {};
  }

  constexpr static std::errc skip_field(uint32_t field_num, wire_type field_wire_type, concepts::has_meta auto &,
                                        auto &context, basic_in &archive) {
    return do_skip_field(field_num, field_wire_type, archive);
  }

  constexpr static std::errc do_skip_field(uint32_t field_num, wire_type field_wire_type, basic_in &archive) {
    vuint64_t length = 0;
    switch (field_wire_type) {
    case wire_type::varint:
      return archive(length);
    case wire_type::length_delimited:
      return archive.skip_length_delimited();
    case wire_type::fixed_64:
      return archive.skip(8);
    case wire_type::sgroup:
      return do_skip_group(field_num, archive);
    case wire_type::fixed_32:
      return archive.skip(4);
    default:
      return std::errc::result_out_of_range;
    }
  }

  constexpr static std::errc do_skip_group(uint32_t field_num, basic_in &archive) {
    while (archive.m_data.size()) {
      vuint32_t tag;
      if (auto result = archive(tag); result != std::errc{}) [[unlikely]] {
        return result;
      }
      const uint32_t next_field_num = tag_number(tag);
      const wire_type next_type = proto::tag_type(tag);

      if (next_type == wire_type::egroup && field_num == next_field_num) {
        return {};
      } else {
        return do_skip_field(next_field_num, next_type, archive);
      }
    }
    return std::errc::result_out_of_range;
  }

  constexpr static std::errc skip_tag(uint32_t tag, basic_in &archive) {
    vuint32_t t;
    if (auto result = archive(t); result != std::errc{}) [[unlikely]] {
      return result;
    }
    if (t != tag) [[unlikely]] {
      return std::errc::result_out_of_range;
    }
    return {};
  }

  template <typename T>
  constexpr static std::size_t count_packed_elements(uint32_t length, basic_in &archive) {

    if constexpr (concepts::byte_serializable<T>) {
      return length / sizeof(T);
    } else if constexpr (std::is_enum_v<T> || concepts::varint<T>) {
      auto data = archive.m_data.subspan(0, length);
      return std::count_if(data.begin(), data.end(), [](auto c) { return (static_cast<char>(c) & 0x80) == 0; });
    } else {
      static_assert(!sizeof(T));
    }
  }

  constexpr static std::errc count_unpacked_elements(uint32_t number, wire_type field_type, std::size_t &count,
                                                     basic_in archive) {
    const vuint32_t input_tag = make_tag(number, field_type);
    vuint32_t tag;

    do {
      if (auto result = do_skip_field(number, field_type, archive); result != std::errc{}) {
        return result;
      }

      ++count;

      if (archive.m_data.empty()) {
        return {};
      }

      if (auto result = archive(tag); result != std::errc{}) [[unlikely]] {
        return result;
      }
    } while (tag == input_tag);
    return {};
  }

  template <typename Meta>
  constexpr static std::errc deserialize_packed_repeated(Meta, wire_type, uint32_t, auto &&item, auto &context,
                                                         basic_in &archive) {
    using type = std::remove_reference_t<decltype(item)>;
    using value_type = typename type::value_type;

    decltype(auto) growable = make_growable(context, item);
    using element_type =
        std::conditional_t<std::same_as<typename Meta::type, void> || std::same_as<value_type, char> ||
                               std::same_as<value_type, std::byte> || std::same_as<typename Meta::type, type>,
                           value_type, typename Meta::type>;

    vuint64_t length;
    if (auto result = archive(length); result != std::errc{}) [[unlikely]] {
      return result;
    }

    if constexpr (requires { growable.resize(1); }) {
      // packed repeated vector,
      std::size_t size = count_packed_elements<element_type>(length, archive);
      growable.resize(size);

      using serialize_type = std::conditional_t<std::is_enum_v<value_type> && !std::same_as<value_type, std::byte>,
                                                vint64_t, element_type>;

      if constexpr (concepts::byte_serializable<serialize_type>) {
        return archive(growable);
      } else {
        for (auto &value : growable) {
          serialize_type underlying;
          if (auto result = archive(underlying); result != std::errc{}) [[unlikely]] {
            return result;
          }
          value = static_cast<element_type>(underlying.value);
        }
        return {};
      }
    } else if constexpr (std::is_same_v<type, std::string_view>) {
      // handling string_view
      auto data = archive.m_data;
      if (data.size() < length) {
        return std::errc::result_out_of_range;
      }
      item = std::string_view((const char *)data.data(), length);
      archive.skip(length);
    } else if constexpr ((std::is_same_v<value_type, char> ||
                          std::is_same_v<value_type, std::byte>)&&std::is_same_v<type, std::span<const value_type>>) {
      // handling bytes
      auto data = archive.m_data;
      if (data.size() < length) {
        return std::errc::result_out_of_range;
      }
      item = std::span<const value_type>((const value_type *)data.data(), length);
      archive.skip(length);
    } else if constexpr (requires { item.insert(value_type{}); }) {
      // packed repeated set
      auto fetch = [&]() constexpr {
        element_type value;

        if constexpr (std::is_enum_v<element_type>) {
          vint64_t underlying;
          if (auto result = archive(underlying); result != std::errc{}) [[unlikely]] {
            return result;
          }
          value = static_cast<element_type>(underlying.value);
        } else {
          // varint
          if (auto result = archive(value); result != std::errc{}) [[unlikely]] {
            return result;
          }
        }
        item.insert(value_type(value));
        return std::errc{};
      };

      auto end_position = length + archive.m_data.data();
      while (archive.m_data.data() < end_position) {
        if (auto result = fetch(); result != std::errc{}) [[unlikely]] {
          return result;
        }
      }
    } else {
      static_assert(concepts::has_memory_resource<decltype(context)>, "memory resource is required");
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

    constexpr std::errc deserialize(wire_type field_type, uint32_t field_num, auto &context, basic_in &archive) {
      if constexpr (concepts::scalar<base_value_type>) {
        return pb_deserializer::deserialize_field(Meta{}, field_type, field_num, element.value, context, archive);
      } else {
        return pb_deserializer::deserialize_sized(element.value, context, archive);
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
  constexpr static std::errc deserialize_unpacked_repeated(Meta, wire_type field_type, uint32_t field_num, auto &&item,
                                                           auto &context, basic_in &archive) {
    using type = std::remove_reference_t<decltype(item)>;

    decltype(auto) growable = make_growable(context, item);

    if constexpr (concepts::resizable_or_reservable<decltype(growable)>) {
      std::size_t count = 0;
      if (auto result = count_unpacked_elements(field_num, field_type, count, archive); result != std::errc{})
          [[unlikely]] {
        return result;
      }
      auto old_size = item.size();
      const std::size_t new_size = item.size() + count;

      resize_or_reserve(growable, new_size);

      for (auto i = old_size; i < new_size; ++i) {
        unpacked_element_inserter<Meta, std::remove_cvref_t<decltype(growable)>> inserter(growable, i);
        if (auto result = inserter.deserialize(field_type, field_num, context, archive); result != std::errc{})
            [[unlikely]] {
          return result;
        }

        if (i < new_size - 1) {
          if (auto result = skip_tag((field_num << 3 | (uint32_t)field_type), archive); result != std::errc{})
              [[unlikely]] {
            return result;
          }
        }
      }
    } else {
      unpacked_element_inserter<Meta, type> inserter{item};
      return inserter.deserialize(field_type, field_num, context, archive);
    }
    return {};
  }

  template <typename Meta>
  constexpr static std::errc deserialize_field(Meta meta, wire_type field_type, uint32_t field_num, auto &&item,
                                               auto &context, basic_in &archive) {
    using type = std::remove_reference_t<decltype(item)>;
    using serialize_type = typename traits::get_serialize_type<Meta, type>::type;

    if constexpr (std::is_enum_v<type>) {
      vint64_t value;
      if (auto result = archive(value); result != std::errc{}) [[unlikely]] {
        return result;
      }
      item = static_cast<type>(value.value);
    } else if constexpr (std::is_same_v<type, boolean>) {
      return archive(item.value);
    } else if constexpr (concepts::optional<type>) {
      if constexpr (requires { item.emplace(); }) {
        return deserialize_field(meta, field_type, field_num, item.emplace(), context, archive);
      } else {
        item = typename type::value_type{};
        return deserialize_field(meta, field_type, field_num, *item, context, archive);
      }
    } else if constexpr (concepts::unique_ptr<type>) {
      using element_type = std::remove_reference_t<decltype(*item)>;
      auto loaded = std::make_unique<element_type>();
      if (auto result = deserialize_field(meta, field_type, field_num, *loaded, context, archive);
          result != std::errc{}) [[unlikely]] {
        return result;
      }
      item.reset(loaded.release());
    } else if constexpr (std::is_pointer_v<type>) {
      static_assert(concepts::has_memory_resource<decltype(context)>, "memory resource is required");
      using element_type = std::remove_cvref_t<decltype(*item)>;
      void *buffer = context.memory_resource.allocate(sizeof(element_type), alignof(element_type));
      if (buffer == nullptr) [[unlikely]] {
        return std::errc::not_enough_memory;
      }
      auto loaded = new (buffer) element_type;
      if (auto result = deserialize_field(meta, field_type, field_num, *loaded, context, archive);
          result != std::errc{}) [[unlikely]] {
        return result;
      }
      item = loaded;
    } else if constexpr (concepts::oneof_type<type>) {
      static_assert(std::is_same_v<std::remove_cvref_t<decltype(std::get<0>(type{}))>, std::monostate>);
      return deserialize_oneof<0, typename Meta::alternatives_meta>(
          field_type, field_num, std::forward<decltype(item)>(item), context, archive);
    } else if constexpr (!std::is_same_v<type, serialize_type> && concepts::scalar<serialize_type> &&
                         !concepts::container<type>) {
      serialize_type value;
      if (auto result = deserialize_field(meta, field_type, field_num, value, context, archive); result != std::errc{})
          [[unlikely]] {
        return result;
      }
      if constexpr (std::is_arithmetic_v<type>) {
        item = static_cast<type>(value);
      } else {
        item = std::move(value);
      }
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
    } else if constexpr (concepts::string_or_bytes<type>) {
      return deserialize_packed_repeated(meta, field_type, field_num, std::forward<type>(item), context, archive);
    } else { // repeated non-group
      using value_type = typename type::value_type;
      if constexpr (concepts::numeric<value_type> && meta.encoding != encoding_rule::unpacked_repeated) {
        if (field_type != wire_type::length_delimited) {
          return deserialize_unpacked_repeated(meta, field_type, field_num, std::forward<type>(item), context, archive);
        }
        return deserialize_packed_repeated(meta, field_type, field_num, std::forward<type>(item), context, archive);
      } else {
        return deserialize_unpacked_repeated(meta, field_type, field_num, std::forward<type>(item), context, archive);
      }
    }
    return {};
  }

  constexpr static std::errc deserialize_group(uint32_t field_num, auto &&item, auto &context, basic_in &archive) {

    while (!archive.m_data.empty()) {
      vuint32_t tag;
      if (auto result = archive(tag); result != std::errc{}) [[unlikely]] {
        return result;
      }

      if (proto::tag_type(tag) == wire_type::egroup && field_num == tag_number(tag)) {
        return {};
      }

      if (auto result = deserialize_field_by_num(tag_number(tag), proto::tag_type(tag), item, context, archive);
          result != std::errc{}) [[unlikely]] {
        return result;
      }
    }

    return std::errc::result_out_of_range;
  }

  template <std::size_t Index, concepts::tuple Meta>
  constexpr static std::errc deserialize_oneof(wire_type field_type, uint32_t field_num, auto &&item, auto &context,
                                               basic_in &archive) {
    if constexpr (Index < std::tuple_size_v<Meta>) {
      using meta = typename std::tuple_element<Index, Meta>::type;
      if (meta::number == field_num) {
        if constexpr (requires { item.template emplace<Index + 1>(); }) {
          return deserialize_field(meta{}, field_type, field_num, item.template emplace<Index + 1>(), context, archive);
        } else {
          item = std::variant_alternative_t<Index + 1, std::decay_t<decltype(item)>>{};
          return deserialize_field(meta{}, field_type, field_num, std::get<Index + 1>(item), context, archive);
        }
      } else {
        return deserialize_oneof<Index + 1, Meta>(field_type, field_num, std::forward<decltype(item)>(item), context,
                                                  archive);
      }
    }
    return {};
  }

  template <std::size_t Index>
  constexpr static std::errc deserialize_field_by_index(uint32_t field_num, wire_type field_wire_type, auto &item,
                                                        auto &context, basic_in &archive) {
    using type = std::remove_reference_t<decltype(item)>;
    using Meta = typename traits::field_meta_of<type, Index>::type;
    if constexpr (requires { requires Meta::number == UINT32_MAX; }) {
      // this is extension, not a regular field
      return {};
    } else {
      return deserialize_field(Meta(), field_wire_type, field_num, Meta::access(item), context, archive);
    }
  }

  template <typename Type, typename Context, std::size_t... I>
  constexpr static auto deserialize_funs(std::index_sequence<I...>) {
    using deserialize_fun_ptr = std::errc (*)(uint32_t, wire_type, Type &, Context &, basic_in &);
    return std::array<deserialize_fun_ptr, sizeof...(I)>{&deserialize_field_by_index<I>...};
  }

  template <typename Type, typename Context>
  constexpr static auto deserialize_funs() {
    constexpr std::size_t num_members = traits::number_of_members<Type>;
    return deserialize_funs<Type, Context>(std::make_index_sequence<num_members>());
  }

  constexpr static std::errc deserialize_field_by_num(uint32_t field_num, wire_type field_wire_type, auto &item,
                                                      auto &context, basic_in &archive) {
    using type = std::remove_cvref_t<decltype(item)>;
    using context_type = std::remove_cvref_t<decltype(context)>;
    constexpr auto fun_ptrs = deserialize_funs<type, context_type>();
    auto index = traits::reverse_indices<type>::number_to_index(field_num);
    if (index) {
      return (*fun_ptrs[*index])(field_num, field_wire_type, item, context, archive);
    } else [[unlikely]] {
      return skip_field(field_num, field_wire_type, item, context, archive);
    }
  }

  constexpr static std::errc deserialize(concepts::has_meta auto &item, auto &context, basic_in &archive) {

    while (!archive.m_data.empty()) {
      vuint32_t tag;
      if (auto result = archive(tag); result != std::errc{}) [[unlikely]] {
        return result;
      }

      if (auto result = deserialize_field_by_num(tag_number(tag), proto::tag_type(tag), item, context, archive);
          result != std::errc{}) {
        [[unlikely]] return result;
      }
    }

    return {};
  }

  constexpr static std::errc deserialize_sized(auto &&item, auto &context, basic_in &archive) {
    vint64_t len;
    if (auto result = archive(len); result != std::errc{}) [[unlikely]] {
      return result;
    }
    if (len <= archive.m_data.size()) [[likely]] {
      basic_in new_archive{archive.m_data.subspan(0, len)};
      archive.skip(len);
      return deserialize(item, context, new_archive);
    }
    return std::errc::result_out_of_range;
  }

  constexpr static std::errc deserialize(concepts::has_meta auto &item, concepts::contiguous_byte_range auto &&buffer) {
    std::monostate context;
    basic_in archive(buffer);
    return deserialize(item, context, archive);
  }
};

} // namespace hpp::proto

struct GoogleMessage1SubMessage {
  int32_t field1 = {};
  int32_t field2 = {};
  int32_t field3 = {};
  std::string field15 = {};
  bool field12 = {};
  int64_t field13 = {};
  int64_t field14 = {};
  int32_t field16 = {};
  int32_t field19 = {};
  bool field20 = {};
  bool field28 = {};
  uint64_t field21 = {};
  int32_t field22 = {};
  bool field23 = {};
  bool field206 = {};
  uint32_t field203 = {};
  int32_t field204 = {};
  std::string field205 = {};
  uint64_t field207 = {};
  uint64_t field300 = {};

  bool operator==(const GoogleMessage1SubMessage &) const = default;
};

auto pb_meta(const GoogleMessage1SubMessage &) -> std::tuple<
    hpp::proto::field_meta<1, &GoogleMessage1SubMessage::field1, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<2, &GoogleMessage1SubMessage::field2, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<3, &GoogleMessage1SubMessage::field3, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<15, &GoogleMessage1SubMessage::field15, hpp::proto::encoding_rule::defaulted>,
    hpp::proto::field_meta<12, &GoogleMessage1SubMessage::field12, hpp::proto::encoding_rule::defaulted, bool>,
    hpp::proto::field_meta<13, &GoogleMessage1SubMessage::field13, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<14, &GoogleMessage1SubMessage::field14, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<16, &GoogleMessage1SubMessage::field16, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<19, &GoogleMessage1SubMessage::field19, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<20, &GoogleMessage1SubMessage::field20, hpp::proto::encoding_rule::defaulted, bool>,
    hpp::proto::field_meta<28, &GoogleMessage1SubMessage::field28, hpp::proto::encoding_rule::defaulted, bool>,
    hpp::proto::field_meta<21, &GoogleMessage1SubMessage::field21, hpp::proto::encoding_rule::defaulted>,
    hpp::proto::field_meta<22, &GoogleMessage1SubMessage::field22, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<23, &GoogleMessage1SubMessage::field23, hpp::proto::encoding_rule::defaulted, bool>,
    hpp::proto::field_meta<206, &GoogleMessage1SubMessage::field206, hpp::proto::encoding_rule::defaulted, bool>,
    hpp::proto::field_meta<203, &GoogleMessage1SubMessage::field203, hpp::proto::encoding_rule::defaulted>,
    hpp::proto::field_meta<204, &GoogleMessage1SubMessage::field204, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vint64_t>,
    hpp::proto::field_meta<205, &GoogleMessage1SubMessage::field205, hpp::proto::encoding_rule::defaulted>,
    hpp::proto::field_meta<207, &GoogleMessage1SubMessage::field207, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vuint64_t>,
    hpp::proto::field_meta<300, &GoogleMessage1SubMessage::field300, hpp::proto::encoding_rule::defaulted,
                           hpp::proto::vuint64_t>>;

void expect_impl(bool predicate, const char *filename, int lineno) {
  if (!predicate) {
    std::cerr << "expectation failed: " << filename << '(' << lineno << ") `\n";
  }
}

#define expect(...) expect_impl(__VA_ARGS__, __FILE__, __LINE__)

// void verify_basic_out() {
//     using namespace hpp::proto;
//     {
//         std::array<std::byte, 4> data1;
//         basic_out<std::byte> out{data1};
//         out(1);
//         expect(out.m_data.empty());
//         expect("\x01\x00\x00\x00"_cts == data1);
//     }
//     {
//         std::array<std::byte, 2> data1;
//         basic_out<std::byte> out{data1};
//         out(varint{150});
//         expect(out.m_data.empty());
//         expect("\x96\x01"_cts == data1);
//     }
//     {
//         std::array<std::byte, 8> data1;
//         basic_out<std::byte> out{data1};
//         out(std::array{1, 2});
//         expect(out.m_data.empty());
//         expect("\x01\x00\x00\x00\x02\x00\x00\x00"_cts == data1);
//     }

//     constexpr std::string_view a = "abc"_cts;
//     constexpr std::span<const std::byte> b = "abc"_cts;
//     std::span<const std::byte> c = "abc"_cts;
// }
using namespace hpp::proto;

struct example {
  int32_t i; // field number == 1

  constexpr bool operator==(const example &) const = default;
};
auto pb_meta(const example &) -> std::tuple<hpp::proto::field_meta<1, &example::i, encoding_rule::defaulted, vint64_t>>;

struct nested_example {
  example nested; // field number == 1
  constexpr bool operator==(const nested_example &) const = default;
};
auto pb_meta(const nested_example &) -> std::tuple<hpp::proto::field_meta<1, &nested_example::nested>>;

struct example_default_type {
  int32_t i = 1; // field number == 1

  constexpr bool operator==(const example_default_type &) const = default;
};

auto pb_meta(const example_default_type &)
    -> std::tuple<hpp::proto::field_meta<1, &example_default_type::i, encoding_rule::defaulted, vint64_t, 1>>;

struct example_optional_type {
  hpp::proto::optional<int32_t, 1> i; // field number == 1

  constexpr bool operator==(const example_optional_type &) const = default;
};

auto pb_meta(const example_optional_type &)
    -> std::tuple<hpp::proto::field_meta<1, &example_optional_type::i, encoding_rule::explicit_presence, vint64_t>>;

struct repeated_enum {
  enum class NestedEnum { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
  std::vector<NestedEnum> values;
  bool operator==(const repeated_enum &) const = default;
};

auto pb_meta(const repeated_enum &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_enum::values, encoding_rule::packed_repeated>>;

struct repeated_enum_unpacked {
  enum class NestedEnum { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
  std::vector<NestedEnum> values;
  bool operator==(const repeated_enum_unpacked &) const = default;
};

auto pb_meta(const repeated_enum_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_enum_unpacked::values, encoding_rule::unpacked_repeated>>;

struct repeated_fixed {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed &) const = default;
};

auto pb_meta(const repeated_fixed &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_fixed::integers, encoding_rule::packed_repeated>>;

struct repeated_fixed_unpacked {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed_unpacked &) const = default;
};

auto pb_meta(const repeated_fixed_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_fixed_unpacked::integers, encoding_rule::unpacked_repeated>>;
struct repeated_integers {
  std::vector<int32_t> integers;
  bool operator==(const repeated_integers &) const = default;
};

auto pb_meta(const repeated_integers &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_integers::integers, encoding_rule::packed_repeated, vsint32_t>>;

struct repeated_integers_unpacked {
  std::vector<vsint32_t> integers;
  bool operator==(const repeated_integers_unpacked &) const = default;
};

auto pb_meta(const repeated_integers_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_integers_unpacked::integers, encoding_rule::unpacked_repeated>>;

struct repeated_bool {
  std::vector<hpp::proto::boolean> booleans;
  bool operator==(const repeated_bool &) const = default;
};

auto pb_meta(const repeated_bool &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_bool::booleans, encoding_rule::packed_repeated, bool>>;

struct repeated_bool_unpacked {
  std::vector<hpp::proto::boolean> booleans;
  bool operator==(const repeated_bool_unpacked &) const = default;
};

auto pb_meta(const repeated_bool_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_bool_unpacked::booleans, encoding_rule::unpacked_repeated, bool>>;

enum class color_t { red, blue, green };

struct map_example {
  std::map<int32_t, color_t> dict;
  bool operator==(const map_example &) const = default;
};

auto pb_meta(const map_example &)
    -> std::tuple<hpp::proto::field_meta<1, &map_example::dict, encoding_rule::unpacked_repeated,
                                         hpp::proto::map_entry<vint64_t, color_t>>>;

struct oneof_example {
  std::variant<std::monostate, std::string, int32_t, color_t> value;
  bool operator==(const oneof_example &) const = default;
};

auto pb_meta(const oneof_example &) -> std::tuple<
    hpp::proto::oneof_field_meta<&oneof_example::value, hpp::proto::field_meta<1, 1, encoding_rule::explicit_presence>,
                                 hpp::proto::field_meta<2, 2, encoding_rule::explicit_presence, vint64_t>,
                                 hpp::proto::field_meta<3, 3, encoding_rule::explicit_presence>>>;

struct recursive_type1 {
  hpp::proto::heap_based_optional<recursive_type1> child;
  uint32_t payload = {};

  bool operator==(const recursive_type1 &other) const = default;

#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARATOR
  friend auto operator<=>(const recursive_type1 &, const recursive_type1 &) = default;
#endif
};

auto pb_meta(const recursive_type1 &)
    -> std::tuple<hpp::proto::field_meta<1, &recursive_type1::child>,
                  hpp::proto::field_meta<2, &recursive_type1::payload, encoding_rule::defaulted, vint64_t>>;

struct group {
  uint32_t a;
  bool operator==(const group &) const = default;
};

auto pb_meta(const group &) -> std::tuple<hpp::proto::field_meta<2, &group::a, encoding_rule::defaulted, vint64_t>>;

struct repeated_group {
  std::vector<group> repeatedgroup;
  bool operator==(const repeated_group &) const = default;
};

auto pb_meta(const repeated_group &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_group::repeatedgroup, encoding_rule::group>>;

struct string_example {
  std::string value;
  bool operator==(const string_example &) const = default;
};

auto pb_meta(const string_example &)
    -> std::tuple<hpp::proto::field_meta<1, &string_example::value, encoding_rule::defaulted>>;

struct string_with_default {
  std::string value = "test";
  bool operator==(const string_with_default &) const = default;
};
auto pb_meta(const string_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, &string_with_default::value, encoding_rule::defaulted, void, "test"_cts>>;

struct string_with_optional {
  hpp::proto::optional<std::string, "test"_cts> value;
  bool operator==(const string_with_optional &) const = default;
};
auto pb_meta(const string_with_optional &)
    -> std::tuple<hpp::proto::field_meta<1, &string_with_optional::value, encoding_rule::explicit_presence>>;

struct repeated_examples {
  std::vector<example> examples;
  bool operator==(const repeated_examples &) const = default;
};

auto pb_meta(const repeated_examples &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_examples::examples, encoding_rule::unpacked_repeated>>;

template <typename T>
std::string to_hex(const T &data) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string result;
  result.resize(data.size() * 2);
  int index = 0;
  for (auto b : data) {
    unsigned char c = static_cast<unsigned char>(b);
    result[index++] = qmap[c >> 4];
    result[index++] = qmap[c & '\x0F'];
  }
  return result;
}

consteval auto to_pb_bytes(auto ObjectLambda) {
  constexpr auto sz = hpp::proto::pb_serializer::message_size(ObjectLambda());
  if constexpr (sz == 0) {
    return std::span<std::byte>{};
  } else {
    std::array<std::byte, sz> buffer;
    hpp::proto::pb_serializer::serialize(ObjectLambda(), buffer);
    return buffer;
  }
}

template <typename T>
constexpr auto from_pb_bytes(auto &&buffer) {
  T obj;
  auto ec = pb_deserializer::deserialize(obj, buffer);
  if (ec != std::errc{})
    throw std::system_error(std::make_error_code(ec));
  return obj;
}

template <typename T>
constexpr auto from_pb_bytes1(auto &&buffer) {
  T obj;
  auto ec = pb_deserializer::deserialize(obj, buffer());
  if (ec != std::errc{})
    throw std::system_error(std::make_error_code(ec));
  return obj;
}

#define carg(...) ([]() constexpr -> decltype(auto) { return __VA_ARGS__; })

void verify_basic_in() {
  using namespace hpp::proto;

  auto verify = [](auto expected_value, std::span<const std::byte> data) {
    pb_deserializer::basic_in in{data};
    decltype(expected_value) value;
    expect(in(value) == std::errc{});
    if constexpr (requires { expected_value.size(); }) {
      expect(std::ranges::equal(value, expected_value));
    } else {
      expect(value == expected_value);
    }
    expect(in.m_data.empty());
  };

  verify(1, "\x01\x00\x00\x00"_cts);
  verify(varint{150}, "\x96\x01"_cts);
  verify(std::array{1, 2}, "\x01\x00\x00\x00\x02\x00\x00\x00"_cts);
}

constexpr void constexpr_verify(auto buffer, auto object_fun) {
  static_assert(std::ranges::equal(buffer(), to_pb_bytes(object_fun)));
  static_assert(object_fun() == from_pb_bytes<decltype(object_fun())>(buffer()));
}

int main() {
  verify_basic_in();

  GoogleMessage1SubMessage msg;
  msg.field1 = 1;
  msg.field15 = "abc";
  msg.field206 = true;

  hpp::proto::pb_serializer ser;
  expect(ser.message_size(msg) == 10);

  pb_deserializer deserializer;

  constexpr_verify(carg("\x08\x96\x01"_bytes_view), carg(example{150}));
  static_assert(to_pb_bytes(carg(example{})).empty());

  constexpr_verify(carg("\x0a\x03\x08\x96\x01"_bytes_view), carg(nested_example{.nested = example{150}}));

  static_assert(to_pb_bytes(carg(example_default_type{})).empty());

#if defined(__cpp_lib_constexpr_vector) && (__cpp_lib_constexpr_vector >= 201907L)
  {
    using enum repeated_enum::NestedEnum;
    constexpr_verify(carg("\x0a\x0d\x01\x02\x03\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_view),
                     carg(repeated_enum{{FOO, BAR, BAZ, NEG}}));
  }
  {
    using enum repeated_enum_unpacked::NestedEnum;
    constexpr_verify(carg("\x08\x01\x08\x02\x08\x03\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_view),
                     carg(repeated_enum_unpacked{{FOO, BAR, BAZ, NEG}}));
  }

  constexpr_verify(
      carg(
          "\x0a\x18\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_view),
      carg(repeated_fixed{{1, 2, 3}}));

  constexpr_verify(
      carg(
          "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_view),
      carg(repeated_fixed_unpacked{{1, 2, 3}}));

  constexpr_verify(carg("\x0a\x09\x00\x02\x04\x06\x08\x01\x03\x05\x07"_bytes_view),
                   carg(repeated_integers{{0, 1, 2, 3, 4, -1, -2, -3, -4}}));

  constexpr_verify(carg("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x00\x08\x01\x08\x03\x08\x05\x08\x07"_bytes_view),
                   carg(repeated_integers_unpacked{{1, 2, 3, 4, 0, -1, -2, -3, -4}}));

  constexpr_verify(carg("\x0a\x03\x01\x00\x01"_bytes_view), carg(repeated_bool{{true, false, true}}));

  constexpr_verify(carg("\x08\x01\x08\x00\x08\x01"_bytes_view), carg(repeated_bool_unpacked{{true, false, true}}));

  constexpr_verify(carg("\x0b\x10\x01\x0c\x0b\x10\x02\x0c"_bytes_view),
                   carg(repeated_group{.repeatedgroup = {{1}, {2}}}));

  constexpr_verify(carg("\x0a\x02\x08\x01\x0a\x02\x08\x02\x0a\x02\x08\x03\x0a\x02\x08\x04"
                        "\x0a\x0b\x08\xff\xff\xff\xff\xff\xff"
                        "\xff\xff\xff\x01\x0a\x0b\x08\xfe\xff\xff\xff\xff\xff\xff\xff\xff"
                        "\x01\x0a\x0b\x08\xfd\xff\xff\xff\xff"
                        "\xff\xff\xff\xff\x01\x0a\x0b\x08\xfc\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_view),
                   carg(repeated_examples{.examples = {{1}, {2}, {3}, {4}, {-1}, {-2}, {-3}, {-4}}}));
#endif
#if defined(__cpp_lib_constexpr_string) && (__cpp_lib_constexpr_string >= 201907L)

  constexpr_verify(carg(""_bytes_view), carg(string_example{}));
#if defined(__cpp_lib_variant) && (__cpp_lib_variant >= 202106L)
  constexpr_verify(carg("\x0a\x04\x74\x65\x73\x74"_bytes_view), carg(string_with_optional{.value = "test"}));

  constexpr_verify(carg(""_bytes_view), carg(oneof_example{}));

  constexpr_verify(carg("\x0a\x04\x74\x65\x73\x74"_bytes_view), carg(oneof_example{.value = "test"}));
  constexpr_verify(carg("\x10\x05"_bytes_view), carg(oneof_example{.value = 5}));
  constexpr_verify(carg("\x10\x00"_bytes_view), carg(oneof_example{.value = 0}));
  constexpr_verify(carg("\x18\x02"_bytes_view), carg(oneof_example{.value = color_t::green}));
#endif
#endif
  {
    recursive_type1 child;
    child.payload = 2;
    recursive_type1 value, value2;
    value.child = child;
    value.payload = 1;

    std::vector<std::byte> data;
    ser.serialize(value, data);

    expect("\x0a\x02\x10\x02\x10\x01"_cts == data);

    expect(pb_deserializer::deserialize(value2, "\x0a\x02\x10\x02\x10\x01"_bytes_view) == std::errc{});
    expect(value == value2);
  }

  {
    std::vector<std::byte> data;
    map_example value{{{1, color_t::red}, {2, color_t::blue}, {3, color_t::green}}};
    const auto encoded = "\x0a\x04\x08\x01\x10\x00\x0a\x04\x08\x02\x10\x01\x0a\x04\x08\x03\x10\x02"_bytes_view;

    ser.serialize(value, data);
    expect(std::ranges::equal(encoded, data));

    map_example value2;
    expect(pb_deserializer::deserialize(value2, encoded) == std::errc{});
    expect(value == value2);
  }
}