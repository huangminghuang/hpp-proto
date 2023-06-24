#include <boost/ut.hpp>
#include <hpp_proto/hpp_proto.h>

namespace ut = boost::ut;
using namespace zpp::bits::literals;
using hpp::proto::encoding_rule;

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

template <zpp::bits::string_literal String>
constexpr auto operator""_bytes_array() {
  return zpp::bits::to_bytes<String>();
}

struct example {
  int32_t i; // field number == 1

  constexpr bool operator==(const example &) const = default;
};
auto pb_meta(const example &) -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, zpp::bits::vint64_t>>;

static_assert(hpp::proto::to_bytes<example{150}>() == "089601"_decode_hex);

static_assert(hpp::proto::from_bytes<"089601"_decode_hex, example>().i == 150);

static_assert(hpp::proto::to_bytes<example{}>().size() == 0);

static_assert(hpp::proto::from_bytes<std::array<std::byte, 0>{}, example>().i == 0);
struct nested_example {
  example nested; // field number == 1
};

static_assert(hpp::proto::to_bytes<nested_example{.nested = example{150}}>() == "0a03089601"_decode_hex);

static_assert(hpp::proto::from_bytes<"0a03089601"_decode_hex, nested_example>().nested.i == 150);

using namespace zpp::bits::literals;

struct example_explicit_presence {
  int32_t i; // field number == 1

  constexpr bool operator==(const example_explicit_presence &) const = default;
};

auto pb_meta(const example_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence, zpp::bits::vint64_t>>;

static_assert(hpp::proto::to_bytes<example_explicit_presence{}>() == "0800"_decode_hex);

static_assert(hpp::proto::from_bytes<"0800"_decode_hex, example_explicit_presence>().i == 0);

struct example_default_type {
  int32_t i = 1; // field number == 1

  constexpr bool operator==(const example_default_type &) const = default;
};

auto serialize(const example_default_type &) -> zpp::bits::members<1>;

auto pb_meta(const example_default_type &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, zpp::bits::vint64_t, 1>>;

static_assert(hpp::proto::to_bytes<example_default_type{}>().size() == 0);

ut::suite test_example_default_type = [] {
  auto [data, in, out] = hpp::proto::data_in_out(zpp::bits::no_size{});
  example_default_type v;
  ut::expect(success(out(v)));
  ut::expect(data.size() == 0);
};

static_assert(hpp::proto::from_bytes<std::array<std::byte, 0>{}, example_default_type>().i == 1);

struct example_optioanl_type {
  hpp::proto::optional<int32_t, 1> i; // field number == 1

  constexpr bool operator==(const example_optioanl_type &) const = default;
};

auto serialize(const example_optioanl_type &) -> zpp::bits::members<1>;

auto pb_meta(const example_optioanl_type &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence, zpp::bits::vint64_t>>;

// static_assert(hpp::proto::to_bytes<example_optioanl_type{}>().size() == 0);

struct nested_explicit_id_example {
  example nested{}; // field number == 3
};

auto pb_meta(const nested_explicit_id_example &) -> std::tuple<hpp::proto::field_meta<3>>;

//// doesn't work with zpp::bits::unsized_t
static_assert(hpp::proto::to_bytes<nested_explicit_id_example{.nested = example{150}}>() == "1a03089601"_decode_hex);
static_assert(hpp::proto::from_bytes<"1a03089601"_decode_hex, nested_explicit_id_example>().nested.i == 150);

enum test_mode { decode_encode, decode_only };

template <typename T>
void verify(auto encoded_data, T &&expected_value, test_mode mode = decode_encode) {
  std::remove_cvref_t<T> value;

  ut::expect(success(hpp::proto::in{encoded_data}(value)));
  ut::expect(value == expected_value);

  if (mode == decode_only)
    return;

  std::array<std::byte, encoded_data.size()> new_data;
  ut::expect(success(hpp::proto::out{new_data}(value)));

  ut::expect(encoded_data == new_data);
}

struct repeated_integers {
  std::vector<int32_t> integers;
  bool operator==(const repeated_integers &) const = default;
};

auto pb_meta(const repeated_integers &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, zpp::bits::vsint32_t>>;

struct repeated_integers_unpacked {
  std::vector<zpp::bits::vsint32_t> integers;
  bool operator==(const repeated_integers_unpacked &) const = default;
};

auto pb_meta(const repeated_integers_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated>>;

struct repeated_integers_unpacked_explicit_type {
  std::vector<int32_t> integers;
  bool operator==(const repeated_integers_unpacked_explicit_type &) const = default;
};

auto pb_meta(const repeated_integers_unpacked_explicit_type &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated, zpp::bits::vsint32_t>>;
using namespace boost::ut::literals;

ut::suite test_repeated_integers = [] {
  "repeated_integers"_test = [] {
    verify("\x0a\x09\x00\x02\x04\x06\x08\x01\x03\x05\x07"_bytes_array,
           repeated_integers{{0, 1, 2, 3, 4, -1, -2, -3, -4}});
  };

  "repeated_integers_unpacked"_test = [] {
    verify("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x01\x08\x03\x08\x05\x08\x07"_bytes_array,
           repeated_integers_unpacked{{1, 2, 3, 4, -1, -2, -3, -4}});
  };

  "repeated_integers_unpacked_decode"_test = [] {
    verify("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x01\x08\x03\x08\x05\x08\x07"_bytes_array,
           repeated_integers{{1, 2, 3, 4, -1, -2, -3, -4}}, decode_only);
  };

  "repeated_integers_unpacked_explicit_type"_test = [] {
    verify("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x01\x08\x03\x08\x05\x08\x07"_bytes_array,
           repeated_integers_unpacked_explicit_type{{1, 2, 3, 4, -1, -2, -3, -4}});
  };
};

struct repeated_fixed {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed &) const = default;
};
struct repeated_fixed_explicit_type {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed_explicit_type &) const = default;
};

auto pb_meta(const repeated_fixed_explicit_type &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, uint64_t>>;
struct repeated_fixed_unpacked {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed_unpacked &) const = default;
};

auto pb_meta(const repeated_fixed_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated>>;

struct repeated_fixed_unpacked_explicit_type {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed_unpacked_explicit_type &) const = default;
};

auto pb_meta(const repeated_fixed_unpacked_explicit_type &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated, uint64_t>>;

using namespace boost::ut::literals;

ut::suite test_repeated_fixed = [] {
  "repeated_fixed"_test = [] {
    verify(
        "\x0a\x18\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_array,
        repeated_fixed{{1, 2, 3}});
  };

  "repeated_fixed_explicit_type"_test = [] {
    verify(
        "\x0a\x18\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_array,
        repeated_fixed_explicit_type{{1, 2, 3}});
  };

  "repeated_fixed_unpacked"_test = [] {
    verify(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_array,
        repeated_fixed_unpacked{{1, 2, 3}});
  };

  "repeated_fixed_unpacked_decode"_test = [] {
    verify(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_array,
        repeated_fixed{{1, 2, 3}}, decode_only);
  };

  "repeated_fixed_unpacked_explicit_type_decode"_test = [] {
    verify(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_array,
        repeated_fixed_explicit_type{{1, 2, 3}}, decode_only);
  };

  "repeated_fixed_unpacked_explicit_type"_test = [] {
    verify(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_array,
        repeated_fixed_unpacked_explicit_type{{1, 2, 3}});
  };
};

struct repeated_bool {
  std::vector<hpp::proto::boolean> booleans;
  bool operator==(const repeated_bool &) const = default;
};

auto pb_meta(const repeated_bool &) -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, bool>>;

struct repeated_bool_unpacked {
  std::vector<hpp::proto::boolean> booleans;
  bool operator==(const repeated_bool_unpacked &) const = default;
};

auto pb_meta(const repeated_bool_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated, bool>>;

ut::suite test_repeated_bool = [] {
  "repeated_bool"_test = [] { verify("\x0a\x03\x01\x00\x01"_bytes_array, repeated_bool{{true, false, true}}); };

  "repeated_bool_unpacked"_test = [] {
    verify("\x08\x01\x08\x00\x08\x01"_bytes_array, repeated_bool_unpacked{{true, false, true}});
  };
};

struct repeated_enum {
  enum class NestedEnum { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
  std::vector<NestedEnum> values;
  bool operator==(const repeated_enum &) const = default;
};

auto pb_meta(const repeated_enum &) -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted>>;

struct repeated_enum_unpacked {
  enum class NestedEnum { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
  std::vector<NestedEnum> values;
  bool operator==(const repeated_enum_unpacked &) const = default;
};

auto pb_meta(const repeated_enum_unpacked &) -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated>>;

ut::suite test_repeated_enums = [] {
  {
    using enum repeated_enum::NestedEnum;
    "repeated_enum"_test = [] {
      verify("\x0a\x0d\x01\x02\x03\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_array,
             repeated_enum{{FOO, BAR, BAZ, NEG}});
    };
  }
  {
    using enum repeated_enum_unpacked::NestedEnum;
    "repeated_enum_unpacked"_test = [] {
      verify("\x08\x01\x08\x02\x08\x03\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_array,
             repeated_enum_unpacked{{FOO, BAR, BAZ, NEG}});
    };
  }
};

struct repeated_examples {
  std::vector<example> examples;
  bool operator==(const repeated_examples &) const = default;
};

ut::suite test_repeated_example = [] {
  auto [data, in, out] = hpp::proto::data_in_out();
  out(repeated_examples{.examples = {{1}, {2}, {3}, {4}, {-1}, {-2}, {-3}, {-4}}}).or_throw();

  repeated_examples r;
  in(r).or_throw();

  ut::expect(r.examples == (std::vector<example>{{1}, {2}, {3}, {4}, {-1}, {-2}, {-3}, {-4}}));
};

struct group {
  uint32_t a;
  bool operator==(const group &) const = default;
};

auto pb_meta(const group &) -> std::tuple<hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>>;

struct repeated_group {
  std::vector<group> repeatedgroup;
  bool operator==(const repeated_group &) const = default;
};

auto pb_meta(const repeated_group &) -> std::tuple<hpp::proto::field_meta<1, encoding_rule::group>>;

ut::suite test_repeated_group = [] {
  auto [data, in, out] = hpp::proto::data_in_out();
  out(repeated_group{.repeatedgroup = {{1}, {2}}}).or_throw();

  repeated_group r;
  in(r).or_throw();

  ut::expect(r.repeatedgroup == (std::vector<group>{{1}, {2}}));
};

enum class color_t { red, blue, green };

struct map_example {
  hpp::proto::flat_map<int32_t, color_t> dict;
  bool operator==(const map_example &) const = default;
};

auto pb_meta(const map_example &) -> std::tuple<
    hpp::proto::field_meta<1, encoding_rule::defaulted, hpp::proto::map_entry<zpp::bits::vint64_t, color_t>>>;

ut::suite test_map_example = [] {
  "map_example"_test = [] {
    verify("\x0a\x04\x08\x01\x10\x00\x0a\x04\x08\x02\x10\x01\x0a\x04\x08\x03\x10\x02"_bytes_array,
           map_example{{{1, color_t::red}, {2, color_t::blue}, {3, color_t::green}}});
  };
};

struct string_example {
  std::string value;
  bool operator==(const string_example &) const = default;
};

struct string_explicit_presence {
  std::string value;
  bool operator==(const string_explicit_presence &) const = default;
};

auto pb_meta(const string_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence>>;

using namespace hpp::proto::literals;

struct string_with_default {
  std::string value = "test";
  bool operator==(const string_with_default &) const = default;
};
auto pb_meta(const string_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, void, "test"_hppproto_s>>;

auto serialize(const string_with_default &) -> zpp::bits::members<1>;

struct string_with_optional {
  hpp::proto::optional<std::string, "test"_hppproto_s> value;
  bool operator==(const string_with_optional &) const = default;
};
auto pb_meta(const string_with_optional &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence, void>>;

auto serialize(const string_with_optional &) -> zpp::bits::members<1>;

ut::suite test_string_example = [] {
  "string_example"_test = [] { verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, string_example{.value = "test"}); };

  "string_explicit_presence"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, string_explicit_presence{.value = "test"});
  };

  "string_with_default_empty"_test = [] { verify(std::array<std::byte, 0>{}, string_with_default{}); };

  "string_with_default"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, string_with_default{.value = "test"}, decode_only);
  };

  "string_with_optional"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, string_with_optional{.value = "test"});
  };

  "optional_value_access"_test = [] {
    string_with_optional v;
    ut::expect(v.value.value_or_default() == "test");
  };
};

struct string_view_example {
  std::string_view value;
  bool operator==(const string_view_example &) const = default;
};

struct string_view_explicit_presence {
  std::string_view value;
  bool operator==(const string_view_explicit_presence &) const = default;
};

auto pb_meta(const string_view_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence>>;

struct string_view_with_default {
  std::string_view value = "test";
  bool operator==(const string_view_with_default &) const = default;
};
auto pb_meta(const string_view_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, void, "test"_hppproto_s>>;

auto serialize(const string_view_with_default &) -> zpp::bits::members<1>;

struct string_view_with_optional {
  hpp::proto::optional<std::string_view, "test"_hppproto_s> value;
  bool operator==(const string_view_with_optional &) const = default;
};
auto pb_meta(const string_view_with_optional &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence>>;

auto serialize(const string_view_with_optional &) -> zpp::bits::members<1>;

ut::suite test_string_view_example = [] {
  "string_view_example"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, string_view_example{.value = "test"});
  };

  "string_view_explicit_presence"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, string_view_explicit_presence{.value = "test"});
  };

  "string_view_with_default_empty"_test = [] { verify(std::array<std::byte, 0>{}, string_view_with_default{}); };

  "string_view_with_default"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, string_view_with_default{.value = "test"}, decode_only);
  };

  "string_view_with_optional"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, string_view_with_optional{.value = "test"});
  };

  "optional_value_access"_test = [] {
    string_view_with_optional v;
    ut::expect(v.value.value_or_default() == "test");
  };
};

struct bytes_example {
  std::vector<std::byte> value;
  bool operator==(const bytes_example &) const = default;
};

struct bytes_explicit_presence {
  std::vector<std::byte> value;
  bool operator==(const bytes_explicit_presence &) const = default;
};

auto pb_meta(const bytes_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence>>;


struct bytes_with_default {
  std::vector<std::byte> value = "test"_bytes;
  bool operator==(const bytes_with_default &) const = default;
};

auto pb_meta(const bytes_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, void, "test"_hppproto_s>>;


auto serialize(const bytes_with_default &) -> zpp::bits::members<1>;

struct bytes_with_optional {
  hpp::proto::optional<std::vector<std::byte>, "test"_hppproto_s> value;
  bool operator==(const bytes_with_optional &) const = default;
};

auto pb_meta(const bytes_with_optional &) -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence>>;

auto serialize(const bytes_with_optional &) -> zpp::bits::members<1>;

ut::suite test_bytes = [] {
  const static auto verified_value =
      std::vector<std::byte>{std::byte{0x74}, std::byte{0x65}, std::byte{0x73}, std::byte{0x74}};

  "bytes_example"_test = [] { verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, bytes_example{.value = verified_value}); };

  "bytes_explicit_presence"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, bytes_explicit_presence{.value = verified_value});
  };

  "bytes_with_default_empty"_test = [] { verify(std::array<std::byte, 0>{}, bytes_with_default{}); };

  "bytes_with_default"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, bytes_with_default{.value = verified_value}, decode_only);
  };

  "bytes_with_optional"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, bytes_with_optional{.value = verified_value});
  };

  "optional_value_access"_test = [] {
    bytes_with_optional v;
    ut::expect(v.value.value_or_default() == verified_value);
  };
};

struct char_vector_example {
  std::vector<char> value;
  bool operator==(const char_vector_example &) const = default;
};

struct char_vector_explicit_presence {
  std::vector<char> value;
  bool operator==(const char_vector_explicit_presence &) const = default;
};

auto pb_meta(const bytes_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence>>;

struct char_vector_with_default {
  std::vector<char> value = {'t', 'e', 's', 't'};
  bool operator==(const char_vector_with_default &) const = default;
};

auto pb_meta(const char_vector_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, void, "test"_hppproto_s>>;

auto serialize(const char_vector_with_default &) -> zpp::bits::members<1>;

struct char_vector_with_optional {
  hpp::proto::optional<std::vector<char>, "test"_hppproto_s> value;
  bool operator==(const char_vector_with_optional &) const = default;
};

auto pb_meta(const char_vector_with_optional &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence>>;

auto serialize(const char_vector_with_optional &) -> zpp::bits::members<1>;

ut::suite test_char_vector = [] {
  const static auto verified_value = std::vector<char>{'t', 'e', '\0', 't'};

  "char_vector_example"_test = [] {
    verify("\x0a\x04\x74\x65\x00\x74"_bytes_array, char_vector_example{.value = verified_value});
  };

  "char_vector_explicit_presence"_test = [] {
    verify("\x0a\x04\x74\x65\x00\x74"_bytes_array, char_vector_explicit_presence{.value = verified_value});
  };

  "char_vector_with_default_empty"_test = [] { verify(std::array<std::byte, 0>{}, char_vector_with_default{}); };

  "char_vector_with_default"_test = [] {
    verify("\x0a\x04\x74\x65\x00\x74"_bytes_array, char_vector_with_default{.value = verified_value});
  };

  "char_vector_with_optional"_test = [] {
    verify("\x0a\x04\x74\x65\x00\x74"_bytes_array, char_vector_with_optional{.value = verified_value});
  };

  "optional_value_access"_test = [] {
    char_vector_with_optional v;
    ut::expect(v.value.value_or_default() == std::vector<char>{'t', 'e', 's', 't'});
  };
};

struct byte_span_example {
  std::span<const std::byte> value;
  bool operator==(const byte_span_example &other) const {
    return std::equal(value.begin(), value.end(), other.value.begin(), other.value.end());
  }
};

struct byte_span_explicit_presence {
  std::span<const std::byte> value;
  bool operator==(const byte_span_explicit_presence &other) const {
    return std::equal(value.begin(), value.end(), other.value.begin(), other.value.end());
  }
};

auto pb_meta(const byte_span_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence>>;

struct byte_span_with_default {
  std::span<const std::byte> value = "test"_bytes_span;
  bool operator==(const byte_span_with_default &other) const {
    return std::equal(value.begin(), value.end(), other.value.begin(), other.value.end());
  }
};

auto pb_meta(const byte_span_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, void, "test"_hppproto_s>>;

auto serialize(const byte_span_with_default &) -> zpp::bits::members<1>;

struct byte_span_with_optional {
  hpp::proto::optional<std::span<const std::byte>, "test"_hppproto_s> value;
  bool operator==(const byte_span_with_optional &other) const {
    return (!value.has_value() && !other.value.has_value()) ||
           (value.has_value() && other.value.has_value() &&
            std::equal(value->begin(), value->end(), other.value->begin(), other.value->end()));
  }
};

auto pb_meta(const byte_span_with_optional &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence>>;

auto serialize(const byte_span_with_optional &) -> zpp::bits::members<1>;

ut::suite test_byte_span = [] {
  static const std::byte verified_value[] = {std::byte{0x74}, std::byte{0x65}, std::byte{0x73}, std::byte{0x74}};

  "byte_span_example"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, byte_span_example{.value = verified_value});
  };

  "byte_span_explicit_presence"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, byte_span_explicit_presence{.value = verified_value});
  };

  "byte_span_with_default_empty"_test = [] { verify(std::array<std::byte, 0>{}, byte_span_with_default{}); };

  "byte_span_with_optional_empty"_test = [] { verify(std::array<std::byte, 0>{}, byte_span_with_optional{}); };

};

struct repeated_strings {
  std::vector<std::string> values;
  bool operator==(const repeated_strings &) const = default;
};

struct repeated_strings_explicit_type {
  std::vector<std::string> values;
  bool operator==(const repeated_strings_explicit_type &) const = default;
};

auto pb_meta(const repeated_strings_explicit_type &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, std::string>>;

struct repeated_strings_explicit_presence {
  std::vector<std::string> values;
  bool operator==(const repeated_strings_explicit_presence &) const = default;
};

auto pb_meta(const repeated_strings_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence, std::string>>;

using namespace std::literals;

ut::suite test_repeated_strings = [] {
  "repeated_strings"_test = [] {
    verify("\x0a\x03\x61\x62\x63\x0a\x03\x64\x65\x66"_bytes_array, repeated_strings{.values = {"abc"s, "def"s}});
  };
  "repeated_strings_explicit_type"_test = [] {
    verify("\x0a\x03\x61\x62\x63\x0a\x03\x64\x65\x66"_bytes_array,
           repeated_strings_explicit_type{.values = {"abc"s, "def"s}});
  };
  "repeated_strings_explicit_presence"_test = [] {
    verify("\x0a\x03\x61\x62\x63\x0a\x03\x64\x65\x66"_bytes_array,
           repeated_strings_explicit_presence{.values = {"abc"s, "def"s}});
  };
};

struct oneof_example {
  std::variant<std::monostate, std::string, int32_t, color_t> value;
  bool operator==(const oneof_example &) const = default;
};

auto pb_meta(const oneof_example &) -> std::tuple<
    std::tuple<hpp::proto::field_meta<1>, hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>,
               hpp::proto::field_meta<3>>>;

ut::suite test_oneof = [] {
  "empty_oneof_example"_test = [] { verify(std::array<std::byte, 0>{}, oneof_example{}); };

  "string_oneof_example"_test = [] { verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, oneof_example{.value = "test"}); };

  "integer_oneof_example"_test = [] { verify("\x10\x05"_bytes_array, oneof_example{.value = 5}); };

  "enum_oneof_example"_test = [] { verify("\x18\x02"_bytes_array, oneof_example{.value = color_t::green}); };
};

struct extension_example {
  int32_t int_value;
  struct extension_t {
    using pb_extension = extension_example;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  auto get_extension(auto meta) { return meta.read(extensions); }

  template <typename Meta>
  void set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  bool has_extension(auto meta) const { return meta.element_of(extensions); }

  bool operator==(const extension_example &other) const = default;
};

auto pb_meta(const extension_example &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, zpp::bits::vint64_t>,
                  hpp::proto::field_meta<UINT32_MAX>>;

constexpr auto i32_ext() {
  return hpp::proto::extension_meta<extension_example, 10, encoding_rule::explicit_presence, zpp::bits::vint64_t,
                                    int32_t>{};
}

constexpr auto string_ext() {
  return hpp::proto::extension_meta<extension_example, 11, encoding_rule::explicit_presence, std::string,
                                    std::string>{};
}

constexpr auto i32_defaulted_ext() {
  return hpp::proto::extension_meta<extension_example, 13, encoding_rule::defaulted, zpp::bits::vint64_t, int32_t,
                                    zpp::bits::vint64_t{10}>{};
}

constexpr auto i32_unset_ext() {
  return hpp::proto::extension_meta<extension_example, 14, encoding_rule::explicit_presence, zpp::bits::vint64_t,
                                    int32_t>{};
}

constexpr auto example_ext() {
  return hpp::proto::extension_meta<extension_example, 15, encoding_rule::explicit_presence, example, example>{};
}

constexpr auto repeated_i32_ext() {
  return hpp::proto::repeated_extension_meta<extension_example, 20, encoding_rule::unpacked_repeated,
                                             zpp::bits::vint64_t, int32_t>{};
}

constexpr auto repeated_string_ext() {
  return hpp::proto::repeated_extension_meta<extension_example, 21, encoding_rule::unpacked_repeated, std::string,
                                             std::string>{};
}

constexpr auto repeated_packed_i32_ext() {
  return hpp::proto::repeated_extension_meta<extension_example, 22, encoding_rule::defaulted, zpp::bits::vint64_t,
                                             int32_t>{};
}

ut::suite test_extensions = [] {
  "get_extension"_test = [] {
    auto encoded_data =
        "\x08\x96\x01\x50\x01\x5a\x04\x74\x65\x73\x74\x7a\x03\x08\x96\x01\xa0\x01\x01\xa0\x01\x02\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66\xb2\x01\x03\01\02\03"_bytes_array;
    extension_example expected_value{
        .int_value = 150,
        .extensions = {.fields = {{10U, "\x50\x01"_bytes},
                                  {11U, "\x5a\x04\x74\x65\x73\x74"_bytes},
                                  {15U, "\x7a\x03\x08\x96\x01"_bytes},
                                  {20U, "\xa0\x01\x01\xa0\x01\x02"_bytes},
                                  {21U, "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes},
                                  {22U, "\xb2\x01\x03\01\02\03"_bytes}}}};
    extension_example value;
    ut::expect(success(hpp::proto::in{encoded_data}(value)));
    ut::expect(value == expected_value);

    ut::expect(value.has_extension(i32_ext()));
    ut::expect(value.has_extension(string_ext()));
    ut::expect(!value.has_extension(i32_defaulted_ext()));
    ut::expect(!value.has_extension(i32_unset_ext()));
    ut::expect(value.has_extension(example_ext()));

    {
      auto v = value.get_extension(i32_ext());
      ut::expect(v.has_value());
      ut::expect(v.value() == 1);
    }
    {
      auto v = value.get_extension(string_ext());
      ut::expect(v.has_value());
      ut::expect(v.value() == "test");
    }
    {
      auto v = value.get_extension(example_ext());
      ut::expect(v.has_value());
      ut::expect(v.value() == example{.i = 150});
    }
    { ut::expect(value.get_extension(repeated_i32_ext()) == std::vector<int32_t>{1, 2}); }
    { ut::expect(value.get_extension(repeated_string_ext()) == std::vector<std::string>{"abc", "def"}); }
    { ut::expect(value.get_extension(repeated_packed_i32_ext()) == std::vector<int32_t>{1, 2, 3}); }

    std::array<std::byte, encoded_data.size()> new_data;
    ut::expect(success(hpp::proto::out{new_data}(value)));

    ut::expect(encoded_data == new_data);
  };
  "set_extension"_test = [] {
    extension_example value;
    ut::expect(ut::nothrow([&] { value.set_extension(i32_ext(), 1); }));
    ut::expect(value.extensions.fields[10] == "\x50\x01"_bytes);

    ut::expect(ut::nothrow([&] { value.set_extension(string_ext(), "test"); }));
    ut::expect(value.extensions.fields[11] == "\x5a\x04\x74\x65\x73\x74"_bytes);

    ut::expect(ut::nothrow([&] { value.set_extension(i32_defaulted_ext(), 10); }));
    ut::expect(value.extensions.fields.count(13) == 1);

    ut::expect(ut::nothrow([&] { value.set_extension(example_ext(), {.i = 150}); }));
    ut::expect(value.extensions.fields[15] == "\x7a\x03\x08\x96\x01"_bytes);

    ut::expect(ut::nothrow([&] { value.set_extension(repeated_i32_ext(), {1, 2}); }));
    ut::expect(value.extensions.fields[20] == "\xa0\x01\x01\xa0\x01\x02"_bytes);

    ut::expect(ut::nothrow([&] { value.set_extension(repeated_string_ext(), {"abc", "def"}); }));
    ut::expect(value.extensions.fields[21] == "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes);

    ut::expect(ut::nothrow([&] { value.set_extension(repeated_packed_i32_ext(), {1, 2, 3}); }));
    ut::expect(value.extensions.fields[22] == "\xb2\x01\x03\01\02\03"_bytes);
  };
};

struct recursive_type1 {
  hpp::proto::heap_based_optional<recursive_type1> child;
  uint32_t payload;

  bool operator==(const recursive_type1 &other) const = default;

#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR
  friend auto operator<=>(const recursive_type1 &, const recursive_type1 &) = default;
#endif

  using pb_meta =
      std::tuple<hpp::proto::field_meta<1>, hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>>;
};

struct recursive_type2 {
  std::vector<recursive_type2> children;
  int32_t payload;

  bool operator==(const recursive_type2 &other) const = default;

  using pb_meta =
      std::tuple<hpp::proto::field_meta<1>, hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>>;
};

ut::suite recursive_types = [] {
  "recursive_type1"_test = [] {
    verify("\x0a\x02\x10\x02\x10\x01"_bytes_array, recursive_type1{recursive_type1{{}, 2}, 1});
  };
  "recursive_type2"_test = [] {
    recursive_type2 child;
    child.payload = 2;
    recursive_type2 value;
    value.children.push_back(child);
    value.payload = 1;

    verify("\x0a\x02\x10\x02\x10\x01"_bytes_array, value);
  };
};

struct monster {
  using enum color_t;
  struct vec3 {
    float x;
    float y;
    float z;

    bool operator==(const vec3 &) const = default;
  };

  struct weapon {
    std::string name;
    int damage;

    bool operator==(const weapon &) const = default;
  };

  vec3 pos;
  int32_t mana;
  int hp;
  std::string name;
  std::vector<std::uint8_t> inventory;
  color_t color;
  std::vector<weapon> weapons;
  weapon equipped;
  std::vector<vec3> path;
  bool boss;

  bool operator==(const monster &) const = default;
  using pb_meta =
      std::tuple<hpp::proto::field_meta<1>, hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>,
                 hpp::proto::field_meta<3>, hpp::proto::field_meta<4>, hpp::proto::field_meta<5>,
                 hpp::proto::field_meta<6>, hpp::proto::field_meta<7>, hpp::proto::field_meta<8>,
                 hpp::proto::field_meta<9>, hpp::proto::field_meta<10>>;
};

ut::suite test_monster = [] {
  auto [data, in, out] = hpp::proto::data_in_out(zpp::bits::size4b{});
  monster m = {.pos = {1.0, 2.0, 3.0},
               .mana = 200,
               .hp = 1000,
               .name = "mushroom",
               .inventory = {1, 2, 3},
               .color = monster::blue,
               .weapons =
                   {
                       monster::weapon{.name = "sword", .damage = 55},
                       monster::weapon{.name = "spear", .damage = 150},
                   },
               .equipped =
                   {
                       monster::weapon{.name = "none", .damage = 15},
                   },
               .path = {monster::vec3{2.0, 3.0, 4.0}, monster::vec3{5.0, 6.0, 7.0}},
               .boss = true};
  out(m).or_throw();

  monster m2;
  in(m2).or_throw();

  ut::expect(m.pos == m2.pos);
  ut::expect(m.mana == m2.mana);
  ut::expect(m.hp == m2.hp);
  ut::expect(m.name == m2.name);
  ut::expect(m.inventory == m2.inventory);
  ut::expect(m.color == m2.color);
  ut::expect(m.weapons == m2.weapons);
  ut::expect(m.equipped == m2.equipped);
  ut::expect(m.path == m2.path);
  ut::expect(m.boss == m2.boss);
  ut::expect(m == m2);
};

ut::suite test_monster_unsized = [] {
  auto [data, in, out] = hpp::proto::data_in_out(zpp::bits::no_size{});
  monster m = {.pos = {1.0, 2.0, 3.0},
               .mana = 200,
               .hp = 1000,
               .name = "mushroom",
               .inventory = {1, 2, 3},
               .color = monster::blue,
               .weapons =
                   {
                       monster::weapon{.name = "sword", .damage = 55},
                       monster::weapon{.name = "spear", .damage = 150},
                   },
               .equipped =
                   {
                       monster::weapon{.name = "none", .damage = 15},
                   },
               .path = {monster::vec3{2.0, 3.0, 4.0}, monster::vec3{5.0, 6.0, 7.0}},
               .boss = true};

  ut::expect(success(out(m)));
  monster m2;
  ut::expect(success(in(m2)));

  ut::expect(m.pos == m2.pos);
  ut::expect(m.mana == m2.mana);
  ut::expect(m.hp == m2.hp);
  ut::expect(m.name == m2.name);
  ut::expect(m.inventory == m2.inventory);
  ut::expect(m.color == m2.color);
  ut::expect(m.weapons == m2.weapons);
  ut::expect(m.equipped == m2.equipped);
  ut::expect(m.path == m2.path);
  ut::expect(m.boss == m2.boss);
  ut::expect(m == m2);
};

struct monster_with_optional {
  using enum color_t;
  using vec3 = monster::vec3;
  using weapon = monster::weapon;

  vec3 pos;
  int32_t mana;
  int hp;
  std::string name;
  std::vector<std::uint8_t> inventory;
  color_t color;
  std::vector<weapon> weapons;
  std::optional<weapon> equipped;
  std::vector<vec3> path;
  bool boss;

  bool operator==(const monster_with_optional &) const = default;
  using pb_meta =
      std::tuple<hpp::proto::field_meta<1>, hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>,
                 hpp::proto::field_meta<3>, hpp::proto::field_meta<4>, hpp::proto::field_meta<5>,
                 hpp::proto::field_meta<6>, hpp::proto::field_meta<7>, hpp::proto::field_meta<8>,
                 hpp::proto::field_meta<9>, hpp::proto::field_meta<10>>;
  using serialize = zpp::bits::members<10>;
};

ut::suite test_monster_with_optional = [] {
  monster_with_optional m = {.pos = {1.0, 2.0, 3.0},
                             .mana = 200,
                             .hp = 1000,
                             .name = "mushroom",
                             .inventory = {1, 2, 3},
                             .color = monster::blue,
                             .weapons =
                                 {
                                     monster::weapon{.name = "sword", .damage = 55},
                                     monster::weapon{.name = "spear", .damage = 150},
                                 },
                             .equipped =
                                 {
                                     monster::weapon{.name = "none", .damage = 15},
                                 },
                             .path = {monster::vec3{2.0, 3.0, 4.0}, monster::vec3{5.0, 6.0, 7.0}},
                             .boss = true};

  {
    auto [data, in, out] = hpp::proto::data_in_out(zpp::bits::no_size{});
    ut::expect(success(out(m)));
    monster_with_optional m2;
    ut::expect(success(in(m2)));

    ut::expect(m.pos == m2.pos);
    ut::expect(m.mana == m2.mana);
    ut::expect(m.hp == m2.hp);
    ut::expect(m.name == m2.name);
    ut::expect(m.inventory == m2.inventory);
    ut::expect(m.color == m2.color);
    ut::expect(m.weapons == m2.weapons);
    ut::expect(m.equipped == m2.equipped);
    ut::expect(m.path == m2.path);
    ut::expect(m.boss == m2.boss);
    ut::expect(m == m2);
  }

  m.equipped.reset();
  {
    auto [data, in, out] = hpp::proto::data_in_out(zpp::bits::no_size{});
    ut::expect(success(out(m)));
    monster_with_optional m2;
    ut::expect(success(in(m2)));
    ut::expect(m == m2);
  }
};

struct person {
  std::string name;  // = 1
  int32_t id;        // = 2
  std::string email; // = 3

  enum phone_type {
    mobile = 0,
    home = 1,
    work = 2,
  };

  struct phone_number {
    std::string number; // = 1
    phone_type type;    // = 2
  };

  std::vector<phone_number> phones; // = 4

  using pb_meta =
      std::tuple<hpp::proto::field_meta<1>, hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>,
                 hpp::proto::field_meta<3>, hpp::proto::field_meta<4>>;
};

struct address_book {
  std::vector<person> people; // = 1
};

ut::suite test_person = [] {
  constexpr auto data = "\n\x08John Doe\x10\xd2\t\x1a\x10jdoe@example.com\"\x0c\n\x08"
                        "555-4321\x10\x01"_bytes_array;
  static_assert(data.size() == 45);

  person p;
  ut::expect(success(hpp::proto::in{data}(p)));

  using namespace std::literals::string_view_literals;
  using namespace boost::ut;

  ut::expect(p.name == "John Doe"sv);
  ut::expect(that % p.id == 1234);
  ut::expect(p.email == "jdoe@example.com"sv);
  ut::expect((p.phones.size() == 1_u) >> fatal);
  ut::expect(p.phones[0].number == "555-4321"sv);
  ut::expect(that % p.phones[0].type == person::home);

  std::array<std::byte, data.size()> new_data;
  ut::expect(success(hpp::proto::out{new_data}(p)));

  ut::expect(data == new_data);
};

ut::suite test_address_book = [] {
  constexpr auto data = "\n-\n\x08John Doe\x10\xd2\t\x1a\x10jdoe@example.com\"\x0c\n\x08"
                        "555-4321\x10\x01\n>\n\nJohn Doe "
                        "2\x10\xd3\t\x1a\x11jdoe2@example.com\"\x0c\n\x08"
                        "555-4322\x10\x01\"\x0c\n\x08"
                        "555-4323\x10\x02"_bytes_array;

  static_assert(data.size() == 111);

  using namespace std::literals::string_view_literals;
  using namespace boost::ut;

  address_book b;
  expect(success(hpp::proto::in{data}(b)));

  expect(b.people.size() == 2_u);
  expect(b.people[0].name == "John Doe"sv);
  expect(that % b.people[0].id == 1234);
  expect(b.people[0].email == "jdoe@example.com"sv);
  expect((b.people[0].phones.size() == 1u) >> fatal);
  expect(b.people[0].phones[0].number == "555-4321"sv);
  expect(b.people[0].phones[0].type == person::home);
  expect(b.people[1].name == "John Doe 2"sv);
  expect(that % b.people[1].id == 1235);
  expect(b.people[1].email == "jdoe2@example.com"sv);
  expect((b.people[1].phones.size() == 2_u) >> fatal);
  expect(b.people[1].phones[0].number == "555-4322"sv);
  expect(b.people[1].phones[0].type == person::home);
  expect(b.people[1].phones[1].number == "555-4323"sv);
  expect(b.people[1].phones[1].type == person::work);

  std::array<std::byte, data.size()> new_data;
  hpp::proto::out out{new_data};
  expect(success(out(b)));
  expect(out.position() == data.size());
  expect(data == new_data);
};

struct person_explicit {
  std::string extra;
  std::string name;
  int32_t id;
  std::string email;

  enum phone_type {
    mobile = 0,
    home = 1,
    work = 2,
  };

  struct phone_number {
    std::string number;
    phone_type type;

    using pb_meta = std::tuple<hpp::proto::field_meta<1>, hpp::proto::field_meta<2>>;
  };

  std::vector<phone_number> phones;

  using pb_meta = std::tuple<hpp::proto::field_meta<10>, hpp::proto::field_meta<1>,
                             hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>,
                             hpp::proto::field_meta<3>, hpp::proto::field_meta<4>>;
};

ut::suite test_person_explicit = [] {
  constexpr auto data = "\n\x08John Doe\x10\xd2\t\x1a\x10jdoe@example.com\"\x0c\n\x08"
                        "555-4321\x10\x01"_bytes_array;
  static_assert(data.size() == 45);

  using namespace std::literals::string_view_literals;
  using namespace boost::ut;

  person_explicit p;
  expect(success(hpp::proto::in{data}(p)));

  expect(p.name == "John Doe"sv);
  expect(that % p.id == 1234);
  expect(p.email == "jdoe@example.com"sv);
  expect((p.phones.size() == 1_u) >> fatal);
  expect(p.phones[0].number == "555-4321"sv);
  expect(that % p.phones[0].type == person_explicit::home);

  person p1;
  p1.name = p.name;
  p1.id = p.id;
  p1.email = p.email;
  p1.phones.push_back({p.phones[0].number, person::phone_type(p.phones[0].type)});

  std::array<std::byte, data.size()> new_data;
  expect(success(hpp::proto::out{new_data, zpp::bits::no_size{}}(p1)));

  expect(data == new_data);
};

struct person_map {
  std::string name;  // = 1
  int32_t id;        // = 2
  std::string email; // = 3

  enum phone_type {
    mobile = 0,
    home = 1,
    work = 2,
  };

  hpp::proto::flat_map<std::string, phone_type> phones; // = 4

  using pb_meta =
      std::tuple<hpp::proto::field_meta<1>, hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>,
                 hpp::proto::field_meta<3>, hpp::proto::field_meta<4>>;
};

ut::suite test_person_map = [] {
  constexpr auto data = "\n\x08John Doe\x10\xd2\t\x1a\x10jdoe@example.com\"\x0c\n\x08"
                        "555-4321\x10\x01"_bytes_array;
  static_assert(data.size() == 45);

  using namespace std::literals::string_view_literals;
  using namespace boost::ut;

  person_map p;
  expect(success(hpp::proto::in{data}(p)));

  expect(p.name == "John Doe"sv);
  expect(that % p.id == 1234);
  expect(p.email == "jdoe@example.com"sv);
  expect((p.phones.size() == 1_u) >> fatal);
  expect((p.phones.contains("555-4321")) >> fatal);
  expect(that % p.phones["555-4321"] == person_map::home);

  std::array<std::byte, data.size()> new_data;
  expect(success(hpp::proto::out{new_data}(p)));

  expect(data == new_data);
};

ut::suite test_default_person_in_address_book = [] {
  constexpr auto data = "\n\x00"_bytes_array;

  using namespace std::literals::string_view_literals;
  using namespace boost::ut;

  address_book b;
  expect(success(hpp::proto::in{data}(b)));

  expect(b.people.size() == 1_u);
  expect(b.people[0].name == ""sv);
  expect(that % b.people[0].id == 0);
  expect(b.people[0].email == ""sv);
  expect(b.people[0].phones.size() == 0_u);

  std::array<std::byte, "0a00"_decode_hex.size()> new_data;
  expect(success(hpp::proto::out{new_data}(b)));

  expect(new_data == "0a00"_decode_hex);
};

ut::suite test_empty_address_book = [] {
  constexpr auto data = ""_bytes_array;

  using namespace boost::ut;

  address_book b;
  expect(success(hpp::proto::in{data}(b)));

  expect(b.people.size() == 0_u);

  std::array<std::byte, 1> new_data;
  hpp::proto::out out{new_data};
  expect(success(out(b)));

  expect(out.position() == 0_u);
};

ut::suite test_empty_person = [] {
  constexpr auto data = ""_bytes_array;
  using namespace std::literals::string_view_literals;
  using namespace boost::ut;

  person p;
  expect(success(hpp::proto::in{data}(p)));

  expect(p.name.size() == 0_u);
  expect(p.name == ""sv);
  expect(that % p.id == 0);
  expect(p.email == ""sv);
  expect(p.phones.size() == 0_u);

  std::array<std::byte, 2> new_data;
  hpp::proto::out out{new_data};
  expect(success(out(p)));
  expect(out.position() == 0_u);
};

void verify_unknown_fields(auto encoded_data, auto expected_value) {
  decltype(expected_value) value;
  hpp::proto::in in{encoded_data};
  ut::expect(success(in(value)));
  ut::expect(value == expected_value);
  ut::expect(in.has_unknown_fields());
}

ut::suite test_decode_unknown_field = [] {
  "string_example_varint_unknown"_test = [] {
    verify_unknown_fields("\x18\x02\x0a\x04\x74\x65\x73\x74"_bytes_array, string_example{.value = "test"});
  };

  "string_example_i64_unknown"_test = [] {
    verify_unknown_fields("\x19\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x04\x74\x65\x73\x74"_bytes_array,
                          string_example{.value = "test"});
  };

  "string_example_length_delimited_unknown"_test = [] {
    verify_unknown_fields("\x1a\x02\x02\x03\x0a\x04\x74\x65\x73\x74"_bytes_array, string_example{.value = "test"});
  };

  "string_example_i32_unknown"_test = [] {
    verify_unknown_fields("\x1d\x01\x02\x03\x04\x0a\x04\x74\x65\x73\x74"_bytes_array, string_example{.value = "test"});
  };

  "string_example_invalid_wire_type"_test = [] {
    string_example value;
    ut::expect(failure(hpp::proto::in{"\x1c\x02\x0a\x04\x74\x65\x73\x74"_bytes_array}(value)));
  };
};

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return result;
}