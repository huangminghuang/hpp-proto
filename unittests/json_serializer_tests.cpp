#include "test_util.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/json.hpp>
#include <hpp_proto/json/duration_codec.hpp>
#include <hpp_proto/json/timestamp_codec.hpp>
#include <string_view>

template <typename T>
constexpr auto non_owning = false;

template <template <typename Traits> class Message>
constexpr auto non_owning<Message<hpp_proto::non_owning_traits>> = true;

using optional_string_t = hpp_proto::optional<std::string>;
static_assert(glz::nullable_t<optional_string_t> && not glz::custom_read<optional_string_t>);

struct byte_span_example {
  hpp_proto::equality_comparable_span<const std::byte> field;
  bool operator==(const byte_span_example &other) const = default;
};
constexpr auto message_type_url(const byte_span_example &) {
  return hpp_proto::string_literal<"type.googleapis.com/byte_span_example">{};
}

template <>
struct glz::meta<byte_span_example> {
  using T = byte_span_example;
  static constexpr auto value = object("field", hpp_proto::as_optional_ref<&T::field>);
};

struct uint64_example {
  uint64_t field = 0;
  bool operator==(const uint64_example &) const = default;
};
constexpr auto message_type_url(const uint64_example &) {
  return hpp_proto::string_literal<"type.googleapis.com/uint64_example">{};
}

template <>
struct glz::meta<uint64_example> {
  using T = uint64_example;
  static constexpr auto value = object("field", glz::quoted_num<&uint64_example::field>);
};

struct optional_example {
  int32_t field1 = {};
  uint64_t field2 = {};
  int32_t field3 = {};
  double field4 = {};
  bool operator==(const optional_example &) const = default;
};
constexpr auto message_type_url(const optional_example &) {
  return hpp_proto::string_literal<"type.googleapis.com/optional_example">{};
}

template <>
struct glz::meta<optional_example> {
  using T = optional_example;
  static constexpr auto value = object(
      // clang-format off
      "field1", hpp_proto::as_optional_ref<&T::field1>, 
      "field2", hpp_proto::as_optional_ref<&T::field2>, 
      "field3", hpp_proto::as_optional_ref<&T::field3>, 
      "field4", hpp_proto::as_optional_ref<&T::field4>);
  // clang-format on
};

struct explicit_optional_bool_example {
  hpp_proto::optional<bool> field;
  bool operator==(const explicit_optional_bool_example &) const = default;
};

constexpr auto message_type_url(const explicit_optional_bool_example &) {
  return hpp_proto::string_literal<"type.googleapis.com/explicit_optional_bool_example">{};
}

template <>
struct glz::meta<explicit_optional_bool_example> {
  using T = explicit_optional_bool_example;
  static constexpr auto value = object("field", &T::field);
};

struct explicit_optional_uint64_example {
  hpp_proto::optional<uint64_t> field;
  bool operator==(const explicit_optional_uint64_example &) const = default;
};
constexpr auto message_type_url(const explicit_optional_uint64_example &) {
  return hpp_proto::string_literal<"type.googleapis.com/explicit_optional_uint64_example">{};
}

template <>
struct glz::meta<explicit_optional_uint64_example> {
  using T = explicit_optional_uint64_example;
  static constexpr auto value = object("field", &T::field);
};

struct uint32_span_example {
  hpp_proto::equality_comparable_span<const uint32_t> field;
  bool operator==(const uint32_span_example &) const = default;
};
constexpr auto message_type_url(const uint32_span_example &) {
  return hpp_proto::string_literal<"type.googleapis.com/uint32_span_example">{};
}

template <>
constexpr auto non_owning<uint32_span_example> = true;

template <>
struct glz::meta<uint32_span_example> {
  using T = uint32_span_example;
  static constexpr auto value = object("field", hpp_proto::as_optional_ref<&T::field>);
};

struct pair_vector_example {
  std::vector<std::pair<std::string, int32_t>> field;
  bool operator==(const pair_vector_example &) const = default;
};
constexpr auto message_type_url(const pair_vector_example &) {
  return hpp_proto::string_literal<"type.googleapis.com/pair_vector_example">{};
}

struct json_overload_example {
  int value = 0;
  bool operator==(const json_overload_example &) const = default;
};

enum class enum_read_example_field : int32_t { zero = 0, one = 1 };

struct enum_read_example {
  enum_read_example_field value = enum_read_example_field::zero;
  bool operator==(const enum_read_example &) const = default;
};

template <>
struct glz::meta<json_overload_example> {
  using T = json_overload_example;
  static constexpr auto value = object("value", &T::value);
};

template <>
struct glz::meta<enum_read_example> {
  using T = enum_read_example;
  static constexpr auto value = object("value", &T::value);
};

static_assert(hpp_proto::concepts::null_terminated_str<const char *>);
static_assert(hpp_proto::concepts::null_terminated_str<decltype("x")>);
static_assert(hpp_proto::concepts::null_terminated_str<const char8_t *>);
static_assert(hpp_proto::concepts::null_terminated_str<decltype(u8"x")>);
static_assert(hpp_proto::concepts::null_terminated_str<std::string>);
static_assert(hpp_proto::concepts::null_terminated_str<std::u8string>);
static_assert(hpp_proto::concepts::non_null_terminated_str<std::string_view>);
static_assert(hpp_proto::concepts::non_null_terminated_str<std::basic_string_view<char8_t>>);

template <>
struct glz::meta<pair_vector_example> {
  using T = pair_vector_example;
  static constexpr auto value = object("field", hpp_proto::as_optional_ref<&T::field>);
};

struct pair_span_example {
  hpp_proto::equality_comparable_span<const std::pair<std::string_view, int32_t>> field;
  bool operator==(const pair_span_example &) const = default;
};
constexpr auto message_type_url(const pair_span_example &) {
  return hpp_proto::string_literal<"type.googleapis.com/pair_span_example">{};
}

template <>
constexpr auto non_owning<pair_span_example> = true;
template <>
struct glz::meta<pair_span_example> {
  using T = pair_span_example;
  static constexpr auto value = object("field", hpp_proto::as_optional_ref<&T::field>);
};

struct object_span_example {
  hpp_proto::equality_comparable_span<const optional_example> field;
  bool operator==(const object_span_example &) const = default;
};
constexpr auto message_type_url(const object_span_example &) {
  return hpp_proto::string_literal<"type.googleapis.com/object_span_example">{};
}

template <>
constexpr auto non_owning<object_span_example> = true;

template <>
struct glz::meta<object_span_example> {
  using T = object_span_example;
  static constexpr auto value = object("field", hpp_proto::as_optional_ref<&T::field>);
};

struct non_owning_nested_example {
  hpp_proto::optional_indirect_view<optional_example> nested;
  bool operator==(const non_owning_nested_example &) const = default;
};
constexpr auto message_type_url(const non_owning_nested_example &) {
  return hpp_proto::string_literal<"type.googleapis.com/non_owning_nested_example">{};
}

template <>
constexpr auto non_owning<non_owning_nested_example> = true;

template <>
struct glz::meta<non_owning_nested_example> {
  using T = non_owning_nested_example;
  static constexpr auto value = object("nested", hpp_proto::as_optional_indirect_view_ref<&T::nested>);
};

struct oneof_example {
  std::variant<std::monostate, std::string, int32_t> value;
  bool operator==(const oneof_example &) const = default;
};

template <>
struct glz::meta<oneof_example> {
  using T = oneof_example;
  static constexpr auto value = object("string_field", hpp_proto::as_oneof_member<&T::value, 1>, "int32_field",
                                       hpp_proto::as_oneof_member<&T::value, 2>);
};

namespace ut = boost::ut;

const ut::suite test_base64 = [] {
  auto verify = [](std::string_view data, std::string_view encoded) {
    using namespace boost::ut;
    expect(ge(hpp_proto::base64::max_encode_size(data), encoded.size()));
    std::string result;
    result.resize(hpp_proto::base64::max_encode_size(data));
    auto encoded_size = hpp_proto::base64::encode(data, result);
    result.resize(encoded_size);
    expect(eq(encoded, result));
    hpp_proto::json_context<> ctx;
    expect(hpp_proto::base64::decode(encoded, result, ctx));
    expect(eq(data, result));
  };

  verify("", "");
  verify("light work.", "bGlnaHQgd29yay4=");
  verify("light work", "bGlnaHQgd29yaw==");
  verify("light wor", "bGlnaHQgd29y");
  verify("abcdefghijklmnopqrstuvwxyz", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=");

  verify("f", "Zg==");
  verify("fo", "Zm8=");
  verify("foo", "Zm9v");
  verify("foob", "Zm9vYg==");
  verify("fooba", "Zm9vYmE=");
  verify("foobar", "Zm9vYmFy");

  using namespace boost::ut;

  "invalid_decode"_test = [] {
    using namespace boost::ut;
    using namespace std::literals::string_view_literals;
    hpp_proto::json_context<> ctx;
    std::string result;
    // The decoder should reject invalid base64 strings.
    // 1. Invalid characters
    expect(!hpp_proto::base64::decode("bGlnaHQgd29yay4-"sv, result, ctx));
    // 2. Padding in the middle
    expect(!hpp_proto::base64::decode("Zg==YWJj"sv, result, ctx));
    // 3. Incorrect padding
    expect(!hpp_proto::base64::decode("Zm9vYg="sv, result, ctx));   // "foob" is "Zm9vYg=="
    expect(!hpp_proto::base64::decode("Zm9vYmE=="sv, result, ctx)); // "fooba" is "Zm9vYmE="
  };
};

using source_location = boost::ut::reflection::source_location;

template <typename T>
void verify(const T &msg, std::string_view json, const source_location &from_loc = source_location::current()) {
  using namespace boost::ut;
  std::string from_line_number = "from line " + std::to_string(from_loc.line());
  expect(eq(json, hpp_proto::write_json(msg).value())) << from_line_number;

  T msg2;

  if constexpr (!non_owning<T>) {
    expect(fatal((hpp_proto::read_json(msg2, json).ok()))) << from_line_number;
    expect(msg == msg2);
  } else {
    std::pmr::monotonic_buffer_resource mr;
    expect(fatal((hpp_proto::read_json(msg2, json, hpp_proto::alloc_from{mr}).ok()))) << from_line_number;
    expect(msg == msg2);
  }
}

template <typename Traits>
struct bytes_example {
  typename Traits::bytes_t field0;
  hpp_proto::optional<typename Traits::bytes_t> field1;
  hpp_proto::optional<typename Traits::bytes_t, hpp_proto::bytes_literal<"test">{}> field2;
  typename Traits::bytes_t field3;
  bool operator==(const bytes_example &) const = default;
};

template <typename T>
constexpr auto message_type_url(const bytes_example<T> &) {
  return hpp_proto::string_literal<"type.googleapis.com/bytes_example">{};
}

template <>
constexpr auto non_owning<std::string_view> = true;

template <typename T>
constexpr auto non_owning<hpp_proto::equality_comparable_span<const T>> = true;

template <typename Traits>
struct glz::meta<bytes_example<Traits>> {
  using T = bytes_example<Traits>;
  // clang-format off
  static constexpr auto value = object("field0", &T::field0,
                                       "field1", &T::field1, 
                                       "field2", &T::field2, 
                                       "field3", hpp_proto::as_optional_ref<&T::field3>);
  // clang-format on
};

const ut::suite test_bytes = [] {
  using namespace boost::ut::literals;
  using namespace boost::ut;

  "bytes"_test = []<class Traits> {
    verify(bytes_example<Traits>{}, R"({"field0":""})");
    verify(bytes_example<Traits>{.field0 = "foo"_bytes,
                                 .field1 = "light work."_bytes,
                                 .field2 = "light work"_bytes,
                                 .field3 = "light wor"_bytes},
           R"({"field0":"Zm9v","field1":"bGlnaHQgd29yay4=","field2":"bGlnaHQgd29yaw==","field3":"bGlnaHQgd29y"})");
  } | std::tuple<hpp_proto::default_traits, hpp_proto::non_owning_traits, hpp_proto::pmr_traits>{};
};

template <typename Traits>
struct string_example {
  ::hpp_proto::optional<typename Traits::string_t> optional_string;
  Traits::template repeated_t<typename Traits::string_t> repeated_string;

  // NOLINTNEXTLINE(cppcoreguidelines-use-enum-class)
  enum oneof_field_oneof_case : uint8_t { oneof_uint32 = 1, oneof_string = 3, oneof_bytes = 4 };

  static constexpr std::array<std::uint32_t, 5> oneof_field_oneof_numbers{0U, 111U, 112U, 113U, 114U};
  std::variant<std::monostate, std::uint32_t, typename Traits::string_t, typename Traits::bytes_t> oneof_field;
  bool operator==(const string_example &) const = default;
};

// clang-format off
template <typename Traits>
struct glz::meta<string_example<Traits>> {
  using T = string_example<Traits>;
  static constexpr auto value =
      object("optionalString", &T::optional_string, 
             "repeatedString", ::hpp_proto::as_optional_ref<&T::repeated_string>,
             "oneofUint32", ::hpp_proto::as_oneof_member<&T::oneof_field, 1>,
             "oneofString", ::hpp_proto::as_oneof_member<&T::oneof_field, 2>, 
             "oneofBytes", ::hpp_proto::as_oneof_member<&T::oneof_field, 3>);
};
// clang-format on

const ut::suite test_string_json = [] {
  using namespace boost::ut;
  "test_escape"_test = []<class Traits> {
    verify(string_example<Traits>{.optional_string = "te\t"}, R"({"optionalString":"te\t"})");
  } | std::tuple<hpp_proto::default_traits, hpp_proto::non_owning_traits>{};

  string_example<hpp_proto::default_traits> msg;
  expect(hpp_proto::read_json(msg, "{\"optionalString\":null}").ok());
  expect(!hpp_proto::read_json(msg, "{\"repeatedString\":[\"a\rsdfads\"],\"optionalString\":\"abc\"}").ok());
};

const ut::suite test_uint64_json = [] { verify(uint64_example{.field = 123U}, R"({"field":"123"})"); };

const ut::suite test_optional_json = [] {
  verify(optional_example{.field2 = 123U, .field3 = 456}, R"({"field2":"123","field3":456})");
};

const ut::suite test_uint32_span_json = [] {
  std::array<uint32_t, 3> content{1, 2, 3};
  verify<uint32_span_example>(uint32_span_example{.field = content}, R"({"field":[1,2,3]})");
};

const ut::suite test_pair_vector_json = [] {
  using namespace std::literals::string_literals;
  verify<pair_vector_example>(pair_vector_example{.field = {{"one"s, 1}, {"two"s, 2}, {"three"s, 3}}},
                              R"({"field":{"one":1,"two":2,"three":3}})");
};

const ut::suite test_pair_span_json = [] {
  using namespace std::literals::string_view_literals;
  std::array<std::pair<std::string_view, int32_t>, 3> content{{{"one"sv, 1}, {"two"sv, 2}, {"three"sv, 3}}};
  verify<pair_span_example>(pair_span_example{.field = content}, R"({"field":{"one":1,"two":2,"three":3}})");
};

const ut::suite test_object_span_json = [] {
  std::array<optional_example, 3> content = {
      {{.field1 = 1, .field2 = 1ULL}, {.field1 = 2, .field2 = 2ULL}, {.field1 = 3, .field2 = 3ULL}}};
  verify<object_span_example>(
      object_span_example{.field = content},
      R"({"field":[{"field1":1,"field2":"1"},{"field1":2,"field2":"2"},{"field1":3,"field2":"3"}]})");
};

const ut::suite test_non_owning_nested = [] {
  const optional_example nested = {.field1 = 1, .field2 = 1ULL};
  verify<non_owning_nested_example>(non_owning_nested_example{.nested = &nested},
                                    R"({"nested":{"field1":1,"field2":"1"}})");
};

const ut::suite test_explicit_optional_bool = [] {
  verify<explicit_optional_bool_example>(explicit_optional_bool_example{}, R"({})");
  verify<explicit_optional_bool_example>(explicit_optional_bool_example{.field = true}, R"({"field":true})");
  verify<explicit_optional_bool_example>(explicit_optional_bool_example{.field = false}, R"({"field":false})");
};

const ut::suite test_explicit_optional_uint64 = [] {
  verify<explicit_optional_uint64_example>(explicit_optional_uint64_example{}, R"({})");
  verify<explicit_optional_uint64_example>(explicit_optional_uint64_example{.field = 32}, R"({"field":"32"})");
};

const ut::suite test_oneof = [] {
  verify<oneof_example>(oneof_example{.value = "abc"}, R"({"string_field":"abc"})");
  verify<oneof_example>(oneof_example{.value = "tes\t"}, R"({"string_field":"tes\t"})");
};

const ut::suite test_prettify = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;
  using namespace std::string_literals;
  using namespace std::string_view_literals;

  "prettify"_test = [] {
    optional_example msg{.field2 = 123U, .field3 = 456};
    auto json = hpp_proto::write_json<hpp_proto::json_write_opts{.prettify = true}>(msg).value();
    expect(eq(json, R"({
   "field2": "123",
   "field3": 456
})"s));
  };
};

const ut::suite test_read_json_overloads = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;

  auto expect_read = [](auto &&buffer) {
    json_overload_example msg{};
    auto status = hpp_proto::read_json(msg, buffer);
    expect(status.ok());
    expect(eq(msg.value, 1_i));
  };

  "read_json_accepts_char_inputs"_test = [&] {
    expect_read(R"({"value":1})");
    expect_read(std::string{R"({"value":1})"});
    expect_read(std::string_view{R"({"value":1})"});
  };

  "read_json_accepts_char8_inputs"_test = [&] {
    expect_read(u8R"({"value":1})");
    expect_read(std::u8string{u8R"({"value":1})"});
    expect_read(std::basic_string_view<char8_t>{u8R"({"value":1})"});
  };

  "read_json_rejects_null_pointer_input"_test = [] {
    json_overload_example msg{};
    auto status = hpp_proto::read_json(msg, static_cast<const char *>(nullptr));
    expect(!status.ok());
  };

  "read_json_rejects_non_null_terminated_c_array"_test = [] {
    char fixed_json[] = {'{', '"', 'v', 'a', 'l', 'u', 'e', '"', ':', '1', '}'};
    json_overload_example msg{};
    auto status = hpp_proto::read_json(msg, fixed_json);
    expect(!status.ok());
  };
};

const ut::suite test_read_json_full_buffer = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;
  using namespace std::string_view_literals;

  "read_json_rejects_trailing_non_whitespace"_test = [] {
    json_overload_example msg{};
    auto status = hpp_proto::read_json(msg, R"({"value":1}) trailing)");
    expect(!status.ok());
  };

  "read_json_accepts_trailing_whitespace"_test = [] {
    json_overload_example msg{};
    auto status = hpp_proto::read_json(msg, R"({"value":1}  )");
    expect(status.ok());
  };

  "read_json_truncated_enum_value_ws_handled_regression"_test = [] {
    enum_read_example msg{};
    constexpr auto opts = glz::ws_handled<hpp_proto::json_read_opts{}>();
    auto status = hpp_proto::read_json<opts>(msg, R"({"value":)");
    expect(!status.ok());
  };
};

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
