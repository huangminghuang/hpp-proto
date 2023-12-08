#include "test_util.h"
#include <boost/ut.hpp>
#include <hpp_proto/json_serializer.h>
#include <hpp_proto/timestamp_codec.h>
#include <hpp_proto/duration_codec.h>
#include<source_location>

template <typename T>
constexpr auto non_owning = false;

struct byte_span_example {
  std::span<const std::byte> field;
  bool operator==(const byte_span_example &other) const {
    return std::equal(field.begin(), field.end(), other.field.begin(), other.field.end());
  }
};

template <>
struct glz::meta<byte_span_example> {
  using T = byte_span_example;
  static constexpr auto value = object("field", hpp::proto::as_optional_ref<&T::field>);
};

struct uint64_example {
  uint64_t field = 0;
  bool operator==(const uint64_example &) const = default;
};

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

template <>
struct glz::meta<optional_example> {
  using T = optional_example;
  static constexpr auto value = object(
      // clang-format off
      "field1", hpp::proto::as_optional_ref<&T::field1>, 
      "field2", hpp::proto::as_optional_ref<&T::field2>, 
      "field3", hpp::proto::as_optional_ref<&T::field3>, 
      "field4", hpp::proto::as_optional_ref<&T::field4>);
  // clang-format on
};

struct explicit_optional_bool_example {
  hpp::proto::optional<bool> field = {};
  bool operator==(const explicit_optional_bool_example &) const = default;
};

template <>
struct glz::meta<explicit_optional_bool_example> {
  using T = explicit_optional_bool_example;
  static constexpr auto value = object("field", hpp::proto::as_optional_ref<&T::field>);
};

struct explicit_optional_uint64_example {
  hpp::proto::optional<uint64_t> field;
  bool operator==(const explicit_optional_uint64_example &) const = default;
};

template <>
struct glz::meta<explicit_optional_uint64_example> {
  using T = explicit_optional_uint64_example;
  static constexpr auto value = object("field", &T::field);
};

struct uint32_span_example {
  std::span<const uint32_t> field;
  bool operator==(const uint32_span_example &other) const {
    return std::equal(field.begin(), field.end(), other.field.begin(), other.field.end());
  }
};

template <>
constexpr auto non_owning<uint32_span_example> = true;

template <>
struct glz::meta<uint32_span_example> {
  using T = uint32_span_example;
  static constexpr auto value = object("field", hpp::proto::as_optional_ref<&T::field>);
};

struct pair_vector_example {
  std::vector<std::pair<std::string, int32_t>> field;
  bool operator==(const pair_vector_example &other) const = default;
};

template <>
struct glz::meta<pair_vector_example> {
  using T = pair_vector_example;
  static constexpr auto value = object("field", hpp::proto::as_optional_ref<&T::field>);
};

struct pair_span_example {
  std::span<const std::pair<std::string_view, int32_t>> field;
  bool operator==(const pair_span_example &other) const {
    return std::equal(field.begin(), field.end(), other.field.begin(), other.field.end());
  }
};

template <>
constexpr auto non_owning<pair_span_example> = true;
template <>
struct glz::meta<pair_span_example> {
  using T = pair_span_example;
  static constexpr auto value = object("field", hpp::proto::as_optional_ref<&T::field>);
};

struct object_span_example {
  std::span<const optional_example> field;
  bool operator==(const object_span_example &other) const {
    return std::equal(field.begin(), field.end(), other.field.begin(), other.field.end());
  }
};

template <>
constexpr auto non_owning<object_span_example> = true;

template <>
struct glz::meta<object_span_example> {
  using T = object_span_example;
  static constexpr auto value = object("field", hpp::proto::as_optional_ref<&T::field>);
};

struct non_owning_nested_example {
  const optional_example *nested = {};
  bool operator==(const non_owning_nested_example &other) const {
    return nested == other.nested || (nested != nullptr && other.nested != nullptr && *nested == *other.nested);
  }
};

template <>
constexpr auto non_owning<non_owning_nested_example> = true;

template <>
struct glz::meta<non_owning_nested_example> {
  using T = non_owning_nested_example;
  static constexpr auto value = object("nested", &T::nested);
};

namespace ut = boost::ut;

const ut::suite test_base64 = [] {
  auto verify = [](std::string_view data, std::string_view encoded) {
    using namespace boost::ut;
    expect(ge(hpp::proto::base64::max_encode_size(data), encoded.size()));
    std::string result;
    result.resize(hpp::proto::base64::max_encode_size(data));
    auto encoded_size = hpp::proto::base64::encode(data, result);
    result.resize(encoded_size);
    expect(eq(encoded, result));
    expect(hpp::proto::base64::decode(encoded, result));
    expect(eq(data, result));
  };

  verify("", "");
  verify("light work.", "bGlnaHQgd29yay4=");
  verify("light work", "bGlnaHQgd29yaw==");
  verify("light wor", "bGlnaHQgd29y");

  verify("f", "Zg==");
  verify("fo", "Zm8=");
  verify("foo", "Zm9v");
  verify("foob", "Zm9vYg==");
  verify("fooba", "Zm9vYmE=");
  verify("foobar", "Zm9vYmFy");
};

template <typename T>
void verify(const T &msg, std::string_view json, const std::source_location& from_loc= std::source_location::current()) {
  using namespace boost::ut;
  std::string from_line_number = "from line " + std::to_string(from_loc.line());
  expect(eq(json, hpp::proto::write_json(msg).value())) << from_line_number;

  T msg2;

  if constexpr (!non_owning<T>) {
    expect((!hpp::proto::read_json(msg2, json)) >> fatal) << from_line_number;;
    expect(msg == msg2);
  } else {
    monotonic_buffer_resource mr{1024};
    expect((!hpp::proto::read_json(msg2, json, mr)) >> fatal) << from_line_number;;
    expect(msg == msg2);
  }
}

template <typename Bytes>
struct bytes_example {
  Bytes field0;
  std::optional<Bytes> field1;
  hpp::proto::optional<Bytes, hpp::proto::cts_wrapper<"test">{}> field2;
  Bytes field3;
  bool operator==(const bytes_example &other) const {
    auto equal_optional_range = [](const auto &lhs, const auto &rhs) {
      return (lhs.has_value() == rhs.has_value()) && (!lhs.has_value() || (std::ranges::equal(*lhs, *rhs)));
    };
    return std::ranges::equal(field0, other.field0) && equal_optional_range(field1, other.field1) &&
           equal_optional_range(field2, other.field2) && std::ranges::equal(field3, other.field3);
  }
};

template <>
constexpr auto non_owning<std::string_view> = true;

template <typename T>
constexpr auto non_owning<std::span<const T>> = true;

template <typename Bytes>
constexpr auto non_owning<bytes_example<Bytes>> = non_owning<Bytes>;

template <typename Bytes>
struct glz::meta<bytes_example<Bytes>> {
  using T = bytes_example<Bytes>;
  // clang-format off
  static constexpr auto value = object("field0", &T::field0,
                                       "field1", &T::field1, 
                                       "field2", &T::field2, 
                                       "field3", hpp::proto::as_optional_ref<&T::field3>);
  // clang-format on
};

const ut::suite test_bytes = [] {
  using namespace boost::ut::literals;
  using namespace boost::ut;

  "bytes"_test = []<class Bytes> {
    verify(bytes_example<Bytes>{}, R"({"field0":""})");
    using namespace hpp::proto::literals;
    verify(bytes_example<Bytes>{.field0 = static_cast<Bytes>("foo"_cts),
                                .field1 = static_cast<Bytes>("light work."_cts),
                                .field2 = static_cast<Bytes>("light work"_cts),
                                .field3 = static_cast<Bytes>("light wor"_cts)},
           R"({"field0":"Zm9v","field1":"bGlnaHQgd29yay4=","field2":"bGlnaHQgd29yaw==","field3":"bGlnaHQgd29y"})");
  } | std::tuple<std::vector<std::byte>, std::span<const std::byte>>{};
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

struct timestamp_t {
  constexpr static bool reflect = false;
  constexpr static auto proto_message_name_ = "timestamp_t";
  int64_t seconds = {};
  int32_t nanos = {};
  bool operator==(const timestamp_t &) const = default;
};

template <>
struct hpp::proto::json_codec<timestamp_t> {
  using type = hpp::proto::timestamp_codec;
};

const ut::suite test_timestamp = [] {
  verify<timestamp_t>(timestamp_t{.seconds = 1000}, R"("1970-01-01T00:16:40Z")");
  verify<timestamp_t>(timestamp_t{.seconds = 1000, .nanos = 20}, R"("1970-01-01T00:16:40.000000020Z")");

  timestamp_t msg;
  ut::expect(!hpp::proto::read_json(msg, R"("1970-01-01T00:16:40.2Z")"));
  ut::expect(msg == timestamp_t{.seconds = 1000, .nanos = 200000000});

  ut::expect(hpp::proto::read_json(msg, R"("1970-01-01T00:16:40.2xZ")"));
  ut::expect(hpp::proto::read_json(msg, R"("1970-01-01T00:16:40")"));
  ut::expect(hpp::proto::read_json(msg, R"("197-01-01T00:16:40")"));
  ut::expect(hpp::proto::read_json(msg, R"("197-01-01T00:16:40.00000000000Z")"));


  ut::expect(!hpp::proto::write_json(timestamp_t{.seconds = 1000, .nanos = 1000000000}).has_value());
};

struct duration_t {
  constexpr static bool reflect = false;
  constexpr static auto proto_message_name_ = "duration_t";
  int64_t seconds = {};
  int32_t nanos = {};
  bool operator==(const duration_t &) const = default;
};

template <>
struct hpp::proto::json_codec<duration_t> {
  using type = hpp::proto::duration_codec;
};

const ut::suite test_duration = [] {
  verify<duration_t>(duration_t{.seconds = 1000}, R"("1000s")");
  verify<duration_t>(duration_t{.seconds = 1000, .nanos = 20}, R"("1000.000000020s")");
  verify<duration_t>(duration_t{.seconds = -1000, .nanos = -20}, R"("-1000.000000020s")");

  duration_t msg;
  ut::expect(!hpp::proto::read_json(msg, R"("1000.2s")"));
  ut::expect(msg == duration_t{.seconds = 1000, .nanos = 200000000});

  ut::expect(!hpp::proto::read_json(msg, R"("-1000.2s")"));
  ut::expect(msg == duration_t{.seconds = -1000, .nanos = -200000000});

  ut::expect(hpp::proto::read_json(msg, R"("1000")"));
  ut::expect(hpp::proto::read_json(msg, R"("1000.2xs")"));
  ut::expect(hpp::proto::read_json(msg, R"("-1000.-10000000s")"));
  ut::expect(hpp::proto::read_json(msg, R"("-1000. 10000000s")"));
  ut::expect(hpp::proto::read_json(msg, R"("1000.0000000000000000s")"));


  ut::expect(!hpp::proto::write_json(duration_t{.seconds = 1000, .nanos = 1000000000}).has_value());
};


struct Int64Value {
  int64_t value;
  bool operator == (const Int64Value&) const = default;
};

namespace glz::detail {
template <>
struct to_json<Int64Value> {
  template <auto Opts>
  GLZ_FLATTEN static void op(auto &value, auto&& ...args) {
    write<json>::template op<opt_true<Opts, &opts::quoted_num>>(value.value, std::forward<decltype(args)>(args)...);
  }
};

template <>
struct from_json<Int64Value> {
  template <auto Opts>
  GLZ_FLATTEN static void op(auto &value, auto&& ...args) {
    read<json>::template op<opt_true<Opts, &opts::quoted_num>>(value.value, std::forward<decltype(args)>(args)...);
  }
};
}

const ut::suite test_wrapper = [] {
  verify<Int64Value>(Int64Value{1000}, R"("1000")");
};

int main() {

  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}