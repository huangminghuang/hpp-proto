#include "test_util.h"
#include <boost/ut.hpp>
#include <hpp_proto/json_serializer.h>

struct bytes_example {
  hpp::proto::bytes field;
  bool operator==(const bytes_example &other) const = default;
};

template <>
struct glz::meta<bytes_example> {
  using T = bytes_example;
  static constexpr auto value = object("field", hpp::proto::as_optional_ref<&T::field>);
};

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
struct glz::meta<non_owning_nested_example> {
  using T = non_owning_nested_example;
  static constexpr auto value = object("nested", &T::nested);
};

template <typename T, int MemoryResourceSize = 0>
void verify(const T &msg, std::string_view json) {
  using namespace boost::ut;
  expect(json == hpp::proto::write_json(msg));

  T msg2;

  if constexpr (MemoryResourceSize == 0) {
    expect((!hpp::proto::read_json(msg2, json)) >> fatal);
    expect(msg == msg2);
  } else {
    monotonic_buffer_resource mr{MemoryResourceSize};
    expect((!hpp::proto::read_json(msg2, json, mr)) >> fatal);
    expect(msg == msg2);
  }
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
template <typename Msg, int MemoryResourceSize = 0>
void verify_bytes(std::string_view text, std::string_view json) {
  using namespace boost::ut;
#ifdef __cpp_lib_bit_cast
  const std::span<const std::byte> bs{std::bit_cast<const std::byte *>(text.data()), text.size()};
#else
  const std::span<const std::byte> bs{reinterpret_cast<const std::byte *>(text.data()), text.size()};
#endif

  Msg msg;
  // NOLINTBEGIN(bugprone-assignment-in-if-condition)
  if constexpr (requires { msg.field = bs; }) {
    msg.field = bs;
  } else {
    msg.field.assign(bs.begin(), bs.end());
  }
  // NOLINTEND(bugprone-assignment-in-if-condition)

  verify<Msg, MemoryResourceSize>(std::move(msg), json);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

namespace ut = boost::ut;

const ut::suite test_bytes_json = [] {
  using namespace boost::ut::literals;
  "empty"_test = [] { verify_bytes<bytes_example>("", R"({})"); };
  "one_padding"_test = [] { verify_bytes<bytes_example>("light work.", R"({"field":"bGlnaHQgd29yay4="})"); };
  "two_padding"_test = [] { verify_bytes<bytes_example>("light work", R"({"field":"bGlnaHQgd29yaw=="})"); };
  "no_padding"_test = [] { verify_bytes<bytes_example>("light wor", R"({"field":"bGlnaHQgd29y"})"); };

  "non_owning_empty"_test = [] { verify_bytes<byte_span_example, 16>("", R"({})"); };
  "non_owning_one_padding"_test = [] {
    verify_bytes<byte_span_example, 16>("light work.", R"({"field":"bGlnaHQgd29yay4="})");
  };
  "non_owning_two_padding"_test = [] {
    verify_bytes<byte_span_example, 16>("light work", R"({"field":"bGlnaHQgd29yaw=="})");
  };
  "non_owning_no_padding"_test = [] {
    verify_bytes<byte_span_example, 16>("light wor", R"({"field":"bGlnaHQgd29y"})");
  };
};


struct string_as_bytes {
  std::string field;
  bool operator==(const string_as_bytes &other) const = default;
};

template <>
struct glz::meta<string_as_bytes> {
  using T = string_as_bytes;
  static constexpr auto value = object("field", hpp::proto::with_codec<hpp::proto::base64, &T::field>);
};

const ut::suite test_with_codec = [] {
  using namespace boost::ut::literals;
  // "empty"_test = [] { verify_bytes<bytes_example>("", R"({})"); };
  "one_padding"_test = [] { verify(string_as_bytes{"light work."}, R"({"field":"bGlnaHQgd29yay4="})"); };
  // "two_padding"_test = [] { verify_bytes<bytes_example>("light work", R"({"field":"bGlnaHQgd29yaw=="})"); };
  // "no_padding"_test = [] { verify_bytes<bytes_example>("light wor", R"({"field":"bGlnaHQgd29y"})"); };

  // "non_owning_empty"_test = [] { verify_bytes<byte_span_example, 16>("", R"({})"); };
  // "non_owning_one_padding"_test = [] {
  //   verify_bytes<byte_span_example, 16>("light work.", R"({"field":"bGlnaHQgd29yay4="})");
  // };
  // "non_owning_two_padding"_test = [] {
  //   verify_bytes<byte_span_example, 16>("light work", R"({"field":"bGlnaHQgd29yaw=="})");
  // };
  // "non_owning_no_padding"_test = [] {
  //   verify_bytes<byte_span_example, 16>("light wor", R"({"field":"bGlnaHQgd29y"})");
  // };
};

const ut::suite test_uint64_json = [] { verify(uint64_example{.field = 123U}, R"({"field":"123"})"); };

const ut::suite test_optional_json = [] {
  verify(optional_example{.field2 = 123U, .field3 = 456}, R"({"field2":"123","field3":456})");
};

const ut::suite test_uint32_span_json = [] {
  std::array<uint32_t, 3> content{1, 2, 3};
  verify<uint32_span_example, 32>(uint32_span_example{.field = content}, R"({"field":[1,2,3]})");
};

const ut::suite test_pair_vector_json = [] {
  using namespace std::literals::string_literals;
  verify<pair_vector_example, 128>(pair_vector_example{.field = {{"one"s, 1}, {"two"s, 2}, {"three"s, 3}}},
                                   R"({"field":{"one":1,"two":2,"three":3}})");
};

const ut::suite test_pair_span_json = [] {
  using namespace std::literals::string_view_literals;
  std::array<std::pair<std::string_view, int32_t>, 3> content{{{"one"sv, 1}, {"two"sv, 2}, {"three"sv, 3}}};
  verify<pair_span_example, 128>(pair_span_example{.field = content}, R"({"field":{"one":1,"two":2,"three":3}})");
};

const ut::suite test_object_span_json = [] {
  std::array<optional_example, 3> content = {
      {{.field1 = 1, .field2 = 1ULL}, {.field1 = 2, .field2 = 2ULL}, {.field1 = 3, .field2 = 3ULL}}};
  verify<object_span_example, 128>(
      object_span_example{.field = content},
      R"({"field":[{"field1":1,"field2":"1"},{"field1":2,"field2":"2"},{"field1":3,"field2":"3"}]})");
};

const ut::suite test_non_owning_nested = [] {
  const optional_example nested = {.field1 = 1, .field2 = 1ULL};
  verify<non_owning_nested_example, 128>(non_owning_nested_example{.nested = &nested},
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

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}