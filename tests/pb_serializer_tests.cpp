#include "test_util.h"
#include <boost/ut.hpp>
#include <hpp_proto/pb_serializer.h>

namespace ut = boost::ut;
using namespace zpp::bits::literals;
using hpp::proto::encoding_rule;

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

  std::vector<std::byte> new_data;
  ut::expect(success(hpp::proto::out{new_data}(value)));

  ut::expect(equal_range(encoded_data, new_data));
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

struct non_owning_repeated_integers {
  std::span<const int32_t> integers;
  bool operator==(const non_owning_repeated_integers &other) const { return equal_range(integers, other.integers); }
};

auto pb_meta(const non_owning_repeated_integers &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, zpp::bits::vsint32_t>>;

struct non_owning_repeated_integers_unpacked {
  std::span<const zpp::bits::vsint32_t> integers;
  bool operator==(const non_owning_repeated_integers_unpacked &other) const {
    return equal_range(integers, other.integers);
  }
};

auto pb_meta(const non_owning_repeated_integers_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated>>;

struct non_owning_repeated_integers_unpacked_explicit_type {
  std::span<const int32_t> integers;
  bool operator==(const non_owning_repeated_integers_unpacked_explicit_type &other) const {
    return equal_range(integers, other.integers);
  }
};

auto pb_meta(const non_owning_repeated_integers_unpacked_explicit_type &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated, zpp::bits::vsint32_t>>;

template <typename T>
void verify_non_owning(auto encoded_data, T &&expected_value, std::size_t memory_size, test_mode mode = decode_encode) {
  std::remove_cvref_t<T> value;

  monotonic_memory_resource mr{memory_size};
  ut::expect(success(hpp::proto::in{encoded_data, mr}(value)));
  ut::expect(value == expected_value);

  if (mode == decode_only)
    return;

  std::array<std::byte, encoded_data.size()> new_data;
  ut::expect(success(hpp::proto::out{new_data}(value)));

  ut::expect(encoded_data == new_data);
}

ut::suite test_non_owning_repeated_integers = [] {
  "non_owning_repeated_integers"_test = [] {
    std::array x{0, 1, 2, 3, 4, -1, -2, -3, -4};
    verify_non_owning("\x0a\x09\x00\x02\x04\x06\x08\x01\x03\x05\x07"_bytes_array, non_owning_repeated_integers{x}, 64);
  };

  "non_owning_repeated_integers_unpacked"_test = [] {
    std::array<zpp::bits::vsint32_t, 8> x{1, 2, 3, 4, -1, -2, -3, -4};
    verify_non_owning("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x01\x08\x03\x08\x05\x08\x07"_bytes_array,
                      non_owning_repeated_integers_unpacked{x}, 64);
  };

  "non_owning_repeated_integers_unpacked_decode"_test = [] {
    std::array x{1, 2, 3, 4, -1, -2, -3, -4};
    verify_non_owning("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x01\x08\x03\x08\x05\x08\x07"_bytes_array,
                      non_owning_repeated_integers{x}, 64, decode_only);
  };

  "non_owning_repeated_integers_unpacked_explicit_type"_test = [] {
    std::array x{1, 2, 3, 4, -1, -2, -3, -4};
    verify_non_owning("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x01\x08\x03\x08\x05\x08\x07"_bytes_array,
                      non_owning_repeated_integers_unpacked_explicit_type{x}, 64);
  };
};

struct non_owing_nested_example {
  const example *nested; // field number == 1

  constexpr bool operator==(const non_owing_nested_example &other) const {
    return nested == other.nested || (nested && other.nested && *nested == *other.nested);
  }
};

ut::suite test_non_owning_nested_example = [] {
  example ex{.i = 150};
  verify_non_owning("\x0a\x03\x08\x96\x01"_bytes_array, non_owing_nested_example{.nested = &ex}, 16);
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

struct non_owning_repeated_fixed {
  std::span<const uint64_t> integers;
  bool operator==(const non_owning_repeated_fixed &other) const { return equal_range(integers, other.integers); }
};
struct non_owning_repeated_fixed_explicit_type {
  std::span<const uint64_t> integers;
  bool operator==(const non_owning_repeated_fixed_explicit_type &other) const {
    return equal_range(integers, other.integers);
  }
};

auto pb_meta(const non_owning_repeated_fixed_explicit_type &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, uint64_t>>;
struct non_owning_repeated_fixed_unpacked {
  std::span<const uint64_t> integers;
  bool operator==(const non_owning_repeated_fixed_unpacked &other) const {
    return equal_range(integers, other.integers);
  }
};

auto pb_meta(const non_owning_repeated_fixed_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated>>;

struct non_owning_repeated_fixed_unpacked_explicit_type {
  std::span<const uint64_t> integers;
  bool operator==(const non_owning_repeated_fixed_unpacked_explicit_type &other) const {
    return equal_range(integers, other.integers);
  }
};

auto pb_meta(const non_owning_repeated_fixed_unpacked_explicit_type &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated, uint64_t>>;

ut::suite test_non_owning_repeated_fixed = [] {
  "non_owning_repeated_fixed"_test = [] {
    std::array<uint64_t, 3> x{1, 2, 3};
    verify_non_owning(
        "\x0a\x18\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_array,
        non_owning_repeated_fixed{x}, 32);
  };

  "non_owning_repeated_fixed_explicit_type"_test = [] {
    std::array<uint64_t, 3> x{1, 2, 3};
    verify_non_owning(
        "\x0a\x18\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_array,
        non_owning_repeated_fixed_explicit_type{x}, 32);
  };

  "non_owning_repeated_fixed_unpacked"_test = [] {
    std::array<uint64_t, 3> x{1, 2, 3};
    verify_non_owning(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_array,
        non_owning_repeated_fixed_unpacked{x}, 32);
  };

  "non_owning_repeated_fixed_unpacked_decode"_test = [] {
    std::array<uint64_t, 3> x{1, 2, 3};
    verify_non_owning(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_array,
        non_owning_repeated_fixed{x}, 32, decode_only);
  };

  "non_owning_repeated_fixed_unpacked_explicit_type_decode"_test = [] {
    std::array<uint64_t, 3> x{1, 2, 3};
    verify_non_owning(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_array,
        non_owning_repeated_fixed_explicit_type{x}, 32, decode_only);
  };

  "non_owning_repeated_fixed_unpacked_explicit_type"_test = [] {
    std::array<uint64_t, 3> x{1, 2, 3};
    verify_non_owning(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"_bytes_array,
        non_owning_repeated_fixed_unpacked_explicit_type{x}, 32);
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

struct non_owning_repeated_bool {
  std::span<const bool> booleans;
  bool operator==(const non_owning_repeated_bool &other) const { return equal_range(booleans, other.booleans); }
};

auto pb_meta(const non_owning_repeated_bool &) -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, bool>>;

struct non_owning_repeated_bool_unpacked {
  std::span<const bool> booleans;
  bool operator==(const non_owning_repeated_bool_unpacked &other) const {
    return equal_range(booleans, other.booleans);
  }
};

auto pb_meta(const non_owning_repeated_bool_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated, bool>>;

ut::suite test_non_owning_repeated_bool = [] {
  "non_owning_repeated_bool"_test = [] {
    std::array x{true, false, true};
    verify_non_owning("\x0a\x03\x01\x00\x01"_bytes_array, non_owning_repeated_bool{x}, 8);
  };

  "non_owning_repeated_bool_unpacked"_test = [] {
    std::array x{true, false, true};
    verify_non_owning("\x08\x01\x08\x00\x08\x01"_bytes_array, non_owning_repeated_bool_unpacked{x}, 8);
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
  "repeated_enum"_test = [] {
    using enum repeated_enum::NestedEnum;
    verify("\x0a\x0d\x01\x02\x03\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_array,
           repeated_enum{{FOO, BAR, BAZ, NEG}});
  };

  "repeated_enum_unpacked"_test = [] {
    using enum repeated_enum_unpacked::NestedEnum;
    verify("\x08\x01\x08\x02\x08\x03\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_array,
           repeated_enum_unpacked{{FOO, BAR, BAZ, NEG}});
  };
};

struct non_owning_repeated_enum {
  enum class NestedEnum { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
  std::span<const NestedEnum> values;
  bool operator==(const non_owning_repeated_enum &other) const { return equal_range(values, other.values); }
};

auto pb_meta(const non_owning_repeated_enum &) -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted>>;

struct non_owning_repeated_enum_unpacked {
  enum class NestedEnum { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
  std::span<const NestedEnum> values;
  bool operator==(const non_owning_repeated_enum_unpacked &other) const { return equal_range(values, other.values); }
};

auto pb_meta(const non_owning_repeated_enum_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated>>;

ut::suite test_non_owning_repeated_enums = [] {
  "non_owning_repeated_enum"_test = [] {
    using enum non_owning_repeated_enum::NestedEnum;
    std::array<non_owning_repeated_enum::NestedEnum, 4> x{FOO, BAR, BAZ, NEG};
    verify_non_owning("\x0a\x0d\x01\x02\x03\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_array,
                      non_owning_repeated_enum{x}, 64);
  };

  "non_owning_repeated_enum_unpacked"_test = [] {
    using enum non_owning_repeated_enum_unpacked::NestedEnum;
    std::array<non_owning_repeated_enum_unpacked::NestedEnum, 4> x{FOO, BAR, BAZ, NEG};
    verify_non_owning("\x08\x01\x08\x02\x08\x03\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_array,
                      non_owning_repeated_enum_unpacked{x}, 32);
  };
};

struct repeated_examples {
  std::vector<example> examples;
  bool operator==(const repeated_examples &) const = default;
};

auto pb_meta(const repeated_examples &) -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated>>;

struct non_owning_repeated_examples {
  std::span<const example> examples;
  bool operator==(const non_owning_repeated_examples &other) const { return equal_range(examples, other.examples); }
};

auto pb_meta(const non_owning_repeated_examples &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::unpacked_repeated>>;

ut::suite test_repeated_example = [] {
  auto encoded = "\x0a\x02\x08\x01\x0a\x02\x08\x02\x0a\x02\x08\x03\x0a\x02\x08\x04\x0a\x0b\x08\xff\xff\xff\xff\xff\xff"
                 "\xff\xff\xff\x01\x0a\x0b\x08\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x01\x0a\x0b\x08\xfd\xff\xff\xff\xff"
                 "\xff\xff\xff\xff\x01\x0a\x0b\x08\xfc\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_array;

  "repeated_example"_test = [&] {
    repeated_examples expected{.examples = {{1}, {2}, {3}, {4}, {-1}, {-2}, {-3}, {-4}}};
    verify(encoded, expected);
  };

  "non_owning_repeated_example"_test = [&] {
    std::array<example, 8> x = {example{1},  example{2},  example{3},  example{4},
                                example{-1}, example{-2}, example{-3}, example{-4}};
    non_owning_repeated_examples expected{.examples = x};
    verify_non_owning(encoded, expected, 64);
  };
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
  auto encoded = "\x0b\x10\x01\x0c\x0b\x10\x02\x0c"_bytes_array;

  "repeated_group"_test = [&] {
    repeated_group expected{.repeatedgroup = {{1}, {2}}};
    verify(encoded, expected);
  };
};

enum class color_t { red, blue, green };

struct map_example {
  std::map<int32_t, color_t> dict;
  bool operator==(const map_example &) const = default;
};

auto pb_meta(const map_example &) -> std::tuple<
    hpp::proto::field_meta<1, encoding_rule::defaulted, hpp::proto::map_entry<zpp::bits::vint64_t, color_t>>>;

struct flat_map_example {
  hpp::proto::flat_map<int32_t, color_t> dict;
  bool operator==(const flat_map_example &) const = default;
};

auto pb_meta(const flat_map_example &) -> std::tuple<
    hpp::proto::field_meta<1, encoding_rule::defaulted, hpp::proto::map_entry<zpp::bits::vint64_t, color_t>>>;

struct sequential_map_example {
  std::vector<std::pair<int32_t, color_t>> dict;
  bool operator==(const sequential_map_example &) const = default;
};

auto pb_meta(const sequential_map_example &) -> std::tuple<
    hpp::proto::field_meta<1, encoding_rule::defaulted, hpp::proto::map_entry<zpp::bits::vint64_t, color_t>>>;

struct non_owning_map_example {
  std::span<const std::pair<int32_t, color_t>> dict;
  bool operator==(const non_owning_map_example &other) const { return equal_range(dict, other.dict); }
};

auto pb_meta(const non_owning_map_example &) -> std::tuple<
    hpp::proto::field_meta<1, encoding_rule::defaulted, hpp::proto::map_entry<zpp::bits::vint64_t, color_t>>>;

ut::suite test_map_example = [] {
  auto encoded = "\x0a\x04\x08\x01\x10\x00\x0a\x04\x08\x02\x10\x01\x0a\x04\x08\x03\x10\x02"_bytes_array;

  "map_example"_test = [&] {
    verify(encoded, map_example{{{1, color_t::red}, {2, color_t::blue}, {3, color_t::green}}});
  };

  "flat_map_example"_test = [&] {
    verify(encoded, flat_map_example{{{1, color_t::red}, {2, color_t::blue}, {3, color_t::green}}});
  };

  "sequential_map_example"_test = [&] {
    verify(encoded, sequential_map_example{{{1, color_t::red}, {2, color_t::blue}, {3, color_t::green}}});
  };

  "non_owning_map_example"_test = [&] {
    using value_type = std::pair<int32_t, color_t>;
    std::array<value_type, 3> x = {value_type{1, color_t::red}, value_type{2, color_t::blue},
                                   value_type{3, color_t::green}};
    verify_non_owning(encoded, non_owning_map_example{x}, 32);
  };
};

struct string_example {
  std::string value;
  bool operator==(const string_example &) const = default;
};

auto pb_meta(const string_example &) -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted>>;

using namespace hpp::proto::literals;

struct string_with_default {
  std::string value = "test";
  bool operator==(const string_with_default &) const = default;
};
auto pb_meta(const string_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, void, "test"_cts>>;

auto serialize(const string_with_default &) -> zpp::bits::members<1>;

struct string_with_optional {
  hpp::proto::optional<std::string, "test"_cts> value;
  bool operator==(const string_with_optional &) const = default;
};
auto pb_meta(const string_with_optional &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence, void>>;

auto serialize(const string_with_optional &) -> zpp::bits::members<1>;

ut::suite test_string_example = [] {
  "string_example"_test = [] { verify("\x0a\x04\x74\x65\x73\x74"_bytes_array, string_example{.value = "test"}); };

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
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, void, "test"_cts>>;

auto serialize(const string_view_with_default &) -> zpp::bits::members<1>;

struct string_view_with_optional {
  hpp::proto::optional<std::string_view, "test"_cts> value;
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
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, void, "test"_cts>>;

auto serialize(const bytes_with_default &) -> zpp::bits::members<1>;

struct bytes_with_optional {
  hpp::proto::optional<std::vector<std::byte>, "test"_cts> value;
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
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, void, "test"_cts>>;

auto serialize(const char_vector_with_default &) -> zpp::bits::members<1>;

struct char_vector_with_optional {
  hpp::proto::optional<std::vector<char>, "test"_cts> value;
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
  bool operator==(const byte_span_example &other) const { return equal_range(value, other.value); }
};

struct byte_span_explicit_presence {
  std::span<const std::byte> value;
  bool operator==(const byte_span_explicit_presence &other) const { return equal_range(value, other.value); }
};

auto pb_meta(const byte_span_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence>>;

struct byte_span_with_default {
  std::span<const std::byte> value = "test"_bytes_view;
  bool operator==(const byte_span_with_default &other) const { return equal_range(value, other.value); }
};

auto pb_meta(const byte_span_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, void, "test"_cts>>;

auto serialize(const byte_span_with_default &) -> zpp::bits::members<1>;

struct byte_span_with_optional {
  hpp::proto::optional<std::span<const std::byte>, "test"_cts> value;
  bool operator==(const byte_span_with_optional &other) const {
    return (!value.has_value() && !other.value.has_value()) ||
           (value.has_value() && other.value.has_value() && equal_range(*value, *other.value));
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

struct non_owning_repeated_string {
  std::span<std::string_view> values;
  bool operator==(const non_owning_repeated_string &other) const { return equal_range(values, other.values); }
};

auto pb_meta(const non_owning_repeated_string &) -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted>>;

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

  "non_owning_repeated_string"_test = [] {
    std::string_view storage[] = {"abc"sv, "def"sv};

    verify_non_owning("\x0a\x03\x61\x62\x63\x0a\x03\x64\x65\x66"_bytes_array,
                      non_owning_repeated_string{.values = storage}, 32);
  };
};

struct optional_bools {
  hpp::proto::optional<bool> false_defaulted;
  hpp::proto::optional<bool, true> true_defaulted;
  bool operator==(const optional_bools &) const = default;
};
auto serialize(const optional_bools &) -> zpp::bits::members<2>;

auto pb_meta(const optional_bools &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::explicit_presence>,
                  hpp::proto::field_meta<2, encoding_rule::explicit_presence, bool, true>>;

ut::suite test_optional_bools = [] {
  "empty_optional_bools"_test = [] {
    std::vector<std::byte> data;
    verify(data, optional_bools{});
  };

  "optional_bools_all_true"_test = [] {
    verify("\x08\x01\x10\x01"_bytes_array, optional_bools{.false_defaulted = true, .true_defaulted = true});
  };

  "optional_bools_all_false"_test = [] {
    verify("\x08\x00\x10\x00"_bytes_array, optional_bools{.false_defaulted = false, .true_defaulted = false});
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

  [[nodiscard]] auto get_extension(auto meta) { return meta.read(extensions, std::monostate{}); }

  template <typename Meta>
  [[nodiscard]] std::error_code set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }

  template <typename Meta>
    requires Meta::is_repeated
  [[nodiscard]] std::error_code set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
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
  return hpp::proto::repeated_extension_meta<extension_example, 21, encoding_rule::unpacked_repeated, void,
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
    {
      auto v = value.get_extension(repeated_i32_ext());
      ut::expect(v.has_value());
      ut::expect(v.value() == std::vector<int32_t>{1, 2});
    }
    {
      auto v = value.get_extension(repeated_string_ext());
      ut::expect(v.has_value());
      ut::expect(v == std::vector<std::string>{"abc", "def"});
    }
    {
      auto v = value.get_extension(repeated_packed_i32_ext());
      ut::expect(v.has_value());
      ut::expect(v == std::vector<int32_t>{1, 2, 3});
    }

    std::array<std::byte, encoded_data.size()> new_data;
    ut::expect(success(hpp::proto::out{new_data}(value)));

    ut::expect(encoded_data == new_data);
  };
  "set_extension"_test = [] {
    extension_example value;
    ut::expect(!value.set_extension(i32_ext(), 1));
    ut::expect(value.extensions.fields[10] == "\x50\x01"_bytes);

    ut::expect(!value.set_extension(string_ext(), "test"));
    ut::expect(value.extensions.fields[11] == "\x5a\x04\x74\x65\x73\x74"_bytes);

    ut::expect(!value.set_extension(i32_defaulted_ext(), 10));
    ut::expect(value.extensions.fields.count(13) == 0);

    ut::expect(!value.set_extension(example_ext(), {.i = 150}));
    ut::expect(value.extensions.fields[15] == "\x7a\x03\x08\x96\x01"_bytes);

    ut::expect(!value.set_extension(repeated_i32_ext(), {1, 2}));
    ut::expect(value.extensions.fields[20] == "\xa0\x01\x01\xa0\x01\x02"_bytes);

    ut::expect(!value.set_extension(repeated_string_ext(), {"abc", "def"}));
    ut::expect(value.extensions.fields[21] == "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes);

    ut::expect(!value.set_extension(repeated_packed_i32_ext(), {1, 2, 3}));
    ut::expect(value.extensions.fields[22] == "\xb2\x01\x03\01\02\03"_bytes);
  };
};

struct non_owning_extension_example {
  int32_t int_value;
  struct extension_t {
    using pb_extension = non_owning_extension_example;
    std::span<std::pair<uint32_t, std::span<const std::byte>>> fields;
    bool operator==(const extension_t &other) const {
      return std::equal(fields.begin(), fields.end(), other.fields.begin(), other.fields.end(),
                        [](const auto &lhs, const auto &rhs) {
                          return lhs.first == rhs.first && equal_range(lhs.second, rhs.second);
                        });
    }
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) { return meta.read(extensions, std::monostate{}); }

  [[nodiscard]] auto get_extension(auto meta, hpp::proto::concepts::memory_resource auto &mr) {
    return meta.read(extensions, mr);
  }

  template <typename Meta>
  [[nodiscard]] std::error_code set_extension(Meta meta, typename Meta::set_value_type &&value,
                                              hpp::proto::concepts::memory_resource auto &mr) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value), mr);
  }

  template <typename Meta>
    requires Meta::is_repeated
  [[nodiscard]] std::error_code set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value,
                                              hpp::proto::concepts::memory_resource auto &mr) {
    return meta.write(extensions, std::span<const typename Meta::element_type>(value.begin(), value.end()), mr);
  }

  bool has_extension(auto meta) const { return meta.element_of(extensions); }
  bool operator==(const non_owning_extension_example &other) const = default;
};

auto pb_meta(const non_owning_extension_example &)
    -> std::tuple<hpp::proto::field_meta<1, encoding_rule::defaulted, zpp::bits::vint64_t>,
                  hpp::proto::field_meta<UINT32_MAX>>;

constexpr auto non_owning_i32_ext() {
  return hpp::proto::extension_meta<non_owning_extension_example, 10, encoding_rule::explicit_presence,
                                    zpp::bits::vint64_t, int32_t>{};
}

constexpr auto non_owning_string_ext() {
  return hpp::proto::extension_meta<non_owning_extension_example, 11, encoding_rule::explicit_presence,
                                    std::string_view, std::string_view>{};
}

constexpr auto non_owning_i32_defaulted_ext() {
  return hpp::proto::extension_meta<non_owning_extension_example, 13, encoding_rule::defaulted, zpp::bits::vint64_t,
                                    int32_t, zpp::bits::vint64_t{10}>{};
}

constexpr auto non_owning_i32_unset_ext() {
  return hpp::proto::extension_meta<non_owning_extension_example, 14, encoding_rule::explicit_presence,
                                    zpp::bits::vint64_t, int32_t>{};
}

constexpr auto non_owning_example_ext() {
  return hpp::proto::extension_meta<non_owning_extension_example, 15, encoding_rule::explicit_presence, example,
                                    example>{};
}

constexpr auto non_owning_repeated_i32_ext() {
  return hpp::proto::repeated_extension_meta<non_owning_extension_example, 20, encoding_rule::unpacked_repeated,
                                             zpp::bits::vint64_t, int32_t>{};
}

constexpr auto non_owning_repeated_string_ext() {
  return hpp::proto::repeated_extension_meta<non_owning_extension_example, 21, encoding_rule::unpacked_repeated, void,
                                             std::string_view>{};
}

constexpr auto non_owning_repeated_packed_i32_ext() {
  return hpp::proto::repeated_extension_meta<non_owning_extension_example, 22, encoding_rule::defaulted,
                                             zpp::bits::vint64_t, int32_t>{};
}

ut::suite test_non_owning_extensions = [] {
  "get_non_owning_extension"_test = [] {
    auto encoded_data =
        "\x08\x96\x01\x50\x01\x5a\x04\x74\x65\x73\x74\x7a\x03\x08\x96\x01\xa0\x01\x01\xa0\x01\x02\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66\xb2\x01\x03\01\02\03"_bytes_array;

    std::array<std::pair<uint32_t, std::span<const std::byte>>, 6> fields_storage = {
        {{10U, "\x50\x01"_bytes_view},
         {11U, "\x5a\x04\x74\x65\x73\x74"_bytes_view},
         {15U, "\x7a\x03\x08\x96\x01"_bytes_view},
         {20U, "\xa0\x01\x01\xa0\x01\x02"_bytes_view},
         {21U, "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes_view},
         {22U, "\xb2\x01\x03\01\02\03"_bytes_view}}};

    non_owning_extension_example expected_value{.int_value = 150, .extensions = {.fields = fields_storage}};
    non_owning_extension_example value;

    monotonic_memory_resource mr{1024};
    ut::expect(success(hpp::proto::in{encoded_data, mr}(value)));
    ut::expect(value == expected_value);

    ut::expect(value.has_extension(non_owning_i32_ext()));
    ut::expect(value.has_extension(non_owning_string_ext()));
    ut::expect(!value.has_extension(non_owning_i32_defaulted_ext()));
    ut::expect(!value.has_extension(non_owning_i32_unset_ext()));
    ut::expect(value.has_extension(non_owning_example_ext()));

    {
      auto v = value.get_extension(non_owning_i32_ext());
      ut::expect(v.has_value());
      ut::expect(v.value() == 1);
    }
    {
      auto v = value.get_extension(non_owning_string_ext(), mr);
      ut::expect(v.has_value());
      ut::expect(v.value() == "test");
    }
    {
      auto v = value.get_extension(non_owning_example_ext());
      ut::expect(v.has_value());
      ut::expect(v.value() == example{.i = 150});
    }
    {
      auto v = value.get_extension(non_owning_repeated_i32_ext(), mr);
      ut::expect(v.has_value());
      ut::expect(equal_range(v.value(), std::initializer_list<uint32_t>{1, 2}));
    }
    {
      auto v = value.get_extension(non_owning_repeated_string_ext(), mr);
      ut::expect(v.has_value());
      using namespace std::literals;
      ut::expect(equal_range(v.value(), std::initializer_list<std::string_view>{"abc"sv, "def"sv}));
    }
    {
      auto v = value.get_extension(non_owning_repeated_packed_i32_ext(), mr);
      ut::expect(v.has_value());
      ut::expect(equal_range(v.value(), std::initializer_list<uint32_t>{1, 2, 3}));
    }

    std::array<std::byte, encoded_data.size()> new_data;
    ut::expect(success(hpp::proto::out{new_data}(value)));

    ut::expect(encoded_data == new_data);
  };
  "set_non_owning_extension"_test = [] {
    monotonic_memory_resource mr{1024};
    non_owning_extension_example value;
    ut::expect(!value.set_extension(non_owning_i32_ext(), 1, mr));
    ut::expect(value.extensions.fields.back().first == 10);
    ut::expect(equal_range(value.extensions.fields.back().second, "\x50\x01"_bytes));

    ut::expect(!value.set_extension(non_owning_string_ext(), "test", mr));
    ut::expect(value.extensions.fields.back().first == 11);
    ut::expect(equal_range(value.extensions.fields.back().second, "\x5a\x04\x74\x65\x73\x74"_bytes));

    ut::expect(!value.set_extension(non_owning_i32_defaulted_ext(), 10, mr));
    ut::expect(value.extensions.fields.back().first != 13);

    ut::expect(!value.set_extension(non_owning_example_ext(), {.i = 150}, mr));
    ut::expect(value.extensions.fields.back().first == 15);
    ut::expect(equal_range(value.extensions.fields.back().second, "\x7a\x03\x08\x96\x01"_bytes));

    ut::expect(!value.set_extension(non_owning_repeated_i32_ext(), {1, 2}, mr));
    ut::expect(value.extensions.fields.back().first == 20);
    ut::expect(equal_range(value.extensions.fields.back().second, "\xa0\x01\x01\xa0\x01\x02"_bytes));

    using namespace std::literals;
    ut::expect(!value.set_extension(non_owning_repeated_string_ext(), {"abc"sv, "def"sv}, mr));
    ut::expect(value.extensions.fields.back().first == 21);
    ut::expect(
        equal_range(value.extensions.fields.back().second, "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes));

    ut::expect(!value.set_extension(non_owning_repeated_packed_i32_ext(), {1, 2, 3}, mr));
    ut::expect(value.extensions.fields.back().first == 22);
    ut::expect(equal_range(value.extensions.fields.back().second, "\xb2\x01\x03\01\02\03"_bytes));
  };
};

struct recursive_type1 {
  hpp::proto::heap_based_optional<recursive_type1> child;
  uint32_t payload;

  bool operator==(const recursive_type1 &other) const = default;

#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARATOR
  friend auto operator<=>(const recursive_type1 &, const recursive_type1 &) = default;
#endif
};

auto pb_meta(const recursive_type1 &)
    -> std::tuple<hpp::proto::field_meta<1>, hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>>;

struct recursive_type2 {
  std::vector<recursive_type2> children;
  int32_t payload;

  bool operator==(const recursive_type2 &other) const = default;
};

auto pb_meta(const recursive_type2 &)
    -> std::tuple<hpp::proto::field_meta<1>, hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>>;

struct non_owning_recursive_type1 {
  non_owning_recursive_type1 *child = nullptr;
  uint32_t payload;

  bool operator==(const non_owning_recursive_type1 &other) const {
    return payload == other.payload &&
           ((child == other.child) || (child != nullptr && other.child != nullptr && *child == *other.child));
  }
};

auto pb_meta(const non_owning_recursive_type1 &)
    -> std::tuple<hpp::proto::field_meta<1>, hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>>;

struct non_owning_recursive_type2 {
  std::span<non_owning_recursive_type2> children = {};
  int32_t payload;
#ifdef _LIBCPP_VERSION
  constexpr non_owning_recursive_type2() = default;
  constexpr non_owning_recursive_type2(const non_owning_recursive_type2 &other)
      : children(other.children.data(), other.children.size()), payload(other.payload) {}
  constexpr non_owning_recursive_type2& operator=(const non_owning_recursive_type2 &other) = default;
#endif
  bool operator==(const non_owning_recursive_type2 &other) const {
    return payload == other.payload &&
           std::equal(children.begin(), children.end(), other.children.begin(), other.children.end());
  }
};

auto serialize(const non_owning_recursive_type2 &) -> zpp::bits::members<2>;


auto pb_meta(const non_owning_recursive_type2 &)
    -> std::tuple<hpp::proto::field_meta<1>, hpp::proto::field_meta<2, encoding_rule::defaulted, zpp::bits::vint64_t>>;

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

  "non_owning_recursive_type1"_test = [] {
    non_owning_recursive_type1 child{nullptr, 2};
    non_owning_recursive_type1 value{&child, 1};

    verify_non_owning("\x0a\x02\x10\x02\x10\x01"_bytes_array, value, 64);
  };

  "non_owning_recursive_type2"_test = [] {
    non_owning_recursive_type2 child[1];
    child[0].payload = 2;
    non_owning_recursive_type2 value;
    value.children = child;
    value.payload = 1;

    verify_non_owning("\x0a\x02\x10\x02\x10\x01"_bytes_array, value, 64);
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
                 hpp::proto::field_meta<3>,
                 hpp::proto::field_meta<4, encoding_rule::defaulted, hpp::proto::map_entry<std::string, phone_type>>>;
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