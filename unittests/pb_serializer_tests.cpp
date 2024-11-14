#include "test_util.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/pb_serializer.hpp>

namespace ut = boost::ut;
using hpp::proto::field_option;
using namespace boost::ut::literals;
using namespace std::string_view_literals;

const ut::suite varint_decode_tests = [] {
  using namespace boost::ut;
  "unchecked_parse_bool"_test = [] {
    bool value;
    std::string_view data = "\x00"sv;
    expect(hpp::proto::unchecked_parse_bool(data.data(), data.data() + data.size(), value) ==
           data.data() + data.size());
    expect(value == false);

    data = "\x01"sv;
    expect(hpp::proto::unchecked_parse_bool(data.data(), data.data() + data.size(), value) ==
           data.data() + data.size());
    expect(value == true);

    // oversized bool
    data = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x01"sv;
    expect(hpp::proto::unchecked_parse_bool(data.data(), data.data() + data.size(), value) ==
           data.data() + data.size());
    expect(value == true);

    // unterminated bool
    data = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xF1"sv;
    expect(hpp::proto::unchecked_parse_bool(data.data(), data.data() + data.size(), value) ==
           data.data() + data.size() + 1);
  };

  using vint64_t = hpp::proto::vint64_t;

  "unchecked_parse_varint"_test =
      [](int64_t arg) {
        std::array<std::byte, 16> data;
        auto end = hpp::proto::unchecked_pack_varint(hpp::proto::varint{arg}, data.data());

        int64_t parsed_value;
        ut::expect(hpp::proto::shift_mix_parse_varint<int64_t>(data.data(), data.data() + data.size(), parsed_value) ==
                   end);
      } |
      std::vector<int64_t>{
          127LL,           16383LL,           2097151LL,           268435455LL,           34359738367LL,
          4398046511103LL, 562949953421311LL, 72057594037927935LL, 9223372036854775807LL, -1LL};

  "unterminated_varint"_test = [] {
    auto data = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xF1"sv;
    auto end = data.data() + 16;
    int64_t parsed_value;
    ut::expect(hpp::proto::shift_mix_parse_varint<int64_t>(data.data(), end, parsed_value) == end + 1);
  };
};

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define carg(...) ([]() constexpr -> decltype(auto) { return __VA_ARGS__; })
// NOLINTEND(cppcoreguidelines-macro-usage)

constexpr void constexpr_verify(auto buffer, auto object_fun) {
  static_assert(std::ranges::equal(buffer(), hpp::proto::write_proto(object_fun)));
  static_assert(object_fun() == hpp::proto::read_proto<decltype(object_fun())>(buffer()).value());
}

struct example {
  int32_t i = 0; // field number == 1

  constexpr bool operator==(const example &) const = default;
};
auto pb_meta(const example &)
    -> std::tuple<hpp::proto::field_meta<1, &example::i, field_option::none, hpp::proto::vint64_t>>;

struct nested_example {
  example nested; // field number == 1
  constexpr bool operator==(const nested_example &) const = default;
};
auto pb_meta(const nested_example &) -> std::tuple<hpp::proto::field_meta<1, &nested_example::nested>>;

struct example_explicit_presence {
  int32_t i; // field number == 1

  constexpr bool operator==(const example_explicit_presence &) const = default;
};

auto pb_meta(const example_explicit_presence &) -> std::tuple<
    hpp::proto::field_meta<1, &example_explicit_presence::i, field_option::explicit_presence, hpp::proto::vint64_t>>;

struct example_default_type {
  int32_t i = 1; // field number == 1

  constexpr bool operator==(const example_default_type &) const = default;
};

auto pb_meta(const example_default_type &)
    -> std::tuple<hpp::proto::field_meta<1, &example_default_type::i, field_option::none, hpp::proto::vint64_t, 1>>;

const ut::suite test_example_default_type = [] {
  example_default_type const v;
  std::vector<char> data;
  ut::expect(hpp::proto::write_proto(v, data).ok());
  ut::expect(data.empty());
};

struct example_optional_type {
  hpp::proto::optional<int32_t, 1> i; // field number == 1

  constexpr bool operator==(const example_optional_type &) const = default;
};

auto pb_meta(const example_optional_type &) -> std::tuple<
    hpp::proto::field_meta<1, &example_optional_type::i, field_option::explicit_presence, hpp::proto::vint64_t>>;

enum test_mode : uint8_t { decode_encode, decode_only };

template <typename T>
void verify(auto encoded_data, const T &expected_value, test_mode mode = decode_encode) {
  std::remove_cvref_t<T> value;

  ut::expect(hpp::proto::read_proto(value, encoded_data).ok());
  ut::expect(ut::fatal(value == expected_value));

  if (mode == decode_only) {
    return;
  }

  std::vector<char> new_data;
  ut::expect(hpp::proto::write_proto(value, new_data).ok());

  ut::expect(std::ranges::equal(encoded_data, new_data));
}

struct repeated_sint32 {
  std::vector<int32_t> integers;
  bool operator==(const repeated_sint32 &) const = default;
};

auto pb_meta(const repeated_sint32 &) -> std::tuple<
    hpp::proto::field_meta<1, &repeated_sint32::integers, field_option::is_packed, hpp::proto::vsint32_t>>;

struct repeated_sint32_unpacked {
  std::vector<hpp::proto::vsint32_t> integers;
  bool operator==(const repeated_sint32_unpacked &) const = default;
};

auto pb_meta(const repeated_sint32_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_sint32_unpacked::integers, field_option::none>>;

struct repeated_sint32_unpacked_explicit_type {
  std::vector<int32_t> integers;
  bool operator==(const repeated_sint32_unpacked_explicit_type &) const = default;
};

auto pb_meta(const repeated_sint32_unpacked_explicit_type &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_sint32_unpacked_explicit_type::integers, field_option::none,
                                         hpp::proto::vsint32_t>>;

struct repeated_uint64 {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_uint64 &) const = default;
};

auto pb_meta(const repeated_uint64 &) -> std::tuple<
    hpp::proto::field_meta<1, &repeated_uint64::integers, field_option::is_packed, hpp::proto::vuint64_t>>;

const ut::suite test_repeated_sint32 = [] {
  "repeated_sint32"_test = [] {
    verify("\x0a\x09\x00\x02\x04\x06\x08\x01\x03\x05\x07"sv, repeated_sint32{{0, 1, 2, 3, 4, -1, -2, -3, -4}});
  };

  "repeated_sint32_unpacked"_test = [] {
    verify("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x00\x08\x01\x08\x03\x08\x05\x08\x07"sv,
           repeated_sint32_unpacked{{1, 2, 3, 4, 0, -1, -2, -3, -4}});
  };

  "repeated_sint32_unpacked_decode"_test = [] {
    verify("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x00\x08\x01\x08\x03\x08\x05\x08\x07"sv,
           repeated_sint32{{1, 2, 3, 4, 0, -1, -2, -3, -4}}, decode_only);
  };

  "repeated_sint32_unpacked_explicit_type"_test = [] {
    verify("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x00\x08\x01\x08\x03\x08\x05\x08\x07"sv,
           repeated_sint32_unpacked_explicit_type{{1, 2, 3, 4, 0, -1, -2, -3, -4}});
  };

  "overlong integer"_test = [] {
    repeated_uint64 value;
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x0d\x01\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x10\x02"sv).ok());
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x0d\x01\x02\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x10"sv).ok());
  };
};

struct non_owning_repeated_sint32 {
  hpp::proto::equality_comparable_span<const int32_t> integers;
  bool operator==(const non_owning_repeated_sint32 &) const = default;
};

auto pb_meta(const non_owning_repeated_sint32 &) -> std::tuple<
    hpp::proto::field_meta<1, &non_owning_repeated_sint32::integers, field_option::is_packed, hpp::proto::vsint32_t>>;

struct non_owning_repeated_sint32_unpacked {
  hpp::proto::equality_comparable_span<const hpp::proto::vsint32_t> integers;
  bool operator==(const non_owning_repeated_sint32_unpacked &) const = default;
};

auto pb_meta(const non_owning_repeated_sint32_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owning_repeated_sint32_unpacked::integers, field_option::none>>;

struct non_owning_repeated_sint32_unpacked_explicit_type {
  hpp::proto::equality_comparable_span<const int32_t> integers;
  bool operator==(const non_owning_repeated_sint32_unpacked_explicit_type &) const = default;
};

auto pb_meta(const non_owning_repeated_sint32_unpacked_explicit_type &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owning_repeated_sint32_unpacked_explicit_type::integers,
                                         field_option::none, hpp::proto::vsint32_t>>;

template <typename T>
void verify_non_owning(auto encoded_data, const T &expected_value, std::size_t memory_size,
                       test_mode mode = decode_encode) {
  std::remove_cvref_t<T> value;

  monotonic_buffer_resource mr{memory_size};
  ut::expect(hpp::proto::read_proto(value, encoded_data, mr, hpp::proto::always_allocate_memory{}).ok());
  ut::expect(value == expected_value);

  if (mode == decode_only) {
    return;
  }

  std::vector<char> new_data{};
  ut::expect(hpp::proto::write_proto(value, new_data).ok());

  ut::expect(std::ranges::equal(encoded_data, new_data));
}

const ut::suite test_non_owning_repeated_sint32 = [] {
  "non_owning_repeated_sint32"_test = [] {
    std::array x{0, 1, 2, 3, 4, -1, -2, -3, -4};
    verify_non_owning("\x0a\x09\x00\x02\x04\x06\x08\x01\x03\x05\x07"sv, non_owning_repeated_sint32{x}, 128);
  };

  "non_owning_repeated_sint32_unpacked"_test = [] {
    std::array<hpp::proto::vsint32_t, 9> x{1, 2, 3, 4, 0, -1, -2, -3, -4};
    verify_non_owning("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x00\x08\x01\x08\x03\x08\x05\x08\x07"sv,
                      non_owning_repeated_sint32_unpacked{x}, 128);
  };

  "non_owning_repeated_sint32_unpacked_decode"_test = [] {
    std::array x{1, 2, 3, 4, 0, -1, -2, -3, -4};
    verify_non_owning("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x00\x08\x01\x08\x03\x08\x05\x08\x07"sv,
                      non_owning_repeated_sint32{x}, 128, decode_only);
  };

  "non_owning_repeated_sint32_unpacked_explicit_type"_test = [] {
    std::array x{1, 2, 3, 4, 0, -1, -2, -3, -4};
    verify_non_owning("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x00\x08\x01\x08\x03\x08\x05\x08\x07"sv,
                      non_owning_repeated_sint32_unpacked_explicit_type{x}, 128);
  };
};

struct non_owing_nested_example {
  hpp::proto::optional_message_view<example> nested; // field number == 1

  constexpr bool operator==(const non_owing_nested_example &) const = default;
};

auto pb_meta(const non_owing_nested_example &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owing_nested_example::nested, field_option::none>>;

const ut::suite test_non_owning_nested_example = [] {
  example const ex{.i = 150};
  verify_non_owning("\x0a\x03\x08\x96\x01"sv, non_owing_nested_example{.nested = &ex}, 64);
};

struct repeated_fixed {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed &) const = default;
};

auto pb_meta(const repeated_fixed &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_fixed::integers, field_option::is_packed>>;

struct repeated_fixed_explicit_type {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed_explicit_type &) const = default;
};

auto pb_meta(const repeated_fixed_explicit_type &) -> std::tuple<
    hpp::proto::field_meta<1, &repeated_fixed_explicit_type::integers, field_option::is_packed, uint64_t>>;
struct repeated_fixed_unpacked {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed_unpacked &) const = default;
};

auto pb_meta(const repeated_fixed_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_fixed_unpacked::integers, field_option::none>>;

struct repeated_fixed_unpacked_explicit_type {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed_unpacked_explicit_type &) const = default;
};

auto pb_meta(const repeated_fixed_unpacked_explicit_type &) -> std::tuple<
    hpp::proto::field_meta<1, &repeated_fixed_unpacked_explicit_type::integers, field_option::none, uint64_t>>;

const ut::suite test_repeated_fixed = [] {
  "repeated_fixed"_test = [] {
    verify("\x0a\x18\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"sv,
           repeated_fixed{{1, 2, 3}});
  };

  "repeated_fixed_explicit_type"_test = [] {
    verify("\x0a\x18\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"sv,
           repeated_fixed_explicit_type{{1, 2, 3}});
  };

  "repeated_fixed_unpacked"_test = [] {
    verify(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"sv,
        repeated_fixed_unpacked{{1, 2, 3}});
  };

  "repeated_fixed_unpacked_decode"_test = [] {
    verify(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"sv,
        repeated_fixed{{1, 2, 3}}, decode_only);
  };

  "repeated_fixed_unpacked_explicit_type_decode"_test = [] {
    verify(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"sv,
        repeated_fixed_explicit_type{{1, 2, 3}}, decode_only);
  };

  "repeated_fixed_unpacked_explicit_type"_test = [] {
    verify(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"sv,
        repeated_fixed_unpacked_explicit_type{{1, 2, 3}});
  };
};

struct non_owning_repeated_fixed {
  hpp::proto::equality_comparable_span<const uint64_t> integers;
  bool operator==(const non_owning_repeated_fixed &) const = default;
};

auto pb_meta(const non_owning_repeated_fixed &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owning_repeated_fixed::integers, field_option::is_packed>>;
struct non_owning_repeated_fixed_explicit_type {
  hpp::proto::equality_comparable_span<const uint64_t> integers;
  bool operator==(const non_owning_repeated_fixed_explicit_type &) const = default;
};

auto pb_meta(const non_owning_repeated_fixed_explicit_type &) -> std::tuple<
    hpp::proto::field_meta<1, &non_owning_repeated_fixed_explicit_type::integers, field_option::is_packed, uint64_t>>;
struct non_owning_repeated_fixed_unpacked {
  hpp::proto::equality_comparable_span<const uint64_t> integers;
  bool operator==(const non_owning_repeated_fixed_unpacked &) const = default;
};

auto pb_meta(const non_owning_repeated_fixed_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owning_repeated_fixed_unpacked::integers, field_option::none>>;

struct non_owning_repeated_fixed_unpacked_explicit_type {
  hpp::proto::equality_comparable_span<const uint64_t> integers;
  bool operator==(const non_owning_repeated_fixed_unpacked_explicit_type &) const = default;
};

auto pb_meta(const non_owning_repeated_fixed_unpacked_explicit_type &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owning_repeated_fixed_unpacked_explicit_type::integers,
                                         field_option::none, uint64_t>>;

const ut::suite test_non_owning_repeated_fixed = [] {
  "non_owning_repeated_fixed"_test = [] {
    std::array<uint64_t, 3> x{1, 2, 3};
    verify_non_owning(
        "\x0a\x18\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"sv,
        non_owning_repeated_fixed{x}, 64);
  };

  "non_owning_repeated_fixed_explicit_type"_test = [] {
    std::array<uint64_t, 3> x{1, 2, 3};
    verify_non_owning(
        "\x0a\x18\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"sv,
        non_owning_repeated_fixed_explicit_type{x}, 64);
  };

  "non_owning_repeated_fixed_unpacked"_test = [] {
    std::array<uint64_t, 3> x{1, 2, 3};
    verify_non_owning(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"sv,
        non_owning_repeated_fixed_unpacked{x}, 64);
  };

  "non_owning_repeated_fixed_unpacked_decode"_test = [] {
    std::array<uint64_t, 3> x{1, 2, 3};
    verify_non_owning(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"sv,
        non_owning_repeated_fixed{x}, 64, decode_only);
  };

  "non_owning_repeated_fixed_unpacked_explicit_type_decode"_test = [] {
    std::array<uint64_t, 3> x{1, 2, 3};
    verify_non_owning(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"sv,
        non_owning_repeated_fixed_explicit_type{x}, 64, decode_only);
  };

  "non_owning_repeated_fixed_unpacked_explicit_type"_test = [] {
    std::array<uint64_t, 3> x{1, 2, 3};
    verify_non_owning(
        "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"sv,
        non_owning_repeated_fixed_unpacked_explicit_type{x}, 64);
  };
};

struct repeated_bool {
  std::vector<hpp::proto::boolean> booleans;
  bool operator==(const repeated_bool &) const = default;
};

auto pb_meta(const repeated_bool &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_bool::booleans, field_option::is_packed, bool>>;

struct repeated_bool_unpacked {
  std::vector<hpp::proto::boolean> booleans;
  bool operator==(const repeated_bool_unpacked &) const = default;
};

auto pb_meta(const repeated_bool_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_bool_unpacked::booleans, field_option::none, bool>>;

const ut::suite test_repeated_bool = [] {
  "repeated_bool"_test = [] { verify("\x0a\x03\x01\x00\x01"sv, repeated_bool{{true, false, true}}); };

  "repeated_bool_unpacked"_test = [] {
    verify("\x08\x01\x08\x00\x08\x01"sv, repeated_bool_unpacked{{true, false, true}});
  };
};

struct non_owning_repeated_bool {
  hpp::proto::equality_comparable_span<const bool> booleans;
  bool operator==(const non_owning_repeated_bool &) const = default;
};

auto pb_meta(const non_owning_repeated_bool &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owning_repeated_bool::booleans, field_option::is_packed, bool>>;

struct non_owning_repeated_bool_unpacked {
  hpp::proto::equality_comparable_span<const bool> booleans;
  bool operator==(const non_owning_repeated_bool_unpacked &) const = default;
};

auto pb_meta(const non_owning_repeated_bool_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owning_repeated_bool_unpacked::booleans, field_option::none, bool>>;

const ut::suite test_non_owning_repeated_bool = [] {
  "non_owning_repeated_bool"_test = [] {
    std::array x{true, false, true};
    verify_non_owning("\x0a\x03\x01\x00\x01"sv, non_owning_repeated_bool{x}, 64);
  };

  "non_owning_repeated_bool_unpacked"_test = [] {
    std::array x{true, false, true};
    verify_non_owning("\x08\x01\x08\x00\x08\x01"sv, non_owning_repeated_bool_unpacked{x}, 64);
  };
};

struct repeated_enum {
  enum class NestedEnum : int8_t { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
  std::vector<NestedEnum> values;
  bool operator==(const repeated_enum &) const = default;
};

auto pb_meta(const repeated_enum &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_enum::values, field_option::is_packed>>;

struct repeated_enum_unpacked {
  enum class NestedEnum : int8_t { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
  std::vector<NestedEnum> values;
  bool operator==(const repeated_enum_unpacked &) const = default;
};

auto pb_meta(const repeated_enum_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_enum_unpacked::values, field_option::none>>;

struct closed_enum_message {
  enum class NestedEnum : int8_t { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3 };
  std::vector<NestedEnum> repeated_values;
  std::optional<NestedEnum> value;
  bool operator==(const closed_enum_message &) const = default;
};

bool is_valid(closed_enum_message::NestedEnum v) {
  return v >= closed_enum_message::NestedEnum::ZERO && v <= closed_enum_message::NestedEnum::BAZ;
}

auto pb_meta(const closed_enum_message &)
    -> std::tuple<hpp::proto::field_meta<1, &closed_enum_message::repeated_values, field_option::closed_enum>,
                  hpp::proto::field_meta<2, &closed_enum_message::value, field_option::closed_enum>>;

struct non_owning_repeated_enum {
  enum class NestedEnum : int8_t { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
  hpp::proto::equality_comparable_span<const NestedEnum> values;
  bool operator==(const non_owning_repeated_enum &) const = default;
};

auto pb_meta(const non_owning_repeated_enum &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owning_repeated_enum::values, field_option::is_packed>>;

struct non_owning_repeated_enum_unpacked {
  enum class NestedEnum : int8_t { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
  hpp::proto::equality_comparable_span<const NestedEnum> values;
  bool operator==(const non_owning_repeated_enum_unpacked &) const = default;
};

auto pb_meta(const non_owning_repeated_enum_unpacked &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owning_repeated_enum_unpacked::values, field_option::none>>;

const ut::suite test_enums = [] {
  "repeated_enum"_test = [] {
    using enum repeated_enum::NestedEnum;
    verify("\x0a\x0d\x01\x02\x03\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"sv, repeated_enum{{FOO, BAR, BAZ, NEG}});
  };

  "repeated_enum_unpacked"_test = [] {
    using enum repeated_enum_unpacked::NestedEnum;
    verify("\x08\x01\x08\x02\x08\x03\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"sv,
           repeated_enum_unpacked{{FOO, BAR, BAZ, NEG}});
  };

  "non_owning_repeated_enum"_test = [] {
    using enum non_owning_repeated_enum::NestedEnum;
    std::array<non_owning_repeated_enum::NestedEnum, 4> x{FOO, BAR, BAZ, NEG};
    verify_non_owning("\x0a\x0d\x01\x02\x03\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"sv, non_owning_repeated_enum{x},
                      128);
  };

  "non_owning_repeated_enum_unpacked"_test = [] {
    using enum non_owning_repeated_enum_unpacked::NestedEnum;
    std::array<non_owning_repeated_enum_unpacked::NestedEnum, 4> x{FOO, BAR, BAZ, NEG};
    verify_non_owning("\x08\x01\x08\x02\x08\x03\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"sv,
                      non_owning_repeated_enum_unpacked{x}, 64);
  };

  "close_enum_field"_test = [] {
    using enum closed_enum_message::NestedEnum;
    using namespace boost::ut;
    closed_enum_message msg;
    closed_enum_message::NestedEnum invalid_enum = static_cast<closed_enum_message::NestedEnum>(4);
    msg.value = invalid_enum;
    msg.repeated_values = {FOO, BAR, invalid_enum, BAZ};
    std::vector<std::byte> buffer;
    expect(hpp::proto::write_proto(msg, buffer).ok());

    closed_enum_message new_msg;
    expect(hpp::proto::read_proto(new_msg, buffer).ok());
    // expect(!new_msg.value.has_value());
    // expect(new_msg.repeated_values == std::vector<closed_enum_message::NestedEnum>{FOO, BAR, BAZ});
  };
};

struct repeated_examples {
  std::vector<example> examples;
  bool operator==(const repeated_examples &) const = default;
};

auto pb_meta(const repeated_examples &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_examples::examples, field_option::none>>;

struct non_owning_repeated_examples {
  hpp::proto::equality_comparable_span<const example> examples;
  bool operator==(const non_owning_repeated_examples &) const = default;
};

auto pb_meta(const non_owning_repeated_examples &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owning_repeated_examples::examples, field_option::none>>;

const ut::suite test_repeated_example = [] {
  auto encoded = "\x0a\x02\x08\x01\x0a\x02\x08\x02\x0a\x02\x08\x03\x0a\x02\x08\x04\x0a\x0b\x08\xff\xff\xff\xff\xff\xff"
                 "\xff\xff\xff\x01\x0a\x0b\x08\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x01\x0a\x0b\x08\xfd\xff\xff\xff\xff"
                 "\xff\xff\xff\xff\x01\x0a\x0b\x08\xfc\xff\xff\xff\xff\xff\xff\xff\xff\x01"sv;

  "repeated_example"_test = [&] {
    repeated_examples const expected{.examples = {{1}, {2}, {3}, {4}, {-1}, {-2}, {-3}, {-4}}};
    verify(encoded, expected);
  };

  "non_owning_repeated_example"_test = [&] {
    std::array<example, 8> x = {example{1},  example{2},  example{3},  example{4},
                                example{-1}, example{-2}, example{-3}, example{-4}};
    non_owning_repeated_examples const expected{.examples = x};
    verify_non_owning(encoded, expected, 128);
  };
};

struct group {
  uint32_t a;
  bool operator==(const group &) const = default;
};

auto pb_meta(const group &)
    -> std::tuple<hpp::proto::field_meta<2, &group::a, field_option::none, hpp::proto::vint64_t>>;

struct repeated_group {
  std::vector<group> repeatedgroup;
  bool operator==(const repeated_group &) const = default;
};

auto pb_meta(const repeated_group &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_group::repeatedgroup, field_option::group>>;

const ut::suite test_repeated_group = [] {
  auto encoded = "\x0b\x10\x01\x0c\x0b\x10\x02\x0c"sv;

  "repeated_group"_test = [&] {
    const repeated_group expected{.repeatedgroup = {{1}, {2}}};
    verify(encoded, expected);
  };
};

enum class color_t : uint8_t { red, blue, green };

struct map_example {
  std::map<int32_t, color_t> dict;
  bool operator==(const map_example &) const = default;
};

auto pb_meta(const map_example &)
    -> std::tuple<hpp::proto::field_meta<1, &map_example::dict, field_option::none,
                                         hpp::proto::map_entry<hpp::proto::vint64_t, color_t>>>;

struct flat_map_example {
  hpp::proto::flat_map<int32_t, color_t> dict;
  bool operator==(const flat_map_example &) const = default;
};

auto pb_meta(const flat_map_example &)
    -> std::tuple<hpp::proto::field_meta<1, &flat_map_example::dict, field_option::none,
                                         hpp::proto::map_entry<hpp::proto::vint64_t, color_t>>>;

struct sequential_map_example {
  std::vector<std::pair<int32_t, color_t>> dict;
  bool operator==(const sequential_map_example &) const = default;
};

auto pb_meta(const sequential_map_example &)
    -> std::tuple<hpp::proto::field_meta<1, &sequential_map_example::dict, field_option::none,
                                         hpp::proto::map_entry<hpp::proto::vint64_t, color_t>>>;

struct non_owning_map_example {
  hpp::proto::equality_comparable_span<const std::pair<int32_t, color_t>> dict;
  bool operator==(const non_owning_map_example &) const = default;
};

auto pb_meta(const non_owning_map_example &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owning_map_example::dict, field_option::none,
                                         hpp::proto::map_entry<hpp::proto::vint64_t, color_t>>>;

const ut::suite test_map_example = [] {
  auto encoded = "\x0a\x04\x08\x01\x10\x00\x0a\x04\x08\x02\x10\x01\x0a\x04\x08\x03\x10\x02"sv;

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
    verify_non_owning(encoded, non_owning_map_example{x}, 64);
  };
};

struct string_example {
  std::string value;
  bool operator==(const string_example &) const = default;
};

auto pb_meta(const string_example &)
    -> std::tuple<hpp::proto::field_meta<1, &string_example::value, field_option::utf8_validation>>;

struct string_with_default {
  std::string value = "test";
  bool operator==(const string_with_default &) const = default;
};
auto pb_meta(const string_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, &string_with_default::value, field_option::none, void,
                                         hpp::proto::string_literal<"test">{}>>;

struct string_with_optional {
  hpp::proto::optional<std::string, hpp::proto::string_literal<"test">{}> value;
  bool operator==(const string_with_optional &) const = default;
};
auto pb_meta(const string_with_optional &)
    -> std::tuple<hpp::proto::field_meta<1, &string_with_optional::value,
                                         field_option::explicit_presence | field_option::utf8_validation>>;

struct string_required {
  std::string value;
  bool operator==(const string_required &) const = default;
};

auto pb_meta(const string_required &)
    -> std::tuple<hpp::proto::field_meta<1, &string_required::value, field_option::explicit_presence>>;

const ut::suite test_string_example = [] {
  "empty_string"_test = [] { verify(""sv, string_example{}); };
  "string_example"_test = [] { verify("\x0a\x04\x74\x65\x73\x74"sv, string_example{.value = "test"}); };

  "string_with_default_empty"_test = [] { verify(""sv, string_with_default{}); };

  "string_with_default"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"sv, string_with_default{.value = "test"}, decode_only);
  };

  "string_with_optional"_test = [] { verify("\x0a\x04\x74\x65\x73\x74"sv, string_with_optional{.value = "test"}); };

  "optional_value_access"_test = [] {
    string_with_optional const v;
    ut::expect(v.value.value() == "test");
  };

  "string_required"_test = [] { verify("\x0a\x00"sv, string_required{}); };
};

struct string_view_example {
  std::string_view value;
  bool operator==(const string_view_example &) const = default;
};

auto pb_meta(const string_view_example &)
    -> std::tuple<hpp::proto::field_meta<1, &string_view_example::value, field_option::none>>;

struct string_view_explicit_presence {
  std::string_view value;
  bool operator==(const string_view_explicit_presence &) const = default;
};

auto pb_meta(const string_view_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, &string_view_explicit_presence::value, field_option::explicit_presence>>;

struct string_view_with_default {
  std::string_view value = "test";
  bool operator==(const string_view_with_default &) const = default;
};
auto pb_meta(const string_view_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, &string_view_with_default::value, field_option::none, void,
                                         hpp::proto::string_literal<"test">{}>>;

struct string_view_with_optional {
  hpp::proto::optional<std::string_view, hpp::proto::string_literal<"test">{}> value;
  bool operator==(const string_view_with_optional &) const = default;
};
auto pb_meta(const string_view_with_optional &)
    -> std::tuple<hpp::proto::field_meta<1, &string_view_with_optional::value, field_option::explicit_presence>>;

const ut::suite test_string_view_example = [] {
  "string_view_example"_test = [] {
    auto encoded_data = "\x0a\x04\x74\x65\x73\x74"sv;
    auto expected_value = string_view_example{.value = "test"};
    verify_non_owning(encoded_data, expected_value, 64);
  };

  "string_view_explicit_presence"_test = [] {
    verify_non_owning("\x0a\x04\x74\x65\x73\x74"sv, string_view_explicit_presence{.value = "test"}, 64);
  };

  "string_view_with_default_empty"_test = [] { verify_non_owning(""sv, string_view_with_default{}, 64); };

  "string_view_with_default"_test = [] {
    verify_non_owning("\x0a\x04\x74\x65\x73\x74"sv, string_view_with_default{.value = "test"}, 64, decode_only);
  };

  "string_view_with_optional"_test = [] {
    verify_non_owning("\x0a\x04\x74\x65\x73\x74"sv, string_view_with_optional{.value = "test"}, 64);
  };

  "optional_value_access"_test = [] {
    string_view_with_optional const v;
    ut::expect(v.value.value() == "test");
  };
};

struct bytes_example {
  std::vector<std::byte> value;
  bool operator==(const bytes_example &) const = default;
};

auto pb_meta(const bytes_example &) -> std::tuple<hpp::proto::field_meta<1, &bytes_example::value, field_option::none>>;

struct bytes_explicit_presence {
  std::vector<std::byte> value;
  bool operator==(const bytes_explicit_presence &) const = default;
};

auto pb_meta(const bytes_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, &bytes_explicit_presence::value, field_option::explicit_presence>>;

struct bytes_with_default {
  std::vector<std::byte> value = "test"_bytes;
  bool operator==(const bytes_with_default &) const = default;
};

auto pb_meta(const bytes_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, &bytes_with_default::value, field_option::none, void,
                                         hpp::proto::bytes_literal<"test">{}>>;

struct bytes_with_optional {
  hpp::proto::optional<std::vector<std::byte>, hpp::proto::bytes_literal<"test">{}> value;
  bool operator==(const bytes_with_optional &) const = default;
};

auto pb_meta(const bytes_with_optional &)
    -> std::tuple<hpp::proto::field_meta<1, &bytes_with_optional::value, field_option::explicit_presence>>;

const ut::suite test_bytes = [] {
  const static auto verified_value = "\x74\x65\x73\x74"_bytes;

  "bytes_example"_test = [] { verify("\x0a\x04\x74\x65\x73\x74"sv, bytes_example{.value = verified_value}); };

  "bytes_explicit_presence"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"sv, bytes_explicit_presence{.value = verified_value});
  };

  "bytes_with_default_empty"_test = [] { verify(""sv, bytes_with_default{}); };

  "bytes_with_default"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"sv, bytes_with_default{.value = verified_value}, decode_only);
  };

  "bytes_with_optional"_test = [] {
    verify("\x0a\x04\x74\x65\x73\x74"sv, bytes_with_optional{.value = verified_value});
  };

  "optional_value_access"_test = [] {
    bytes_with_optional const v;
    ut::expect(v.value.value() == verified_value);
  };
};

struct byte_span_example {
  hpp::proto::equality_comparable_span<const std::byte> value;
  bool operator==(const byte_span_example &) const = default;
};

auto pb_meta(const byte_span_example &)
    -> std::tuple<hpp::proto::field_meta<1, &byte_span_example::value, field_option::none>>;

struct byte_span_explicit_presence {
  hpp::proto::equality_comparable_span<const std::byte> value;
  bool operator==(const byte_span_explicit_presence &) const = default;
};

auto pb_meta(const byte_span_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, &byte_span_explicit_presence::value, field_option::explicit_presence>>;

struct byte_span_with_default {
  hpp::proto::equality_comparable_span<const std::byte> value = "test"_bytes_view;
  bool operator==(const byte_span_with_default &) const = default;
};

auto pb_meta(const byte_span_with_default &)
    -> std::tuple<hpp::proto::field_meta<1, &byte_span_with_default::value, field_option::none, void,
                                         hpp::proto::bytes_literal<"test">{}>>;

struct byte_span_with_optional {
  hpp::proto::optional<hpp::proto::equality_comparable_span<const std::byte>, hpp::proto::bytes_literal<"test">{}>
      value;
  bool operator==(const byte_span_with_optional &) const = default;
};

auto pb_meta(const byte_span_with_optional &)
    -> std::tuple<hpp::proto::field_meta<1, &byte_span_with_optional::value, field_option::explicit_presence>>;

const ut::suite test_byte_span = [] {
  static const std::byte verified_value[] = {std::byte{0x74}, std::byte{0x65}, std::byte{0x73}, std::byte{0x74}};

  "byte_span_example"_test = [] {
    verify_non_owning("\x0a\x04\x74\x65\x73\x74"sv, byte_span_example{.value = verified_value}, 64);
  };

  "byte_span_explicit_presence"_test = [] {
    verify_non_owning("\x0a\x04\x74\x65\x73\x74"sv, byte_span_explicit_presence{.value = verified_value}, 64);
  };

  "byte_span_with_default_empty"_test = [] { verify_non_owning(""sv, byte_span_with_default{}, 64); };

  "byte_span_with_optional_empty"_test = [] { verify_non_owning(""sv, byte_span_with_optional{}, 64); };
};

struct repeated_int32 {
  std::vector<int32_t> integers;
  bool operator==(const repeated_int32 &) const = default;
};

auto pb_meta(const repeated_int32 &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_int32::integers, field_option::is_packed, hpp::proto::vint32_t>>;

template <typename T>
void verify_segmented_input(auto &encoded, const T &value, const std::vector<int> &sizes) {
  std::vector<std::span<char>> segments;
  segments.resize(sizes.size());
  char *b = encoded.data();
  assert(sizes.size() > 0);
  for (unsigned i = 0; i < sizes.size(); ++i) {
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    char *e = b + sizes[i];
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    segments[i] = {b, e};
    b = e;
  }
  T decoded;
  ut::expect(hpp::proto::pb_serializer::deserialize(decoded, segments, hpp::proto::pb_context{}).ok());
  ut::expect(value == decoded);
};

const ut::suite test_segmented_byte_range = [] {
  "bytes_with_segmented_input"_test = [] {
    bytes_example value;
    value.value.resize(128);
    for (int i = 0; i < 128; ++i) {
      value.value[i] = std::byte(i);
    }

    std::vector<char> encoded;
    ut::expect(hpp::proto::write_proto(value, encoded).ok());
    ut::expect(encoded.size() == 131);

    verify_segmented_input(encoded, value, {48, 48, 25, 10});
    verify_segmented_input(encoded, value, {10, 48, 25, 48});
    verify_segmented_input(encoded, value, {25, 48, 10, 48});
  };

  "packed_int32_with_segmented_input"_test = [] {
    repeated_int32 value;
    value.integers.resize(32);
    std::iota(value.integers.begin(), value.integers.end(), -15);
    std::vector<char> encoded;
    ut::expect(hpp::proto::write_proto(value, encoded).ok());

    verify(encoded, value);
    verify_segmented_input(encoded, value, {90, 10, 70});
  };

  "packed_sint32_with_segmented_input"_test = [] {
    repeated_sint32 value;
    value.integers.resize(32);
    std::iota(value.integers.begin(), value.integers.begin() + 16, INT32_MAX - 16);
    std::iota(value.integers.begin() + 16, value.integers.end(), INT32_MIN);
    std::vector<char> encoded;
    ut::expect(hpp::proto::write_proto(value, encoded).ok());

    verify(encoded, value);
    const int len = static_cast<int>(encoded.size());
    const int s = (len - 10) / 2;
    verify_segmented_input(encoded, value, {s, 10, len - 10 - s});
  };
};

struct repeated_strings {
  std::vector<std::string> values;
  bool operator==(const repeated_strings &) const = default;
};

auto pb_meta(const repeated_strings &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_strings::values, field_option::none>>;

struct repeated_strings_explicit_type {
  std::vector<std::string> values;
  bool operator==(const repeated_strings_explicit_type &) const = default;
};

auto pb_meta(const repeated_strings_explicit_type &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_strings_explicit_type::values, field_option::none, std::string>>;

struct non_owning_repeated_string {
  hpp::proto::equality_comparable_span<std::string_view> values;
  bool operator==(const non_owning_repeated_string &) const = default;
};

auto pb_meta(const non_owning_repeated_string &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owning_repeated_string::values, field_option::none>>;

using namespace std::literals;

const ut::suite test_repeated_strings = [] {
  "repeated_strings"_test = [] {
    verify("\x0a\x03\x61\x62\x63\x0a\x03\x64\x65\x66"sv, repeated_strings{.values = {"abc"s, "def"s}});
  };
  "repeated_strings_explicit_type"_test = [] {
    verify("\x0a\x03\x61\x62\x63\x0a\x03\x64\x65\x66"sv, repeated_strings_explicit_type{.values = {"abc"s, "def"s}});
  };

  "non_owning_repeated_string"_test = [] {
    std::string_view storage[] = {"abc"sv, "def"sv};

    verify_non_owning("\x0a\x03\x61\x62\x63\x0a\x03\x64\x65\x66"sv, non_owning_repeated_string{.values = storage}, 128);
  };
};

struct optional_bools {
  hpp::proto::optional<bool> false_defaulted;
  hpp::proto::optional<bool, true> true_defaulted;
  bool operator==(const optional_bools &) const = default;
};

auto pb_meta(const optional_bools &) -> std::tuple<
    hpp::proto::field_meta<1, &optional_bools::false_defaulted, field_option::explicit_presence>,
    hpp::proto::field_meta<2, &optional_bools::true_defaulted, field_option::explicit_presence, bool, true>>;

const ut::suite test_optional_bools = [] {
  "empty_optional_bools"_test = [] {
    std::vector<char> const data;
    verify(data, optional_bools{});
  };

  "optional_bools_all_true"_test = [] {
    verify("\x08\x01\x10\x01"sv, optional_bools{.false_defaulted = true, .true_defaulted = true});
  };

  "optional_bools_all_false"_test = [] {
    verify("\x08\x00\x10\x00"sv, optional_bools{.false_defaulted = false, .true_defaulted = false});
  };
};

struct oneof_example {
  std::variant<std::monostate, std::string, int32_t, color_t> value;
  bool operator==(const oneof_example &) const = default;
};

auto pb_meta(const oneof_example &) -> std::tuple<
    hpp::proto::oneof_field_meta<&oneof_example::value, hpp::proto::field_meta<1, 1, field_option::explicit_presence>,
                                 hpp::proto::field_meta<2, 2, field_option::explicit_presence, hpp::proto::vint64_t>,
                                 hpp::proto::field_meta<3, 3, field_option::explicit_presence>>>;

const ut::suite test_oneof = [] {
  "empty_oneof_example"_test = [] { verify(""sv, oneof_example{}); };

  "string_oneof_example"_test = [] { verify("\x0a\x04\x74\x65\x73\x74"sv, oneof_example{.value = "test"}); };

  "integer_oneof_example_5"_test = [] { verify("\x10\x05"sv, oneof_example{.value = 5}); };
  "integer_oneof_example_0"_test = [] { verify("\x10\x00"sv, oneof_example{.value = 0}); };

  "enum_oneof_example"_test = [] { verify("\x18\x02"sv, oneof_example{.value = color_t::green}); };
};

struct extension_example {
  int32_t int_value = {};
  struct extension_t {
    using pb_extension = extension_example;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) { return meta.read(extensions); }

  template <typename Meta>
  [[nodiscard]] hpp::proto::status set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::move(value));
  }

  template <typename Meta>
    requires Meta::is_repeated
  [[nodiscard]] hpp::proto::status set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
  }

  [[nodiscard]] bool has_extension(auto meta) const { return meta.element_of(extensions); }

  bool operator==(const extension_example &) const = default;
};

auto pb_meta(const extension_example &)
    -> std::tuple<hpp::proto::field_meta<1, &extension_example::int_value, field_option::none, hpp::proto::vint64_t>,
                  hpp::proto::field_meta<UINT32_MAX, &extension_example::extensions>>;

constexpr auto i32_ext() {
  return hpp::proto::extension_meta<extension_example, 10, field_option::explicit_presence, hpp::proto::vint64_t,
                                    int32_t>{};
}

constexpr auto string_ext() {
  return hpp::proto::extension_meta<extension_example, 11, field_option::explicit_presence, std::string, std::string>{};
}

constexpr auto i32_defaulted_ext() {
  return hpp::proto::extension_meta<extension_example, 13, field_option::none, hpp::proto::vint64_t, int32_t,
                                    hpp::proto::vint64_t{10}>{};
}

constexpr auto i32_unset_ext() {
  return hpp::proto::extension_meta<extension_example, 14, field_option::explicit_presence, hpp::proto::vint64_t,
                                    int32_t>{};
}

constexpr auto example_ext() {
  return hpp::proto::extension_meta<extension_example, 15, field_option::explicit_presence, example, example>{};
}

constexpr auto repeated_i32_ext() {
  return hpp::proto::repeated_extension_meta<extension_example, 20, field_option::none, hpp::proto::vint64_t,
                                             int32_t>{};
}

constexpr auto repeated_string_ext() {
  return hpp::proto::repeated_extension_meta<extension_example, 21, field_option::none, void, std::string>{};
}

constexpr auto repeated_packed_i32_ext() {
  return hpp::proto::repeated_extension_meta<extension_example, 22, field_option::is_packed, hpp::proto::vint64_t,
                                             int32_t>{};
}

const ut::suite test_extensions = [] {
  "get_extension"_test = [] {
    auto encoded_data =
        "\x08\x96\x01\x50\x01\x5a\x04\x74\x65\x73\x74\x7a\x03\x08\x96\x01\xa0\x01\x01\xa0\x01\x02\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66\xb2\x01\x03\01\02\03"sv;
    const extension_example expected_value{
        .int_value = 150,
        .extensions = {.fields = {{10U, "\x50\x01"_bytes},
                                  {11U, "\x5a\x04\x74\x65\x73\x74"_bytes},
                                  {15U, "\x7a\x03\x08\x96\x01"_bytes},
                                  {20U, "\xa0\x01\x01\xa0\x01\x02"_bytes},
                                  {21U, "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes},
                                  {22U, "\xb2\x01\x03\01\02\03"_bytes}}}};
    extension_example value;
    ut::expect(hpp::proto::read_proto(value, encoded_data).ok());
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

    std::vector<char> new_data{};
    ut::expect(hpp::proto::write_proto(value, new_data).ok());

    ut::expect(std::ranges::equal(encoded_data, new_data));
  };
  "set_extension"_test = [] {
    extension_example value;
    ut::expect(value.set_extension(i32_ext(), 1).ok());
    ut::expect(value.extensions.fields[10] == "\x50\x01"_bytes);

    ut::expect(value.set_extension(string_ext(), "test").ok());
    ut::expect(value.extensions.fields[11] == "\x5a\x04\x74\x65\x73\x74"_bytes);

    ut::expect(value.set_extension(i32_defaulted_ext(), 10).ok());
    ut::expect(value.extensions.fields.count(13) == 0);

    ut::expect(value.set_extension(example_ext(), {.i = 150}).ok());
    ut::expect(value.extensions.fields[15] == "\x7a\x03\x08\x96\x01"_bytes);

    ut::expect(value.set_extension(repeated_i32_ext(), {1, 2}).ok());
    ut::expect(value.extensions.fields[20] == "\xa0\x01\x01\xa0\x01\x02"_bytes);

    ut::expect(value.set_extension(repeated_string_ext(), {"abc", "def"}).ok());
    ut::expect(value.extensions.fields[21] == "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes);

    ut::expect(value.set_extension(repeated_packed_i32_ext(), {1, 2, 3}).ok());
    ut::expect(value.extensions.fields[22] == "\xb2\x01\x03\01\02\03"_bytes);
  };
};

struct non_owning_extension_example {
  int32_t int_value = {};
  struct extension_t {
    using pb_extension = non_owning_extension_example;
    hpp::proto::equality_comparable_span<std::pair<uint32_t, hpp::proto::equality_comparable_span<const std::byte>>>
        fields;
    bool operator==(const extension_t &) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) { return meta.read(extensions); }

  [[nodiscard]] auto get_extension(auto meta, hpp::proto::concepts::is_option_type auto &&...option) {
    return meta.read(extensions, std::forward<decltype(option)>(option)...);
  }

  template <typename Meta>
  [[nodiscard]] hpp::proto::status set_extension(Meta meta, typename Meta::set_value_type &&value,
                                                 hpp::proto::concepts::is_option_type auto &&...option) {
    return meta.write(extensions, std::move(value), std::forward<decltype(option)>(option)...);
  }

  template <typename Meta>
    requires Meta::is_repeated
  [[nodiscard]] hpp::proto::status set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value,
                                                 hpp::proto::concepts::is_option_type auto &&...option) {
    return meta.write(extensions, std::span<const typename Meta::element_type>(value.begin(), value.end()),
                      std::forward<decltype(option)>(option)...);
  }

  [[nodiscard]] bool has_extension(auto meta) const { return meta.element_of(extensions); }
  bool operator==(const non_owning_extension_example &) const = default;
};

auto pb_meta(const non_owning_extension_example &) -> std::tuple<
    hpp::proto::field_meta<1, &non_owning_extension_example::int_value, field_option::none, hpp::proto::vint64_t>,
    hpp::proto::field_meta<UINT32_MAX, &non_owning_extension_example::extensions>>;

constexpr auto non_owning_i32_ext() {
  return hpp::proto::extension_meta<non_owning_extension_example, 10, field_option::explicit_presence,
                                    hpp::proto::vint64_t, int32_t>{};
}

constexpr auto non_owning_string_ext() {
  return hpp::proto::extension_meta<non_owning_extension_example, 11, field_option::explicit_presence, std::string_view,
                                    std::string_view>{};
}

constexpr auto non_owning_i32_defaulted_ext() {
  return hpp::proto::extension_meta<non_owning_extension_example, 13, field_option::none, hpp::proto::vint64_t, int32_t,
                                    hpp::proto::vint64_t{10}>{};
}

constexpr auto non_owning_i32_unset_ext() {
  return hpp::proto::extension_meta<non_owning_extension_example, 14, field_option::explicit_presence,
                                    hpp::proto::vint64_t, int32_t>{};
}

constexpr auto non_owning_example_ext() {
  return hpp::proto::extension_meta<non_owning_extension_example, 15, field_option::explicit_presence, example,
                                    example>{};
}

constexpr auto non_owning_repeated_i32_ext() {
  return hpp::proto::repeated_extension_meta<non_owning_extension_example, 20, field_option::none, hpp::proto::vint64_t,
                                             int32_t>{};
}

constexpr auto non_owning_repeated_string_ext() {
  return hpp::proto::repeated_extension_meta<non_owning_extension_example, 21, field_option::none, void,
                                             std::string_view>{};
}

constexpr auto non_owning_repeated_packed_i32_ext() {
  return hpp::proto::repeated_extension_meta<non_owning_extension_example, 22, field_option::is_packed,
                                             hpp::proto::vint64_t, int32_t>{};
}

const ut::suite test_non_owning_extensions = [] {
  "get_non_owning_extension"_test = [] {
    auto encoded_data =
        "\x08\x96\x01\x50\x01\x5a\x04\x74\x65\x73\x74\x7a\x03\x08\x96\x01\xa0\x01\x01\xa0\x01\x02\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66\xb2\x01\x03\01\02\03"sv;

    std::array<std::pair<uint32_t, hpp::proto::equality_comparable_span<const std::byte>>, 6> fields_storage = {
        {{10U, "\x50\x01"_bytes_view},
         {11U, "\x5a\x04\x74\x65\x73\x74"_bytes_view},
         {15U, "\x7a\x03\x08\x96\x01"_bytes_view},
         {20U, "\xa0\x01\x01\xa0\x01\x02"_bytes_view},
         {21U, "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes_view},
         {22U, "\xb2\x01\x03\01\02\03"_bytes_view}}};

    non_owning_extension_example const expected_value{.int_value = 150, .extensions = {.fields = fields_storage}};
    non_owning_extension_example value;

    monotonic_buffer_resource mr{1024};
    ut::expect(hpp::proto::read_proto(value, encoded_data, mr).ok());
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
      ut::expect(std::ranges::equal(v.value(), std::initializer_list<uint32_t>{1, 2}));
    }
    {
      auto v = value.get_extension(non_owning_repeated_string_ext(), mr);
      ut::expect(v.has_value());
      using namespace std::literals;
      ut::expect(std::ranges::equal(v.value(), std::initializer_list<std::string_view>{"abc"sv, "def"sv}));
    }
    {
      auto v = value.get_extension(non_owning_repeated_packed_i32_ext(), mr);
      ut::expect(v.has_value());
      ut::expect(std::ranges::equal(v.value(), std::initializer_list<uint32_t>{1, 2, 3}));
    }

    std::vector<char> new_data{};
    ut::expect(hpp::proto::write_proto(value, new_data).ok());

    ut::expect(std::ranges::equal(encoded_data, new_data));
  };
  "set_non_owning_extension"_test = [] {
    monotonic_buffer_resource mr{1024};
    non_owning_extension_example value;
    ut::expect(value.set_extension(non_owning_i32_ext(), 1, mr).ok());
    ut::expect(value.extensions.fields.back().first == 10);
    ut::expect(std::ranges::equal(value.extensions.fields.back().second, "\x50\x01"_bytes));

    ut::expect(value.set_extension(non_owning_string_ext(), "test", mr).ok());
    ut::expect(value.extensions.fields.back().first == 11);
    ut::expect(std::ranges::equal(value.extensions.fields.back().second, "\x5a\x04\x74\x65\x73\x74"_bytes));

    ut::expect(value.set_extension(non_owning_i32_defaulted_ext(), 10, mr).ok());
    ut::expect(value.extensions.fields.back().first != 13);

    ut::expect(value.set_extension(non_owning_example_ext(), {.i = 150}, mr).ok());
    ut::expect(value.extensions.fields.back().first == 15);
    ut::expect(std::ranges::equal(value.extensions.fields.back().second, "\x7a\x03\x08\x96\x01"_bytes));

    ut::expect(value.set_extension(non_owning_repeated_i32_ext(), {1, 2}, mr).ok());
    ut::expect(value.extensions.fields.back().first == 20);
    ut::expect(std::ranges::equal(value.extensions.fields.back().second, "\xa0\x01\x01\xa0\x01\x02"_bytes));

    using namespace std::literals;
    ut::expect(value.set_extension(non_owning_repeated_string_ext(), {"abc"sv, "def"sv}, mr).ok());
    ut::expect(value.extensions.fields.back().first == 21);
    ut::expect(std::ranges::equal(value.extensions.fields.back().second,
                                  "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes));

    ut::expect(value.set_extension(non_owning_repeated_packed_i32_ext(), {1, 2, 3}, mr).ok());
    ut::expect(value.extensions.fields.back().first == 22);
    ut::expect(std::ranges::equal(value.extensions.fields.back().second, "\xb2\x01\x03\01\02\03"_bytes));
  };
};

// NOLINTBEGIN(misc-no-recursion)
struct recursive_type1 {
  hpp::proto::heap_based_optional<recursive_type1> child;
  uint32_t payload = {};

  bool operator==(const recursive_type1 &) const = default;
};

auto pb_meta(const recursive_type1 &)
    -> std::tuple<hpp::proto::field_meta<1, &recursive_type1::child>,
                  hpp::proto::field_meta<2, &recursive_type1::payload, field_option::none, hpp::proto::vint64_t>>;

struct recursive_type2 {
  std::vector<recursive_type2> children;
  int32_t payload = {};

  bool operator==(const recursive_type2 &) const = default;
};

auto pb_meta(const recursive_type2 &)
    -> std::tuple<hpp::proto::field_meta<1, &recursive_type2::children, field_option::none>,
                  hpp::proto::field_meta<2, &recursive_type2::payload, field_option::none, hpp::proto::vint64_t>>;

struct non_owning_recursive_type1 {
  hpp::proto::optional_message_view<non_owning_recursive_type1> child;
  uint32_t payload = {};

  bool operator==(const non_owning_recursive_type1 &) const = default;
};

auto pb_meta(const non_owning_recursive_type1 &) -> std::tuple<
    hpp::proto::field_meta<1, &non_owning_recursive_type1::child>,
    hpp::proto::field_meta<2, &non_owning_recursive_type1::payload, field_option::none, hpp::proto::vint64_t>>;

// NOLINTBEGIN(cppcoreguidelines-special-member-functions)
struct non_owning_recursive_type2 {
  hpp::proto::equality_comparable_span<const non_owning_recursive_type2> children;
  int32_t payload = {};
#ifdef __clang__
  constexpr non_owning_recursive_type2() noexcept = default;
  constexpr ~non_owning_recursive_type2() noexcept = default;
  constexpr non_owning_recursive_type2(const non_owning_recursive_type2 &other) noexcept
      : children(other.children.data(), other.children.size()), payload(other.payload) {
    // clang libc++ has trouble to copy the span when non_owning_recursive_type2 is not a complete type
  }
  constexpr non_owning_recursive_type2 &operator=(const non_owning_recursive_type2 &other) noexcept = default;
#endif
  bool operator==(const non_owning_recursive_type2 &) const = default;
};
// NOLINTEND(cppcoreguidelines-special-member-functions)

auto pb_meta(const non_owning_recursive_type2 &) -> std::tuple<
    hpp::proto::field_meta<1, &non_owning_recursive_type2::children, field_option::none>,
    hpp::proto::field_meta<2, &non_owning_recursive_type2::payload, field_option::none, hpp::proto::vint64_t>>;

const ut::suite recursive_types = [] {
  "recursive_type1"_test = [] {
    recursive_type1 child;
    child.payload = 2;
    recursive_type1 value;
    value.child = child;
    value.payload = 1;
    verify("\x0a\x02\x10\x02\x10\x01"sv, value);
  };
  "recursive_type2"_test = [] {
    recursive_type2 child;
    child.payload = 2;
    recursive_type2 value;
    value.children.push_back(child);
    value.payload = 1;

    verify("\x0a\x02\x10\x02\x10\x01"sv, value);
  };

  "non_owning_recursive_type1"_test = [] {
    non_owning_recursive_type1 child{nullptr, 2};
    non_owning_recursive_type1 const value{&child, 1};

    verify_non_owning("\x0a\x02\x10\x02\x10\x01"sv, value, 64);
  };

  "non_owning_recursive_type2"_test = [] {
    non_owning_recursive_type2 child[1];
    child[0].payload = 2;
    non_owning_recursive_type2 value;
    value.children = child;
    value.payload = 1;

    verify_non_owning("\x0a\x02\x10\x02\x10\x01"sv, value, 64);
  };
};
// NOLINTEND(misc-no-recursion)

struct monster {
  using enum color_t;
  struct vec3 {
    float x;
    float y;
    float z;

    bool operator==(const vec3 &) const = default;
    using pb_meta = std::tuple<hpp::proto::field_meta<1, &vec3::x>, hpp::proto::field_meta<2, &vec3::y>,
                               hpp::proto::field_meta<3, &vec3::z>>;
  };

  struct weapon {
    std::string name;
    int damage = {};

    bool operator==(const weapon &) const = default;
    using pb_meta = std::tuple<hpp::proto::field_meta<1, &weapon::name>, hpp::proto::field_meta<2, &weapon::damage>>;
  };

  vec3 pos = {};
  int32_t mana = {};
  int hp = {};
  std::string name;
  std::vector<std::uint32_t> inventory;
  color_t color = {};
  std::vector<weapon> weapons;
  weapon equipped = {};
  std::vector<vec3> path;
  bool boss = {};

  bool operator==(const monster &) const = default;
  using pb_meta = std::tuple<
      hpp::proto::field_meta<1, &monster::pos>,
      hpp::proto::field_meta<2, &monster::mana, field_option::none, hpp::proto::vint64_t>,
      hpp::proto::field_meta<3, &monster::hp>, hpp::proto::field_meta<4, &monster::name>,
      hpp::proto::field_meta<5, &monster::inventory, field_option::is_packed>,
      hpp::proto::field_meta<6, &monster::color>, hpp::proto::field_meta<7, &monster::weapons, field_option::none>,
      hpp::proto::field_meta<8, &monster::equipped>, hpp::proto::field_meta<9, &monster::path, field_option::none>,
      hpp::proto::field_meta<10, &monster::boss>>;
};

struct monster_with_optional {
  using enum color_t;
  using vec3 = monster::vec3;
  using weapon = monster::weapon;

  vec3 pos = {};
  int32_t mana = {};
  int hp = {};
  std::string name;
  std::vector<std::uint32_t> inventory;
  color_t color = {};
  std::vector<weapon> weapons;
  std::optional<weapon> equipped;
  std::vector<vec3> path;
  bool boss = {};

  bool operator==(const monster_with_optional &) const = default;
  using pb_meta =
      std::tuple<hpp::proto::field_meta<1, &monster_with_optional::pos>,
                 hpp::proto::field_meta<2, &monster_with_optional::mana, field_option::none, hpp::proto::vint64_t>,
                 hpp::proto::field_meta<3, &monster_with_optional::hp>,
                 hpp::proto::field_meta<4, &monster_with_optional::name>,
                 hpp::proto::field_meta<5, &monster_with_optional::inventory, field_option::is_packed>,
                 hpp::proto::field_meta<6, &monster_with_optional::color>,
                 hpp::proto::field_meta<7, &monster_with_optional::weapons, field_option::none>,
                 hpp::proto::field_meta<8, &monster_with_optional::equipped>,
                 hpp::proto::field_meta<9, &monster_with_optional::path, field_option::none>,
                 hpp::proto::field_meta<10, &monster_with_optional::boss>>;
};

struct person {
  std::string name;  // = 1
  int32_t id = {};   // = 2
  std::string email; // = 3

  enum phone_type : uint8_t {
    mobile = 0,
    home = 1,
    work = 2,
  };

  struct phone_number {
    std::string number;   // = 1
    phone_type type = {}; // = 2
    using pb_meta =
        std::tuple<hpp::proto::field_meta<1, &phone_number::number>, hpp::proto::field_meta<2, &phone_number::type>>;
  };

  std::vector<phone_number> phones; // = 4

  using pb_meta = std::tuple<hpp::proto::field_meta<1, &person::name>,
                             hpp::proto::field_meta<2, &person::id, field_option::none, hpp::proto::vint64_t>,
                             hpp::proto::field_meta<3, &person::email>,
                             hpp::proto::field_meta<4, &person::phones, field_option::none>>;
};

struct address_book {
  std::vector<person> people; // = 1
  using pb_meta = std::tuple<hpp::proto::field_meta<1, &address_book::people, field_option::none>>;
};

struct person_map {
  std::string name;  // = 1
  int32_t id = {};   // = 2
  std::string email; // = 3

  enum phone_type : uint8_t {
    mobile = 0,
    home = 1,
    work = 2,
  };

  hpp::proto::flat_map<std::string, phone_type> phones; // = 4

  using pb_meta = std::tuple<hpp::proto::field_meta<1, &person_map::name>,
                             hpp::proto::field_meta<2, &person_map::id, field_option::none, hpp::proto::vint64_t>,
                             hpp::proto::field_meta<3, &person_map::email>,
                             hpp::proto::field_meta<4, &person_map::phones, field_option::none,
                                                    hpp::proto::map_entry<std::string, phone_type>>>;
};

const ut::suite composite_type = [] {
  "monster"_test = [] {
    monster const m = {.pos = {1.0, 2.0, 3.0},
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

    std::vector<char> data;
    ut::expect(hpp::proto::write_proto(m, data).ok());
    monster m2;
    ut::expect(ut::fatal(hpp::proto::read_proto(m2, data).ok()));

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

  "monster_with_optional"_test = [] {
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
      std::vector<char> data;
      ut::expect(hpp::proto::write_proto(m, data).ok());
      std::cerr << "\n" << to_hex(data) << "\n";

      monster_with_optional m2;
      ut::expect(hpp::proto::read_proto(m2, data).ok());

      ut::expect(m.pos == m2.pos);
      ut::expect(m.mana == m2.mana);
      ut::expect(m.hp == m2.hp);
      ut::expect(m.name == m2.name);
      ut::expect(m.inventory == m2.inventory);
      ut::expect(m.color == m2.color);
      ut::expect(m.weapons == m2.weapons);
      ut::expect(m.equipped == m2.equipped);
      ut::expect(m.path == m2.path);
      ut::expect(ut::eq(m.boss, m2.boss));
      ut::expect(m == m2);
    }

    m.equipped.reset();
    {
      std::vector<char> data;
      ut::expect(hpp::proto::write_proto(m, data).ok());
      monster_with_optional m2;
      ut::expect(hpp::proto::read_proto(m2, data).ok());
      ut::expect(m == m2);
    }
  };

  "person"_test = [] {
    constexpr auto data = "\n\x08John Doe\x10\xd2\t\x1a\x10jdoe@example.com\"\x0c\n\x08"
                          "555-4321\x10\x01"sv;
    static_assert(data.size() == 45);

    person p;
    ut::expect(hpp::proto::read_proto(p, data).ok());

    using namespace std::literals::string_view_literals;
    using namespace boost::ut;

    ut::expect(p.name == "John Doe"sv);
    ut::expect(that % p.id == 1234);
    ut::expect(p.email == "jdoe@example.com"sv);
    ut::expect(fatal((p.phones.size() == 1_u)));
    ut::expect(p.phones[0].number == "555-4321"sv);
    ut::expect(that % p.phones[0].type == person::home);

    std::array<char, data.size()> new_data{};
    ut::expect(hpp::proto::write_proto(p, new_data).ok());

    ut::expect(std::ranges::equal(data, new_data));
  };

  "address_book"_test = [] {
    constexpr auto data = "\n-\n\x08John Doe\x10\xd2\t\x1a\x10jdoe@example.com\"\x0c\n\x08"
                          "555-4321\x10\x01\n>\n\nJohn Doe "
                          "2\x10\xd3\t\x1a\x11jdoe2@example.com\"\x0c\n\x08"
                          "555-4322\x10\x01\"\x0c\n\x08"
                          "555-4323\x10\x02"sv;

    static_assert(data.size() == 111);

    using namespace std::literals::string_view_literals;
    using namespace boost::ut;

    address_book b;
    ut::expect(hpp::proto::read_proto(b, data).ok());

    expect(b.people.size() == 2_u);
    expect(b.people[0].name == "John Doe"sv);
    expect(that % b.people[0].id == 1234);
    expect(b.people[0].email == "jdoe@example.com"sv);
    expect(fatal((b.people[0].phones.size() == 1U)));
    expect(b.people[0].phones[0].number == "555-4321"sv);
    expect(b.people[0].phones[0].type == person::home);
    expect(b.people[1].name == "John Doe 2"sv);
    expect(that % b.people[1].id == 1235);
    expect(b.people[1].email == "jdoe2@example.com"sv);
    expect(fatal((b.people[1].phones.size() == 2_u)));
    expect(b.people[1].phones[0].number == "555-4322"sv);
    expect(b.people[1].phones[0].type == person::home);
    expect(b.people[1].phones[1].number == "555-4323"sv);
    expect(b.people[1].phones[1].type == person::work);

    std::array<char, data.size()> new_data{};
    expect(hpp::proto::write_proto(b, new_data).ok());
    expect(std::ranges::equal(data, new_data));
  };

  "person_map"_test = [] {
    constexpr auto data = "\n\x08John Doe\x10\xd2\t\x1a\x10jdoe@example.com\"\x0c\n\x08"
                          "555-4321\x10\x01"sv;
    static_assert(data.size() == 45);

    using namespace std::literals::string_view_literals;
    using namespace boost::ut;

    person_map p;
    expect(hpp::proto::read_proto(p, data).ok());

    expect(p.name == "John Doe"sv);
    expect(that % p.id == 1234);
    expect(p.email == "jdoe@example.com"sv);
    expect(fatal((p.phones.size() == 1_u)));
    expect(fatal((p.phones.contains("555-4321"))));
    expect(that % p.phones["555-4321"] == person_map::home);

    std::array<char, data.size()> new_data{};
    expect(hpp::proto::write_proto(p, new_data).ok());

    expect(std::ranges::equal(data, new_data));
  };

  "default_person_in_address_book"_test = [] {
    constexpr auto data = "\n\x00"sv;

    using namespace std::literals::string_view_literals;
    using namespace boost::ut;

    address_book b;
    expect(hpp::proto::read_proto(b, data).ok());

    expect(b.people.size() == 1_u);
    expect(b.people[0].name.empty());
    expect(that % b.people[0].id == 0);
    expect(b.people[0].email.empty());
    expect(b.people[0].phones.empty());

    std::array<char, "\x0a\x00"sv.size()> new_data{};
    expect(hpp::proto::write_proto(b, new_data).ok());

    expect(std::ranges::equal(new_data, "\x0a\x00"sv));
  };

  "test_empty_address_book"_test = [] {
    constexpr auto data = ""sv;

    using namespace boost::ut;

    address_book b;
    expect(hpp::proto::read_proto(b, data).ok());

    expect(b.people.size() == 0_u);

    std::vector<char> new_data{};
    expect(hpp::proto::write_proto(b, new_data).ok());
    expect(new_data.empty());
  };

  "empty_person"_test = [] {
    constexpr auto data = ""sv;
    using namespace std::literals::string_view_literals;
    using namespace boost::ut;

    person p;
    expect(hpp::proto::read_proto(p, data).ok());

    expect(p.name.empty());
    expect(that % p.id == 0);
    expect(p.email.empty());
    expect(p.phones.empty());

    std::vector<char> new_data{};
    expect(hpp::proto::write_proto(p, new_data).ok());
    expect(new_data.empty());
  };
};

int main() {
#if !defined(_MSC_VER) || (defined(__clang_major__) && (__clang_major__ > 14))
  constexpr_verify(carg("\x08\x96\x01"_bytes_view), carg(example{150}));
  constexpr_verify(carg("\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_view), carg(example{-1}));
  constexpr_verify(carg(""_bytes_view), carg(example{}));
  constexpr_verify(carg("\x0a\x03\x08\x96\x01"_bytes_view), carg(nested_example{.nested = example{150}}));
  constexpr_verify(carg("\x08\x00"_bytes_view), carg(example_explicit_presence{.i = 0}));
  constexpr_verify(carg(""_bytes_view), carg(example_default_type{}));
#endif
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}