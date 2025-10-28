#include "test_util.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/pb_serializer.hpp>
#include <numeric>
#include <unordered_map>

namespace ut = boost::ut;
using hpp::proto::field_option;
using namespace boost::ut::literals;
using namespace std::string_view_literals;

const ut::suite bit_cast_view_test = [] {
  using namespace boost::ut;
  "bit_cast_view"_test = [] {
    constexpr auto data_size = 10;
    std::vector<int> data(data_size);
    constexpr auto chunk_size = sizeof(int);
    // NOLINTNEXTLINE(modernize-use-ranges)
    std::iota(data.begin(), data.end(), 0);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    std::span<const char> input_range{reinterpret_cast<const char *>(data.data()), data.size() * chunk_size};
    int i = 0;
    for (auto v : hpp::proto::detail::bit_cast_view<int>(input_range)) {
      ut::expect(v == i);
      ++i;
    }
  };
};

const ut::suite varint_decode_tests = [] {
  using namespace boost::ut;
  "unchecked_parse_bool"_test = [] {
    bool value = true;
    std::string_view data = "\x00"sv;
    expect(hpp::proto::unchecked_parse_bool(data, value) == data.data() + data.size());
    expect(!value);

    data = "\x01"sv;
    expect(hpp::proto::unchecked_parse_bool(data, value) == data.data() + data.size());
    expect(value);

    // oversized bool
    data = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x01"sv;
    expect(hpp::proto::unchecked_parse_bool(data, value) == data.data() + data.size());
    expect(value);

    // unterminated bool
    data = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xF1"sv;
    expect(hpp::proto::unchecked_parse_bool(data, value) > (data.data() + data.size()));
  };

  using vint64_t = hpp::proto::vint64_t;

  "unchecked_parse_varint"_test =
      [](int64_t arg) {
        std::array<std::byte, 16> data = {};
        const auto *end = hpp::proto::unchecked_pack_varint(hpp::proto::varint{arg}, data.data());

        int64_t parsed_value = 0;
        const auto *r = hpp::proto::shift_mix_parse_varint<int64_t>(data, parsed_value);
        ut::expect(r == end);
      } |
      std::vector<int64_t>{
          127LL,           16383LL,           2097151LL,           268435455LL,           34359738367LL,
          4398046511103LL, 562949953421311LL, 72057594037927935LL, 9223372036854775807LL, -1LL};

  "unterminated_varint"_test = [] {
    auto data = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xF1"sv;
    int64_t parsed_value; // NOLINT(cppcoreguidelines-init-variables)
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    ut::expect(hpp::proto::shift_mix_parse_varint<int64_t>(data, parsed_value) > (data.data() + data.size()));
  };
};

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define carg(...) ([]() constexpr -> decltype(auto) { return __VA_ARGS__; })

constexpr void constexpr_verify(auto buffer, auto object_fun) {
  static_assert(std::ranges::equal(buffer(), hpp::proto::write_proto(object_fun)));
  static_assert(object_fun() == hpp::proto::read_proto<decltype(object_fun())>(buffer()).value());
}

struct empty {
  bool operator==(const empty &) const = default;
};

auto pb_meta(const empty &) -> std::tuple<>;

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

auto pb_meta(const example_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, &example_explicit_presence::i, field_option::explicit_presence,
                                         hpp::proto::vint64_t>>;

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

auto pb_meta(const example_optional_type &)
    -> std::tuple<
        hpp::proto::field_meta<1, &example_optional_type::i, field_option::explicit_presence, hpp::proto::vint64_t>>;

enum test_mode : uint8_t { decode_encode, decode_only };

template <typename T>
void verify(auto encoded_data, const T &expected_value, test_mode mode = decode_encode) {
  std::remove_cvref_t<T> value;

  std::pmr::monotonic_buffer_resource mr;
  ut::expect(hpp::proto::read_proto(value, encoded_data, hpp::proto::alloc_from{mr}).ok());
  ut::expect(ut::fatal(value == expected_value));

  if (mode == decode_only) {
    return;
  }

  std::vector<char> new_data;
  ut::expect(hpp::proto::write_proto(value, new_data).ok());

  ut::expect(std::ranges::equal(encoded_data, new_data));
}

struct bool_example {
  bool b = false; // field number == 1
  constexpr bool operator==(const bool_example &) const = default;
};

auto pb_meta(const bool_example &) -> std::tuple<hpp::proto::field_meta<1, &bool_example::b, field_option::none>>;

const ut::suite test_bool = [] {
  "bool"_test = [] { verify("\x08\x01"sv, bool_example{.b = true}); };

  "invalid_bool"_test = [] {
    bool_example value;
    ut::expect(!hpp::proto::read_proto(value, "\x08\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"sv).ok());
  };
};

template <typename Traits = hpp::proto::default_traits>
struct repeated_sint32 {
  Traits::template repeated_t<int32_t> integers;
  bool operator==(const repeated_sint32 &) const = default;
};

template <typename Traits>
auto pb_meta(const repeated_sint32<Traits> &)
    -> std::tuple<
        hpp::proto::field_meta<1, &repeated_sint32<Traits>::integers, field_option::is_packed, hpp::proto::vsint32_t>>;

template <typename Traits = hpp::proto::default_traits>

struct repeated_sint32_unpacked {
  Traits::template repeated_t<hpp::proto::vsint32_t> integers;
  bool operator==(const repeated_sint32_unpacked &) const = default;
};

template <typename Traits>
auto pb_meta(const repeated_sint32_unpacked<Traits> &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_sint32_unpacked<Traits>::integers, field_option::none>>;

template <typename Traits = hpp::proto::default_traits>

struct repeated_sint32_unpacked_explicit_type {
  Traits::template repeated_t<int32_t> integers;
  bool operator==(const repeated_sint32_unpacked_explicit_type &) const = default;
};

template <typename Traits>
auto pb_meta(const repeated_sint32_unpacked_explicit_type<Traits> &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_sint32_unpacked_explicit_type<Traits>::integers,
                                         field_option::none, hpp::proto::vsint32_t>>;

template <typename Traits = hpp::proto::default_traits>
struct repeated_uint64 {
  Traits::template repeated_t<uint64_t> integers;
  bool operator==(const repeated_uint64 &) const = default;
};

template <typename Traits>
auto pb_meta(const repeated_uint64<Traits> &)
    -> std::tuple<
        hpp::proto::field_meta<1, &repeated_uint64<Traits>::integers, field_option::is_packed, hpp::proto::vuint64_t>>;

const ut::suite test_repeated_vint = [] {
  "invalid_repeated_sint32"_test = [] {
    repeated_sint32 value;
    // last element unterminated
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x03\xa8\x96\xb1"sv).ok());
    ut::expect(
        !hpp::proto::read_proto(value, "\x0a\x10\x08\x16\x21\x30\x40\x50\x60\x70\x80\x90\xa1\xb2\xc3\xd4\xe5\xf6"sv)
             .ok());

    // overlong element in the middle
    ut::expect(
        !hpp::proto::read_proto(value, "\x0a\x10\x08\xF6\xF1\xF0\xF0\xF0\xF0\xF0\x80\x90\xa1\xb2\xc3\xd4\xe5\x06"sv)
             .ok());
    // overlong element in the middle
    ut::expect(
        !hpp::proto::read_proto(value, "\x0a\x11\x08\x16\x21\x30\x40\x50\x80\xF0\x80\x90\xa1\xb2\xc3\xd4\xe5\x85\x06"sv)
             .ok());
    // zero length
    ut::expect(hpp::proto::read_proto(value, "\x0a\x00"sv).ok());
    // invalid length
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"sv).ok());
    // skip invalid length
    ut::expect(!hpp::proto::read_proto(value, "\x1a\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"sv).ok());

    ut::expect(!hpp::proto::read_proto(value, "\x0a\x00\xa8\x96\x01"sv).ok());
    // encoded size longer than available data
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x04\xa8\x96\x01"sv).ok());
    // invalid tag
    ut::expect(!hpp::proto::read_proto(value, "\x8a\x84\xa8\x96\x81\x0a\x84\xa8\x96\x01"sv).ok());
  };

  "invalid_repeated_sint32_unpacked"_test = [] {
    repeated_sint32_unpacked value;
    // invalid element
    ut::expect(!hpp::proto::read_proto(value, "\x08\x02\x08\x94\x88\xa6\xb8\xc8\xd8\xe0"sv).ok());
    // wrong tag type
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x02"sv).ok());
  };

  "overlong integer"_test = [] {
    repeated_uint64 value;
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x0d\x01\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x02"sv).ok());
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x0d\x01\x02\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x10"sv).ok());
  };

  using namespace boost::ut;

  "normal_cases"_test = []<class Traits> {
    "repeated_sint32"_test = [] {
      verify("\x0a\x09\x00\x02\x04\x06\x08\x01\x03\x05\x07"sv,
             repeated_sint32<Traits>{.integers = std::initializer_list{0, 1, 2, 3, 4, -1, -2, -3, -4}});
    };

    "repeated_sint32_unpacked"_test = [] {
      verify("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x00\x08\x01\x08\x03\x08\x05\x08\x07"sv,
             repeated_sint32_unpacked<Traits>{
                 .integers = std::initializer_list<hpp::proto::vsint32_t>{1, 2, 3, 4, 0, -1, -2, -3, -4}});
    };

    "repeated_sint32_unpacked_decode"_test = [] {
      verify("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x00\x08\x01\x08\x03\x08\x05\x08\x07"sv,
             repeated_sint32<Traits>{.integers = std::initializer_list{1, 2, 3, 4, 0, -1, -2, -3, -4}}, decode_only);
    };

    "repeated_sint32_unpacked_explicit_type"_test = [] {
      verify("\x08\x02\x08\x04\x08\x06\x08\x08\x08\x00\x08\x01\x08\x03\x08\x05\x08\x07"sv,
             repeated_sint32_unpacked_explicit_type<Traits>{.integers =
                                                                std::initializer_list{1, 2, 3, 4, 0, -1, -2, -3, -4}});
    };
  } | std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits>{};
};

struct non_owing_nested_example {
  hpp::proto::optional_message_view<example> nested; // field number == 1

  constexpr bool operator==(const non_owing_nested_example &) const = default;
};

auto pb_meta(const non_owing_nested_example &)
    -> std::tuple<hpp::proto::field_meta<1, &non_owing_nested_example::nested, field_option::none>>;

const ut::suite test_non_owning_nested_example = [] {
  example const ex{.i = 150};
  verify("\x0a\x03\x08\x96\x01"sv, non_owing_nested_example{.nested = &ex});
};

template <typename Traits = hpp::proto::default_traits>
struct repeated_fixed {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed &) const = default;
};

template <typename Traits>
auto pb_meta(const repeated_fixed<Traits> &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_fixed<Traits>::integers, field_option::is_packed>>;

template <typename Traits = hpp::proto::default_traits>

struct repeated_fixed_explicit_type {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed_explicit_type &) const = default;
};

template <typename Traits>
auto pb_meta(const repeated_fixed_explicit_type<Traits> &)
    -> std::tuple<
        hpp::proto::field_meta<1, &repeated_fixed_explicit_type<Traits>::integers, field_option::is_packed, uint64_t>>;

template <typename Traits = hpp::proto::default_traits>
struct repeated_fixed_unpacked {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed_unpacked &) const = default;
};

template <typename Traits>
auto pb_meta(const repeated_fixed_unpacked<Traits> &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_fixed_unpacked<Traits>::integers, field_option::none>>;

template <typename Traits = hpp::proto::default_traits>
struct repeated_fixed_unpacked_explicit_type {
  std::vector<uint64_t> integers;
  bool operator==(const repeated_fixed_unpacked_explicit_type &) const = default;
};

template <typename Traits>
auto pb_meta(const repeated_fixed_unpacked_explicit_type<Traits> &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_fixed_unpacked_explicit_type<Traits>::integers,
                                         field_option::none, uint64_t>>;

const ut::suite test_repeated_fixed = [] {
  using namespace boost::ut;
  "invalid_repeated_fixed"_test = [] {
    repeated_fixed value;
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x08\x08\x96\x01"sv).ok());
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x03\x08\x96\x01"sv).ok());
  };

  "zero_length_repeated_fixed"_test = [] {
    repeated_fixed value;
    ut::expect(hpp::proto::read_proto(value, "\x0a\x00"sv).ok());
  };

  "normal_cases"_test = []<class Traits> {
    "repeated_fixed"_test = [] {
      verify(
          "\x0a\x18\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"sv,
          repeated_fixed<Traits>{{1, 2, 3}});
    };

    "repeated_fixed_explicit_type"_test = [] {
      verify(
          "\x0a\x18\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"sv,
          repeated_fixed_explicit_type<Traits>{{1, 2, 3}});
    };

    "repeated_fixed_unpacked"_test = [] {
      verify(
          "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"sv,
          repeated_fixed_unpacked<Traits>{{1, 2, 3}});
    };

    "repeated_fixed_unpacked_decode"_test = [] {
      verify(
          "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"sv,
          repeated_fixed<Traits>{{1, 2, 3}}, decode_only);
    };

    "repeated_fixed_unpacked_explicit_type_decode"_test = [] {
      verify(
          "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"sv,
          repeated_fixed_explicit_type<Traits>{{1, 2, 3}}, decode_only);
    };

    "repeated_fixed_unpacked_explicit_type"_test = [] {
      verify(
          "\x09\x01\x00\x00\x00\x00\x00\x00\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x09\x03\x00\x00\x00\x00\x00\x00\x00"sv,
          repeated_fixed_unpacked_explicit_type<Traits>{{1, 2, 3}});
    };
  } | std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits>{};
};

template <typename Traits = hpp::proto::default_traits>
struct repeated_bool {
  std::vector<hpp::proto::boolean> booleans;
  bool operator==(const repeated_bool &) const = default;
};

template <typename Traits>
auto pb_meta(const repeated_bool<Traits> &)
    -> std::tuple<
        hpp::proto::field_meta<1, &repeated_bool<Traits>::booleans, field_option::is_packed, hpp::proto::boolean>>;

template <typename Traits = hpp::proto::default_traits>
struct repeated_bool_unpacked {
  std::vector<hpp::proto::boolean> booleans;
  bool operator==(const repeated_bool_unpacked &) const = default;
};

template <typename Traits>
auto pb_meta(const repeated_bool_unpacked<Traits> &)
    -> std::tuple<
        hpp::proto::field_meta<1, &repeated_bool_unpacked<Traits>::booleans, field_option::none, hpp::proto::boolean>>;

const ut::suite test_repeated_bool = [] {
  using namespace boost::ut;

  "normal_cases"_test = []<class Traits>() {
    "repeated_bool"_test = [] { verify("\x0a\x03\x01\x00\x01"sv, repeated_bool<Traits>{{true, false, true}}); };

    "repeated packed overlong bool"_test = [] {
      std::pmr::monotonic_buffer_resource mr;
      repeated_bool<Traits> value;
      ut::expect(hpp::proto::read_proto(value, "\x0a\x0d\x81\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"sv,
                                        hpp::proto::alloc_from{mr})
                     .ok());
      ut::expect(value ==
                 repeated_bool<Traits>{{true, true, true, true, true, true, true, true, true, true, true, true}});
    };

    "repeated_bool_unpacked"_test = [] {
      verify("\x08\x01\x08\x00\x08\x01"sv, repeated_bool_unpacked<Traits>{{true, false, true}});
    };

    "repeated_overlong_bool_unpacked"_test = [] {
      std::pmr::monotonic_buffer_resource mr;
      repeated_bool_unpacked<Traits> value;
      ut::expect(
          hpp::proto::read_proto(value, "\x08\x01\x08\x00\x08\x01\x08\x81\x00"sv, hpp::proto::alloc_from{mr}).ok());
      ut::expect(value == repeated_bool_unpacked<Traits>{{true, false, true, true}});
    };

    "invalid_repeated_bool"_test = [] {
      std::pmr::monotonic_buffer_resource mr;
      repeated_bool<Traits> value;
      ut::expect(!hpp::proto::read_proto(value, "\x0a\x03\x01\x00\x81"sv, hpp::proto::alloc_from{mr}).ok());
      ut::expect(!hpp::proto::read_proto(value, "\x0a\x0e\x01\x80\x81\x80\x81\x80\x81\x80\x81\x80\x81\x80\x81\x00"sv,
                                         hpp::proto::alloc_from{mr})
                      .ok());
    };
  } | std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits>{};
};

enum class ForeignEnum : int8_t { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, NEG = -1 };
bool is_valid(ForeignEnum v) { return v >= ForeignEnum::NEG && v <= ForeignEnum::BAZ; }

enum class ForeignEnumEx : int8_t { ZERO = 0, FOO = 1, BAR = 2, BAZ = 3, EXTRA = 4, NEG = -1 };

template <typename Traits = hpp::proto::default_traits>
struct open_enum_message {
  typename Traits::template repeated_t<ForeignEnumEx> expanded_repeated_field;
  ForeignEnumEx foreign_enum_field;
  typename Traits::template repeated_t<ForeignEnumEx> packed_repeated_field;
  std::optional<example> optional_message_field;
  [[no_unique_address]] hpp::proto::pb_unknown_fields<Traits> unknown_fields_;
  bool operator==(const open_enum_message &) const = default;
};

template <typename Traits>
auto pb_meta(const open_enum_message<Traits> &)
    -> std::tuple<
        hpp::proto::field_meta<1, &open_enum_message<Traits>::expanded_repeated_field, field_option::none>,
        hpp::proto::field_meta<2, &open_enum_message<Traits>::foreign_enum_field, field_option::none>,
        hpp::proto::field_meta<3, &open_enum_message<Traits>::packed_repeated_field, field_option::is_packed>,
        hpp::proto::field_meta<4, &open_enum_message<Traits>::optional_message_field, field_option::none>,
        hpp::proto::field_meta<UINT32_MAX, &open_enum_message<Traits>::unknown_fields_>>;

template <typename Traits = hpp::proto::default_traits>
struct closed_enum_message {
  typename Traits::template repeated_t<ForeignEnum> expanded_repeated_field;
  std::optional<ForeignEnum> foreign_enum_field;
  typename Traits::template repeated_t<ForeignEnum> packed_repeated_field;
  [[no_unique_address]] hpp::proto::pb_unknown_fields<Traits> unknown_fields_;
  bool operator==(const closed_enum_message &) const = default;
};

template <typename Traits>
auto pb_meta(const closed_enum_message<Traits> &)
    -> std::tuple<
        hpp::proto::field_meta<1, &closed_enum_message<Traits>::expanded_repeated_field, field_option::closed_enum>,
        hpp::proto::field_meta<2, &closed_enum_message<Traits>::foreign_enum_field,
                               field_option::explicit_presence | field_option::closed_enum>,
        hpp::proto::field_meta<3, &closed_enum_message<Traits>::packed_repeated_field,
                               field_option::is_packed | field_option::closed_enum>,
        hpp::proto::field_meta<UINT32_MAX, &closed_enum_message<Traits>::unknown_fields_>>;

const ut::suite test_enums = [] {
  using enum ForeignEnumEx;
  "enum_message"_test = [] { verify("\x10\x01"sv, open_enum_message{.foreign_enum_field = FOO}); };

  "invalid_enum_message"_test = [] {
    open_enum_message value = {};
    ut::expect(!hpp::proto::read_proto(value, "\x10\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"sv).ok());
  };

  using namespace boost::ut;

  "repeated_open_enum"_test = []<class Traits> {
    "repeated_enum_packed"_test = [] {
      verify("\x1a\x0d\x01\x02\x03\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"sv,
             open_enum_message<Traits>{.packed_repeated_field = std::initializer_list{FOO, BAR, BAZ, NEG}});
    };

    "repeated_enum_unpacked"_test = [] {
      verify("\x08\x01\x08\x02\x08\x03\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"sv,
             open_enum_message<Traits>{.expanded_repeated_field = std::initializer_list{FOO, BAR, BAZ, NEG}});
    };
  } | std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits>{};

  "repeated_closed_enum"_test =
      []<class Traits> {
        open_enum_message msg;
        msg.foreign_enum_field = EXTRA;
        msg.expanded_repeated_field = {FOO, BAR, EXTRA, BAZ};
        msg.packed_repeated_field = {FOO, BAR, EXTRA, BAZ};
        msg.optional_message_field.emplace().i = 1;
        std::vector<std::byte> buffer;
        expect(hpp::proto::write_proto(msg, buffer).ok());

        using ClosedMessage = closed_enum_message<Traits>;

        std::pmr::monotonic_buffer_resource mr;

        ClosedMessage closed_msg;
        expect(hpp::proto::read_proto(closed_msg, buffer, hpp::proto::alloc_from{mr}).ok());
        expect(!closed_msg.foreign_enum_field.has_value());
        auto expected_repeated = std::initializer_list{ForeignEnum::FOO, ForeignEnum::BAR, ForeignEnum::BAZ};
        expect(std::ranges::equal(closed_msg.expanded_repeated_field, expected_repeated));
        expect(std::ranges::equal(closed_msg.packed_repeated_field, expected_repeated));

        if constexpr (!std::is_empty_v<typename Traits::unknown_fields_range_t>) {
          expect(std::ranges::equal(closed_msg.unknown_fields_.fields, "\x08\x04\x10\x04\x18\04\x22\x02\x08\x01"_bytes_view));
          expect(hpp::proto::write_proto(closed_msg, buffer).ok());

          open_enum_message restored_msg;
          expect(hpp::proto::read_proto(restored_msg, buffer).ok());

          expect(restored_msg.foreign_enum_field == EXTRA);
          expect(std::ranges::equal(restored_msg.expanded_repeated_field, std::initializer_list{FOO, BAR, BAZ, EXTRA}));
          expect(std::ranges::equal(restored_msg.packed_repeated_field, std::initializer_list{FOO, BAR, BAZ, EXTRA}));
          expect(restored_msg.optional_message_field.has_value() && restored_msg.optional_message_field->i == 1);
        }
      } |
      std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits,
                 hpp::proto::keep_unknown_fields<hpp::proto::default_traits>,
                 hpp::proto::keep_unknown_fields<hpp::proto::non_owning_traits>>{};
};

template <typename Traits = hpp::proto::default_traits>
struct repeated_message_examples {
  std::vector<example> examples;
  bool operator==(const repeated_message_examples &) const = default;
};

template <typename Traits>
auto pb_meta(const repeated_message_examples<Traits> &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_message_examples<Traits>::examples, field_option::none>>;

const ut::suite test_repeated_example = [] {
  using namespace boost::ut;
  auto encoded = "\x0a\x02\x08\x01\x0a\x02\x08\x02\x0a\x02\x08\x03\x0a\x02\x08\x04\x0a\x0b\x08\xff\xff\xff\xff\xff\xff"
                 "\xff\xff\xff\x01\x0a\x0b\x08\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x01\x0a\x0b\x08\xfd\xff\xff\xff\xff"
                 "\xff\xff\xff\xff\x01\x0a\x0b\x08\xfc\xff\xff\xff\xff\xff\xff\xff\xff\x01"sv;

  "repeated_message_examples"_test = [&]<class Traits> {
    repeated_message_examples<Traits> const expected{.examples = {{1}, {2}, {3}, {4}, {-1}, {-2}, {-3}, {-4}}};
    verify(encoded, expected);
  } | std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits>{};

  "invalid_repeated_example"_test = [] {
    repeated_message_examples value;
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x02\x08\x01\x0a\x02\x08\xa2"sv).ok());
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

  "invalid_repeated_group"_test = [] {
    repeated_group value;
    ut::expect(!hpp::proto::read_proto(value, "\x0b\x10\x01\x0c\x0b"sv).ok());
    // invalid tag
    ut::expect(!hpp::proto::read_proto(value, "\x1f\x10\x01\x0c\x0b"sv).ok());
    // group with zero tag field
    ut::expect(!hpp::proto::read_proto(value, "\x0b\x00\x01\x1c"sv).ok());
    // group with incomplete field
    ut::expect(!hpp::proto::read_proto(value, "\x0b\x10"sv).ok());
    // skip group with zero tag field
    ut::expect(!hpp::proto::read_proto(value, "\x1b\x00\x01\x1c"sv).ok());
    // skip group with incomplete field
    ut::expect(!hpp::proto::read_proto(value, "\x1b\x10"sv).ok());
    // skip group with invalid field
    ut::expect(!hpp::proto::read_proto(value, "\x1b\x10\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"sv).ok());
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

struct string_key_map_example {
  hpp::proto::flat_map<std::string, color_t> dict;
  bool operator==(const string_key_map_example &) const = default;
};

auto pb_meta(const string_key_map_example &)
    -> std::tuple<
        hpp::proto::field_meta<1, &string_key_map_example::dict, field_option::none,
                               hpp::proto::map_entry<std::string, color_t, hpp::proto::field_option::utf8_validation,
                                                     hpp::proto::field_option::none>>>;

struct unordered_map_example {
  std::unordered_map<std::string, color_t> dict;
  bool operator==(const unordered_map_example &) const = default;
};

auto pb_meta(const unordered_map_example &)
    -> std::tuple<
        hpp::proto::field_meta<1, &unordered_map_example::dict, field_option::none,
                               hpp::proto::map_entry<std::string, color_t, hpp::proto::field_option::utf8_validation,
                                                     hpp::proto::field_option::none>>>;

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
    verify(encoded, non_owning_map_example{x});
  };

  "string_key_map_example"_test = [&] {
    string_key_map_example const expected{
        .dict = {{"red", color_t::red}, {"blue", color_t::blue}, {"green", color_t::green}}};
    verify(
        "\x0a\x08\x0a\x04\x62\x6c\x75\x65\x10\x01\x0a\x09\x0a\x05\x67\x72\x65\x65\x6e\x10\x02\x0a\x07\x0a\x03\x72\x65\x64\x10\x00"sv,
        expected);
    string_key_map_example value{.dict = {{"\xc0\xdf", color_t::red}}};
    ut::expect(!hpp::proto::write_proto(value).has_value());
  };

  "unordered_key_map_example"_test = [&] {
    unordered_map_example const msg{
        .dict = {{"red", color_t::red}, {"blue", color_t::blue}, {"green", color_t::green}}};
    std::vector<std::byte> buffer;
    ut::expect(hpp::proto::write_proto(msg, buffer).ok());

    unordered_map_example value;
    ut::expect(hpp::proto::read_proto(value, buffer).ok());
    ut::expect(value == msg);

    // double check if the encoded value is correct
    string_key_map_example another;
    ut::expect(hpp::proto::read_proto(another, buffer).ok());
    value = unordered_map_example{.dict{another.dict.begin(), another.dict.end()}};
    ut::expect(value == msg);
  };

  "invalid_map_entry"_test = [] {
    map_example value;
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x04\x08\x01\x10\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"sv).ok());
  };

  "invalid_non_owning_map_entry"_test = [] {
    non_owning_map_example value;
    std::pmr::monotonic_buffer_resource mr;
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x04\x08\x01\x10\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"sv,
                                       hpp::proto::alloc_from(mr))
                    .ok());
  };
};

template <typename Traits = hpp::proto::default_traits>
struct string_example {
  typename Traits::string_t field;
  hpp::proto::optional<typename Traits::string_t, hpp::proto::string_literal<"test">{}> optional_field;
  bool operator==(const string_example &) const = default;
};

template <typename Traits>
auto pb_meta(const string_example<Traits> &)
    -> std::tuple<hpp::proto::field_meta<1, &string_example<Traits>::field, field_option::utf8_validation>,
                  hpp::proto::field_meta<2, &string_example<Traits>::optional_field,
                                         field_option::explicit_presence | field_option::utf8_validation>>;

struct string_required {
  std::string value;
  bool operator==(const string_required &) const = default;
};

auto pb_meta(const string_required &)
    -> std::tuple<hpp::proto::field_meta<1, &string_required::value, field_option::explicit_presence>>;

const ut::suite test_string_example = [] {
  "string_required"_test = [] { verify("\x0a\x00"sv, string_required{}); };
  using namespace boost::ut;
  "string"_test = []<class Traits> {
    "empty_string_feild"_test = [] { verify(""sv, string_example<Traits>{}); };
    "string_field"_test = [] { verify("\x0a\x04\x74\x65\x73\x74"sv, string_example<Traits>{.field = "test"}); };

    "optional_string_field"_test = [] {
      string_example<Traits> const v;
      ut::expect(v.optional_field.value() == "test");
      verify("\x12\x04\x74\x65\x73\x74"sv, string_example<Traits>{.optional_field = "test"});
    };

    "invalid_utf8"_test = [] {
      string_example<Traits> v{.field = "\xC0\xDF"};
      ut::expect(!hpp::proto::write_proto(v).has_value());
    };

    "invalid_string_length"_test = [] {
      string_example<Traits> v;
      std::pmr::monotonic_buffer_resource mr;
      ut::expect(!hpp::proto::read_proto(v, "\x0a\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x10\x74\x65"sv,
                                         hpp::proto::alloc_from(mr))
                      .ok());
    };
  } | std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits>{};
};

template <typename Traits = hpp::proto::default_traits>
struct bytes_example {
  typename Traits::bytes_t field;
  hpp::proto::optional<typename Traits::bytes_t, hpp::proto::bytes_literal<"test">{}> optional_field;
  bool operator==(const bytes_example &) const = default;
};

template <typename Traits>
auto pb_meta(const bytes_example<Traits> &)
    -> std::tuple<hpp::proto::field_meta<1, &bytes_example<Traits>::field, field_option::none>,
                  hpp::proto::field_meta<2, &bytes_example<Traits>::optional_field, field_option::explicit_presence>>;

struct bytes_explicit_presence {
  std::vector<std::byte> value;
  bool operator==(const bytes_explicit_presence &) const = default;
};

auto pb_meta(const bytes_explicit_presence &)
    -> std::tuple<hpp::proto::field_meta<1, &bytes_explicit_presence::value, field_option::explicit_presence>>;

const ut::suite test_bytes = [] {
  const auto verified_value = std::initializer_list{std::byte{'t'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'}};
  static_assert(std::is_convertible_v<std::vector<std::byte>, hpp::proto::equality_comparable_span<const std::byte>>);

  "bytes_explicit_presence"_test = [&] {
    verify("\x0a\x04\x74\x65\x73\x74"sv, bytes_explicit_presence{.value = verified_value});
  };

  using namespace boost::ut;
  "bytes_example"_test = [&]<class Traits>() {
    "field"_test = [&] { verify("\x0a\x04\x74\x65\x73\x74"sv, bytes_example<Traits>{.field = verified_value}); };

    "optional_field"_test = [&] {
      verify("\x12\x04\x74\x65\x73\x74"sv, bytes_example<Traits>{.optional_field = verified_value});
    };

    bytes_example<Traits> const v;
    ut::expect(std::ranges::equal(v.optional_field.value(), verified_value));
  } | std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits>{};
};

struct repeated_int32 {
  std::vector<int32_t> integers;
  bool operator==(const repeated_int32 &) const = default;
};

auto pb_meta(const repeated_int32 &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_int32::integers, field_option::is_packed, hpp::proto::vint32_t>>;

template <typename T>
void verify_segmented_input(auto &encoded, const T &value, const std::vector<int> &sizes) {
  std::vector<std::vector<char>> segments;
  segments.resize(sizes.size());
  std::size_t len = 0;
  for (unsigned i = 0; i < sizes.size(); ++i) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    segments[i] = std::vector<char>{encoded.data() + len, encoded.data() + len + static_cast<std::size_t>(sizes[i])};
    len += sizes[i];
  }
  T decoded;
  ut::expect(hpp::proto::read_proto(decoded, segments).ok());
  ut::expect(value == decoded);
};

auto split(auto data, int pos) {
  return std::array<std::vector<char>, 2>{std::vector<char>{data.begin(), data.begin() + pos},
                                          std::vector<char>{data.begin() + pos, data.end()}};
};

const ut::suite test_segmented_byte_range = [] {
  "empty_with_segmented_input"_test = [] {
    empty value;
    std::vector<std::span<char>> segments;
    ut::expect(hpp::proto::read_proto(value, segments).ok());
  };

  "bytes_with_segmented_input"_test = [] {
    bytes_example value;
    value.field.resize(128);
    for (int i = 0; i < 128; ++i) {
      value.field[i] = std::byte(i);
    }

    std::vector<char> encoded;
    ut::expect(hpp::proto::write_proto(value, encoded).ok());
    ut::expect(encoded.size() == 131);

    verify_segmented_input(encoded, value, {48, 48, 25, 10});
    verify_segmented_input(encoded, value, {48, 0, 48, 25, 10});
    verify_segmented_input(encoded, value, {10, 48, 25, 48});
    verify_segmented_input(encoded, value, {25, 48, 10, 48});
    verify_segmented_input(encoded, value, {48, 25, 10, 48});
    verify_segmented_input(encoded, value, {10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 31});
  };

  "packed_int32_with_segmented_input"_test = [] {
    repeated_int32 value;
    value.integers.resize(32);
    // NOLINTNEXTLINE(modernize-use-ranges)
    std::iota(value.integers.begin(), value.integers.end(), -15);
    std::vector<char> encoded;
    ut::expect(hpp::proto::write_proto(value, encoded).ok());

    verify(encoded, value);
    verify_segmented_input(encoded, value, {90, 10, 70});
  };

  "invalid_packed_int32_with_segmented_input"_test = [] {
    repeated_int32 value;

    using namespace std::string_literals;
    // invalid int32 in the middle
    ut::expect(
        !hpp::proto::read_proto(
             value, split("\x0a\x13\x01\x82\x80\x80\x80\x81\x80\x81\x81\x81\x81\x81\x01\x01\x01\x81\x81\x81\x00"s, 18))
             .ok());

    // no valid int32 in slope area
    ut::expect(
        !hpp::proto::read_proto(
             value, split("\x0a\x13\x81\x82\x80\x80\x80\x81\x80\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x00"s, 18))
             .ok());
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

  "packed_overlong_bool_with_segmented_input"_test = [] {
    repeated_bool value;
    auto encoded = "\x0a\x12\x01\x02\x00\x80\x10\x81\x00\x01\x01\x01\x01\x01\x01\x01\x01\x81\x81\x01"sv;
    ut::expect(hpp::proto::read_proto(value, split(encoded, 18)).ok());
    auto expected_value =
        repeated_bool{{true, true, false, true, true, true, true, true, true, true, true, true, true, true}};
    ut::expect(value == expected_value);
  };

  "invalid_packed_bool_with_segmented_input"_test = [] {
    repeated_bool value;
    using namespace std::string_literals;
    // non-terminated packed bool
    ut::expect(
        !hpp::proto::read_proto(
             value, split("\x0a\x12\x01\x02\x00\x80\x10\x81\x00\x01\x01\x01\x01\x01\x01\x01\x01\x81\x81\x81"s, 18))
             .ok());
    // invalid bool in the middle
    ut::expect(
        !hpp::proto::read_proto(
             value, split("\x0a\x13\x01\x82\x80\x80\x80\x81\x80\x81\x81\x81\x81\x81\x01\x01\x01\x81\x81\x81\x00"s, 18))
             .ok());
    // no valid bool in slope area
    ut::expect(
        !hpp::proto::read_proto(
             value, split("\x0a\x13\x81\x82\x80\x80\x80\x81\x80\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x00"s, 18))
             .ok());
  };

  "skip_group"_test = [] {
    repeated_bool value;
    using namespace std::string_literals;
    ut::expect(
        hpp::proto::read_proto(
            value,
            split(
                "\x1b\x0a\x08\x0a\x04\x62\x6c\x75\x65\x10\x01\x0a\x09\x0a\x05\x67\x72\x65\x65\x6e\x10\x02\x0a\x07\x0a\x03\x72\x65\x64\x10\x00\x1c"s,
                18))
            .ok());
    ut::expect(
        !hpp::proto::read_proto(
             value,
             split(
                 "\x1b\x0a\x08\x0a\x04\x62\x6c\x75\x65\x10\x01\x0a\x09\x0a\x05\x67\x72\x65\x65\x6e\x10\x02\x0a\x07\x0a\x03\x72\x65\x64\x10\x00"s,
                 18))
             .ok());
  };
};

template <typename Traits = hpp::proto::default_traits>
struct repeated_strings {
  Traits::template repeated_t<typename Traits::string_t> values;
  bool operator==(const repeated_strings &) const = default;
};

template <typename Traits>
auto pb_meta(const repeated_strings<Traits> &)
    -> std::tuple<hpp::proto::field_meta<1, &repeated_strings<Traits>::values, field_option::utf8_validation>>;

using namespace std::literals;

const ut::suite test_repeated_strings = [] {
  "invalid_repeated_strings"_test = [] {
    repeated_strings value;
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x03\x61\x62"sv).ok());
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x02\xc0\xdf"sv).ok());

    value.values.emplace_back("\xc0\xdf");
    ut::expect(!hpp::proto::write_proto(value).has_value());
  };

  using namespace boost::ut;
  "repeated_strings"_test = []<class Traits> {
    using element_type = typename Traits::string_t;
    verify("\x0a\x03\x61\x62\x63\x0a\x03\x64\x65\x66"sv,
           repeated_strings<Traits>{.values = std::initializer_list<element_type>{"abc", "def"}});
  } | std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits>{};
};

struct optional_bools {
  hpp::proto::optional<bool> false_defaulted;
  hpp::proto::optional<bool, true> true_defaulted;
  bool operator==(const optional_bools &) const = default;
};

auto pb_meta(const optional_bools &)
    -> std::tuple<
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

auto pb_meta(const oneof_example &)
    -> std::tuple<hpp::proto::oneof_field_meta<
        &oneof_example::value, hpp::proto::field_meta<1, 1, field_option::explicit_presence>,
        hpp::proto::field_meta<2, 2, field_option::explicit_presence, hpp::proto::vint64_t>,
        hpp::proto::field_meta<3, 3, field_option::explicit_presence>>>;

const ut::suite test_oneof = [] {
  "empty_oneof_example"_test = [] { verify(""sv, oneof_example{}); };

  "string_oneof_example"_test = [] { verify("\x0a\x04\x74\x65\x73\x74"sv, oneof_example{.value = "test"}); };

  "integer_oneof_example_5"_test = [] { verify("\x10\x05"sv, oneof_example{.value = 5}); };
  "integer_oneof_example_0"_test = [] { verify("\x10\x00"sv, oneof_example{.value = 0}); };

  "enum_oneof_example"_test = [] { verify("\x18\x02"sv, oneof_example{.value = color_t::green}); };
};

template <typename Traits = hpp::proto::default_traits>
struct extension_example {
  using hpp_proto_traits_type = Traits;
  int32_t int_value = {};
  hpp::proto::pb_extensions<Traits> unknown_fields_;

  [[nodiscard]] hpp::proto::status get_extension(auto &ext,
                                                 hpp::proto::concepts::is_option_type auto &&...option) const {
    return ext.get_from(*this, option...);
  }

  [[nodiscard]] hpp::proto::status set_extension(auto &&ext, hpp::proto::concepts::is_option_type auto &&...option) {
    return ext.set_to(*this, option...);
  }

  [[nodiscard]] bool has_extension(auto &&ext) const { return ext.in(*this); }

  bool operator==(const extension_example &) const = default;
};

template <typename Traits>
auto pb_meta(const extension_example<Traits> &)   
    -> std::tuple<
        hpp::proto::field_meta<1, &extension_example<Traits>::int_value, field_option::none, hpp::proto::vint64_t>,
        hpp::proto::field_meta<UINT32_MAX, &extension_example<Traits>::unknown_fields_>>;

template <typename Traits = ::hpp::proto::default_traits>
struct i32_ext : hpp::proto::extension_base<i32_ext<Traits>, extension_example> {
  using value_type = std::int32_t;
  value_type value = {};
  using pb_meta = std::tuple<
      ::hpp::proto::field_meta<10, &i32_ext<Traits>::value, field_option::explicit_presence, hpp::proto::vint64_t>>;
};

template <typename Traits = ::hpp::proto::default_traits>
struct string_ext : ::hpp::proto::extension_base<string_ext<Traits>, extension_example> {
  using value_type = typename Traits::string_t;
  value_type value = {};
  using pb_meta = std::tuple<::hpp::proto::field_meta<
      11, &string_ext<Traits>::value, field_option::explicit_presence | ::hpp::proto::field_option::utf8_validation>>;
};

template <typename Traits = ::hpp::proto::default_traits>
struct i32_defaulted_ext : ::hpp::proto::extension_base<i32_defaulted_ext<Traits>, extension_example> {
  using value_type = std::int32_t;
  value_type value = 10;
  using pb_meta = std::tuple<::hpp::proto::field_meta<13, &i32_defaulted_ext<Traits>::value,
                                                      field_option::explicit_presence, hpp::proto::vint64_t, 10>>;
};

template <typename Traits = ::hpp::proto::default_traits>
struct i32_unset_ext : ::hpp::proto::extension_base<i32_unset_ext<Traits>, extension_example> {
  using value_type = std::int32_t;
  value_type value = {};
  using pb_meta = std::tuple<::hpp::proto::field_meta<14, &i32_unset_ext<Traits>::value,
                                                      field_option::explicit_presence, hpp::proto::vint64_t>>;
};

template <typename Traits = ::hpp::proto::default_traits>
struct example_ext : ::hpp::proto::extension_base<example_ext<Traits>, extension_example> {
  using value_type = example;
  value_type value = {};
  using pb_meta =
      std::tuple<::hpp::proto::field_meta<15, &example_ext<Traits>::value, field_option::explicit_presence>>;
  ;
};

template <typename Traits = ::hpp::proto::default_traits>
struct repeated_i32_ext : ::hpp::proto::extension_base<repeated_i32_ext<Traits>, extension_example> {
  using value_type = typename Traits::template repeated_t<std::int32_t>;
  value_type value;
  using pb_meta = std::tuple<
      ::hpp::proto::field_meta<20, &repeated_i32_ext<Traits>::value, field_option::none, hpp::proto::vint64_t>>;
};

template <typename Traits = ::hpp::proto::default_traits>
struct repeated_string_ext : ::hpp::proto::extension_base<repeated_string_ext<Traits>, extension_example> {
  using value_type = typename Traits::template repeated_t<typename Traits::string_t>;
  value_type value;
  using pb_meta = std::tuple<::hpp::proto::field_meta<21, &repeated_string_ext<Traits>::value, field_option::none>>;
};

template <typename Traits = ::hpp::proto::default_traits>
struct repeated_packed_i32_ext : ::hpp::proto::extension_base<repeated_packed_i32_ext<Traits>, extension_example> {
  using value_type = typename Traits::template repeated_t<std::int32_t>;
  value_type value;
  using pb_meta = std::tuple<::hpp::proto::field_meta<22, &repeated_packed_i32_ext<Traits>::value,
                                                      field_option::is_packed, hpp::proto::vint64_t>>;
};

const ut::suite test_extensions = [] {
  "get_extension"_test = [] {
    auto encoded_data =
        "\x08\x96\x01\x50\x01\x5a\x04\x74\x65\x73\x74\x7a\x03\x08\x96\x01\xa0\x01\x01\xa0\x01\x02\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66\xb2\x01\x03\01\02\03"sv;
    const extension_example expected_value{
        .int_value = 150,
        .unknown_fields_ = {.fields = {{10U, "\x50\x01"_bytes},
                                  {11U, "\x5a\x04\x74\x65\x73\x74"_bytes},
                                  {15U, "\x7a\x03\x08\x96\x01"_bytes},
                                  {20U, "\xa0\x01\x01\xa0\x01\x02"_bytes},
                                  {21U, "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes},
                                  {22U, "\xb2\x01\x03\01\02\03"_bytes}}}};
    extension_example value;
    ut::expect(hpp::proto::read_proto(value, encoded_data).ok());
    ut::expect(value == expected_value);

    {
      i32_ext ext;
      ut::expect(value.has_extension(ext));
      ut::expect(value.get_extension(ext).ok());
      ut::expect(ext.value == 1);
    }

    {
      string_ext ext;
      ut::expect(value.has_extension(ext));
      ut::expect(value.get_extension(ext).ok());
      ut::expect(ext.value == "test");
    }
    {
      example_ext ext;
      ut::expect(value.has_extension(ext));
      ut::expect(value.get_extension(ext).ok());
      ut::expect(ext.value == example{.i = 150});
    }
    {
      repeated_i32_ext ext;
      ut::expect(value.has_extension(ext));
      ut::expect(value.get_extension(ext).ok());
      ut::expect(ext.value == std::vector<int32_t>{1, 2});
    }
    {
      repeated_string_ext ext;
      ut::expect(value.has_extension(ext));
      ut::expect(value.get_extension(ext).ok());
      ut::expect(ext.value == std::vector<std::string>{"abc", "def"});
    }
    {
      repeated_packed_i32_ext ext;
      ut::expect(value.has_extension(ext));
      ut::expect(value.get_extension(ext).ok());
      ut::expect(ext.value == std::vector<int32_t>{1, 2, 3});
    }

    std::vector<char> new_data{};
    ut::expect(hpp::proto::write_proto(value, new_data).ok());
    ut::expect(std::ranges::equal(encoded_data, new_data));
  };
  "set_extension"_test = [] {
    extension_example value;

    ut::expect(value.set_extension(i32_ext{.value = 1}).ok());
    ut::expect(value.unknown_fields_.fields[10] == "\x50\x01"_bytes);

    ut::expect(value.set_extension(string_ext{.value = "test"}).ok());
    ut::expect(value.unknown_fields_.fields[11] == "\x5a\x04\x74\x65\x73\x74"_bytes);

    ut::expect(value.set_extension(i32_defaulted_ext{}).ok());
    ut::expect(value.unknown_fields_.fields.contains(13));

    ut::expect(value.set_extension(example_ext{.value = example{.i = 150}}).ok());
    ut::expect(value.unknown_fields_.fields[15] == "\x7a\x03\x08\x96\x01"_bytes);

    ut::expect(value.set_extension(repeated_i32_ext{.value = {1, 2}}).ok());
    ut::expect(value.unknown_fields_.fields[20] == "\xa0\x01\x01\xa0\x01\x02"_bytes);

    ut::expect(value.set_extension(repeated_string_ext{.value = {"abc", "def"}}).ok());
    ut::expect(value.unknown_fields_.fields[21] == "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes);

    ut::expect(value.set_extension(repeated_packed_i32_ext{.value = {1, 2, 3}}).ok());
    ut::expect(value.unknown_fields_.fields[22] == "\xb2\x01\x03\01\02\03"_bytes);
  };

  "invalid_extension"_test = [] {
    extension_example value;
    ut::expect(!hpp::proto::read_proto(value, "\x08\x96\x01\x50\x81\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"sv).ok());
  };

  "read_invalid_extension"_test = [] {
    extension_example value{.int_value = 150, .unknown_fields_ = {.fields = {{15U, "\x7a\x03\x08\x96\x81"_bytes}}}};
    example_ext ext;
    ut::expect(ext.in(value));
    ut::expect(!ext.get_from(value).ok());
  };

  "write_invalid_extension"_test = [] {
    extension_example value;
    ut::expect(!string_ext{.value = "\xc0\xcd"}.set_to(value).ok());
  };
};

const ut::suite test_non_owning_extensions = [] {
  using non_owning_extension_example = extension_example<hpp::proto::non_owning_traits>;
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

    non_owning_extension_example const expected_value{.int_value = 150, .unknown_fields_ = {.fields = fields_storage}};
    non_owning_extension_example value;

    std::pmr::monotonic_buffer_resource mr;
    ut::expect(hpp::proto::read_proto(value, encoded_data, hpp::proto::alloc_from{mr}).ok());
    ut::expect(value == expected_value);

    ut::expect(value.has_extension(string_ext{}));
    ut::expect(!value.has_extension(i32_defaulted_ext{}));
    ut::expect(!value.has_extension(i32_unset_ext{}));
    ut::expect(value.has_extension(example_ext{}));

    {
      string_ext<hpp::proto::non_owning_traits> ext;
      ut::expect(value.has_extension(ext));
      ut::expect(value.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
      ut::expect(ext.value == "test"sv);
    }
    {
      example_ext<hpp::proto::non_owning_traits> ext;
      ut::expect(value.has_extension(ext));
      ut::expect(value.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
      ut::expect(ext.value == example{.i = 150});
    }
    {
      repeated_i32_ext<hpp::proto::non_owning_traits> ext;
      ut::expect(value.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
      ut::expect(std::ranges::equal(ext.value, std::initializer_list<uint32_t>{1, 2}));
    }
    {
      repeated_string_ext<hpp::proto::non_owning_traits> ext;
      ut::expect(value.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
      using namespace std::literals;
      ut::expect(std::ranges::equal(ext.value, std::initializer_list<std::string_view>{"abc"sv, "def"sv}));
    }
    {
      repeated_packed_i32_ext<hpp::proto::non_owning_traits> ext;
      ut::expect(value.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
      ut::expect(std::ranges::equal(ext.value, std::initializer_list<uint32_t>{1, 2, 3}));
    }

    std::vector<char> new_data{};
    ut::expect(hpp::proto::write_proto(value, new_data).ok());

    ut::expect(std::ranges::equal(encoded_data, new_data));
  };
  "set_non_owning_extension"_test = [] {
    std::pmr::monotonic_buffer_resource mr;
    non_owning_extension_example value;
    ut::expect(value.set_extension(i32_ext{.value = 1}, hpp::proto::alloc_from{mr}).ok());
    ut::expect(value.unknown_fields_.fields.back().first == 10);
    ut::expect(std::ranges::equal(value.unknown_fields_.fields.back().second, "\x50\x01"_bytes));

    ut::expect(value.set_extension(string_ext{.value = "test"}, hpp::proto::alloc_from{mr}).ok());
    ut::expect(value.unknown_fields_.fields.back().first == 11);
    ut::expect(std::ranges::equal(value.unknown_fields_.fields.back().second, "\x5a\x04\x74\x65\x73\x74"_bytes));

    ut::expect(value.set_extension(i32_defaulted_ext{}, hpp::proto::alloc_from{mr}).ok());
    ut::expect(value.unknown_fields_.fields.back().first == 13);

    ut::expect(value.set_extension(example_ext{.value = example{.i = 150}}, hpp::proto::alloc_from{mr}).ok());
    ut::expect(value.unknown_fields_.fields.back().first == 15);
    ut::expect(std::ranges::equal(value.unknown_fields_.fields.back().second, "\x7a\x03\x08\x96\x01"_bytes));

    ut::expect(value.set_extension(repeated_i32_ext{.value = {1, 2}}, hpp::proto::alloc_from{mr}).ok());
    ut::expect(value.unknown_fields_.fields.back().first == 20);
    ut::expect(std::ranges::equal(value.unknown_fields_.fields.back().second, "\xa0\x01\x01\xa0\x01\x02"_bytes));

    using namespace std::literals;
    ut::expect(
        value
            .set_extension(
                repeated_string_ext<hpp::proto::non_owning_traits>{.value = std::initializer_list{"abc"sv, "def"sv}},
                hpp::proto::alloc_from{mr})
            .ok());
    ut::expect(value.unknown_fields_.fields.back().first == 21);
    ut::expect(std::ranges::equal(value.unknown_fields_.fields.back().second,
                                  "\xaa\x01\x03\x61\x62\x63\xaa\x01\x03\x64\x65\x66"_bytes));

    ut::expect(value
                   .set_extension(
                       repeated_packed_i32_ext<hpp::proto::non_owning_traits>{.value = std::initializer_list{1, 2, 3}},
                       hpp::proto::alloc_from{mr})
                   .ok());
    ut::expect(value.unknown_fields_.fields.back().first == 22);
    ut::expect(std::ranges::equal(value.unknown_fields_.fields.back().second, "\xb2\x01\x03\01\02\03"_bytes));
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

auto pb_meta(const non_owning_recursive_type1 &)
    -> std::tuple<
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

auto pb_meta(const non_owning_recursive_type2 &)
    -> std::tuple<
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

    verify("\x0a\x02\x10\x02\x10\x01"sv, value);
  };

  "invalid_non_owning_recursive_type1"_test = [] {
    non_owning_recursive_type1 value;
    std::pmr::monotonic_buffer_resource mr;
    ut::expect(!hpp::proto::read_proto(value, "\x0a\x0c\x10\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x10\x10\x01"sv,
                                       hpp::proto::alloc_from{mr})
                    .ok());
  };

  "non_owning_recursive_type2"_test = [] {
    non_owning_recursive_type2 child[1];
    child[0].payload = 2;
    non_owning_recursive_type2 value;
    value.children = child;
    value.payload = 1;

    verify("\x0a\x02\x10\x02\x10\x01"sv, value);
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
  hpp::proto::pb_unknown_fields<hpp::proto::default_traits> unknown_fields_;

  bool operator==(const monster &) const = default;
  using pb_meta = std::tuple<
      hpp::proto::field_meta<1, &monster::pos>,
      hpp::proto::field_meta<2, &monster::mana, field_option::none, hpp::proto::vint64_t>,
      hpp::proto::field_meta<3, &monster::hp>, hpp::proto::field_meta<4, &monster::name>,
      hpp::proto::field_meta<5, &monster::inventory, field_option::is_packed>,
      hpp::proto::field_meta<6, &monster::color>, hpp::proto::field_meta<7, &monster::weapons, field_option::none>,
      hpp::proto::field_meta<8, &monster::equipped>, hpp::proto::field_meta<9, &monster::path, field_option::none>,
      hpp::proto::field_meta<10, &monster::boss>, hpp::proto::field_meta<UINT32_MAX, &monster::unknown_fields_>>;
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

  "invalid_nested_message"_test = [] {
    ut::expect(!hpp::proto::read_proto<monster_with_optional>("\x42\x07\x0a\x04\x73\x65\x73\x74"sv).has_value());
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
  constexpr_verify(carg(""_bytes_view), carg(empty{}));
  constexpr_verify(carg("\x08\x96\x01"_bytes_view), carg(example{150}));
  constexpr_verify(carg("\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"_bytes_view), carg(example{-1}));
  constexpr_verify(carg(""_bytes_view), carg(example{}));
  constexpr_verify(carg("\x0a\x03\x08\x96\x01"_bytes_view), carg(nested_example{.nested = example{150}}));
  constexpr_verify(carg("\x08\x00"_bytes_view), carg(example_explicit_presence{.i = 0}));
  constexpr_verify(carg(""_bytes_view), carg(example_default_type{}));
  // constexpr_verify(carg("\x0a\x09\x00\x02\x04\x06\x08\x01\x03\x05\x07"_bytes_view), carg(repeated_sint32{{0, 1, 2, 3,
  //  4, -1, -2, -3, -4}}));
#endif
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}