#pragma once
#include "test_util.hpp"
#include <array>
#include <boost/ut.hpp>
#include <google/protobuf/map_unittest.pb.hpp>

template <typename Traits>
struct init_list {
  using bool_t = typename Traits::template repeated_t<bool>::value_type;
  using string_t = typename Traits::string_t;
  using bytes_t = typename Traits::bytes_t;

  constexpr static auto map_int32_int32 = std::initializer_list<std::pair<std::int32_t, std::int32_t>>{{0, 0}, {1, 1}};
  constexpr static auto map_int64_int64 =
      std::initializer_list<std::pair<std::int64_t, std::int64_t>>{{0LL, 0LL}, {1LL, 1LL}};
  constexpr static auto map_uint32_uint32 =
      std::initializer_list<std::pair<std::uint32_t, std::uint32_t>>{{0U, 0U}, {1U, 1U}};
  constexpr static auto map_uint64_uint64 =
      std::initializer_list<std::pair<std::uint64_t, std::uint64_t>>{{0ULL, 0ULL}, {1ULL, 1ULL}};
  constexpr static auto map_int32_float = std::initializer_list<std::pair<std::int32_t, float>>{{0, 0.0F}, {1, 1.0F}};
  constexpr static auto map_int32_double = std::initializer_list<std::pair<std::int32_t, double>>{{0, 0.0}, {1, 1.0}};
  constexpr static auto map_bool_bool = std::initializer_list<std::pair<bool_t, bool_t>>{{false, false}, {true, true}};
  constexpr static auto map_int32_enum = std::initializer_list<std::pair<std::int32_t, protobuf_unittest::MapEnum>>{
      {0, protobuf_unittest::MapEnum::MAP_ENUM_FOO}, {1, protobuf_unittest::MapEnum::MAP_ENUM_BAR}};

  const static std::array<std::pair<string_t, string_t>, 2> map_string_string;
  const static std::array<std::pair<std::int32_t, bytes_t>, 2> map_int32_bytes;
  constexpr static auto map_int32_foreign_message =
      std::initializer_list<std::pair<std::int32_t, ::protobuf_unittest::ForeignMessage<Traits>>>{{0, {.c = 0}},
                                                                                                  {1, {.c = 1}}};
};

template <typename Traits>
const std::array<std::pair<typename Traits::string_t, typename Traits::string_t>, 2>
    init_list<Traits>::map_string_string{{
        {typename Traits::string_t("0"), typename Traits::string_t("0")},
        {typename Traits::string_t("1"), typename Traits::string_t("1")},
    }};

template <typename Traits>
const std::array<std::pair<std::int32_t, typename Traits::bytes_t>, 2> init_list<Traits>::map_int32_bytes{{
    {0, static_cast<typename Traits::bytes_t>("0"_bytes)},
    {1, static_cast<typename Traits::bytes_t>("1"_bytes)},
}};

template <typename T>
void set_map(T &map, const auto &init_values) {
  if constexpr (requires { T{init_values}; }) {
    map = T{init_values};
  } else {
    using std::begin;
    using std::end;
    map = T{begin(init_values), end(init_values)};
  }
}

template <typename Traits>
inline void SetMapFields(protobuf_unittest::TestMap<Traits> *message) {
  using init_t = init_list<Traits>;

  set_map(message->map_int32_int32, init_t::map_int32_int32);
  set_map(message->map_int64_int64, init_t::map_int64_int64);
  set_map(message->map_uint32_uint32, init_t::map_uint32_uint32);
  set_map(message->map_uint64_uint64, init_t::map_uint64_uint64);
  set_map(message->map_sint32_sint32, init_t::map_int32_int32);
  set_map(message->map_sint64_sint64, init_t::map_int64_int64);
  set_map(message->map_fixed32_fixed32, init_t::map_uint32_uint32);
  set_map(message->map_fixed64_fixed64, init_t::map_uint64_uint64);
  set_map(message->map_sfixed32_sfixed32, init_t::map_int32_int32);
  set_map(message->map_sfixed64_sfixed64, init_t::map_int64_int64);
  set_map(message->map_int32_float, init_t::map_int32_float);
  set_map(message->map_int32_double, init_t::map_int32_double);
  set_map(message->map_bool_bool, init_t::map_bool_bool);
  set_map(message->map_int32_enum, init_t::map_int32_enum);
  set_map(message->map_string_string, init_t::map_string_string);
  set_map(message->map_int32_bytes, init_t::map_int32_bytes);
  set_map(message->map_int32_foreign_message, init_t::map_int32_foreign_message);
}

struct pair_equal {
  bool operator()(const auto &lhs, const auto &rhs) const { return lhs.first == rhs.first && lhs.second == rhs.second; }
};

bool map_equal(const auto &lhs, const auto &rhs) { return std::ranges::equal(lhs, rhs, pair_equal{}); }

template <typename Traits>
inline void ExpectMapFieldsSet(const protobuf_unittest::TestMap<Traits> &message) {
  using namespace boost::ut;
  using init_t = init_list<Traits>;

  expect(map_equal(message.map_int32_int32, init_t::map_int32_int32));
  expect(map_equal(message.map_int64_int64, init_t::map_int64_int64));
  expect(map_equal(message.map_uint32_uint32, init_t::map_uint32_uint32));
  expect(map_equal(message.map_uint64_uint64, init_t::map_uint64_uint64));
  expect(map_equal(message.map_sint32_sint32, init_t::map_int32_int32));
  expect(map_equal(message.map_sint64_sint64, init_t::map_int64_int64));
  expect(map_equal(message.map_fixed32_fixed32, init_t::map_uint32_uint32));
  expect(map_equal(message.map_fixed64_fixed64, init_t::map_uint64_uint64));
  expect(map_equal(message.map_sfixed32_sfixed32, init_t::map_int32_int32));
  expect(map_equal(message.map_sfixed64_sfixed64, init_t::map_int64_int64));
  expect(map_equal(message.map_int32_float, init_t::map_int32_float));
  expect(map_equal(message.map_int32_double, init_t::map_int32_double));
  expect(map_equal(message.map_bool_bool, init_t::map_bool_bool));
  expect(map_equal(message.map_int32_enum, init_t::map_int32_enum));
  expect(map_equal(message.map_string_string, init_t::map_string_string));
  expect(map_equal(message.map_int32_bytes, init_t::map_int32_bytes));
  expect(map_equal(message.map_int32_foreign_message, init_t::map_int32_foreign_message));
}
