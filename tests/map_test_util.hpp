#pragma once
#include "test_util.hpp"
#include <boost/ut.hpp>
#include <google/protobuf/map_unittest.pb.hpp>

inline void SetMapFields(protobuf_unittest::TestMap *message) {

  // Add first element.
  message->map_int32_int32[0] = 0;
  message->map_int64_int64[0] = 0;
  message->map_uint32_uint32[0] = 0;
  message->map_uint64_uint64[0] = 0;
  message->map_sint32_sint32[0] = 0;
  message->map_sint64_sint64[0] = 0;
  message->map_fixed32_fixed32[0] = 0;
  message->map_fixed64_fixed64[0] = 0;
  message->map_sfixed32_sfixed32[0] = 0;
  message->map_sfixed64_sfixed64[0] = 0;
  message->map_int32_float[0] = 0.0;
  message->map_int32_double[0] = 0.0;
  message->map_bool_bool[0] = false;
  message->map_string_string["0"] = "0";
  message->map_int32_bytes[0] = "0"_bytes;
  message->map_int32_enum[0] = protobuf_unittest::MapEnum::MAP_ENUM_FOO;
  message->map_int32_foreign_message[0].c = 0;

  // Add second element
  message->map_int32_int32[1] = 1;
  message->map_int64_int64[1] = 1;
  message->map_uint32_uint32[1] = 1;
  message->map_uint64_uint64[1] = 1;
  message->map_sint32_sint32[1] = 1;
  message->map_sint64_sint64[1] = 1;
  message->map_fixed32_fixed32[1] = 1;
  message->map_fixed64_fixed64[1] = 1;
  message->map_sfixed32_sfixed32[1] = 1;
  message->map_sfixed64_sfixed64[1] = 1;
  message->map_int32_float[1] = 1.0;
  message->map_int32_double[1] = 1.0;
  message->map_bool_bool[1] = true;
  message->map_string_string["1"] = "1";
  message->map_int32_bytes[1] = "1"_bytes;
  message->map_int32_enum[1] = protobuf_unittest::MapEnum::MAP_ENUM_BAR;
  message->map_int32_foreign_message[1].c = 1;
}

void ExpectMapFieldsSet(const protobuf_unittest::TestMap &message) {
  using namespace boost::ut;
  using namespace std::literals::string_literals;
  expect(fatal(eq(2, message.map_int32_int32.size())));
  expect(fatal(eq(2, message.map_int64_int64.size())));
  expect(fatal(eq(2, message.map_uint32_uint32.size())));
  expect(fatal(eq(2, message.map_uint64_uint64.size())));
  expect(fatal(eq(2, message.map_sint32_sint32.size())));
  expect(fatal(eq(2, message.map_sint64_sint64.size())));
  expect(fatal(eq(2, message.map_fixed32_fixed32.size())));
  expect(fatal(eq(2, message.map_fixed64_fixed64.size())));
  expect(fatal(eq(2, message.map_sfixed32_sfixed32.size())));
  expect(fatal(eq(2, message.map_sfixed64_sfixed64.size())));
  expect(fatal(eq(2, message.map_int32_float.size())));
  expect(fatal(eq(2, message.map_int32_double.size())));
  expect(fatal(eq(2, message.map_bool_bool.size())));
  expect(fatal(eq(2, message.map_string_string.size())));
  expect(fatal(eq(2, message.map_int32_bytes.size())));
  expect(fatal(eq(2, message.map_int32_enum.size())));
  expect(fatal(eq(2, message.map_int32_foreign_message.size())));

  expect(eq(0, message.map_int32_int32.at(0)));
  expect(eq(0, message.map_int64_int64.at(0)));
  expect(eq(0, message.map_uint32_uint32.at(0)));
  expect(eq(0, message.map_uint64_uint64.at(0)));
  expect(eq(0, message.map_sint32_sint32.at(0)));
  expect(eq(0, message.map_sint64_sint64.at(0)));
  expect(eq(0, message.map_fixed32_fixed32.at(0)));
  expect(eq(0, message.map_fixed64_fixed64.at(0)));
  expect(eq(0, message.map_sfixed32_sfixed32.at(0)));
  expect(eq(0, message.map_sfixed64_sfixed64.at(0)));
  expect(eq(0, message.map_int32_float.at(0)));
  expect(eq(0, message.map_int32_double.at(0)));
  expect(eq(false, message.map_bool_bool.at(0)));
  expect(eq("0"s, message.map_string_string.at("0")));
  expect("0"_bytes == message.map_int32_bytes.at(0));
  expect(protobuf_unittest::MapEnum::MAP_ENUM_FOO == message.map_int32_enum.at(0));
  expect(eq(0, message.map_int32_foreign_message.at(0).c.value()));

  expect(eq(1, message.map_int32_int32.at(1)));
  expect(eq(1, message.map_int64_int64.at(1)));
  expect(eq(1, message.map_uint32_uint32.at(1)));
  expect(eq(1, message.map_uint64_uint64.at(1)));
  expect(eq(1, message.map_sint32_sint32.at(1)));
  expect(eq(1, message.map_sint64_sint64.at(1)));
  expect(eq(1, message.map_fixed32_fixed32.at(1)));
  expect(eq(1, message.map_fixed64_fixed64.at(1)));
  expect(eq(1, message.map_sfixed32_sfixed32.at(1)));
  expect(eq(1, message.map_sfixed64_sfixed64.at(1)));
  expect(eq(1, message.map_int32_float.at(1)));
  expect(eq(1, message.map_int32_double.at(1)));
  expect(eq(true, message.map_bool_bool.at(1)));
  expect(eq("1"s, message.map_string_string.at("1")));
  expect("1"_bytes == message.map_int32_bytes.at(1));
  expect(protobuf_unittest::MapEnum::MAP_ENUM_BAR == message.map_int32_enum.at(1));
  expect(eq(1, message.map_int32_foreign_message.at(1).c.value()));
}