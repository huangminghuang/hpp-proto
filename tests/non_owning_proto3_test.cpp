
#include "gpb_proto_json/gpb_proto_json.h"
#include "test_util.h"
#include <boost/ut.hpp>
#include <non_owning/google/protobuf/unittest_proto3.glz.hpp>
#include <non_owning/google/protobuf/unittest_proto3.pb.hpp>

using namespace non_owning;
using namespace std::string_view_literals;
using namespace hpp::proto::literals;

// We selectively set/check a few representative fields rather than all fields
// as this test is only expected to cover the basics of lite support.
inline void SetAllFields(proto3_unittest::TestAllTypes *m) {

  m->optional_int32 = 100;
  m->optional_string = "asdf";
  m->optional_bytes = "jkl;"_bytes_view;

  m->optional_nested_message = proto3_unittest::TestAllTypes::NestedMessage { .bb = 42 };
  m->optional_foreign_message.emplace().c = 43;
  m->optional_nested_enum = proto3_unittest::TestAllTypes::NestedEnum::BAZ;
  m->optional_foreign_enum = proto3_unittest::ForeignEnum::FOREIGN_BAZ;
  m->optional_lazy_message = proto3_unittest::TestAllTypes::NestedMessage { .bb = 45 };
  m->optional_unverified_lazy_message= proto3_unittest::TestAllTypes::NestedMessage { .bb = 46 };

  const static int32_t repeated_int32[] = {100};
  m->repeated_int32 = repeated_int32;
  const static std::string_view repeated_string[] = {"asdf"sv};
  m->repeated_string = repeated_string;
  const static hpp::proto::bytes_view repeated_bytes[] = {"jkl;"_bytes_view};
  m->repeated_bytes = repeated_bytes;
  const static proto3_unittest::TestAllTypes::NestedMessage repeated_nested_message[] = {
      proto3_unittest::TestAllTypes::NestedMessage{.bb = 46}};
  m->repeated_nested_message = repeated_nested_message;
  const static proto3_unittest::ForeignMessage repeated_foreign_message[] = {proto3_unittest::ForeignMessage{.c = 47}};
  m->repeated_foreign_message = repeated_foreign_message;
  const static proto3_unittest::TestAllTypes::NestedEnum repeated_nested_enum[] = {
      proto3_unittest::TestAllTypes::NestedEnum::BAZ};
  m->repeated_nested_enum = repeated_nested_enum;
  const static proto3_unittest::ForeignEnum repeated_foreign_enum[] = {proto3_unittest::ForeignEnum::FOREIGN_BAZ};
  m->repeated_foreign_enum = repeated_foreign_enum;
  const static proto3_unittest::TestAllTypes::NestedMessage repeated_lazy_message[] = {
      proto3_unittest::TestAllTypes::NestedMessage{.bb = 49}};
  m->repeated_lazy_message = repeated_lazy_message;

  m->oneof_field = 1U;
  m->oneof_field = proto3_unittest::TestAllTypes::NestedMessage { .bb = 50 };
  m->oneof_field = "test"; // only this one remains set
}

inline void SetUnpackedFields(proto3_unittest::TestUnpackedTypes *message) {
  const static int32_t repeated_int32[] = {601, 701};
  message->repeated_int32 = repeated_int32;
  const static int64_t repeated_int64[] = {602LL, 702LL};
  message->repeated_int64 = repeated_int64;
  const static uint32_t repeated_uint32[] = {603U, 703U};
  message->repeated_uint32 = repeated_uint32;
  const static uint64_t repeated_uint64[] = {604ULL, 704ULL};
  message->repeated_uint64 = repeated_uint64;
  const static int32_t repeated_sint32[] = {605, 705};
  message->repeated_sint32 = repeated_sint32;
  const static int64_t repeated_sint64[] = {606LL, 706LL};
  message->repeated_sint64 = repeated_sint64;

  const static uint32_t repeated_fixed32[] = {607U, 707U};
  message->repeated_fixed32 = repeated_fixed32;
  const static uint64_t repeated_fixed64[] = {608ULL, 708ULL};
  message->repeated_fixed64 = repeated_fixed64;
  const static int32_t repeated_sfixed32[] = {609, 709};
  message->repeated_sfixed32 = repeated_sfixed32;
  const static int64_t repeated_sfixed64[] = {610LL, 710LL};
  message->repeated_sfixed64 = repeated_sfixed64;
  const static float repeated_float[] = {611.F, 711.F};
  message->repeated_float = repeated_float;
  const static double repeated_double[] = {612., 712.};
  message->repeated_double = repeated_double;
  const static bool repeated_bool[] = {true, false};
  message->repeated_bool = repeated_bool;
  const static proto3_unittest::TestAllTypes::NestedEnum repeated_nested_enum[] = {
      proto3_unittest::TestAllTypes::NestedEnum::BAR, proto3_unittest::TestAllTypes::NestedEnum::BAZ};
  message->repeated_nested_enum = repeated_nested_enum;
}

inline void ExpectAllFieldsSet(const proto3_unittest::TestAllTypes &m) {
  namespace ut = boost::ut;
  using namespace hpp::proto::literals;

  ut::expect(100 == m.optional_int32);
  ut::expect("asdf"sv == m.optional_string);
  ut::expect(ranges_equal("jkl;"_bytes, m.optional_bytes));

  ut::expect(m.optional_nested_message.has_value() && 42 == m.optional_nested_message->bb);
  ut::expect(m.optional_foreign_message.has_value() && 43 == m.optional_foreign_message->c);
  ut::expect(proto3_unittest::TestAllTypes::NestedEnum::BAZ == m.optional_nested_enum);
  ut::expect(proto3_unittest::ForeignEnum::FOREIGN_BAZ == m.optional_foreign_enum);
  ut::expect(m.optional_lazy_message.has_value() && 45 == m.optional_lazy_message->bb);
  ut::expect(m.optional_unverified_lazy_message.has_value() && 46 == m.optional_unverified_lazy_message->bb);

  ut::expect(1 == m.repeated_int32.size());
  ut::expect(100 == m.repeated_int32[0]);
  ut::expect(1 == m.repeated_string.size());
  ut::expect("asdf" == m.repeated_string[0]);
  ut::expect(1 == m.repeated_bytes.size());
  ut::expect(ranges_equal("jkl;"_bytes, m.repeated_bytes[0]));
  ut::expect(1 == m.repeated_nested_message.size());
  ut::expect(46 == m.repeated_nested_message[0].bb);
  ut::expect(1 == m.repeated_foreign_message.size());
  ut::expect(47 == m.repeated_foreign_message[0].c);
  ut::expect(1 == m.repeated_nested_enum.size());
  ut::expect(proto3_unittest::TestAllTypes::NestedEnum::BAZ == m.repeated_nested_enum[0]);
  ut::expect(1 == m.repeated_foreign_enum.size());
  ut::expect(proto3_unittest::ForeignEnum::FOREIGN_BAZ == m.repeated_foreign_enum[0]);
  ut::expect(1 == m.repeated_lazy_message.size());
  ut::expect(49 == m.repeated_lazy_message[0].bb);

  ut::expect("test"sv == std::get<std::string_view>(m.oneof_field));
}

void ExpectUnpackedFieldsSet(proto3_unittest::TestUnpackedTypes &message) {
  namespace ut = boost::ut;

  ut::expect(ranges_equal(std::vector{601, 701}, message.repeated_int32));
  ut::expect(ranges_equal(std::vector{602LL, 702LL}, message.repeated_int64));
  ut::expect(ranges_equal(std::vector{603U, 703U}, message.repeated_uint32));
  ut::expect(ranges_equal(std::vector{604ULL, 704ULL}, message.repeated_uint64));
  ut::expect(ranges_equal(std::vector{605, 705}, message.repeated_sint32));
  ut::expect(ranges_equal(std::vector{606LL, 706LL}, message.repeated_sint64));
  ut::expect(ranges_equal(std::vector{607U, 707U}, message.repeated_fixed32));
  ut::expect(ranges_equal(std::vector{608ULL, 708ULL}, message.repeated_fixed64));
  ut::expect(ranges_equal(std::vector{609, 709}, message.repeated_sfixed32));
  ut::expect(ranges_equal(std::vector{610LL, 710LL}, message.repeated_sfixed64));
  ut::expect(ranges_equal(std::vector{611.F, 711.F}, message.repeated_float));
  ut::expect(ranges_equal(std::vector{612., 712.}, message.repeated_double));
  ut::expect(ranges_equal(std::vector<hpp::proto::boolean>{true, false}, message.repeated_bool));
  ut::expect(ranges_equal(
      std::vector{proto3_unittest::TestAllTypes::NestedEnum::BAR, proto3_unittest::TestAllTypes::NestedEnum::BAZ},
      message.repeated_nested_enum));
}

const boost::ut::suite non_owning_proto3_lite_test = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;
  auto unittest_proto3_descriptorset = descriptorset_from_file("unittest_proto3.bin");

  "protobuf"_test = [] {
    proto3_unittest::TestAllTypes original;
    SetAllFields(&original);

    proto3_unittest::TestAllTypes msg;

    monotonic_buffer_resource mr{4096};
    std::vector<std::byte> data;

    expect(hpp::proto::write_proto(original, data).success());
    expect(hpp::proto::read_proto(msg, data, hpp::proto::pb_context{mr}).success());

    ExpectAllFieldsSet(msg);
  };

  "unpacked_repeated"_test = [&] {
    proto3_unittest::TestUnpackedTypes original;
    SetUnpackedFields(&original);

    proto3_unittest::TestUnpackedTypes msg;

    monotonic_buffer_resource mr{4096};
    std::vector<std::byte> data;
    expect(hpp::proto::write_proto(original, data).success());
    expect(hpp::proto::read_proto(msg, data, hpp::proto::pb_context{mr}).success());

    ExpectUnpackedFieldsSet(msg);

    auto json_string = glz::write_json(original);
    auto m = gpb_based::json_to_proto(unittest_proto3_descriptorset, "proto3_unittest.TestUnpackedTypes", json_string);

    expect(eq(m.size(), data.size()));
    expect(memcmp(data.data(), m.data(), m.size()) == 0);
  };

  "glaze"_test = [&] {
    proto3_unittest::TestAllTypes original;
    SetAllFields(&original);

    monotonic_buffer_resource mr{4096};
    std::vector<char> data;
    expect(hpp::proto::write_proto(original, data).success());

    auto original_json = gpb_based::proto_to_json(unittest_proto3_descriptorset, "proto3_unittest.TestAllTypes",
                                                  {data.data(), data.size()});

    expect(hpp::proto::write_json(original).value() == original_json);

    proto3_unittest::TestAllTypes msg;
    expect(hpp::proto::read_json(msg, original_json, hpp::proto::json_context{mr}).success());

    ExpectAllFieldsSet(msg);
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}