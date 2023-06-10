
#include "gpb_proto_json/gpb_proto_json.h"
#include <boost/ut.hpp>
#include <google/protobuf/unittest.glz.hpp>
#include <google/protobuf/unittest.pb.hpp>
#include <regex>
namespace ut = boost::ut;

template <zpp::bits::string_literal String>
constexpr auto operator""_bytes() {
  auto v = zpp::bits::to_bytes<String>();
  return std::vector<std::byte>{v.begin(), v.end()};
}

namespace std {
std::ostream &operator<<(std::ostream &os, std::byte b) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  char result[] = "\\x00";
  unsigned char c = static_cast<unsigned char>(b);
  result[2] = qmap[c >> 4];
  result[3] = qmap[c & '\x0F'];
  return os << result;
}

std::ostream &operator<<(std::ostream &os, const std::vector<std::byte> &bytes) {
  for (auto b : bytes) {
    os << b;
  }
  return os;
}
} // namespace std

namespace TestUtil {
using namespace std::literals::string_literals;
using namespace boost::ut;

// Set every field in the message to a unique value.
inline void SetAllFields(protobuf_unittest::TestAllTypes *message);
inline void SetOptionalFields(protobuf_unittest::TestAllTypes *message);
inline void AddRepeatedFields1(protobuf_unittest::TestAllTypes *message);
inline void AddRepeatedFields2(protobuf_unittest::TestAllTypes *message);
inline void SetDefaultFields(protobuf_unittest::TestAllTypes *message);
inline void SetOneofFields(protobuf_unittest::TestAllTypes *message);
inline void SetAllExtensions(protobuf_unittest::TestAllExtensions *message);
inline void SetOneofFields(protobuf_unittest::TestAllExtensions *message);
inline void SetAllFieldsAndExtensions(protobuf_unittest::TestFieldOrderings *message);
inline void SetPackedFields(protobuf_unittest::TestPackedTypes *message);
inline void SetPackedExtensions(protobuf_unittest::TestPackedExtensions *message);
inline void SetUnpackedFields(protobuf_unittest::TestUnpackedTypes *message);
inline void SetOneof1(protobuf_unittest::TestOneof2 *message);
inline void SetOneof2(protobuf_unittest::TestOneof2 *message);

// Use the repeated versions of the set_*() accessors to modify all the
// repeated fields of the message (which should already have been
// initialized with Set*Fields()).  Set*Fields() itself only tests
// the add_*() accessors.
inline void ModifyRepeatedFields(protobuf_unittest::TestAllTypes *message);

// Check that all fields have the values that they should have after
// Set*Fields() is called.
inline void ExpectAllFieldsSet(const protobuf_unittest::TestAllTypes &message);
inline void ExpectAllExtensionsSet(const protobuf_unittest::TestAllExtensions &message);
inline void ExpectPackedFieldsSet(const protobuf_unittest::TestPackedTypes &message);
inline void ExpectPackedExtensionsSet(const protobuf_unittest::TestPackedExtensions &message);
inline void ExpectUnpackedFieldsSet(const protobuf_unittest::TestUnpackedTypes &message);
inline void ExpectUnpackedExtensionsSet(const protobuf_unittest::TestUnpackedExtensions &message);
inline void ExpectOneofSet1(const protobuf_unittest::TestOneof2 &message);
inline void ExpectOneofSet2(const protobuf_unittest::TestOneof2 &message);

// Expect that the message is modified as would be expected from
// Modify*Fields().
inline void ExpectRepeatedFieldsModified(const protobuf_unittest::TestAllTypes &message);

// Check that all fields have their default values.
inline void ExpectClear(const protobuf_unittest::TestAllTypes &message);
inline void ExpectExtensionsClear(const protobuf_unittest::TestAllExtensions &message);
inline void ExpectOneofClear(const protobuf_unittest::TestOneof2 &message);

} // namespace TestUtil

inline void TestUtil::SetAllFields(protobuf_unittest::TestAllTypes *message) {
  SetOptionalFields(message);
  AddRepeatedFields1(message);
  AddRepeatedFields2(message);
  SetDefaultFields(message);
  SetOneofFields(message);
}

inline void TestUtil::SetOptionalFields(protobuf_unittest::TestAllTypes *message) {
  message->optional_int32 = 101;
  message->optional_int64 = 102;
  message->optional_uint32 = 103;
  message->optional_uint64 = 104;
  message->optional_sint32 = 105;
  message->optional_sint64 = 106;
  message->optional_fixed32 = 107;
  message->optional_fixed64 = 108;
  message->optional_sfixed32 = 109;
  message->optional_sfixed64 = 110;
  message->optional_float = 111;
  message->optional_double = 112;
  message->optional_bool = true;
  message->optional_string = "115";
  message->optional_bytes = "116"_bytes;

  message->optional_nested_message.emplace().bb = 118;
  message->optional_foreign_message.emplace().c = 119;
  message->optional_import_message.emplace().d = 120;
  message->optional_public_import_message.emplace().e = 126;
  message->optional_lazy_message.emplace().bb = 127;
  message->optional_unverified_lazy_message.emplace().bb = 128;

  message->optional_nested_enum = protobuf_unittest::TestAllTypes::NestedEnum::BAZ;
  message->optional_foreign_enum = protobuf_unittest::ForeignEnum::FOREIGN_BAZ;
  message->optional_import_enum = protobuf_unittest_import::ImportEnum::IMPORT_BAZ;
}

// -------------------------------------------------------------------

inline void TestUtil::AddRepeatedFields1(protobuf_unittest::TestAllTypes *message) {
  message->repeated_int32.push_back(201);
  message->repeated_int64.push_back(202);
  message->repeated_uint32.push_back(203);
  message->repeated_uint64.push_back(204);
  message->repeated_sint32.push_back(205);
  message->repeated_sint64.push_back(206);
  message->repeated_fixed32.push_back(207);
  message->repeated_fixed64.push_back(208);
  message->repeated_sfixed32.push_back(209);
  message->repeated_sfixed64.push_back(210);
  message->repeated_float.push_back(211);
  message->repeated_double.push_back(212);
  message->repeated_bool.push_back(true);
  message->repeated_string.push_back("215");
  message->repeated_bytes.push_back("216"_bytes);

  message->repeated_nested_message.emplace_back().bb = 218;
  message->repeated_foreign_message.emplace_back().c = 219;
  message->repeated_import_message.emplace_back().d = 220;
  message->repeated_lazy_message.emplace_back().bb = 227;

  message->repeated_nested_enum.push_back(protobuf_unittest::TestAllTypes::NestedEnum::BAR);
  message->repeated_foreign_enum.push_back(protobuf_unittest::ForeignEnum::FOREIGN_BAR);
  message->repeated_import_enum.push_back(protobuf_unittest_import::ImportEnum::IMPORT_BAR);
}

inline void TestUtil::AddRepeatedFields2(protobuf_unittest::TestAllTypes *message) {
  // Add a second one of each field.
  message->repeated_int32.push_back(301);
  message->repeated_int64.push_back(302);
  message->repeated_uint32.push_back(303);
  message->repeated_uint64.push_back(304);
  message->repeated_sint32.push_back(305);
  message->repeated_sint64.push_back(306);
  message->repeated_fixed32.push_back(307);
  message->repeated_fixed64.push_back(308);
  message->repeated_sfixed32.push_back(309);
  message->repeated_sfixed64.push_back(310);
  message->repeated_float.push_back(311);
  message->repeated_double.push_back(312);
  message->repeated_bool.push_back(false);
  message->repeated_string.push_back("315");
  message->repeated_bytes.push_back("316"_bytes);

  message->repeated_nested_message.emplace_back().bb = 318;
  message->repeated_foreign_message.emplace_back().c = 319;
  message->repeated_import_message.emplace_back().d = 320;
  message->repeated_lazy_message.emplace_back().bb = 327;

  message->repeated_nested_enum.push_back(protobuf_unittest::TestAllTypes::NestedEnum::BAZ);
  message->repeated_foreign_enum.push_back(protobuf_unittest::ForeignEnum::FOREIGN_BAZ);
  message->repeated_import_enum.push_back(protobuf_unittest_import::ImportEnum::IMPORT_BAZ);
}

// -------------------------------------------------------------------

inline void TestUtil::SetDefaultFields(protobuf_unittest::TestAllTypes *message) {
  message->default_int32 = 401;
  message->default_int64 = 402;
  message->default_uint32 = 403;
  message->default_uint64 = 404;
  message->default_sint32 = 405;
  message->default_sint64 = 406;
  message->default_fixed32 = 407;
  message->default_fixed64 = 408;
  message->default_sfixed32 = 409;
  message->default_sfixed64 = 410;
  message->default_float = 411;
  message->default_double = 412;
  message->default_bool = false;
  message->default_string = "415";
  message->default_bytes = "416"_bytes;

  message->default_nested_enum = protobuf_unittest::TestAllTypes::NestedEnum::FOO;
  message->default_foreign_enum = protobuf_unittest::ForeignEnum::FOREIGN_FOO;
  message->default_import_enum = protobuf_unittest_import::ImportEnum::IMPORT_FOO;
}

// -------------------------------------------------------------------

inline void TestUtil::ModifyRepeatedFields(protobuf_unittest::TestAllTypes *message) {
  message->repeated_int32[1] = 501;
  message->repeated_int64[1] = 502;
  message->repeated_uint32[1] = 503;
  message->repeated_uint64[1] = 504;
  message->repeated_sint32[1] = 505;
  message->repeated_sint64[1] = 506;
  message->repeated_fixed32[1] = 507;
  message->repeated_fixed64[1] = 508;
  message->repeated_sfixed32[1] = 509;
  message->repeated_sfixed64[1] = 510;
  message->repeated_float[1] = 511;
  message->repeated_double[1] = 512;
  message->repeated_bool[1] = true;
  message->repeated_string[1] = "515";
  message->repeated_bytes[1] = "516"_bytes;

  message->repeated_nested_message[1].bb = 518;
  message->repeated_foreign_message[1].c = 519;
  message->repeated_import_message[1].d = 520;
  message->repeated_lazy_message[1].bb = 527;

  message->repeated_nested_enum[1] = protobuf_unittest::TestAllTypes::NestedEnum::FOO;
  message->repeated_foreign_enum[1] = protobuf_unittest::ForeignEnum::FOREIGN_FOO;
  message->repeated_import_enum[1] = protobuf_unittest_import::ImportEnum::IMPORT_FOO;
}

// ------------------------------------------------------------------
inline void TestUtil::SetOneofFields(protobuf_unittest::TestAllTypes *message) {
  message->oneof_field = 601U;
  message->oneof_field = protobuf_unittest::TestAllTypes::NestedMessage{.bb = 602};
  message->oneof_field = "603";
  message->oneof_field = "604"_bytes;
}

// -------------------------------------------------------------------

inline void TestUtil::ExpectAllFieldsSet(const protobuf_unittest::TestAllTypes &message) {
  ut::expect(message.optional_int32.has_value());
  ut::expect(message.optional_int64.has_value());
  ut::expect(message.optional_uint32.has_value());
  ut::expect(message.optional_uint64.has_value());
  ut::expect(message.optional_sint32.has_value());
  ut::expect(message.optional_sint64.has_value());
  ut::expect(message.optional_fixed32.has_value());
  ut::expect(message.optional_fixed64.has_value());
  ut::expect(message.optional_sfixed32.has_value());
  ut::expect(message.optional_sfixed64.has_value());
  ut::expect(message.optional_float.has_value());
  ut::expect(message.optional_double.has_value());
  ut::expect(message.optional_bool.has_value());
  ut::expect(message.optional_string.has_value());
  ut::expect(message.optional_bytes.has_value());

  ut::expect(message.optional_nested_message.has_value());
  ut::expect(message.optional_foreign_message.has_value());
  ut::expect(message.optional_import_message.has_value());
  ut::expect(message.optional_public_import_message.has_value());
  ut::expect(message.optional_lazy_message.has_value());
  ut::expect(message.optional_unverified_lazy_message.has_value());

  ut::expect(message.optional_nested_message->bb.has_value());
  ut::expect(message.optional_foreign_message->c.has_value());
  ut::expect(message.optional_import_message->d.has_value());
  ut::expect(message.optional_public_import_message->e.has_value());
  ut::expect(message.optional_lazy_message->bb.has_value());
  ut::expect(message.optional_unverified_lazy_message->bb.has_value());

  ut::expect(message.optional_nested_enum.has_value());
  ut::expect(message.optional_foreign_enum.has_value());
  ut::expect(message.optional_import_enum.has_value());

  ut::expect(ut::eq(101, message.optional_int32.value()));
  ut::expect(ut::eq(102, message.optional_int64.value()));
  ut::expect(ut::eq(103, message.optional_uint32.value()));
  ut::expect(ut::eq(104, message.optional_uint64.value()));
  ut::expect(ut::eq(105, message.optional_sint32.value()));
  ut::expect(ut::eq(106, message.optional_sint64.value()));
  ut::expect(ut::eq(107, message.optional_fixed32.value()));
  ut::expect(ut::eq(108, message.optional_fixed64.value()));
  ut::expect(ut::eq(109, message.optional_sfixed32.value()));
  ut::expect(ut::eq(110, message.optional_sfixed64.value()));
  ut::expect(ut::eq(111, message.optional_float.value()));
  ut::expect(ut::eq(112, message.optional_double.value()));
  ut::expect(message.optional_bool.value());

  ut::expect(ut::eq("115"s, message.optional_string.value()));
  ut::expect(ut::eq("116"_bytes, message.optional_bytes.value()));

  ut::expect(ut::eq(118, message.optional_nested_message->bb.value()));
  ut::expect(ut::eq(119, message.optional_foreign_message->c.value()));
  ut::expect(ut::eq(120, message.optional_import_message->d.value()));
  ut::expect(ut::eq(126, message.optional_public_import_message->e.value()));
  ut::expect(ut::eq(127, message.optional_lazy_message->bb.value()));
  ut::expect(ut::eq(128, message.optional_unverified_lazy_message->bb.value()));

  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::BAZ == message.optional_nested_enum.value());
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == message.optional_foreign_enum.value());
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_BAZ == message.optional_import_enum.value());

  // -----------------------------------------------------------------
  using namespace boost::ut;
  ut::expect(ut::eq(2, message.repeated_int32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_int64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_uint32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_uint64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_sint32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_sint64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_fixed32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_fixed64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_sfixed32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_sfixed64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_float.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_double.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_bool.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_string.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_bytes.size()) >> ut::fatal);

  ut::expect(ut::eq(2, message.repeated_nested_message.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_foreign_message.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_import_message.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_lazy_message.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_nested_enum.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_foreign_enum.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_import_enum.size()) >> ut::fatal);

  ut::expect(ut::eq(201, message.repeated_int32[0]));
  ut::expect(ut::eq(202, message.repeated_int64[0]));
  ut::expect(ut::eq(203, message.repeated_uint32[0]));
  ut::expect(ut::eq(204, message.repeated_uint64[0]));
  ut::expect(ut::eq(205, message.repeated_sint32[0]));
  ut::expect(ut::eq(206, message.repeated_sint64[0]));
  ut::expect(ut::eq(207, message.repeated_fixed32[0]));
  ut::expect(ut::eq(208, message.repeated_fixed64[0]));
  ut::expect(ut::eq(209, message.repeated_sfixed32[0]));
  ut::expect(ut::eq(210, message.repeated_sfixed64[0]));
  ut::expect(ut::eq(211, message.repeated_float[0]));
  ut::expect(ut::eq(212, message.repeated_double[0]));
  ut::expect(message.repeated_bool[0]);
  ut::expect(ut::eq("215"s, message.repeated_string[0]));
  ut::expect(ut::eq("216"_bytes, message.repeated_bytes[0]));

  ut::expect(ut::eq(218, message.repeated_nested_message[0].bb.value()));
  ut::expect(ut::eq(219, message.repeated_foreign_message[0].c.value()));
  ut::expect(ut::eq(220, message.repeated_import_message[0].d.value()));
  ut::expect(ut::eq(227, message.repeated_lazy_message[0].bb.value()));

  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::BAR == message.repeated_nested_enum[0]);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == message.repeated_foreign_enum[0]);
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_BAR == message.repeated_import_enum[0]);

  ut::expect(ut::eq(301, message.repeated_int32[1]));
  ut::expect(ut::eq(302, message.repeated_int64[1]));
  ut::expect(ut::eq(303, message.repeated_uint32[1]));
  ut::expect(ut::eq(304, message.repeated_uint64[1]));
  ut::expect(ut::eq(305, message.repeated_sint32[1]));
  ut::expect(ut::eq(306, message.repeated_sint64[1]));
  ut::expect(ut::eq(307, message.repeated_fixed32[1]));
  ut::expect(ut::eq(308, message.repeated_fixed64[1]));
  ut::expect(ut::eq(309, message.repeated_sfixed32[1]));
  ut::expect(ut::eq(310, message.repeated_sfixed64[1]));
  ut::expect(ut::eq(311, message.repeated_float[1]));
  ut::expect(ut::eq(312, message.repeated_double[1]));
  ut::expect(!message.repeated_bool[1]);
  ut::expect(ut::eq("315"s, message.repeated_string[1]));
  ut::expect(ut::eq("316"_bytes, message.repeated_bytes[1]));

  ut::expect(ut::eq(318, message.repeated_nested_message[1].bb.value()));
  ut::expect(ut::eq(319, message.repeated_foreign_message[1].c.value()));
  ut::expect(ut::eq(320, message.repeated_import_message[1].d.value()));
  ut::expect(ut::eq(327, message.repeated_lazy_message[1].bb.value()));

  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::BAZ == message.repeated_nested_enum[1]);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == message.repeated_foreign_enum[1]);
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_BAZ == message.repeated_import_enum[1]);

  // -----------------------------------------------------------------

  ut::expect(message.default_int32.has_value());
  ut::expect(message.default_int64.has_value());
  ut::expect(message.default_uint32.has_value());
  ut::expect(message.default_uint64.has_value());
  ut::expect(message.default_sint32.has_value());
  ut::expect(message.default_sint64.has_value());
  ut::expect(message.default_fixed32.has_value());
  ut::expect(message.default_fixed64.has_value());
  ut::expect(message.default_sfixed32.has_value());
  ut::expect(message.default_sfixed64.has_value());
  ut::expect(message.default_float.has_value());
  ut::expect(message.default_double.has_value());
  ut::expect(message.default_bool.has_value());
  ut::expect(message.default_string.has_value());
  ut::expect(message.default_bytes.has_value());

  ut::expect(message.default_nested_enum.has_value());
  ut::expect(message.default_foreign_enum.has_value());
  ut::expect(message.default_import_enum.has_value());

  ut::expect(ut::eq(401, message.default_int32.value_or_default()));
  ut::expect(ut::eq(402, message.default_int64.value_or_default()));
  ut::expect(ut::eq(403, message.default_uint32.value_or_default()));
  ut::expect(ut::eq(404, message.default_uint64.value_or_default()));
  ut::expect(ut::eq(405, message.default_sint32.value_or_default()));
  ut::expect(ut::eq(406, message.default_sint64.value_or_default()));
  ut::expect(ut::eq(407, message.default_fixed32.value_or_default()));
  ut::expect(ut::eq(408, message.default_fixed64.value_or_default()));
  ut::expect(ut::eq(409, message.default_sfixed32.value_or_default()));
  ut::expect(ut::eq(410, message.default_sfixed64.value_or_default()));
  ut::expect(ut::eq(411, message.default_float.value_or_default()));
  ut::expect(ut::eq(412, message.default_double.value_or_default()));
  ut::expect(!message.default_bool.value_or_default());
  ut::expect(ut::eq("415"s, message.default_string.value_or_default()));
  ut::expect(ut::eq("416"_bytes, message.default_bytes.value_or_default()));

  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::FOO == message.default_nested_enum.value_or_default());
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO == message.default_foreign_enum.value_or_default());
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO == message.default_import_enum.value_or_default());

  ut::expect(message.oneof_field.index() == protobuf_unittest::TestAllTypes::oneof_bytes);

  ut::expect(ut::eq("604"_bytes, std::get<protobuf_unittest::TestAllTypes::oneof_bytes>(message.oneof_field)));
}

// -------------------------------------------------------------------

inline void TestUtil::ExpectClear(const protobuf_unittest::TestAllTypes &message) {
  //.blah.has_value() should initially be false for all optional fields.
  ut::expect(!message.optional_int32.has_value());
  ut::expect(!message.optional_int64.has_value());
  ut::expect(!message.optional_uint32.has_value());
  ut::expect(!message.optional_uint64.has_value());
  ut::expect(!message.optional_sint32.has_value());
  ut::expect(!message.optional_sint64.has_value());
  ut::expect(!message.optional_fixed32.has_value());
  ut::expect(!message.optional_fixed64.has_value());
  ut::expect(!message.optional_sfixed32.has_value());
  ut::expect(!message.optional_sfixed64.has_value());
  ut::expect(!message.optional_float.has_value());
  ut::expect(!message.optional_double.has_value());
  ut::expect(!message.optional_bool.has_value());
  ut::expect(!message.optional_string.has_value());
  ut::expect(!message.optional_bytes.has_value());

  ut::expect(!message.optional_nested_message.has_value());
  ut::expect(!message.optional_foreign_message.has_value());
  ut::expect(!message.optional_import_message.has_value());
  ut::expect(!message.optional_public_import_message.has_value());
  ut::expect(!message.optional_lazy_message.has_value());
  ut::expect(!message.optional_unverified_lazy_message.has_value());

  ut::expect(!message.optional_nested_enum.has_value());
  ut::expect(!message.optional_foreign_enum.has_value());
  ut::expect(!message.optional_import_enum.has_value());

  ut::expect(!message.optional_string_piece.has_value());
  ut::expect(!message.optional_cord.has_value());

  // Repeated fields are empty.
  ut::expect(ut::eq(0, message.repeated_int32.size()));
  ut::expect(ut::eq(0, message.repeated_int64.size()));
  ut::expect(ut::eq(0, message.repeated_uint32.size()));
  ut::expect(ut::eq(0, message.repeated_uint64.size()));
  ut::expect(ut::eq(0, message.repeated_sint32.size()));
  ut::expect(ut::eq(0, message.repeated_sint64.size()));
  ut::expect(ut::eq(0, message.repeated_fixed32.size()));
  ut::expect(ut::eq(0, message.repeated_fixed64.size()));
  ut::expect(ut::eq(0, message.repeated_sfixed32.size()));
  ut::expect(ut::eq(0, message.repeated_sfixed64.size()));
  ut::expect(ut::eq(0, message.repeated_float.size()));
  ut::expect(ut::eq(0, message.repeated_double.size()));
  ut::expect(ut::eq(0, message.repeated_bool.size()));
  ut::expect(ut::eq(0, message.repeated_string.size()));
  ut::expect(ut::eq(0, message.repeated_bytes.size()));

  ut::expect(ut::eq(0, message.repeated_nested_message.size()));
  ut::expect(ut::eq(0, message.repeated_foreign_message.size()));
  ut::expect(ut::eq(0, message.repeated_import_message.size()));
  ut::expect(ut::eq(0, message.repeated_lazy_message.size()));
  ut::expect(ut::eq(0, message.repeated_nested_enum.size()));
  ut::expect(ut::eq(0, message.repeated_foreign_enum.size()));
  ut::expect(ut::eq(0, message.repeated_import_enum.size()));

  ut::expect(ut::eq(0, message.repeated_string_piece.size()));
  ut::expect(ut::eq(0, message.repeated_cord.size()));

  //.blah.has_value() should also be false for all default fields.
  ut::expect(!message.default_int32.has_value());
  ut::expect(!message.default_int64.has_value());
  ut::expect(!message.default_uint32.has_value());
  ut::expect(!message.default_uint64.has_value());
  ut::expect(!message.default_sint32.has_value());
  ut::expect(!message.default_sint64.has_value());
  ut::expect(!message.default_fixed32.has_value());
  ut::expect(!message.default_fixed64.has_value());
  ut::expect(!message.default_sfixed32.has_value());
  ut::expect(!message.default_sfixed64.has_value());
  ut::expect(!message.default_float.has_value());
  ut::expect(!message.default_double.has_value());
  ut::expect(!message.default_bool.has_value());
  ut::expect(!message.default_string.has_value());
  ut::expect(!message.default_bytes.has_value());

  ut::expect(!message.default_nested_enum.has_value());
  ut::expect(!message.default_foreign_enum.has_value());
  ut::expect(!message.default_import_enum.has_value());

  // Fields with defaults have their default values (duh).
  ut::expect(ut::eq(41, message.default_int32.value_or_default()));
  ut::expect(ut::eq(42, message.default_int64.value_or_default()));
  ut::expect(ut::eq(43, message.default_uint32.value_or_default()));
  ut::expect(ut::eq(44, message.default_uint64.value_or_default()));
  ut::expect(ut::eq(-45, message.default_sint32.value_or_default()));
  ut::expect(ut::eq(46, message.default_sint64.value_or_default()));
  ut::expect(ut::eq(47, message.default_fixed32.value_or_default()));
  ut::expect(ut::eq(48, message.default_fixed64.value_or_default()));
  ut::expect(ut::eq(49, message.default_sfixed32.value_or_default()));
  ut::expect(ut::eq(-50, message.default_sfixed64.value_or_default()));
  ut::expect(ut::eq(51.5, message.default_float.value_or_default()));
  ut::expect(ut::eq(52e3, message.default_double.value_or_default()));
  ut::expect(message.default_bool.value_or_default());
  ut::expect(ut::eq("hello"s, message.default_string.value_or_default()));
  ut::expect(ut::eq("world"_bytes, message.default_bytes.value_or_default()));

  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::BAR == message.default_nested_enum.value_or_default());
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == message.default_foreign_enum.value_or_default());
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_BAR == message.default_import_enum.value_or_default());

  ut::expect(std::holds_alternative<std::monostate>(message.oneof_field));
}

// -------------------------------------------------------------------

inline void TestUtil::ExpectRepeatedFieldsModified(const protobuf_unittest::TestAllTypes &message) {
  using namespace boost::ut;
  // ModifyRepeatedFields only sets the second repeated element of each
  // field.  In addition to verifying this, we also verify that the first
  // element and size were *not* modified.
  ut::expect(ut::eq(2, message.repeated_int32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_int64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_uint32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_uint64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_sint32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_sint64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_fixed32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_fixed64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_sfixed32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_sfixed64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_float.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_double.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_bool.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_string.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_bytes.size()) >> ut::fatal);

  ut::expect(ut::eq(2, message.repeated_nested_message.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_foreign_message.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_import_message.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_lazy_message.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_nested_enum.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_foreign_enum.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.repeated_import_enum.size()) >> ut::fatal);

  ut::expect(ut::eq(201, message.repeated_int32[0]));
  ut::expect(ut::eq(202, message.repeated_int64[0]));
  ut::expect(ut::eq(203, message.repeated_uint32[0]));
  ut::expect(ut::eq(204, message.repeated_uint64[0]));
  ut::expect(ut::eq(205, message.repeated_sint32[0]));
  ut::expect(ut::eq(206, message.repeated_sint64[0]));
  ut::expect(ut::eq(207, message.repeated_fixed32[0]));
  ut::expect(ut::eq(208, message.repeated_fixed64[0]));
  ut::expect(ut::eq(209, message.repeated_sfixed32[0]));
  ut::expect(ut::eq(210, message.repeated_sfixed64[0]));
  ut::expect(ut::eq(211, message.repeated_float[0]));
  ut::expect(ut::eq(212, message.repeated_double[0]));
  ut::expect(message.repeated_bool[0]);
  ut::expect(ut::eq("215"s, message.repeated_string[0]));
  ut::expect(ut::eq("216"_bytes, message.repeated_bytes[0]));

  ut::expect(ut::eq(218, message.repeated_nested_message[0].bb.value()));
  ut::expect(ut::eq(219, message.repeated_foreign_message[0].c.value()));
  ut::expect(ut::eq(220, message.repeated_import_message[0].d.value()));
  ut::expect(ut::eq(227, message.repeated_lazy_message[0].bb.value()));

  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::BAR == message.repeated_nested_enum[0]);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == message.repeated_foreign_enum[0]);
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_BAR == message.repeated_import_enum[0]);

  // Actually verify the second (modified) elements now.
  ut::expect(ut::eq(501, message.repeated_int32[1]));
  ut::expect(ut::eq(502, message.repeated_int64[1]));
  ut::expect(ut::eq(503, message.repeated_uint32[1]));
  ut::expect(ut::eq(504, message.repeated_uint64[1]));
  ut::expect(ut::eq(505, message.repeated_sint32[1]));
  ut::expect(ut::eq(506, message.repeated_sint64[1]));
  ut::expect(ut::eq(507, message.repeated_fixed32[1]));
  ut::expect(ut::eq(508, message.repeated_fixed64[1]));
  ut::expect(ut::eq(509, message.repeated_sfixed32[1]));
  ut::expect(ut::eq(510, message.repeated_sfixed64[1]));
  ut::expect(ut::eq(511, message.repeated_float[1]));
  ut::expect(ut::eq(512, message.repeated_double[1]));
  ut::expect(message.repeated_bool[1]);
  ut::expect(ut::eq("515"s, message.repeated_string[1]));
  ut::expect(ut::eq("516"_bytes, message.repeated_bytes[1]));

  ut::expect(ut::eq(518, message.repeated_nested_message[1].bb.value()));
  ut::expect(ut::eq(519, message.repeated_foreign_message[1].c.value()));
  ut::expect(ut::eq(520, message.repeated_import_message[1].d.value()));
  ut::expect(ut::eq(527, message.repeated_lazy_message[1].bb.value()));

  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::FOO == message.repeated_nested_enum[1]);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO == message.repeated_foreign_enum[1]);
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO == message.repeated_import_enum[1]);
}

// -------------------------------------------------------------------

inline void TestUtil::SetPackedFields(protobuf_unittest::TestPackedTypes *message) {
  message->packed_int32.push_back(601);
  message->packed_int64.push_back(602);
  message->packed_uint32.push_back(603);
  message->packed_uint64.push_back(604);
  message->packed_sint32.push_back(605);
  message->packed_sint64.push_back(606);
  message->packed_fixed32.push_back(607);
  message->packed_fixed64.push_back(608);
  message->packed_sfixed32.push_back(609);
  message->packed_sfixed64.push_back(610);
  message->packed_float.push_back(611);
  message->packed_double.push_back(612);
  message->packed_bool.push_back(true);
  message->packed_enum.push_back(protobuf_unittest::ForeignEnum::FOREIGN_BAR);
  // add a second one of each field
  message->packed_int32.push_back(701);
  message->packed_int64.push_back(702);
  message->packed_uint32.push_back(703);
  message->packed_uint64.push_back(704);
  message->packed_sint32.push_back(705);
  message->packed_sint64.push_back(706);
  message->packed_fixed32.push_back(707);
  message->packed_fixed64.push_back(708);
  message->packed_sfixed32.push_back(709);
  message->packed_sfixed64.push_back(710);
  message->packed_float.push_back(711);
  message->packed_double.push_back(712);
  message->packed_bool.push_back(false);
  message->packed_enum.push_back(protobuf_unittest::ForeignEnum::FOREIGN_BAZ);
}

inline void TestUtil::SetUnpackedFields(protobuf_unittest::TestUnpackedTypes *message) {
  // The values applied here must match those of SetPackedFields.

  message->unpacked_int32.push_back(601);
  message->unpacked_int64.push_back(602);
  message->unpacked_uint32.push_back(603);
  message->unpacked_uint64.push_back(604);
  message->unpacked_sint32.push_back(605);
  message->unpacked_sint64.push_back(606);
  message->unpacked_fixed32.push_back(607);
  message->unpacked_fixed64.push_back(608);
  message->unpacked_sfixed32.push_back(609);
  message->unpacked_sfixed64.push_back(610);
  message->unpacked_float.push_back(611);
  message->unpacked_double.push_back(612);
  message->unpacked_bool.push_back(true);
  message->unpacked_enum.push_back(protobuf_unittest::ForeignEnum::FOREIGN_BAR);
  // add a second one of each field
  message->unpacked_int32.push_back(701);
  message->unpacked_int64.push_back(702);
  message->unpacked_uint32.push_back(703);
  message->unpacked_uint64.push_back(704);
  message->unpacked_sint32.push_back(705);
  message->unpacked_sint64.push_back(706);
  message->unpacked_fixed32.push_back(707);
  message->unpacked_fixed64.push_back(708);
  message->unpacked_sfixed32.push_back(709);
  message->unpacked_sfixed64.push_back(710);
  message->unpacked_float.push_back(711);
  message->unpacked_double.push_back(712);
  message->unpacked_bool.push_back(false);
  message->unpacked_enum.push_back(protobuf_unittest::ForeignEnum::FOREIGN_BAZ);
}

// -------------------------------------------------------------------

inline void TestUtil::ExpectPackedFieldsSet(const protobuf_unittest::TestPackedTypes &message) {
  ut::expect(ut::eq(2, message.packed_int32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_int64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_uint32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_uint64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_sint32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_sint64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_fixed32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_fixed64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_sfixed32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_sfixed64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_float.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_double.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_bool.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.packed_enum.size()) >> ut::fatal);

  ut::expect(ut::eq(601, message.packed_int32[0]));
  ut::expect(ut::eq(602, message.packed_int64[0]));
  ut::expect(ut::eq(603, message.packed_uint32[0]));
  ut::expect(ut::eq(604, message.packed_uint64[0]));
  ut::expect(ut::eq(605, message.packed_sint32[0]));
  ut::expect(ut::eq(606, message.packed_sint64[0]));
  ut::expect(ut::eq(607, message.packed_fixed32[0]));
  ut::expect(ut::eq(608, message.packed_fixed64[0]));
  ut::expect(ut::eq(609, message.packed_sfixed32[0]));
  ut::expect(ut::eq(610, message.packed_sfixed64[0]));
  ut::expect(ut::eq(611, message.packed_float[0]));
  ut::expect(ut::eq(612, message.packed_double[0]));
  ut::expect(message.packed_bool[0]);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == message.packed_enum[0]);

  ut::expect(ut::eq(701, message.packed_int32[1]));
  ut::expect(ut::eq(702, message.packed_int64[1]));
  ut::expect(ut::eq(703, message.packed_uint32[1]));
  ut::expect(ut::eq(704, message.packed_uint64[1]));
  ut::expect(ut::eq(705, message.packed_sint32[1]));
  ut::expect(ut::eq(706, message.packed_sint64[1]));
  ut::expect(ut::eq(707, message.packed_fixed32[1]));
  ut::expect(ut::eq(708, message.packed_fixed64[1]));
  ut::expect(ut::eq(709, message.packed_sfixed32[1]));
  ut::expect(ut::eq(710, message.packed_sfixed64[1]));
  ut::expect(ut::eq(711, message.packed_float[1]));
  ut::expect(ut::eq(712, message.packed_double[1]));
  ut::expect(!message.packed_bool[1]);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == message.packed_enum[1]);
}

inline void TestUtil::ExpectUnpackedFieldsSet(const protobuf_unittest::TestUnpackedTypes &message) {
  // The values expected here must match those of ExpectPackedFieldsSet.

  ut::expect(ut::eq(2, message.unpacked_int32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_int64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_uint32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_uint64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_sint32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_sint64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_fixed32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_fixed64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_sfixed32.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_sfixed64.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_float.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_double.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_bool.size()) >> ut::fatal);
  ut::expect(ut::eq(2, message.unpacked_enum.size()) >> ut::fatal);

  ut::expect(ut::eq(601, message.unpacked_int32[0]));
  ut::expect(ut::eq(602, message.unpacked_int64[0]));
  ut::expect(ut::eq(603, message.unpacked_uint32[0]));
  ut::expect(ut::eq(604, message.unpacked_uint64[0]));
  ut::expect(ut::eq(605, message.unpacked_sint32[0]));
  ut::expect(ut::eq(606, message.unpacked_sint64[0]));
  ut::expect(ut::eq(607, message.unpacked_fixed32[0]));
  ut::expect(ut::eq(608, message.unpacked_fixed64[0]));
  ut::expect(ut::eq(609, message.unpacked_sfixed32[0]));
  ut::expect(ut::eq(610, message.unpacked_sfixed64[0]));
  ut::expect(ut::eq(611, message.unpacked_float[0]));
  ut::expect(ut::eq(612, message.unpacked_double[0]));
  ut::expect(message.unpacked_bool[0]);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == message.unpacked_enum[0]);

  ut::expect(ut::eq(701, message.unpacked_int32[1]));
  ut::expect(ut::eq(702, message.unpacked_int64[1]));
  ut::expect(ut::eq(703, message.unpacked_uint32[1]));
  ut::expect(ut::eq(704, message.unpacked_uint64[1]));
  ut::expect(ut::eq(705, message.unpacked_sint32[1]));
  ut::expect(ut::eq(706, message.unpacked_sint64[1]));
  ut::expect(ut::eq(707, message.unpacked_fixed32[1]));
  ut::expect(ut::eq(708, message.unpacked_fixed64[1]));
  ut::expect(ut::eq(709, message.unpacked_sfixed32[1]));
  ut::expect(ut::eq(710, message.unpacked_sfixed64[1]));
  ut::expect(ut::eq(711, message.unpacked_float[1]));
  ut::expect(ut::eq(712, message.unpacked_double[1]));
  ut::expect(!message.unpacked_bool[1]);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == message.unpacked_enum[1]);
}

// ===================================================================
// Extensions
//
// All this code is exactly equivalent to the above code except that it's
// manipulating extension fields instead of normal ones.

inline void TestUtil::SetAllExtensions(protobuf_unittest::TestAllExtensions *message) {
  message->set_extension(protobuf_unittest::optional_int32_extension(), 101);
  message->set_extension(protobuf_unittest::optional_int64_extension(), 102);
  message->set_extension(protobuf_unittest::optional_uint32_extension(), 103);
  message->set_extension(protobuf_unittest::optional_uint64_extension(), 104);
  message->set_extension(protobuf_unittest::optional_sint32_extension(), 105);
  message->set_extension(protobuf_unittest::optional_sint64_extension(), 106);
  message->set_extension(protobuf_unittest::optional_fixed32_extension(), 107);
  message->set_extension(protobuf_unittest::optional_fixed64_extension(), 108);
  message->set_extension(protobuf_unittest::optional_sfixed32_extension(), 109);
  message->set_extension(protobuf_unittest::optional_sfixed64_extension(), 110);
  message->set_extension(protobuf_unittest::optional_float_extension(), 111);
  message->set_extension(protobuf_unittest::optional_double_extension(), 112);
  message->set_extension(protobuf_unittest::optional_bool_extension(), true);
  message->set_extension(protobuf_unittest::optional_string_extension(), "115");
  message->set_extension(protobuf_unittest::optional_bytes_extension(), "116"_bytes);

  message->set_extension(protobuf_unittest::optional_nested_message_extension(), {.bb = 118});
  message->set_extension(protobuf_unittest::optional_foreign_message_extension(), {.c = 119});
  message->set_extension(protobuf_unittest::optional_import_message_extension(), {.d = 120});

  message->set_extension(protobuf_unittest::optional_nested_enum_extension(),
                         protobuf_unittest::TestAllTypes::NestedEnum::BAZ);
  message->set_extension(protobuf_unittest::optional_foreign_enum_extension(),
                         protobuf_unittest::ForeignEnum::FOREIGN_BAZ);
  message->set_extension(protobuf_unittest::optional_import_enum_extension(),
                         protobuf_unittest_import::ImportEnum::IMPORT_BAZ);

  message->set_extension(protobuf_unittest::optional_string_piece_extension(), "124");
  message->set_extension(protobuf_unittest::optional_cord_extension(), "125");

  message->set_extension(protobuf_unittest::optional_public_import_message_extension(), {.e = 126});
  message->set_extension(protobuf_unittest::optional_lazy_message_extension(), {.bb = 127});
  message->set_extension(protobuf_unittest::optional_unverified_lazy_message_extension(), {.bb = 128});

  // -----------------------------------------------------------------

  message->set_extension(protobuf_unittest::repeated_int32_extension(), {201, 301});
  message->set_extension(protobuf_unittest::repeated_int64_extension(), {202, 302});
  message->set_extension(protobuf_unittest::repeated_uint32_extension(), {203, 303});
  message->set_extension(protobuf_unittest::repeated_uint64_extension(), {204, 304});
  message->set_extension(protobuf_unittest::repeated_sint32_extension(), {205, 305});
  message->set_extension(protobuf_unittest::repeated_sint64_extension(), {206, 306});
  message->set_extension(protobuf_unittest::repeated_fixed32_extension(), {207, 307});
  message->set_extension(protobuf_unittest::repeated_fixed64_extension(), {208, 308});
  message->set_extension(protobuf_unittest::repeated_sfixed32_extension(), {209, 309});
  message->set_extension(protobuf_unittest::repeated_sfixed64_extension(), {210, 310});
  message->set_extension(protobuf_unittest::repeated_float_extension(), {211, 311});
  message->set_extension(protobuf_unittest::repeated_double_extension(), {212, 312});
  message->set_extension(protobuf_unittest::repeated_bool_extension(), {true, false});
  message->set_extension(protobuf_unittest::repeated_string_extension(), {"215", "315"});
  message->set_extension(protobuf_unittest::repeated_bytes_extension(), {"216"_bytes, "316"_bytes});

  message->set_extension(protobuf_unittest::repeated_nested_message_extension(), {{.bb = 218}, {.bb = 318}});
  message->set_extension(protobuf_unittest::repeated_foreign_message_extension(), {{.c = 219}, {.c = 319}});
  message->set_extension(protobuf_unittest::repeated_import_message_extension(), {{.d = 220}, {.d = 320}});
  message->set_extension(protobuf_unittest::repeated_lazy_message_extension(), {{.bb = 227}, {.bb = 327}});

  message->set_extension(
      protobuf_unittest::repeated_nested_enum_extension(),
      {protobuf_unittest::TestAllTypes::NestedEnum::BAR, protobuf_unittest::TestAllTypes::NestedEnum::BAZ});
  message->set_extension(protobuf_unittest::repeated_foreign_enum_extension(),
                         {protobuf_unittest::ForeignEnum::FOREIGN_BAR, protobuf_unittest::ForeignEnum::FOREIGN_BAZ});
  message->set_extension(
      protobuf_unittest::repeated_import_enum_extension(),
      {protobuf_unittest_import::ImportEnum::IMPORT_BAR, protobuf_unittest_import::ImportEnum::IMPORT_BAZ});

  message->set_extension(protobuf_unittest::repeated_string_piece_extension(), {"224", "324"});
  message->set_extension(protobuf_unittest::repeated_cord_extension(), {"225", "325"});

  // -----------------------------------------------------------------

  message->set_extension(protobuf_unittest::default_int32_extension(), 401);
  message->set_extension(protobuf_unittest::default_int64_extension(), 402);
  message->set_extension(protobuf_unittest::default_uint32_extension(), 403);
  message->set_extension(protobuf_unittest::default_uint64_extension(), 404);
  message->set_extension(protobuf_unittest::default_sint32_extension(), 405);
  message->set_extension(protobuf_unittest::default_sint64_extension(), 406);
  message->set_extension(protobuf_unittest::default_fixed32_extension(), 407);
  message->set_extension(protobuf_unittest::default_fixed64_extension(), 408);
  message->set_extension(protobuf_unittest::default_sfixed32_extension(), 409);
  message->set_extension(protobuf_unittest::default_sfixed64_extension(), 410);
  message->set_extension(protobuf_unittest::default_float_extension(), 411);
  message->set_extension(protobuf_unittest::default_double_extension(), 412);
  message->set_extension(protobuf_unittest::default_bool_extension(), false);
  message->set_extension(protobuf_unittest::default_string_extension(), "415");
  message->set_extension(protobuf_unittest::default_bytes_extension(), "416"_bytes);

  message->set_extension(protobuf_unittest::default_nested_enum_extension(),
                         protobuf_unittest::TestAllTypes::NestedEnum::FOO);
  message->set_extension(protobuf_unittest::default_foreign_enum_extension(),
                         protobuf_unittest::ForeignEnum::FOREIGN_FOO);
  message->set_extension(protobuf_unittest::default_import_enum_extension(),
                         protobuf_unittest_import::ImportEnum::IMPORT_FOO);

  message->set_extension(protobuf_unittest::default_string_piece_extension(), "424");
  message->set_extension(protobuf_unittest::default_cord_extension(), "425");

  SetOneofFields(message);
}

inline void TestUtil::SetOneofFields(protobuf_unittest::TestAllExtensions *message) {
  message->set_extension(protobuf_unittest::oneof_uint32_extension(), 601);
  message->set_extension(protobuf_unittest::oneof_nested_message_extension(), {.bb = 602});
  message->set_extension(protobuf_unittest::oneof_string_extension(), "603");
  message->set_extension(protobuf_unittest::oneof_bytes_extension(), "604"_bytes);
}

// -------------------------------------------------------------------

inline void TestUtil::SetAllFieldsAndExtensions(protobuf_unittest::TestFieldOrderings *message) {
  // ABSL_CHECK(message);
  message->my_int = 1;
  message->my_string = "foo";
  message->my_float = 1.0;
  message->set_extension(protobuf_unittest::my_extension_int(), 23);
  message->set_extension(protobuf_unittest::my_extension_string(), "bar");
}
// -------------------------------------------------------------------

inline void TestUtil::ExpectAllExtensionsSet(const protobuf_unittest::TestAllExtensions &message) {
  ut::expect(message.has_extension(protobuf_unittest::optional_int32_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_int64_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_uint32_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_uint64_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_sint32_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_sint64_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_fixed32_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_fixed64_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_sfixed32_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_sfixed64_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_float_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_double_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_bool_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_string_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_bytes_extension()));

  ut::expect(message.has_extension(protobuf_unittest::optional_nested_message_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_foreign_message_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_import_message_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_public_import_message_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_lazy_message_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_unverified_lazy_message_extension()));

  ut::expect(message.get_extension(protobuf_unittest::optional_nested_message_extension())->bb.has_value());
  ut::expect(message.get_extension(protobuf_unittest::optional_foreign_message_extension())->c.has_value());
  ut::expect(message.get_extension(protobuf_unittest::optional_import_message_extension())->d.has_value());
  ut::expect(message.get_extension(protobuf_unittest::optional_public_import_message_extension())->e.has_value());
  ut::expect(message.get_extension(protobuf_unittest::optional_lazy_message_extension())->bb.has_value());
  ut::expect(message.get_extension(protobuf_unittest::optional_unverified_lazy_message_extension())->bb.has_value());

  ut::expect(message.has_extension(protobuf_unittest::optional_nested_enum_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_foreign_enum_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_import_enum_extension()));

  ut::expect(message.has_extension(protobuf_unittest::optional_string_piece_extension()));
  ut::expect(message.has_extension(protobuf_unittest::optional_cord_extension()));

  ut::expect(ut::eq(101, message.get_extension(protobuf_unittest::optional_int32_extension()).value()));
  ut::expect(ut::eq(102, message.get_extension(protobuf_unittest::optional_int64_extension()).value()));
  ut::expect(ut::eq(103, message.get_extension(protobuf_unittest::optional_uint32_extension()).value()));
  ut::expect(ut::eq(104, message.get_extension(protobuf_unittest::optional_uint64_extension()).value()));
  ut::expect(ut::eq(105, message.get_extension(protobuf_unittest::optional_sint32_extension()).value()));
  ut::expect(ut::eq(106, message.get_extension(protobuf_unittest::optional_sint64_extension()).value()));
  ut::expect(ut::eq(107, message.get_extension(protobuf_unittest::optional_fixed32_extension()).value()));
  ut::expect(ut::eq(108, message.get_extension(protobuf_unittest::optional_fixed64_extension()).value()));
  ut::expect(ut::eq(109, message.get_extension(protobuf_unittest::optional_sfixed32_extension()).value()));
  ut::expect(ut::eq(110, message.get_extension(protobuf_unittest::optional_sfixed64_extension()).value()));
  ut::expect(ut::eq(111, message.get_extension(protobuf_unittest::optional_float_extension()).value()));
  ut::expect(ut::eq(112, message.get_extension(protobuf_unittest::optional_double_extension()).value()));
  ut::expect(message.get_extension(protobuf_unittest::optional_bool_extension()).value());
  ut::expect(ut::eq("115"s, message.get_extension(protobuf_unittest::optional_string_extension()).value()));
  ut::expect(ut::eq("116"_bytes, message.get_extension(protobuf_unittest::optional_bytes_extension()).value()));

  ut::expect(ut::eq(118, message.get_extension(protobuf_unittest::optional_nested_message_extension())->bb.value()));
  ut::expect(ut::eq(119, message.get_extension(protobuf_unittest::optional_foreign_message_extension())->c.value()));
  ut::expect(ut::eq(120, message.get_extension(protobuf_unittest::optional_import_message_extension())->d.value()));

  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::BAZ ==
             message.get_extension(protobuf_unittest::optional_nested_enum_extension()).value());
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ ==
             message.get_extension(protobuf_unittest::optional_foreign_enum_extension()).value());
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_BAZ ==
             message.get_extension(protobuf_unittest::optional_import_enum_extension()).value());

  ut::expect(ut::eq("124"s, message.get_extension(protobuf_unittest::optional_string_piece_extension()).value()));
  ut::expect(ut::eq("125"s, message.get_extension(protobuf_unittest::optional_cord_extension()).value()));
  ut::expect(
      ut::eq(126, message.get_extension(protobuf_unittest::optional_public_import_message_extension())->e.value()));
  ut::expect(ut::eq(127, message.get_extension(protobuf_unittest::optional_lazy_message_extension())->bb.value()));
  ut::expect(
      ut::eq(128, message.get_extension(protobuf_unittest::optional_unverified_lazy_message_extension())->bb.value()));

  // -----------------------------------------------------------------

  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::repeated_int32_extension()), std::vector<int32_t>{201, 301}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::repeated_int64_extension()), std::vector<int64_t>{202, 302}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::repeated_uint32_extension()), std::vector<uint32_t>{203, 303}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::repeated_uint64_extension()), std::vector<uint64_t>{204, 304}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::repeated_sint32_extension()), std::vector<int32_t>{205, 305}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::repeated_sint64_extension()), std::vector<int64_t>{206, 306}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::repeated_fixed32_extension()), std::vector<uint32_t>{207, 307}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::repeated_fixed64_extension()), std::vector<uint64_t>{208, 308}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::repeated_sfixed32_extension()), std::vector<int32_t>{209, 309}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::repeated_sfixed64_extension()), std::vector<int64_t>{210, 310}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::repeated_float_extension()), std::vector<float>{211, 311}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::repeated_double_extension()), std::vector<double>{212, 312}));
  ut::expect(ut::eq(message.get_extension(protobuf_unittest::repeated_bool_extension()),
                    std::vector<unsigned char>{true, false}));
  ut::expect(ut::eq(message.get_extension(protobuf_unittest::repeated_string_extension()),
                    std::vector<std::string>{"215", "315"}));
  ut::expect(ut::eq(message.get_extension(protobuf_unittest::repeated_bytes_extension()),
                    std::vector{"216"_bytes, "316"_bytes}));

  auto repeated_nested_message_extension =
      message.get_extension(protobuf_unittest::repeated_nested_message_extension());
  ut::expect(ut::eq(2, repeated_nested_message_extension.size()) >> ut::fatal);
  ut::expect(protobuf_unittest::TestAllTypes::NestedMessage{.bb = 218} == repeated_nested_message_extension[0]);
  ut::expect(protobuf_unittest::TestAllTypes::NestedMessage{.bb = 318} == repeated_nested_message_extension[1]);

  auto repeated_foreign_message_extension =
      message.get_extension(protobuf_unittest::repeated_foreign_message_extension());
  ut::expect(ut::eq(2, repeated_foreign_message_extension.size()) >> ut::fatal);
  ut::expect(protobuf_unittest::ForeignMessage{.c = 219} == repeated_foreign_message_extension[0]);
  ut::expect(protobuf_unittest::ForeignMessage{.c = 319} == repeated_foreign_message_extension[1]);

  auto repeated_import_message_extension =
      message.get_extension(protobuf_unittest::repeated_import_message_extension());
  ut::expect(ut::eq(2, repeated_import_message_extension.size()) >> ut::fatal);
  ut::expect(protobuf_unittest_import::ImportMessage{.d = 220} == repeated_import_message_extension[0]);
  ut::expect(protobuf_unittest_import::ImportMessage{.d = 320} == repeated_import_message_extension[1]);

  auto repeated_lazy_message_extension = message.get_extension(protobuf_unittest::repeated_lazy_message_extension());
  ut::expect(ut::eq(2, repeated_lazy_message_extension.size()) >> ut::fatal);
  ut::expect(protobuf_unittest::TestAllTypes::NestedMessage{.bb = 227} == repeated_lazy_message_extension[0]);
  ut::expect(protobuf_unittest::TestAllTypes::NestedMessage{.bb = 327} == repeated_lazy_message_extension[1]);

  auto repeated_nested_enum_extension = message.get_extension(protobuf_unittest::repeated_nested_enum_extension());
  ut::expect(ut::eq(2, repeated_nested_enum_extension.size()) >> ut::fatal);
  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::BAR == repeated_nested_enum_extension[0]);
  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::BAZ == repeated_nested_enum_extension[1]);

  auto repeated_foreign_enum_extension = message.get_extension(protobuf_unittest::repeated_foreign_enum_extension());
  ut::expect(ut::eq(2, repeated_foreign_enum_extension.size()) >> ut::fatal);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == repeated_foreign_enum_extension[0]);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == repeated_foreign_enum_extension[1]);

  auto repeated_import_enum_extension = message.get_extension(protobuf_unittest::repeated_import_enum_extension());
  ut::expect(ut::eq(2, repeated_import_enum_extension.size()) >> ut::fatal);
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_BAR == repeated_import_enum_extension[0]);
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_BAZ == repeated_import_enum_extension[1]);

  ut::expect(ut::eq(message.get_extension(protobuf_unittest::repeated_string_piece_extension()),
                    std::vector<std::string>{"224", "324"}));
  ut::expect(ut::eq(message.get_extension(protobuf_unittest::repeated_cord_extension()),
                    std::vector<std::string>{"224", "325"}));

  // -----------------------------------------------------------------

  ut::expect(message.has_extension(protobuf_unittest::default_int32_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_int64_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_uint32_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_uint64_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_sint32_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_sint64_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_fixed32_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_fixed64_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_sfixed32_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_sfixed64_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_float_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_double_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_bool_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_string_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_bytes_extension()));

  ut::expect(message.has_extension(protobuf_unittest::default_nested_enum_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_foreign_enum_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_import_enum_extension()));

  ut::expect(message.has_extension(protobuf_unittest::default_string_piece_extension()));
  ut::expect(message.has_extension(protobuf_unittest::default_cord_extension()));

  ut::expect(ut::eq(401, message.get_extension(protobuf_unittest::default_int32_extension()).value_or_default()));
  ut::expect(ut::eq(402, message.get_extension(protobuf_unittest::default_int64_extension()).value_or_default()));
  ut::expect(ut::eq(403, message.get_extension(protobuf_unittest::default_uint32_extension()).value_or_default()));
  ut::expect(ut::eq(404, message.get_extension(protobuf_unittest::default_uint64_extension()).value_or_default()));
  ut::expect(ut::eq(405, message.get_extension(protobuf_unittest::default_sint32_extension()).value_or_default()));
  ut::expect(ut::eq(406, message.get_extension(protobuf_unittest::default_sint64_extension()).value_or_default()));
  ut::expect(ut::eq(407, message.get_extension(protobuf_unittest::default_fixed32_extension()).value_or_default()));
  ut::expect(ut::eq(408, message.get_extension(protobuf_unittest::default_fixed64_extension()).value_or_default()));
  ut::expect(ut::eq(409, message.get_extension(protobuf_unittest::default_sfixed32_extension()).value_or_default()));
  ut::expect(ut::eq(410, message.get_extension(protobuf_unittest::default_sfixed64_extension()).value_or_default()));
  ut::expect(ut::eq(411, message.get_extension(protobuf_unittest::default_float_extension()).value_or_default()));
  ut::expect(ut::eq(412, message.get_extension(protobuf_unittest::default_double_extension()).value_or_default()));
  ut::expect(!message.get_extension(protobuf_unittest::default_bool_extension()).value_or_default());
  ut::expect(ut::eq("415"s, message.get_extension(protobuf_unittest::default_string_extension()).value_or_default()));
  ut::expect(
      ut::eq("416"_bytes, message.get_extension(protobuf_unittest::default_bytes_extension()).value_or_default()));

  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::FOO ==
             message.get_extension(protobuf_unittest::default_nested_enum_extension()).value_or_default());
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO ==
             message.get_extension(protobuf_unittest::default_foreign_enum_extension()).value_or_default());
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO ==
             message.get_extension(protobuf_unittest::default_import_enum_extension()).value_or_default());

  ut::expect(
      ut::eq("424"s, message.get_extension(protobuf_unittest::default_string_piece_extension()).value_or_default()));
  ut::expect(ut::eq("425"s, message.get_extension(protobuf_unittest::default_cord_extension()).value_or_default()));

  ut::expect(message.has_extension(protobuf_unittest::oneof_uint32_extension()));
  ut::expect(message.get_extension(protobuf_unittest::oneof_nested_message_extension())->bb.has_value());
  ut::expect(message.has_extension(protobuf_unittest::oneof_string_extension()));
  ut::expect(message.has_extension(protobuf_unittest::oneof_bytes_extension()));

  ut::expect(ut::eq(601, message.get_extension(protobuf_unittest::oneof_uint32_extension()).value()));
  ut::expect(ut::eq(602, message.get_extension(protobuf_unittest::oneof_nested_message_extension())->bb.value()));
  ut::expect(ut::eq("603"s, message.get_extension(protobuf_unittest::oneof_string_extension()).value()));
  ut::expect(ut::eq("604"_bytes, message.get_extension(protobuf_unittest::oneof_bytes_extension()).value()));
}

// -------------------------------------------------------------------

inline void TestUtil::ExpectExtensionsClear(const protobuf_unittest::TestAllExtensions &message) {
  auto [data, out] = hpp::proto::data_out();
  ut::expect(success(out(message)));
  ut::expect(ut::eq(0, data.size()));

  //.blah.has_value() should initially be false for all optional fields.
  ut::expect(!message.has_extension(protobuf_unittest::optional_int32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_int64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_uint32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_uint64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_sint32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_sint64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_fixed32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_fixed64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_sfixed32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_sfixed64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_float_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_double_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_bool_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_string_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_bytes_extension()));

  ut::expect(!message.has_extension(protobuf_unittest::optional_nested_message_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_foreign_message_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_import_message_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_public_import_message_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_lazy_message_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_unverified_lazy_message_extension()));

  ut::expect(!message.has_extension(protobuf_unittest::optional_nested_enum_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_foreign_enum_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_import_enum_extension()));

  ut::expect(!message.has_extension(protobuf_unittest::optional_string_piece_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::optional_cord_extension()));

  // Optional fields without defaults are set to zero or something like it.
  ut::expect(!message.get_extension(protobuf_unittest::optional_int32_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_int64_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_uint32_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_uint64_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_sint32_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_sint64_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_fixed32_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_fixed64_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_sfixed32_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_sfixed64_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_float_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_double_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_bool_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_string_extension()).has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_bytes_extension()).has_value());

  // Embedded messages should also be clear.
  ut::expect(!message.get_extension(protobuf_unittest::optional_nested_message_extension())->bb.has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_foreign_message_extension())->c.has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_import_message_extension())->d.has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_public_import_message_extension())->e.has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_lazy_message_extension())->bb.has_value());
  ut::expect(!message.get_extension(protobuf_unittest::optional_unverified_lazy_message_extension())->bb.has_value());

  ut::expect(ut::eq(0, message.get_extension(protobuf_unittest::optional_nested_message_extension())->bb.value()));
  ut::expect(ut::eq(0, message.get_extension(protobuf_unittest::optional_foreign_message_extension())->c.value()));
  ut::expect(ut::eq(0, message.get_extension(protobuf_unittest::optional_import_message_extension())->d.value()));
  ut::expect(
      ut::eq(0, message.get_extension(protobuf_unittest::optional_public_import_message_extension())->e.value()));
  ut::expect(ut::eq(0, message.get_extension(protobuf_unittest::optional_lazy_message_extension())->bb.value()));
  ut::expect(
      ut::eq(0, message.get_extension(protobuf_unittest::optional_unverified_lazy_message_extension())->bb.value()));

  // Enums without defaults are set to the first value in the enum.
  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::FOO ==
             message.get_extension(protobuf_unittest::optional_nested_enum_extension()).value());
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO ==
             message.get_extension(protobuf_unittest::optional_foreign_enum_extension()).value());
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO ==
             message.get_extension(protobuf_unittest::optional_import_enum_extension()).value());

  ut::expect(ut::eq(""s, message.get_extension(protobuf_unittest::optional_string_piece_extension()).value()));
  ut::expect(ut::eq(""s, message.get_extension(protobuf_unittest::optional_cord_extension()).value()));

  // Repeated fields are empty.
  ut::expect(!message.has_extension(protobuf_unittest::repeated_int32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_int64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_uint32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_uint64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_sint32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_sint64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_fixed32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_fixed64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_sfixed32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_sfixed64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_float_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_double_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_bool_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_string_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_bytes_extension()));

  ut::expect(!message.has_extension(protobuf_unittest::repeated_nested_message_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_foreign_message_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_import_message_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_lazy_message_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_nested_enum_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_foreign_enum_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_import_enum_extension()));

  ut::expect(!message.has_extension(protobuf_unittest::repeated_string_piece_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::repeated_cord_extension()));

  //.blah.has_value() should also be false for all default fields.
  ut::expect(!message.has_extension(protobuf_unittest::default_int32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_int64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_uint32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_uint64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_sint32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_sint64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_fixed32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_fixed64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_sfixed32_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_sfixed64_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_float_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_double_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_bool_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_string_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_bytes_extension()));

  ut::expect(!message.has_extension(protobuf_unittest::default_nested_enum_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_foreign_enum_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_import_enum_extension()));

  ut::expect(!message.has_extension(protobuf_unittest::default_string_piece_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::default_cord_extension()));

  // Fields with defaults have their default values (duh).
  ut::expect(ut::eq(41, message.get_extension(protobuf_unittest::default_int32_extension()).value_or_default()));
  ut::expect(ut::eq(42, message.get_extension(protobuf_unittest::default_int64_extension()).value_or_default()));
  ut::expect(ut::eq(43, message.get_extension(protobuf_unittest::default_uint32_extension()).value_or_default()));
  ut::expect(ut::eq(44, message.get_extension(protobuf_unittest::default_uint64_extension()).value_or_default()));
  ut::expect(ut::eq(-45, message.get_extension(protobuf_unittest::default_sint32_extension()).value_or_default()));
  ut::expect(ut::eq(46, message.get_extension(protobuf_unittest::default_sint64_extension()).value_or_default()));
  ut::expect(ut::eq(47, message.get_extension(protobuf_unittest::default_fixed32_extension()).value_or_default()));
  ut::expect(ut::eq(48, message.get_extension(protobuf_unittest::default_fixed64_extension()).value_or_default()));
  ut::expect(ut::eq(49, message.get_extension(protobuf_unittest::default_sfixed32_extension()).value_or_default()));
  ut::expect(ut::eq(-50, message.get_extension(protobuf_unittest::default_sfixed64_extension()).value_or_default()));
  ut::expect(ut::eq(51.5, message.get_extension(protobuf_unittest::default_float_extension()).value_or_default()));
  ut::expect(ut::eq(52e3, message.get_extension(protobuf_unittest::default_double_extension()).value_or_default()));
  ut::expect(message.get_extension(protobuf_unittest::default_bool_extension()).value_or_default());
  ut::expect(ut::eq("hello"s, message.get_extension(protobuf_unittest::default_string_extension()).value_or_default()));
  ut::expect(
      ut::eq("world"_bytes, message.get_extension(protobuf_unittest::default_bytes_extension()).value_or_default()));

  ut::expect(protobuf_unittest::TestAllTypes::NestedEnum::BAR ==
             message.get_extension(protobuf_unittest::default_nested_enum_extension()).value_or_default());
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR ==
             message.get_extension(protobuf_unittest::default_foreign_enum_extension()).value_or_default());
  ut::expect(protobuf_unittest_import::ImportEnum::IMPORT_BAR ==
             message.get_extension(protobuf_unittest::default_import_enum_extension()).value_or_default());

  ut::expect(
      ut::eq("abc"s, message.get_extension(protobuf_unittest::default_string_piece_extension()).value_or_default()));
  ut::expect(ut::eq("123"s, message.get_extension(protobuf_unittest::default_cord_extension()).value_or_default()));

  ut::expect(!message.has_extension(protobuf_unittest::oneof_uint32_extension()));
  ut::expect(!message.get_extension(protobuf_unittest::oneof_nested_message_extension())->bb.has_value());
  ut::expect(!message.has_extension(protobuf_unittest::oneof_string_extension()));
  ut::expect(!message.has_extension(protobuf_unittest::oneof_bytes_extension()));
}
// -------------------------------------------------------------------

inline void TestUtil::SetPackedExtensions(protobuf_unittest::TestPackedExtensions *message) {
  message->set_extension(protobuf_unittest::packed_int32_extension(), {601, 701});
  message->set_extension(protobuf_unittest::packed_int64_extension(), {602, 702});
  message->set_extension(protobuf_unittest::packed_uint32_extension(), {603, 703});
  message->set_extension(protobuf_unittest::packed_uint64_extension(), {604, 704});
  message->set_extension(protobuf_unittest::packed_sint32_extension(), {605, 705});
  message->set_extension(protobuf_unittest::packed_sint64_extension(), {606, 706});
  message->set_extension(protobuf_unittest::packed_fixed32_extension(), {607, 707});
  message->set_extension(protobuf_unittest::packed_fixed64_extension(), {608, 708});
  message->set_extension(protobuf_unittest::packed_sfixed32_extension(), {609, 709});
  message->set_extension(protobuf_unittest::packed_sfixed64_extension(), {610, 710});
  message->set_extension(protobuf_unittest::packed_float_extension(), {611, 711});
  message->set_extension(protobuf_unittest::packed_double_extension(), {612, 712});
  message->set_extension(protobuf_unittest::packed_bool_extension(), {true, false});
  message->set_extension(protobuf_unittest::packed_enum_extension(),
                         {protobuf_unittest::ForeignEnum::FOREIGN_BAR, protobuf_unittest::ForeignEnum::FOREIGN_BAZ});
}

// -------------------------------------------------------------------

inline void TestUtil::ExpectPackedExtensionsSet(const protobuf_unittest::TestPackedExtensions &message) {

  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::packed_int32_extension()), std::vector<int32_t>{601, 701}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::packed_int64_extension()), std::vector<int64_t>{602, 702}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::packed_uint32_extension()), std::vector<uint32_t>{603, 703}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::packed_uint64_extension()), std::vector<uint64_t>{604, 704}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::packed_sint32_extension()), std::vector<int32_t>{605, 705}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::packed_sint64_extension()), std::vector<int64_t>{606, 706}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::packed_fixed32_extension()), std::vector<uint32_t>{607, 707}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::packed_fixed64_extension()), std::vector<uint64_t>{608, 708}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::packed_sfixed32_extension()), std::vector<int32_t>{609, 709}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::packed_sfixed64_extension()), std::vector<int64_t>{610, 710}));
  ut::expect(ut::eq(message.get_extension(protobuf_unittest::packed_float_extension()), std::vector<float>{611, 711}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::packed_double_extension()), std::vector<double>{612, 712}));
  ut::expect(ut::eq(message.get_extension(protobuf_unittest::packed_bool_extension()),
                    std::vector<unsigned char>{true, false}));

  auto packed_enum_extension = message.get_extension(protobuf_unittest::packed_enum_extension());
  ut::expect(ut::eq(2, packed_enum_extension.size()) >> ut::fatal);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == packed_enum_extension[0]);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == packed_enum_extension[1]);
}

// -------------------------------------------------------------------

inline void TestUtil::ExpectUnpackedExtensionsSet(const protobuf_unittest::TestUnpackedExtensions &message) {
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::unpacked_int32_extension()), std::vector<int32_t>{601, 701}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::unpacked_int64_extension()), std::vector<int64_t>{602, 702}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::unpacked_uint32_extension()), std::vector<uint32_t>{603, 703}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::unpacked_uint64_extension()), std::vector<uint64_t>{604, 704}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::unpacked_sint32_extension()), std::vector<int32_t>{605, 705}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::unpacked_sint64_extension()), std::vector<int64_t>{606, 706}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::unpacked_fixed32_extension()), std::vector<uint32_t>{607, 707}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::unpacked_fixed64_extension()), std::vector<uint64_t>{608, 708}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::unpacked_sfixed32_extension()), std::vector<int32_t>{609, 709}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::unpacked_sfixed64_extension()), std::vector<int64_t>{610, 710}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::unpacked_float_extension()), std::vector<float>{611, 711}));
  ut::expect(
      ut::eq(message.get_extension(protobuf_unittest::unpacked_double_extension()), std::vector<double>{612, 712}));
  ut::expect(ut::eq(message.get_extension(protobuf_unittest::unpacked_bool_extension()),
                    std::vector<unsigned char>{true, false}));

  auto unpacked_enum_extension = message.get_extension(protobuf_unittest::unpacked_enum_extension());
  ut::expect(ut::eq(2, unpacked_enum_extension.size()) >> ut::fatal);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == unpacked_enum_extension[0]);
  ut::expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == unpacked_enum_extension[1]);
}

inline void TestUtil::SetOneof1(protobuf_unittest::TestOneof2 *message) {
  message->foo.emplace<protobuf_unittest::TestOneof2::foo_lazy_message>().moo_int = 100;
  message->bar.emplace<protobuf_unittest::TestOneof2::bar_string>("101");
  message->baz_int = 102;
  message->baz_string = "103";
}

inline void TestUtil::SetOneof2(protobuf_unittest::TestOneof2 *message) {
  message->foo.emplace<protobuf_unittest::TestOneof2::foo_int>(200);
  message->bar.emplace<protobuf_unittest::TestOneof2::bar_enum>(protobuf_unittest::TestOneof2::NestedEnum::BAZ);
  message->baz_int = 202;
  message->baz_string = "203";
}

inline void TestUtil::ExpectOneofSet1(const protobuf_unittest::TestOneof2 &message) {

  ut::expect(ut::eq(protobuf_unittest::TestOneof2::foo_lazy_message, message.foo.index()) >> ut::fatal);
  auto &foo_lazy_message = std::get<protobuf_unittest::TestOneof2::foo_lazy_message>(message.foo);
  ut::expect(foo_lazy_message.moo_int.has_value());

  ut::expect(ut::eq(protobuf_unittest::TestOneof2::bar_string, message.bar.index()) >> ut::fatal);
  ut::expect(message.baz_int.has_value());
  ut::expect(message.baz_string.has_value());

  ut::expect(ut::eq(0, foo_lazy_message.corge_int.size()) >> ut::fatal);

  ut::expect(ut::eq(100, foo_lazy_message.moo_int.value()));
  ut::expect(ut::eq("101"s, std::get<protobuf_unittest::TestOneof2::bar_string>(message.bar)));
  ut::expect(ut::eq(102, message.baz_int.value()));
  ut::expect(ut::eq("103"s, message.baz_string.value()));
}

inline void TestUtil::ExpectOneofSet2(const protobuf_unittest::TestOneof2 &message) {

  ut::expect(ut::eq(protobuf_unittest::TestOneof2::foo_int, message.foo.index()));
  ut::expect(ut::eq(protobuf_unittest::TestOneof2::bar_enum, message.bar.index()));
  ut::expect(message.baz_int.has_value());
  ut::expect(message.baz_string.has_value());

  ut::expect(ut::eq(200, std::get<protobuf_unittest::TestOneof2::foo_int>(message.foo)));
  ut::expect(protobuf_unittest::TestOneof2::NestedEnum::BAZ ==
             std::get<protobuf_unittest::TestOneof2::bar_enum>(message.bar));
  ut::expect(ut::eq(202, message.baz_int.value()));
  ut::expect(ut::eq("203"s, message.baz_string.value()));
}

inline void TestUtil::ExpectOneofClear(const protobuf_unittest::TestOneof2 &message) {
  ut::expect(!message.baz_int.has_value());
  ut::expect(!message.baz_string.has_value());

  ut::expect(ut::eq(0, message.foo.index()));
  ut::expect(ut::eq(0, message.bar.index()));
}

std::string unittest_proto2_descriptorset() {
  std::ifstream in("unittest_proto2.bin", std::ios::in | std::ios::binary);
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(in.tellg());
  in.seekg(0, std::ios::beg);
  in.read(&contents[0], contents.size());
  return contents;
}

ut::suite proto_test = [] {
  using namespace boost::ut::literals;

  "test_lite1"_test = [] {
    protobuf_unittest::TestAllTypes message, message2, message3;

    TestUtil::ExpectClear(message);
    TestUtil::SetAllFields(&message);
    message2 = message;

    auto [data, in, out] = hpp::proto::data_in_out();
    ut::expect(success(out(message2)));
    ut::expect(success(in(message3)));

    TestUtil::ExpectAllFieldsSet(message);
    TestUtil::ExpectAllFieldsSet(message2);
    TestUtil::ExpectAllFieldsSet(message3);
  };

  "glaze"_test = [] {
    protobuf_unittest::TestAllTypes original;
    TestUtil::SetAllFields(&original);

    auto [data, in, out] = hpp::proto::data_in_out();
    using zpp::bits::success;

    ut::expect(success(out(original)));

    auto original_json = gpb_based::proto_to_json(unittest_proto2_descriptorset(), "protobuf_unittest.TestAllTypes",
                                       {(const char *)data.data(), data.size()});

    std::regex empty_array_re(R"(,"\w+":\[\])");

    auto glaze_generated_json = glz::write_json(original);
    auto glaze_generated_json_no_empty_array = std::regex_replace(glaze_generated_json, empty_array_re, "");

    ut::expect(ut::eq(glaze_generated_json_no_empty_array, original_json));

    protobuf_unittest::TestAllTypes msg;
    ut::expect(!glz::read_json(msg, original_json));

    TestUtil::ExpectAllFieldsSet(msg);
  };
};

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return result;
}