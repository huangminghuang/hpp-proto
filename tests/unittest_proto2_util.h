#pragma once
#include "test_util.h"
#include <boost/ut.hpp>
#include <google/protobuf/unittest.glz.hpp>
#include <google/protobuf/unittest.pb.hpp>

// NOLINTBEGIN(cert-dcl58-cpp)
namespace std {
template <typename T>
  requires requires { glz::meta<T>::value; }
std::ostream &operator<<(std::ostream &os, const T &v) {
  return os << hpp::proto::write_json(v).value();
}
} // namespace std
// NOLINTEND(cert-dcl58-cpp)

namespace TestUtil {
using namespace std::literals::string_literals;
using namespace boost::ut;

// Set every field in the message to a unique value.
inline void SetAll(protobuf_unittest::TestAllTypes *message);
inline void SetOptionalFields(protobuf_unittest::TestAllTypes *message);
inline void AddRepeatedFields1(protobuf_unittest::TestAllTypes *message);
inline void AddRepeatedFields2(protobuf_unittest::TestAllTypes *message);
inline void SetDefaultFields(protobuf_unittest::TestAllTypes *message);
inline void SetOneofFields(protobuf_unittest::TestAllTypes *message);
inline void SetAll(protobuf_unittest::TestAllExtensions *message);
inline void SetOneofFields(protobuf_unittest::TestAllExtensions *message);
inline void SetAllFieldsAndExtensions(protobuf_unittest::TestFieldOrderings *message);
inline void SetAll(protobuf_unittest::TestPackedTypes *message);
inline void SetAll(protobuf_unittest::TestPackedExtensions *message);
inline void SetAll(protobuf_unittest::TestUnpackedTypes *message);
inline void SetOneof1(protobuf_unittest::TestOneof2 *message);
inline void SetOneof2(protobuf_unittest::TestOneof2 *message);

// Use the repeated versions of the set_*() accessors to modify all the
// repeated fields of the message (which should already have been
// initialized with Set*Fields()).  Set*Fields() itself only tests
// the add_*() accessors.
inline void ModifyRepeatedFields(protobuf_unittest::TestAllTypes *message);

// Check that all fields have the values that they should have after
// Set*Fields() is called.
inline void ExpectAllSet(const protobuf_unittest::TestAllTypes &message);
inline void ExpectAllSet(const protobuf_unittest::TestAllExtensions &message);
inline void ExpectAllSet(const protobuf_unittest::TestPackedTypes &message);
inline void ExpectAllSet(const protobuf_unittest::TestPackedExtensions &message);
inline void ExpectAllSet(const protobuf_unittest::TestUnpackedTypes &message);
inline void ExpectAllSet(const protobuf_unittest::TestUnpackedExtensions &message);
inline void ExpectOneofSet1(const protobuf_unittest::TestOneof2 &message);
inline void ExpectOneofSet2(const protobuf_unittest::TestOneof2 &message);

// Expect that the message is modified as would be expected from
// Modify*Fields().
inline void ExpectRepeatedFieldsModified(const protobuf_unittest::TestAllTypes &message);

// Check that all fields have their default values.
inline void ExpectClear(const protobuf_unittest::TestAllTypes &message);
inline void ExpectClear(const protobuf_unittest::TestAllExtensions &message);
inline void ExpectOneofClear(const protobuf_unittest::TestOneof2 &message);

inline void SetAll(protobuf_unittest::TestAllTypes *message) {
  SetOptionalFields(message);
  AddRepeatedFields1(message);
  AddRepeatedFields2(message);
  SetDefaultFields(message);
  SetOneofFields(message);
}

inline void SetOptionalFields(protobuf_unittest::TestAllTypes *message) {
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
  message->optional_float = 111.0F;
  message->optional_double = 112;
  message->optional_bool = true;
  message->optional_string = "115";
  message->optional_bytes = "116"_bytes;

  message->optionalgroup = protobuf_unittest::TestAllTypes::OptionalGroup{.a = 117};
  message->optional_nested_message = protobuf_unittest::TestAllTypes::NestedMessage{.bb = 118};
  message->optional_foreign_message.emplace().c = 119;
  message->optional_import_message.emplace().d = 120;
  message->optional_public_import_message.emplace().e = 126;
  message->optional_lazy_message = protobuf_unittest::TestAllTypes::NestedMessage{.bb = 127};

  message->optional_nested_enum = protobuf_unittest::TestAllTypes::NestedEnum::BAZ;
  message->optional_foreign_enum = protobuf_unittest::ForeignEnum::FOREIGN_BAZ;
  message->optional_import_enum = protobuf_unittest_import::ImportEnum::IMPORT_BAZ;
}

// -------------------------------------------------------------------

inline void AddRepeatedFields1(protobuf_unittest::TestAllTypes *message) {
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
  message->repeated_bool.emplace_back(true);
  message->repeated_string.emplace_back("215");
  message->repeated_bytes.push_back("216"_bytes);

  message->repeatedgroup.emplace_back().a = 217;
  message->repeated_nested_message.emplace_back().bb = 218;
  message->repeated_foreign_message.emplace_back().c = 219;
  message->repeated_import_message.emplace_back().d = 220;
  message->repeated_lazy_message.emplace_back().bb = 227;

  message->repeated_nested_enum.push_back(protobuf_unittest::TestAllTypes::NestedEnum::BAR);
  message->repeated_foreign_enum.push_back(protobuf_unittest::ForeignEnum::FOREIGN_BAR);
  message->repeated_import_enum.push_back(protobuf_unittest_import::ImportEnum::IMPORT_BAR);
}

inline void AddRepeatedFields2(protobuf_unittest::TestAllTypes *message) {
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
  message->repeated_bool.emplace_back(false);
  message->repeated_string.emplace_back("315");
  message->repeated_bytes.push_back("316"_bytes);

  message->repeatedgroup.emplace_back().a = 317;
  message->repeated_nested_message.emplace_back().bb = 318;
  message->repeated_foreign_message.emplace_back().c = 319;
  message->repeated_import_message.emplace_back().d = 320;
  message->repeated_lazy_message.emplace_back().bb = 327;

  message->repeated_nested_enum.push_back(protobuf_unittest::TestAllTypes::NestedEnum::BAZ);
  message->repeated_foreign_enum.push_back(protobuf_unittest::ForeignEnum::FOREIGN_BAZ);
  message->repeated_import_enum.push_back(protobuf_unittest_import::ImportEnum::IMPORT_BAZ);
}

// -------------------------------------------------------------------

inline void SetDefaultFields(protobuf_unittest::TestAllTypes *message) {
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
  message->default_float = 411.0F;
  message->default_double = 412;
  message->default_bool = false;
  message->default_string = "415";
  message->default_bytes = "416"_bytes;

  message->default_nested_enum = protobuf_unittest::TestAllTypes::NestedEnum::FOO;
  message->default_foreign_enum = protobuf_unittest::ForeignEnum::FOREIGN_FOO;
  message->default_import_enum = protobuf_unittest_import::ImportEnum::IMPORT_FOO;
}

// -------------------------------------------------------------------

inline void ModifyRepeatedFields(protobuf_unittest::TestAllTypes *message) {
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

  message->repeatedgroup[1].a = 517;
  message->repeated_nested_message[1].bb = 518;
  message->repeated_foreign_message[1].c = 519;
  message->repeated_import_message[1].d = 520;
  message->repeated_lazy_message[1].bb = 527;

  message->repeated_nested_enum[1] = protobuf_unittest::TestAllTypes::NestedEnum::FOO;
  message->repeated_foreign_enum[1] = protobuf_unittest::ForeignEnum::FOREIGN_FOO;
  message->repeated_import_enum[1] = protobuf_unittest_import::ImportEnum::IMPORT_FOO;
}

// ------------------------------------------------------------------
inline void SetOneofFields(protobuf_unittest::TestAllTypes *message) {
  message->oneof_field = 601U;
  using enum protobuf_unittest::TestAllTypes::oneof_field_oneof_case;
  message->oneof_field.emplace<static_cast<int>(oneof_nested_message)>( protobuf_unittest::TestAllTypes::NestedMessage{.bb = 602});
  message->oneof_field.emplace<static_cast<int>(oneof_string)>("603");
  message->oneof_field = "604"_bytes;
}

// -------------------------------------------------------------------

inline void ExpectAllSet(const protobuf_unittest::TestAllTypes &message) {
  expect(eq(101, message.optional_int32.value()));
  expect(eq(102, message.optional_int64.value()));
  expect(eq(103, message.optional_uint32.value()));
  expect(eq(104, message.optional_uint64.value()));
  expect(eq(105, message.optional_sint32.value()));
  expect(eq(106, message.optional_sint64.value()));
  expect(eq(107, message.optional_fixed32.value()));
  expect(eq(108, message.optional_fixed64.value()));
  expect(eq(109, message.optional_sfixed32.value()));
  expect(eq(110, message.optional_sfixed64.value()));
  expect(eq(111, message.optional_float.value()));
  expect(eq(112, message.optional_double.value()));
  expect(message.optional_bool.value());

  expect(eq("115"s, message.optional_string));
  expect(eq("116"_bytes, message.optional_bytes));

  //NOLINTBEGIN(bugprone-unchecked-optional-access)
  expect(eq(117, message.optionalgroup->a.value()));
  expect(eq(118, message.optional_nested_message->bb.value()));
  expect(eq(119, message.optional_foreign_message->c.value()));
  expect(eq(120, message.optional_import_message->d.value()));
  expect(eq(126, message.optional_public_import_message->e.value()));
  expect(eq(127, message.optional_lazy_message->bb.value()));
  //NOLINTEND(bugprone-unchecked-optional-access)

  expect(protobuf_unittest::TestAllTypes::NestedEnum::BAZ == message.optional_nested_enum);
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == message.optional_foreign_enum);
  expect(protobuf_unittest_import::ImportEnum::IMPORT_BAZ == message.optional_import_enum);

  // -----------------------------------------------------------------
  expect(fatal(eq(2, message.repeated_int32.size())));
  expect(fatal(eq(2, message.repeated_int64.size())));
  expect(fatal(eq(2, message.repeated_uint32.size())));
  expect(fatal(eq(2, message.repeated_uint64.size())));
  expect(fatal(eq(2, message.repeated_sint32.size())));
  expect(fatal(eq(2, message.repeated_sint64.size())));
  expect(fatal(eq(2, message.repeated_fixed32.size())));
  expect(fatal(eq(2, message.repeated_fixed64.size())));
  expect(fatal(eq(2, message.repeated_sfixed32.size())));
  expect(fatal(eq(2, message.repeated_sfixed64.size())));
  expect(fatal(eq(2, message.repeated_float.size())));
  expect(fatal(eq(2, message.repeated_double.size())));
  expect(fatal(eq(2, message.repeated_bool.size())));
  expect(fatal(eq(2, message.repeated_string.size())));
  expect(fatal(eq(2, message.repeated_bytes.size())));

  expect(fatal(eq(2, message.repeatedgroup.size())));
  expect(fatal(eq(2, message.repeated_nested_message.size())));
  expect(fatal(eq(2, message.repeated_foreign_message.size())));
  expect(fatal(eq(2, message.repeated_import_message.size())));
  expect(fatal(eq(2, message.repeated_lazy_message.size())));
  expect(fatal(eq(2, message.repeated_nested_enum.size())));
  expect(fatal(eq(2, message.repeated_foreign_enum.size())));
  expect(fatal(eq(2, message.repeated_import_enum.size())));

  expect(eq(201, message.repeated_int32[0]));
  expect(eq(202, message.repeated_int64[0]));
  expect(eq(203, message.repeated_uint32[0]));
  expect(eq(204, message.repeated_uint64[0]));
  expect(eq(205, message.repeated_sint32[0]));
  expect(eq(206, message.repeated_sint64[0]));
  expect(eq(207, message.repeated_fixed32[0]));
  expect(eq(208, message.repeated_fixed64[0]));
  expect(eq(209, message.repeated_sfixed32[0]));
  expect(eq(210, message.repeated_sfixed64[0]));
  expect(eq(211, message.repeated_float[0]));
  expect(eq(212, message.repeated_double[0]));
  expect(message.repeated_bool[0]);
  expect(eq("215"s, message.repeated_string[0]));
  expect(eq("216"_bytes, message.repeated_bytes[0]));

  expect(eq(217, message.repeatedgroup[0].a.value()));
  expect(eq(218, message.repeated_nested_message[0].bb.value()));
  expect(eq(219, message.repeated_foreign_message[0].c.value()));
  expect(eq(220, message.repeated_import_message[0].d.value()));
  expect(eq(227, message.repeated_lazy_message[0].bb.value()));

  expect(protobuf_unittest::TestAllTypes::NestedEnum::BAR == message.repeated_nested_enum[0]);
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == message.repeated_foreign_enum[0]);
  expect(protobuf_unittest_import::ImportEnum::IMPORT_BAR == message.repeated_import_enum[0]);

  expect(eq(301, message.repeated_int32[1]));
  expect(eq(302, message.repeated_int64[1]));
  expect(eq(303, message.repeated_uint32[1]));
  expect(eq(304, message.repeated_uint64[1]));
  expect(eq(305, message.repeated_sint32[1]));
  expect(eq(306, message.repeated_sint64[1]));
  expect(eq(307, message.repeated_fixed32[1]));
  expect(eq(308, message.repeated_fixed64[1]));
  expect(eq(309, message.repeated_sfixed32[1]));
  expect(eq(310, message.repeated_sfixed64[1]));
  expect(eq(311, message.repeated_float[1]));
  expect(eq(312, message.repeated_double[1]));
  expect(!message.repeated_bool[1]);
  expect(eq("315"s, message.repeated_string[1]));
  expect(eq("316"_bytes, message.repeated_bytes[1]));

  expect(eq(317, message.repeatedgroup[1].a.value()));
  expect(eq(318, message.repeated_nested_message[1].bb.value()));
  expect(eq(319, message.repeated_foreign_message[1].c.value()));
  expect(eq(320, message.repeated_import_message[1].d.value()));
  expect(eq(327, message.repeated_lazy_message[1].bb.value()));

  expect(protobuf_unittest::TestAllTypes::NestedEnum::BAZ == message.repeated_nested_enum[1]);
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == message.repeated_foreign_enum[1]);
  expect(protobuf_unittest_import::ImportEnum::IMPORT_BAZ == message.repeated_import_enum[1]);

  // -----------------------------------------------------------------

  expect(eq(401, message.default_int32.value()));
  expect(eq(402, message.default_int64.value()));
  expect(eq(403, message.default_uint32.value()));
  expect(eq(404, message.default_uint64.value()));
  expect(eq(405, message.default_sint32.value()));
  expect(eq(406, message.default_sint64.value()));
  expect(eq(407, message.default_fixed32.value()));
  expect(eq(408, message.default_fixed64.value()));
  expect(eq(409, message.default_sfixed32.value()));
  expect(eq(410, message.default_sfixed64.value()));
  expect(eq(411, message.default_float.value()));
  expect(eq(412, message.default_double.value()));
  expect(!message.default_bool.value());
  expect(eq("415"s, message.default_string.value()));
  expect(eq("416"_bytes, message.default_bytes.value()));

  expect(protobuf_unittest::TestAllTypes::NestedEnum::FOO == message.default_nested_enum);
  expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO == message.default_foreign_enum);
  expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO == message.default_import_enum);

  expect(message.oneof_field.index() == protobuf_unittest::TestAllTypes::oneof_bytes);

  expect(eq("604"_bytes, std::get<protobuf_unittest::TestAllTypes::oneof_bytes>(message.oneof_field)));
}

// -------------------------------------------------------------------

inline void ExpectClear(const protobuf_unittest::TestAllTypes &message) {
  //.blah.has_value() should initially be false for all optional fields.

  expect(!message.optional_int32.has_value());
  expect(!message.optional_int64.has_value());
  expect(!message.optional_uint32.has_value());
  expect(!message.optional_uint64.has_value());
  expect(!message.optional_sint32.has_value());
  expect(!message.optional_sint64.has_value());
  expect(!message.optional_fixed32.has_value());
  expect(!message.optional_fixed64.has_value());
  expect(!message.optional_sfixed32.has_value());
  expect(!message.optional_sfixed64.has_value());
  expect(!message.optional_float.has_value());
  expect(!message.optional_double.has_value());
  expect(!message.optional_bool.has_value());
  expect(!message.optional_string.has_value());
  expect(!message.optional_bytes.has_value());

  expect(!message.optionalgroup.has_value());
  expect(!message.optional_nested_message.has_value());
  expect(!message.optional_foreign_message.has_value());
  expect(!message.optional_import_message.has_value());
  expect(!message.optional_public_import_message.has_value());
  expect(!message.optional_lazy_message.has_value());

  expect(!message.optional_nested_enum.has_value());
  expect(protobuf_unittest::TestAllTypes::NestedEnum::FOO == message.optional_nested_enum.value_or_default());
  expect(!message.optional_foreign_enum.has_value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO == message.optional_foreign_enum.value_or_default());
  expect(!message.optional_import_enum.has_value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO == message.optional_import_enum.value_or_default());

  expect(!message.optional_string_piece.has_value());
  expect(!message.optional_cord.has_value());

  // Repeated fields are empty.
  expect(eq(0, message.repeated_int32.size()));
  expect(eq(0, message.repeated_int64.size()));
  expect(eq(0, message.repeated_uint32.size()));
  expect(eq(0, message.repeated_uint64.size()));
  expect(eq(0, message.repeated_sint32.size()));
  expect(eq(0, message.repeated_sint64.size()));
  expect(eq(0, message.repeated_fixed32.size()));
  expect(eq(0, message.repeated_fixed64.size()));
  expect(eq(0, message.repeated_sfixed32.size()));
  expect(eq(0, message.repeated_sfixed64.size()));
  expect(eq(0, message.repeated_float.size()));
  expect(eq(0, message.repeated_double.size()));
  expect(eq(0, message.repeated_bool.size()));
  expect(eq(0, message.repeated_string.size()));
  expect(eq(0, message.repeated_bytes.size()));

  expect(eq(0, message.repeatedgroup.size()));
  expect(eq(0, message.repeated_nested_message.size()));
  expect(eq(0, message.repeated_foreign_message.size()));
  expect(eq(0, message.repeated_import_message.size()));
  expect(eq(0, message.repeated_lazy_message.size()));
  expect(eq(0, message.repeated_nested_enum.size()));
  expect(eq(0, message.repeated_foreign_enum.size()));
  expect(eq(0, message.repeated_import_enum.size()));

  expect(eq(0, message.repeated_string_piece.size()));
  expect(eq(0, message.repeated_cord.size()));

  // Fields with defaults have their default values (duh).
  expect(eq(41, message.default_int32.value_or_default()));
  expect(eq(42, message.default_int64.value_or_default()));
  expect(eq(43, message.default_uint32.value_or_default()));
  expect(eq(44, message.default_uint64.value_or_default()));
  expect(eq(-45, message.default_sint32.value_or_default()));
  expect(eq(46, message.default_sint64.value_or_default()));
  expect(eq(47, message.default_fixed32.value_or_default()));
  expect(eq(48, message.default_fixed64.value_or_default()));
  expect(eq(49, message.default_sfixed32.value_or_default()));
  expect(eq(-50, message.default_sfixed64.value_or_default()));
  expect(eq(51.5, message.default_float.value_or_default()));
  expect(eq(52e3, message.default_double.value_or_default()));
  expect(message.default_bool.value_or_default());
  expect(eq("hello"s, message.default_string.value_or_default()));
  expect(eq("world"_bytes, message.default_bytes.value_or_default()));

  expect(!message.default_nested_enum.has_value());
  expect(protobuf_unittest::TestAllTypes::NestedEnum::BAR == message.default_nested_enum.value_or_default());
  expect(!message.default_foreign_enum.has_value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == message.default_foreign_enum.value_or_default());
  expect(!message.default_import_enum.has_value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_BAR == message.default_import_enum.value_or_default());

  expect(std::holds_alternative<std::monostate>(message.oneof_field));
}

// -------------------------------------------------------------------

inline void ExpectRepeatedFieldsModified(const protobuf_unittest::TestAllTypes &message) {
  // ModifyRepeatedFields only sets the second repeated element of each
  // field.  In addition to verifying this, we also verify that the first
  // element and size were *not* modified.
  expect(fatal(eq(2, message.repeated_int32.size())));
  expect(fatal(eq(2, message.repeated_int64.size())));
  expect(fatal(eq(2, message.repeated_uint32.size())));
  expect(fatal(eq(2, message.repeated_uint64.size())));
  expect(fatal(eq(2, message.repeated_sint32.size())));
  expect(fatal(eq(2, message.repeated_sint64.size())));
  expect(fatal(eq(2, message.repeated_fixed32.size())));
  expect(fatal(eq(2, message.repeated_fixed64.size())));
  expect(fatal(eq(2, message.repeated_sfixed32.size())));
  expect(fatal(eq(2, message.repeated_sfixed64.size())));
  expect(fatal(eq(2, message.repeated_float.size())));
  expect(fatal(eq(2, message.repeated_double.size())));
  expect(fatal(eq(2, message.repeated_bool.size())));
  expect(fatal(eq(2, message.repeated_string.size())));
  expect(fatal(eq(2, message.repeated_bytes.size())));

  expect(fatal(eq(2, message.repeated_nested_message.size())));
  expect(fatal(eq(2, message.repeated_foreign_message.size())));
  expect(fatal(eq(2, message.repeated_import_message.size())));
  expect(fatal(eq(2, message.repeated_lazy_message.size())));
  expect(fatal(eq(2, message.repeated_nested_enum.size())));
  expect(fatal(eq(2, message.repeated_foreign_enum.size())));
  expect(fatal(eq(2, message.repeated_import_enum.size())));

  expect(eq(201, message.repeated_int32[0]));
  expect(eq(202, message.repeated_int64[0]));
  expect(eq(203, message.repeated_uint32[0]));
  expect(eq(204, message.repeated_uint64[0]));
  expect(eq(205, message.repeated_sint32[0]));
  expect(eq(206, message.repeated_sint64[0]));
  expect(eq(207, message.repeated_fixed32[0]));
  expect(eq(208, message.repeated_fixed64[0]));
  expect(eq(209, message.repeated_sfixed32[0]));
  expect(eq(210, message.repeated_sfixed64[0]));
  expect(eq(211, message.repeated_float[0]));
  expect(eq(212, message.repeated_double[0]));
  expect(message.repeated_bool[0]);
  expect(eq("215"s, message.repeated_string[0]));
  expect(eq("216"_bytes, message.repeated_bytes[0]));

  expect(eq(218, message.repeatedgroup[0].a.value()));
  expect(eq(218, message.repeated_nested_message[0].bb.value()));
  expect(eq(219, message.repeated_foreign_message[0].c.value()));
  expect(eq(220, message.repeated_import_message[0].d.value()));
  expect(eq(227, message.repeated_lazy_message[0].bb.value()));

  expect(protobuf_unittest::TestAllTypes::NestedEnum::BAR == message.repeated_nested_enum[0]);
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == message.repeated_foreign_enum[0]);
  expect(protobuf_unittest_import::ImportEnum::IMPORT_BAR == message.repeated_import_enum[0]);

  // Actually verify the second (modified) elements now.
  expect(eq(501, message.repeated_int32[1]));
  expect(eq(502, message.repeated_int64[1]));
  expect(eq(503, message.repeated_uint32[1]));
  expect(eq(504, message.repeated_uint64[1]));
  expect(eq(505, message.repeated_sint32[1]));
  expect(eq(506, message.repeated_sint64[1]));
  expect(eq(507, message.repeated_fixed32[1]));
  expect(eq(508, message.repeated_fixed64[1]));
  expect(eq(509, message.repeated_sfixed32[1]));
  expect(eq(510, message.repeated_sfixed64[1]));
  expect(eq(511, message.repeated_float[1]));
  expect(eq(512, message.repeated_double[1]));
  expect(message.repeated_bool[1]);
  expect(eq("515"s, message.repeated_string[1]));
  expect(eq("516"_bytes, message.repeated_bytes[1]));

  expect(eq(517, message.repeatedgroup[1].a.value()));
  expect(eq(518, message.repeated_nested_message[1].bb.value()));
  expect(eq(519, message.repeated_foreign_message[1].c.value()));
  expect(eq(520, message.repeated_import_message[1].d.value()));
  expect(eq(527, message.repeated_lazy_message[1].bb.value()));

  expect(protobuf_unittest::TestAllTypes::NestedEnum::FOO == message.repeated_nested_enum[1]);
  expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO == message.repeated_foreign_enum[1]);
  expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO == message.repeated_import_enum[1]);
}

// -------------------------------------------------------------------

inline void SetAll(protobuf_unittest::TestPackedTypes *message) {
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
  message->packed_bool.emplace_back(true);
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
  message->packed_bool.emplace_back(false);
  message->packed_enum.push_back(protobuf_unittest::ForeignEnum::FOREIGN_BAZ);
}

inline void SetAll(protobuf_unittest::TestUnpackedTypes *message) {
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
  message->unpacked_bool.emplace_back(true);
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
  message->unpacked_bool.emplace_back(false);
  message->unpacked_enum.push_back(protobuf_unittest::ForeignEnum::FOREIGN_BAZ);
}

// -------------------------------------------------------------------

inline void ExpectAllSet(const protobuf_unittest::TestPackedTypes &message) {
  expect(fatal(eq(2, message.packed_int32.size())));
  expect(fatal(eq(2, message.packed_int64.size())));
  expect(fatal(eq(2, message.packed_uint32.size())));
  expect(fatal(eq(2, message.packed_uint64.size())));
  expect(fatal(eq(2, message.packed_sint32.size())));
  expect(fatal(eq(2, message.packed_sint64.size())));
  expect(fatal(eq(2, message.packed_fixed32.size())));
  expect(fatal(eq(2, message.packed_fixed64.size())));
  expect(fatal(eq(2, message.packed_sfixed32.size())));
  expect(fatal(eq(2, message.packed_sfixed64.size())));
  expect(fatal(eq(2, message.packed_float.size())));
  expect(fatal(eq(2, message.packed_double.size())));
  expect(fatal(eq(2, message.packed_bool.size())));
  expect(fatal(eq(2, message.packed_enum.size())));

  expect(eq(601, message.packed_int32[0]));
  expect(eq(602, message.packed_int64[0]));
  expect(eq(603, message.packed_uint32[0]));
  expect(eq(604, message.packed_uint64[0]));
  expect(eq(605, message.packed_sint32[0]));
  expect(eq(606, message.packed_sint64[0]));
  expect(eq(607, message.packed_fixed32[0]));
  expect(eq(608, message.packed_fixed64[0]));
  expect(eq(609, message.packed_sfixed32[0]));
  expect(eq(610, message.packed_sfixed64[0]));
  expect(eq(611, message.packed_float[0]));
  expect(eq(612, message.packed_double[0]));
  expect(message.packed_bool[0]);
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == message.packed_enum[0]);

  expect(eq(701, message.packed_int32[1]));
  expect(eq(702, message.packed_int64[1]));
  expect(eq(703, message.packed_uint32[1]));
  expect(eq(704, message.packed_uint64[1]));
  expect(eq(705, message.packed_sint32[1]));
  expect(eq(706, message.packed_sint64[1]));
  expect(eq(707, message.packed_fixed32[1]));
  expect(eq(708, message.packed_fixed64[1]));
  expect(eq(709, message.packed_sfixed32[1]));
  expect(eq(710, message.packed_sfixed64[1]));
  expect(eq(711, message.packed_float[1]));
  expect(eq(712, message.packed_double[1]));
  expect(!message.packed_bool[1]);
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == message.packed_enum[1]);
}

inline void ExpectAllSet(const protobuf_unittest::TestUnpackedTypes &message) {
  // The values expected here must match those of ExpectAllSet.
  expect(fatal(eq(2, message.unpacked_int32.size())));
  expect(fatal(eq(2, message.unpacked_int64.size())));
  expect(fatal(eq(2, message.unpacked_uint32.size())));
  expect(fatal(eq(2, message.unpacked_uint64.size())));
  expect(fatal(eq(2, message.unpacked_sint32.size())));
  expect(fatal(eq(2, message.unpacked_sint64.size())));
  expect(fatal(eq(2, message.unpacked_fixed32.size())));
  expect(fatal(eq(2, message.unpacked_fixed64.size())));
  expect(fatal(eq(2, message.unpacked_sfixed32.size())));
  expect(fatal(eq(2, message.unpacked_sfixed64.size())));
  expect(fatal(eq(2, message.unpacked_float.size())));
  expect(fatal(eq(2, message.unpacked_double.size())));
  expect(fatal(eq(2, message.unpacked_bool.size())));
  expect(fatal(eq(2, message.unpacked_enum.size())));

  expect(eq(601, message.unpacked_int32[0]));
  expect(eq(602, message.unpacked_int64[0]));
  expect(eq(603, message.unpacked_uint32[0]));
  expect(eq(604, message.unpacked_uint64[0]));
  expect(eq(605, message.unpacked_sint32[0]));
  expect(eq(606, message.unpacked_sint64[0]));
  expect(eq(607, message.unpacked_fixed32[0]));
  expect(eq(608, message.unpacked_fixed64[0]));
  expect(eq(609, message.unpacked_sfixed32[0]));
  expect(eq(610, message.unpacked_sfixed64[0]));
  expect(eq(611, message.unpacked_float[0]));
  expect(eq(612, message.unpacked_double[0]));
  expect(message.unpacked_bool[0]);
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == message.unpacked_enum[0]);

  expect(eq(701, message.unpacked_int32[1]));
  expect(eq(702, message.unpacked_int64[1]));
  expect(eq(703, message.unpacked_uint32[1]));
  expect(eq(704, message.unpacked_uint64[1]));
  expect(eq(705, message.unpacked_sint32[1]));
  expect(eq(706, message.unpacked_sint64[1]));
  expect(eq(707, message.unpacked_fixed32[1]));
  expect(eq(708, message.unpacked_fixed64[1]));
  expect(eq(709, message.unpacked_sfixed32[1]));
  expect(eq(710, message.unpacked_sfixed64[1]));
  expect(eq(711, message.unpacked_float[1]));
  expect(eq(712, message.unpacked_double[1]));
  expect(!message.unpacked_bool[1]);
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == message.unpacked_enum[1]);
}

// ===================================================================
// Extensions
//
// All this code is exactly equivalent to the above code except that it's
// manipulating extension fields instead of normal ones.
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

inline void SetAll(protobuf_unittest::TestAllExtensions *message) {
  expect(message->set_extension(protobuf_unittest::optional_int32_extension(), 101).ok());
  expect(message->set_extension(protobuf_unittest::optional_int64_extension(), 102).ok());
  expect(message->set_extension(protobuf_unittest::optional_uint32_extension(), 103).ok());
  expect(message->set_extension(protobuf_unittest::optional_uint64_extension(), 104).ok());
  expect(message->set_extension(protobuf_unittest::optional_sint32_extension(), 105).ok());
  expect(message->set_extension(protobuf_unittest::optional_sint64_extension(), 106).ok());
  expect(message->set_extension(protobuf_unittest::optional_fixed32_extension(), 107).ok());
  expect(message->set_extension(protobuf_unittest::optional_fixed64_extension(), 108).ok());
  expect(message->set_extension(protobuf_unittest::optional_sfixed32_extension(), 109).ok());
  expect(message->set_extension(protobuf_unittest::optional_sfixed64_extension(), 110).ok());
  expect(message->set_extension(protobuf_unittest::optional_float_extension(), 111).ok());
  expect(message->set_extension(protobuf_unittest::optional_double_extension(), 112).ok());
  expect(message->set_extension(protobuf_unittest::optional_bool_extension(), true).ok());
  expect(message->set_extension(protobuf_unittest::optional_string_extension(), "115").ok());
  expect(message->set_extension(protobuf_unittest::optional_bytes_extension(), "116"_bytes).ok());

  expect(message->set_extension(protobuf_unittest::optionalgroup_extension(), {.a = 117}).ok());
  expect(message->set_extension(protobuf_unittest::optional_nested_message_extension(), {.bb = 118}).ok());
  expect(message->set_extension(protobuf_unittest::optional_foreign_message_extension(), {.c = 119}).ok());
  expect(message->set_extension(protobuf_unittest::optional_import_message_extension(), {.d = 120}).ok());

  expect(message->set_extension(protobuf_unittest::optional_nested_enum_extension(),
                                 protobuf_unittest::TestAllTypes::NestedEnum::BAZ).ok());
  expect(message->set_extension(protobuf_unittest::optional_foreign_enum_extension(),
                                 protobuf_unittest::ForeignEnum::FOREIGN_BAZ).ok());
  expect(message->set_extension(protobuf_unittest::optional_import_enum_extension(),
                                 protobuf_unittest_import::ImportEnum::IMPORT_BAZ).ok());

  expect(message->set_extension(protobuf_unittest::optional_string_piece_extension(), "124").ok());
  expect(message->set_extension(protobuf_unittest::optional_cord_extension(), "125").ok());

  expect(message->set_extension(protobuf_unittest::optional_public_import_message_extension(), {.e = 126}).ok());
  expect(message->set_extension(protobuf_unittest::optional_lazy_message_extension(), {.bb = 127}).ok());

  // -----------------------------------------------------------------

  expect(message->set_extension(protobuf_unittest::repeated_int32_extension(), {201, 301}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_int64_extension(), {202, 302}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_uint32_extension(), {203, 303}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_uint64_extension(), {204, 304}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_sint32_extension(), {205, 305}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_sint64_extension(), {206, 306}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_fixed32_extension(), {207, 307}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_fixed64_extension(), {208, 308}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_sfixed32_extension(), {209, 309}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_sfixed64_extension(), {210, 310}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_float_extension(), {211, 311}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_double_extension(), {212, 312}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_bool_extension(), {true, false}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_string_extension(), {"215", "315"}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_bytes_extension(), {"216"_bytes, "316"_bytes}).ok());

  expect(message->set_extension(protobuf_unittest::repeatedgroup_extension(), {{.a = 217}, {.a = 317}}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_nested_message_extension(), {{.bb = 218}, {.bb = 318}}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_foreign_message_extension(), {{.c = 219}, {.c = 319}}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_import_message_extension(), {{.d = 220}, {.d = 320}}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_lazy_message_extension(), {{.bb = 227}, {.bb = 327}}).ok());

  expect(message->set_extension(
      protobuf_unittest::repeated_nested_enum_extension(),
      {protobuf_unittest::TestAllTypes::NestedEnum::BAR, protobuf_unittest::TestAllTypes::NestedEnum::BAZ}).ok());
  expect(message->set_extension(
      protobuf_unittest::repeated_foreign_enum_extension(),
      {protobuf_unittest::ForeignEnum::FOREIGN_BAR, protobuf_unittest::ForeignEnum::FOREIGN_BAZ}).ok());
  expect(message->set_extension(
      protobuf_unittest::repeated_import_enum_extension(),
      {protobuf_unittest_import::ImportEnum::IMPORT_BAR, protobuf_unittest_import::ImportEnum::IMPORT_BAZ}).ok());

  expect(message->set_extension(protobuf_unittest::repeated_string_piece_extension(), {"224", "324"}).ok());
  expect(message->set_extension(protobuf_unittest::repeated_cord_extension(), {"225", "325"}).ok());

  // -----------------------------------------------------------------

  expect(message->set_extension(protobuf_unittest::default_int32_extension(), 401).ok());
  expect(message->set_extension(protobuf_unittest::default_int64_extension(), 402).ok());
  expect(message->set_extension(protobuf_unittest::default_uint32_extension(), 403).ok());
  expect(message->set_extension(protobuf_unittest::default_uint64_extension(), 404).ok());
  expect(message->set_extension(protobuf_unittest::default_sint32_extension(), 405).ok());
  expect(message->set_extension(protobuf_unittest::default_sint64_extension(), 406).ok());
  expect(message->set_extension(protobuf_unittest::default_fixed32_extension(), 407).ok());
  expect(message->set_extension(protobuf_unittest::default_fixed64_extension(), 408).ok());
  expect(message->set_extension(protobuf_unittest::default_sfixed32_extension(), 409).ok());
  expect(message->set_extension(protobuf_unittest::default_sfixed64_extension(), 410).ok());
  expect(message->set_extension(protobuf_unittest::default_float_extension(), 411).ok());
  expect(message->set_extension(protobuf_unittest::default_double_extension(), 412).ok());

  expect(message->set_extension(protobuf_unittest::default_bool_extension(), false).ok());
  expect(message->set_extension(protobuf_unittest::default_string_extension(), "415").ok());
  expect(message->set_extension(protobuf_unittest::default_bytes_extension(), "416"_bytes).ok());

  expect(message->set_extension(protobuf_unittest::default_nested_enum_extension(),
                                 protobuf_unittest::TestAllTypes::NestedEnum::FOO).ok());
  expect(message->set_extension(protobuf_unittest::default_foreign_enum_extension(),
                                 protobuf_unittest::ForeignEnum::FOREIGN_FOO).ok());
  expect(message->set_extension(protobuf_unittest::default_import_enum_extension(),
                                 protobuf_unittest_import::ImportEnum::IMPORT_FOO).ok());

  expect(message->set_extension(protobuf_unittest::default_string_piece_extension(), "424").ok());
  expect(message->set_extension(protobuf_unittest::default_cord_extension(), "425").ok());

  SetOneofFields(message);
}

inline void SetOneofFields(protobuf_unittest::TestAllExtensions *message) {
  expect(message->set_extension(protobuf_unittest::oneof_uint32_extension(), 601).ok());
  expect(message->set_extension(protobuf_unittest::oneof_nested_message_extension(), {.bb = 602}).ok());
  expect(message->set_extension(protobuf_unittest::oneof_string_extension(), "603").ok());
  expect(message->set_extension(protobuf_unittest::oneof_bytes_extension(), "604"_bytes).ok());
}

// -------------------------------------------------------------------

inline void SetAllFieldsAndExtensions(protobuf_unittest::TestFieldOrderings *message) {
  message->my_int = 1;
  message->my_string = "foo";
  message->my_float = 1.0F;
  expect(message->set_extension(protobuf_unittest::my_extension_int(), 23).ok());
  expect(message->set_extension(protobuf_unittest::my_extension_string(), "bar").ok());
}
// -------------------------------------------------------------------

inline void ExpectAllSet(const protobuf_unittest::TestAllExtensions &message) {
  expect(message.has_extension(protobuf_unittest::optional_int32_extension()));
  expect(message.has_extension(protobuf_unittest::optional_int64_extension()));
  expect(message.has_extension(protobuf_unittest::optional_uint32_extension()));
  expect(message.has_extension(protobuf_unittest::optional_uint64_extension()));
  expect(message.has_extension(protobuf_unittest::optional_sint32_extension()));
  expect(message.has_extension(protobuf_unittest::optional_sint64_extension()));
  expect(message.has_extension(protobuf_unittest::optional_fixed32_extension()));
  expect(message.has_extension(protobuf_unittest::optional_fixed64_extension()));
  expect(message.has_extension(protobuf_unittest::optional_sfixed32_extension()));
  expect(message.has_extension(protobuf_unittest::optional_sfixed64_extension()));
  expect(message.has_extension(protobuf_unittest::optional_float_extension()));
  expect(message.has_extension(protobuf_unittest::optional_double_extension()));
  expect(message.has_extension(protobuf_unittest::optional_bool_extension()));
  expect(message.has_extension(protobuf_unittest::optional_string_extension()));
  expect(message.has_extension(protobuf_unittest::optional_bytes_extension()));

  expect(message.has_extension(protobuf_unittest::optionalgroup_extension()));
  expect(message.has_extension(protobuf_unittest::optional_nested_message_extension()));
  expect(message.has_extension(protobuf_unittest::optional_foreign_message_extension()));
  expect(message.has_extension(protobuf_unittest::optional_import_message_extension()));
  expect(message.has_extension(protobuf_unittest::optional_public_import_message_extension()));
  expect(message.has_extension(protobuf_unittest::optional_lazy_message_extension()));

  expect(message.get_extension(protobuf_unittest::optionalgroup_extension())->a);
  expect(message.get_extension(protobuf_unittest::optional_nested_message_extension())->bb);
  expect(message.get_extension(protobuf_unittest::optional_foreign_message_extension())->c);
  expect(message.get_extension(protobuf_unittest::optional_import_message_extension())->d);
  expect(message.get_extension(protobuf_unittest::optional_public_import_message_extension())->e);
  expect(message.get_extension(protobuf_unittest::optional_lazy_message_extension())->bb);

  expect(message.has_extension(protobuf_unittest::optional_nested_enum_extension()));
  expect(message.has_extension(protobuf_unittest::optional_foreign_enum_extension()));
  expect(message.has_extension(protobuf_unittest::optional_import_enum_extension()));

  expect(message.has_extension(protobuf_unittest::optional_string_piece_extension()));
  expect(message.has_extension(protobuf_unittest::optional_cord_extension()));

  expect(eq(101, message.get_extension(protobuf_unittest::optional_int32_extension()).value()));
  expect(eq(102, message.get_extension(protobuf_unittest::optional_int64_extension()).value()));
  expect(eq(103, message.get_extension(protobuf_unittest::optional_uint32_extension()).value()));
  expect(eq(104, message.get_extension(protobuf_unittest::optional_uint64_extension()).value()));
  expect(eq(105, message.get_extension(protobuf_unittest::optional_sint32_extension()).value()));
  expect(eq(106, message.get_extension(protobuf_unittest::optional_sint64_extension()).value()));
  expect(eq(107, message.get_extension(protobuf_unittest::optional_fixed32_extension()).value()));
  expect(eq(108, message.get_extension(protobuf_unittest::optional_fixed64_extension()).value()));
  expect(eq(109, message.get_extension(protobuf_unittest::optional_sfixed32_extension()).value()));
  expect(eq(110, message.get_extension(protobuf_unittest::optional_sfixed64_extension()).value()));
  expect(eq(111, message.get_extension(protobuf_unittest::optional_float_extension()).value()));
  expect(eq(112, message.get_extension(protobuf_unittest::optional_double_extension()).value()));
  expect(message.get_extension(protobuf_unittest::optional_bool_extension()).value());
  expect(eq("115"s, message.get_extension(protobuf_unittest::optional_string_extension()).value()));
  expect(eq("116"_bytes, message.get_extension(protobuf_unittest::optional_bytes_extension()).value()));

  expect(eq(117, message.get_extension(protobuf_unittest::optionalgroup_extension()).value().a.value()));
  expect(eq(118, message.get_extension(protobuf_unittest::optional_nested_message_extension()).value().bb.value()));
  expect(eq(119, message.get_extension(protobuf_unittest::optional_foreign_message_extension()).value().c.value()));
  expect(eq(120, message.get_extension(protobuf_unittest::optional_import_message_extension()).value().d.value()));

  expect(protobuf_unittest::TestAllTypes::NestedEnum::BAZ ==
         message.get_extension(protobuf_unittest::optional_nested_enum_extension()).value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ ==
         message.get_extension(protobuf_unittest::optional_foreign_enum_extension()).value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_BAZ ==
         message.get_extension(protobuf_unittest::optional_import_enum_extension()).value());

  expect(eq("124"s, message.get_extension(protobuf_unittest::optional_string_piece_extension()).value()));
  expect(eq("125"s, message.get_extension(protobuf_unittest::optional_cord_extension()).value()));
  expect(
      eq(126, message.get_extension(protobuf_unittest::optional_public_import_message_extension()).value().e.value()));
  expect(eq(127, message.get_extension(protobuf_unittest::optional_lazy_message_extension()).value().bb.value()));
  
  // -----------------------------------------------------------------

  expect(
      eq(message.get_extension(protobuf_unittest::repeated_int32_extension()).value(), std::vector<int32_t>{201, 301}));
  expect(
      eq(message.get_extension(protobuf_unittest::repeated_int64_extension()).value(), std::vector<int64_t>{202, 302}));
  expect(eq(message.get_extension(protobuf_unittest::repeated_uint32_extension()).value(),
            std::vector<uint32_t>{203, 303}));
  expect(eq(message.get_extension(protobuf_unittest::repeated_uint64_extension()).value(),
            std::vector<uint64_t>{204, 304}));
  expect(eq(message.get_extension(protobuf_unittest::repeated_sint32_extension()).value(),
            std::vector<int32_t>{205, 305}));
  expect(eq(message.get_extension(protobuf_unittest::repeated_sint64_extension()).value(),
            std::vector<int64_t>{206, 306}));
  expect(eq(message.get_extension(protobuf_unittest::repeated_fixed32_extension()).value(),
            std::vector<uint32_t>{207, 307}));
  expect(eq(message.get_extension(protobuf_unittest::repeated_fixed64_extension()).value(),
            std::vector<uint64_t>{208, 308}));
  expect(eq(message.get_extension(protobuf_unittest::repeated_sfixed32_extension()).value(),
            std::vector<int32_t>{209, 309}));
  expect(eq(message.get_extension(protobuf_unittest::repeated_sfixed64_extension()).value(),
            std::vector<int64_t>{210, 310}));
  expect(
      eq(message.get_extension(protobuf_unittest::repeated_float_extension()).value(), std::vector<float>{211, 311}));
  expect(
      eq(message.get_extension(protobuf_unittest::repeated_double_extension()).value(), std::vector<double>{212, 312}));
  expect(eq(message.get_extension(protobuf_unittest::repeated_bool_extension()).value(),
            std::vector<hpp::proto::boolean>{true, false}));
  expect(eq(message.get_extension(protobuf_unittest::repeated_string_extension()).value(),
            std::vector<std::string>{"215", "315"}));
  expect(eq(message.get_extension(protobuf_unittest::repeated_bytes_extension()).value(),
            std::vector{"216"_bytes, "316"_bytes}));

  expect(message.get_extension(protobuf_unittest::repeatedgroup_extension()).value() ==
         std::vector<protobuf_unittest::RepeatedGroup_extension>{{.a = 217}, {.a = 317}});

  expect(message.get_extension(protobuf_unittest::repeated_nested_message_extension()).value() ==
         std::vector<protobuf_unittest::TestAllTypes::NestedMessage>{{.bb = 218}, {.bb = 318}});

  expect(message.get_extension(protobuf_unittest::repeated_foreign_message_extension()).value() ==
         std::vector<protobuf_unittest::ForeignMessage>{{.c = 219}, {.c = 319}});

  expect(message.get_extension(protobuf_unittest::repeated_import_message_extension()).value() ==
         std::vector<protobuf_unittest_import::ImportMessage>{{.d = 220}, {.d = 320}});

  expect(message.get_extension(protobuf_unittest::repeated_lazy_message_extension()).value() ==
         std::vector<protobuf_unittest::TestAllTypes::NestedMessage>{{.bb = 227}, {.bb = 327}});

  expect(message.get_extension(protobuf_unittest::repeated_nested_enum_extension()).value() ==
         std::vector<protobuf_unittest::TestAllTypes::NestedEnum>{protobuf_unittest::TestAllTypes::NestedEnum::BAR,
                                                                  protobuf_unittest::TestAllTypes::NestedEnum::BAZ});

  expect(message.get_extension(protobuf_unittest::repeated_foreign_enum_extension()).value() ==
         std::vector<protobuf_unittest::ForeignEnum>{protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                     protobuf_unittest::ForeignEnum::FOREIGN_BAZ});

  expect(message.get_extension(protobuf_unittest::repeated_import_enum_extension()).value() ==
         std::vector<protobuf_unittest_import::ImportEnum>{protobuf_unittest_import::ImportEnum::IMPORT_BAR,
                                                           protobuf_unittest_import::ImportEnum::IMPORT_BAZ});

  expect(eq(message.get_extension(protobuf_unittest::repeated_string_piece_extension()).value(),
            std::vector<std::string>{"224", "324"}));

  expect(eq(message.get_extension(protobuf_unittest::repeated_cord_extension()).value(),
            std::vector<std::string>{"225", "325"}));

  // -----------------------------------------------------------------

  expect(message.has_extension(protobuf_unittest::default_int32_extension()));
  expect(message.has_extension(protobuf_unittest::default_int64_extension()));
  expect(message.has_extension(protobuf_unittest::default_uint32_extension()));
  expect(message.has_extension(protobuf_unittest::default_uint64_extension()));
  expect(message.has_extension(protobuf_unittest::default_sint32_extension()));
  expect(message.has_extension(protobuf_unittest::default_sint64_extension()));
  expect(message.has_extension(protobuf_unittest::default_fixed32_extension()));
  expect(message.has_extension(protobuf_unittest::default_fixed64_extension()));
  expect(message.has_extension(protobuf_unittest::default_sfixed32_extension()));
  expect(message.has_extension(protobuf_unittest::default_sfixed64_extension()));
  expect(message.has_extension(protobuf_unittest::default_float_extension()));
  expect(message.has_extension(protobuf_unittest::default_double_extension()));
  expect(message.has_extension(protobuf_unittest::default_bool_extension()));
  expect(message.has_extension(protobuf_unittest::default_string_extension()));
  expect(message.has_extension(protobuf_unittest::default_bytes_extension()));

  expect(message.has_extension(protobuf_unittest::default_nested_enum_extension()));
  expect(message.has_extension(protobuf_unittest::default_foreign_enum_extension()));
  expect(message.has_extension(protobuf_unittest::default_import_enum_extension()));

  expect(message.has_extension(protobuf_unittest::default_string_piece_extension()));
  expect(message.has_extension(protobuf_unittest::default_cord_extension()));

  expect(eq(401, message.get_extension(protobuf_unittest::default_int32_extension()).value()));
  expect(eq(402, message.get_extension(protobuf_unittest::default_int64_extension()).value()));
  expect(eq(403, message.get_extension(protobuf_unittest::default_uint32_extension()).value()));
  expect(eq(404, message.get_extension(protobuf_unittest::default_uint64_extension()).value()));
  expect(eq(405, message.get_extension(protobuf_unittest::default_sint32_extension()).value()));
  expect(eq(406, message.get_extension(protobuf_unittest::default_sint64_extension()).value()));
  expect(eq(407, message.get_extension(protobuf_unittest::default_fixed32_extension()).value()));
  expect(eq(408, message.get_extension(protobuf_unittest::default_fixed64_extension()).value()));
  expect(eq(409, message.get_extension(protobuf_unittest::default_sfixed32_extension()).value()));
  expect(eq(410, message.get_extension(protobuf_unittest::default_sfixed64_extension()).value()));
  expect(eq(411, message.get_extension(protobuf_unittest::default_float_extension()).value()));
  expect(eq(412, message.get_extension(protobuf_unittest::default_double_extension()).value()));
  expect(!message.get_extension(protobuf_unittest::default_bool_extension()).value());
  expect(eq("415"s, message.get_extension(protobuf_unittest::default_string_extension()).value()));
  expect(eq("416"_bytes, message.get_extension(protobuf_unittest::default_bytes_extension()).value()));

  expect(protobuf_unittest::TestAllTypes::NestedEnum::FOO ==
         message.get_extension(protobuf_unittest::default_nested_enum_extension()).value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO ==
         message.get_extension(protobuf_unittest::default_foreign_enum_extension()).value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO ==
         message.get_extension(protobuf_unittest::default_import_enum_extension()).value());

  expect(eq("424"s, message.get_extension(protobuf_unittest::default_string_piece_extension()).value()));
  expect(eq("425"s, message.get_extension(protobuf_unittest::default_cord_extension()).value()));

  expect(message.has_extension(protobuf_unittest::oneof_uint32_extension()));
  expect(message.get_extension(protobuf_unittest::oneof_nested_message_extension())->bb);
  expect(message.has_extension(protobuf_unittest::oneof_string_extension()));
  expect(message.has_extension(protobuf_unittest::oneof_bytes_extension()));

  expect(eq(601, message.get_extension(protobuf_unittest::oneof_uint32_extension()).value()));
  expect(eq(602, message.get_extension(protobuf_unittest::oneof_nested_message_extension()).value().bb.value()));
  expect(eq("603"s, message.get_extension(protobuf_unittest::oneof_string_extension()).value()));
  expect(eq("604"_bytes, message.get_extension(protobuf_unittest::oneof_bytes_extension()).value()));
}
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
// -------------------------------------------------------------------

inline void ExpectClear(const protobuf_unittest::TestAllExtensions &message) {
  std::vector<std::byte> data;
  expect(hpp::proto::write_proto(message, data).ok());
  expect(eq(0, data.size()));

  //.blah.has_value() should initially be false for all optional fields.
  expect(!message.has_extension(protobuf_unittest::optional_int32_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_int64_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_uint32_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_uint64_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_sint32_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_sint64_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_fixed32_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_fixed64_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_sfixed32_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_sfixed64_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_float_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_double_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_bool_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_string_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_bytes_extension()));

  expect(!message.has_extension(protobuf_unittest::optionalgroup_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_nested_message_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_foreign_message_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_import_message_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_public_import_message_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_lazy_message_extension()));

  expect(!message.has_extension(protobuf_unittest::optional_nested_enum_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_foreign_enum_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_import_enum_extension()));

  expect(!message.has_extension(protobuf_unittest::optional_string_piece_extension()));
  expect(!message.has_extension(protobuf_unittest::optional_cord_extension()));

  // Optional fields without defaults are set to zero or something like it.
  expect(eq(0, message.get_extension(protobuf_unittest::optional_int32_extension()).value()));
  expect(eq(0, message.get_extension(protobuf_unittest::optional_int64_extension()).value()));
  expect(eq(0, message.get_extension(protobuf_unittest::optional_uint32_extension()).value()));
  expect(eq(0, message.get_extension(protobuf_unittest::optional_uint64_extension()).value()));
  expect(eq(0, message.get_extension(protobuf_unittest::optional_sint32_extension()).value()));
  expect(eq(0, message.get_extension(protobuf_unittest::optional_sint64_extension()).value()));
  expect(eq(0, message.get_extension(protobuf_unittest::optional_fixed32_extension()).value()));
  expect(eq(0, message.get_extension(protobuf_unittest::optional_fixed64_extension()).value()));
  expect(eq(0, message.get_extension(protobuf_unittest::optional_sfixed32_extension()).value()));
  expect(eq(0, message.get_extension(protobuf_unittest::optional_sfixed64_extension()).value()));
  expect(eq(0, message.get_extension(protobuf_unittest::optional_float_extension()).value()));
  expect(eq(0.0, message.get_extension(protobuf_unittest::optional_double_extension()).value()));
  expect(eq(0.0F, message.get_extension(protobuf_unittest::optional_bool_extension()).value()));
  expect(eq(""s, message.get_extension(protobuf_unittest::optional_string_extension()).value()));
  expect(eq(""_bytes, message.get_extension(protobuf_unittest::optional_bytes_extension()).value()));

  // Embedded messages should also be clear.
  expect(!message.get_extension(protobuf_unittest::optionalgroup_extension()).has_value());
  expect(!message.get_extension(protobuf_unittest::optional_nested_message_extension()).has_value());
  expect(!message.get_extension(protobuf_unittest::optional_foreign_message_extension()).has_value());
  expect(!message.get_extension(protobuf_unittest::optional_import_message_extension()).has_value());
  expect(!message.get_extension(protobuf_unittest::optional_public_import_message_extension()).has_value());
  expect(!message.get_extension(protobuf_unittest::optional_lazy_message_extension()).has_value());

  // Enums without defaults are set to the first value in the enum.
  expect(protobuf_unittest::TestAllTypes::NestedEnum::FOO ==
         message.get_extension(protobuf_unittest::optional_nested_enum_extension()).value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO ==
         message.get_extension(protobuf_unittest::optional_foreign_enum_extension()).value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO ==
         message.get_extension(protobuf_unittest::optional_import_enum_extension()).value());

  expect(eq(""s, message.get_extension(protobuf_unittest::optional_string_piece_extension()).value()));
  expect(eq(""s, message.get_extension(protobuf_unittest::optional_cord_extension()).value()));

  // Repeated fields are empty.
  expect(!message.has_extension(protobuf_unittest::repeated_int32_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_int64_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_uint32_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_uint64_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_sint32_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_sint64_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_fixed32_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_fixed64_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_sfixed32_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_sfixed64_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_float_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_double_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_bool_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_string_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_bytes_extension()));

  expect(!message.has_extension(protobuf_unittest::repeatedgroup_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_nested_message_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_foreign_message_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_import_message_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_lazy_message_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_nested_enum_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_foreign_enum_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_import_enum_extension()));

  expect(!message.has_extension(protobuf_unittest::repeated_string_piece_extension()));
  expect(!message.has_extension(protobuf_unittest::repeated_cord_extension()));

  //.blah.has_value() should also be false for all default fields.
  expect(!message.has_extension(protobuf_unittest::default_int32_extension()));
  expect(!message.has_extension(protobuf_unittest::default_int64_extension()));
  expect(!message.has_extension(protobuf_unittest::default_uint32_extension()));
  expect(!message.has_extension(protobuf_unittest::default_uint64_extension()));
  expect(!message.has_extension(protobuf_unittest::default_sint32_extension()));
  expect(!message.has_extension(protobuf_unittest::default_sint64_extension()));
  expect(!message.has_extension(protobuf_unittest::default_fixed32_extension()));
  expect(!message.has_extension(protobuf_unittest::default_fixed64_extension()));
  expect(!message.has_extension(protobuf_unittest::default_sfixed32_extension()));
  expect(!message.has_extension(protobuf_unittest::default_sfixed64_extension()));
  expect(!message.has_extension(protobuf_unittest::default_float_extension()));
  expect(!message.has_extension(protobuf_unittest::default_double_extension()));
  expect(!message.has_extension(protobuf_unittest::default_bool_extension()));
  expect(!message.has_extension(protobuf_unittest::default_string_extension()));
  expect(!message.has_extension(protobuf_unittest::default_bytes_extension()));

  expect(!message.has_extension(protobuf_unittest::default_nested_enum_extension()));
  expect(!message.has_extension(protobuf_unittest::default_foreign_enum_extension()));
  expect(!message.has_extension(protobuf_unittest::default_import_enum_extension()));

  expect(!message.has_extension(protobuf_unittest::default_string_piece_extension()));
  expect(!message.has_extension(protobuf_unittest::default_cord_extension()));

  // Fields with defaults have their default values (duh).
  expect(eq(41, message.get_extension(protobuf_unittest::default_int32_extension()).value()));
  expect(eq(42, message.get_extension(protobuf_unittest::default_int64_extension()).value()));
  expect(eq(43, message.get_extension(protobuf_unittest::default_uint32_extension()).value()));
  expect(eq(44, message.get_extension(protobuf_unittest::default_uint64_extension()).value()));
  expect(eq(-45, message.get_extension(protobuf_unittest::default_sint32_extension()).value()));
  expect(eq(46, message.get_extension(protobuf_unittest::default_sint64_extension()).value()));
  expect(eq(47, message.get_extension(protobuf_unittest::default_fixed32_extension()).value()));
  expect(eq(48, message.get_extension(protobuf_unittest::default_fixed64_extension()).value()));
  expect(eq(49, message.get_extension(protobuf_unittest::default_sfixed32_extension()).value()));
  expect(eq(-50, message.get_extension(protobuf_unittest::default_sfixed64_extension()).value()));
  expect(eq(51.5, message.get_extension(protobuf_unittest::default_float_extension()).value()));
  expect(eq(52e3, message.get_extension(protobuf_unittest::default_double_extension()).value()));
  expect(message.get_extension(protobuf_unittest::default_bool_extension()).value());
  expect(eq("hello"s, message.get_extension(protobuf_unittest::default_string_extension()).value()));
  expect(eq("world"_bytes, message.get_extension(protobuf_unittest::default_bytes_extension()).value()));

  expect(protobuf_unittest::TestAllTypes::NestedEnum::BAR ==
         message.get_extension(protobuf_unittest::default_nested_enum_extension()).value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR ==
         message.get_extension(protobuf_unittest::default_foreign_enum_extension()).value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_BAR ==
         message.get_extension(protobuf_unittest::default_import_enum_extension()).value());

  expect(eq("abc"s, message.get_extension(protobuf_unittest::default_string_piece_extension()).value()));
  expect(eq("123"s, message.get_extension(protobuf_unittest::default_cord_extension()).value()));

  expect(!message.has_extension(protobuf_unittest::oneof_uint32_extension()));
  expect(!message.has_extension(protobuf_unittest::oneof_nested_message_extension()));
  expect(!message.has_extension(protobuf_unittest::oneof_string_extension()));
  expect(!message.has_extension(protobuf_unittest::oneof_bytes_extension()));
}
// -------------------------------------------------------------------

inline void SetAll(protobuf_unittest::TestPackedExtensions *message) {
  expect(message->set_extension(protobuf_unittest::packed_int32_extension(), {601, 701}).ok());
  expect(message->set_extension(protobuf_unittest::packed_int64_extension(), {602, 702}).ok());
  expect(message->set_extension(protobuf_unittest::packed_uint32_extension(), {603, 703}).ok());
  expect(message->set_extension(protobuf_unittest::packed_uint64_extension(), {604, 704}).ok());
  expect(message->set_extension(protobuf_unittest::packed_sint32_extension(), {605, 705}).ok());
  expect(message->set_extension(protobuf_unittest::packed_sint64_extension(), {606, 706}).ok());
  expect(message->set_extension(protobuf_unittest::packed_fixed32_extension(), {607, 707}).ok());
  expect(message->set_extension(protobuf_unittest::packed_fixed64_extension(), {608, 708}).ok());
  expect(message->set_extension(protobuf_unittest::packed_sfixed32_extension(), {609, 709}).ok());
  expect(message->set_extension(protobuf_unittest::packed_sfixed64_extension(), {610, 710}).ok());
  expect(message->set_extension(protobuf_unittest::packed_float_extension(), {611, 711}).ok());
  expect(message->set_extension(protobuf_unittest::packed_double_extension(), {612, 712}).ok());
  expect(message->set_extension(protobuf_unittest::packed_bool_extension(), {true, false}).ok());
  expect(message->set_extension(
      protobuf_unittest::packed_enum_extension(),
      {protobuf_unittest::ForeignEnum::FOREIGN_BAR, protobuf_unittest::ForeignEnum::FOREIGN_BAZ}).ok());
}

// -------------------------------------------------------------------

inline void ExpectAllSet(const protobuf_unittest::TestPackedExtensions &message) {
  expect(
      eq(message.get_extension(protobuf_unittest::packed_int32_extension()).value(), std::vector<int32_t>{601, 701}));
  expect(
      eq(message.get_extension(protobuf_unittest::packed_int64_extension()).value(), std::vector<int64_t>{602, 702}));
  expect(
      eq(message.get_extension(protobuf_unittest::packed_uint32_extension()).value(), std::vector<uint32_t>{603, 703}));
  expect(
      eq(message.get_extension(protobuf_unittest::packed_uint64_extension()).value(), std::vector<uint64_t>{604, 704}));
  expect(
      eq(message.get_extension(protobuf_unittest::packed_sint32_extension()).value(), std::vector<int32_t>{605, 705}));
  expect(
      eq(message.get_extension(protobuf_unittest::packed_sint64_extension()).value(), std::vector<int64_t>{606, 706}));
  expect(eq(message.get_extension(protobuf_unittest::packed_fixed32_extension()).value(),
            std::vector<uint32_t>{607, 707}));
  expect(eq(message.get_extension(protobuf_unittest::packed_fixed64_extension()).value(),
            std::vector<uint64_t>{608, 708}));
  expect(eq(message.get_extension(protobuf_unittest::packed_sfixed32_extension()).value(),
            std::vector<int32_t>{609, 709}));
  expect(eq(message.get_extension(protobuf_unittest::packed_sfixed64_extension()).value(),
            std::vector<int64_t>{610, 710}));
  expect(eq(message.get_extension(protobuf_unittest::packed_float_extension()).value(), std::vector<float>{611, 711}));
  expect(
      eq(message.get_extension(protobuf_unittest::packed_double_extension()).value(), std::vector<double>{612, 712}));
  expect(eq(message.get_extension(protobuf_unittest::packed_bool_extension()).value(),
            std::vector<hpp::proto::boolean>{true, false}));

  expect(message.get_extension(protobuf_unittest::packed_enum_extension()).value() ==
         std::vector<protobuf_unittest::ForeignEnum>{protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                     protobuf_unittest::ForeignEnum::FOREIGN_BAZ});
}

// -------------------------------------------------------------------

inline void ExpectAllSet(const protobuf_unittest::TestUnpackedExtensions &message) {
  expect(
      eq(message.get_extension(protobuf_unittest::unpacked_int32_extension()).value(), std::vector<int32_t>{601, 701}));
  expect(
      eq(message.get_extension(protobuf_unittest::unpacked_int64_extension()).value(), std::vector<int64_t>{602, 702}));
  expect(eq(message.get_extension(protobuf_unittest::unpacked_uint32_extension()).value(),
            std::vector<uint32_t>{603, 703}));
  expect(eq(message.get_extension(protobuf_unittest::unpacked_uint64_extension()).value(),
            std::vector<uint64_t>{604, 704}));
  expect(eq(message.get_extension(protobuf_unittest::unpacked_sint32_extension()).value(),
            std::vector<int32_t>{605, 705}));
  expect(eq(message.get_extension(protobuf_unittest::unpacked_sint64_extension()).value(),
            std::vector<int64_t>{606, 706}));
  expect(eq(message.get_extension(protobuf_unittest::unpacked_fixed32_extension()).value(),
            std::vector<uint32_t>{607, 707}));
  expect(eq(message.get_extension(protobuf_unittest::unpacked_fixed64_extension()).value(),
            std::vector<uint64_t>{608, 708}));
  expect(eq(message.get_extension(protobuf_unittest::unpacked_sfixed32_extension()).value(),
            std::vector<int32_t>{609, 709}));
  expect(eq(message.get_extension(protobuf_unittest::unpacked_sfixed64_extension()).value(),
            std::vector<int64_t>{610, 710}));
  expect(
      eq(message.get_extension(protobuf_unittest::unpacked_float_extension()).value(), std::vector<float>{611, 711}));
  expect(
      eq(message.get_extension(protobuf_unittest::unpacked_double_extension()).value(), std::vector<double>{612, 712}));
  expect(eq(message.get_extension(protobuf_unittest::unpacked_bool_extension()).value(),
            std::vector<hpp::proto::boolean>{true, false}));

  expect(message.get_extension(protobuf_unittest::unpacked_enum_extension()).value() ==
         std::vector<protobuf_unittest::ForeignEnum>{protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                     protobuf_unittest::ForeignEnum::FOREIGN_BAZ});
}

inline void SetOneof1(protobuf_unittest::TestOneof2 *message) {
  message->foo.emplace<protobuf_unittest::TestOneof2::foo_lazy_message>().moo_int = 100;
  message->bar.emplace<protobuf_unittest::TestOneof2::bar_string>("101");
  message->baz_int = 102;
  message->baz_string = "103";
}

inline void SetOneof2(protobuf_unittest::TestOneof2 *message) {
  message->foo.emplace<protobuf_unittest::TestOneof2::foo_int>(200);
  message->bar.emplace<protobuf_unittest::TestOneof2::bar_enum>(protobuf_unittest::TestOneof2::NestedEnum::BAZ);
  message->baz_int = 202;
  message->baz_string = "203";
}

inline void ExpectOneofSet1(const protobuf_unittest::TestOneof2 &message) {
  expect(fatal(eq(protobuf_unittest::TestOneof2::foo_lazy_message, message.foo.index())));
  const auto &foo_lazy_message = std::get<protobuf_unittest::TestOneof2::foo_lazy_message>(message.foo);

  expect(fatal(eq(protobuf_unittest::TestOneof2::bar_string, message.bar.index())));

  expect(fatal(eq(0, foo_lazy_message.corge_int.size())));

  expect(eq(100, foo_lazy_message.moo_int.value()));
  expect(eq("101"s, std::get<protobuf_unittest::TestOneof2::bar_string>(message.bar)));
  expect(eq(102, message.baz_int.value()));
  expect(eq("103"s, message.baz_string.value()));
}

inline void ExpectOneofSet2(const protobuf_unittest::TestOneof2 &message) {
  expect(eq(protobuf_unittest::TestOneof2::foo_int, message.foo.index()));
  expect(eq(protobuf_unittest::TestOneof2::bar_enum, message.bar.index()));

  expect(eq(200, std::get<protobuf_unittest::TestOneof2::foo_int>(message.foo)));
  expect(protobuf_unittest::TestOneof2::NestedEnum::BAZ ==
         std::get<protobuf_unittest::TestOneof2::bar_enum>(message.bar));
  expect(eq(202, message.baz_int.value()));
  expect(eq("203"s, message.baz_string.value()));
}

inline void ExpectOneofClear(const protobuf_unittest::TestOneof2 &message) {
  expect(!message.baz_int.has_value());
  expect(!message.baz_string.has_value());

  expect(eq(0, message.foo.index()));
  expect(eq(0, message.bar.index()));
}

} // namespace TestUtil

inline std::string unittest_proto2_descriptorset() {
  std::ifstream in("unittest_proto2.bin", std::ios::in | std::ios::binary);
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(in.tellg());
  in.seekg(0, std::ios::beg);
  in.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  return contents;
}