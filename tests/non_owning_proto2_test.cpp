#include "gpb_proto_json/gpb_proto_json.h"
#include "test_util.h"
#include <boost/ut.hpp>
#include <non_owning/google/protobuf/unittest.glz.hpp>
#include <non_owning/google/protobuf/unittest.pb.hpp>

template <typename T>
  requires requires { glz::meta<T>::value; }
std::ostream &operator<<(std::ostream &os, const T &v) {
  return os << hpp::proto::write_json(v).value();
}

namespace TestUtil {
using namespace std::literals::string_view_literals;
using namespace hpp::proto::literals;
using namespace boost::ut;
using namespace non_owning;

// Set every field in the message to a unique value.
inline void SetAll(protobuf_unittest::TestAllTypes *message, monotonic_buffer_resource &mr);
inline void SetOptionalFields(protobuf_unittest::TestAllTypes *message);
inline void SetRepeatedFields(protobuf_unittest::TestAllTypes *message);
inline void SetDefaultFields(protobuf_unittest::TestAllTypes *message);
inline void SetOneofFields(protobuf_unittest::TestAllTypes *message);
inline void SetAll(protobuf_unittest::TestAllExtensions *message, monotonic_buffer_resource &mr);
inline void SetOneofFields(protobuf_unittest::TestAllExtensions *message, monotonic_buffer_resource &mr);
inline void SetAllFieldsAndExtensions(protobuf_unittest::TestFieldOrderings *message, monotonic_buffer_resource &mr);
inline void SetAll(protobuf_unittest::TestPackedTypes *message, monotonic_buffer_resource &mr);
inline void SetAll(protobuf_unittest::TestPackedExtensions *message, monotonic_buffer_resource &mr);
inline void SetAll(protobuf_unittest::TestUnpackedTypes *message, monotonic_buffer_resource &mr);
inline void SetOneof1(protobuf_unittest::TestOneof2 *message);
inline void SetOneof2(protobuf_unittest::TestOneof2 *message);

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

// Check that all fields have their default values.
inline void ExpectClear(const protobuf_unittest::TestAllTypes &message);
inline void ExpectClear(const protobuf_unittest::TestAllExtensions &message);
inline void ExpectOneofClear(const protobuf_unittest::TestOneof2 &message);

inline void SetAll(protobuf_unittest::TestAllTypes *message, monotonic_buffer_resource & /*unused*/) {
  SetOptionalFields(message);
  SetRepeatedFields(message);
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
  message->optional_float = 111.0f;
  message->optional_double = 112;
  message->optional_bool = true;
  message->optional_string = "115";
  message->optional_bytes = "116"_bytes_view;

  message->optionalgroup = protobuf_unittest::TestAllTypes::OptionalGroup{.a = 117};
  message->optional_nested_message = protobuf_unittest::TestAllTypes::NestedMessage{.bb = 118};
  message->optional_foreign_message.emplace().c = 119;
  message->optional_import_message.emplace().d = 120;
  message->optional_public_import_message.emplace().e = 126;
  message->optional_lazy_message = protobuf_unittest::TestAllTypes::NestedMessage{.bb = 127};
  message->optional_unverified_lazy_message = protobuf_unittest::TestAllTypes::NestedMessage{.bb = 128};

  message->optional_nested_enum = protobuf_unittest::TestAllTypes::NestedEnum::BAZ;
  message->optional_foreign_enum = protobuf_unittest::ForeignEnum::FOREIGN_BAZ;
  message->optional_import_enum = protobuf_unittest_import::ImportEnum::IMPORT_BAZ;
}

// -------------------------------------------------------------------

inline void SetRepeatedFields(protobuf_unittest::TestAllTypes *message) {
  const static int32_t repeated_int32[] = {201, 301};
  message->repeated_int32 = repeated_int32;
  const static int64_t repeated_int64[] = {202LL, 302LL};
  message->repeated_int64 = repeated_int64;
  const static uint32_t repeated_uint32[] = {203U, 303U};
  message->repeated_uint32 = repeated_uint32;
  const static uint64_t repeated_uint64[] = {204ULL, 304ULL};
  message->repeated_uint64 = repeated_uint64;
  const static int32_t repeated_sint32[] = {205, 305};
  message->repeated_sint32 = repeated_sint32;
  const static int64_t repeated_sint64[] = {206LL, 306LL};
  message->repeated_sint64 = repeated_sint64;

  const static uint32_t repeated_fixed32[] = {207U, 307U};
  message->repeated_fixed32 = repeated_fixed32;
  const static uint64_t repeated_fixed64[] = {208ULL, 308ULL};
  message->repeated_fixed64 = repeated_fixed64;
  const static int32_t repeated_sfixed32[] = {209, 309};
  message->repeated_sfixed32 = repeated_sfixed32;
  const static int64_t repeated_sfixed64[] = {210LL, 310LL};
  message->repeated_sfixed64 = repeated_sfixed64;
  const static float repeated_float[] = {211.F, 311.F};
  message->repeated_float = repeated_float;
  const static double repeated_double[] = {212., 312.};
  message->repeated_double = repeated_double;
  const static bool repeated_bool[] = {true, false};
  message->repeated_bool = repeated_bool;

  const static std::string_view repeated_string[] = {"215"sv, "315"sv};
  message->repeated_string = repeated_string;
  const static hpp::proto::bytes_view repeated_bytes[] = {"216"_bytes_view, "316"_bytes_view};
  message->repeated_bytes = repeated_bytes;

  const static protobuf_unittest::TestAllTypes::RepeatedGroup repeatedgroup[] = {{.a = 217}, {.a = 317}};
  message->repeatedgroup = repeatedgroup;
  const static protobuf_unittest::TestAllTypes::NestedMessage repeated_nested_message[] = {{.bb = 218}, {.bb = 318}};
  message->repeated_nested_message = repeated_nested_message;

  const static protobuf_unittest::ForeignMessage repeated_foreign_message[] = {{.c = 219}, {.c = 319}};
  message->repeated_foreign_message = repeated_foreign_message;
  const static non_owning::protobuf_unittest_import::ImportMessage repeated_import_message[] = {{.d = 220}, {.d = 320}};
  message->repeated_import_message = repeated_import_message;
  const static protobuf_unittest::TestAllTypes::NestedMessage repeated_lazy_message[] = {{.bb = 227}, {.bb = 327}};
  message->repeated_lazy_message = repeated_lazy_message;

  const static protobuf_unittest::TestAllTypes::NestedEnum repeated_nested_enum[] = {
      protobuf_unittest::TestAllTypes::NestedEnum::BAR, protobuf_unittest::TestAllTypes::NestedEnum::BAZ};
  message->repeated_nested_enum = repeated_nested_enum;
  const static protobuf_unittest::ForeignEnum repeated_foreign_enum[] = {protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                                         protobuf_unittest::ForeignEnum::FOREIGN_BAZ};
  message->repeated_foreign_enum = repeated_foreign_enum;
  const static protobuf_unittest_import::ImportEnum repeated_import_enum[] = {
      protobuf_unittest_import::ImportEnum::IMPORT_BAR, protobuf_unittest_import::ImportEnum::IMPORT_BAZ};
  message->repeated_import_enum = repeated_import_enum;
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
  message->default_float = 411;
  message->default_double = 412;
  message->default_bool = false;
  message->default_string = "415";
  message->default_bytes = "416"_bytes_view;

  message->default_nested_enum = protobuf_unittest::TestAllTypes::NestedEnum::FOO;
  message->default_foreign_enum = protobuf_unittest::ForeignEnum::FOREIGN_FOO;
  message->default_import_enum = protobuf_unittest_import::ImportEnum::IMPORT_FOO;
}

// ------------------------------------------------------------------
inline void SetOneofFields(protobuf_unittest::TestAllTypes *message) {
  message->oneof_field = 601U;
  message->oneof_field = protobuf_unittest::TestAllTypes::NestedMessage{.bb = 602};
  message->oneof_field = "603";
  message->oneof_field = "604"_bytes_view;
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

  expect(eq("115"sv, message.optional_string.value()));
  expect(ranges_equal("116"_bytes, message.optional_bytes.value()));

  expect(message.optionalgroup.has_value() && 117 == message.optionalgroup->a.value());
  expect(message.optional_nested_message.has_value() && 118 == message.optional_nested_message->bb.value());
  expect(message.optional_foreign_message.has_value() && 119 == message.optional_foreign_message->c.value());
  expect(message.optional_import_message.has_value() && 120 == message.optional_import_message->d.value());
  expect(message.optional_public_import_message.has_value() &&
         126 == message.optional_public_import_message->e.value());
  expect(message.optional_lazy_message.has_value() && 127 == message.optional_lazy_message->bb.value());
  expect(message.optional_unverified_lazy_message.has_value() &&
         128 == message.optional_unverified_lazy_message->bb.value());

  expect(protobuf_unittest::TestAllTypes::NestedEnum::BAZ == message.optional_nested_enum.value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == message.optional_foreign_enum.value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_BAZ == message.optional_import_enum.value());

  // -----------------------------------------------------------------
  expect(eq(2, message.repeated_int32.size()) >> fatal);
  expect(eq(2, message.repeated_int64.size()) >> fatal);
  expect(eq(2, message.repeated_uint32.size()) >> fatal);
  expect(eq(2, message.repeated_uint64.size()) >> fatal);
  expect(eq(2, message.repeated_sint32.size()) >> fatal);
  expect(eq(2, message.repeated_sint64.size()) >> fatal);
  expect(eq(2, message.repeated_fixed32.size()) >> fatal);
  expect(eq(2, message.repeated_fixed64.size()) >> fatal);
  expect(eq(2, message.repeated_sfixed32.size()) >> fatal);
  expect(eq(2, message.repeated_sfixed64.size()) >> fatal);
  expect(eq(2, message.repeated_float.size()) >> fatal);
  expect(eq(2, message.repeated_double.size()) >> fatal);
  expect(eq(2, message.repeated_bool.size()) >> fatal);
  expect(eq(2, message.repeated_string.size()) >> fatal);
  expect(eq(2, message.repeated_bytes.size()) >> fatal);

  expect(eq(2, message.repeatedgroup.size()) >> fatal);
  expect(eq(2, message.repeated_nested_message.size()) >> fatal);
  expect(eq(2, message.repeated_foreign_message.size()) >> fatal);
  expect(eq(2, message.repeated_import_message.size()) >> fatal);
  expect(eq(2, message.repeated_lazy_message.size()) >> fatal);
  expect(eq(2, message.repeated_nested_enum.size()) >> fatal);
  expect(eq(2, message.repeated_foreign_enum.size()) >> fatal);
  expect(eq(2, message.repeated_import_enum.size()) >> fatal);

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
  expect(eq("215"sv, message.repeated_string[0]));
  expect(ranges_equal("216"_bytes, message.repeated_bytes[0]));

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
  expect(eq("315"sv, message.repeated_string[1]));
  expect(ranges_equal("316"_bytes, message.repeated_bytes[1]));

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
  expect(eq("415"sv, message.default_string.value()));
  expect(ranges_equal("416"_bytes, message.default_bytes.value()));

  expect(protobuf_unittest::TestAllTypes::NestedEnum::FOO == message.default_nested_enum.value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO == message.default_foreign_enum.value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO == message.default_import_enum.value());

  expect(message.oneof_field.index() == protobuf_unittest::TestAllTypes::oneof_bytes);

  expect(ranges_equal("604"_bytes, std::get<protobuf_unittest::TestAllTypes::oneof_bytes>(message.oneof_field)));
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
  expect(!message.optional_unverified_lazy_message.has_value());

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
  expect(eq("hello"sv, message.default_string.value_or_default()));
  expect(ranges_equal("world"_bytes, message.default_bytes.value_or_default()));

  expect(!message.default_nested_enum.has_value());
  expect(protobuf_unittest::TestAllTypes::NestedEnum::BAR == message.default_nested_enum.value_or_default());
  expect(!message.default_foreign_enum.has_value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == message.default_foreign_enum.value_or_default());
  expect(!message.default_import_enum.has_value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_BAR == message.default_import_enum.value_or_default());

  expect(std::holds_alternative<std::monostate>(message.oneof_field));
}

// -------------------------------------------------------------------

inline void SetAll(protobuf_unittest::TestPackedTypes *message, monotonic_buffer_resource & /*unused*/) {
  const static int32_t packed_int32[] = {601, 701};
  message->packed_int32 = packed_int32;

  const static int64_t packed_int64[] = {602, 702};
  message->packed_int64 = packed_int64;

  const static uint32_t packed_uint32[] = {603, 703};
  message->packed_uint32 = packed_uint32;

  const static uint64_t packed_uint64[] = {604, 704};
  message->packed_uint64 = packed_uint64;

  const static int32_t packed_sint32[] = {605, 705};
  message->packed_sint32 = packed_sint32;

  const static int64_t packed_sint64[] = {606, 706};
  message->packed_sint64 = packed_sint64;

  const static uint32_t packed_fixed32[] = {607, 707};
  message->packed_fixed32 = packed_fixed32;

  const static uint64_t packed_fixed64[] = {608, 708};
  message->packed_fixed64 = packed_fixed64;

  const static int32_t packed_sfixed32[] = {609, 709};
  message->packed_sfixed32 = packed_sfixed32;

  const static int64_t packed_sfixed64[] = {610, 710};
  message->packed_sfixed64 = packed_sfixed64;

  const static float packed_float[] = {611, 711};
  message->packed_float = packed_float;

  const static double packed_double[] = {612, 712};
  message->packed_double = packed_double;

  const static bool packed_bool[] = {true, false};
  message->packed_bool = packed_bool;
  const static protobuf_unittest::ForeignEnum packed_enum[] = {protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                               protobuf_unittest::ForeignEnum::FOREIGN_BAZ};
  message->packed_enum = packed_enum;
}

inline void SetAll(protobuf_unittest::TestUnpackedTypes *message, monotonic_buffer_resource & /*unused*/) {
  // The values applied here must match those of SetPackedFields.

  const static int32_t unpacked_int32[] = {601, 701};
  message->unpacked_int32 = unpacked_int32;

  const static int64_t unpacked_int64[] = {602, 702};
  message->unpacked_int64 = unpacked_int64;

  const static uint32_t unpacked_uint32[] = {603, 703};
  message->unpacked_uint32 = unpacked_uint32;

  const static uint64_t unpacked_uint64[] = {604, 704};
  message->unpacked_uint64 = unpacked_uint64;

  const static int32_t unpacked_sint32[] = {605, 705};
  message->unpacked_sint32 = unpacked_sint32;

  const static int64_t unpacked_sint64[] = {606, 706};
  message->unpacked_sint64 = unpacked_sint64;

  const static uint32_t unpacked_fixed32[] = {607, 707};
  message->unpacked_fixed32 = unpacked_fixed32;

  const static uint64_t unpacked_fixed64[] = {608, 708};
  message->unpacked_fixed64 = unpacked_fixed64;

  const static int32_t unpacked_sfixed32[] = {609, 709};
  message->unpacked_sfixed32 = unpacked_sfixed32;

  const static int64_t unpacked_sfixed64[] = {610, 710};
  message->unpacked_sfixed64 = unpacked_sfixed64;

  const static float unpacked_float[] = {611, 711};
  message->unpacked_float = unpacked_float;

  const static double unpacked_double[] = {612, 712};
  message->unpacked_double = unpacked_double;

  const static bool unpacked_bool[] = {true, false};
  message->unpacked_bool = unpacked_bool;
  const static protobuf_unittest::ForeignEnum unpacked_enum[] = {protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                                 protobuf_unittest::ForeignEnum::FOREIGN_BAZ};
  message->unpacked_enum = unpacked_enum;
}

// -------------------------------------------------------------------

inline void ExpectAllSet(const protobuf_unittest::TestPackedTypes &message) {
  expect(eq(2, message.packed_int32.size()) >> fatal);
  expect(eq(2, message.packed_int64.size()) >> fatal);
  expect(eq(2, message.packed_uint32.size()) >> fatal);
  expect(eq(2, message.packed_uint64.size()) >> fatal);
  expect(eq(2, message.packed_sint32.size()) >> fatal);
  expect(eq(2, message.packed_sint64.size()) >> fatal);
  expect(eq(2, message.packed_fixed32.size()) >> fatal);
  expect(eq(2, message.packed_fixed64.size()) >> fatal);
  expect(eq(2, message.packed_sfixed32.size()) >> fatal);
  expect(eq(2, message.packed_sfixed64.size()) >> fatal);
  expect(eq(2, message.packed_float.size()) >> fatal);
  expect(eq(2, message.packed_double.size()) >> fatal);
  expect(eq(2, message.packed_bool.size()) >> fatal);
  expect(eq(2, message.packed_enum.size()) >> fatal);

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
  // The values expected here must match those of ExpectPackedFieldsSet.
  expect(eq(2, message.unpacked_int32.size()) >> fatal);
  expect(eq(2, message.unpacked_int64.size()) >> fatal);
  expect(eq(2, message.unpacked_uint32.size()) >> fatal);
  expect(eq(2, message.unpacked_uint64.size()) >> fatal);
  expect(eq(2, message.unpacked_sint32.size()) >> fatal);
  expect(eq(2, message.unpacked_sint64.size()) >> fatal);
  expect(eq(2, message.unpacked_fixed32.size()) >> fatal);
  expect(eq(2, message.unpacked_fixed64.size()) >> fatal);
  expect(eq(2, message.unpacked_sfixed32.size()) >> fatal);
  expect(eq(2, message.unpacked_sfixed64.size()) >> fatal);
  expect(eq(2, message.unpacked_float.size()) >> fatal);
  expect(eq(2, message.unpacked_double.size()) >> fatal);
  expect(eq(2, message.unpacked_bool.size()) >> fatal);
  expect(eq(2, message.unpacked_enum.size()) >> fatal);

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

inline void SetAll(protobuf_unittest::TestAllExtensions *message, monotonic_buffer_resource &mr) {
  expect(!message->set_extension(protobuf_unittest::optional_int32_extension(), 101, mr));
  expect(!message->set_extension(protobuf_unittest::optional_int64_extension(), 102, mr));
  expect(!message->set_extension(protobuf_unittest::optional_uint32_extension(), 103, mr));
  expect(!message->set_extension(protobuf_unittest::optional_uint64_extension(), 104, mr));
  expect(!message->set_extension(protobuf_unittest::optional_sint32_extension(), 105, mr));
  expect(!message->set_extension(protobuf_unittest::optional_sint64_extension(), 106, mr));
  expect(!message->set_extension(protobuf_unittest::optional_fixed32_extension(), 107, mr));
  expect(!message->set_extension(protobuf_unittest::optional_fixed64_extension(), 108, mr));
  expect(!message->set_extension(protobuf_unittest::optional_sfixed32_extension(), 109, mr));
  expect(!message->set_extension(protobuf_unittest::optional_sfixed64_extension(), 110, mr));
  expect(!message->set_extension(protobuf_unittest::optional_float_extension(), 111, mr));
  expect(!message->set_extension(protobuf_unittest::optional_double_extension(), 112, mr));
  expect(!message->set_extension(protobuf_unittest::optional_bool_extension(), true, mr));
  expect(!message->set_extension(protobuf_unittest::optional_string_extension(), "115", mr));
  expect(!message->set_extension(protobuf_unittest::optional_bytes_extension(), "116"_bytes_view, mr));

  expect(!message->set_extension(protobuf_unittest::optionalgroup_extension(), {.a = 117}, mr));
  expect(!message->set_extension(protobuf_unittest::optional_nested_message_extension(), {.bb = 118}, mr));
  expect(!message->set_extension(protobuf_unittest::optional_foreign_message_extension(), {.c = 119}, mr));
  expect(!message->set_extension(protobuf_unittest::optional_import_message_extension(), {.d = 120}, mr));

  expect(!message->set_extension(protobuf_unittest::optional_nested_enum_extension(),
                                 protobuf_unittest::TestAllTypes::NestedEnum::BAZ, mr));
  expect(!message->set_extension(protobuf_unittest::optional_foreign_enum_extension(),
                                 protobuf_unittest::ForeignEnum::FOREIGN_BAZ, mr));
  expect(!message->set_extension(protobuf_unittest::optional_import_enum_extension(),
                                 protobuf_unittest_import::ImportEnum::IMPORT_BAZ, mr));

  expect(!message->set_extension(protobuf_unittest::optional_string_piece_extension(), "124", mr));
  expect(!message->set_extension(protobuf_unittest::optional_cord_extension(), "125", mr));

  expect(!message->set_extension(protobuf_unittest::optional_public_import_message_extension(), {.e = 126}, mr));
  expect(!message->set_extension(protobuf_unittest::optional_lazy_message_extension(), {.bb = 127}, mr));
  expect(!message->set_extension(protobuf_unittest::optional_unverified_lazy_message_extension(), {.bb = 128}, mr));

  // -----------------------------------------------------------------

  const static int32_t repeated_int32_extension[] = {201, 301};
  expect(!message->set_extension(protobuf_unittest::repeated_int32_extension(), repeated_int32_extension, mr));
  const static int64_t repeated_int64_extension[] = {202, 302};
  expect(!message->set_extension(protobuf_unittest::repeated_int64_extension(), repeated_int64_extension, mr));
  const static uint32_t repeated_uint32_extension[] = {203, 303};
  expect(!message->set_extension(protobuf_unittest::repeated_uint32_extension(), repeated_uint32_extension, mr));
  const static uint64_t repeated_uint64_extension[] = {204, 304};
  expect(!message->set_extension(protobuf_unittest::repeated_uint64_extension(), repeated_uint64_extension, mr));
  const static int32_t repeated_sint32_extension[] = {205, 305};
  expect(!message->set_extension(protobuf_unittest::repeated_sint32_extension(), repeated_sint32_extension, mr));
  const static int64_t repeated_sint64_extension[] = {206, 306};
  expect(!message->set_extension(protobuf_unittest::repeated_sint64_extension(), repeated_sint64_extension, mr));
  const static uint32_t repeated_fixed32_extension[] = {207, 307};
  expect(!message->set_extension(protobuf_unittest::repeated_fixed32_extension(), repeated_fixed32_extension, mr));
  const static uint64_t repeated_fixed64_extension[] = {208, 308};
  expect(!message->set_extension(protobuf_unittest::repeated_fixed64_extension(), repeated_fixed64_extension, mr));
  const static int32_t repeated_sfixed32_extension[] = {209, 309};
  expect(!message->set_extension(protobuf_unittest::repeated_sfixed32_extension(), repeated_sfixed32_extension, mr));
  const static int64_t repeated_sfixed64_extension[] = {210, 310};
  expect(!message->set_extension(protobuf_unittest::repeated_sfixed64_extension(), repeated_sfixed64_extension, mr));
  const static float repeated_float_extension[] = {211, 311};
  expect(!message->set_extension(protobuf_unittest::repeated_float_extension(), repeated_float_extension, mr));
  const static double repeated_double_extension[] = {212, 312};
  expect(!message->set_extension(protobuf_unittest::repeated_double_extension(), repeated_double_extension, mr));
  const static bool repeated_bool_extension[] = {true, false};
  expect(!message->set_extension(protobuf_unittest::repeated_bool_extension(), repeated_bool_extension, mr));
  const static std::string_view repeated_string_extension[] = {"215", "315"};
  expect(!message->set_extension(protobuf_unittest::repeated_string_extension(), repeated_string_extension, mr));
  const static std::span<const std::byte> repeated_bytes_extension[] = {"216"_bytes_view, "316"_bytes_view};
  expect(!message->set_extension(protobuf_unittest::repeated_bytes_extension(), repeated_bytes_extension, mr));

  const static protobuf_unittest::RepeatedGroup_extension repeatedgroup[] = {{.a = 217}, {.a = 317}};
  expect(!message->set_extension(protobuf_unittest::repeatedgroup_extension(), repeatedgroup, mr));
  const static protobuf_unittest::TestAllTypes::NestedMessage repeated_nested_message_extension[] = {{.bb = 218},
                                                                                                     {.bb = 318}};
  expect(!message->set_extension(protobuf_unittest::repeated_nested_message_extension(),
                                 repeated_nested_message_extension, mr));
  const static protobuf_unittest::ForeignMessage repeated_foreign_message_extension[] = {{.c = 219}, {.c = 319}};
  expect(!message->set_extension(protobuf_unittest::repeated_foreign_message_extension(),
                                 repeated_foreign_message_extension, mr));
  const static protobuf_unittest_import::ImportMessage repeated_import_message_extension[] = {{.d = 220}, {.d = 320}};
  expect(!message->set_extension(protobuf_unittest::repeated_import_message_extension(),
                                 repeated_import_message_extension, mr));
  const static protobuf_unittest::TestAllTypes::NestedMessage repeated_lazy_message_extension[] = {{.bb = 227},
                                                                                                   {.bb = 327}};
  expect(!message->set_extension(protobuf_unittest::repeated_lazy_message_extension(), repeated_lazy_message_extension,
                                 mr));

  const static protobuf_unittest::TestAllTypes::NestedEnum repeated_nested_enum[] = {
      protobuf_unittest::TestAllTypes::NestedEnum::BAR, protobuf_unittest::TestAllTypes::NestedEnum::BAZ};
  expect(!message->set_extension(protobuf_unittest::repeated_nested_enum_extension(), repeated_nested_enum, mr));
  const static protobuf_unittest::ForeignEnum repeated_foreign_enum[] = {protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                                         protobuf_unittest::ForeignEnum::FOREIGN_BAZ};
  expect(!message->set_extension(protobuf_unittest::repeated_foreign_enum_extension(), repeated_foreign_enum, mr));
  const static protobuf_unittest_import::ImportEnum repeated_import_enum[] = {
      protobuf_unittest_import::ImportEnum::IMPORT_BAR, protobuf_unittest_import::ImportEnum::IMPORT_BAZ};
  expect(!message->set_extension(protobuf_unittest::repeated_import_enum_extension(), repeated_import_enum, mr));

  const static std::string_view repeated_string_piece_extension[] = {"224"sv, "324"sv};
  expect(!message->set_extension(protobuf_unittest::repeated_string_piece_extension(), repeated_string_piece_extension,
                                 mr));
  const static std::string_view repeated_cord_extension[] = {"225"sv, "325"sv};
  expect(!message->set_extension(protobuf_unittest::repeated_cord_extension(), repeated_cord_extension, mr));

  // -----------------------------------------------------------------

  expect(!message->set_extension(protobuf_unittest::default_int32_extension(), 401, mr));
  expect(!message->set_extension(protobuf_unittest::default_int64_extension(), 402, mr));
  expect(!message->set_extension(protobuf_unittest::default_uint32_extension(), 403, mr));
  expect(!message->set_extension(protobuf_unittest::default_uint64_extension(), 404, mr));
  expect(!message->set_extension(protobuf_unittest::default_sint32_extension(), 405, mr));
  expect(!message->set_extension(protobuf_unittest::default_sint64_extension(), 406, mr));
  expect(!message->set_extension(protobuf_unittest::default_fixed32_extension(), 407, mr));
  expect(!message->set_extension(protobuf_unittest::default_fixed64_extension(), 408, mr));
  expect(!message->set_extension(protobuf_unittest::default_sfixed32_extension(), 409, mr));
  expect(!message->set_extension(protobuf_unittest::default_sfixed64_extension(), 410, mr));
  expect(!message->set_extension(protobuf_unittest::default_float_extension(), 411, mr));
  expect(!message->set_extension(protobuf_unittest::default_double_extension(), 412, mr));

  expect(!message->set_extension(protobuf_unittest::default_bool_extension(), false, mr));
  expect(!message->set_extension(protobuf_unittest::default_string_extension(), "415", mr));
  expect(!message->set_extension(protobuf_unittest::default_bytes_extension(), "416"_bytes_view, mr));

  expect(!message->set_extension(protobuf_unittest::default_nested_enum_extension(),
                                 protobuf_unittest::TestAllTypes::NestedEnum::FOO, mr));
  expect(!message->set_extension(protobuf_unittest::default_foreign_enum_extension(),
                                 protobuf_unittest::ForeignEnum::FOREIGN_FOO, mr));
  expect(!message->set_extension(protobuf_unittest::default_import_enum_extension(),
                                 protobuf_unittest_import::ImportEnum::IMPORT_FOO, mr));

  expect(!message->set_extension(protobuf_unittest::default_string_piece_extension(), "424", mr));
  expect(!message->set_extension(protobuf_unittest::default_cord_extension(), "425", mr));

  SetOneofFields(message, mr);
}

inline void SetOneofFields(protobuf_unittest::TestAllExtensions *message, monotonic_buffer_resource &mr) {
  expect(!message->set_extension(protobuf_unittest::oneof_uint32_extension(), 601, mr));
  expect(!message->set_extension(protobuf_unittest::oneof_nested_message_extension(), {.bb = 602}, mr));
  expect(!message->set_extension(protobuf_unittest::oneof_string_extension(), "603", mr));
  expect(!message->set_extension(protobuf_unittest::oneof_bytes_extension(), "604"_bytes_view, mr));
}

// -------------------------------------------------------------------

inline void SetAllFieldsAndExtensions(protobuf_unittest::TestFieldOrderings *message, monotonic_buffer_resource &mr) {
  // ABSL_CHECK(message);
  message->my_int = 1;
  message->my_string = "foo";
  message->my_float = 1.0f;
  expect(!message->set_extension(protobuf_unittest::my_extension_int(), 23, mr));
  expect(!message->set_extension(protobuf_unittest::my_extension_string(), "bar", mr));
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
  expect(message.has_extension(protobuf_unittest::optional_unverified_lazy_message_extension()));

  expect(message.get_extension(protobuf_unittest::optionalgroup_extension())->a);
  expect(message.get_extension(protobuf_unittest::optional_nested_message_extension())->bb);
  expect(message.get_extension(protobuf_unittest::optional_foreign_message_extension())->c);
  expect(message.get_extension(protobuf_unittest::optional_import_message_extension())->d);
  expect(message.get_extension(protobuf_unittest::optional_public_import_message_extension())->e);
  expect(message.get_extension(protobuf_unittest::optional_lazy_message_extension())->bb);
  expect(message.get_extension(protobuf_unittest::optional_unverified_lazy_message_extension())->bb);

  expect(message.has_extension(protobuf_unittest::optional_nested_enum_extension()));
  expect(message.has_extension(protobuf_unittest::optional_foreign_enum_extension()));
  expect(message.has_extension(protobuf_unittest::optional_import_enum_extension()));

  expect(message.has_extension(protobuf_unittest::optional_string_piece_extension()));
  expect(message.has_extension(protobuf_unittest::optional_cord_extension()));

  monotonic_buffer_resource mr(8192);

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
  expect(eq("115"sv, message.get_extension(protobuf_unittest::optional_string_extension()).value()));
  expect(ranges_equal("116"_bytes, message.get_extension(protobuf_unittest::optional_bytes_extension(), mr).value()));

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

  expect(eq("124"sv, message.get_extension(protobuf_unittest::optional_string_piece_extension()).value()));
  expect(eq("125"sv, message.get_extension(protobuf_unittest::optional_cord_extension()).value()));
  expect(
      eq(126, message.get_extension(protobuf_unittest::optional_public_import_message_extension()).value().e.value()));
  expect(eq(127, message.get_extension(protobuf_unittest::optional_lazy_message_extension()).value().bb.value()));
  expect(eq(128,
            message.get_extension(protobuf_unittest::optional_unverified_lazy_message_extension()).value().bb.value()));

  // -----------------------------------------------------------------

  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_int32_extension(), mr).value(),
                      std::vector<int32_t>{201, 301}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_int64_extension(), mr).value(),
                      std::vector<int64_t>{202, 302}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_uint32_extension(), mr).value(),
                      std::vector<uint32_t>{203, 303}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_uint64_extension(), mr).value(),
                      std::vector<uint64_t>{204, 304}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_sint32_extension(), mr).value(),
                      std::vector<int32_t>{205, 305}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_sint64_extension(), mr).value(),
                      std::vector<int64_t>{206, 306}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_fixed32_extension(), mr).value(),
                      std::vector<uint32_t>{207, 307}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_fixed64_extension(), mr).value(),
                      std::vector<uint64_t>{208, 308}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_sfixed32_extension(), mr).value(),
                      std::vector<int32_t>{209, 309}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_sfixed64_extension(), mr).value(),
                      std::vector<int64_t>{210, 310}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_float_extension(), mr).value(),
                      std::vector<float>{211, 311}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_double_extension(), mr).value(),
                      std::vector<double>{212, 312}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_bool_extension(), mr).value(),
                      std::vector<hpp::proto::boolean>{true, false}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_string_extension(), mr).value(),
                      std::vector<std::string_view>{"215"sv, "315"sv}));

  auto repeated_bytes = message.get_extension(protobuf_unittest::repeated_bytes_extension(), mr).value();
  expect(eq(2, repeated_bytes.size()));
  expect(ranges_equal(repeated_bytes[0], "216"_bytes_view));
  expect(ranges_equal(repeated_bytes[1], "316"_bytes_view));

  expect(ranges_equal(message.get_extension(protobuf_unittest::repeatedgroup_extension(), mr).value(),
                      std::vector<protobuf_unittest::RepeatedGroup_extension>{{.a = 217}, {.a = 317}},
                      [](auto x, auto y) { return x.a == y.a; }));

  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_nested_message_extension(), mr).value(),
                      std::vector<protobuf_unittest::TestAllTypes::NestedMessage>{{.bb = 218}, {.bb = 318}},
                      [](auto x, auto y) { return x.bb == y.bb; }));

  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_foreign_message_extension(), mr).value(),
                      std::vector<protobuf_unittest::ForeignMessage>{{.c = 219}, {.c = 319}},
                      [](auto x, auto y) { return x.c == y.c; }));

  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_import_message_extension(), mr).value(),
                      std::vector<protobuf_unittest_import::ImportMessage>{{.d = 220}, {.d = 320}},
                      [](auto x, auto y) { return x.d == y.d; }));

  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_lazy_message_extension(), mr).value(),
                      std::vector<protobuf_unittest::TestAllTypes::NestedMessage>{{.bb = 227}, {.bb = 327}},
                      [](auto x, auto y) { return x.bb == y.bb; }));

  expect(ranges_equal(
      message.get_extension(protobuf_unittest::repeated_nested_enum_extension(), mr).value(),
      std::vector<protobuf_unittest::TestAllTypes::NestedEnum>{protobuf_unittest::TestAllTypes::NestedEnum::BAR,
                                                               protobuf_unittest::TestAllTypes::NestedEnum::BAZ}));

  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_foreign_enum_extension(), mr).value(),
                      std::vector<protobuf_unittest::ForeignEnum>{protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                                  protobuf_unittest::ForeignEnum::FOREIGN_BAZ}));

  expect(ranges_equal(
      message.get_extension(protobuf_unittest::repeated_import_enum_extension(), mr).value(),
      std::vector<protobuf_unittest_import::ImportEnum>{protobuf_unittest_import::ImportEnum::IMPORT_BAR,
                                                        protobuf_unittest_import::ImportEnum::IMPORT_BAZ}));

  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_string_piece_extension(), mr).value(),
                      std::vector<std::string_view>{"224"sv, "324"sv}));

  expect(ranges_equal(message.get_extension(protobuf_unittest::repeated_cord_extension(), mr).value(),
                      std::vector<std::string_view>{"225"sv, "325"sv}));

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
  expect(eq("415"sv, message.get_extension(protobuf_unittest::default_string_extension()).value()));
  expect(ranges_equal("416"_bytes, message.get_extension(protobuf_unittest::default_bytes_extension(), mr).value()));

  expect(protobuf_unittest::TestAllTypes::NestedEnum::FOO ==
         message.get_extension(protobuf_unittest::default_nested_enum_extension()).value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO ==
         message.get_extension(protobuf_unittest::default_foreign_enum_extension()).value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO ==
         message.get_extension(protobuf_unittest::default_import_enum_extension()).value());

  expect(eq("424"sv, message.get_extension(protobuf_unittest::default_string_piece_extension()).value()));
  expect(eq("425"sv, message.get_extension(protobuf_unittest::default_cord_extension()).value()));

  expect(message.has_extension(protobuf_unittest::oneof_uint32_extension()));
  expect(message.get_extension(protobuf_unittest::oneof_nested_message_extension())->bb);
  expect(message.has_extension(protobuf_unittest::oneof_string_extension()));
  expect(message.has_extension(protobuf_unittest::oneof_bytes_extension()));

  expect(eq(601, message.get_extension(protobuf_unittest::oneof_uint32_extension()).value()));
  expect(eq(602, message.get_extension(protobuf_unittest::oneof_nested_message_extension())->bb.value()));
  expect(eq("603"sv, message.get_extension(protobuf_unittest::oneof_string_extension()).value()));
  expect(ranges_equal("604"_bytes_view, message.get_extension(protobuf_unittest::oneof_bytes_extension(), mr).value()));
}

// -------------------------------------------------------------------

inline void ExpectClear(const protobuf_unittest::TestAllExtensions &message) {
  std::vector<std::byte> data;
  expect(!hpp::proto::write_proto(message, data));
  expect(eq(0, data.size()));

  monotonic_buffer_resource mr(16);

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
  expect(!message.has_extension(protobuf_unittest::optional_unverified_lazy_message_extension()));

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
  expect(eq(""sv, message.get_extension(protobuf_unittest::optional_string_extension()).value()));
  expect(ranges_equal(""_bytes, message.get_extension(protobuf_unittest::optional_bytes_extension(), mr).value()));

  // Embedded messages should also be clear.
  expect(!message.get_extension(protobuf_unittest::optionalgroup_extension()).has_value());
  expect(!message.get_extension(protobuf_unittest::optional_nested_message_extension()).has_value());
  expect(!message.get_extension(protobuf_unittest::optional_foreign_message_extension()).has_value());
  expect(!message.get_extension(protobuf_unittest::optional_import_message_extension()).has_value());
  expect(!message.get_extension(protobuf_unittest::optional_public_import_message_extension()).has_value());
  expect(!message.get_extension(protobuf_unittest::optional_lazy_message_extension()).has_value());
  expect(!message.get_extension(protobuf_unittest::optional_unverified_lazy_message_extension()).has_value());

  // Enums without defaults are set to the first value in the enum.
  expect(protobuf_unittest::TestAllTypes::NestedEnum::FOO ==
         message.get_extension(protobuf_unittest::optional_nested_enum_extension()).value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO ==
         message.get_extension(protobuf_unittest::optional_foreign_enum_extension()).value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO ==
         message.get_extension(protobuf_unittest::optional_import_enum_extension()).value());

  expect(eq(""sv, message.get_extension(protobuf_unittest::optional_string_piece_extension()).value()));
  expect(eq(""sv, message.get_extension(protobuf_unittest::optional_cord_extension()).value()));

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
  expect(eq("hello"sv, message.get_extension(protobuf_unittest::default_string_extension()).value()));
  expect(ranges_equal("world"_bytes, message.get_extension(protobuf_unittest::default_bytes_extension(), mr).value()));

  expect(protobuf_unittest::TestAllTypes::NestedEnum::BAR ==
         message.get_extension(protobuf_unittest::default_nested_enum_extension()).value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR ==
         message.get_extension(protobuf_unittest::default_foreign_enum_extension()).value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_BAR ==
         message.get_extension(protobuf_unittest::default_import_enum_extension()).value());

  expect(eq("abc"sv, message.get_extension(protobuf_unittest::default_string_piece_extension()).value()));
  expect(eq("123"sv, message.get_extension(protobuf_unittest::default_cord_extension()).value()));

  expect(!message.has_extension(protobuf_unittest::oneof_uint32_extension()));
  expect(!message.has_extension(protobuf_unittest::oneof_nested_message_extension()));
  expect(!message.has_extension(protobuf_unittest::oneof_string_extension()));
  expect(!message.has_extension(protobuf_unittest::oneof_bytes_extension()));
}
// -------------------------------------------------------------------

inline void SetAll(protobuf_unittest::TestPackedExtensions *message, monotonic_buffer_resource &mr) {
  const int32_t packed_int32[] = {601, 701};
  expect(!message->set_extension(protobuf_unittest::packed_int32_extension(), packed_int32, mr));
  const int64_t packed_int64[] = {602, 702};
  expect(!message->set_extension(protobuf_unittest::packed_int64_extension(), packed_int64, mr));
  const uint32_t packed_uint32[] = {603, 703};
  expect(!message->set_extension(protobuf_unittest::packed_uint32_extension(), packed_uint32, mr));
  const uint64_t packed_uint64[] = {604, 704};
  expect(!message->set_extension(protobuf_unittest::packed_uint64_extension(), packed_uint64, mr));
  const int32_t packed_sint32[] = {605, 705};
  expect(!message->set_extension(protobuf_unittest::packed_sint32_extension(), packed_sint32, mr));
  const int64_t packed_sint64[] = {606, 706};
  expect(!message->set_extension(protobuf_unittest::packed_sint64_extension(), packed_sint64, mr));
  const uint32_t packed_fixed32[] = {607, 707};
  expect(!message->set_extension(protobuf_unittest::packed_fixed32_extension(), packed_fixed32, mr));
  const uint64_t packed_fixed64[] = {608, 708};
  expect(!message->set_extension(protobuf_unittest::packed_fixed64_extension(), packed_fixed64, mr));
  const int32_t packed_sfixed32[] = {609, 709};
  expect(!message->set_extension(protobuf_unittest::packed_sfixed32_extension(), packed_sfixed32, mr));
  const int64_t packed_sfixed64[] = {610, 710};
  expect(!message->set_extension(protobuf_unittest::packed_sfixed64_extension(), packed_sfixed64, mr));
  const float packed_float[] = {611, 711};
  expect(!message->set_extension(protobuf_unittest::packed_float_extension(), packed_float, mr));
  const double packed_double[] = {612, 712};
  expect(!message->set_extension(protobuf_unittest::packed_double_extension(), packed_double, mr));
  const bool packed_bool[] = {true, false};
  expect(!message->set_extension(protobuf_unittest::packed_bool_extension(), packed_bool, mr));
  const protobuf_unittest::ForeignEnum packed_enum[] = {protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                        protobuf_unittest::ForeignEnum::FOREIGN_BAZ};
  expect(!message->set_extension(protobuf_unittest::packed_enum_extension(), packed_enum, mr));
}

// -------------------------------------------------------------------

inline void ExpectAllSet(const protobuf_unittest::TestPackedExtensions &message) {
  monotonic_buffer_resource mr(8192);
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_int32_extension(), mr).value(),
                      std::vector<int32_t>{601, 701}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_int64_extension(), mr).value(),
                      std::vector<int64_t>{602, 702}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_uint32_extension(), mr).value(),
                      std::vector<uint32_t>{603, 703}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_uint64_extension(), mr).value(),
                      std::vector<uint64_t>{604, 704}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_sint32_extension(), mr).value(),
                      std::vector<int32_t>{605, 705}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_sint64_extension(), mr).value(),
                      std::vector<int64_t>{606, 706}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_fixed32_extension(), mr).value(),
                      std::vector<uint32_t>{607, 707}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_fixed64_extension(), mr).value(),
                      std::vector<uint64_t>{608, 708}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_sfixed32_extension(), mr).value(),
                      std::vector<int32_t>{609, 709}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_sfixed64_extension(), mr).value(),
                      std::vector<int64_t>{610, 710}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_float_extension(), mr).value(),
                      std::vector<float>{611, 711}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_double_extension(), mr).value(),
                      std::vector<double>{612, 712}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_bool_extension(), mr).value(),
                      std::vector<hpp::proto::boolean>{true, false}));

  expect(ranges_equal(message.get_extension(protobuf_unittest::packed_enum_extension(), mr).value(),
                      std::vector<protobuf_unittest::ForeignEnum>{protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                                  protobuf_unittest::ForeignEnum::FOREIGN_BAZ}));
}

// -------------------------------------------------------------------

inline void ExpectAllSet(const protobuf_unittest::TestUnpackedExtensions &message) {
  monotonic_buffer_resource mr(8192);
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_int32_extension(), mr).value(),
                      std::vector<int32_t>{601, 701}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_int64_extension(), mr).value(),
                      std::vector<int64_t>{602, 702}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_uint32_extension(), mr).value(),
                      std::vector<uint32_t>{603, 703}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_uint64_extension(), mr).value(),
                      std::vector<uint64_t>{604, 704}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_sint32_extension(), mr).value(),
                      std::vector<int32_t>{605, 705}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_sint64_extension(), mr).value(),
                      std::vector<int64_t>{606, 706}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_fixed32_extension(), mr).value(),
                      std::vector<uint32_t>{607, 707}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_fixed64_extension(), mr).value(),
                      std::vector<uint64_t>{608, 708}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_sfixed32_extension(), mr).value(),
                      std::vector<int32_t>{609, 709}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_sfixed64_extension(), mr).value(),
                      std::vector<int64_t>{610, 710}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_float_extension(), mr).value(),
                      std::vector<float>{611, 711}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_double_extension(), mr).value(),
                      std::vector<double>{612, 712}));
  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_bool_extension(), mr).value(),
                      std::vector<hpp::proto::boolean>{true, false}));

  expect(ranges_equal(message.get_extension(protobuf_unittest::unpacked_enum_extension(), mr).value(),
                      std::vector<protobuf_unittest::ForeignEnum>{protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                                  protobuf_unittest::ForeignEnum::FOREIGN_BAZ}));
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
  expect(eq(protobuf_unittest::TestOneof2::foo_lazy_message, message.foo.index()) >> fatal);
  const auto &foo_lazy_message = std::get<protobuf_unittest::TestOneof2::foo_lazy_message>(message.foo);

  expect(eq(protobuf_unittest::TestOneof2::bar_string, message.bar.index()) >> fatal);

  expect(eq(0, foo_lazy_message.corge_int.size()) >> fatal);

  expect(eq(100, foo_lazy_message.moo_int.value()));
  expect(eq("101"sv, std::get<protobuf_unittest::TestOneof2::bar_string>(message.bar)));
  expect(eq(102, message.baz_int.value()));
  expect(eq("103"sv, message.baz_string.value()));
}

inline void ExpectOneofSet2(const protobuf_unittest::TestOneof2 &message) {
  expect(eq(protobuf_unittest::TestOneof2::foo_int, message.foo.index()));
  expect(eq(protobuf_unittest::TestOneof2::bar_enum, message.bar.index()));

  expect(eq(200, std::get<protobuf_unittest::TestOneof2::foo_int>(message.foo)));
  expect(protobuf_unittest::TestOneof2::NestedEnum::BAZ ==
         std::get<protobuf_unittest::TestOneof2::bar_enum>(message.bar));
  expect(eq(202, message.baz_int.value()));
  expect(eq("203"sv, message.baz_string.value()));
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
const std::size_t max_memory_resource_size = 1U << 20U;
const boost::ut::suite proto_test = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;
  using namespace non_owning;

  "protobuf"_test =
      []<class T> {
        T message;
        T message2;
        T message3;
        monotonic_buffer_resource mr{max_memory_resource_size};

        if constexpr (requires { TestUtil::ExpectClear(message); }) {
          TestUtil::ExpectClear(message);
        }
        TestUtil::SetAll(&message, mr);
        message2 = message;

        std::vector<std::byte> data;
        expect(!hpp::proto::write_proto(message2, data));
        expect(!hpp::proto::read_proto(message3, data, mr));

        TestUtil::ExpectAllSet(message);
        TestUtil::ExpectAllSet(message2);
        TestUtil::ExpectAllSet(message3);
      } |
      std::tuple<protobuf_unittest::TestAllTypes, protobuf_unittest::TestAllExtensions,
                 protobuf_unittest::TestUnpackedTypes, protobuf_unittest::TestPackedTypes,
                 protobuf_unittest::TestPackedExtensions>{};

  "interoperate_with_google_protobuf_parser"_test =
      []<class T> {
        T original;
        monotonic_buffer_resource mr{max_memory_resource_size};

        TestUtil::SetAll(&original, mr);

        std::vector<char> data;
        expect(!hpp::proto::write_proto(original, data));

        auto original_json = gpb_based::proto_to_json(unittest_proto2_descriptorset(),
                                                      pb_message_name(original).c_str(), {data.data(), data.size()});

        auto generated_json = hpp::proto::write_json(original);

        expect(eq(generated_json.value(), original_json));

        T msg;
        expect(!hpp::proto::read_json(msg, original_json, mr));

        TestUtil::ExpectAllSet(msg);
      } |
      std::tuple<protobuf_unittest::TestAllTypes, protobuf_unittest::TestUnpackedTypes,
                 protobuf_unittest::TestPackedTypes>{};
};

// TODO: need a test case of TestOneof2

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}