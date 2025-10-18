#include "gpb_proto_json/gpb_proto_json.hpp"
#include "test_util.hpp"
#include <boost/ut.hpp>
#include <google/protobuf/unittest.glz.hpp>
#include <google/protobuf/unittest.pb.hpp>

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
// NOLINTBEGIN(clang-diagnostic-missing-designated-field-initializers)

template <typename T>
  requires requires { glz::meta<T>::value; }
std::ostream &operator<<(std::ostream &os, const T &v) {
  return os << hpp::proto::write_json(v).value();
}

using non_owning_t = hpp::proto::non_owning_traits;
using TestAllTypes_t = protobuf_unittest::TestAllTypes<non_owning_t>;
using TestAllExtensions_t = protobuf_unittest::TestAllExtensions<non_owning_t>;
using TestFieldOrderings_t = protobuf_unittest::TestFieldOrderings<non_owning_t>;
using TestPackedTypes_t = protobuf_unittest::TestPackedTypes<non_owning_t>;
using TestPackedExtensions_t = protobuf_unittest::TestPackedExtensions<non_owning_t>;
using TestUnpackedTypes_t = protobuf_unittest::TestUnpackedTypes<non_owning_t>;
using TestUnpackedExtensions_t = protobuf_unittest::TestUnpackedExtensions<non_owning_t>;
using TestOneof2_t = protobuf_unittest::TestOneof2<non_owning_t>;
namespace TestUtil {
using namespace std::literals::string_view_literals;
using namespace boost::ut;

// Set every field in the message to a unique value.
inline void SetAll(TestAllTypes_t *message, auto &&mr);
inline void SetOptionalFields(TestAllTypes_t *message);
inline void SetRepeatedFields(TestAllTypes_t *message);
inline void SetDefaultFields(TestAllTypes_t *message);
inline void SetOneofFields(TestAllTypes_t *message);
inline void SetAll(TestAllExtensions_t *message, auto &&mr);
inline void SetOneofFields(TestAllExtensions_t *message, auto &&mr);
inline void SetAllFieldsAndExtensions(TestFieldOrderings_t *message, auto &&mr);
inline void SetAll(TestPackedTypes_t *message, auto &&mr);
inline void SetAll(TestPackedExtensions_t *message, auto &&mr);
inline void SetAll(TestUnpackedTypes_t *message, auto &&mr);
inline void SetOneof1(TestOneof2_t *message);
inline void SetOneof2(TestOneof2_t *message);

// Check that all fields have the values that they should have after
// Set*Fields() is called.
inline void ExpectAllSet(const TestAllTypes_t &message);
inline void ExpectAllSet(const TestAllExtensions_t &message);
inline void ExpectAllSet(const TestPackedTypes_t &message);
inline void ExpectAllSet(const TestPackedExtensions_t &message);
inline void ExpectAllSet(const TestUnpackedTypes_t &message);
inline void ExpectAllSet(const TestUnpackedExtensions_t &message);
inline void ExpectOneofSet1(const TestOneof2_t &message);
inline void ExpectOneofSet2(const TestOneof2_t &message);

// Check that all fields have their default values.
inline void ExpectClear(const TestAllTypes_t &message);
inline void ExpectClear(const TestAllExtensions_t &message);
inline void ExpectOneofClear(const TestOneof2_t &message);

inline void SetAll(TestAllTypes_t *message, auto && /*unused*/) {
  SetOptionalFields(message);
  SetRepeatedFields(message);
  SetDefaultFields(message);
  SetOneofFields(message);
}

inline void SetOptionalFields(TestAllTypes_t *message) {
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
  message->optional_bytes = "116"_bytes_view;

  message->optionalgroup = TestAllTypes_t::OptionalGroup{.a = 117};
  message->optional_nested_message = TestAllTypes_t::NestedMessage{.bb = 118};
  message->optional_foreign_message.emplace().c = 119;
  message->optional_import_message.emplace().d = 120;
  message->optional_public_import_message.emplace().e = 126;
  message->optional_lazy_message = TestAllTypes_t::NestedMessage{.bb = 127};

  message->optional_nested_enum = TestAllTypes_t::NestedEnum::BAZ;
  message->optional_foreign_enum = protobuf_unittest::ForeignEnum::FOREIGN_BAZ;
  message->optional_import_enum = protobuf_unittest_import::ImportEnum::IMPORT_BAZ;
}

// -------------------------------------------------------------------

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

inline void SetRepeatedFields(TestAllTypes_t *message) {
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

  const static TestAllTypes_t::RepeatedGroup repeatedgroup[] = {{.a = 217}, {.a = 317}};
  message->repeatedgroup = repeatedgroup;
  const static TestAllTypes_t::NestedMessage repeated_nested_message[] = {{.bb = 218}, {.bb = 318}};
  message->repeated_nested_message = repeated_nested_message;

  const static protobuf_unittest::ForeignMessage<non_owning_t> repeated_foreign_message[] = {{.c = 219, .d = {}},
                                                                                             {.c = 319, .d = {}}};
  message->repeated_foreign_message = repeated_foreign_message;
  const static protobuf_unittest_import::ImportMessage<non_owning_t> repeated_import_message[] = {{.d = 220},
                                                                                                  {.d = 320}};
  message->repeated_import_message = repeated_import_message;
  const static TestAllTypes_t::NestedMessage repeated_lazy_message[] = {{.bb = 227}, {.bb = 327}};
  message->repeated_lazy_message = repeated_lazy_message;

  const static TestAllTypes_t::NestedEnum repeated_nested_enum[] = {TestAllTypes_t::NestedEnum::BAR,
                                                                    TestAllTypes_t::NestedEnum::BAZ};
  message->repeated_nested_enum = repeated_nested_enum;
  const static protobuf_unittest::ForeignEnum repeated_foreign_enum[] = {protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                                         protobuf_unittest::ForeignEnum::FOREIGN_BAZ};
  message->repeated_foreign_enum = repeated_foreign_enum;
  const static protobuf_unittest_import::ImportEnum repeated_import_enum[] = {
      protobuf_unittest_import::ImportEnum::IMPORT_BAR, protobuf_unittest_import::ImportEnum::IMPORT_BAZ};
  message->repeated_import_enum = repeated_import_enum;
}

// -------------------------------------------------------------------

inline void SetDefaultFields(TestAllTypes_t *message) {
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

  message->default_nested_enum = TestAllTypes_t::NestedEnum::FOO;
  message->default_foreign_enum = protobuf_unittest::ForeignEnum::FOREIGN_FOO;
  message->default_import_enum = protobuf_unittest_import::ImportEnum::IMPORT_FOO;
}

// ------------------------------------------------------------------
inline void SetOneofFields(TestAllTypes_t *message) {
  message->oneof_field.emplace<1>(601U);
  using enum TestAllTypes_t::oneof_field_oneof_case;
  message->oneof_field.emplace<static_cast<int>(oneof_nested_message)>(TestAllTypes_t::NestedMessage{.bb = 602});
  message->oneof_field.emplace<static_cast<int>(oneof_string)>("603");
  message->oneof_field = "604"_bytes_view;
}

// -------------------------------------------------------------------

inline void ExpectAllSet(const TestAllTypes_t &message) {
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
  expect(std::ranges::equal("116"_bytes, message.optional_bytes.value()));

  expect(message.optionalgroup.has_value() && 117 == message.optionalgroup->a.value());
  expect(message.optional_nested_message.has_value() && 118 == message.optional_nested_message->bb.value());
  expect(message.optional_foreign_message.has_value() && 119 == message.optional_foreign_message->c.value());
  expect(message.optional_import_message.has_value() && 120 == message.optional_import_message->d.value());
  expect(message.optional_public_import_message.has_value() &&
         126 == message.optional_public_import_message->e.value());
  expect(message.optional_lazy_message.has_value() && 127 == message.optional_lazy_message->bb.value());

  expect(TestAllTypes_t::NestedEnum::BAZ == message.optional_nested_enum.value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAZ == message.optional_foreign_enum.value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_BAZ == message.optional_import_enum.value());

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
  expect(eq("215"sv, message.repeated_string[0]));
  expect(std::ranges::equal("216"_bytes, message.repeated_bytes[0]));

  expect(eq(217, message.repeatedgroup[0].a.value()));
  expect(eq(218, message.repeated_nested_message[0].bb.value()));
  expect(eq(219, message.repeated_foreign_message[0].c.value()));
  expect(eq(220, message.repeated_import_message[0].d.value()));
  expect(eq(227, message.repeated_lazy_message[0].bb.value()));

  expect(TestAllTypes_t::NestedEnum::BAR == message.repeated_nested_enum[0]);
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
  expect(std::ranges::equal("316"_bytes, message.repeated_bytes[1]));

  expect(eq(317, message.repeatedgroup[1].a.value()));
  expect(eq(318, message.repeated_nested_message[1].bb.value()));
  expect(eq(319, message.repeated_foreign_message[1].c.value()));
  expect(eq(320, message.repeated_import_message[1].d.value()));
  expect(eq(327, message.repeated_lazy_message[1].bb.value()));

  expect(TestAllTypes_t::NestedEnum::BAZ == message.repeated_nested_enum[1]);
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
  expect(std::ranges::equal("416"_bytes, message.default_bytes.value()));

  expect(TestAllTypes_t::NestedEnum::FOO == message.default_nested_enum.value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO == message.default_foreign_enum.value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO == message.default_import_enum.value());

  expect(message.oneof_field.index() == TestAllTypes_t::oneof_bytes);

  expect(std::ranges::equal("604"_bytes, std::get<TestAllTypes_t::oneof_bytes>(message.oneof_field)));
}

// -------------------------------------------------------------------

inline void ExpectClear(const TestAllTypes_t &message) {
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
  expect(TestAllTypes_t::NestedEnum::FOO == message.optional_nested_enum.value());
  expect(!message.optional_foreign_enum.has_value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_FOO == message.optional_foreign_enum.value());
  expect(!message.optional_import_enum.has_value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_FOO == message.optional_import_enum.value());

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
  expect(eq(41, message.default_int32.value()));
  expect(eq(42, message.default_int64.value()));
  expect(eq(43, message.default_uint32.value()));
  expect(eq(44, message.default_uint64.value()));
  expect(eq(-45, message.default_sint32.value()));
  expect(eq(46, message.default_sint64.value()));
  expect(eq(47, message.default_fixed32.value()));
  expect(eq(48, message.default_fixed64.value()));
  expect(eq(49, message.default_sfixed32.value()));
  expect(eq(-50, message.default_sfixed64.value()));
  expect(eq(51.5, message.default_float.value()));
  expect(eq(52e3, message.default_double.value()));
  expect(message.default_bool.value());
  expect(eq("hello"sv, message.default_string.value()));
  expect(std::ranges::equal("world"_bytes, message.default_bytes.value()));

  expect(!message.default_nested_enum.has_value());
  expect(TestAllTypes_t::NestedEnum::BAR == message.default_nested_enum.value());
  expect(!message.default_foreign_enum.has_value());
  expect(protobuf_unittest::ForeignEnum::FOREIGN_BAR == message.default_foreign_enum.value());
  expect(!message.default_import_enum.has_value());
  expect(protobuf_unittest_import::ImportEnum::IMPORT_BAR == message.default_import_enum.value());

  expect(std::holds_alternative<std::monostate>(message.oneof_field));
}

// -------------------------------------------------------------------

inline void SetAll(TestPackedTypes_t *message, auto && /*unused*/) {
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

inline void SetAll(TestUnpackedTypes_t *message, auto && /*unused*/) {
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

inline void ExpectAllSet(const TestPackedTypes_t &message) {
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

inline void ExpectAllSet(const TestUnpackedTypes_t &message) {
  // The values expected here must match those of ExpectPackedFieldsSet.
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

inline void SetAll(TestAllExtensions_t *message, auto &&mr) {
  using namespace std::string_view_literals;
  auto expect_set_extension_ok = [&](auto &&ext) {
    expect(message->set_extension(ext, hpp::proto::alloc_from{mr}).ok());
  };
  using namespace protobuf_unittest;
  expect_set_extension_ok(optional_int32_extension{.value = 101});
  expect_set_extension_ok(optional_int64_extension{.value = 102});
  expect_set_extension_ok(optional_uint32_extension{.value = 103});
  expect_set_extension_ok(optional_uint64_extension{.value = 104});
  expect_set_extension_ok(optional_sint32_extension{.value = 105});
  expect_set_extension_ok(optional_sint64_extension{.value = 106});
  expect_set_extension_ok(optional_fixed32_extension{.value = 107});
  expect_set_extension_ok(optional_fixed64_extension{.value = 108});
  expect_set_extension_ok(optional_sfixed32_extension{.value = 109});
  expect_set_extension_ok(optional_sfixed64_extension{.value = 110});
  expect_set_extension_ok(optional_float_extension{.value = 111});
  expect_set_extension_ok(optional_double_extension{.value = 112});
  expect_set_extension_ok(optional_bool_extension{.value = true});
  expect_set_extension_ok(optional_string_extension{.value = "115"});
  expect_set_extension_ok(optional_bytes_extension{.value = "116"_bytes});

  expect_set_extension_ok(optionalgroup_extension{.value = {.a = 117}});
  expect_set_extension_ok(optional_nested_message_extension{.value = {.bb = 118}});
  expect_set_extension_ok(optional_foreign_message_extension{.value = {.c = 119}});
  expect_set_extension_ok(optional_import_message_extension{.value = {.d = 120}});
  using NestedEnum = protobuf_unittest::TestAllTypes<>::NestedEnum;

  expect_set_extension_ok(optional_nested_enum_extension{.value = NestedEnum::BAZ});
  expect_set_extension_ok(optional_foreign_enum_extension{.value = ForeignEnum::FOREIGN_BAZ});
  expect_set_extension_ok(optional_import_enum_extension{.value = protobuf_unittest_import::ImportEnum::IMPORT_BAZ});

  expect_set_extension_ok(optional_string_piece_extension{.value = "124"});
  expect_set_extension_ok(optional_cord_extension{.value = "125"});

  expect_set_extension_ok(optional_public_import_message_extension{.value = {.e = 126}});
  expect_set_extension_ok(optional_lazy_message_extension{.value = {.bb = 127}});

  // -----------------------------------------------------------------

  expect_set_extension_ok(repeated_int32_extension<non_owning_t>{.value = std::initializer_list{201, 301}});
  expect_set_extension_ok(repeated_int64_extension<non_owning_t>{.value = std::initializer_list{202LL, 302LL}});
  expect_set_extension_ok(repeated_uint32_extension<non_owning_t>{.value = std::initializer_list{203U, 303U}});
  expect_set_extension_ok(repeated_uint64_extension<non_owning_t>{.value = std::initializer_list{204ULL, 304ULL}});
  expect_set_extension_ok(repeated_sint32_extension<non_owning_t>{.value = std::initializer_list{205, 305}});
  expect_set_extension_ok(repeated_sint64_extension<non_owning_t>{.value = std::initializer_list{206LL, 306LL}});
  expect_set_extension_ok(repeated_fixed32_extension<non_owning_t>{.value = std::initializer_list{207U, 307U}});
  expect_set_extension_ok(repeated_fixed64_extension<non_owning_t>{.value = std::initializer_list{208ULL, 308ULL}});
  expect_set_extension_ok(repeated_sfixed32_extension<non_owning_t>{.value = std::initializer_list{209, 309}});
  expect_set_extension_ok(repeated_sfixed64_extension<non_owning_t>{.value = std::initializer_list{210LL, 310LL}});
  expect_set_extension_ok(repeated_float_extension<non_owning_t>{.value = std::initializer_list<float>{211, 311}});
  expect_set_extension_ok(repeated_double_extension<non_owning_t>{.value = std::initializer_list<double>{212, 312}});
  expect_set_extension_ok(repeated_bool_extension<non_owning_t>{.value = std::initializer_list{true, false}});
  expect_set_extension_ok(repeated_string_extension<non_owning_t>{.value = std::initializer_list{"215"sv, "315"sv}});
  expect_set_extension_ok(repeated_bytes_extension{.value = std::initializer_list{"216"_bytes, "316"_bytes}});

  expect_set_extension_ok(
      repeatedgroup_extension{.value = std::initializer_list<RepeatedGroup_extension<>>{{.a = 217}, {.a = 317}}});
  using NestedMessage = protobuf_unittest::TestAllTypes<non_owning_t>::NestedMessage;
  expect_set_extension_ok(repeated_nested_message_extension<non_owning_t>{
      .value = std::initializer_list<NestedMessage>{{.bb = 218}, {.bb = 318}}});
  expect_set_extension_ok(repeated_foreign_message_extension<non_owning_t>{
      .value = std::initializer_list<ForeignMessage<non_owning_t>>{{.c = 219}, {.c = 319}}});
  expect_set_extension_ok(repeated_import_message_extension<non_owning_t>{
      .value = std::initializer_list<protobuf_unittest_import::ImportMessage<non_owning_t>>{{.d = 220}, {.d = 320}}});
  expect_set_extension_ok(repeated_lazy_message_extension<non_owning_t>{
      .value = std::initializer_list<NestedMessage>{{.bb = 227}, {.bb = 327}}});

  expect_set_extension_ok(
      repeated_nested_enum_extension{.value = std::initializer_list{NestedEnum::BAR, NestedEnum::BAZ}});
  expect_set_extension_ok(repeated_foreign_enum_extension{
      .value = std::initializer_list{ForeignEnum::FOREIGN_BAR, ForeignEnum::FOREIGN_BAZ}});
  expect_set_extension_ok(
      repeated_import_enum_extension{.value = std::initializer_list{protobuf_unittest_import::ImportEnum::IMPORT_BAR,
                                                                    protobuf_unittest_import::ImportEnum::IMPORT_BAZ}});

  expect_set_extension_ok(repeated_string_piece_extension{.value = std::initializer_list<std::string>{"224", "324"}});
  expect_set_extension_ok(repeated_cord_extension{.value = std::initializer_list<std::string>{"225", "325"}});

  // -----------------------------------------------------------------

  expect_set_extension_ok(default_int32_extension{.value = 401});
  expect_set_extension_ok(default_int64_extension{.value = 402});
  expect_set_extension_ok(default_uint32_extension{.value = 403});
  expect_set_extension_ok(default_uint64_extension{.value = 404});
  expect_set_extension_ok(default_sint32_extension{.value = 405});
  expect_set_extension_ok(default_sint64_extension{.value = 406});
  expect_set_extension_ok(default_fixed32_extension{.value = 407});
  expect_set_extension_ok(default_fixed64_extension{.value = 408});
  expect_set_extension_ok(default_sfixed32_extension{.value = 409});
  expect_set_extension_ok(default_sfixed64_extension{.value = 410});
  expect_set_extension_ok(default_float_extension{.value = 411});
  expect_set_extension_ok(default_double_extension{.value = 412});

  expect_set_extension_ok(default_bool_extension{.value = false});
  expect_set_extension_ok(default_string_extension{.value = "415"});
  expect_set_extension_ok(default_bytes_extension{.value = "416"_bytes});

  expect_set_extension_ok(default_nested_enum_extension{.value = NestedEnum::FOO});
  expect_set_extension_ok(default_foreign_enum_extension{.value = ForeignEnum::FOREIGN_FOO});
  expect_set_extension_ok(default_import_enum_extension{.value = protobuf_unittest_import::ImportEnum::IMPORT_FOO});

  expect_set_extension_ok(default_string_piece_extension{.value = "424"});
  expect_set_extension_ok(default_cord_extension{.value = "425"});

  SetOneofFields(message, hpp::proto::alloc_from{mr});
}

inline void SetOneofFields(TestAllExtensions_t *message, auto &&mr) {
  auto expect_set_extension_ok = [&](auto &&ext) {
    expect(message->set_extension(ext, hpp::proto::alloc_from{mr}).ok());
  };

  expect_set_extension_ok(protobuf_unittest::oneof_uint32_extension{.value = 601});
  expect_set_extension_ok(protobuf_unittest::oneof_nested_message_extension<non_owning_t>{.value = {.bb = 602}});
  expect_set_extension_ok(protobuf_unittest::oneof_string_extension<non_owning_t>{.value = "603"});
  expect_set_extension_ok(protobuf_unittest::oneof_bytes_extension<non_owning_t>{.value = "604"_bytes_view});
}

// -------------------------------------------------------------------

inline void SetAllFieldsAndExtensions(TestFieldOrderings_t *message, auto &&mr) {
  message->my_int = 1;
  message->my_string = "foo";
  message->my_float = 1.0F;
  expect(message->set_extension(protobuf_unittest::my_extension_int(), 23, hpp::proto::alloc_from{mr}).ok());
  expect(message->set_extension(protobuf_unittest::my_extension_string(), "bar", hpp::proto::alloc_from{mr}).ok());
}
// -------------------------------------------------------------------

inline void ExpectAllSet(const TestAllExtensions_t &message) {
  expect(message.has_extension(protobuf_unittest::optional_int32_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_int64_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_uint32_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_uint64_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_sint32_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_sint64_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_fixed32_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_fixed64_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_sfixed32_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_sfixed64_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_float_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_double_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_bool_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_string_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_bytes_extension{}));

  expect(message.has_extension(protobuf_unittest::optionalgroup_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_nested_message_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_foreign_message_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_import_message_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_public_import_message_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_lazy_message_extension{}));

  auto get_value = [](const auto &ext) { return ext.value; };

  auto expect_extension_value_set = [&](auto ext, const auto &get_value) {
    expect(message.get_extension(ext).ok());
    expect(get_value(ext));
  };

  expect_extension_value_set(protobuf_unittest::optionalgroup_extension{}, [](const auto &ext) { return ext.value.a; });
  expect_extension_value_set(protobuf_unittest::optional_nested_message_extension{},
                             [](const auto &ext) { return ext.value.bb; });
  expect_extension_value_set(protobuf_unittest::optional_foreign_message_extension{},
                             [](const auto &ext) { return ext.value.c; });
  expect_extension_value_set(protobuf_unittest::optional_import_message_extension{},
                             [](const auto &ext) { return ext.value.d; });
  expect_extension_value_set(protobuf_unittest::optional_public_import_message_extension{},
                             [](const auto &ext) { return ext.value.e; });
  expect_extension_value_set(protobuf_unittest::optional_lazy_message_extension{},
                             [](const auto &ext) { return ext.value.bb; });

  expect(message.has_extension(protobuf_unittest::optional_nested_enum_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_foreign_enum_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_import_enum_extension{}));

  expect(message.has_extension(protobuf_unittest::optional_string_piece_extension{}));
  expect(message.has_extension(protobuf_unittest::optional_cord_extension{}));

  std::pmr::monotonic_buffer_resource mr;

  auto expect_extension_value_eq = [&](const auto &value, auto ext, const auto &get_value) {
    expect(message.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
    expect(value == get_value(ext));
  };

  expect_extension_value_eq(101, protobuf_unittest::optional_int32_extension{}, get_value);
  expect_extension_value_eq(102, protobuf_unittest::optional_int64_extension{}, get_value);
  expect_extension_value_eq(103U, protobuf_unittest::optional_uint32_extension{}, get_value);
  expect_extension_value_eq(104U, protobuf_unittest::optional_uint64_extension{}, get_value);
  expect_extension_value_eq(105, protobuf_unittest::optional_sint32_extension{}, get_value);
  expect_extension_value_eq(106, protobuf_unittest::optional_sint64_extension{}, get_value);
  expect_extension_value_eq(107U, protobuf_unittest::optional_fixed32_extension{}, get_value);
  expect_extension_value_eq(108U, protobuf_unittest::optional_fixed64_extension{}, get_value);
  expect_extension_value_eq(109, protobuf_unittest::optional_sfixed32_extension{}, get_value);
  expect_extension_value_eq(110, protobuf_unittest::optional_sfixed64_extension{}, get_value);
  expect_extension_value_eq(111, protobuf_unittest::optional_float_extension{}, get_value);
  expect_extension_value_eq(112, protobuf_unittest::optional_double_extension{}, get_value);
  expect_extension_value_eq(true, protobuf_unittest::optional_bool_extension{}, get_value);
  expect_extension_value_eq("115"sv, protobuf_unittest::optional_string_extension<non_owning_t>{}, get_value);
  expect_extension_value_eq("116"_bytes_view, protobuf_unittest::optional_bytes_extension<non_owning_t>{}, get_value);

  expect_extension_value_eq(117, protobuf_unittest::optionalgroup_extension{},
                            [](const auto &ext) { return ext.value.a.value(); });
  expect_extension_value_eq(118, protobuf_unittest::optional_nested_message_extension{},
                            [](const auto &ext) { return ext.value.bb.value(); });

  expect_extension_value_eq(119, protobuf_unittest::optional_foreign_message_extension{},
                            [](const auto &ext) { return ext.value.c.value(); });

  expect_extension_value_eq(120, protobuf_unittest::optional_import_message_extension{},
                            [](const auto &ext) { return ext.value.d.value(); });

  using enum TestAllTypes_t::NestedEnum;
  expect_extension_value_eq(BAZ, protobuf_unittest::optional_nested_enum_extension{}, get_value);
  using enum protobuf_unittest::ForeignEnum;
  expect_extension_value_eq(FOREIGN_BAZ, protobuf_unittest::optional_foreign_enum_extension{}, get_value);
  using enum protobuf_unittest_import::ImportEnum;
  expect_extension_value_eq(IMPORT_BAZ, protobuf_unittest::optional_import_enum_extension{}, get_value);

  expect_extension_value_eq("124"sv, protobuf_unittest::optional_string_piece_extension<non_owning_t>{}, get_value);
  expect_extension_value_eq("125"sv, protobuf_unittest::optional_cord_extension<non_owning_t>{}, get_value);
  expect_extension_value_eq(126, protobuf_unittest::optional_public_import_message_extension{},
                            [](const auto &ext) { return ext.value.e.value(); });

  expect_extension_value_eq(127, protobuf_unittest::optional_lazy_message_extension{},
                            [](const auto &ext) { return ext.value.bb.value(); });

  // -----------------------------------------------------------------

  auto expect_extension_range_eq =
      [&]<typename Extension>(std::initializer_list<typename Extension::value_type::value_type> value, Extension ext) {
        expect(message.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
        expect(std::ranges::equal(value, ext.value));
      };

  expect_extension_range_eq({201, 301}, protobuf_unittest::repeated_int32_extension<non_owning_t>{});
  expect_extension_range_eq({202, 302}, protobuf_unittest::repeated_int64_extension<non_owning_t>{});
  expect_extension_range_eq({203, 303}, protobuf_unittest::repeated_uint32_extension<non_owning_t>{});
  expect_extension_range_eq({204, 304}, protobuf_unittest::repeated_uint64_extension<non_owning_t>{});
  expect_extension_range_eq({205, 305}, protobuf_unittest::repeated_sint32_extension<non_owning_t>{});
  expect_extension_range_eq({206, 306}, protobuf_unittest::repeated_sint64_extension<non_owning_t>{});
  expect_extension_range_eq({207, 307}, protobuf_unittest::repeated_fixed32_extension<non_owning_t>{});
  expect_extension_range_eq({208, 308}, protobuf_unittest::repeated_fixed64_extension<non_owning_t>{});
  expect_extension_range_eq({209, 309}, protobuf_unittest::repeated_sfixed32_extension<non_owning_t>{});
  expect_extension_range_eq({210, 310}, protobuf_unittest::repeated_sfixed64_extension<non_owning_t>{});
  expect_extension_range_eq({211, 311}, protobuf_unittest::repeated_float_extension<non_owning_t>{});
  expect_extension_range_eq({212, 312}, protobuf_unittest::repeated_double_extension<non_owning_t>{});
  expect_extension_range_eq({true, false}, protobuf_unittest::repeated_bool_extension<non_owning_t>{});
  expect_extension_range_eq({"215"sv, "315"sv}, protobuf_unittest::repeated_string_extension<non_owning_t>{});
  expect_extension_range_eq({"216"_bytes_view, "316"_bytes_view},
                            protobuf_unittest::repeated_bytes_extension<non_owning_t>{});
  expect_extension_range_eq({{.a = 217}, {.a = 317}}, protobuf_unittest::repeatedgroup_extension<non_owning_t>{});

  expect_extension_range_eq({{.bb = 218}, {.bb = 318}},
                            protobuf_unittest::repeated_nested_message_extension<non_owning_t>{});

  expect_extension_range_eq({{.c = 219, .d = {}}, {.c = 319, .d = {}}},
                            protobuf_unittest::repeated_foreign_message_extension<non_owning_t>{});

  expect_extension_range_eq({{.d = 220}, {.d = 320}},
                            protobuf_unittest::repeated_import_message_extension<non_owning_t>{});

  expect_extension_range_eq({{.bb = 227}, {.bb = 327}},
                            protobuf_unittest::repeated_lazy_message_extension<non_owning_t>{});

  expect_extension_range_eq({TestAllTypes_t::NestedEnum::BAR, TestAllTypes_t::NestedEnum::BAZ},
                            protobuf_unittest::repeated_nested_enum_extension<non_owning_t>{});

  expect_extension_range_eq({protobuf_unittest::ForeignEnum::FOREIGN_BAR, protobuf_unittest::ForeignEnum::FOREIGN_BAZ},
                            protobuf_unittest::repeated_foreign_enum_extension<non_owning_t>{});

  expect_extension_range_eq(
      {protobuf_unittest_import::ImportEnum::IMPORT_BAR, protobuf_unittest_import::ImportEnum::IMPORT_BAZ},
      protobuf_unittest::repeated_import_enum_extension<non_owning_t>{});

  expect_extension_range_eq({"224"sv, "324"sv}, protobuf_unittest::repeated_string_piece_extension<non_owning_t>{});

  expect_extension_range_eq({"225"sv, "325"sv}, protobuf_unittest::repeated_cord_extension<non_owning_t>{});

  // -----------------------------------------------------------------

  expect(message.has_extension(protobuf_unittest::default_int32_extension{}));
  expect(message.has_extension(protobuf_unittest::default_int64_extension{}));
  expect(message.has_extension(protobuf_unittest::default_uint32_extension{}));
  expect(message.has_extension(protobuf_unittest::default_uint64_extension{}));
  expect(message.has_extension(protobuf_unittest::default_sint32_extension{}));
  expect(message.has_extension(protobuf_unittest::default_sint64_extension{}));
  expect(message.has_extension(protobuf_unittest::default_fixed32_extension{}));
  expect(message.has_extension(protobuf_unittest::default_fixed64_extension{}));
  expect(message.has_extension(protobuf_unittest::default_sfixed32_extension{}));
  expect(message.has_extension(protobuf_unittest::default_sfixed64_extension{}));
  expect(message.has_extension(protobuf_unittest::default_float_extension{}));
  expect(message.has_extension(protobuf_unittest::default_double_extension{}));
  expect(message.has_extension(protobuf_unittest::default_bool_extension{}));
  expect(message.has_extension(protobuf_unittest::default_string_extension{}));
  expect(message.has_extension(protobuf_unittest::default_bytes_extension{}));

  expect(message.has_extension(protobuf_unittest::default_nested_enum_extension{}));
  expect(message.has_extension(protobuf_unittest::default_foreign_enum_extension{}));
  expect(message.has_extension(protobuf_unittest::default_import_enum_extension{}));

  expect(message.has_extension(protobuf_unittest::default_string_piece_extension{}));
  expect(message.has_extension(protobuf_unittest::default_cord_extension{}));

  expect_extension_value_eq(401, protobuf_unittest::default_int32_extension{}, get_value);
  expect_extension_value_eq(402, protobuf_unittest::default_int64_extension{}, get_value);
  expect_extension_value_eq(403U, protobuf_unittest::default_uint32_extension{}, get_value);
  expect_extension_value_eq(404U, protobuf_unittest::default_uint64_extension{}, get_value);
  expect_extension_value_eq(405, protobuf_unittest::default_sint32_extension{}, get_value);
  expect_extension_value_eq(406, protobuf_unittest::default_sint64_extension{}, get_value);
  expect_extension_value_eq(407U, protobuf_unittest::default_fixed32_extension{}, get_value);
  expect_extension_value_eq(408U, protobuf_unittest::default_fixed64_extension{}, get_value);
  expect_extension_value_eq(409, protobuf_unittest::default_sfixed32_extension{}, get_value);
  expect_extension_value_eq(410, protobuf_unittest::default_sfixed64_extension{}, get_value);
  expect_extension_value_eq(411, protobuf_unittest::default_float_extension{}, get_value);
  expect_extension_value_eq(412, protobuf_unittest::default_double_extension{}, get_value);
  expect_extension_value_eq(false, protobuf_unittest::default_bool_extension{}, get_value);
  expect_extension_value_eq("415"sv, protobuf_unittest::default_string_extension{}, get_value);
  expect_extension_value_eq("416"_bytes, protobuf_unittest::default_bytes_extension{}, get_value);

  expect_extension_value_eq(FOO, protobuf_unittest::default_nested_enum_extension{}, get_value);
  expect_extension_value_eq(FOREIGN_FOO, protobuf_unittest::default_foreign_enum_extension{}, get_value);
  expect_extension_value_eq(IMPORT_FOO, protobuf_unittest::default_import_enum_extension{}, get_value);

  expect_extension_value_eq("424"sv, protobuf_unittest::default_string_piece_extension{}, get_value);
  expect_extension_value_eq("425"sv, protobuf_unittest::default_cord_extension{}, get_value);

  expect(message.has_extension(protobuf_unittest::oneof_uint32_extension{}));
  expect_extension_value_set(protobuf_unittest::oneof_nested_message_extension{},
                             [](const auto &ext) { return ext.value.bb.value(); });
  expect(message.has_extension(protobuf_unittest::oneof_string_extension{}));
  expect(message.has_extension(protobuf_unittest::oneof_bytes_extension{}));

  expect_extension_value_eq(601U, protobuf_unittest::oneof_uint32_extension{}, get_value);
  expect_extension_value_eq(602, protobuf_unittest::oneof_nested_message_extension{},
                            [](const auto &ext) { return ext.value.bb.value(); });
  expect_extension_value_eq("603"sv, protobuf_unittest::oneof_string_extension{}, get_value);
  expect_extension_value_eq("604"_bytes_view, protobuf_unittest::oneof_bytes_extension{}, get_value);
}

// -------------------------------------------------------------------

inline void ExpectClear(const TestAllExtensions_t &message) {
  std::vector<std::byte> data;
  expect(hpp::proto::write_proto(message, data).ok());
  expect(eq(0, data.size()));

  std::pmr::monotonic_buffer_resource mr;

  //.blah.has_value() should initially be false for all optional fields.
  expect(!message.has_extension(protobuf_unittest::optional_int32_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_int64_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_uint32_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_uint64_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_sint32_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_sint64_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_fixed32_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_fixed64_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_sfixed32_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_sfixed64_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_float_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_double_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_bool_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_string_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_bytes_extension{}));

  expect(!message.has_extension(protobuf_unittest::optionalgroup_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_nested_message_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_foreign_message_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_import_message_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_public_import_message_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_lazy_message_extension{}));

  expect(!message.has_extension(protobuf_unittest::optional_nested_enum_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_foreign_enum_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_import_enum_extension{}));

  expect(!message.has_extension(protobuf_unittest::optional_string_piece_extension{}));
  expect(!message.has_extension(protobuf_unittest::optional_cord_extension{}));

  auto get_value = [](const auto &ext) { return ext.value; };

  auto expect_extension_value_eq = [&](auto v, auto ext, const auto &get_value) {
    expect(message.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
    expect(v == get_value(ext));
  };

  // Optional fields without defaults are set to zero or something like it.
  expect_extension_value_eq(0, protobuf_unittest::optional_int32_extension{}, get_value);
  expect_extension_value_eq(0, protobuf_unittest::optional_int64_extension{}, get_value);
  expect_extension_value_eq(0U, protobuf_unittest::optional_uint32_extension{}, get_value);
  expect_extension_value_eq(0U, protobuf_unittest::optional_uint64_extension{}, get_value);
  expect_extension_value_eq(0, protobuf_unittest::optional_sint32_extension{}, get_value);
  expect_extension_value_eq(0, protobuf_unittest::optional_sint64_extension{}, get_value);
  expect_extension_value_eq(0U, protobuf_unittest::optional_fixed32_extension{}, get_value);
  expect_extension_value_eq(0U, protobuf_unittest::optional_fixed64_extension{}, get_value);
  expect_extension_value_eq(0, protobuf_unittest::optional_sfixed32_extension{}, get_value);
  expect_extension_value_eq(0, protobuf_unittest::optional_sfixed64_extension{}, get_value);
  expect_extension_value_eq(0, protobuf_unittest::optional_float_extension{}, get_value);
  expect_extension_value_eq(0.0, protobuf_unittest::optional_double_extension{}, get_value);
  expect_extension_value_eq(0.0F, protobuf_unittest::optional_bool_extension{}, get_value);
  expect_extension_value_eq(""sv, protobuf_unittest::optional_string_extension<non_owning_t>{}, get_value);
  expect_extension_value_eq(""_bytes_view, protobuf_unittest::optional_bytes_extension<non_owning_t>{}, get_value);

  auto expect_extension_value_not_set = [&](auto ext, const auto &get_value) {
    expect(message.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
    expect(!get_value(ext).has_value());
  };
  // Embedded messages should also be clear.
  expect_extension_value_not_set(protobuf_unittest::optionalgroup_extension{},
                                 [](const auto &ext) { return ext.value.a; });
  expect_extension_value_not_set(protobuf_unittest::optional_nested_message_extension{},
                                 [](const auto &ext) { return ext.value.bb; });
  expect_extension_value_not_set(protobuf_unittest::optional_foreign_message_extension{},
                                 [](const auto &ext) { return ext.value.c; });
  expect_extension_value_not_set(protobuf_unittest::optional_import_message_extension{},
                                 [](const auto &ext) { return ext.value.d; });
  expect_extension_value_not_set(protobuf_unittest::optional_public_import_message_extension{},
                                 [](const auto &ext) { return ext.value.e; });
  expect_extension_value_not_set(protobuf_unittest::optional_lazy_message_extension{},
                                 [](const auto &ext) { return ext.value.bb; });

  // Enums without defaults are set to the first value in the enum.
  using enum TestAllTypes_t::NestedEnum;
  using enum protobuf_unittest::ForeignEnum;
  expect_extension_value_eq(FOREIGN_FOO, protobuf_unittest::optional_foreign_enum_extension{}, get_value);
  using enum protobuf_unittest_import::ImportEnum;
  expect_extension_value_eq(IMPORT_FOO, protobuf_unittest::optional_import_enum_extension{}, get_value);

  auto opt = hpp::proto::alloc_from{mr};
  expect_extension_value_eq(""sv, protobuf_unittest::optional_string_piece_extension<non_owning_t>{}, get_value);
  expect_extension_value_eq(""sv, protobuf_unittest::optional_cord_extension<non_owning_t>{}, get_value);

  // Repeated fields are empty.
  expect(!message.has_extension(protobuf_unittest::repeated_int32_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_int64_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_uint32_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_uint64_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_sint32_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_sint64_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_fixed32_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_fixed64_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_sfixed32_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_sfixed64_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_float_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_double_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_bool_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_string_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_bytes_extension{}));

  expect(!message.has_extension(protobuf_unittest::repeatedgroup_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_nested_message_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_foreign_message_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_import_message_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_lazy_message_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_nested_enum_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_foreign_enum_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_import_enum_extension{}));

  expect(!message.has_extension(protobuf_unittest::repeated_string_piece_extension{}));
  expect(!message.has_extension(protobuf_unittest::repeated_cord_extension{}));

  //.blah.has_value() should also be false for all default fields.
  expect(!message.has_extension(protobuf_unittest::default_int32_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_int64_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_uint32_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_uint64_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_sint32_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_sint64_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_fixed32_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_fixed64_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_sfixed32_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_sfixed64_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_float_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_double_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_bool_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_string_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_bytes_extension{}));

  expect(!message.has_extension(protobuf_unittest::default_nested_enum_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_foreign_enum_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_import_enum_extension{}));

  expect(!message.has_extension(protobuf_unittest::default_string_piece_extension{}));
  expect(!message.has_extension(protobuf_unittest::default_cord_extension{}));

  // Fields with defaults have their default values (duh).
  expect_extension_value_eq(41, protobuf_unittest::default_int32_extension{}, get_value);
  expect_extension_value_eq(42, protobuf_unittest::default_int64_extension{}, get_value);
  expect_extension_value_eq(43U, protobuf_unittest::default_uint32_extension{}, get_value);
  expect_extension_value_eq(44U, protobuf_unittest::default_uint64_extension{}, get_value);
  expect_extension_value_eq(-45, protobuf_unittest::default_sint32_extension{}, get_value);
  expect_extension_value_eq(46, protobuf_unittest::default_sint64_extension{}, get_value);
  expect_extension_value_eq(47U, protobuf_unittest::default_fixed32_extension{}, get_value);
  expect_extension_value_eq(48U, protobuf_unittest::default_fixed64_extension{}, get_value);
  expect_extension_value_eq(49, protobuf_unittest::default_sfixed32_extension{}, get_value);
  expect_extension_value_eq(-50, protobuf_unittest::default_sfixed64_extension{}, get_value);
  expect_extension_value_eq(51.5, protobuf_unittest::default_float_extension{}, get_value);
  expect_extension_value_eq(52e3, protobuf_unittest::default_double_extension{}, get_value);
  expect_extension_value_eq(true, protobuf_unittest::default_bool_extension{}, get_value);
  expect_extension_value_eq("hello"sv, protobuf_unittest::default_string_extension{}, get_value);
  expect_extension_value_eq("world"_bytes, protobuf_unittest::default_bytes_extension{}, get_value);

  expect_extension_value_eq(BAR, protobuf_unittest::default_nested_enum_extension{}, get_value);
  expect_extension_value_eq(FOREIGN_BAR, protobuf_unittest::default_foreign_enum_extension{}, get_value);
  expect_extension_value_eq(IMPORT_BAR, protobuf_unittest::default_import_enum_extension{}, get_value);

  expect_extension_value_eq("abc"sv, protobuf_unittest::default_string_piece_extension{}, get_value);
  expect_extension_value_eq("123"sv, protobuf_unittest::default_cord_extension{}, get_value);

  expect(!message.has_extension(protobuf_unittest::oneof_uint32_extension{}));
  expect(!message.has_extension(protobuf_unittest::oneof_nested_message_extension{}));
  expect(!message.has_extension(protobuf_unittest::oneof_string_extension{}));
  expect(!message.has_extension(protobuf_unittest::oneof_bytes_extension{}));
}
// -------------------------------------------------------------------

inline void SetAll(TestPackedExtensions_t *message, auto &&mr) {

  auto expect_set_extension_ok = [&](auto &&ext) {
    expect(message->set_extension(ext, hpp::proto::alloc_from{mr}).ok());
  };
  using namespace protobuf_unittest;

  expect_set_extension_ok(packed_int32_extension{.value = std::initializer_list{601, 701}});
  expect_set_extension_ok(packed_int64_extension{.value = std::initializer_list<int64_t>{602, 702}});
  expect_set_extension_ok(packed_uint32_extension{.value = std::initializer_list<uint32_t>{603, 703}});
  expect_set_extension_ok(packed_uint64_extension{.value = std::initializer_list<uint64_t>{604, 704}});
  expect_set_extension_ok(packed_sint32_extension{.value = std::initializer_list<int32_t>{605, 705}});
  expect_set_extension_ok(packed_sint64_extension{.value = std::initializer_list<int64_t>{606, 706}});
  expect_set_extension_ok(packed_fixed32_extension{.value = std::initializer_list<uint32_t>{607, 707}});
  expect_set_extension_ok(packed_fixed64_extension{.value = std::initializer_list<uint64_t>{608, 708}});
  expect_set_extension_ok(packed_sfixed32_extension{.value = std::initializer_list<int32_t>{609, 709}});
  expect_set_extension_ok(packed_sfixed64_extension{.value = std::initializer_list<int64_t>{610, 710}});
  expect_set_extension_ok(packed_float_extension{.value = std::initializer_list<float>{611, 711}});
  expect_set_extension_ok(packed_double_extension{.value = std::initializer_list<double>{612, 712}});
  expect_set_extension_ok(packed_bool_extension{.value = std::initializer_list<hpp::proto::boolean>{true, false}});
  using enum ForeignEnum;
  expect_set_extension_ok(
      packed_enum_extension<>{.value = std::initializer_list<ForeignEnum>{FOREIGN_BAR, FOREIGN_BAZ}});
}

// -------------------------------------------------------------------

inline void ExpectAllSet(const TestPackedExtensions_t &message) {
  std::pmr::monotonic_buffer_resource mr;

  auto expect_extension_range_eq =
      [&]<typename Extension>(std::initializer_list<typename Extension::value_type::value_type> value, Extension ext) {
        expect(message.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
        expect(std::ranges::equal(value, ext.value));
      };

  expect_extension_range_eq({601, 701}, protobuf_unittest::packed_int32_extension{});
  expect_extension_range_eq({602, 702}, protobuf_unittest::packed_int64_extension{});
  expect_extension_range_eq({603, 703}, protobuf_unittest::packed_uint32_extension{});
  expect_extension_range_eq({604, 704}, protobuf_unittest::packed_uint64_extension{});
  expect_extension_range_eq({605, 705}, protobuf_unittest::packed_sint32_extension{});
  expect_extension_range_eq({606, 706}, protobuf_unittest::packed_sint64_extension{});
  expect_extension_range_eq({607, 707}, protobuf_unittest::packed_fixed32_extension{});
  expect_extension_range_eq({608, 708}, protobuf_unittest::packed_fixed64_extension{});
  expect_extension_range_eq({609, 709}, protobuf_unittest::packed_sfixed32_extension{});
  expect_extension_range_eq({610, 710}, protobuf_unittest::packed_sfixed64_extension{});
  expect_extension_range_eq({611, 711}, protobuf_unittest::packed_float_extension{});
  expect_extension_range_eq({612, 712}, protobuf_unittest::packed_double_extension{});
  expect_extension_range_eq({true, false}, protobuf_unittest::packed_bool_extension{});

  expect_extension_range_eq(
      std::initializer_list<protobuf_unittest::ForeignEnum>{protobuf_unittest::ForeignEnum::FOREIGN_BAR,
                                                            protobuf_unittest::ForeignEnum::FOREIGN_BAZ},
      protobuf_unittest::packed_enum_extension{});
}

// -------------------------------------------------------------------

inline void ExpectAllSet(const TestUnpackedExtensions_t &message) {
  std::pmr::monotonic_buffer_resource mr;
  auto expect_extension_range_eq =
      [&]<typename Extension>(std::initializer_list<typename Extension::value_type::value_type> value, Extension ext) {
        expect(message.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
        expect(std::ranges::equal(value, ext.value));
      };

  expect_extension_range_eq({601, 701}, protobuf_unittest::unpacked_int32_extension{});
  expect_extension_range_eq({602, 702}, protobuf_unittest::unpacked_int64_extension{});
  expect_extension_range_eq({603, 703}, protobuf_unittest::unpacked_uint32_extension{});
  expect_extension_range_eq({604, 704}, protobuf_unittest::unpacked_uint64_extension{});
  expect_extension_range_eq({605, 705}, protobuf_unittest::unpacked_sint32_extension{});
  expect_extension_range_eq({606, 706}, protobuf_unittest::unpacked_sint64_extension{});
  expect_extension_range_eq({607, 707}, protobuf_unittest::unpacked_fixed32_extension{});
  expect_extension_range_eq({608, 708}, protobuf_unittest::unpacked_fixed64_extension{});
  expect_extension_range_eq({609, 709}, protobuf_unittest::unpacked_sfixed32_extension{});
  expect_extension_range_eq({610, 710}, protobuf_unittest::unpacked_sfixed64_extension{});
  expect_extension_range_eq({611, 711}, protobuf_unittest::unpacked_float_extension{});
  expect_extension_range_eq({612, 712}, protobuf_unittest::unpacked_double_extension{});
  expect_extension_range_eq({true, false}, protobuf_unittest::unpacked_bool_extension{});

  expect_extension_range_eq({protobuf_unittest::ForeignEnum::FOREIGN_BAR, protobuf_unittest::ForeignEnum::FOREIGN_BAZ},
                            protobuf_unittest::unpacked_enum_extension{});
}

inline void SetOneof1(TestOneof2_t *message) {
  message->foo.emplace<TestOneof2_t::foo_lazy_message>().moo_int = 100;
  message->bar.emplace<TestOneof2_t::bar_string>("101");
  message->baz_int = 102;
  message->baz_string = "103";
}

inline void SetOneof2(TestOneof2_t *message) {
  message->foo.emplace<TestOneof2_t::foo_int>(200);
  message->bar.emplace<TestOneof2_t::bar_enum>(TestOneof2_t::NestedEnum::BAZ);
  message->baz_int = 202;
  message->baz_string = "203";
}

inline void ExpectOneofSet1(const TestOneof2_t &message) {
  expect(fatal(eq(TestOneof2_t::foo_lazy_message, message.foo.index())));
  const auto &foo_lazy_message = std::get<TestOneof2_t::foo_lazy_message>(message.foo);

  expect(fatal(eq(TestOneof2_t::bar_string, message.bar.index())));

  expect(fatal(eq(0, foo_lazy_message.corge_int.size())));

  expect(eq(100, foo_lazy_message.moo_int.value()));
  expect(eq("101"sv, std::get<TestOneof2_t::bar_string>(message.bar)));
  expect(eq(102, message.baz_int.value()));
  expect(eq("103"sv, message.baz_string.value()));
}

inline void ExpectOneofSet2(const TestOneof2_t &message) {
  expect(eq(TestOneof2_t::foo_int, message.foo.index()));
  expect(eq(TestOneof2_t::bar_enum, message.bar.index()));

  expect(eq(200, std::get<TestOneof2_t::foo_int>(message.foo)));
  expect(TestOneof2_t::NestedEnum::BAZ == std::get<TestOneof2_t::bar_enum>(message.bar));
  expect(eq(202, message.baz_int.value()));
  expect(eq("203"sv, message.baz_string.value()));
}

inline void ExpectOneofClear(const TestOneof2_t &message) {
  expect(!message.baz_int.has_value());
  expect(!message.baz_string.has_value());

  expect(eq(0, message.foo.index()));
  expect(eq(0, message.bar.index()));
}

} // namespace TestUtil
// NOLINTEND(clang-diagnostic-missing-designated-field-initializers)

const boost::ut::suite proto_test = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;
  auto unittest_descriptorset = read_file("unittest.desc.binpb");

  "protobuf"_test = []<class T> {
    T message;
    T message2;
    T message3;
    std::pmr::monotonic_buffer_resource mr;

    if constexpr (requires { TestUtil::ExpectClear(message); }) {
      TestUtil::ExpectClear(message);
    }
    TestUtil::SetAll(&message, hpp::proto::alloc_from{mr});
    message2 = message;

    std::vector<std::byte> data;
    expect(hpp::proto::write_proto(message2, data).ok());
    expect(hpp::proto::read_proto(message3, data, hpp::proto::alloc_from{mr}).ok());

    TestUtil::ExpectAllSet(message);
    TestUtil::ExpectAllSet(message2);
    TestUtil::ExpectAllSet(message3);
  } | std::tuple<TestAllTypes_t, TestAllExtensions_t, TestUnpackedTypes_t, TestPackedTypes_t, TestPackedExtensions_t>{};

#if !defined(HPP_PROTO_DISABLE_GLAZE)
  "interoperate_with_google_protobuf_parser"_test = [&]<class T> {
    T original;
    std::pmr::monotonic_buffer_resource mr;

    TestUtil::SetAll(&original, hpp::proto::alloc_from{mr});

    std::vector<char> data;
    expect(hpp::proto::write_proto(original, data).ok());

    auto original_json = gpb_based::proto_to_json(unittest_descriptorset, hpp::proto::message_name(original),
                                                  {data.data(), data.size()});
    expect(fatal(!original_json.empty()));
    auto generated_json = hpp::proto::write_json(original);

    expect(eq(generated_json.value(), original_json));

    T msg;
    expect(hpp::proto::read_json(msg, original_json, hpp::proto::alloc_from{mr}).ok());

    TestUtil::ExpectAllSet(msg);
  } | std::tuple<TestAllTypes_t, TestUnpackedTypes_t, TestPackedTypes_t>{};
#endif
};
// TODO: need a test case of TestOneof2

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}