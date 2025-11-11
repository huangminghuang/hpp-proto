#pragma once

#include "gpb_proto_json/gpb_proto_json.hpp"
#include "test_util.hpp"
#include <boost/ut.hpp>

// NOLINTBEGIN(clang-diagnostic-missing-designated-field-initializers)

using namespace std::literals::string_view_literals;
using namespace boost::ut;
template <hpp::proto::compile_time_string cts>
using bytes_literal = hpp::proto::bytes_literal<cts>;

template <typename T>
  requires requires { glz::meta<T>::value; }
std::ostream &operator<<(std::ostream &os, const T &v) {
  return os << hpp::proto::write_json(v).value();
}

template <typename Traits, template <typename> typename TypeMapping>
struct TestSuite {
  using mapping_t = TypeMapping<Traits>;
  using TestAllTypes_t = typename mapping_t::TestAllTypes_t;
  using TestAllExtensions_t = typename mapping_t::TestAllExtensions_t;
  using TestPackedTypes_t = typename mapping_t::TestPackedTypes_t;
  using TestPackedExtensions_t = typename mapping_t::TestPackedExtensions_t;

  using NestedEnum = typename mapping_t::NestedEnum;
  using ForeignEnum = typename mapping_t::ForeignEnum;
  using ImportEnum = typename mapping_t::ImportEnum;
  using ForeignMessage_t = typename mapping_t::ForeignMessage_t;
  using ImportMessage_t = typename mapping_t::ImportMessage_t;
  using NestedMessage_t = typename mapping_t::NestedMessage_t;
  using RepeatedGroup_t = typename mapping_t::RepeatedGroup_t;
  using RepeatedGroup_extension_t = typename mapping_t::RepeatedGroup_extension_t;

  using oneof_uint32_extension_t = typename mapping_t::oneof_uint32_extension_t;
  using oneof_nested_message_extension_t = typename mapping_t::oneof_nested_message_extension_t;
  using oneof_string_extension_t = typename mapping_t::oneof_string_extension_t;
  using oneof_bytes_extension_t = typename mapping_t::oneof_bytes_extension_t;

  using optional_int32_extension_t = typename mapping_t::optional_int32_extension_t;
  using optional_int64_extension_t = typename mapping_t::optional_int64_extension_t;
  using optional_uint32_extension_t = typename mapping_t::optional_uint32_extension_t;
  using optional_uint64_extension_t = typename mapping_t::optional_uint64_extension_t;
  using optional_sint32_extension_t = typename mapping_t::optional_sint32_extension_t;
  using optional_sint64_extension_t = typename mapping_t::optional_sint64_extension_t;
  using optional_fixed32_extension_t = typename mapping_t::optional_fixed32_extension_t;
  using optional_fixed64_extension_t = typename mapping_t::optional_fixed64_extension_t;
  using optional_sfixed32_extension_t = typename mapping_t::optional_sfixed32_extension_t;
  using optional_sfixed64_extension_t = typename mapping_t::optional_sfixed64_extension_t;
  using optional_float_extension_t = typename mapping_t::optional_float_extension_t;
  using optional_double_extension_t = typename mapping_t::optional_double_extension_t;
  using optional_bool_extension_t = typename mapping_t::optional_bool_extension_t;
  using optional_string_extension_t = typename mapping_t::optional_string_extension_t;
  using optional_bytes_extension_t = typename mapping_t::optional_bytes_extension_t;

  using optionalgroup_extension_t = typename mapping_t::optionalgroup_extension_t;
  using optional_nested_message_extension_t = typename mapping_t::optional_nested_message_extension_t;
  using optional_foreign_message_extension_t = typename mapping_t::optional_foreign_message_extension_t;
  using optional_import_message_extension_t = typename mapping_t::optional_import_message_extension_t;
  using optional_public_import_message_extension_t = typename mapping_t::optional_public_import_message_extension_t;
  using optional_lazy_message_extension_t = typename mapping_t::optional_lazy_message_extension_t;

  using optional_nested_enum_extension_t = typename mapping_t::optional_nested_enum_extension_t;
  using optional_foreign_enum_extension_t = typename mapping_t::optional_foreign_enum_extension_t;
  using optional_import_enum_extension_t = typename mapping_t::optional_import_enum_extension_t;

  using optional_string_piece_extension_t = typename mapping_t::optional_string_piece_extension_t;
  using optional_cord_extension_t = typename mapping_t::optional_cord_extension_t;

  using default_int32_extension_t = typename mapping_t::default_int32_extension_t;
  using default_int64_extension_t = typename mapping_t::default_int64_extension_t;
  using default_uint32_extension_t = typename mapping_t::default_uint32_extension_t;
  using default_uint64_extension_t = typename mapping_t::default_uint64_extension_t;
  using default_sint32_extension_t = typename mapping_t::default_sint32_extension_t;
  using default_sint64_extension_t = typename mapping_t::default_sint64_extension_t;
  using default_fixed32_extension_t = typename mapping_t::default_fixed32_extension_t;
  using default_fixed64_extension_t = typename mapping_t::default_fixed64_extension_t;
  using default_sfixed32_extension_t = typename mapping_t::default_sfixed32_extension_t;
  using default_sfixed64_extension_t = typename mapping_t::default_sfixed64_extension_t;
  using default_float_extension_t = typename mapping_t::default_float_extension_t;
  using default_double_extension_t = typename mapping_t::default_double_extension_t;
  using default_bool_extension_t = typename mapping_t::default_bool_extension_t;
  using default_string_extension_t = typename mapping_t::default_string_extension_t;
  using default_bytes_extension_t = typename mapping_t::default_bytes_extension_t;

  using default_nested_enum_extension_t = typename mapping_t::default_nested_enum_extension_t;
  using default_foreign_enum_extension_t = typename mapping_t::default_foreign_enum_extension_t;
  using default_import_enum_extension_t = typename mapping_t::default_import_enum_extension_t;

  using default_string_piece_extension_t = typename mapping_t::default_string_piece_extension_t;
  using default_cord_extension_t = typename mapping_t::default_cord_extension_t;

  using repeated_int32_extension_t = typename mapping_t::repeated_int32_extension_t;
  using repeated_int64_extension_t = typename mapping_t::repeated_int64_extension_t;
  using repeated_uint32_extension_t = typename mapping_t::repeated_uint32_extension_t;
  using repeated_uint64_extension_t = typename mapping_t::repeated_uint64_extension_t;
  using repeated_sint32_extension_t = typename mapping_t::repeated_sint32_extension_t;
  using repeated_sint64_extension_t = typename mapping_t::repeated_sint64_extension_t;
  using repeated_fixed32_extension_t = typename mapping_t::repeated_fixed32_extension_t;
  using repeated_fixed64_extension_t = typename mapping_t::repeated_fixed64_extension_t;
  using repeated_sfixed32_extension_t = typename mapping_t::repeated_sfixed32_extension_t;
  using repeated_sfixed64_extension_t = typename mapping_t::repeated_sfixed64_extension_t;
  using repeated_float_extension_t = typename mapping_t::repeated_float_extension_t;
  using repeated_double_extension_t = typename mapping_t::repeated_double_extension_t;
  using repeated_bool_extension_t = typename mapping_t::repeated_bool_extension_t;
  using repeated_string_extension_t = typename mapping_t::repeated_string_extension_t;
  using repeated_bytes_extension_t = typename mapping_t::repeated_bytes_extension_t;

  using repeatedgroup_extension_t = typename mapping_t::repeatedgroup_extension_t;
  using repeated_nested_message_extension_t = typename mapping_t::repeated_nested_message_extension_t;
  using repeated_foreign_message_extension_t = typename mapping_t::repeated_foreign_message_extension_t;
  using repeated_import_message_extension_t = typename mapping_t::repeated_import_message_extension_t;
  using repeated_lazy_message_extension_t = typename mapping_t::repeated_lazy_message_extension_t;
  using repeated_nested_enum_extension_t = typename mapping_t::repeated_nested_enum_extension_t;
  using repeated_foreign_enum_extension_t = typename mapping_t::repeated_foreign_enum_extension_t;
  using repeated_import_enum_extension_t = typename mapping_t::repeated_import_enum_extension_t;

  using repeated_string_piece_extension_t = typename mapping_t::repeated_string_piece_extension_t;
  using repeated_cord_extension_t = typename mapping_t::repeated_cord_extension_t;

  using packed_int32_extension_t = typename mapping_t::packed_int32_extension_t;
  using packed_int64_extension_t = typename mapping_t::packed_int64_extension_t;
  using packed_uint32_extension_t = typename mapping_t::packed_uint32_extension_t;
  using packed_uint64_extension_t = typename mapping_t::packed_uint64_extension_t;
  using packed_sint32_extension_t = typename mapping_t::packed_sint32_extension_t;
  using packed_sint64_extension_t = typename mapping_t::packed_sint64_extension_t;
  using packed_fixed32_extension_t = typename mapping_t::packed_fixed32_extension_t;
  using packed_fixed64_extension_t = typename mapping_t::packed_fixed64_extension_t;
  using packed_sfixed32_extension_t = typename mapping_t::packed_sfixed32_extension_t;
  using packed_sfixed64_extension_t = typename mapping_t::packed_sfixed64_extension_t;
  using packed_float_extension_t = typename mapping_t::packed_float_extension_t;
  using packed_double_extension_t = typename mapping_t::packed_double_extension_t;
  using packed_bool_extension_t = typename mapping_t::packed_bool_extension_t;
  using packed_enum_extension_t = typename mapping_t::packed_enum_extension_t;

  using bool_t = typename Traits::template repeated_t<bool>::value_type;
  using string_t = typename Traits::string_t;
  using bytes_t = typename Traits::bytes_t;

  static void SetAll(TestAllTypes_t *message, auto && /*unused*/) {
    SetOptionalFields(message);
    SetRepeatedFields(message);
    SetDefaultFields(message);
    SetOneofFields(message);
  }

  static void SetOptionalFields(TestAllTypes_t *message) {
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

    message->optionalgroup.emplace().a = 117;
    message->optional_nested_message.emplace().bb = 118;
    message->optional_foreign_message.emplace().c = 119;
    message->optional_import_message.emplace().d = 120;
    message->optional_public_import_message.emplace().e = 126;
    message->optional_lazy_message.emplace().bb = 127;

    message->optional_nested_enum = NestedEnum::BAZ;
    message->optional_foreign_enum = mapping_t::FOREIGN_BAZ;
    message->optional_import_enum = mapping_t::IMPORT_BAZ;
  }

  static void SetRepeatedFields(TestAllTypes_t *message) {
    const static auto repeated_int32 = std::initializer_list<int32_t>{201, 301};
    message->repeated_int32 = repeated_int32;
    const static auto repeated_int64 = std::initializer_list<int64_t>{202LL, 302LL};
    message->repeated_int64 = repeated_int64;
    const static auto repeated_uint32 = std::initializer_list<uint32_t>{203U, 303U};
    message->repeated_uint32 = repeated_uint32;
    const static auto repeated_uint64 = std::initializer_list<uint64_t>{204ULL, 304ULL};
    message->repeated_uint64 = repeated_uint64;
    const static auto repeated_sint32 = std::initializer_list<int32_t>{205, 305};
    message->repeated_sint32 = repeated_sint32;
    const static auto repeated_sint64 = std::initializer_list<int64_t>{206LL, 306LL};
    message->repeated_sint64 = repeated_sint64;

    const static auto repeated_fixed32 = std::initializer_list<uint32_t>{207U, 307U};
    message->repeated_fixed32 = repeated_fixed32;
    const static auto repeated_fixed64 = std::initializer_list<uint64_t>{208ULL, 308ULL};
    message->repeated_fixed64 = repeated_fixed64;
    const static auto repeated_sfixed32 = std::initializer_list<int32_t>{209, 309};
    message->repeated_sfixed32 = repeated_sfixed32;
    const static auto repeated_sfixed64 = std::initializer_list<int64_t>{210LL, 310LL};
    message->repeated_sfixed64 = repeated_sfixed64;
    const static auto repeated_float = std::initializer_list<float>{211.F, 311.F};
    message->repeated_float = repeated_float;
    const static auto repeated_double = std::initializer_list<double>{212., 312.};
    message->repeated_double = repeated_double;
    const static auto repeated_bool = std::initializer_list<bool_t>{true, false};
    message->repeated_bool = repeated_bool;

    const static auto repeated_string = std::initializer_list<string_t>{"215", "315"};
    message->repeated_string = repeated_string;
    const static auto repeated_bytes = std::initializer_list<bytes_t>{"216"_bytes, "316"_bytes};
    message->repeated_bytes = repeated_bytes;

    const static auto repeatedgroup = std::initializer_list<RepeatedGroup_t>{{.a = 217}, {.a = 317}};
    message->repeatedgroup = repeatedgroup;

    const static auto repeated_nested_message = std::initializer_list<NestedMessage_t>{{.bb = 218}, {.bb = 318}};
    message->repeated_nested_message = repeated_nested_message;

    const static auto repeated_foreign_message = std::initializer_list<ForeignMessage_t>{{.c = 219}, {.c = 319}};
    message->repeated_foreign_message = repeated_foreign_message;

    const static auto repeated_import_message = std::initializer_list<ImportMessage_t>{{.d = 220}, {.d = 320}};
    message->repeated_import_message = repeated_import_message;

    const static auto repeated_lazy_message = std::initializer_list<NestedMessage_t>{{.bb = 227}, {.bb = 327}};
    message->repeated_lazy_message = repeated_lazy_message;

    const static auto repeated_nested_enum = std::initializer_list<NestedEnum>{NestedEnum::BAR, NestedEnum::BAZ};
    message->repeated_nested_enum = repeated_nested_enum;
    const static auto repeated_foreign_enum =
        std::initializer_list<ForeignEnum>{mapping_t::FOREIGN_BAR, mapping_t::FOREIGN_BAZ};
    message->repeated_foreign_enum = repeated_foreign_enum;
    const static auto repeated_import_enum =
        std::initializer_list<ImportEnum>{mapping_t::IMPORT_BAR, mapping_t::IMPORT_BAZ};
    message->repeated_import_enum = repeated_import_enum;
  }

  // -------------------------------------------------------------------

  static void SetDefaultFields(TestAllTypes_t *message) {
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

    message->default_nested_enum = NestedEnum::FOO;
    message->default_foreign_enum = mapping_t::FOREIGN_FOO;
    message->default_import_enum = mapping_t::IMPORT_FOO;
  }

  // ------------------------------------------------------------------
  static void SetOneofFields(TestAllTypes_t *message) {
    message->oneof_field.template emplace<1>(601U);
    constexpr int oneof_nested_message_id = TestAllTypes_t::oneof_field_oneof_case::oneof_nested_message;
    message->oneof_field.template emplace<oneof_nested_message_id>().bb = 602;
    message->oneof_field.template emplace<string_t>("603");
    message->oneof_field.template emplace<bytes_t>("604"_bytes);
  }

  // -------------------------------------------------------------------

  static void expect_eq(auto expected, const auto &actual) {
    if constexpr (hpp::proto::concepts::optional<decltype(actual)>) {
      expect(eq(expected, actual.value()));
    } else {
      expect(eq(expected, actual));
    }
  }

  static void ExpectAllSet(const TestAllTypes_t &message) {
    expect_eq(101, message.optional_int32);
    expect_eq(102, message.optional_int64);
    expect_eq(103, message.optional_uint32);
    expect_eq(104, message.optional_uint64);
    expect_eq(105, message.optional_sint32);
    expect_eq(106, message.optional_sint64);
    expect_eq(107, message.optional_fixed32);
    expect_eq(108, message.optional_fixed64);
    expect_eq(109, message.optional_sfixed32);
    expect_eq(110, message.optional_sfixed64);
    expect_eq(111, message.optional_float);
    expect_eq(112, message.optional_double);
    expect_eq(true, message.optional_bool);

    expect_eq("115"sv, message.optional_string);
    expect_eq(bytes_literal<"116">(), message.optional_bytes);

    expect_eq(117, message.optionalgroup.value().a);
    expect_eq(118, message.optional_nested_message.value().bb);
    expect_eq(119, message.optional_foreign_message.value().c);
    expect_eq(120, message.optional_import_message.value().d);
    expect_eq(126, message.optional_public_import_message.value().e);
    expect_eq(127, message.optional_lazy_message.value().bb);

    expect_eq(NestedEnum::BAZ, message.optional_nested_enum);
    expect_eq(mapping_t::FOREIGN_BAZ, message.optional_foreign_enum);
    expect_eq(mapping_t::IMPORT_BAZ, message.optional_import_enum);

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
    expect(eq("216"_bytes, message.repeated_bytes[0]));

    expect(eq(217, message.repeatedgroup[0].a.value()));
    expect(eq(218, message.repeated_nested_message[0].bb.value()));
    expect(eq(219, message.repeated_foreign_message[0].c.value()));
    expect(eq(220, message.repeated_import_message[0].d.value()));
    expect(eq(227, message.repeated_lazy_message[0].bb.value()));

    expect(NestedEnum::BAR == message.repeated_nested_enum[0]);
    expect(mapping_t::FOREIGN_BAR == message.repeated_foreign_enum[0]);
    expect(mapping_t::IMPORT_BAR == message.repeated_import_enum[0]);

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
    expect(eq("316"_bytes, message.repeated_bytes[1]));

    expect_eq(317, message.repeatedgroup[1].a);
    expect_eq(318, message.repeated_nested_message[1].bb);
    expect_eq(319, message.repeated_foreign_message[1].c);
    expect_eq(320, message.repeated_import_message[1].d);
    expect_eq(327, message.repeated_lazy_message[1].bb);

    expect(eq(NestedEnum::BAZ, message.repeated_nested_enum[1]));
    expect(eq(mapping_t::FOREIGN_BAZ, message.repeated_foreign_enum[1]));
    expect(eq(mapping_t::IMPORT_BAZ, message.repeated_import_enum[1]));

    // -----------------------------------------------------------------

    expect_eq(401, message.default_int32);
    expect_eq(402, message.default_int64);
    expect_eq(403, message.default_uint32);
    expect_eq(404, message.default_uint64);
    expect_eq(405, message.default_sint32);
    expect_eq(406, message.default_sint64);
    expect_eq(407, message.default_fixed32);
    expect_eq(408, message.default_fixed64);
    expect_eq(409, message.default_sfixed32);
    expect_eq(410, message.default_sfixed64);
    expect_eq(411, message.default_float);
    expect_eq(412, message.default_double);
    expect(!message.default_bool.value());
    expect_eq("415"sv, message.default_string);
    expect_eq("416"_bytes, message.default_bytes);

    expect_eq(NestedEnum::FOO, message.default_nested_enum);
    expect_eq(mapping_t::FOREIGN_FOO, message.default_foreign_enum);
    expect_eq(mapping_t::IMPORT_FOO, message.default_import_enum);

    expect(eq(message.oneof_field.index(), TestAllTypes_t::oneof_bytes));
    expect(eq("604"_bytes, std::get<TestAllTypes_t::oneof_bytes>(message.oneof_field)));
  }

  // -------------------------------------------------------------------

  static void ExpectClear(const TestAllTypes_t &message) {
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
    expect(NestedEnum::FOO == message.optional_nested_enum.value());
    expect(!message.optional_foreign_enum.has_value());
    expect(mapping_t::FOREIGN_FOO == message.optional_foreign_enum.value());
    expect(!message.optional_import_enum.has_value());
    expect(mapping_t::IMPORT_FOO == message.optional_import_enum.value());

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
    expect_eq(41, message.default_int32);
    expect_eq(42, message.default_int64);
    expect_eq(43, message.default_uint32);
    expect_eq(44, message.default_uint64);
    expect(eq(-45, message.default_sint32.value()));
    expect_eq(46, message.default_sint64);
    expect_eq(47, message.default_fixed32);
    expect_eq(48, message.default_fixed64);
    expect_eq(49, message.default_sfixed32);
    expect(eq(-50, message.default_sfixed64.value()));
    expect(eq(51.5, message.default_float.value()));
    expect_eq(52e3, message.default_double);
    expect(message.default_bool.value());
    expect(eq("hello"sv, message.default_string.value()));
    expect(std::ranges::equal("world"_bytes, message.default_bytes.value()));

    expect(!message.default_nested_enum.has_value());
    expect(NestedEnum::BAR == message.default_nested_enum.value());
    expect(!message.default_foreign_enum.has_value());
    expect(mapping_t::FOREIGN_BAR == message.default_foreign_enum.value());
    expect(!message.default_import_enum.has_value());
    expect(mapping_t::IMPORT_BAR == message.default_import_enum.value());

    expect(std::holds_alternative<std::monostate>(message.oneof_field));
  }

  // -------------------------------------------------------------------

  static void SetAll(TestPackedTypes_t *message, auto && /*unused*/) {
    const static auto packed_int32 = std::initializer_list<int32_t>{601, 701};
    message->packed_int32 = packed_int32;

    const static auto packed_int64 = std::initializer_list<int64_t>{602, 702};
    message->packed_int64 = packed_int64;

    const static auto packed_uint32 = std::initializer_list<uint32_t>{603, 703};
    message->packed_uint32 = packed_uint32;

    const static auto packed_uint64 = std::initializer_list<uint64_t>{604, 704};
    message->packed_uint64 = packed_uint64;

    const static auto packed_sint32 = std::initializer_list<int32_t>{605, 705};
    message->packed_sint32 = packed_sint32;

    const static auto packed_sint64 = std::initializer_list<int64_t>{606, 706};
    message->packed_sint64 = packed_sint64;

    const static auto packed_fixed32 = std::initializer_list<uint32_t>{607, 707};
    message->packed_fixed32 = packed_fixed32;

    const static auto packed_fixed64 = std::initializer_list<uint64_t>{608, 708};
    message->packed_fixed64 = packed_fixed64;

    const static auto packed_sfixed32 = std::initializer_list<int32_t>{609, 709};
    message->packed_sfixed32 = packed_sfixed32;

    const static auto packed_sfixed64 = std::initializer_list<int64_t>{610, 710};
    message->packed_sfixed64 = packed_sfixed64;

    const static auto packed_float = std::initializer_list<float>{611, 711};
    message->packed_float = packed_float;

    const static auto packed_double = std::initializer_list<double>{612, 712};
    message->packed_double = packed_double;

    const static auto packed_bool = std::initializer_list<bool_t>{true, false};
    message->packed_bool = packed_bool;
    const static auto packed_enum = std::initializer_list<ForeignEnum>{mapping_t::FOREIGN_BAR, mapping_t::FOREIGN_BAZ};
    message->packed_enum = packed_enum;
  }

  static void SetAll(typename mapping_t::TestUnpackedTypes_t *message, auto && /*unused*/) {
    // The values applied here must match those of SetPackedFields.

    const static auto unpacked_int32 = std::initializer_list<int32_t>{601, 701};
    message->unpacked_int32 = unpacked_int32;

    const static auto unpacked_int64 = std::initializer_list<int64_t>{602, 702};
    message->unpacked_int64 = unpacked_int64;

    const static auto unpacked_uint32 = std::initializer_list<uint32_t>{603, 703};
    message->unpacked_uint32 = unpacked_uint32;

    const static auto unpacked_uint64 = std::initializer_list<uint64_t>{604, 704};
    message->unpacked_uint64 = unpacked_uint64;

    const static auto unpacked_sint32 = std::initializer_list<int32_t>{605, 705};
    message->unpacked_sint32 = unpacked_sint32;

    const static auto unpacked_sint64 = std::initializer_list<int64_t>{606, 706};
    message->unpacked_sint64 = unpacked_sint64;

    const static auto unpacked_fixed32 = std::initializer_list<uint32_t>{607, 707};
    message->unpacked_fixed32 = unpacked_fixed32;

    const static auto unpacked_fixed64 = std::initializer_list<uint64_t>{608, 708};
    message->unpacked_fixed64 = unpacked_fixed64;

    const static auto unpacked_sfixed32 = std::initializer_list<int32_t>{609, 709};
    message->unpacked_sfixed32 = unpacked_sfixed32;

    const static auto unpacked_sfixed64 = std::initializer_list<int64_t>{610, 710};
    message->unpacked_sfixed64 = unpacked_sfixed64;

    const static auto unpacked_float = std::initializer_list<float>{611, 711};
    message->unpacked_float = unpacked_float;

    const static auto unpacked_double = std::initializer_list<double>{612, 712};
    message->unpacked_double = unpacked_double;

    const static auto unpacked_bool = std::initializer_list<bool_t>{true, false};
    message->unpacked_bool = unpacked_bool;
    const static auto unpacked_enum =
        std::initializer_list<ForeignEnum>{mapping_t::FOREIGN_BAR, mapping_t::FOREIGN_BAZ};
    message->unpacked_enum = unpacked_enum;
  }

  // -------------------------------------------------------------------

  static void ExpectAllSet(const TestPackedTypes_t &message) {
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
    expect(mapping_t::FOREIGN_BAR == message.packed_enum[0]);

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
    expect(mapping_t::FOREIGN_BAZ == message.packed_enum[1]);
  }

  static void ExpectAllSet(const typename mapping_t::TestUnpackedTypes_t &message) {
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
    expect(mapping_t::FOREIGN_BAR == message.unpacked_enum[0]);

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
    expect(mapping_t::FOREIGN_BAZ == message.unpacked_enum[1]);
  }

  // ===================================================================
  // Extensions
  //
  // All this code is exactly equivalent to the above code except that it's
  // manipulating extension fields instead of normal ones.

  static void SetAll(TestAllExtensions_t *message, auto &&mr) {
    using namespace std::string_view_literals;
    auto expect_set_extension_ok = [&](auto &&ext) {
      expect(message->set_extension(ext, hpp::proto::alloc_from{mr}).ok());
    };
    expect_set_extension_ok(optional_int32_extension_t{.value = 101});
    expect_set_extension_ok(optional_int64_extension_t{.value = 102});
    expect_set_extension_ok(optional_uint32_extension_t{.value = 103});
    expect_set_extension_ok(optional_uint64_extension_t{.value = 104});
    expect_set_extension_ok(optional_sint32_extension_t{.value = 105});
    expect_set_extension_ok(optional_sint64_extension_t{.value = 106});
    expect_set_extension_ok(optional_fixed32_extension_t{.value = 107});
    expect_set_extension_ok(optional_fixed64_extension_t{.value = 108});
    expect_set_extension_ok(optional_sfixed32_extension_t{.value = 109});
    expect_set_extension_ok(optional_sfixed64_extension_t{.value = 110});
    expect_set_extension_ok(optional_float_extension_t{.value = 111});
    expect_set_extension_ok(optional_double_extension_t{.value = 112});
    expect_set_extension_ok(optional_bool_extension_t{.value = true});
    expect_set_extension_ok(optional_string_extension_t{.value = "115"});
    expect_set_extension_ok(optional_bytes_extension_t{.value = "116"_bytes});

    expect_set_extension_ok(optionalgroup_extension_t{.value = {.a = 117}});
    expect_set_extension_ok(optional_nested_message_extension_t{.value = {.bb = 118}});
    expect_set_extension_ok(optional_foreign_message_extension_t{.value = {.c = 119}});
    expect_set_extension_ok(optional_import_message_extension_t{.value = {.d = 120}});

    expect_set_extension_ok(optional_nested_enum_extension_t{.value = NestedEnum::BAZ});
    expect_set_extension_ok(optional_foreign_enum_extension_t{.value = mapping_t::FOREIGN_BAZ});
    expect_set_extension_ok(optional_import_enum_extension_t{.value = mapping_t::IMPORT_BAZ});

    expect_set_extension_ok(optional_string_piece_extension_t{.value = "124"});
    expect_set_extension_ok(optional_cord_extension_t{.value = "125"});

    expect_set_extension_ok(optional_public_import_message_extension_t{.value = {.e = 126}});
    expect_set_extension_ok(optional_lazy_message_extension_t{.value = {.bb = 127}});

    // -----------------------------------------------------------------

    expect_set_extension_ok(repeated_int32_extension_t{.value = std::initializer_list<int32_t>{201, 301}});
    expect_set_extension_ok(repeated_int64_extension_t{.value = std::initializer_list<int64_t>{202LL, 302LL}});
    expect_set_extension_ok(repeated_uint32_extension_t{.value = std::initializer_list<uint32_t>{203U, 303U}});
    expect_set_extension_ok(repeated_uint64_extension_t{.value = std::initializer_list<uint64_t>{204ULL, 304ULL}});
    expect_set_extension_ok(repeated_sint32_extension_t{.value = std::initializer_list<int32_t>{205, 305}});
    expect_set_extension_ok(repeated_sint64_extension_t{.value = std::initializer_list<int64_t>{206LL, 306LL}});
    expect_set_extension_ok(repeated_fixed32_extension_t{.value = std::initializer_list<uint32_t>{207U, 307U}});
    expect_set_extension_ok(repeated_fixed64_extension_t{.value = std::initializer_list<uint64_t>{208ULL, 308ULL}});
    expect_set_extension_ok(repeated_sfixed32_extension_t{.value = std::initializer_list<int32_t>{209, 309}});
    expect_set_extension_ok(repeated_sfixed64_extension_t{.value = std::initializer_list<int64_t>{210LL, 310LL}});
    expect_set_extension_ok(repeated_float_extension_t{.value = std::initializer_list<float>{211, 311}});
    expect_set_extension_ok(repeated_double_extension_t{.value = std::initializer_list<double>{212, 312}});
    expect_set_extension_ok(repeated_bool_extension_t{.value = std::initializer_list<bool_t>{true, false}});
    expect_set_extension_ok(repeated_string_extension_t{.value = std::initializer_list<string_t>{"215", "315"}});
    expect_set_extension_ok(
        repeated_bytes_extension_t{.value = std::initializer_list<bytes_t>{"216"_bytes, "316"_bytes}});

    expect_set_extension_ok(
        repeatedgroup_extension_t{.value = std::initializer_list<RepeatedGroup_extension_t>{{.a = 217}, {.a = 317}}});
    expect_set_extension_ok(
        repeated_nested_message_extension_t{.value = std::initializer_list<NestedMessage_t>{{.bb = 218}, {.bb = 318}}});
    expect_set_extension_ok(
        repeated_foreign_message_extension_t{.value = std::initializer_list<ForeignMessage_t>{{.c = 219}, {.c = 319}}});
    expect_set_extension_ok(
        repeated_import_message_extension_t{.value = std::initializer_list<ImportMessage_t>{{.d = 220}, {.d = 320}}});
    expect_set_extension_ok(
        repeated_lazy_message_extension_t{.value = std::initializer_list<NestedMessage_t>{{.bb = 227}, {.bb = 327}}});

    expect_set_extension_ok(
        repeated_nested_enum_extension_t{.value = std::initializer_list<NestedEnum>{NestedEnum::BAR, NestedEnum::BAZ}});
    using foreign_enum_t = typename repeated_foreign_enum_extension_t::value_type::value_type;
    expect_set_extension_ok(repeated_foreign_enum_extension_t{
        .value = std::initializer_list<foreign_enum_t>{mapping_t::FOREIGN_BAR, mapping_t::FOREIGN_BAZ}});
    using import_enum_t = typename repeated_import_enum_extension_t::value_type::value_type;
    expect_set_extension_ok(repeated_import_enum_extension_t{
        .value = std::initializer_list<import_enum_t>{mapping_t::IMPORT_BAR, mapping_t::IMPORT_BAZ}});

    expect_set_extension_ok(repeated_string_piece_extension_t{.value = std::initializer_list<string_t>{"224", "324"}});
    expect_set_extension_ok(repeated_cord_extension_t{.value = std::initializer_list<string_t>{"225", "325"}});

    // -----------------------------------------------------------------

    expect_set_extension_ok(default_int32_extension_t{.value = 401});
    expect_set_extension_ok(default_int64_extension_t{.value = 402});
    expect_set_extension_ok(default_uint32_extension_t{.value = 403});
    expect_set_extension_ok(default_uint64_extension_t{.value = 404});
    expect_set_extension_ok(default_sint32_extension_t{.value = 405});
    expect_set_extension_ok(default_sint64_extension_t{.value = 406});
    expect_set_extension_ok(default_fixed32_extension_t{.value = 407});
    expect_set_extension_ok(default_fixed64_extension_t{.value = 408});
    expect_set_extension_ok(default_sfixed32_extension_t{.value = 409});
    expect_set_extension_ok(default_sfixed64_extension_t{.value = 410});
    expect_set_extension_ok(default_float_extension_t{.value = 411});
    expect_set_extension_ok(default_double_extension_t{.value = 412});

    expect_set_extension_ok(default_bool_extension_t{.value = false});
    expect_set_extension_ok(default_string_extension_t{.value = "415"});
    expect_set_extension_ok(default_bytes_extension_t{.value = "416"_bytes});

    expect_set_extension_ok(default_nested_enum_extension_t{.value = NestedEnum::FOO});
    expect_set_extension_ok(default_foreign_enum_extension_t{.value = mapping_t::FOREIGN_FOO});
    expect_set_extension_ok(default_import_enum_extension_t{.value = mapping_t::IMPORT_FOO});

    expect_set_extension_ok(default_string_piece_extension_t{.value = "424"});
    expect_set_extension_ok(default_cord_extension_t{.value = "425"});

    SetOneofFields(message, hpp::proto::alloc_from{mr});
  }

  static void SetOneofFields(TestAllExtensions_t *message, auto &&mr) {
    auto expect_set_extension_ok = [&](auto &&ext) {
      expect(message->set_extension(ext, hpp::proto::alloc_from{mr}).ok());
    };

    expect_set_extension_ok(oneof_uint32_extension_t{.value = 601});
    expect_set_extension_ok(oneof_nested_message_extension_t{.value = {.bb = 602}});
    expect_set_extension_ok(oneof_string_extension_t{.value = "603"});
    expect_set_extension_ok(oneof_bytes_extension_t{.value = "604"_bytes});
  }

  // -------------------------------------------------------------------

  static void ExpectAllSet(const TestAllExtensions_t &message) {
    expect(message.has_extension(optional_int32_extension_t{}));
    expect(message.has_extension(optional_int64_extension_t{}));
    expect(message.has_extension(optional_uint32_extension_t{}));
    expect(message.has_extension(optional_uint64_extension_t{}));
    expect(message.has_extension(optional_sint32_extension_t{}));
    expect(message.has_extension(optional_sint64_extension_t{}));
    expect(message.has_extension(optional_fixed32_extension_t{}));
    expect(message.has_extension(optional_fixed64_extension_t{}));
    expect(message.has_extension(optional_sfixed32_extension_t{}));
    expect(message.has_extension(optional_sfixed64_extension_t{}));
    expect(message.has_extension(optional_float_extension_t{}));
    expect(message.has_extension(optional_double_extension_t{}));
    expect(message.has_extension(optional_bool_extension_t{}));
    expect(message.has_extension(optional_string_extension_t{}));
    expect(message.has_extension(optional_bytes_extension_t{}));

    expect(message.has_extension(optionalgroup_extension_t{}));
    expect(message.has_extension(optional_nested_message_extension_t{}));
    expect(message.has_extension(optional_foreign_message_extension_t{}));
    expect(message.has_extension(optional_import_message_extension_t{}));
    expect(message.has_extension(optional_public_import_message_extension_t{}));
    expect(message.has_extension(optional_lazy_message_extension_t{}));

    auto get_value = [](const auto &ext) { return ext.value; };

    auto expect_extension_value_set = [&](auto ext, const auto &get_value) {
      std::pmr::monotonic_buffer_resource mr;
      expect(message.get_extension(ext, hpp::proto::alloc_from(mr)).ok());
      expect(get_value(ext));
    };

    expect_extension_value_set(optionalgroup_extension_t{}, [](const auto &ext) { return ext.value.a; });
    expect_extension_value_set(optional_nested_message_extension_t{}, [](const auto &ext) { return ext.value.bb; });
    expect_extension_value_set(optional_foreign_message_extension_t{}, [](const auto &ext) { return ext.value.c; });
    expect_extension_value_set(optional_import_message_extension_t{}, [](const auto &ext) { return ext.value.d; });
    expect_extension_value_set(optional_public_import_message_extension_t{},
                               [](const auto &ext) { return ext.value.e; });
    expect_extension_value_set(optional_lazy_message_extension_t{}, [](const auto &ext) { return ext.value.bb; });

    expect(message.has_extension(optional_nested_enum_extension_t{}));
    expect(message.has_extension(optional_foreign_enum_extension_t{}));
    expect(message.has_extension(optional_import_enum_extension_t{}));

    expect(message.has_extension(optional_string_piece_extension_t{}));
    expect(message.has_extension(optional_cord_extension_t{}));

    std::pmr::monotonic_buffer_resource mr;

    auto expect_extension_value_eq = [&](const auto &value, auto ext, const auto &get_value) {
      expect(message.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
      expect(value == get_value(ext));
    };

    expect_extension_value_eq(101, optional_int32_extension_t{}, get_value);
    expect_extension_value_eq(102, optional_int64_extension_t{}, get_value);
    expect_extension_value_eq(103U, optional_uint32_extension_t{}, get_value);
    expect_extension_value_eq(104U, optional_uint64_extension_t{}, get_value);
    expect_extension_value_eq(105, optional_sint32_extension_t{}, get_value);
    expect_extension_value_eq(106, optional_sint64_extension_t{}, get_value);
    expect_extension_value_eq(107U, optional_fixed32_extension_t{}, get_value);
    expect_extension_value_eq(108U, optional_fixed64_extension_t{}, get_value);
    expect_extension_value_eq(109, optional_sfixed32_extension_t{}, get_value);
    expect_extension_value_eq(110, optional_sfixed64_extension_t{}, get_value);
    expect_extension_value_eq(111, optional_float_extension_t{}, get_value);
    expect_extension_value_eq(112, optional_double_extension_t{}, get_value);
    expect_extension_value_eq(true, optional_bool_extension_t{}, get_value);
    expect_extension_value_eq("115"sv, optional_string_extension_t{}, get_value);
    expect_extension_value_eq("116"_bytes, optional_bytes_extension_t{}, get_value);

    expect_extension_value_eq(117, optionalgroup_extension_t{}, [](const auto &ext) { return ext.value.a.value(); });
    expect_extension_value_eq(118, optional_nested_message_extension_t{},
                              [](const auto &ext) { return ext.value.bb.value(); });

    expect_extension_value_eq(119, optional_foreign_message_extension_t{},
                              [](const auto &ext) { return ext.value.c.value(); });

    expect_extension_value_eq(120, optional_import_message_extension_t{},
                              [](const auto &ext) { return ext.value.d.value(); });

    expect_extension_value_eq(NestedEnum::BAZ, optional_nested_enum_extension_t{}, get_value);
    expect_extension_value_eq(mapping_t::FOREIGN_BAZ, optional_foreign_enum_extension_t{}, get_value);
    expect_extension_value_eq(mapping_t::IMPORT_BAZ, optional_import_enum_extension_t{}, get_value);

    expect_extension_value_eq("124"sv, optional_string_piece_extension_t{}, get_value);
    expect_extension_value_eq("125"sv, optional_cord_extension_t{}, get_value);
    expect_extension_value_eq(126, optional_public_import_message_extension_t{},
                              [](const auto &ext) { return ext.value.e.value(); });

    expect_extension_value_eq(127, optional_lazy_message_extension_t{},
                              [](const auto &ext) { return ext.value.bb.value(); });

    // -----------------------------------------------------------------

    auto expect_extension_range_eq =
        [&]<typename Extension>(std::initializer_list<typename Extension::value_type::value_type> value,
                                Extension ext) {
          expect(message.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
          expect(std::ranges::equal(value, ext.value));
        };

    expect_extension_range_eq({201, 301}, repeated_int32_extension_t{});
    expect_extension_range_eq({202, 302}, repeated_int64_extension_t{});
    expect_extension_range_eq({203, 303}, repeated_uint32_extension_t{});
    expect_extension_range_eq({204, 304}, repeated_uint64_extension_t{});
    expect_extension_range_eq({205, 305}, repeated_sint32_extension_t{});
    expect_extension_range_eq({206, 306}, repeated_sint64_extension_t{});
    expect_extension_range_eq({207, 307}, repeated_fixed32_extension_t{});
    expect_extension_range_eq({208, 308}, repeated_fixed64_extension_t{});
    expect_extension_range_eq({209, 309}, repeated_sfixed32_extension_t{});
    expect_extension_range_eq({210, 310}, repeated_sfixed64_extension_t{});
    expect_extension_range_eq({211, 311}, repeated_float_extension_t{});
    expect_extension_range_eq({212, 312}, repeated_double_extension_t{});
    expect_extension_range_eq({true, false}, repeated_bool_extension_t{});
    expect_extension_range_eq(std::initializer_list<string_t>{"215", "315"}, repeated_string_extension_t{});
    expect_extension_range_eq(std::initializer_list<bytes_t>{"216"_bytes, "316"_bytes}, repeated_bytes_extension_t{});
    expect_extension_range_eq({{.a = 217}, {.a = 317}}, repeatedgroup_extension_t{});

    expect_extension_range_eq({{.bb = 218}, {.bb = 318}}, repeated_nested_message_extension_t{});

    expect_extension_range_eq({{.c = 219}, {.c = 319}}, repeated_foreign_message_extension_t{});

    expect_extension_range_eq({{.d = 220}, {.d = 320}}, repeated_import_message_extension_t{});

    expect_extension_range_eq({{.bb = 227}, {.bb = 327}}, repeated_lazy_message_extension_t{});

    expect_extension_range_eq({NestedEnum::BAR, NestedEnum::BAZ}, repeated_nested_enum_extension_t{});

    expect_extension_range_eq({mapping_t::FOREIGN_BAR, mapping_t::FOREIGN_BAZ}, repeated_foreign_enum_extension_t{});

    expect_extension_range_eq({mapping_t::IMPORT_BAR, mapping_t::IMPORT_BAZ}, repeated_import_enum_extension_t{});

    expect_extension_range_eq(std::initializer_list<string_t>{"224", "324"}, repeated_string_piece_extension_t{});

    expect_extension_range_eq(std::initializer_list<string_t>{"225", "325"}, repeated_cord_extension_t{});

    // -----------------------------------------------------------------

    expect(message.has_extension(default_int32_extension_t{}));
    expect(message.has_extension(default_int64_extension_t{}));
    expect(message.has_extension(default_uint32_extension_t{}));
    expect(message.has_extension(default_uint64_extension_t{}));
    expect(message.has_extension(default_sint32_extension_t{}));
    expect(message.has_extension(default_sint64_extension_t{}));
    expect(message.has_extension(default_fixed32_extension_t{}));
    expect(message.has_extension(default_fixed64_extension_t{}));
    expect(message.has_extension(default_sfixed32_extension_t{}));
    expect(message.has_extension(default_sfixed64_extension_t{}));
    expect(message.has_extension(default_float_extension_t{}));
    expect(message.has_extension(default_double_extension_t{}));
    expect(message.has_extension(default_bool_extension_t{}));
    expect(message.has_extension(default_string_extension_t{}));
    expect(message.has_extension(default_bytes_extension_t{}));

    expect(message.has_extension(default_nested_enum_extension_t{}));
    expect(message.has_extension(default_foreign_enum_extension_t{}));
    expect(message.has_extension(default_import_enum_extension_t{}));

    expect(message.has_extension(default_string_piece_extension_t{}));
    expect(message.has_extension(default_cord_extension_t{}));

    expect_extension_value_eq(401, default_int32_extension_t{}, get_value);
    expect_extension_value_eq(402, default_int64_extension_t{}, get_value);
    expect_extension_value_eq(403U, default_uint32_extension_t{}, get_value);
    expect_extension_value_eq(404U, default_uint64_extension_t{}, get_value);
    expect_extension_value_eq(405, default_sint32_extension_t{}, get_value);
    expect_extension_value_eq(406, default_sint64_extension_t{}, get_value);
    expect_extension_value_eq(407U, default_fixed32_extension_t{}, get_value);
    expect_extension_value_eq(408U, default_fixed64_extension_t{}, get_value);
    expect_extension_value_eq(409, default_sfixed32_extension_t{}, get_value);
    expect_extension_value_eq(410, default_sfixed64_extension_t{}, get_value);
    expect_extension_value_eq(411, default_float_extension_t{}, get_value);
    expect_extension_value_eq(412, default_double_extension_t{}, get_value);
    expect_extension_value_eq(false, default_bool_extension_t{}, get_value);
    expect_extension_value_eq("415"sv, default_string_extension_t{}, get_value);
    expect_extension_value_eq("416"_bytes, default_bytes_extension_t{}, get_value);

    expect_extension_value_eq(NestedEnum::FOO, default_nested_enum_extension_t{}, get_value);
    expect_extension_value_eq(mapping_t::FOREIGN_FOO, default_foreign_enum_extension_t{}, get_value);
    expect_extension_value_eq(mapping_t::IMPORT_FOO, default_import_enum_extension_t{}, get_value);

    expect_extension_value_eq("424"sv, default_string_piece_extension_t{}, get_value);
    expect_extension_value_eq("425"sv, default_cord_extension_t{}, get_value);

    expect(message.has_extension(oneof_uint32_extension_t{}));
    expect_extension_value_set(oneof_nested_message_extension_t{},
                               [](const auto &ext) { return ext.value.bb.value(); });
    expect(message.has_extension(oneof_string_extension_t{}));
    expect(message.has_extension(oneof_bytes_extension_t{}));

    expect_extension_value_eq(601U, oneof_uint32_extension_t{}, get_value);
    expect_extension_value_eq(602, oneof_nested_message_extension_t{},
                              [](const auto &ext) { return ext.value.bb.value(); });
    expect_extension_value_eq("603"sv, oneof_string_extension_t{}, get_value);
    expect_extension_value_eq("604"_bytes, oneof_bytes_extension_t{}, get_value);
  }

  // -------------------------------------------------------------------

  static void ExpectClear(const TestAllExtensions_t &message) {
    std::vector<std::byte> data;
    expect(hpp::proto::write_proto(message, data).ok());
    expect(eq(0, data.size()));

    std::pmr::monotonic_buffer_resource mr;

    //.blah.has_value() should initially be false for all optional fields.
    expect(!message.has_extension(optional_int32_extension_t{}));
    expect(!message.has_extension(optional_int64_extension_t{}));
    expect(!message.has_extension(optional_uint32_extension_t{}));
    expect(!message.has_extension(optional_uint64_extension_t{}));
    expect(!message.has_extension(optional_sint32_extension_t{}));
    expect(!message.has_extension(optional_sint64_extension_t{}));
    expect(!message.has_extension(optional_fixed32_extension_t{}));
    expect(!message.has_extension(optional_fixed64_extension_t{}));
    expect(!message.has_extension(optional_sfixed32_extension_t{}));
    expect(!message.has_extension(optional_sfixed64_extension_t{}));
    expect(!message.has_extension(optional_float_extension_t{}));
    expect(!message.has_extension(optional_double_extension_t{}));
    expect(!message.has_extension(optional_bool_extension_t{}));
    expect(!message.has_extension(optional_string_extension_t{}));
    expect(!message.has_extension(optional_bytes_extension_t{}));

    expect(!message.has_extension(optionalgroup_extension_t{}));
    expect(!message.has_extension(optional_nested_message_extension_t{}));
    expect(!message.has_extension(optional_foreign_message_extension_t{}));
    expect(!message.has_extension(optional_import_message_extension_t{}));
    expect(!message.has_extension(optional_public_import_message_extension_t{}));
    expect(!message.has_extension(optional_lazy_message_extension_t{}));

    expect(!message.has_extension(optional_nested_enum_extension_t{}));
    expect(!message.has_extension(optional_foreign_enum_extension_t{}));
    expect(!message.has_extension(optional_import_enum_extension_t{}));

    expect(!message.has_extension(optional_string_piece_extension_t{}));
    expect(!message.has_extension(optional_cord_extension_t{}));

    auto get_value = [](const auto &ext) { return ext.value; };

    auto expect_extension_value_eq = [&](const auto &v, auto &&ext, const auto &get_value) {
      expect(message.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
      expect(v == get_value(ext));
    };

    // Optional fields without defaults are set to zero or something like it.
    expect_extension_value_eq(0, optional_int32_extension_t{}, get_value);
    expect_extension_value_eq(0, optional_int64_extension_t{}, get_value);
    expect_extension_value_eq(0U, optional_uint32_extension_t{}, get_value);
    expect_extension_value_eq(0U, optional_uint64_extension_t{}, get_value);
    expect_extension_value_eq(0, optional_sint32_extension_t{}, get_value);
    expect_extension_value_eq(0, optional_sint64_extension_t{}, get_value);
    expect_extension_value_eq(0U, optional_fixed32_extension_t{}, get_value);
    expect_extension_value_eq(0U, optional_fixed64_extension_t{}, get_value);
    expect_extension_value_eq(0, optional_sfixed32_extension_t{}, get_value);
    expect_extension_value_eq(0, optional_sfixed64_extension_t{}, get_value);
    expect_extension_value_eq(0, optional_float_extension_t{}, get_value);
    expect_extension_value_eq(0.0, optional_double_extension_t{}, get_value);
    expect_extension_value_eq(0.0F, optional_bool_extension_t{}, get_value);
    expect_extension_value_eq(""sv, optional_string_extension_t{}, get_value);
    expect_extension_value_eq(""_bytes, optional_bytes_extension_t{}, get_value);

    auto expect_extension_value_not_set = [&](auto ext, const auto &get_value) {
      expect(message.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
      expect(!get_value(ext).has_value());
    };
    // Embedded messages should also be clear.
    expect_extension_value_not_set(optionalgroup_extension_t{}, [](const auto &ext) { return ext.value.a; });
    expect_extension_value_not_set(optional_nested_message_extension_t{}, [](const auto &ext) { return ext.value.bb; });
    expect_extension_value_not_set(optional_foreign_message_extension_t{}, [](const auto &ext) { return ext.value.c; });
    expect_extension_value_not_set(optional_import_message_extension_t{}, [](const auto &ext) { return ext.value.d; });
    expect_extension_value_not_set(optional_public_import_message_extension_t{},
                                   [](const auto &ext) { return ext.value.e; });
    expect_extension_value_not_set(optional_lazy_message_extension_t{}, [](const auto &ext) { return ext.value.bb; });

    // Enums without defaults are set to the first value in the enum.
    expect_extension_value_eq(mapping_t::FOREIGN_FOO, optional_foreign_enum_extension_t{}, get_value);
    expect_extension_value_eq(mapping_t::IMPORT_FOO, optional_import_enum_extension_t{}, get_value);

    auto opt = hpp::proto::alloc_from{mr};
    expect_extension_value_eq(""sv, optional_string_piece_extension_t{}, get_value);
    expect_extension_value_eq(""sv, optional_cord_extension_t{}, get_value);

    // Repeated fields are empty.
    expect(!message.has_extension(repeated_int32_extension_t{}));
    expect(!message.has_extension(repeated_int64_extension_t{}));
    expect(!message.has_extension(repeated_uint32_extension_t{}));
    expect(!message.has_extension(repeated_uint64_extension_t{}));
    expect(!message.has_extension(repeated_sint32_extension_t{}));
    expect(!message.has_extension(repeated_sint64_extension_t{}));
    expect(!message.has_extension(repeated_fixed32_extension_t{}));
    expect(!message.has_extension(repeated_fixed64_extension_t{}));
    expect(!message.has_extension(repeated_sfixed32_extension_t{}));
    expect(!message.has_extension(repeated_sfixed64_extension_t{}));
    expect(!message.has_extension(repeated_float_extension_t{}));
    expect(!message.has_extension(repeated_double_extension_t{}));
    expect(!message.has_extension(repeated_bool_extension_t{}));
    expect(!message.has_extension(repeated_string_extension_t{}));
    expect(!message.has_extension(repeated_bytes_extension_t{}));

    expect(!message.has_extension(repeatedgroup_extension_t{}));
    expect(!message.has_extension(repeated_nested_message_extension_t{}));
    expect(!message.has_extension(repeated_foreign_message_extension_t{}));
    expect(!message.has_extension(repeated_import_message_extension_t{}));
    expect(!message.has_extension(repeated_lazy_message_extension_t{}));
    expect(!message.has_extension(repeated_nested_enum_extension_t{}));
    expect(!message.has_extension(repeated_foreign_enum_extension_t{}));
    expect(!message.has_extension(repeated_import_enum_extension_t{}));

    expect(!message.has_extension(repeated_string_piece_extension_t{}));
    expect(!message.has_extension(repeated_cord_extension_t{}));

    //.blah.has_value() should also be false for all default fields.
    expect(!message.has_extension(default_int32_extension_t{}));
    expect(!message.has_extension(default_int64_extension_t{}));
    expect(!message.has_extension(default_uint32_extension_t{}));
    expect(!message.has_extension(default_uint64_extension_t{}));
    expect(!message.has_extension(default_sint32_extension_t{}));
    expect(!message.has_extension(default_sint64_extension_t{}));
    expect(!message.has_extension(default_fixed32_extension_t{}));
    expect(!message.has_extension(default_fixed64_extension_t{}));
    expect(!message.has_extension(default_sfixed32_extension_t{}));
    expect(!message.has_extension(default_sfixed64_extension_t{}));
    expect(!message.has_extension(default_float_extension_t{}));
    expect(!message.has_extension(default_double_extension_t{}));
    expect(!message.has_extension(default_bool_extension_t{}));
    expect(!message.has_extension(default_string_extension_t{}));
    expect(!message.has_extension(default_bytes_extension_t{}));

    expect(!message.has_extension(default_nested_enum_extension_t{}));
    expect(!message.has_extension(default_foreign_enum_extension_t{}));
    expect(!message.has_extension(default_import_enum_extension_t{}));

    expect(!message.has_extension(default_string_piece_extension_t{}));
    expect(!message.has_extension(default_cord_extension_t{}));

    // Fields with defaults have their default values (duh).
    expect_extension_value_eq(41, default_int32_extension_t{}, get_value);
    expect_extension_value_eq(42, default_int64_extension_t{}, get_value);
    expect_extension_value_eq(43U, default_uint32_extension_t{}, get_value);
    expect_extension_value_eq(44U, default_uint64_extension_t{}, get_value);
    expect_extension_value_eq(-45, default_sint32_extension_t{}, get_value);
    expect_extension_value_eq(46, default_sint64_extension_t{}, get_value);
    expect_extension_value_eq(47U, default_fixed32_extension_t{}, get_value);
    expect_extension_value_eq(48U, default_fixed64_extension_t{}, get_value);
    expect_extension_value_eq(49, default_sfixed32_extension_t{}, get_value);
    expect_extension_value_eq(-50, default_sfixed64_extension_t{}, get_value);
    expect_extension_value_eq(51.5, default_float_extension_t{}, get_value);
    expect_extension_value_eq(52e3, default_double_extension_t{}, get_value);
    expect_extension_value_eq(true, default_bool_extension_t{}, get_value);
    expect_extension_value_eq("hello"sv, default_string_extension_t{}, get_value);
    expect_extension_value_eq("world"_bytes, default_bytes_extension_t{}, get_value);

    expect_extension_value_eq(NestedEnum::BAR, default_nested_enum_extension_t{}, get_value);
    expect_extension_value_eq(mapping_t::FOREIGN_BAR, default_foreign_enum_extension_t{}, get_value);
    expect_extension_value_eq(mapping_t::IMPORT_BAR, default_import_enum_extension_t{}, get_value);

    expect_extension_value_eq("abc"sv, default_string_piece_extension_t{}, get_value);
    expect_extension_value_eq("123"sv, default_cord_extension_t{}, get_value);

    expect(!message.has_extension(oneof_uint32_extension_t{}));
    expect(!message.has_extension(oneof_nested_message_extension_t{}));
    expect(!message.has_extension(oneof_string_extension_t{}));
    expect(!message.has_extension(oneof_bytes_extension_t{}));
  }
  // -------------------------------------------------------------------

  static void SetAll(TestPackedExtensions_t *message, auto &&mr) {

    auto expect_set_extension_ok = [&](auto &&ext) {
      expect(message->set_extension(ext, hpp::proto::alloc_from{mr}).ok());
    };

    expect_set_extension_ok(packed_int32_extension_t{.value = std::initializer_list<int32_t>{601, 701}});
    expect_set_extension_ok(packed_int64_extension_t{.value = std::initializer_list<int64_t>{602, 702}});
    expect_set_extension_ok(packed_uint32_extension_t{.value = std::initializer_list<uint32_t>{603, 703}});
    expect_set_extension_ok(packed_uint64_extension_t{.value = std::initializer_list<uint64_t>{604, 704}});
    expect_set_extension_ok(packed_sint32_extension_t{.value = std::initializer_list<int32_t>{605, 705}});
    expect_set_extension_ok(packed_sint64_extension_t{.value = std::initializer_list<int64_t>{606, 706}});
    expect_set_extension_ok(packed_fixed32_extension_t{.value = std::initializer_list<uint32_t>{607, 707}});
    expect_set_extension_ok(packed_fixed64_extension_t{.value = std::initializer_list<uint64_t>{608, 708}});
    expect_set_extension_ok(packed_sfixed32_extension_t{.value = std::initializer_list<int32_t>{609, 709}});
    expect_set_extension_ok(packed_sfixed64_extension_t{.value = std::initializer_list<int64_t>{610, 710}});
    expect_set_extension_ok(packed_float_extension_t{.value = std::initializer_list<float>{611, 711}});
    expect_set_extension_ok(packed_double_extension_t{.value = std::initializer_list<double>{612, 712}});
    expect_set_extension_ok(packed_bool_extension_t{.value = std::initializer_list<bool_t>{true, false}});
    expect_set_extension_ok(packed_enum_extension_t{
        .value = std::initializer_list<ForeignEnum>{mapping_t::FOREIGN_BAR, mapping_t::FOREIGN_BAZ}});
  }

  // -------------------------------------------------------------------

  static void ExpectAllSet(const TestPackedExtensions_t &message) {
    std::pmr::monotonic_buffer_resource mr;

    auto expect_extension_range_eq =
        [&]<typename Extension>(std::initializer_list<typename Extension::value_type::value_type> value,
                                Extension ext) {
          expect(message.get_extension(ext, hpp::proto::alloc_from{mr}).ok());
          expect(std::ranges::equal(value, ext.value));
        };

    expect_extension_range_eq({601, 701}, packed_int32_extension_t{});
    expect_extension_range_eq({602, 702}, packed_int64_extension_t{});
    expect_extension_range_eq({603, 703}, packed_uint32_extension_t{});
    expect_extension_range_eq({604, 704}, packed_uint64_extension_t{});
    expect_extension_range_eq({605, 705}, packed_sint32_extension_t{});
    expect_extension_range_eq({606, 706}, packed_sint64_extension_t{});
    expect_extension_range_eq({607, 707}, packed_fixed32_extension_t{});
    expect_extension_range_eq({608, 708}, packed_fixed64_extension_t{});
    expect_extension_range_eq({609, 709}, packed_sfixed32_extension_t{});
    expect_extension_range_eq({610, 710}, packed_sfixed64_extension_t{});
    expect_extension_range_eq({611, 711}, packed_float_extension_t{});
    expect_extension_range_eq({612, 712}, packed_double_extension_t{});
    expect_extension_range_eq({true, false}, packed_bool_extension_t{});

    expect_extension_range_eq(std::initializer_list<ForeignEnum>{mapping_t::FOREIGN_BAR, mapping_t::FOREIGN_BAZ},
                              packed_enum_extension_t{});
  }

  static void run() {
    "protobuf"_test = []<class T> {
      T message;
      T message2;
      T message3;
      std::pmr::monotonic_buffer_resource mr;

      if constexpr (requires { ExpectClear(message); }) {
        ExpectClear(message);
      }
      SetAll(&message, hpp::proto::alloc_from{mr});
      ExpectAllSet(message);

      message2 = message;
      ExpectAllSet(message2);

      std::vector<std::byte> data;
      expect(hpp::proto::write_proto(message2, data).ok());
      expect(hpp::proto::read_proto(message3, data, hpp::proto::alloc_from{mr}).ok());

      ExpectAllSet(message3);
    } | typename mapping_t::protobuf_test_types{};

    auto unittest_descriptorset = read_file("unittest.desc.binpb");

#if !defined(HPP_PROTO_DISABLE_GLAZE)
    "interoperate_with_google_protobuf_parser"_test = [&]<class T> {
      T original;
      std::pmr::monotonic_buffer_resource mr;

      SetAll(&original, hpp::proto::alloc_from{mr});

      std::vector<char> data;
      expect(hpp::proto::write_proto(original, data).ok());

      auto original_json = gpb_based::proto_to_json(unittest_descriptorset, hpp::proto::message_name(original),
                                                    {data.data(), data.size()});
      expect(fatal(!original_json.empty()));
      auto generated_json = hpp::proto::write_json(original);

      expect(eq(generated_json.value(), original_json));

      T msg;
      expect(hpp::proto::read_json(msg, original_json, hpp::proto::alloc_from{mr}).ok());

      ExpectAllSet(msg);
    } | typename mapping_t::interoperability_test_types{};
#endif
  }

}; // struct TestSuite
// NOLINTEND(clang-diagnostic-missing-designated-field-initializers)
