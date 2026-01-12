#include "unittest_testsuite.hpp"
#include <google/protobuf/unittest.glz.hpp>
#include <google/protobuf/unittest.pb.hpp>

template <typename Traits>
struct Proto2TypeMapping {
  using TestAllTypes_t = protobuf_unittest::TestAllTypes<Traits>;
  using TestAllExtensions_t = protobuf_unittest::TestAllExtensions<Traits>;
  using TestPackedTypes_t = protobuf_unittest::TestPackedTypes<Traits>;
  using TestPackedExtensions_t = protobuf_unittest::TestPackedExtensions<Traits>;
  using TestUnpackedTypes_t = protobuf_unittest::TestUnpackedTypes<Traits>;
  using NestedEnum = TestAllTypes_t::NestedEnum;
  using ForeignEnum = protobuf_unittest::ForeignEnum;
  using ImportEnum = protobuf_unittest_import::ImportEnum;
  using ForeignMessage_t = protobuf_unittest::ForeignMessage<Traits>;
  using ImportMessage_t = protobuf_unittest_import::ImportMessage<Traits>;
  using NestedMessage_t = typename TestAllTypes_t::NestedMessage;
  using RepeatedGroup_t = typename TestAllTypes_t::RepeatedGroup;
  using RepeatedGroup_extension_t = protobuf_unittest::RepeatedGroup_extension<Traits>;
  using TestMutualRecursionA_t = protobuf_unittest::TestMutualRecursionA<Traits>;

  using oneof_uint32_extension_t = protobuf_unittest::oneof_uint32_extension;
  using oneof_nested_message_extension_t = protobuf_unittest::oneof_nested_message_extension<Traits>;
  using oneof_string_extension_t = protobuf_unittest::oneof_string_extension<Traits>;
  using oneof_bytes_extension_t = protobuf_unittest::oneof_bytes_extension<Traits>;

  using my_extension_int_t = protobuf_unittest::my_extension_int;
  using my_extension_string_t = protobuf_unittest::my_extension_string<Traits>;

  using optional_int32_extension_t = protobuf_unittest::optional_int32_extension;
  using optional_int64_extension_t = protobuf_unittest::optional_int64_extension;
  using optional_uint32_extension_t = protobuf_unittest::optional_uint32_extension;
  using optional_uint64_extension_t = protobuf_unittest::optional_uint64_extension;
  using optional_sint32_extension_t = protobuf_unittest::optional_sint32_extension;
  using optional_sint64_extension_t = protobuf_unittest::optional_sint64_extension;
  using optional_fixed32_extension_t = protobuf_unittest::optional_fixed32_extension;
  using optional_fixed64_extension_t = protobuf_unittest::optional_fixed64_extension;
  using optional_sfixed32_extension_t = protobuf_unittest::optional_sfixed32_extension;
  using optional_sfixed64_extension_t = protobuf_unittest::optional_sfixed64_extension;
  using optional_float_extension_t = protobuf_unittest::optional_float_extension;
  using optional_double_extension_t = protobuf_unittest::optional_double_extension;
  using optional_bool_extension_t = protobuf_unittest::optional_bool_extension;
  using optional_string_extension_t = protobuf_unittest::optional_string_extension<Traits>;
  using optional_bytes_extension_t = protobuf_unittest::optional_bytes_extension<Traits>;

  using optionalgroup_extension_t = protobuf_unittest::optionalgroup_extension<Traits>;
  using optional_nested_message_extension_t = protobuf_unittest::optional_nested_message_extension<Traits>;
  using optional_foreign_message_extension_t = protobuf_unittest::optional_foreign_message_extension<Traits>;
  using optional_import_message_extension_t = protobuf_unittest::optional_import_message_extension<Traits>;
  using optional_public_import_message_extension_t =
      protobuf_unittest::optional_public_import_message_extension<Traits>;
  using optional_lazy_message_extension_t = protobuf_unittest::optional_lazy_message_extension<Traits>;

  using optional_nested_enum_extension_t = protobuf_unittest::optional_nested_enum_extension;
  using optional_foreign_enum_extension_t = protobuf_unittest::optional_foreign_enum_extension;
  using optional_import_enum_extension_t = protobuf_unittest::optional_import_enum_extension;

  using optional_string_piece_extension_t = protobuf_unittest::optional_string_piece_extension<Traits>;
  using optional_cord_extension_t = protobuf_unittest::optional_cord_extension<Traits>;

  using default_int32_extension_t = protobuf_unittest::default_int32_extension;
  using default_int64_extension_t = protobuf_unittest::default_int64_extension;
  using default_uint32_extension_t = protobuf_unittest::default_uint32_extension;
  using default_uint64_extension_t = protobuf_unittest::default_uint64_extension;
  using default_sint32_extension_t = protobuf_unittest::default_sint32_extension;
  using default_sint64_extension_t = protobuf_unittest::default_sint64_extension;
  using default_fixed32_extension_t = protobuf_unittest::default_fixed32_extension;
  using default_fixed64_extension_t = protobuf_unittest::default_fixed64_extension;
  using default_sfixed32_extension_t = protobuf_unittest::default_sfixed32_extension;
  using default_sfixed64_extension_t = protobuf_unittest::default_sfixed64_extension;
  using default_float_extension_t = protobuf_unittest::default_float_extension;
  using default_double_extension_t = protobuf_unittest::default_double_extension;
  using default_bool_extension_t = protobuf_unittest::default_bool_extension;
  using default_string_extension_t = protobuf_unittest::default_string_extension<Traits>;
  using default_bytes_extension_t = protobuf_unittest::default_bytes_extension<Traits>;

  using default_nested_enum_extension_t = protobuf_unittest::default_nested_enum_extension;
  using default_foreign_enum_extension_t = protobuf_unittest::default_foreign_enum_extension;
  using default_import_enum_extension_t = protobuf_unittest::default_import_enum_extension;

  using default_string_piece_extension_t = protobuf_unittest::default_string_piece_extension<Traits>;
  using default_cord_extension_t = protobuf_unittest::default_cord_extension<Traits>;

  using repeated_int32_extension_t = protobuf_unittest::repeated_int32_extension<Traits>;
  using repeated_int64_extension_t = protobuf_unittest::repeated_int64_extension<Traits>;
  using repeated_uint32_extension_t = protobuf_unittest::repeated_uint32_extension<Traits>;
  using repeated_uint64_extension_t = protobuf_unittest::repeated_uint64_extension<Traits>;
  using repeated_sint32_extension_t = protobuf_unittest::repeated_sint32_extension<Traits>;
  using repeated_sint64_extension_t = protobuf_unittest::repeated_sint64_extension<Traits>;
  using repeated_fixed32_extension_t = protobuf_unittest::repeated_fixed32_extension<Traits>;
  using repeated_fixed64_extension_t = protobuf_unittest::repeated_fixed64_extension<Traits>;
  using repeated_sfixed32_extension_t = protobuf_unittest::repeated_sfixed32_extension<Traits>;
  using repeated_sfixed64_extension_t = protobuf_unittest::repeated_sfixed64_extension<Traits>;
  using repeated_float_extension_t = protobuf_unittest::repeated_float_extension<Traits>;
  using repeated_double_extension_t = protobuf_unittest::repeated_double_extension<Traits>;
  using repeated_bool_extension_t = protobuf_unittest::repeated_bool_extension<Traits>;
  using repeated_string_extension_t = protobuf_unittest::repeated_string_extension<Traits>;
  using repeated_bytes_extension_t = protobuf_unittest::repeated_bytes_extension<Traits>;

  using repeatedgroup_extension_t = protobuf_unittest::repeatedgroup_extension<Traits>;
  using repeated_nested_message_extension_t = protobuf_unittest::repeated_nested_message_extension<Traits>;
  using repeated_foreign_message_extension_t = protobuf_unittest::repeated_foreign_message_extension<Traits>;
  using repeated_import_message_extension_t = protobuf_unittest::repeated_import_message_extension<Traits>;
  using repeated_lazy_message_extension_t = protobuf_unittest::repeated_lazy_message_extension<Traits>;
  using repeated_nested_enum_extension_t = protobuf_unittest::repeated_nested_enum_extension<Traits>;
  using repeated_foreign_enum_extension_t = protobuf_unittest::repeated_foreign_enum_extension<Traits>;
  using repeated_import_enum_extension_t = protobuf_unittest::repeated_import_enum_extension<Traits>;

  using repeated_string_piece_extension_t = protobuf_unittest::repeated_string_piece_extension<Traits>;
  using repeated_cord_extension_t = protobuf_unittest::repeated_cord_extension<Traits>;

  using packed_int32_extension_t = protobuf_unittest::packed_int32_extension<Traits>;
  using packed_int64_extension_t = protobuf_unittest::packed_int64_extension<Traits>;
  using packed_uint32_extension_t = protobuf_unittest::packed_uint32_extension<Traits>;
  using packed_uint64_extension_t = protobuf_unittest::packed_uint64_extension<Traits>;
  using packed_sint32_extension_t = protobuf_unittest::packed_sint32_extension<Traits>;
  using packed_sint64_extension_t = protobuf_unittest::packed_sint64_extension<Traits>;
  using packed_fixed32_extension_t = protobuf_unittest::packed_fixed32_extension<Traits>;
  using packed_fixed64_extension_t = protobuf_unittest::packed_fixed64_extension<Traits>;
  using packed_sfixed32_extension_t = protobuf_unittest::packed_sfixed32_extension<Traits>;
  using packed_sfixed64_extension_t = protobuf_unittest::packed_sfixed64_extension<Traits>;
  using packed_float_extension_t = protobuf_unittest::packed_float_extension<Traits>;
  using packed_double_extension_t = protobuf_unittest::packed_double_extension<Traits>;
  using packed_bool_extension_t = protobuf_unittest::packed_bool_extension<Traits>;
  using packed_enum_extension_t = protobuf_unittest::packed_enum_extension<Traits>;

  using unpacked_int32_extension_t = protobuf_unittest::unpacked_int32_extension<Traits>;
  using unpacked_int64_extension_t = protobuf_unittest::unpacked_int64_extension<Traits>;
  using unpacked_uint32_extension_t = protobuf_unittest::unpacked_uint32_extension<Traits>;
  using unpacked_uint64_extension_t = protobuf_unittest::unpacked_uint64_extension<Traits>;
  using unpacked_sint32_extension_t = protobuf_unittest::unpacked_sint32_extension<Traits>;
  using unpacked_sint64_extension_t = protobuf_unittest::unpacked_sint64_extension<Traits>;
  using unpacked_fixed32_extension_t = protobuf_unittest::unpacked_fixed32_extension<Traits>;
  using unpacked_fixed64_extension_t = protobuf_unittest::unpacked_fixed64_extension<Traits>;
  using unpacked_sfixed32_extension_t = protobuf_unittest::unpacked_sfixed32_extension<Traits>;
  using unpacked_sfixed64_extension_t = protobuf_unittest::unpacked_sfixed64_extension<Traits>;
  using unpacked_float_extension_t = protobuf_unittest::unpacked_float_extension<Traits>;
  using unpacked_double_extension_t = protobuf_unittest::unpacked_double_extension<Traits>;
  using unpacked_bool_extension_t = protobuf_unittest::unpacked_bool_extension<Traits>;
  using unpacked_enum_extension_t = protobuf_unittest::unpacked_enum_extension<Traits>;

  constexpr static auto FOREIGN_FOO = ForeignEnum::FOREIGN_FOO;
  constexpr static auto FOREIGN_BAR = ForeignEnum::FOREIGN_BAR;
  constexpr static auto FOREIGN_BAZ = ForeignEnum::FOREIGN_BAZ;

  constexpr static auto IMPORT_FOO = ImportEnum::IMPORT_FOO;
  constexpr static auto IMPORT_BAR = ImportEnum::IMPORT_BAR;
  constexpr static auto IMPORT_BAZ = ImportEnum::IMPORT_BAZ;

  using protobuf_test_types =
      std::tuple<TestAllTypes_t, TestAllExtensions_t, TestUnpackedTypes_t, TestPackedTypes_t, TestPackedExtensions_t>;

  using interoperability_test_types = std::tuple<TestAllTypes_t, TestUnpackedTypes_t, TestPackedTypes_t>;
};

const boost::ut::suite proto2_test = [] {
  "proto2"_test = []<class Traits> { TestSuite<Traits, Proto2TypeMapping>::run(); } |
                  std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits, hpp::proto::pmr_traits>{};

  "empty"_test = [] {
    protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits> message;
    using namespace std::string_view_literals;
    const auto json = R"({})"sv;
    std::vector<char> in{json.begin(), json.end()};
    std::string out;
    std::pmr::monotonic_buffer_resource mr;
    expect(hpp::proto::read_json(message, in, hpp::proto::alloc_from(mr)).ok());
    expect(hpp::proto::write_json(message, out).ok());
    expect(eq(json, out));
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}