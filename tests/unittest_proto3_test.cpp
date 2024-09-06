#include "gpb_proto_json/gpb_proto_json.hpp"
#include "test_util.hpp"
#include "unittest_proto3_util.hpp"

// static_assert(
//     ensure_all_fields_field_option<proto3_unittest::TestPackedTypes, hpp::proto::field_option::none>());

// static_assert(ensure_all_fields_field_option<proto3_unittest::TestUnpackedTypes,
//                                               hpp::proto::field_option::unpacked_repeated>());

// In this file we only test some basic functionalities of in proto3 and expect
// the rest is fully tested in proto2 unittests because proto3 shares most code
// with proto2.

const boost::ut::suite proto3_lite_test = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;

  auto unittest_proto3_descriptorset = read_file("unittest.desc.pb");

  "protobuf"_test = [] {
    proto3_unittest::TestAllTypes original;
    SetAllFields(&original);

    proto3_unittest::TestAllTypes msg;

    std::vector<std::byte> data;
    expect(hpp::proto::write_proto(original, data).ok());
    expect(hpp::proto::read_proto(msg, data).ok());

    ExpectAllFieldsSet(msg);
  };

  "unpacked_repeated"_test = [&] {
    proto3_unittest::TestUnpackedTypes original;
    SetUnpackedFields(&original);

    proto3_unittest::TestUnpackedTypes msg;

    std::vector<char> data;
    expect(hpp::proto::write_proto(original, data).ok());
    expect(hpp::proto::read_proto(msg, data).ok());

    ExpectUnpackedFieldsSet(msg);

    auto r = glz::write_json(original);
    expect(r.has_value());
    auto original_json = gpb_based::proto_to_json(unittest_proto3_descriptorset, "proto3_unittest.TestUnpackedTypes",
                                                  {data.data(), data.size()});
    expect(fatal(!original_json.empty()));
    expect(eq(*r, original_json));
  };

  "glaze"_test = [&] {
    proto3_unittest::TestAllTypes original;
    SetAllFields(&original);

    std::vector<char> data;
    expect(hpp::proto::write_proto(original, data).ok());

    auto original_json = gpb_based::proto_to_json(unittest_proto3_descriptorset, "proto3_unittest.TestAllTypes",
                                                  {data.data(), data.size()});
    expect(fatal(!original_json.empty()));
    expect(hpp::proto::write_json(original).value() == original_json);

    proto3_unittest::TestAllTypes msg;
    expect(hpp::proto::read_json(msg, original_json).ok());

    ExpectAllFieldsSet(msg);
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}