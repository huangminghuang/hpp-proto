#include "gpb_proto_json/gpb_proto_json.h"
#include "test_util.h"
#include "unittest_proto3_util.h"

// In this file we only test some basic functionalities of in proto3 and expect
// the rest is fully tested in proto2 unittests because proto3 shares most code
// with proto2.

boost::ut::suite proto3_lite_test = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;

  auto unittest_proto3_descriptorset = descriptorset_from_file("unittest_proto3.bin");

  "protobuf"_test = [] {
    proto3_unittest::TestAllTypes original;
    SetAllFields(&original);

    proto3_unittest::TestAllTypes msg;

    auto [data, in, out] = hpp::proto::data_in_out();
    using zpp::bits::success;

    expect(success(out(original)));
    expect(success(in(msg)));

    ExpectAllFieldsSet(msg);
  };

  "unpacked_repeated"_test = [&] {
    proto3_unittest::TestUnpackedTypes original;
    SetUnpackedFields(&original);

    proto3_unittest::TestUnpackedTypes msg;

    auto [data, in, out] = hpp::proto::data_in_out();
    using zpp::bits::success;

    expect(success(out(original)));
    expect(success(in(msg)));

    ExpectUnpackedFieldsSet(msg);

    auto json_string = glz::write_json(original);
    auto m = gpb_based::json_to_proto(unittest_proto3_descriptorset, "proto3_unittest.TestUnpackedTypes", json_string);

    expect(eq(m.size(), data.size()));
    expect(memcmp(data.data(), m.data(), m.size()) == 0);
  };

  "glaze"_test = [&] {
    proto3_unittest::TestAllTypes original;
    SetAllFields(&original);

    auto [data, in, out] = hpp::proto::data_in_out();
    using zpp::bits::success;

    expect(success(out(original)));

    auto original_json = gpb_based::proto_to_json(unittest_proto3_descriptorset, "proto3_unittest.TestAllTypes",
                                                  {(const char *)data.data(), data.size()});

    expect(glz::write_json(original) == original_json);

    proto3_unittest::TestAllTypes msg;
    expect(!glz::read_json(msg, original_json));

    ExpectAllFieldsSet(msg);
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return result;
}