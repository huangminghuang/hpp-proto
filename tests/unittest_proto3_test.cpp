#include "gpb_proto_json/gpb_proto_json.hpp"
#include "test_util.hpp"
#include "unittest_proto3_util.hpp"

// In this file we only test some basic functionalities of in proto3 and expect
// the rest is fully tested in proto2 unittests because proto3 shares most code
// with proto2.

const boost::ut::suite proto3_lite_test = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;

  auto unittest_descriptorset = read_file("unittest.desc.binpb");

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
    should("write_proto should work") = [&] { expect(hpp::proto::write_proto(original, data).ok()); };
    should("read_proto should work") = [&] {
      auto r = hpp::proto::read_proto(msg, data);
      expect(r.ok());
    };

    ExpectUnpackedFieldsSet(msg);

#if !defined(HPP_PROTO_DISABLE_GLAZE)
    auto r = glz::write_json(original);
    should("write_json should work") = [&] { expect(r.has_value()); };
    auto original_json = gpb_based::proto_to_json(unittest_descriptorset, "proto3_unittest.TestUnpackedTypes",
                                                  {data.data(), data.size()});
    should("proto3_unittest.TestUnpackedTypes should be successfully read") = [&] {
      std::cerr << "original_json = " << original_json << "\n";
      expect(fatal(!original_json.empty()));
    };
    should("write_json result should match") = [&] { expect(eq(*r, original_json)); };
#endif
  };

#if !defined(HPP_PROTO_DISABLE_GLAZE)
  "glaze"_test = [&] {
    proto3_unittest::TestAllTypes original;
    SetAllFields(&original);

    std::vector<char> data;
    expect(hpp::proto::write_proto(original, data).ok());

    auto original_json =
        gpb_based::proto_to_json(unittest_descriptorset, "proto3_unittest.TestAllTypes", {data.data(), data.size()});
    expect(fatal(!original_json.empty()));
    expect(hpp::proto::write_json(original).value() == original_json);

    proto3_unittest::TestAllTypes msg;
    expect(hpp::proto::read_json(msg, original_json).ok());

    ExpectAllFieldsSet(msg);
  };
#endif
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}