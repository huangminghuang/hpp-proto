
#include "gpb_proto_json/gpb_proto_json.h"
#include "unittest_proto2_util.h"
#include <regex>
namespace ut = boost::ut;

template <zpp::bits::string_literal String>
constexpr auto operator""_bytes() {
  auto v = zpp::bits::to_bytes<String>();
  return std::vector<std::byte>{v.begin(), v.end()};
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


    auto glaze_generated_json = glz::write_json(original);

    ut::expect(ut::eq(glaze_generated_json, original_json));

    protobuf_unittest::TestAllTypes msg;
    ut::expect(!glz::read_json(msg, original_json));

    TestUtil::ExpectAllFieldsSet(msg);
  };
};

// TODO: need a test case of TestOneof2

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return result;
}