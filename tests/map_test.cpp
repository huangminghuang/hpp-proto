#include "gpb_proto_json/gpb_proto_json.hpp"
#include "map_test_util.hpp"
#include "test_util.hpp"
#include <google/protobuf/map_unittest.glz.hpp>
#include <hpp_proto/pb_serializer.hpp>

const boost::ut::suite map_test = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;

  auto map_unittest_descriptorset = read_file("unittest.desc.binpb");

  "protobuf"_test = [] {
    TestMap original;
    SetMapFields(&original);

    TestMap msg;

    std::vector<char> data;
    expect(hpp::proto::write_proto(original, data).ok());
    expect(hpp::proto::read_proto(msg, data).ok());

    ExpectMapFieldsSet(msg);
  };

#ifndef HPP_PROTO_DISABLE_GLAZE
  "glaze"_test = [&] {
    TestMap original;
    SetMapFields(&original);

    std::vector<char> data;
    expect(hpp::proto::write_proto(original, data).ok());

    auto original_json =
        gpb_based::proto_to_json(map_unittest_descriptorset, "protobuf_unittest.TestMap", {data.data(), data.size()});
    expect(fatal(!original_json.empty()));

    expect(eq(hpp::proto::write_json(original).value(), original_json));

    TestMap msg;
    expect(hpp::proto::read_json(msg, original_json).ok());

    ExpectMapFieldsSet(msg);
  };
#endif
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
