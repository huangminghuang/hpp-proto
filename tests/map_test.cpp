#include "gpb_proto_json/gpb_proto_json.h"
#include "map_test_util.h"
#include "test_util.h"
#include <google/protobuf/map_unittest.glz.hpp>
#include <hpp_proto/pb_serializer.h>

const boost::ut::suite map_test = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;

  auto map_unittest_descriptorset = descriptorset_from_file("map_unittest.bin");

  "protobuf"_test = [] {
    protobuf_unittest::TestMap original;
    SetMapFields(&original);

    protobuf_unittest::TestMap msg;

    auto [data, in, out] = hpp::proto::data_in_out();
    using zpp::bits::success;

    expect(success(out(original)));
    expect(success(in(msg)));

    ExpectMapFieldsSet(msg);
  };

  "glaze"_test = [&] {
    protobuf_unittest::TestMap original;
    SetMapFields(&original);

    std::vector<char> data;
    expect(!hpp::proto::write_proto(original, data));

    auto original_json =
        gpb_based::proto_to_json(map_unittest_descriptorset, "protobuf_unittest.TestMap", {data.data(), data.size()});

    std::cout << "original: " << original_json << "\n";
    std::cout << "hppproto: " << hpp::proto::write_json(original) << "\n";

    expect(hpp::proto::write_json(original) == original_json);

    protobuf_unittest::TestMap msg;
    expect(!hpp::proto::read_json(msg, original_json));

    ExpectMapFieldsSet(msg);
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}