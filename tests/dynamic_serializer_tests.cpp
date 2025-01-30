

#include "test_util.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/dynamic_serializer.hpp>
using namespace boost::ut;

const boost::ut::suite dynamic_serializer_test = [] {
  "unit"_test = [](const std::string &message_name) {
    using namespace boost::ut::literals;

    using namespace std::string_literals;
    std::string data = read_file("data/"s + message_name + ".binpb");

    auto descriptors = read_file("unittest.desc.binpb");
    auto ser = hpp::proto::dynamic_serializer::make(descriptors);
    expect(fatal(ser.has_value()));

    auto gpb_result = read_file("data/"s + message_name + ".json");
    expect(fatal(!gpb_result.empty()));

    auto hpp_result = ser->proto_to_json(message_name, data);
    expect(fatal(hpp_result.has_value()));

    expect(eq(gpb_result, *hpp_result));

    std::string serialized;
    expect(fatal(ser->json_to_proto(message_name, *hpp_result, serialized).ok()));
    expect(eq(to_hex(data), to_hex(serialized)));

    // NOLINTBEGIN(readability-implicit-bool-conversion)
    hpp_result = ser->proto_to_json(message_name, data, hpp::proto::indent_level<3>);
    // NOLINTEND(readability-implicit-bool-conversion)
    expect(fatal(hpp_result.has_value()));
    expect(ser->json_to_proto(message_name, *hpp_result, serialized).ok());
    expect(eq(to_hex(data), to_hex(serialized)));
  } | std::vector<std::string>{
    // "proto3_unittest.TestAllTypes",       "proto3_unittest.TestUnpackedTypes",
    //                            "protobuf_unittest.TestAllTypes",     "protobuf_unittest.TestMap",
                               "protobuf_unittest.TestPackedTypes",
#ifdef EDITION_SUPPORT
                               "protobuf_unittest.TestAllTypesLite", "protobuf_unittest.TestPackedTypesLite",
#endif
                               "protobuf_unittest.TestUnpackedTypes"};
};

const boost::ut::suite dynamic_serializer_skip_test = [] {
  auto descriptors = read_file("unittest.desc.binpb");
  auto ser = hpp::proto::dynamic_serializer::make(descriptors);
  expect(fatal(ser.has_value()));
  std::string data = read_file("data/proto3_unittest.TestAllTypes.binpb");
  
  std::array<char, 2> sbytes, ebytes;
  hpp::proto::unchecked_pack_varint(hpp::proto::make_tag(200, hpp::proto::wire_type::sgroup), sbytes.data());
  hpp::proto::unchecked_pack_varint(hpp::proto::make_tag(200, hpp::proto::wire_type::egroup), ebytes.data());
  std::ranges::copy(sbytes, std::inserter(data, data.begin()));
  std::ranges::copy(ebytes, std::back_inserter(data));  
  std::ranges::copy(read_file("data/protobuf_unittest.TestAllTypes.binpb"), std::back_inserter(data));

  auto hpp_result = ser->proto_to_json("protobuf_unittest.TestAllTypes", data);
  expect(fatal(hpp_result.has_value()));

  auto gpb_result = read_file("data/protobuf_unittest.TestAllTypes.json");
  expect(fatal(!gpb_result.empty()));
  expect(eq(gpb_result, *hpp_result));
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}