

#include "test_util.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/dynamic_serializer.hpp>

const boost::ut::suite dynamic_serializer_test = [] {
  using namespace boost::ut;

  "unit"_test =
      [](const std::string &message_name) {
        using namespace boost::ut::literals;

        using namespace std::string_literals;
        std::string data = read_file("data/"s + message_name + ".pb");

        auto descriptors = read_file("unittest.desc.pb");
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
        hpp_result = ser->proto_to_json<glz::opts{.prettify = true}>(message_name, data);
        // NOLINTEND(readability-implicit-bool-conversion)
        expect(fatal(hpp_result.has_value()));
        expect(ser->json_to_proto(message_name, *hpp_result, serialized).ok());
        expect(eq(to_hex(data), to_hex(serialized)));
      } |
      std::vector<std::string>{"protobuf_unittest.TestAllTypes", "proto3_unittest.TestAllTypes",
                               "protobuf_unittest.TestMap", "protobuf_unittest.TestUnpackedTypes",
                               "protobuf_unittest.TestPackedTypes"};
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}