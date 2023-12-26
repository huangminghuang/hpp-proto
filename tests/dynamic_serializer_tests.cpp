#include "google/protobuf/any_test.glz.hpp"
#include "google/protobuf/any_test.pb.hpp"
#include "google/protobuf/any_test.desc.hpp"
#include "google/protobuf/unittest_proto3.desc.hpp"

#include "gpb_proto_json/gpb_proto_json.h"
#include "map_test_util.h"
#include "test_util.h"
#include "unittest_proto2_util.h"
#include "unittest_proto3_util.h"
#include <hpp_proto/dynamic_serializer.h>
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
void test_fixture(auto &message, const char *message_name, const char *descriptorset_file) {
  using namespace boost::ut::literals;
  using namespace boost::ut;

  std::string data;

  expect(hpp::proto::write_proto(message, data).success());

  auto descriptors = descriptorset_from_file(descriptorset_file);
  auto ser = hpp::proto::dynamic_serializer::make(descriptors);
  expect(ser.has_value() >> fatal);

  auto gpb_result = gpb_based::proto_to_json(descriptors, message_name, data);

  auto hpp_result = ser->proto_to_json(message_name, data);
  expect(hpp_result.has_value() >> fatal);

  expect(eq(gpb_result, *hpp_result));

  std::string serialized;
  expect(ser->json_to_proto(message_name, *hpp_result, serialized).success());
  expect(eq(data, serialized));

  hpp_result = ser->proto_to_json<glz::opts{.prettify = true}>(message_name, data);
  expect(hpp_result.has_value() >> fatal);
  expect(ser->json_to_proto(message_name, *hpp_result, serialized).success());
  expect(eq(data, serialized));
}
// NOLINTEND(bugprone-easily-swappable-parameters)

const boost::ut::suite dynamic_serializer_test = [] {
  using namespace boost::ut;

  "unittest_proto2"_test = [] {
    protobuf_unittest::TestAllTypes message;
    TestUtil::SetAll(&message);
    test_fixture(message, "protobuf_unittest.TestAllTypes", "unittest_proto2.bin");
  };

  "unittest_proto3"_test = [] {
    proto3_unittest::TestAllTypes message;
    SetAllFields(&message);
    test_fixture(message, "proto3_unittest.TestAllTypes", "unittest_proto3.bin");
  };

  "map"_test = [] {
    protobuf_unittest::TestMap message;
    SetMapFields(&message);
    test_fixture(message, "protobuf_unittest.TestMap", "map_unittest.bin");
  };

  "any"_test = [] {
    protobuf_unittest::TestAny message;
    proto3_unittest::ForeignMessage submessage{.c = 1234};
    expect(hpp::proto::pack_any(message.any_value.emplace(), submessage).success());

    std::string data;
    expect(hpp::proto::write_proto(message, data).success());

    auto ser = hpp::proto::dynamic_serializer::make(
      hpp::proto::file_descriptors::desc_set_google_protobuf_unittest_proto3_proto(),
      hpp::proto::file_descriptors::desc_set_google_protobuf_any_test_proto()
    );

    expect(ser.has_value() >> fatal);
    const char* message_name = "protobuf_unittest.TestAny";

    auto hpp_result = ser->proto_to_json<glz::opts{.prettify = true}>(message_name, data);
    expect(hpp_result.has_value() >> fatal);

    std::string serialized;
    expect(ser->json_to_proto(message_name, *hpp_result, serialized).success());
    expect(eq(data, serialized));

  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}