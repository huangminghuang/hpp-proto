#include <google/protobuf/any_test.desc.hpp>
#include <google/protobuf/any_test.glz.hpp>
#include <google/protobuf/any_test.pb.hpp>
#include <google/protobuf/field_mask.desc.hpp>
#include <google/protobuf/field_mask.pb.hpp>
#include <google/protobuf/unittest_proto3.desc.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>
#include <non_owning/google/protobuf/any_test.pb.hpp>
#include <non_owning/google/protobuf/field_mask.pb.hpp>

#include "test_util.h"
#include <boost/ut.hpp>

using namespace boost::ut;

suite test_any = [] {
  "any"_test = [] {
    protobuf_unittest::TestAny message;
    google::protobuf::FieldMask fm{.paths = {"/usr/share", "/usr/local/share"}};
    expect(hpp::proto::pack_any(message.any_value.emplace(), fm).success());

    std::vector<char> buf;
    expect(hpp::proto::write_proto(message, buf).success());

    protobuf_unittest::TestAny message2;
    expect(hpp::proto::read_proto(message2, buf).success());
    google::protobuf::FieldMask fm2;
    expect(hpp::proto::unpack_any(message2.any_value.value(), fm2).success());
    expect(fm == fm2);
  };

  "non_owning_any"_test = [] {
    using namespace std::string_view_literals;

    monotonic_buffer_resource mr{1024};
    hpp::proto::pb_context ctx{mr};

    non_owning::protobuf_unittest::TestAny message;
    std::array<std::string_view, 2> paths{"/usr/share"sv, "/usr/local/share"sv};
    non_owning::google::protobuf::FieldMask fm{.paths = paths};
    expect(hpp::proto::pack_any(message.any_value.emplace(), fm, ctx).success());

    std::vector<char> buf;
    expect(hpp::proto::write_proto(message, buf).success());

    non_owning::protobuf_unittest::TestAny message2;
    expect(hpp::proto::read_proto(message2, buf, ctx).success());
    non_owning::google::protobuf::FieldMask fm2;
    expect(hpp::proto::unpack_any(message2.any_value.value(), fm2, ctx).success());
    expect(std::ranges::equal(paths, fm2.paths));
  };

  "any_json_wellknown"_test = [] {
    protobuf_unittest::TestAny message;
    google::protobuf::FieldMask fm{.paths = {"/usr/share", "/usr/local/share"}};
    expect(hpp::proto::pack_any(message.any_value.emplace(), fm).success());

    auto ser =
        hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_field_mask_proto());
    expect(ser.has_value());

    const std::string_view expected_json =
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.FieldMask","value":"/usr/share,/usr/local/share"}})";
    std::string buf;
    expect(hpp::proto::write_json(message, buf, hpp::proto::json_context{*ser}).success());
    expect(eq(buf, expected_json));

    protobuf_unittest::TestAny message2;
    expect(hpp::proto::read_json(message2, expected_json, hpp::proto::json_context{*ser}).success());
    expect(message == message2);
  };

  "any_josn"_test = [] {
    protobuf_unittest::TestAny message;
    proto3_unittest::ForeignMessage submessage{.c = 1234};
    expect(hpp::proto::pack_any(message.any_value.emplace(), submessage).success());

    std::string data;
    expect(hpp::proto::write_proto(message, data).success());

    auto ser = hpp::proto::dynamic_serializer::make(
        hpp::proto::file_descriptors::desc_set_google_protobuf_unittest_proto3_proto(),
        hpp::proto::file_descriptors::desc_set_google_protobuf_any_test_proto());

    expect(fatal(ser.has_value()));
    const char *message_name = "protobuf_unittest.TestAny";
    std::string_view expected_json =
        R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage","c":1234}})";
    auto hpp_result = ser->proto_to_json(message_name, data);
    expect(fatal(hpp_result.has_value()));
    expect(eq(expected_json, *hpp_result));

    std::string serialized;
    expect(ser->json_to_proto(message_name, expected_json, serialized).success());
    expect(eq(data, serialized));
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}