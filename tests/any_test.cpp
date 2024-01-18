#include "google/protobuf/any_test.pb.hpp"
#include "non_owning/google/protobuf/any_test.pb.hpp"
#include "non_owning/google/protobuf/field_mask.pb.hpp"
#include <google/protobuf/field_mask.pb.hpp>

#include <google/protobuf/any_test.glz.hpp>
#include <google/protobuf/field_mask.desc.hpp>

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

  "any_json"_test = [] {
    protobuf_unittest::TestAny message;
    google::protobuf::FieldMask fm{.paths = {"/usr/share", "/usr/local/share"}};
    expect(hpp::proto::pack_any(message.any_value.emplace(), fm).success());

    auto ser =
        hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_field_mask_proto());
    expect(ser.has_value());

    const std::string expected_json = R"({"@type":"type.googleapis.com/google.protobuf.FieldMask","anyValue":"/usr/share,/usr/local/share"})";
    std::string buf;
    expect(hpp::proto::write_json(message, buf, hpp::proto::json_context{*ser}).success());
    expect(buf == expected_json);

    // protobuf_unittest::TestAny message2;
    // expect(hpp::proto::read_json(message2, expected_json, hpp::proto::json_context{*ser}).success());
    // expect(message == message2);
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}