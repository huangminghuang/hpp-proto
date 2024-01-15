#include "google/protobuf/any_test.pb.hpp"
#include <google/protobuf/field_mask.pb.hpp>
#include "non_owning/google/protobuf/any_test.pb.hpp"
#include "non_owning/google/protobuf/field_mask.pb.hpp"

#include <boost/ut.hpp>
#include "test_util.h"

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
};

int main() {
  const auto result = boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}