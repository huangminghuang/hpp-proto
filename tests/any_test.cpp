
#include <google/protobuf/any_test.desc.hpp>
#include <google/protobuf/any_test.glz.hpp>
#include <google/protobuf/any_test.pb.hpp>
#include <google/protobuf/duration.desc.hpp>
#include <google/protobuf/duration.glz.hpp>
#include <google/protobuf/duration.pb.hpp>
#include <google/protobuf/field_mask.desc.hpp>
#include <google/protobuf/field_mask.pb.hpp>
#include <google/protobuf/timestamp.desc.hpp>
#include <google/protobuf/timestamp.glz.hpp>
#include <google/protobuf/timestamp.pb.hpp>
#include <google/protobuf/unittest_proto3.desc.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>
#include <google/protobuf/wrappers.desc.hpp>
#include <google/protobuf/wrappers.glz.hpp>
#include <google/protobuf/wrappers.pb.hpp>

#include "test_util.hpp"
#include <boost/ut.hpp>

#include <hpp_proto/dynamic_message/json.hpp>


using namespace boost::ut;
using namespace std::string_view_literals;

const suite test_any = [] {
  "any"_test = []<class Traits>() {
    std::pmr::monotonic_buffer_resource mr;
    using string_t = typename Traits::string_t;

    ::protobuf_unittest::TestAny<Traits> message;
    ::google::protobuf::FieldMask<Traits> fm;
    auto paths = std::initializer_list<string_t>{string_t{"/usr/share"}, string_t{"/usr/local/share"}};
    fm.paths = paths;
    expect(hpp::proto::pack_any(message.any_value.emplace(), fm, ::hpp::proto::alloc_from(mr)).ok());

    std::vector<char> buf;
    expect(hpp::proto::write_binpb(message, buf).ok());

    ::protobuf_unittest::TestAny<Traits> message2;
    expect(hpp::proto::read_binpb(message2, buf, ::hpp::proto::alloc_from(mr)).ok());
    ::google::protobuf::FieldMask<Traits> fm2;
    expect(hpp::proto::unpack_any(message2.any_value.value(), fm2, ::hpp::proto::alloc_from(mr)).ok());
    expect(std::ranges::equal(paths, fm2.paths));

    expect(!hpp::proto::unpack_any<::proto3_unittest::ForeignMessage<Traits>>(message2.any_value.value(),
                                                                              ::hpp::proto::alloc_from(mr))
                .has_value());
  } | std::tuple<::hpp::proto::default_traits, ::hpp::proto::non_owning_traits>{};
};

const suite test_dynamic_message_any = [] {
  "wellknown_type"_test = [] {
    ::protobuf_unittest::TestAny<> message;
    ::google::protobuf::FieldMask<> fm;
    fm.paths = {"/usr/share", "/usr/local/share"};
    expect(hpp::proto::pack_any(message.any_value.emplace(), fm).ok());

    ::hpp::proto::dynamic_message_factory message_factory;
    expect(message_factory.init(::hpp::proto::file_descriptors::desc_set_google_protobuf_field_mask_proto()));

    const std::string_view expected_json =
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.FieldMask","value":"/usr/share,/usr/local/share"}})";
    std::string buf;
    expect(hpp::proto::write_json(message, buf, hpp::proto::use_factory{message_factory}).ok());
    expect(eq(buf, expected_json));

    ::protobuf_unittest::TestAny<> message2;
    expect(hpp::proto::read_json(message2, expected_json, hpp::proto::use_factory{message_factory}).ok());
    expect(message == message2);

    expect(hpp::proto::write_json(message, buf, hpp::proto::use_factory{message_factory}, hpp::proto::indent_level<3>)
               .ok());
    using namespace std::string_literals;
    expect(eq(buf, R"({
   "anyValue": {
      "@type": "type.googleapis.com/google.protobuf.FieldMask",
      "value": "/usr/share,/usr/local/share"
   }
})"s));
  };

  std::string_view data =
      "\x12\x39\x0a\x32\x74\x79\x70\x65\x2e\x67\x6f\x6f\x67\x6c\x65\x61\x70\x69\x73\x2e\x63\x6f\x6d\x2f"
      "\x70\x72\x6f\x74\x6f\x33\x5f\x75\x6e\x69\x74\x74\x65\x73\x74\x2e\x46\x6f\x72\x65\x69\x67\x6e\x4d"
      "\x65\x73\x73\x61\x67\x65\x12\x03\x08\xd2\x09";

  auto protos = hpp::proto::distinct_file_descriptor_pb_array{
      ::hpp::proto::file_descriptors::_desc_google_protobuf_unittest_import_proto,
      ::hpp::proto::file_descriptors::_desc_google_protobuf_unittest_import_public_proto,
      ::hpp::proto::file_descriptors::_desc_google_protobuf_unittest_proto3_proto,
      ::hpp::proto::file_descriptors::_desc_google_protobuf_any_proto,
      ::hpp::proto::file_descriptors::_desc_google_protobuf_any_test_proto,
      ::hpp::proto::file_descriptors::_desc_google_protobuf_timestamp_proto,
      ::hpp::proto::file_descriptors::_desc_google_protobuf_duration_proto,
      ::hpp::proto::file_descriptors::_desc_google_protobuf_wrappers_proto,
  };

  "any_json"_test = [&] {
    ::hpp::proto::dynamic_message_factory message_factory;
    expect(message_factory.init(protos));

    const char *message_name = "protobuf_unittest.TestAny";
    std::string_view expected_json =
        R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage","c":1234}})";

    std::string result;
    expect(binpb_to_json(message_factory, message_name, data, result).ok());
    expect(eq(expected_json, result));

    std::vector<char> serialized;
    expect(json_to_binpb(message_factory, message_name, expected_json, serialized).ok());
    expect(std::ranges::equal(data, serialized));

    expect(binpb_to_json(message_factory, message_name, data, result, hpp::proto::indent_level<3>).ok());
    const char *expected_json_indented = R"({
   "anyValue": {
      "@type": "type.googleapis.com/proto3_unittest.ForeignMessage",
      "c": 1234
   }
})";
    expect(eq(expected_json_indented, result));
  };

  "any_json_edge_cases"_test = [&] {
    ::hpp::proto::dynamic_message_factory message_factory;
    expect(message_factory.init(protos));

    auto expect_read_fail = [&](std::string_view json) {
      ::protobuf_unittest::TestAny<> message;
      auto status = hpp::proto::read_json(message, json, hpp::proto::use_factory{message_factory});
      expect(!status.ok());
    };
    auto expect_read_fail_strict = [&](std::string_view json) {
      ::protobuf_unittest::TestAny<> message;
      auto status = hpp::proto::read_json(message, json, hpp::proto::use_factory{message_factory},
                                          hpp::proto::glz_opts_t<glz::opts{.error_on_unknown_keys = true}>{});
      expect(!status.ok());
    };
    auto expect_read_ok = [&](std::string_view json) {
      ::protobuf_unittest::TestAny<> message;
      auto status = hpp::proto::read_json(message, json, hpp::proto::use_factory{message_factory});
      expect(status.ok());
    };

    expect_read_fail(R"({"anyValue":{"value":"/usr/share"}})"); // missing @type
    expect_read_fail(R"({"anyValue":{"@type":"","c":1}})");     // empty @type
    expect_read_fail(R"({"anyValue":{"@type":"type.googleapis.com","c":1}})"); // invalid formatted @type
    expect_read_fail(R"({"anyValue":{"@type":"type.googleapis.com/does.not.Exist","c":1}})"); // unknown type_url
    expect_read_fail(
        R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage","@type":"type.googleapis.com/proto3_unittest.ForeignMessage","c":1}})"); // duplicate @type
    expect_read_fail(
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.FieldMask","value":"/usr/share","extra":1}})"); // unknown key in well-known
    expect_read_fail(
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.FieldMask","value":"/usr/share","value":"/usr/local"}})"); // duplicate value
    expect_read_fail(R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.FieldMask"}})"); // missing value
    expect_read_fail_strict(
        R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage","c":1,"unknown":2}})"); // unknown key with strict option

    std::string bad_utf8 = "{\"anyValue\":{\"@type\":\"\xC0\",\"c\":1}}";
    expect_read_fail(bad_utf8); // invalid utf8 @type
    std::string bad_control = "{\"anyValue\":{\"@type\":\"\x01\",\"c\":1}}";
    expect_read_fail(bad_control); // invalid control character in @type

    expect_read_ok(
        R"({"anyValue":{"c":1234,"@type":"type.googleapis.com/proto3_unittest.ForeignMessage"}})"); // @type not first
  };

  "any_json_wellknown_types"_test = [&] {
    ::hpp::proto::dynamic_message_factory message_factory;
    expect(message_factory.init(protos));

    ::protobuf_unittest::TestAny<> message;
    ::google::protobuf::Timestamp<> ts;
    ts.seconds = 1000;
    ts.nanos = 0;
    expect(hpp::proto::pack_any(message.any_value.emplace(), ts).ok());

    std::string result;
    expect(hpp::proto::write_json(message, result, hpp::proto::use_factory{message_factory}).ok());
    expect(eq(result, R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.Timestamp","value":"1970-01-01T00:16:40Z"}})"sv));

    ::protobuf_unittest::TestAny<> message2;
    expect(hpp::proto::read_json(message2, result, hpp::proto::use_factory{message_factory}).ok());
    expect(message == message2);

    ::protobuf_unittest::TestAny<> message3;
    ::google::protobuf::Duration<> duration;
    duration.seconds = 1000;
    duration.nanos = 0;
    expect(hpp::proto::pack_any(message3.any_value.emplace(), duration).ok());

    expect(hpp::proto::write_json(message3, result, hpp::proto::use_factory{message_factory}).ok());
    expect(eq(result, R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.Duration","value":"1000s"}})"sv));

    ::protobuf_unittest::TestAny<> message4;
    expect(hpp::proto::read_json(message4, result, hpp::proto::use_factory{message_factory}).ok());
    expect(message3 == message4);

    ::protobuf_unittest::TestAny<> message5;
    ::google::protobuf::Int64Value<> int64_value;
    int64_value.value = 1000;
    expect(hpp::proto::pack_any(message5.any_value.emplace(), int64_value).ok());

    expect(hpp::proto::write_json(message5, result, hpp::proto::use_factory{message_factory}).ok());
    expect(eq(result, R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.Int64Value","value":"1000"}})"sv));

    ::protobuf_unittest::TestAny<> message6;
    expect(hpp::proto::read_json(message6, result, hpp::proto::use_factory{message_factory}).ok());
    expect(message5 == message6);

    ::protobuf_unittest::TestAny<> message7;
    ::google::protobuf::Int32Value<> int32_value;
    int32_value.value = 42;
    expect(hpp::proto::pack_any(message7.any_value.emplace(), int32_value).ok());

    expect(hpp::proto::write_json(message7, result, hpp::proto::use_factory{message_factory}).ok());
    expect(eq(result, R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.Int32Value","value":42}})"sv));

    ::protobuf_unittest::TestAny<> message8;
    expect(hpp::proto::read_json(message8, result, hpp::proto::use_factory{message_factory}).ok());
    expect(message7 == message8);
  };

  "type_not_found"_test = [data] {
    hpp::proto::dynamic_message_factory message_factory;
    expect(message_factory.init(hpp::proto::file_descriptors::desc_set_google_protobuf_any_test_proto()));
    std::string result;
    expect(!binpb_to_json(message_factory, "protobuf_unittest.TestAny", data, result).ok());
  };

  "bad_message"_test = [&] {
    ::hpp::proto::dynamic_message_factory message_factory;
    expect(message_factory.init(protos));

    std::string_view data =
        "\x12\x39\x0a\x32\x74\x79\x70\x65\x2e\x67\x6f\x6f\x67\x6c\x65\x61\x70\x69\x73\x2e\x63\x6f\x6d\x2f"
        "\x70\x72\x6f\x74\x6f\x33\x5f\x75\x6e\x69\x74\x74\x65\x73\x74\x2e\x46\x6f\x72\x65\x69\x67\x6e\x4d"
        "\x65\x73\x73\x61\x67\x65\x12\x03\x08\xd2\x89\x80\x80\x80\x80\x80\x80\x80\x90\10";
    std::string result;

    expect(!binpb_to_json(message_factory, "protobuf_unittest.TestAny", data, result).ok());
    using namespace std::string_view_literals;
    expect(!binpb_to_json(message_factory, "protobuf_unittest.TestAny", "\x12\x04\x0a\x02\xc0\xcd"sv, result).ok());
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
