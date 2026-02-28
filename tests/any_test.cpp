
#include <google/protobuf/any_test.desc.hpp>
#include <google/protobuf/any_test.glz.hpp>
#include <google/protobuf/any_test.pb.hpp>
#include <google/protobuf/duration.desc.hpp>
#include <google/protobuf/duration.glz.hpp>
#include <google/protobuf/duration.pb.hpp>
#include <google/protobuf/empty.desc.hpp>
#include <google/protobuf/empty.pb.hpp>
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
#include <utility>

using namespace boost::ut;
using namespace std::string_view_literals;

template <typename Exp>
decltype(auto) expect_ok(Exp &&exp) {
  expect(fatal(exp.has_value()));
  return std::forward<Exp>(exp).value(); // NOLINT
}

const suite test_any = [] {
  "any"_test = []<class Traits>() {
    std::pmr::monotonic_buffer_resource mr;
    using string_t = typename Traits::string_t;

    ::protobuf_unittest::TestAny<Traits> message;
    ::google::protobuf::FieldMask<Traits> fm;
    auto paths = std::initializer_list<string_t>{string_t{"/usr/share"}, string_t{"/usr/local/share"}};
    fm.paths = paths;
    expect(hpp_proto::pack_any(message.any_value.emplace(), fm, ::hpp_proto::alloc_from(mr)).ok());

    std::vector<char> buf;
    expect(hpp_proto::write_binpb(message, buf).ok());

    ::protobuf_unittest::TestAny<Traits> message2;
    expect(hpp_proto::read_binpb(message2, buf, ::hpp_proto::alloc_from(mr)).ok());
    ::google::protobuf::FieldMask<Traits> fm2;
    expect(hpp_proto::unpack_any(message2.any_value.value(), fm2, ::hpp_proto::alloc_from(mr)).ok());
    expect(std::ranges::equal(paths, fm2.paths));

    expect(!hpp_proto::unpack_any<::proto3_unittest::ForeignMessage<Traits>>(message2.any_value.value(),
                                                                             ::hpp_proto::alloc_from(mr))
                .has_value());
  } | std::tuple<::hpp_proto::default_traits, ::hpp_proto::non_owning_traits>{};
};

const suite test_dynamic_message_any = [] {
  "wellknown_type"_test = [] {
    ::protobuf_unittest::TestAny<> message;
    ::google::protobuf::FieldMask<> fm;
    fm.paths = {"/usr/share", "/usr/local/share"};
    expect(hpp_proto::pack_any(message.any_value.emplace(), fm).ok());

    auto message_factory = expect_ok(::hpp_proto::dynamic_message_factory::create(
        ::hpp_proto::file_descriptors::desc_set_google_protobuf_field_mask_proto()));

    const std::string_view expected_json =
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.FieldMask","value":"/usr/share,/usr/local/share"}})";
    std::string buf;
    expect(hpp_proto::write_json(message, buf, hpp_proto::use_factory{message_factory}).ok());
    expect(eq(buf, expected_json));

    ::protobuf_unittest::TestAny<> message2;
    expect(hpp_proto::read_json(message2, expected_json, hpp_proto::use_factory{message_factory}).ok());
    expect(message == message2);

    std::pmr::monotonic_buffer_resource mr;
    ::protobuf_unittest::TestAny<hpp_proto::non_owning_traits> message3;
    expect(hpp_proto::read_json(message3, expected_json, hpp_proto::alloc_from{mr},
                                hpp_proto::use_factory{message_factory})
               .ok());
    expect(fatal(message3.any_value.has_value()));
    expect(message.any_value->type_url == message3.any_value->type_url);
    expect(std::ranges::equal(message.any_value->value, message3.any_value->value));

    expect(hpp_proto::write_json<hpp_proto::json_write_opts{.prettify = true}>(message, buf,
                                                                               hpp_proto::use_factory{message_factory})
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

  auto protos = hpp_proto::distinct_file_descriptor_pb_array{
      ::hpp_proto::file_descriptors::_desc_google_protobuf_unittest_import_proto,
      ::hpp_proto::file_descriptors::_desc_google_protobuf_unittest_import_public_proto,
      ::hpp_proto::file_descriptors::_desc_google_protobuf_unittest_proto3_proto,
      ::hpp_proto::file_descriptors::_desc_google_protobuf_any_proto,
      ::hpp_proto::file_descriptors::_desc_google_protobuf_any_test_proto,
      ::hpp_proto::file_descriptors::_desc_google_protobuf_empty_proto,
      ::hpp_proto::file_descriptors::_desc_google_protobuf_timestamp_proto,
      ::hpp_proto::file_descriptors::_desc_google_protobuf_duration_proto,
      ::hpp_proto::file_descriptors::_desc_google_protobuf_field_mask_proto,
      ::hpp_proto::file_descriptors::_desc_google_protobuf_wrappers_proto,
  };

  auto message_factory = expect_ok(::hpp_proto::dynamic_message_factory::create(protos));

  "any_json_edge_cases"_test = [&] {
    auto expect_read_fail = [&](std::string_view json) {
      ::protobuf_unittest::TestAny<> message;
      auto status = hpp_proto::read_json(message, json, hpp_proto::use_factory{message_factory});
      expect(!status.ok());
    };
    auto expect_read_fail_strict = [&](std::string_view json) {
      ::protobuf_unittest::TestAny<> message;
      auto status = hpp_proto::read_json<glz::opts{.error_on_unknown_keys = true}>(
          message, json, hpp_proto::use_factory{message_factory});
      expect(!status.ok());
    };
    auto expect_read_ok = [&](std::string_view json) {
      ::protobuf_unittest::TestAny<> message;
      auto status = hpp_proto::read_json(message, json, hpp_proto::use_factory{message_factory});
      expect(status.ok()) << json;
    };

    expect_read_fail(R"({"anyValue":{"value":"/usr/share"}})");                               // missing @type
    expect_read_fail(R"({"anyValue":{"@type":"","c":1}})");                                   // empty @type
    expect_read_fail(R"({"anyValue":{"@type":"type.googleapis.com","c":1}})");                // invalid formatted @type
    expect_read_fail(R"({"anyValue":{"@type":"type.googleapis.com/does.not.Exist","c":1}})"); // unknown type_url
    expect_read_ok(
        R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage","@type":"type.googleapis.com/proto3_unittest.ForeignMessage","c":1}})"); // duplicate @type
    expect_read_fail(
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.FieldMask","value":"/usr/share","extra":1}})"); // unknown key in well-known
    expect_read_ok(
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.FieldMask","value":"/usr/share","value":"/usr/local"}})"); // duplicate value
    expect_read_ok(R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.FieldMask"}})"); // missing value
    expect_read_fail_strict(
        R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage","c":1,"unknown":2}})"); // unknown
                                                                                                             // key with
                                                                                                             // strict
                                                                                                             // option

    std::string bad_utf8 = "{\"anyValue\":{\"@type\":\"\xC0\",\"c\":1}}";
    expect_read_fail(bad_utf8); // invalid utf8 @type
    std::string bad_control = "{\"anyValue\":{\"@type\":\"\x01\",\"c\":1}}";
    expect_read_fail(bad_control); // invalid control character in @type

    expect_read_ok( // @type not first
        R"({"anyValue":{"c":1234,"@type":"type.googleapis.com/proto3_unittest.ForeignMessage"}})");
    expect_read_ok( // URL with extra path components should use suffix after last '/'
        R"({"anyValue":{"@type":"https://type.googleapis.com/proto3_unittest.ForeignMessage","c":1234}})");

    expect_read_ok( // duplicated anyValue field
        R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage","c":1234},"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage","c":2345}})");

    expect_read_fail( // duplicated anyValue field, invalid second
        R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage","c":1234},"anyValue":{"c":1234}})");
  };

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  auto expect_test_any_json = [&](const ::protobuf_unittest::TestAny<> &message, std::string_view json,
                                  std::string_view pretty_json = {}) {
    std::string result;
    expect(hpp_proto::write_json(message, result, hpp_proto::use_factory{message_factory}).ok());
    expect(eq(result, json));

    std::vector<char> pb;
    expect(hpp_proto::write_binpb(message, pb).ok());

    std::string dyn_result;
    expect(binpb_to_json(message_factory, "protobuf_unittest.TestAny", pb, dyn_result).ok());
    expect(eq(dyn_result, json));

    if (!pretty_json.empty()) {
      expect(binpb_to_json<hpp_proto::json_write_opts{.prettify = true}>(message_factory, "protobuf_unittest.TestAny",
                                                                         pb, result)
                 .ok());
      expect(eq(pretty_json, result));
    }
  };

  "any_json"_test = [&] {
    expect_test_any_json({.any_value = {}}, "{}"sv);
    ::protobuf_unittest::TestAny<> type_only;
    type_only.any_value.emplace().type_url = "type.googleapis.com/proto3_unittest.ForeignMessage";
    expect_test_any_json(type_only, R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage"}})"sv);

    ::protobuf_unittest::TestAny<> with_value;
    with_value.any_value.emplace() = {.type_url = "type.googleapis.com/proto3_unittest.ForeignMessage",
                                      .value = {std::byte{0x10}, std::byte{0x01}}};
    expect_test_any_json(with_value,
                         R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage"}})"sv);
  };

  auto expect_pack_any_json_roundtrip = [&](const auto &v, std::string_view json, std::string_view pretty_json = {}) {
    ::protobuf_unittest::TestAny<> message;
    expect(hpp_proto::pack_any(message.any_value.emplace(), v).ok()) << json;
    expect_test_any_json(message, json, pretty_json);
    ::protobuf_unittest::TestAny<> message2;
    expect(hpp_proto::read_json(message2, json, hpp_proto::use_factory{message_factory}).ok()) << json;
    expect(message == message2);
  };

  "pack_any_json"_test = [&] {
    expect_pack_any_json_roundtrip(
        proto3_unittest::ForeignMessage<>{.c = 1234},
        R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage","c":1234}})"sv,
        R"({
   "anyValue": {
      "@type": "type.googleapis.com/proto3_unittest.ForeignMessage",
      "c": 1234
   }
})");

    expect_pack_any_json_roundtrip(::google::protobuf::Empty<>{},
                                   R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.Empty"}})"sv);
    expect_pack_any_json_roundtrip(
        ::google::protobuf::Timestamp<>{.seconds = 1000, .nanos = 0},
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.Timestamp","value":"1970-01-01T00:16:40Z"}})"sv);

    expect_pack_any_json_roundtrip(
        ::google::protobuf::Duration<>{.seconds = 1000, .nanos = 0},
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.Duration","value":"1000s"}})"sv);

    expect_pack_any_json_roundtrip(
        ::google::protobuf::Int64Value{.value = 1000},
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.Int64Value","value":"1000"}})"sv);

    expect_pack_any_json_roundtrip(
        ::google::protobuf::Int32Value<>{.value = 42},
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.Int32Value","value":42}})"sv);
  };

  "bad_message"_test = [&] {
    std::string_view data =
        "\x12\x39\x0a\x32\x74\x79\x70\x65\x2e\x67\x6f\x6f\x67\x6c\x65\x61\x70\x69\x73\x2e\x63\x6f\x6d\x2f"
        "\x70\x72\x6f\x74\x6f\x33\x5f\x75\x6e\x69\x74\x74\x65\x73\x74\x2e\x46\x6f\x72\x65\x69\x67\x6e\x4d"
        "\x65\x73\x73\x61\x67\x65\x12\x03\x08\xd2\x89\x80\x80\x80\x80\x80\x80\x80\x90\10";
    std::string result;

    expect(!binpb_to_json(message_factory, "protobuf_unittest.TestAny", data, result).ok());
    using namespace std::string_view_literals;
    expect(!binpb_to_json(message_factory, "protobuf_unittest.TestAny", "\x12\x04\x0a\x02\xc0\xcd"sv, result).ok());
  };

  "type_not_found"_test = [data] {
    auto message_factory = expect_ok(hpp_proto::dynamic_message_factory::create(
        hpp_proto::file_descriptors::desc_set_google_protobuf_any_test_proto()));
    std::string result;
    expect(!binpb_to_json(message_factory, "protobuf_unittest.TestAny", data, result).ok());
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
