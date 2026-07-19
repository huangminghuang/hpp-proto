
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

// Protobuf Any conformance fixtures intentionally use literal wire values and JSON payloads.
// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,misc-const-correctness)

template <typename Exp>
decltype(auto) expect_ok(Exp &&exp) {
  expect(fatal(exp.has_value()));
  return std::forward<Exp>(exp).value();
}

const suite test_any = [] {
  "any"_test = []<class Traits>() {
    std::pmr::monotonic_buffer_resource mr;
    using string_t = Traits::string_t;

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

    message2.any_value->type_url = "type.googleapis.com/Othergoogle.protobuf.FieldMask";
    expect(!hpp_proto::unpack_any(message2.any_value.value(), fm2, ::hpp_proto::alloc_from(mr)).ok());

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
        ::hpp_proto::file_descriptors::google::protobuf::field_mask_proto::file_descriptor_set()));

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
      ::hpp_proto::file_descriptors::google::protobuf::unittest_import_proto::file_descriptor_,
      ::hpp_proto::file_descriptors::google::protobuf::unittest_import_public_proto::file_descriptor_,
      ::hpp_proto::file_descriptors::google::protobuf::unittest_proto3_proto::file_descriptor_,
      ::hpp_proto::file_descriptors::google::protobuf::any_proto::file_descriptor_,
      ::hpp_proto::file_descriptors::google::protobuf::any_test_proto::file_descriptor_,
      ::hpp_proto::file_descriptors::google::protobuf::empty_proto::file_descriptor_,
      ::hpp_proto::file_descriptors::google::protobuf::timestamp_proto::file_descriptor_,
      ::hpp_proto::file_descriptors::google::protobuf::duration_proto::file_descriptor_,
      ::hpp_proto::file_descriptors::google::protobuf::field_mask_proto::file_descriptor_,
      ::hpp_proto::file_descriptors::google::protobuf::wrappers_proto::file_descriptor_,
  };

  auto message_factory = expect_ok(::hpp_proto::dynamic_message_factory::create(protos));

  "dynamic_any_respects_recursion_limit"_test = [&] {
    constexpr std::string_view json =
        R"({"anyValue":{"@type":"type.googleapis.com/protobuf_unittest.TestAny","int32Value":1}})";

    std::pmr::monotonic_buffer_resource accepted_mr;
    auto accepted = expect_ok(message_factory.get_message("protobuf_unittest.TestAny", accepted_mr));
    expect(hpp_proto::read_json(accepted, json, hpp_proto::recursion_limit<2>).ok());

    std::pmr::monotonic_buffer_resource rejected_mr;
    auto rejected = expect_ok(message_factory.get_message("protobuf_unittest.TestAny", rejected_mr));
    auto read_status = hpp_proto::read_json(rejected, json, hpp_proto::recursion_limit<1>);
    expect(!read_status.ok());
    expect(read_status.ctx.ec == glz::error_code::exceeded_max_recursive_depth);

    std::string output;
    auto write_status = hpp_proto::write_json(accepted.cref(), output, hpp_proto::recursion_limit<1>);
    expect(!write_status.ok());
    expect(write_status.ctx.ec == glz::error_code::exceeded_max_recursive_depth);

    output.clear();
    expect(hpp_proto::write_json(accepted.cref(), output, hpp_proto::recursion_limit<2>).ok());

    constexpr std::string_view nested_json =
        R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.TestAllTypes","repeatedNestedMessage":[{"bb":1}]}})";
    std::pmr::monotonic_buffer_resource nested_mr;
    auto nested = expect_ok(message_factory.get_message("protobuf_unittest.TestAny", nested_mr));
    expect(hpp_proto::read_json(nested, nested_json, hpp_proto::recursion_limit<3>).ok());

    std::pmr::monotonic_buffer_resource nested_rejected_mr;
    auto nested_rejected = expect_ok(message_factory.get_message("protobuf_unittest.TestAny", nested_rejected_mr));
    auto nested_read_status = hpp_proto::read_json(nested_rejected, nested_json, hpp_proto::recursion_limit<2>);
    expect(!nested_read_status.ok());
    expect(nested_read_status.ctx.ec == glz::error_code::exceeded_max_recursive_depth);

    output.clear();
    auto nested_write_status = hpp_proto::write_json(nested.cref(), output, hpp_proto::recursion_limit<2>);
    expect(!nested_write_status.ok());
    expect(nested_write_status.ctx.ec == glz::error_code::exceeded_max_recursive_depth);
  };

  "any_binary_conversion_uses_json_recursion_limit"_test = [&] {
    constexpr auto nested_messages = hpp_proto::default_max_recursion_depth + 1;
    std::string recursive_json;
    for (std::uint32_t i = 0; i < nested_messages; ++i) {
      recursive_json += R"({"child":)";
    }
    recursive_json += "{}";
    recursive_json.append(nested_messages, '}');

    std::pmr::monotonic_buffer_resource recursive_mr;
    auto recursive = expect_ok(message_factory.get_message("proto3_unittest.NestedTestAllTypes", recursive_mr));
    auto dynamic_read = hpp_proto::read_json(recursive, recursive_json, hpp_proto::recursion_limit<nested_messages>);
    expect(dynamic_read.ok()) << "build recursive dynamic message";

    std::vector<std::byte> payload;
    auto dynamic_write = hpp_proto::write_binpb(recursive.cref(), payload, hpp_proto::recursion_limit<nested_messages>);
    expect(dynamic_write.ok()) << "encode recursive Any payload";

    ::protobuf_unittest::TestAny<> source;
    source.any_value.emplace().type_url = "type.googleapis.com/proto3_unittest.NestedTestAllTypes";
    source.any_value->value = payload;

    std::string output;
    auto any_write = hpp_proto::write_json(source, output, hpp_proto::use_factory{message_factory},
                                           hpp_proto::recursion_limit<nested_messages>);
    expect(any_write.ok()) << "decode recursive binary payload while writing Any JSON";

    // Build canonical generic-Any JSON directly so the reverse direction independently exercises
    // the JSON-to-binary adapter with the same non-default recursion policy.
    std::string json = R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.NestedTestAllTypes",)";
    json += std::string_view{recursive_json}.substr(1);
    json += '}';

    ::protobuf_unittest::TestAny<> parsed;
    auto any_read = hpp_proto::read_json(parsed, json, hpp_proto::use_factory{message_factory},
                                         hpp_proto::recursion_limit<nested_messages>);
    expect(any_read.ok()) << "encode recursive binary payload while reading Any JSON: "
                          << glz::format_error(any_read.ctx, json);
    expect(parsed == source);
  };

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
    expect_read_fail(R"({"anyValue":{"@type":"type.googleapis.com/","c":1}})");               // empty type name
    expect_read_fail(R"({"anyValue":{"@type":"type.googleapis.com/does.not.Exist","c":1}})"); // unknown type_url
    expect_read_ok(
        R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage","@type":"type.googleapis.com/proto3_unittest.ForeignMessage","c":1}})"); // duplicate @type
    expect_read_fail(
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.FieldMask","value":"/usr/share","extra":1}})"); // unknown key in well-known
    expect_read_fail("{\"anyValue\":{\"@type\":\"type.googleapis.com/google.protobuf.FieldMask\",\"value\":\"/usr/"
                     "share\x01\"}}"); // value with control code
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

    std::vector<char> dynamic_pb;
    expect(hpp_proto::json_to_binpb(message_factory, "protobuf_unittest.TestAny", json, dynamic_pb).ok());
    dyn_result.clear();
    expect(binpb_to_json(message_factory, "protobuf_unittest.TestAny", dynamic_pb, dyn_result).ok());
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
        hpp_proto::file_descriptors::google::protobuf::any_test_proto::file_descriptor_set()));
    std::string result;
    expect(!binpb_to_json(message_factory, "protobuf_unittest.TestAny", data, result).ok());
  };
};

// NOLINTNEXTLINE(bugprone-exception-escape)
int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}

// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,misc-const-correctness)
