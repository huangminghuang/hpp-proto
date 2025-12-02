
#include <google/protobuf/any_test.desc.hpp>
#include <google/protobuf/any_test.glz.hpp>
#include <google/protobuf/any_test.pb.hpp>
#include <google/protobuf/field_mask.desc.hpp>
#include <google/protobuf/field_mask.pb.hpp>
#include <google/protobuf/unittest_proto3.desc.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>

#include "test_util.hpp"
#include <boost/ut.hpp>

#include <hpp_proto/dynamic_message_json.hpp>

using namespace boost::ut;

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
    expect(hpp::proto::write_proto(message, buf).ok());

    ::protobuf_unittest::TestAny<Traits> message2;
    expect(hpp::proto::read_proto(message2, buf, ::hpp::proto::alloc_from(mr)).ok());
    ::google::protobuf::FieldMask<Traits> fm2;
    expect(hpp::proto::unpack_any(message2.any_value.value(), fm2, ::hpp::proto::alloc_from(mr)).ok());
    expect(std::ranges::equal(paths, fm2.paths));

    expect(!hpp::proto::unpack_any<::proto3_unittest::ForeignMessage<Traits>>(message2.any_value.value(),
                                                                              ::hpp::proto::alloc_from(mr))
                .has_value());
  } | std::tuple<::hpp::proto::default_traits, ::hpp::proto::non_owning_traits>{};

// #ifndef HPP_PROTO_DISABLE_GLAZE
#if 0
  "any_json_wellknown"_test = [] {
    ::protobuf_unittest::TestAny<> message;
    ::google::protobuf::FieldMask<> fm;
    fm.paths = {"/usr/share", "/usr/local/share"};
    expect(hpp::proto::pack_any(message.any_value.emplace(), fm).ok());

    auto ser =
        hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_field_mask_proto());
    expect(ser.has_value());

    const std::string_view expected_json =
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.FieldMask","value":"/usr/share,/usr/local/share"}})";
    std::string buf;
    expect(hpp::proto::write_json(message, buf, *ser).ok());
    expect(eq(buf, expected_json));

    ::protobuf_unittest::TestAny<> message2;
    expect(hpp::proto::read_json(message2, expected_json, *ser).ok());
    expect(message == message2);

    expect(hpp::proto::write_json(message, buf, *ser, hpp::proto::indent_level<3>).ok());
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

  "any_json"_test = [data] {
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

    std::vector<char> serialized;
    expect(ser->json_to_proto(message_name, expected_json, serialized).ok());
    expect(std::ranges::equal(data, serialized));

    hpp_result = ser->proto_to_json(message_name, data, hpp::proto::indent_level<3>);
    expect(fatal(hpp_result.has_value()));
    const char *expected_json_indented = R"({
   "anyValue": {
      "@type": "type.googleapis.com/proto3_unittest.ForeignMessage",
      "c": 1234
   }
})";
    expect(eq(expected_json_indented, *hpp_result));
  };

  "any_json_type_not_found"_test = [data] {
    auto ser =
        hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_any_test_proto());

    expect(fatal(ser.has_value()));
    expect(!ser->proto_to_json("protobuf_unittest.TestAny", data).has_value());
  };

  "any_json_bad_message"_test = [] {
    auto ser = hpp::proto::dynamic_serializer::make(
        hpp::proto::file_descriptors::desc_set_google_protobuf_unittest_proto3_proto(),
        hpp::proto::file_descriptors::desc_set_google_protobuf_any_test_proto());

    std::string_view data =
        "\x12\x39\x0a\x32\x74\x79\x70\x65\x2e\x67\x6f\x6f\x67\x6c\x65\x61\x70\x69\x73\x2e\x63\x6f\x6d\x2f"
        "\x70\x72\x6f\x74\x6f\x33\x5f\x75\x6e\x69\x74\x74\x65\x73\x74\x2e\x46\x6f\x72\x65\x69\x67\x6e\x4d"
        "\x65\x73\x73\x61\x67\x65\x12\x03\x08\xd2\x89\x80\x80\x80\x80\x80\x80\x80\x90\10";

    expect(!ser->proto_to_json("protobuf_unittest.TestAny", data).has_value());
    using namespace std::string_view_literals;
    expect(!ser->proto_to_json("protobuf_unittest.TestAny", "\x12\x04\x0a\x02\xc0\xcd"sv).has_value());
  };

#endif
};

const suite test_dynamic_message_any = [] {
  "wellknown_type"_test = [] {
    ::protobuf_unittest::TestAny<> message;
    ::google::protobuf::FieldMask<> fm;
    fm.paths = {"/usr/share", "/usr/local/share"};
    expect(hpp::proto::pack_any(message.any_value.emplace(), fm).ok());

    // ::hpp::proto::distinct_file_descriptor_pb_array descriptor_pbs{
    //     ::hpp::proto::file_descriptors::_desc_google_protobuf_any_proto,
    //     ::hpp::proto::file_descriptors::_desc_google_protobuf_any_test_proto,
    //     ::hpp::proto::file_descriptors::_desc_google_protobuf_field_mask_proto};

    auto message_factory = ::hpp::proto::dynamic_message_factory{
        ::hpp::proto::file_descriptors::desc_set_google_protobuf_field_mask_proto()};

    const std::string_view expected_json =
        R"({"anyValue":{"@type":"type.googleapis.com/google.protobuf.FieldMask","value":"/usr/share,/usr/local/share"}})";
    std::string buf;
    expect(hpp::proto::write_json(message, buf, message_factory).ok());
    expect(eq(buf, expected_json));

    ::protobuf_unittest::TestAny<> message2;
    expect(hpp::proto::read_json(message2, expected_json, message_factory).ok());
    expect(message == message2);

    expect(hpp::proto::write_json(message, buf, message_factory, hpp::proto::indent_level<3>).ok());
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
  };

  "any_json"_test = [&] {
    auto message_factory = ::hpp::proto::dynamic_message_factory{protos};

    const char *message_name = "protobuf_unittest.TestAny";
    std::string_view expected_json =
        R"({"anyValue":{"@type":"type.googleapis.com/proto3_unittest.ForeignMessage","c":1234}})";

    std::string result;
    expect(proto_to_json(message_factory, message_name, data, result).ok());
    expect(eq(expected_json, result));

    std::vector<char> serialized;
    expect(json_to_proto(message_factory, message_name, expected_json, serialized).ok());
    expect(std::ranges::equal(data, serialized));

    expect(proto_to_json(message_factory, message_name, data, result, hpp::proto::indent_level<3>).ok());
    const char *expected_json_indented = R"({
   "anyValue": {
      "@type": "type.googleapis.com/proto3_unittest.ForeignMessage",
      "c": 1234
   }
})";
    expect(eq(expected_json_indented, result));
  };

  "type_not_found"_test = [data] {
    auto message_factory =
        hpp::proto::dynamic_message_factory{hpp::proto::file_descriptors::desc_set_google_protobuf_any_test_proto()};
    std::string result;
    expect(!proto_to_json(message_factory, "protobuf_unittest.TestAny", data, result).ok());
  };

  "bad_message"_test = [&] {
    auto message_factory = ::hpp::proto::dynamic_message_factory{protos};

    std::string_view data =
        "\x12\x39\x0a\x32\x74\x79\x70\x65\x2e\x67\x6f\x6f\x67\x6c\x65\x61\x70\x69\x73\x2e\x63\x6f\x6d\x2f"
        "\x70\x72\x6f\x74\x6f\x33\x5f\x75\x6e\x69\x74\x74\x65\x73\x74\x2e\x46\x6f\x72\x65\x69\x67\x6e\x4d"
        "\x65\x73\x73\x61\x67\x65\x12\x03\x08\xd2\x89\x80\x80\x80\x80\x80\x80\x80\x90\10";
    std::string result;

    expect(!proto_to_json(message_factory, "protobuf_unittest.TestAny", data, result).ok());
    using namespace std::string_view_literals;
    expect(!proto_to_json(message_factory, "protobuf_unittest.TestAny", "\x12\x04\x0a\x02\xc0\xcd"sv, result).ok());
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
