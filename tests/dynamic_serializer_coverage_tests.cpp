#include "test_util.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/dynamic_serializer.hpp>
using namespace boost::ut;
using namespace std::string_view_literals;
using namespace std::string_literals;

const boost::ut::suite dynamic_serializer_coverage_test = [] {
  auto descriptors = read_file("unittest.desc.binpb");
  auto ser = hpp::proto::dynamic_serializer::make(descriptors);
  expect(fatal(ser.has_value()));

  "packed_repeated_error_handling"_test = [&ser] {
    {
      auto r = ser->proto_to_json("proto3_unittest.TestAllTypes", "\x9a\x02\x09\x00\x02\x04\x06\x08\x01\x03\x05\x07"sv);
      expect(fatal(r.has_value()));
      expect(eq(*r, R"({"repeatedSint32":[0,1,2,3,4,-1,-2,-3,-4]})"s));
    }

    // last element unterminated
    expect(!ser->proto_to_json("proto3_unittest.TestAllTypes", "\x9a\x02\xa8\x96\xb1"sv).has_value());
    // overlong element in the middle
    expect(!ser->proto_to_json("proto3_unittest.TestAllTypes",
                               "\x9a\x02\x10\x08\xF6\xF1\xF0\xF0\xF0\xF0\xF0\x80\x90\xa1\xb2\xc3\xd4\xe5\x06"sv)
                .has_value());

    // zero length
    expect(ser->proto_to_json("proto3_unittest.TestAllTypes", "\x9a\x02\x00"sv).has_value());
    // invalid length
    expect(!ser->proto_to_json("proto3_unittest.TestAllTypes", "\x9a\x02\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"sv)
                .has_value());
    // encoded size longer than available data
    expect(!ser->proto_to_json("proto3_unittest.TestAllTypes", "\x9a\x02\x04\xa8\x96\x01"sv).has_value());
  };

  "repeated_string_error_handling"_test = [&ser] {
    {
      auto r = ser->proto_to_json("proto3_unittest.TestAllTypes", "\xe2\x02\x04\x74\x65\x73\x74"sv);
      expect(fatal(r.has_value()));
      expect(eq(*r, R"({"repeatedString":["test"]})"s));
    }

    // invalid UTF-8
    expect(!ser->proto_to_json("proto3_unittest.TestAllTypes", "\xe2\x02\x02\xc0\xda"sv).has_value());
    // length too long
    expect(!ser->proto_to_json("proto3_unittest.TestAllTypes", "\xe2\x02\x05\x74\x65\x73\x74"sv).has_value());
    // invalid length
    expect(!ser->proto_to_json("proto3_unittest.TestAllTypes", "\xe2\x02\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"sv)
                .has_value());
  };

  "nested_message_error_handing"_test = [&ser] {
    {
      auto r = ser->proto_to_json("proto3_unittest.TestAllTypes", "\x92\x01\x02\x08\x01"sv);
      expect(fatal(r.has_value()));
      expect(eq(*r, R"({"optionalNestedMessage":{"bb":1}})"s));
    }

    // length too long
    expect(!ser->proto_to_json("proto3_unittest.TestAllTypes", "\x92\x01\x03\x08\x01"sv).has_value());
    // invalid length
    expect(!ser->proto_to_json("proto3_unittest.TestAllTypes", "\x92\x01\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"sv)
                .has_value());
  };

  "nested_enum_error_handling"_test = [&ser] {
    {
      auto r = ser->proto_to_json("proto3_unittest.TestAllTypes", "\xa8\x01\x01"sv);
      expect(fatal(r.has_value()));
      expect(eq(*r, R"({"optionalNestedEnum":"FOO"})"s));
    }
    // invalid value
    expect(!ser->proto_to_json("proto3_unittest.TestAllTypes", "\xa8\x01\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"sv)
                .has_value());
    // closed enum
    expect(!ser->proto_to_json("protobuf_unittest.TestAllTypes", "\xa8\x01\x04"sv).has_value());
    {
      // out of range open enum
      auto r = ser->proto_to_json("proto3_unittest.TestAllTypes", "\xa8\x01\x04"sv);
      expect(fatal(r.has_value()));
      expect(eq(*r, R"({"optionalNestedEnum":4})"s));
    }
  };

  "skip_unknown_fields"_test = [&ser] {
      expect(ser->proto_to_json("proto3_unittest.TestPackedTypes", "\x0a\x05\x92\x01\x02\x08\x01"sv).has_value());
      // skip invalid length
      expect(!ser->proto_to_json("proto3_unittest.TestPackedTypes", "\x0a\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"sv).has_value());
  };

  "group_error_handling"_test = [&ser] {
    {
      auto r = ser->proto_to_json("protobuf_unittest.TestAllTypes", "\x83\x01\x88\x01\x01\x84\x01"sv);
      expect(fatal(r.has_value()));
      expect(eq(*r, R"({"optionalgroup":{"a":1}})"s));
    }

    // invalid tag
    expect(!ser->proto_to_json("protobuf_unittest.TestAllTypes", "\x83\x01\x00\x01\x01\x84\x01"sv)
                .has_value());

    // invalid nested field
    expect(!ser->proto_to_json("protobuf_unittest.TestAllTypes", "\x83\x01\x88\x01\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x09\x84\x01"sv)
                .has_value());

    // no end tag
    expect(!ser->proto_to_json("protobuf_unittest.TestAllTypes", "\x83\x01\x88\x01\x01"sv).has_value());
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}