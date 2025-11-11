#include <google/protobuf/duration.desc.hpp>
#include <google/protobuf/duration.glz.hpp>
#include <google/protobuf/duration.pb.hpp>

#include <google/protobuf/empty.desc.hpp>
#include <google/protobuf/empty.glz.hpp>
#include <google/protobuf/empty.pb.hpp>

#include <google/protobuf/field_mask.desc.hpp>
#include <google/protobuf/field_mask.glz.hpp>
#include <google/protobuf/field_mask.pb.hpp>

#include <google/protobuf/struct.desc.hpp>
#include <google/protobuf/struct.glz.hpp>
#include <google/protobuf/struct.pb.hpp>

#include <google/protobuf/timestamp.desc.hpp>
#include <google/protobuf/timestamp.glz.hpp>
#include <google/protobuf/timestamp.pb.hpp>

#include <google/protobuf/wrappers.desc.hpp>
#include <google/protobuf/wrappers.glz.hpp>
#include <google/protobuf/wrappers.pb.hpp>

#include <boost/ut.hpp>
namespace ut = boost::ut;
using source_location = boost::ut::reflection::source_location;
using namespace ut;
using namespace std::string_view_literals;
using namespace std::string_literals;

#if defined(__GNUC__)
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wmissing-designated-field-initializers"
#else
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
#endif

template <typename T>
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void verify(const hpp::proto::dynamic_serializer &ser, const T &msg, std::string_view json,
            std::string_view pretty_json = ""sv) {
  expect(eq(json, hpp::proto::write_json(msg).value()));

  if (!pretty_json.empty()) {
    expect(eq(pretty_json, hpp::proto::write_json(msg, hpp::proto::indent_level<3>).value()));
  }

  T msg2;

  expect(fatal((hpp::proto::read_json(msg2, json).ok())));
  expect(msg == msg2);

  if constexpr (requires { hpp::proto::message_name(msg); }) {
    auto message_name = hpp::proto::message_name(msg);

    hpp::proto::bytes pb;
    auto ec = hpp::proto::write_proto(msg, pb);
    expect(ec.ok());

    std::string json_buf;
    expect(ser.proto_to_json(message_name, pb, json_buf).ok());
    expect(json_buf == json);

    if (!pretty_json.empty()) {
      expect(ser.proto_to_json(message_name, pb, json_buf, hpp::proto::indent_level<3>).ok());
      expect(eq(json_buf, pretty_json));
    }

    hpp::proto::bytes pb_buf;
    expect(ser.json_to_proto(message_name, json, pb_buf).ok());
    expect(std::ranges::equal(pb_buf, pb));
  }
}

// NOLINTBEGIN(clang-diagnostic-missing-designated-field-initializers)

const ut::suite test_timestamp = [] {
  using timestamp_t = google::protobuf::Timestamp<>;

  auto ser =
      hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_timestamp_proto());
  expect(fatal((ser.has_value())));

  verify<timestamp_t>(*ser, timestamp_t{.seconds = 1000}, R"("1970-01-01T00:16:40Z")");
  verify<timestamp_t>(*ser, timestamp_t{.seconds = 1000, .nanos = 20}, R"("1970-01-01T00:16:40.000000020Z")");

  timestamp_t msg;
  ut::expect(hpp::proto::read_json(msg, R"("1970-01-01T00:16:40.2Z")").ok());
  ut::expect(msg == timestamp_t{.seconds = 1000, .nanos = 200000000});

  ut::expect(!hpp::proto::read_json(msg, R"("1970-01-01T00:16:40.2xZ")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("1970-01-01T00:16:40")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("197-01-01T00:16:40")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("197-01-01T00:16:40.00000000000Z")").ok());

  ut::expect(!hpp::proto::write_json(timestamp_t{.seconds = 1000, .nanos = 1000000000}).has_value());

  "timestamp_second_overlong"_test = [&ser] {
    std::string json_buf;
    using namespace std::string_view_literals;
    expect(!ser->proto_to_json("google.protobuf.Timestamp",
                               "\x08\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01\x10\x01"sv, json_buf)
                .ok());
  };

  "timestamp_nano_too_large"_test = [&ser] {
    std::string json_buf;
    std::string pb_data;
    expect(hpp::proto::write_proto(timestamp_t{.seconds = 1000, .nanos = 1000000000}, pb_data).ok());
    expect(!ser->proto_to_json("google.protobuf.Timestamp", pb_data, json_buf).ok());
  };
};

const ut::suite test_duration = [] {
  using duration_t = google::protobuf::Duration<>;
  auto ser =
      hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_duration_proto());
  expect(fatal((ser.has_value())));

  verify<duration_t>(*ser, duration_t{.seconds = 1000}, R"("1000s")");
  verify<duration_t>(*ser, duration_t{.seconds = -1000, .nanos = 0}, R"("-1000s")");
  verify<duration_t>(*ser, duration_t{.seconds = 1000, .nanos = 20}, R"("1000.000000020s")");
  verify<duration_t>(*ser, duration_t{.seconds = -1000, .nanos = -20}, R"("-1000.000000020s")");

  duration_t msg;
  ut::expect(hpp::proto::read_json(msg, R"("1000.2s")").ok());
  ut::expect(msg == duration_t{.seconds = 1000, .nanos = 200000000});

  ut::expect(hpp::proto::read_json(msg, R"("-1000.2s")").ok());
  ut::expect(msg == duration_t{.seconds = -1000, .nanos = -200000000});

  ut::expect(!hpp::proto::read_json(msg, R"("1000")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("1000.s")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("1000.2xs")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("abcs")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("-1.s")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"(" 1s")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("1s ")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("-1000.-10000000s")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("-1000. 10000000s")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("1000.0000000000000000s")").ok());

  ut::expect(!hpp::proto::write_json(duration_t{.seconds = 1000, .nanos = 1000000000}).has_value());
};

const ut::suite test_field_mask = [] {
  auto ser =
      hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_field_mask_proto());
  expect(fatal((ser.has_value())));

  using FieldMask = google::protobuf::FieldMask<>;
  verify<FieldMask>(*ser, FieldMask{}, R"("")");
  verify<FieldMask>(*ser, FieldMask{.paths = {"abc", "def"}}, R"("abc,def")");
};

const ut::suite test_wrapper = [] {
  auto ser =
      hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_wrappers_proto());
  expect(fatal((ser.has_value())));
  "wrapper"_test = [&ser] {
    using Int64Value = google::protobuf::Int64Value<>;
    verify<Int64Value>(*ser, Int64Value{1000, {}}, R"("1000")");

    std::string json_buf;
    using namespace std::string_view_literals;
    // wrong tag
    expect(!ser->proto_to_json("google.protobuf.Int64Value", "\x00\x01"sv, json_buf).ok());
    // wrong value
    expect(!ser->proto_to_json("google.protobuf.Int64Value", "\x08\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"sv,
                               json_buf)
                .ok());
    // skip unknown field
    expect(ser->proto_to_json("google.protobuf.Int64Value", "\x10\x01"sv, json_buf).ok());
    expect(json_buf.empty());
  };
};

const ut::suite test_empty = [] {
  auto ser = hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_empty_proto());
  expect(fatal((ser.has_value())));
  using Empty = google::protobuf::Empty<>;
  verify<Empty>(*ser, Empty{}, "{}");
};

#if !defined(_MSC_VER) || (_MSC_VER > 1937)

const ut::suite test_value = [] {
  using namespace boost::ut;
  auto ser =
      hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_struct_proto());
  expect(fatal((ser.has_value())));
  using Value = google::protobuf::Value<>;
  using NullValue = google::protobuf::NullValue;
  using ListValue = google::protobuf::ListValue<>;
  using Struct = google::protobuf::Struct<>;
  "value"_test = [&ser] {
    verify<Value>(*ser, Value{.kind = NullValue{}}, "null");
    verify<Value>(*ser, Value{.kind = true}, "true");
    verify<Value>(*ser, Value{.kind = false}, "false");
    verify<Value>(*ser, Value{.kind = 1.0}, "1");
    verify<Value>(*ser, Value{.kind = "abc"}, R"("abc")");
    verify<Value>(*ser, Value{.kind = ListValue{.values = {Value{.kind = true}, Value{.kind = 1.0}}}}, "[true,1]");
    verify<Value>(*ser, Value{.kind = Struct{.fields = {{"f1", Value{.kind = true}}, {"f2", Value{.kind = 1.0}}}}},
                  R"({"f1":true,"f2":1})");
  };

  "struct"_test = [&ser] {
    using Struct = google::protobuf::Struct<>;
    using NullValue = google::protobuf::NullValue;
    verify<Struct>(*ser, Struct{}, "{}");
    verify<Struct>(
        *ser,
        Struct{.fields = {{"f1", Value{.kind = true}}, {"f2", Value{.kind = 1.0}}, {"f3", Value{.kind = NullValue{}}}}},
        R"({"f1":true,"f2":1,"f3":null})", R"({
   "f1": true,
   "f2": 1,
   "f3": null
})");

    std::string json_buf;
    // field name is not a valid utf8 string
    expect(!ser->proto_to_json("google.protobuf.Struct", "\x0a\x08\x0a\x02\xc0\xcd\x12\x02\x08\x00"sv, json_buf).ok());
    // skip unknown field
    expect(ser->proto_to_json("google.protobuf.Struct", "\x10\x01"sv, json_buf).ok());
  };

  "list"_test = [&ser] {
    using ListValue = google::protobuf::ListValue<>;
    verify<ListValue>(*ser, ListValue{}, "[]");
    verify<ListValue>(*ser, ListValue{.values = {Value{.kind = true}, Value{.kind = 1.0}}}, "[true,1]",
                      "[\n   true,\n   1\n]");

    std::string json_buf;

    // list element is not a valid utf8 string
    expect(!ser->proto_to_json("google.protobuf.ListValue", "\x0a\x04\x1a\x02\xc0\xcd"sv, json_buf).ok());
    // skip unknown element
    expect(ser->proto_to_json("google.protobuf.ListValue", "\x0a\x02\x38\x01"sv, json_buf).ok());
    expect(eq(json_buf, "[]"s));

    // skip unknown field
    expect(ser->proto_to_json("google.protobuf.ListValue", "\x10\x01"sv, json_buf).ok());
  };
};

#endif
// NOLINTEND(clang-diagnostic-missing-designated-field-initializers)

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}