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

#include <hpp_proto/dynamic_message_json.hpp>

#include <optional>
#include <stdexcept>

#include <boost/ut.hpp>
namespace ut = boost::ut;
using source_location = boost::ut::reflection::source_location;
using namespace ut;
using namespace std::string_view_literals;
using namespace std::string_literals;

#ifdef __GNUC__
#ifdef __apple_build_version__
#pragma clang diagnostic ignored "-Wmissing-designated-field-initializers"
#else
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
#endif

template <typename T>
void verify(const ::hpp::proto::dynamic_message_factory &factory, const T &msg, std::string_view json,
            std::optional<std::string_view> pretty_json = std::nullopt) {

  expect(eq(json, hpp::proto::write_json(msg).value()));

  if (pretty_json && !pretty_json->empty()) {
    expect(eq(*pretty_json, hpp::proto::write_json(msg, hpp::proto::indent_level<3>).value()));
  }

  T msg2{};

  expect(fatal((hpp::proto::read_json(msg2, json).ok())));
  expect(msg == msg2);

  std::pmr::monotonic_buffer_resource memory_resource;
  auto dyn_msg = factory.get_message(hpp::proto::message_name(msg), memory_resource);
  expect(fatal(dyn_msg.has_value()));
  auto message = *dyn_msg;

  hpp::proto::bytes pb;
  auto ec = hpp::proto::write_proto(msg, pb);
  expect(ec.ok());

  expect(hpp::proto::read_proto(message, pb).ok());

  std::string json_buf;
  expect(!::glz::write_json(message, json_buf));
  expect(json_buf == json);

  if (pretty_json && !pretty_json->empty()) {
    expect(!::glz::write<glz::opts{.prettify = true}>(message, json_buf));
    expect(eq(json_buf, *pretty_json));
  }

  hpp::proto::bytes pb_buf;
  expect(::hpp::proto::write_proto(message, pb_buf).ok());
  expect(std::ranges::equal(pb_buf, pb));
}

struct pb_buffer_view {
  std::string_view value;
};

hpp::proto::status dynamic_proto_to_json(const ::hpp::proto::dynamic_message_factory &factory,
                                         std::string_view message_name, pb_buffer_view pb_buf, std::string &json) {
  std::pmr::monotonic_buffer_resource memory_resource;
  auto dyn_msg = factory.get_message(message_name, memory_resource);
  if (!dyn_msg.has_value()) {
    return std::errc::invalid_argument;
  }
  auto message = *dyn_msg;
  if (auto r = hpp::proto::read_proto(message, pb_buf.value); !r.ok()) {
    return r;
  }
  if (auto err = glz::write_json(message, json); err) {
    return std::errc::bad_message;
  }
  return {};
}

// NOLINTBEGIN(clang-diagnostic-missing-designated-field-initializers)
const ut::suite test_timestamp = [] {
  using timestamp_t = google::protobuf::Timestamp<>;

  hpp::proto::dynamic_message_factory factory{hpp::proto::file_descriptors::desc_set_google_protobuf_timestamp_proto()};

  verify<timestamp_t>(factory, timestamp_t{.seconds = 1000}, R"("1970-01-01T00:16:40Z")");
  verify<timestamp_t>(factory, timestamp_t{.seconds = 1000, .nanos = 20}, R"("1970-01-01T00:16:40.000000020Z")");

  timestamp_t msg;
  ut::expect(hpp::proto::read_json(msg, R"("1970-01-01T00:16:40.2Z")").ok());
  ut::expect(msg == timestamp_t{.seconds = 1000, .nanos = 200000000});

  ut::expect(!hpp::proto::read_json(msg, R"("1970-01-01T00:16:40.2xZ")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("1970-01-01T00:16:40")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("197-01-01T00:16:40")").ok());
  ut::expect(!hpp::proto::read_json(msg, R"("197-01-01T00:16:40.00000000000Z")").ok());

  ut::expect(!hpp::proto::write_json(timestamp_t{.seconds = 1000, .nanos = 1000000000}).has_value());

  "timestamp_second_overlong"_test = [&factory] {
    std::string json_buf;
    using namespace std::string_view_literals;
    expect(!dynamic_proto_to_json(factory, "google.protobuf.Timestamp",
                                  pb_buffer_view{"\x08\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01\x10\x01"sv},
                                  json_buf)
                .ok());
  };

  "timestamp_nano_too_large"_test = [&factory] {
    std::string json_buf;
    std::string pb_data;
    expect(hpp::proto::write_proto(timestamp_t{.seconds = 1000, .nanos = 1000000000}, pb_data).ok());
    expect(!dynamic_proto_to_json(factory, "google.protobuf.Timestamp", pb_buffer_view{pb_data}, json_buf).ok());
  };
};

const ut::suite test_duration = [] {
  using duration_t = google::protobuf::Duration<>;
  hpp::proto::dynamic_message_factory factory{hpp::proto::file_descriptors::desc_set_google_protobuf_duration_proto()};

  verify<duration_t>(factory, duration_t{.seconds = 1000}, R"("1000s")");
  verify<duration_t>(factory, duration_t{.seconds = -1000, .nanos = 0}, R"("-1000s")");
  verify<duration_t>(factory, duration_t{.seconds = 1000, .nanos = 20}, R"("1000.000000020s")");
  verify<duration_t>(factory, duration_t{.seconds = -1000, .nanos = -20}, R"("-1000.000000020s")");

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
  hpp::proto::dynamic_message_factory factory{
      hpp::proto::file_descriptors::desc_set_google_protobuf_field_mask_proto()};

  using FieldMask = google::protobuf::FieldMask<>;
  verify<FieldMask>(factory, FieldMask{}, R"("")");
  verify<FieldMask>(factory, FieldMask{.paths = {"abc", "def"}}, R"("abc,def")");
};

const ut::suite test_wrapper = [] {
  hpp::proto::dynamic_message_factory factory{hpp::proto::file_descriptors::desc_set_google_protobuf_wrappers_proto()};

  "wrapper"_test = [&factory] {
    using Int64Value = google::protobuf::Int64Value<>;
    verify<Int64Value>(factory, Int64Value{1000, {}}, R"("1000")");

    std::string json_buf;
    using namespace std::string_view_literals;
    // wrong tag
    expect(!dynamic_proto_to_json(factory, "google.protobuf.Int64Value", pb_buffer_view{"\x00\x01"sv}, json_buf).ok());
    // wrong value
    expect(!dynamic_proto_to_json(factory, "google.protobuf.Int64Value",
                                  pb_buffer_view{"\x08\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"sv}, json_buf)
                .ok());
    // skip unknown field
    expect(dynamic_proto_to_json(factory, "google.protobuf.Int64Value", pb_buffer_view{"\x10\x01"sv}, json_buf).ok());
    expect(json_buf.empty());
  };
};

const ut::suite test_empty = [] {
  hpp::proto::dynamic_message_factory factory{hpp::proto::file_descriptors::desc_set_google_protobuf_empty_proto()};
  using Empty = google::protobuf::Empty<>;
  verify<Empty>(factory, Empty{}, "{}");
};

const ut::suite test_value = [] {
  using namespace boost::ut;
  hpp::proto::dynamic_message_factory factory{hpp::proto::file_descriptors::desc_set_google_protobuf_struct_proto()};

  using Value = google::protobuf::Value<>;
  using NullValue = google::protobuf::NullValue;
  using ListValue = google::protobuf::ListValue<>;
  using Struct = google::protobuf::Struct<>;
  "value"_test = [&factory] {
    verify<Value>(factory, Value{.kind = NullValue{}}, "null");
    verify<Value>(factory, Value{.kind = true}, "true");
    verify<Value>(factory, Value{.kind = false}, "false");
    verify<Value>(factory, Value{.kind = 1.0}, "1");
    verify<Value>(factory, Value{.kind = "abc"}, R"("abc")");
    verify<Value>(factory, Value{.kind = ListValue{.values = {Value{.kind = true}, Value{.kind = 1.0}}}}, "[true,1]");
    verify<Value>(factory, Value{.kind = Struct{.fields = {{"f1", Value{.kind = true}}, {"f2", Value{.kind = 1.0}}}}},
                  R"({"f1":true,"f2":1})");
  };

  "struct"_test = [&factory] {
    using Struct = google::protobuf::Struct<>;
    using NullValue = google::protobuf::NullValue;
    verify<Struct>(factory, Struct{}, "{}");
    verify<Struct>(
        factory,
        Struct{.fields = {{"f1", Value{.kind = true}}, {"f2", Value{.kind = 1.0}}, {"f3", Value{.kind = NullValue{}}}}},
        R"({"f1":true,"f2":1,"f3":null})", R"({
   "f1": true,
   "f2": 1,
   "f3": null
})");

    std::string json_buf;
    // field name is not a valid utf8 string
    expect(!dynamic_proto_to_json(factory, "google.protobuf.Struct",
                                  pb_buffer_view{"\x0a\x08\x0a\x02\xc0\xcd\x12\x02\x08\x00"sv}, json_buf)
                .ok());
    // skip unknown field
    expect(dynamic_proto_to_json(factory, "google.protobuf.Struct", pb_buffer_view{"\x10\x01"sv}, json_buf).ok());
  };

  "list"_test = [&factory] {
    using ListValue = google::protobuf::ListValue<>;
    verify<ListValue>(factory, ListValue{}, "[]");
    verify<ListValue>(factory, ListValue{.values = {Value{.kind = true}, Value{.kind = 1.0}}}, "[true,1]",
                      "[\n   true,\n   1\n]");

    std::string json_buf;

    // list element is not a valid utf8 string
    expect(!dynamic_proto_to_json(factory, "google.protobuf.ListValue", pb_buffer_view{"\x0a\x04\x1a\x02\xc0\xcd"sv},
                                  json_buf)
                .ok());
    // skip first unknown element
    expect(dynamic_proto_to_json(factory, "google.protobuf.ListValue", pb_buffer_view{"\x0a\x02\x38\x01"sv}, json_buf)
               .ok());
    expect(eq(json_buf, "[]"s));
    // skip middle unknown element
    expect(dynamic_proto_to_json(factory, "google.protobuf.ListValue",
                                 pb_buffer_view{"\x0a\x02\x20\x01\x0a\x02\x38\x01\x0a\x02\x20\x00"sv}, json_buf)
               .ok());
    expect(eq(json_buf, "[true,false]"s));
    // TODO: we need to test the case where the unknown element in not in the beginning of the list

    // skip unknown field
    expect(dynamic_proto_to_json(factory, "google.protobuf.ListValue", pb_buffer_view{"\x10\x01"sv}, json_buf).ok());
  };
};

// NOLINTEND(clang-diagnostic-missing-designated-field-initializers)

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
