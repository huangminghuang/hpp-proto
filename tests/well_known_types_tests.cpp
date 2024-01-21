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

template <typename T>
void verify(const T &msg, std::string_view json, const hpp::proto::dynamic_serializer &ser,
            const source_location &from_loc = source_location::current()) {
  std::string from_line_number = std::string("from ") + from_loc.file_name() + ":" + std::to_string(from_loc.line());
  expect(eq(json, hpp::proto::write_json(msg).value())) << from_line_number;

  T msg2;

  expect(fatal((hpp::proto::read_json(msg2, json).success()))) << from_line_number;
  expect(msg == msg2);

  if constexpr (requires { hpp::proto::message_name(msg); }) {
    auto message_name = hpp::proto::message_name(msg);

    hpp::proto::bytes pb;
    auto ec = hpp::proto::write_proto(msg, pb);
    expect(!ec.failure()) << from_line_number;

    std::string json_buf;
    expect(ser.proto_to_json(message_name, pb, json_buf).success()) << from_line_number;
    expect(json_buf == json) << from_line_number;
    hpp::proto::bytes pb_buf;
    expect(ser.json_to_proto(message_name, json, pb_buf).success()) << from_line_number;
    expect(std::ranges::equal(pb_buf, pb)) << from_line_number;
  }
}

const ut::suite test_timestamp = [] {
  using timestamp_t = google::protobuf::Timestamp;

  auto ser =
      hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_timestamp_proto());
  expect(fatal((ser.has_value())));

  verify<timestamp_t>(timestamp_t{.seconds = 1000}, R"("1970-01-01T00:16:40Z")", *ser);
  verify<timestamp_t>(timestamp_t{.seconds = 1000, .nanos = 20}, R"("1970-01-01T00:16:40.000000020Z")", *ser);

  timestamp_t msg;
  ut::expect(hpp::proto::read_json(msg, R"("1970-01-01T00:16:40.2Z")").success());
  ut::expect(msg == timestamp_t{.seconds = 1000, .nanos = 200000000});

  ut::expect(hpp::proto::read_json(msg, R"("1970-01-01T00:16:40.2xZ")").failure());
  ut::expect(hpp::proto::read_json(msg, R"("1970-01-01T00:16:40")").failure());
  ut::expect(hpp::proto::read_json(msg, R"("197-01-01T00:16:40")").failure());
  ut::expect(hpp::proto::read_json(msg, R"("197-01-01T00:16:40.00000000000Z")").failure());

  ut::expect(!hpp::proto::write_json(timestamp_t{.seconds = 1000, .nanos = 1000000000}).has_value());
};

const ut::suite test_duration = [] {
  using duration_t = google::protobuf::Duration;
  auto ser =
      hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_duration_proto());
  expect(fatal((ser.has_value())));

  verify<duration_t>(duration_t{.seconds = 1000}, R"("1000s")", *ser);
  verify<duration_t>(duration_t{.seconds = 1000, .nanos = 20}, R"("1000.000000020s")", *ser);
  verify<duration_t>(duration_t{.seconds = -1000, .nanos = -20}, R"("-1000.000000020s")", *ser);

  duration_t msg;
  ut::expect(hpp::proto::read_json(msg, R"("1000.2s")").success());
  ut::expect(msg == duration_t{.seconds = 1000, .nanos = 200000000});

  ut::expect(hpp::proto::read_json(msg, R"("-1000.2s")").success());
  ut::expect(msg == duration_t{.seconds = -1000, .nanos = -200000000});

  ut::expect(hpp::proto::read_json(msg, R"("1000")").failure());
  ut::expect(hpp::proto::read_json(msg, R"("1000.2xs")").failure());
  ut::expect(hpp::proto::read_json(msg, R"("-1000.-10000000s")").failure());
  ut::expect(hpp::proto::read_json(msg, R"("-1000. 10000000s")").failure());
  ut::expect(hpp::proto::read_json(msg, R"("1000.0000000000000000s")").failure());

  ut::expect(!hpp::proto::write_json(duration_t{.seconds = 1000, .nanos = 1000000000}).has_value());
};

const ut::suite test_field_mask = [] {
  auto ser =
      hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_field_mask_proto());
  expect(fatal((ser.has_value())));

  using namespace google::protobuf;
  verify<FieldMask>(FieldMask{}, R"("")", *ser);
  verify<FieldMask>(FieldMask{.paths = {"abc", "def"}}, R"("abc,def")", *ser);
};

const ut::suite test_wrapper = [] {
  auto ser =
      hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_wrappers_proto());
  expect(fatal((ser.has_value())));

  using namespace google::protobuf;
  verify<Int64Value>(Int64Value{1000}, R"("1000")", *ser);
};

const ut::suite test_empty = [] {
  using namespace google::protobuf;
  auto ser = hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_empty_proto());
  expect(fatal((ser.has_value())));

  verify<Empty>(Empty{}, "{}", *ser);
};

const ut::suite test_null_value = [] {
  using namespace google::protobuf;
  auto ser =
      hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_struct_proto());
  expect(fatal((ser.has_value())));

  verify<NullValue>(NullValue{}, "null", *ser);
};

#if !defined(_MSC_VER) || (_MSC_VER > 1937)

const ut::suite test_value = [] {
  using namespace google::protobuf;
  using namespace boost::ut;
  auto ser =
      hpp::proto::dynamic_serializer::make(hpp::proto::file_descriptors::desc_set_google_protobuf_struct_proto());
  expect(fatal((ser.has_value())));

  verify<Value>(Value{.kind = NullValue{}}, "null", *ser);
  verify<Value>(Value{.kind = true}, "true", *ser);
  verify<Value>(Value{.kind = false}, "false", *ser);
  verify<Value>(Value{.kind = 1.0}, "1", *ser);
  verify<Value>(Value{.kind = "abc"}, R"("abc")", *ser);
  verify<Value>(Value{.kind = ListValue{{Value{.kind = true}, Value{.kind = 1.0}}}}, "[true,1]", *ser);
  verify<Value>(Value{.kind = Struct{.fields = {{"f1", Value{.kind = true}}, {"f2", Value{.kind = 1.0}}}}},
                R"({"f1":true,"f2":1})", *ser);
};

#endif

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}