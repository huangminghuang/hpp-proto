#include <google/protobuf/duration.glz.hpp>
#include <google/protobuf/field_mask.glz.hpp>
#include <google/protobuf/timestamp.glz.hpp>
#include <google/protobuf/wrappers.glz.hpp>
#include <google/protobuf/empty.glz.hpp>
#include <google/protobuf/struct.glz.hpp>

#include <boost/ut.hpp>
#include <source_location>
namespace ut = boost::ut;

template <typename T>
void verify(const T &msg, std::string_view json,
            const std::source_location &from_loc = std::source_location::current()) {
  using namespace boost::ut;
  std::string from_line_number = "from line " + std::to_string(from_loc.line());
  expect(eq(json, hpp::proto::write_json(msg).value())) << from_line_number;

  T msg2;

  expect((!hpp::proto::read_json(msg2, json)) >> fatal) << from_line_number;
  expect(msg == msg2);
}

const ut::suite test_timestamp = [] {
  using timestamp_t = google::protobuf::Timestamp;

  verify<timestamp_t>(timestamp_t{.seconds = 1000}, R"("1970-01-01T00:16:40Z")");
  verify<timestamp_t>(timestamp_t{.seconds = 1000, .nanos = 20}, R"("1970-01-01T00:16:40.000000020Z")");

  timestamp_t msg;
  ut::expect(!hpp::proto::read_json(msg, R"("1970-01-01T00:16:40.2Z")"));
  ut::expect(msg == timestamp_t{.seconds = 1000, .nanos = 200000000});

  ut::expect(hpp::proto::read_json(msg, R"("1970-01-01T00:16:40.2xZ")"));
  ut::expect(hpp::proto::read_json(msg, R"("1970-01-01T00:16:40")"));
  ut::expect(hpp::proto::read_json(msg, R"("197-01-01T00:16:40")"));
  ut::expect(hpp::proto::read_json(msg, R"("197-01-01T00:16:40.00000000000Z")"));

  ut::expect(!hpp::proto::write_json(timestamp_t{.seconds = 1000, .nanos = 1000000000}).has_value());
};

const ut::suite test_duration = [] {
  using duration_t = google::protobuf::Duration;

  verify<duration_t>(duration_t{.seconds = 1000}, R"("1000s")");
  verify<duration_t>(duration_t{.seconds = 1000, .nanos = 20}, R"("1000.000000020s")");
  verify<duration_t>(duration_t{.seconds = -1000, .nanos = -20}, R"("-1000.000000020s")");

  duration_t msg;
  ut::expect(!hpp::proto::read_json(msg, R"("1000.2s")"));
  ut::expect(msg == duration_t{.seconds = 1000, .nanos = 200000000});

  ut::expect(!hpp::proto::read_json(msg, R"("-1000.2s")"));
  ut::expect(msg == duration_t{.seconds = -1000, .nanos = -200000000});

  ut::expect(hpp::proto::read_json(msg, R"("1000")"));
  ut::expect(hpp::proto::read_json(msg, R"("1000.2xs")"));
  ut::expect(hpp::proto::read_json(msg, R"("-1000.-10000000s")"));
  ut::expect(hpp::proto::read_json(msg, R"("-1000. 10000000s")"));
  ut::expect(hpp::proto::read_json(msg, R"("1000.0000000000000000s")"));

  ut::expect(!hpp::proto::write_json(duration_t{.seconds = 1000, .nanos = 1000000000}).has_value());
};

const ut::suite test_field_mask = [] {
  using namespace google::protobuf;
  verify<FieldMask>(FieldMask{}, R"("")");
  verify<FieldMask>(FieldMask{ .paths = { "abc", "def"} }, R"("abc,def")");
};

const ut::suite test_wrapper = [] {
  using namespace google::protobuf;
  verify<Int64Value>(Int64Value{1000}, R"("1000")");
};

const ut::suite test_empty = [] {
  using namespace google::protobuf;
  verify<Empty>(Empty{}, "{}");
};

const ut::suite test_null_value = [] {
  using namespace google::protobuf;
  verify<NullValue>(NullValue{}, "null");
};

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}