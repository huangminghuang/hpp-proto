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

#include <hpp_proto/dynamic_message/json.hpp>

#include <optional>
#include <stdexcept>
#include <utility>

#include <boost/ut.hpp>
namespace ut = boost::ut;
using source_location = boost::ut::reflection::source_location;
using namespace ut;
using namespace std::string_view_literals;
using namespace std::string_literals;

template <typename Exp>
decltype(auto) expect_ok(Exp &&exp) {
  expect(fatal(exp.has_value()));
  return std::forward<Exp>(exp).value(); // NOLINT
}

#ifdef __GNUC__
#ifdef __apple_build_version__
#pragma clang diagnostic ignored "-Wmissing-designated-field-initializers"
#else
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
#endif

template <typename T>
void verify(const ::hpp_proto::dynamic_message_factory &factory, const T &msg, std::string_view json,
            std::optional<std::string_view> pretty_json = std::nullopt) {
  expect(eq(json, hpp_proto::write_json(msg).value()));
  if (pretty_json && !pretty_json->empty()) {
    expect(eq(*pretty_json, hpp_proto::write_json<hpp_proto::json_write_opts{.prettify = true}>(msg).value()));
  }
  T msg2{};
  std::pmr::monotonic_buffer_resource mr;

  expect(fatal((hpp_proto::read_json(msg2, json, hpp_proto::alloc_from(mr)).ok())));
  expect(msg == msg2);

  hpp_proto::bytes pb;
  auto ec = hpp_proto::write_binpb(msg, pb);
  expect(ec.ok());

  auto message_name = hpp_proto::message_name(msg);
  hpp_proto::bytes pb_buf1;
  std::string json_buf1;
  expect(hpp_proto::json_to_binpb(factory, message_name, json, pb_buf1).ok());
  expect(std::ranges::equal(pb, pb_buf1));
  expect(hpp_proto::binpb_to_json(factory, message_name, pb_buf1, json_buf1).ok());
  expect(eq(json, json_buf1));

  if (pretty_json && !pretty_json->empty()) {
    hpp_proto::bytes pb_buf2;
    std::string json_buf2;
    expect(hpp_proto::binpb_to_json<hpp_proto::json_write_opts{.prettify = true}>(factory, message_name, pb, json_buf2)
               .ok());
    expect(eq(*pretty_json, json_buf2));
    expect(hpp_proto::json_to_binpb(factory, message_name, *pretty_json, pb_buf2).ok());
    expect(std::ranges::equal(pb, pb_buf2));
  }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void expect_read_json_fail(const ::hpp_proto::dynamic_message_factory &factory, std::string_view message_name,
                           std::string_view json) {
  std::pmr::monotonic_buffer_resource mr;
  auto opt_msg = factory.get_message(message_name, mr);
  expect(fatal(opt_msg.has_value()));
  auto msg = *opt_msg;
  expect(!hpp_proto::read_json(msg, json).ok());
}

// NOLINTBEGIN(clang-diagnostic-missing-designated-field-initializers)
const ut::suite test_timestamp = [] {
  using timestamp_t = google::protobuf::Timestamp<>;

  auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(
      hpp_proto::file_descriptors::desc_set_google_protobuf_timestamp_proto()));

  "verify Timestamp 1970-01-01T00:16:40Z"_test = [&factory] {
    verify<timestamp_t>(factory, timestamp_t{.seconds = 1000}, R"("1970-01-01T00:16:40Z")");
  };

  "verify Timestamp 1970-01-01T00:16:40.100Z"_test = [&factory] {
    verify<timestamp_t>(factory, timestamp_t{.seconds = 1000, .nanos = 100'000'000}, R"("1970-01-01T00:16:40.100Z")");
  };

  "verify Timestamp 1970-01-01T00:16:40.100100Z"_test = [&factory] {
    verify<timestamp_t>(factory, timestamp_t{.seconds = 1000, .nanos = 100'100'000},
                        R"("1970-01-01T00:16:40.100100Z")");
  };

  "verify Timestamp 1970-01-01T00:16:40.000000020Z"_test = [&factory] {
    verify<timestamp_t>(factory, timestamp_t{.seconds = 1000, .nanos = 20}, R"("1970-01-01T00:16:40.000000020Z")");
  };

  "verify Timestamp 1970-01-01T00:16:40.100000020Z"_test = [&factory] {
    verify<timestamp_t>(factory, timestamp_t{.seconds = 1000, .nanos = 100'000'020},
                        R"("1970-01-01T00:16:40.100000020Z")");
  };

  timestamp_t msg;
  ut::expect(hpp_proto::read_json(msg, R"("1970-01-01T00:16:40.2Z")").ok());
  ut::expect(msg == timestamp_t{.seconds = 1000, .nanos = 200000000});

  ut::expect(!hpp_proto::read_json(msg, R"("1970-01-01T00:16:40.2xZ")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("1970-01-01T00:16:40")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("197-01-01T00:16:40")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("197-01-01T00:16:40.00000000000Z")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("1970-13-01T00:00:00Z")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("1970-00-01T00:00:00Z")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("1970-01-32T00:00:00Z")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("1970-01-01T24:00:00Z")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("1970-01-01T00:60:00Z")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("1970-01-01T00:00:60Z")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("1970-01-01T00:33:20.-200Z")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("10000-01-01T00:00:00.00000000000Z")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("0000-01-01T00:00:00.00000000000Z")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("-197-01-01T00:00:00.00000000000Z")").ok());

  ut::expect(!hpp_proto::write_json(timestamp_t{.seconds = 1000, .nanos = 1000000000}).has_value());
  ut::expect(!hpp_proto::write_json(timestamp_t{.seconds = -62135596801, .nanos = 0}).has_value());
  ut::expect(!hpp_proto::write_json(timestamp_t{.seconds = 253402300800, .nanos = 0}).has_value());

  "timestamp_second_overlong"_test = [&factory] {
    std::string json_buf;
    using namespace std::string_view_literals;
    expect(!hpp_proto::binpb_to_json(factory, "google.protobuf.Timestamp",
                                     "\x08\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01\x10\x01"sv, json_buf)
                .ok());
  };

  "timestamp_nano_too_large"_test = [&factory] {
    std::string json_buf;
    std::string pb_data;
    expect(hpp_proto::write_binpb(timestamp_t{.seconds = 1000, .nanos = 1000000000}, pb_data).ok());
    expect(!hpp_proto::binpb_to_json(factory, "google.protobuf.Timestamp", pb_data, json_buf).ok());
  };
};

const ut::suite test_duration = [] {
  using duration_t = google::protobuf::Duration<>;
  auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(
      hpp_proto::file_descriptors::desc_set_google_protobuf_duration_proto()));

  "verify Duration 1000s"_test = [&factory] { verify<duration_t>(factory, duration_t{.seconds = 1000}, R"("1000s")"); };

  "verify Duration -1000s"_test = [&factory] {
    verify<duration_t>(factory, duration_t{.seconds = -1000, .nanos = 0}, R"("-1000s")");
  };

  "verify Duration 1000.100s"_test = [&factory] {
    verify<duration_t>(factory, duration_t{.seconds = 1000, .nanos = 100'000'000}, R"("1000.100s")");
  };

  "verify Duration 1000.100100s"_test = [&factory] {
    verify<duration_t>(factory, duration_t{.seconds = 1000, .nanos = 100'100'000}, R"("1000.100100s")");
  };

  "verify Duration 1000.000000020s"_test = [&factory] {
    verify<duration_t>(factory, duration_t{.seconds = 1000, .nanos = 20}, R"("1000.000000020s")");
  };

  "verify Duration 1000.100000020s"_test = [&factory] {
    verify<duration_t>(factory, duration_t{.seconds = 1000, .nanos = 100'000'020}, R"("1000.100000020s")");
  };

  "verify Duration -1000.000000020s"_test = [&factory] {
    verify<duration_t>(factory, duration_t{.seconds = -1000, .nanos = -20}, R"("-1000.000000020s")");
  };
  "verify Duration -0.0100s"_test = [&factory] {
    verify<duration_t>(factory, duration_t{.seconds = 0, .nanos = -100000000}, R"("-0.100s")");
  };

  duration_t msg;
  ut::expect(hpp_proto::read_json(msg, R"("1000.2s")").ok());
  ut::expect(msg == duration_t{.seconds = 1000, .nanos = 200000000});

  ut::expect(hpp_proto::read_json(msg, R"("-1000.2s")").ok());
  ut::expect(msg == duration_t{.seconds = -1000, .nanos = -200000000});

  ut::expect(!hpp_proto::read_json(msg, R"("1000")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("1000.s")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("1000.2xs")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("abcs")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("-1.s")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"(" 1s")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("1s ")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("-1000.-10000000s")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("-1000. 10000000s")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("1000.0000000000000000s")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("315576000001s")").ok());
  ut::expect(!hpp_proto::read_json(msg, R"("-315576000001s")").ok());

  ut::expect(!hpp_proto::write_json(duration_t{.seconds = 0, .nanos = 1000000000}).has_value());
  ut::expect(!hpp_proto::write_json(duration_t{.seconds = 0, .nanos = -1000000000}).has_value());
  ut::expect(!hpp_proto::write_json(duration_t{.seconds = 315576000001, .nanos = 0}).has_value());
  ut::expect(!hpp_proto::write_json(duration_t{.seconds = -315576000001, .nanos = 0}).has_value());
  ut::expect(!hpp_proto::write_json(duration_t{.seconds = 1, .nanos = -1}).has_value());
  ut::expect(!hpp_proto::write_json(duration_t{.seconds = -1, .nanos = 1}).has_value());
};

const ut::suite test_field_mask = [] {
  auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(
      hpp_proto::file_descriptors::desc_set_google_protobuf_field_mask_proto()));

  using FieldMask = google::protobuf::FieldMask<>;

  "verify FieldMask empty"_test = [&factory] { verify<FieldMask>(factory, FieldMask{}, R"("")"); };

  "verify FieldMask abc def"_test = [&factory] {
    verify<FieldMask>(factory, FieldMask{.paths = {"abc", "def"}}, R"("abc,def")");
    // field mask json format does not escape control code
    verify<FieldMask>(factory, google::protobuf::FieldMask<>{.paths = {"a\x00c"s, "def"s}}, "\"a\x00c,def\"");
    std::array<std::string_view, 2> paths{"a\x00c", "def"};
    verify<google::protobuf::FieldMask<hpp_proto::non_owning_traits>>(
        factory, google::protobuf::FieldMask<hpp_proto::non_owning_traits>{.paths = paths}, "\"a\x00c,def\"");
  };

  "field_mask_empty_clears"_test = [] {
    google::protobuf::FieldMask<> msg;
    msg.paths = {"abc", "def"};
    ut::expect(hpp_proto::read_json(msg, R"("")").ok());
    ut::expect(msg.paths.empty());
  };
};

const ut::suite test_wrapper = [] {
  auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(
      hpp_proto::file_descriptors::desc_set_google_protobuf_wrappers_proto()));
  using Int64Value = google::protobuf::Int64Value<>;

  "verify Int64Value 1000"_test = [&factory] { verify<Int64Value>(factory, Int64Value{1000, {}}, R"("1000")"); };

  "wrapper invalid proto cases"_test = [&factory] {
    std::string json_buf;
    using namespace std::string_view_literals;
    // wrong tag
    expect(!hpp_proto::binpb_to_json(factory, "google.protobuf.Int64Value", "\x00\x01"sv, json_buf).ok());
    // wrong value
    expect(!hpp_proto::binpb_to_json(factory, "google.protobuf.Int64Value",
                                     "\x08\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"sv, json_buf)
                .ok());
    // skip unknown field
    expect(hpp_proto::binpb_to_json(factory, "google.protobuf.Int64Value", "\x10\x01"sv, json_buf).ok());
    expect(json_buf.empty());
  };

  "parse_invalid_int64"_test = [&factory] {
    expect_read_json_fail(factory, "google.protobuf.Int64Value"sv, "\"\n40\""sv);
  };

  "parse_invalid_utf8_string"_test = [] {
    google::protobuf::StringValue<hpp_proto::default_traits> str;
    expect(!read_json(str, "\"\xcd\"").ok());
    google::protobuf::Value<hpp_proto::default_traits> value;
    expect(!read_json(value, "\"\xcd\"").ok());
  };
};

const ut::suite test_empty = [] {
  auto factory = expect_ok(
      hpp_proto::dynamic_message_factory::create(hpp_proto::file_descriptors::desc_set_google_protobuf_empty_proto()));
  using Empty = google::protobuf::Empty<>;

  "verify Empty {}"_test = [&factory] { verify<Empty>(factory, Empty{}, "{}"); };
};

const ut::suite test_value = [] {
  using namespace boost::ut;
  auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(
      hpp_proto::file_descriptors::desc_set_google_protobuf_struct_proto()));

  "value"_test = [&factory]<class Traits>() {
    using string_t = Traits::string_t;
    using Value = google::protobuf::Value<Traits>;
    using NullValue = google::protobuf::NullValue;
    using ListValue = google::protobuf::ListValue<Traits>;
    using Struct = google::protobuf::Struct<Traits>;
    using Struct_value_t = typename decltype(std::declval<Struct>().fields)::value_type;
    "verify Value null"_test = [&factory] { verify<Value>(factory, Value{.kind = NullValue{}}, "null"); };

    "verify Value true"_test = [&factory] { verify<Value>(factory, Value{.kind = true}, "true"); };

    "verify Value false"_test = [&factory] { verify<Value>(factory, Value{.kind = false}, "false"); };

    "verify Value number"_test = [&factory] { verify<Value>(factory, Value{.kind = 1.0}, "1"); };

    "verify Value string"_test = [&factory] { verify<Value>(factory, Value{.kind = string_t{"abc"}}, R"("abc")"); };
    "verify ListValue"_test = [&factory] {
      auto values = std::initializer_list<Value>{Value{.kind = true}, Value{.kind = 1.0}};
      verify<ListValue>(factory, ListValue{.values = values}, "[true,1]", "[\n   true,\n   1\n]");
    };

    "verify Struct empty"_test = [&factory] { verify<Struct>(factory, Struct{}, "{}"); };
    "verify ListValue empty"_test = [&factory] { verify<ListValue>(factory, ListValue{}, "[]"); };

    "verify Value struct"_test = [&factory] {
      Value true_value{.kind = true};
      Value double_value{.kind = 1.0};
      Value string_value{.kind = string_t{"abc"}};
      Value null_value{.kind = NullValue{}};

      auto make_indirect = [](Value &v) {
        if constexpr (std::same_as<Traits, hpp_proto::non_owning_traits>) {
          return hpp_proto::indirect_view<Value>(&v);
        } else {
          return hpp_proto::indirect<Value>(v);
        }
      };

      auto fields = std::initializer_list<Struct_value_t>{{"f1", make_indirect(true_value)},
                                                          {"f2", make_indirect(double_value)},
                                                          {"f3", make_indirect(string_value)},
                                                          {"f4", make_indirect(null_value)}};

      Value struct_value{.kind = Struct{.fields = fields}};

      verify<Value>(factory, struct_value, R"({"f1":true,"f2":1,"f3":"abc","f4":null})",
                    R"({
   "f1": true,
   "f2": 1,
   "f3": "abc",
   "f4": null
})");
    };
  } | std::tuple<hpp_proto::stable_traits, hpp_proto::non_owning_traits>();

  "struct no value field"_test = [&factory]<class Traits>() {
    using namespace std::string_view_literals;
    auto pb_buf = "\x0a\x04\x0a\x00\x12\x00"sv;
    std::pmr::monotonic_buffer_resource mr;
    google::protobuf::Struct<Traits> struct_value;
    expect(hpp_proto::read_binpb(struct_value, pb_buf, hpp_proto::alloc_from(mr)).ok());

    std::string json_buf1;
    expect(hpp_proto::write_json(struct_value, json_buf1).ok());
    expect(eq("{}"sv, json_buf1));

    std::string json_buf2;
    expect(hpp_proto::binpb_to_json(factory, "google.protobuf.Struct", pb_buf, json_buf2).ok());
    expect(eq("{}"sv, json_buf2));
  } | std::tuple<hpp_proto::default_traits, hpp_proto::non_owning_traits>();

  "struct skip_missing_value_then_emit_value"_test = [] {
    using namespace std::string_view_literals;
    auto pb_buf = "\x0a\x05\x0a\x01\x61\x12\x00\x0a\x07\x0a\x01\x62\x12\x02\x20\x01"sv;
    std::pmr::monotonic_buffer_resource mr;
    google::protobuf::Struct<hpp_proto::default_traits> struct_value;
    expect(hpp_proto::read_binpb(struct_value, pb_buf, hpp_proto::alloc_from(mr)).ok());

    std::string json_buf;
    expect(hpp_proto::write_json(struct_value, json_buf).ok());
    expect(eq(R"({"b":true})"sv, json_buf));
  };

  "struct duplicated_value"_test = [&factory]<class Traits>() {
    using namespace std::string_view_literals;
    auto pb_buf = "\x0a\x09\x0a\x01\x65\x12\x02\x32\x00\x12\x00"sv;
    std::pmr::monotonic_buffer_resource mr;
    google::protobuf::Struct<Traits> struct_value;
    expect(hpp_proto::read_binpb(struct_value, pb_buf, hpp_proto::alloc_from(mr)).ok());

    std::string json_buf1;
    expect(hpp_proto::write_json(struct_value, json_buf1).ok());
    expect(eq(R"({"e":[]})"sv, json_buf1));

    std::string json_buf2;
    expect(hpp_proto::binpb_to_json(factory, "google.protobuf.Struct", pb_buf, json_buf2).ok());
    expect(eq(R"({"e":[]})"sv, json_buf2));
  } | std::tuple<hpp_proto::default_traits, hpp_proto::non_owning_traits>();

  "struct prettify separator"_test = [&factory] {
    using Value = google::protobuf::Value<hpp_proto::stable_traits>;
    using Struct = google::protobuf::Struct<hpp_proto::stable_traits>;
    using Struct_value_t = typename decltype(std::declval<Struct>().fields)::value_type;
    auto make_indirect = [](Value &v) { return hpp_proto::indirect<Value>(v); };
    Value a_value{.kind = std::string{"x"}};
    Value b_value{.kind = true};
    auto fields = std::initializer_list<Struct_value_t>{{"a", make_indirect(a_value)}, {"b", make_indirect(b_value)}};
    Struct struct_value{.fields = fields};
    verify<Struct>(factory, struct_value, R"({"a":"x","b":true})", R"({
   "a": "x",
   "b": true
})");
  };

  "struct invalid cases"_test = [&factory] {
    std::string json_buf;
    using namespace std::string_view_literals;
    // field name is not a valid utf8 string
    expect(!hpp_proto::binpb_to_json(factory, "google.protobuf.Struct", "\x0a\x08\x0a\x02\xc0\xcd\x12\x02\x08\x00"sv,
                                     json_buf)
                .ok());
    // skip unknown field
    expect(hpp_proto::binpb_to_json(factory, "google.protobuf.Struct", "\x10\x01"sv, json_buf).ok());
  };

  "list invalid cases"_test = [&factory] {
    std::string json_buf;
    using namespace std::string_view_literals;

    // list element is not a valid utf8 string
    expect(
        !hpp_proto::binpb_to_json(factory, "google.protobuf.ListValue", "\x0a\x04\x1a\x02\xc0\xcd"sv, json_buf).ok());
    // skip first unknown element
    expect(hpp_proto::binpb_to_json(factory, "google.protobuf.ListValue", "\x0a\x02\x38\x01"sv, json_buf).ok());
    expect(eq(json_buf, "[]"s));
    // skip middle unknown element
    expect(hpp_proto::binpb_to_json(factory, "google.protobuf.ListValue",
                                    "\x0a\x02\x20\x01\x0a\x02\x38\x01\x0a\x02\x20\x00"sv, json_buf)
               .ok());
    expect(eq(json_buf, "[true,false]"s));
    // skip unknown field
    expect(hpp_proto::binpb_to_json(factory, "google.protobuf.ListValue", "\x10\x01"sv, json_buf).ok());
  };
  "Struct invalid cases"_test = [] {
    google::protobuf::Struct<> msg;
    expect(!hpp_proto::read_json(msg, R"({"f1":})").ok());
  };
};

// NOLINTEND(clang-diagnostic-missing-designated-field-initializers)

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
