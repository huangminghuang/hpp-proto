#include <boost/ut.hpp>

#include <google/protobuf/map_unittest.glz.hpp>
#include <google/protobuf/unittest.glz.hpp>
#include <google/protobuf/unittest_proto3.glz.hpp>

#include <hpp_proto/dynamic_message/json.hpp>

#include "test_util.hpp"

using namespace boost::ut;

enum struct test_status : uint8_t { fail = 0, ok = 1 };

template <template <typename Traits> class Message>
void test_read(hpp_proto::dynamic_message_factory &factory, std::string_view input, test_status expected) {
  std::pmr::monotonic_buffer_resource mr; // Needs to be alive during read_binpb

  Message<hpp_proto::default_traits> owning_message;
  Message<hpp_proto::non_owning_traits> non_owning_message;

  auto msg_name = message_name(non_owning_message);
  hpp_proto::message_value_mref dyn_message = factory.get_message(msg_name, mr).value();

  auto expect_status_match = [&](const std::string &kind, auto status) {
    bool s = static_cast<bool>(expected);
    using namespace std::string_literals;
    expect(status.ok() == s) <<
        [&] { return kind + " test case with input `"s + std::string{input} + "` did not "s + (s ? "pass" : "fail"); };
  };

  expect_status_match("owning", hpp_proto::read_json(owning_message, input));
  expect_status_match("non-owning", hpp_proto::read_json(non_owning_message, input, hpp_proto::alloc_from{mr}));
  expect_status_match("dynamic", hpp_proto::read_json(dyn_message, input));
}

const suite test_read_json = [] {
  auto factory = hpp_proto::dynamic_message_factory::create(read_file("unittest.desc.binpb"));
  expect(fatal(factory.has_value()));
  auto &message_factory = *factory;

  using enum test_status;
  using namespace std::string_view_literals;
  test_read<protobuf_unittest::TestAllTypes>(message_factory, "{"sv, fail);
  test_read<protobuf_unittest::TestAllTypes>(message_factory, R"({"optionalInt64":"102"} 1)"sv, fail);
  test_read<protobuf_unittest::TestAllTypes>(message_factory, R"({"optionalInt64":"	102"})"sv, fail);
  test_read<protobuf_unittest::TestAllTypes>(message_factory, R"({"repeatedInt64":["	102"]})"sv, fail);

  test_read<protobuf_unittest::TestAllTypes>(message_factory, R"({"optionalString":null})"sv, ok);
  test_read<protobuf_unittest::TestAllTypes>(message_factory, "{\"optionalString\":\"\xcd\"}"sv, fail);
  test_read<proto3_unittest::TestAllTypes>(message_factory, R"({"optionalString":null})"sv, ok);
  test_read<proto3_unittest::TestAllTypes>(message_factory, R"({"oneofNestedMessage" :  null})"sv, ok);

  test_read<protobuf_unittest::TestAllTypes>(message_factory, R"({"repeatedInt32":[1,2,3]})"sv, ok);
  test_read<protobuf_unittest::TestAllTypes>(message_factory, R"({"repeatedString":["abc,"def"]})"sv, fail);
  test_read<protobuf_unittest::TestAllTypes>(message_factory, "{\"repeatedString\":[\"\xcd\"]}"sv, fail);
  test_read<protobuf_unittest::TestAllTypes>(message_factory, R"({"optionalNestedEnum": )"sv, fail);
  test_read<protobuf_unittest::TestAllTypes>(message_factory, R"({"repeatedNestedEnum":[2, 0]})"sv, ok);

  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapInt32Int32":{"	102":0}})"sv, ok);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapBoolBool":{"false":true,"true":false}})"sv, ok);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapBoolBool":{" false":true}})"sv, fail);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapInt32Int32":{   )"sv, fail);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapInt32Int32":{}})"sv, ok);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapInt32Int32":{"1":1,)"sv, fail);
  test_read<protobuf_unittest::TestMap>(message_factory, "{\"mapInt32Int32\":{\"1\":1,", fail);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapInt32Int32":{   "1":1,   "2":2}})"sv, ok);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapInt32Int32":{"1":1 "2":2}})"sv, fail);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapInt32Int32":{"1":1,   )"sv, fail);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapInt32Int32":{"1":1   )"sv, fail);
  test_read<protobuf_unittest::TestMap>(message_factory, "{\"mapInt32Enum\":{\"1\":   ", fail);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({mapSint64Sint64":{"1":" -10"}})"sv, fail);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapStringString":{"1":"0", "1":"1"}})"sv, ok);
  test_read<protobuf_unittest::TestMap>(message_factory, "{\"mapStringString\":{\"\xcd\":\"0\"}"sv, fail);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapInt32ForeignMessage":{"0":null}})", fail);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapInt32Enum":{"0":0}})"sv, ok);
  test_read<protobuf_unittest::TestMap>(message_factory, R"({"mapInt64Int64":{"0":" -64"}})"sv, fail);
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
