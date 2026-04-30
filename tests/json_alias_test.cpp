#include "json_alias_preserved_test.glz.hpp"
#include "json_alias_preserved_test.pb.hpp"
#include "json_alias_test.glz.hpp"
#include "json_alias_test.pb.hpp"
#include "json_required_alias_test.glz.hpp"
#include "json_required_alias_test.pb.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/json.hpp>

using namespace boost::ut;
using namespace std::string_literals;

// JSON alias tests use literal payload values to assert spelling and coercion behavior.
// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

const suite json_alias_tests = [] {
  "default_naming_serialization"_test = [] {
    hpp_proto::test::JsonAliasMessage<> msg;
    msg.first_name = "John";
    msg.account_id = 123;
    msg.test_oneof = "OK"s;

    auto json = hpp_proto::write_json(msg).value();
    // Default should be camelCase for all fields
    expect(eq(json, R"({"firstName":"John","accountId":123,"statusCode":"OK"})"s));
  };

  "default_naming_parsing"_test = [] {
    hpp_proto::test::JsonAliasMessage<> msg;

    // Test camelCase input
    expect(hpp_proto::read_json(msg, R"({"firstName":"Alice","accountId":456,"statusVal":1})").ok());
    expect(eq(msg.first_name, "Alice"s));
    expect(eq(msg.account_id, 456));
    expect(eq(std::get<2>(msg.test_oneof), 1)); // status_val is index 2 (1-based in my generator logic)

    // Test snake_case input (aliases)
    expect(hpp_proto::read_json(msg, R"({"first_name":"Bob","account_id":789,"status_code":"FAIL"})").ok());
    expect(eq(msg.first_name, "Bob"s));
    expect(eq(msg.account_id, 789));
    expect(eq(std::get<1>(msg.test_oneof), "FAIL"s));
  };

  "preserved_naming_serialization"_test = [] {
    hpp_proto::test_preserved::JsonAliasPreservedMessage<> msg;
    msg.first_name = "John";
    msg.account_id = 123;
    msg.test_oneof = "OK"s;

    // preserve_proto_field_names=true should use snake_case
    auto json = hpp_proto::write_json(msg).value();
    expect(eq(json, R"({"first_name":"John","account_id":123,"status_code":"OK"})"s));
  };

  "preserved_naming_parsing"_test = [] {
    hpp_proto::test_preserved::JsonAliasPreservedMessage<> msg;

    // Should still accept camelCase (now as aliases)
    expect(hpp_proto::read_json(msg, R"({"firstName":"Alice","accountId":456,"statusVal":1})").ok());
    expect(eq(msg.first_name, "Alice"s));
    expect(eq(msg.account_id, 456));
    expect(eq(std::get<2>(msg.test_oneof), 1));

    // Should accept snake_case (now as primary)
    expect(hpp_proto::read_json(msg, R"({"first_name":"Bob","account_id":789,"status_code":"FAIL"})").ok());
    expect(eq(msg.first_name, "Bob"s));
    expect(eq(msg.account_id, 789));
    expect(eq(std::get<1>(msg.test_oneof), "FAIL"s));
  };

  "required_field_alias"_test = [] {
    hpp_proto::test::required::RequiredAliasMessage<> msg;
    msg.user_id = 1234567890123456789ULL;
    msg.user_role = "admin"s;

    // Serialization: user_id should be quoted because it's uint64
    auto json = hpp_proto::write_json(msg).value();
    expect(eq(json, R"({"userId":"1234567890123456789","userRole":"admin"})"s));

    // Parsing: accept snake_case aliases
    // user_id (uint64) should accept quoted string even in alias
    expect(hpp_proto::read_json(msg, R"({"user_id":"9876543210987654321","user_role":"guest"})").ok());
    expect(eq(msg.user_id, 9876543210987654321ULL));
    expect(eq(msg.user_role, "guest"s));
  };
};

// NOLINTNEXTLINE(bugprone-exception-escape)
int main() { return static_cast<int>(boost::ut::cfg<>.run({.report_errors = true})); }

// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
