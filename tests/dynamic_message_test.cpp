#include "test_util.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/dynamic_message_json.hpp>
#include <memory_resource>
using namespace boost::ut;

const boost::ut::suite dynamic_message_test = [] {
  using namespace boost::ut::literals;

  std::pmr::monotonic_buffer_resource descriptor_memory_pool;

  google::protobuf::FileDescriptorSet<hpp::proto::non_owning_traits> fileset;
  if (!hpp::proto::read_proto(fileset, read_file("unittest.desc.binpb"), hpp::proto::alloc_from{descriptor_memory_pool})
           .ok()) {
    throw std::runtime_error("Failed to read descriptor set");
  }

  hpp::proto::dynamic_message_factory factory{std::move(fileset), descriptor_memory_pool};
  expect(fatal(!factory.files().empty()));

  "unit"_test = [&factory](const std::string &message_name) -> void {
    using namespace std::string_literals;
    std::string data = read_file("data/"s + message_name + ".binpb");

    std::pmr::monotonic_buffer_resource memory_resource;
    auto optional_msg = factory.get_message(message_name, memory_resource);
    // if using protoc without edition support, TestAllTypesLite and TestPackedTypesLite
    // would be unavailable.
    if (optional_msg.has_value()) {
      hpp::proto::message_value_mref message = optional_msg.value();
      auto r = hpp::proto::read_proto(message, data);
      expect(fatal(r.ok()));

      std::string new_data;
      r = hpp::proto::write_proto(message.cref(), new_data);
      expect(fatal(r.ok()));
      expect(eq(data, new_data));

      std::string str;
      auto err = glz::write_json(message, str);
      expect(!err);

      auto json = read_file("data/"s + message_name + ".json");
      expect(json == str);

      std::pmr::monotonic_buffer_resource memory_resource2;
      auto optional_msg2 = factory.get_message(message_name, memory_resource2);
      hpp::proto::message_value_mref message2 = optional_msg2.value();

      expect(!glz::read_json(message2, json));
      str.clear();
      err = glz::write_json(message2.cref(), str);
      expect(!err);
      expect(eq(json, str));
    }
  } | std::vector<std::string>{"proto3_unittest.TestAllTypes",       "proto3_unittest.TestUnpackedTypes",
                               "protobuf_unittest.TestAllTypes",     "protobuf_unittest.TestPackedTypes",
                               "protobuf_unittest.TestMap",          "protobuf_unittest.TestUnpackedTypes",
                               "protobuf_unittest.TestAllTypesLite", "protobuf_unittest.TestPackedTypesLite"};

  "default_value"_test = [&factory]() {
    using namespace std::string_view_literals;
    std::pmr::monotonic_buffer_resource memory_resource;
    auto msg = factory.get_message("protobuf_unittest.TestAllTypes", memory_resource).value();
    expect(41 == msg.field_by_name<::hpp::proto::int32_field_mref>("default_int32").transform([](auto mref) {
      return mref.value();
    }));
    expect(42LL == msg.field_by_name<::hpp::proto::int64_field_mref>("default_int64").transform([](auto mref) {
      return mref.value();
    }));
    expect(43U == msg.field_by_name<::hpp::proto::uint32_field_mref>("default_uint32").transform([](auto mref) {
      return mref.value();
    }));
    expect(44ULL == msg.field_by_name<::hpp::proto::uint64_field_mref>("default_uint64").transform([](auto mref) {
      return mref.value();
    }));
    expect(-45 == msg.field_by_name<::hpp::proto::sint32_field_mref>("default_sint32").transform([](auto mref) {
      return mref.value();
    }));
    expect(46LL == msg.field_by_name<::hpp::proto::sint64_field_mref>("default_sint64").transform([](auto mref) {
      return mref.value();
    }));
    expect(47U == msg.field_by_name<::hpp::proto::fixed32_field_mref>("default_fixed32").transform([](auto mref) {
      return mref.value();
    }));
    expect(48ULL == msg.field_by_name<::hpp::proto::fixed64_field_mref>("default_fixed64").transform([](auto mref) {
      return mref.value();
    }));
    expect(49U == msg.field_by_name<::hpp::proto::sfixed32_field_mref>("default_sfixed32").transform([](auto mref) {
      return mref.value();
    }));
    expect(-50LL == msg.field_by_name<::hpp::proto::sfixed64_field_mref>("default_sfixed64").transform([](auto mref) {
      return mref.value();
    }));
    expect(51.5F == msg.field_by_name<::hpp::proto::float_field_mref>("default_float").transform([](auto mref) {
      return mref.value();
    }));
    expect(52e3 == msg.field_by_name<::hpp::proto::double_field_mref>("default_double").transform([](auto mref) {
      return mref.value();
    }));

    expect(msg.field_by_name<::hpp::proto::bool_field_mref>("default_bool")
               .transform([](auto mref) { return mref.value(); })
               .value());

    expect("hello"sv == msg.field_by_name<::hpp::proto::string_field_mref>("default_string").transform([](auto mref) {
      return mref.value();
    }));

    expect("world"_bytes == msg.field_by_name<::hpp::proto::bytes_field_mref>("default_bytes").transform([](auto mref) {
      return mref.value();
    }));

    expect("BAR"sv == msg.field_by_name<::hpp::proto::enum_field_mref>("default_nested_enum").transform([](auto mref) {
      return mref.value().name();
    }));

    expect("FOREIGN_BAR"sv ==
           msg.field_by_name<::hpp::proto::enum_field_mref>("default_foreign_enum").transform([](auto mref) {
             return mref.value().name();
           }));

    expect("IMPORT_BAR"sv ==
           msg.field_by_name<::hpp::proto::enum_field_mref>("default_import_enum").transform([](auto mref) {
             return mref.value().name();
           }));

    expect("abc"sv ==
           msg.field_by_name<::hpp::proto::string_field_mref>("default_string_piece").transform([](auto mref) {
             return mref.value();
           }));

    expect("123"sv == msg.field_by_name<::hpp::proto::string_field_mref>("default_cord").transform([](auto mref) {
      return mref.value();
    }));
  };

  "oneof_field_access"_test = [&factory]() {
    using namespace std::string_view_literals;
    std::pmr::monotonic_buffer_resource memory_resource;
    auto msg = factory.get_message("protobuf_unittest.TestAllTypes", memory_resource).value();
    auto oneof_uint32_field = msg.field_by_name<::hpp::proto::uint32_field_mref>("oneof_uint32").value();
    auto oneof_nested_message_field =
        msg.field_by_name<::hpp::proto::message_field_mref>("oneof_nested_message").value();
    auto oneof_string_field = msg.field_by_name<::hpp::proto::string_field_mref>("oneof_string").value();
    auto oneof_bytes_field = msg.field_by_name<::hpp::proto::bytes_field_mref>("oneof_bytes").value();

    expect(!oneof_uint32_field.has_value());
    expect(!oneof_nested_message_field.has_value());
    expect(!oneof_string_field.has_value());
    expect(!oneof_bytes_field.has_value());

    oneof_uint32_field.set(1);
    expect(oneof_uint32_field.has_value());
    expect(!oneof_nested_message_field.has_value());
    expect(!oneof_string_field.has_value());
    expect(!oneof_bytes_field.has_value());

    oneof_string_field.adopt("abc");
    expect(!oneof_uint32_field.has_value());
    expect(!oneof_nested_message_field.has_value());
    expect(oneof_string_field.has_value());
    expect(!oneof_bytes_field.has_value());

    oneof_bytes_field.adopt("def"_bytes);
    expect(!oneof_uint32_field.has_value());
    expect(!oneof_nested_message_field.has_value());
    expect(!oneof_string_field.has_value());
    expect(oneof_bytes_field.has_value());

    oneof_nested_message_field.emplace();
    expect(!oneof_uint32_field.has_value());
    expect(oneof_nested_message_field.has_value());
    expect(!oneof_string_field.has_value());
    expect(!oneof_bytes_field.has_value());
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}