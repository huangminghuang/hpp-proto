#include "test_util.hpp"
#include <array>
#include <boost/ut.hpp>
#include <hpp_proto/dynamic_message.hpp>
#include <hpp_proto/dynamic_message_json.hpp>
#include <limits>
#include <memory_resource>
#include <span>
#include <string>
#include <system_error>
using namespace boost::ut;

const boost::ut::suite parse_default_value_tests = [] {
  "parse_default_value_success"_test = [] {
    expect(eq(hpp::proto::dynamic_message_factory_addons::parse_default_value<int32_t>("123"), 123));
    expect(eq(hpp::proto::dynamic_message_factory_addons::parse_default_value<uint64_t>(
                  std::to_string(std::numeric_limits<uint64_t>::max())),
              std::numeric_limits<uint64_t>::max()));
    expect(eq(hpp::proto::dynamic_message_factory_addons::parse_default_value<float>("1.5"), 1.5f));
    expect(eq(hpp::proto::dynamic_message_factory_addons::parse_default_value<double>("-2.5"), -2.5));
    expect(eq(hpp::proto::dynamic_message_factory_addons::parse_default_value<int32_t>(""),
              0)); // empty defaults to zero-initialized
  };

  "parse_default_value_errors"_test = [] {
    expect(throws<std::invalid_argument>(
        [] { (void)hpp::proto::dynamic_message_factory_addons::parse_default_value<int32_t>("abc"); }));
    expect(throws<std::out_of_range>(
        [] { (void)hpp::proto::dynamic_message_factory_addons::parse_default_value<int32_t>("999999999999"); }));
    expect(throws<std::out_of_range>(
        [] { (void)hpp::proto::dynamic_message_factory_addons::parse_default_value<double>("1e400"); }));
  };
};

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

  "field_cref_get_and_field_mref_set_assign_adopt"_test = [&factory]() {
    using namespace std::string_view_literals;
    std::pmr::monotonic_buffer_resource memory_resource;
    auto msg = factory.get_message("protobuf_unittest.TestAllTypes", memory_resource).value();

    "set on scalar field_mref and read via field_cref::get"_test = [&] {
      auto optional_int32_field = msg.at("optional_int32");
      expect(optional_int32_field.set(123).has_value());
      expect(optional_int32_field.has_value());
      expect(optional_int32_field.get<std::int32_t>().has_value());
      expect(eq(optional_int32_field.get<std::int32_t>().value(), 123));
    };

    "set on field_mref wrong type"_test = [&] {
      auto optional_int32_field = msg.at("optional_int32");
      optional_int32_field.reset();
      expect(!optional_int32_field.has_value());
      expect(!optional_int32_field.set(3.14));
      expect(!optional_int32_field.has_value());
      expect(!optional_int32_field.set(234U));
      expect(!optional_int32_field.has_value());
    };

    "string assign copies into the message"_test = [&] {
      auto optional_string_field = msg["optional_string"];
      std::string source = "assigned";
      expect(optional_string_field.assign(source).has_value());
      expect(optional_string_field.has_value());
      expect(optional_string_field.get<std::string_view>().has_value());
    };

    "adopt aliases existing storage"_test = [&] {
      auto optional_string_field = msg["optional_string"];
      optional_string_field.reset();
      expect(!optional_string_field.has_value());
      std::string_view adopted_string_view = "adopted"sv;
      expect(optional_string_field.adopt(adopted_string_view).has_value());
      expect(optional_string_field.has_value());
      expect(optional_string_field.get<std::string_view>().has_value());
      auto optional_string_field_value = optional_string_field.get<std::string_view>().value();
      expect(eq(optional_string_field_value, std::string_view{"adopted"}));
      expect(optional_string_field_value.data() == adopted_string_view.data());
    };

    "bytes assign"_test = [&] {
      auto optional_bytes_field = msg["optional_bytes"];
      auto assigned_bytes = "\x01\x02\x03"_bytes;
      expect(optional_bytes_field.assign(std::span<const std::byte>(assigned_bytes)).has_value());
      expect(optional_bytes_field.has_value());
      optional_bytes_field.get<hpp::proto::bytes_view>().has_value();
      expect(optional_bytes_field.get<hpp::proto::bytes_view>().has_value());
      auto optional_bytes_field_value = optional_bytes_field.get<hpp::proto::bytes_view>().value();

      expect(std::ranges::equal(assigned_bytes, optional_bytes_field_value));
      expect(assigned_bytes.data() != optional_bytes_field_value.data());
    };

    "bytes adopt"_test = [&] {
      auto optional_bytes_field = msg["optional_bytes"];
      optional_bytes_field.reset();
      expect(!optional_bytes_field.has_value());
      auto adopted_bytes = "\x0A\x0B"_bytes;
      expect(optional_bytes_field.adopt(std::span<const std::byte>(adopted_bytes)).has_value());
      expect(optional_bytes_field.has_value());
      expect(optional_bytes_field.get<hpp::proto::bytes_view>().has_value());

      auto optional_bytes_field_value = optional_bytes_field.get<hpp::proto::bytes_view>().value();
      expect(adopted_bytes.size() == optional_bytes_field_value.size());
      expect(adopted_bytes.data() == optional_bytes_field_value.data());
    };

    "repeated scalar assign and adopt"_test = [&] {
      auto repeated_int_field = msg["repeated_int32"];
      std::array<std::int32_t, 3> ints{1, 2, 3};
      expect(repeated_int_field.assign(std::span<const std::int32_t>(ints)).has_value());
      auto typed_repeated_int_field = repeated_int_field.to<hpp::proto::repeated_int32_field_mref>().value();
      expect(eq(typed_repeated_int_field.size(), std::size_t{3}));
      expect(eq(typed_repeated_int_field[0], 1));
      // assign copies; mutating source should not alter stored values
      ints[0] = 99;
      expect(eq(typed_repeated_int_field[0], 1));
      auto rep_int_cref_span = repeated_int_field.cref().get<std::span<const std::int32_t>>();
      expect(rep_int_cref_span.has_value());
      expect(eq(rep_int_cref_span->size(), std::size_t{3}));

      std::array<std::int32_t, 2> adopt_ints{7, 8};
      expect(repeated_int_field.adopt(std::span<std::int32_t>(adopt_ints)).has_value());
      typed_repeated_int_field = repeated_int_field.to<hpp::proto::repeated_int32_field_mref>().value();
      expect(eq(typed_repeated_int_field.size(), std::size_t{2}));
      expect(typed_repeated_int_field.data() == adopt_ints.data());
      expect(eq(typed_repeated_int_field[1], std::int32_t{8}));
      auto rep_int_cref_span_after_adopt = repeated_int_field.cref().get<std::span<const std::int32_t>>();
      expect(rep_int_cref_span_after_adopt.has_value());
      expect(rep_int_cref_span_after_adopt->data() == adopt_ints.data());
    };

    "repeated string assign and adopt"_test = [&] {
      auto repeated_string_field = msg["repeated_string"];
      std::array<std::string_view, 2> strs{"alpha", "beta"};
      expect(repeated_string_field.assign(std::span<const std::string_view>(strs)).has_value());
      auto typed_repeated_string_field = repeated_string_field.to<hpp::proto::repeated_string_field_mref>().value();
      expect(eq(typed_repeated_string_field.size(), std::size_t{2}));
      expect(typed_repeated_string_field[1] == std::string_view{"beta"});
      // assign copies; mutate source should not affect stored copy
      strs[1] = "changed";
      expect(typed_repeated_string_field[1] == std::string_view{"beta"});
      auto rep_string_cref_span = repeated_string_field.cref().get<std::span<const std::string_view>>();
      expect(rep_string_cref_span.has_value());
      expect(eq(rep_string_cref_span->size(), std::size_t{2}));

      std::array<std::string_view, 1> adopt_strs{"gamma"};
      expect(repeated_string_field.adopt(std::span<std::string_view>(adopt_strs)).has_value());
      typed_repeated_string_field = repeated_string_field.to<hpp::proto::repeated_string_field_mref>().value();
      expect(eq(typed_repeated_string_field.size(), std::size_t{1}));
      expect(typed_repeated_string_field[0] == std::string_view{"gamma"});
      expect(typed_repeated_string_field.data() == adopt_strs.data());
      auto rep_string_cref_span_after_adopt = repeated_string_field.cref().get<std::span<const std::string_view>>();
      expect(rep_string_cref_span_after_adopt.has_value());
      expect(rep_string_cref_span_after_adopt->data() == adopt_strs.data());
    };

    "repeated bytes assign and adopt"_test = [&] {
      auto repeated_bytes_field = msg["repeated_bytes"];
      using byte = std::byte;
      std::array<byte, 2> stored0{byte{0x01}, byte{0x02}};
      std::array<byte, 1> stored1{byte{0x03}};
      std::array<hpp::proto::bytes_view, 2> byte_views{
          hpp::proto::bytes_view{stored0.data(), stored0.size()},
          hpp::proto::bytes_view{stored1.data(), stored1.size()},
      };
      expect(repeated_bytes_field.assign(std::span<const hpp::proto::bytes_view>(byte_views)).has_value());
      auto typed_repeated_bytes_field = repeated_bytes_field.to<hpp::proto::repeated_bytes_field_mref>().value();
      expect(eq(typed_repeated_bytes_field.size(), std::size_t{2}));
      expect(typed_repeated_bytes_field[0] == byte_views[0]);
      auto rep_bytes_cref_span = repeated_bytes_field.cref().get<std::span<const hpp::proto::bytes_view>>();
      expect(rep_bytes_cref_span.has_value());
      expect(eq(rep_bytes_cref_span->size(), std::size_t{2}));

      std::array<byte, 3> adopted_storage{byte{0x0A}, byte{0x0B}, byte{0x0C}};
      std::array<hpp::proto::bytes_view, 1> adopt_views{
          hpp::proto::bytes_view{adopted_storage.data(), adopted_storage.size()}};
      expect(repeated_bytes_field.adopt(std::span<hpp::proto::bytes_view>(adopt_views)).has_value());
      typed_repeated_bytes_field = repeated_bytes_field.to<hpp::proto::repeated_bytes_field_mref>().value();
      expect(eq(typed_repeated_bytes_field.size(), std::size_t{1}));
      expect(typed_repeated_bytes_field[0] == adopt_views[0]);
      expect(typed_repeated_bytes_field.data() == adopt_views.data());
      auto rep_bytes_cref_span_after_adopt = repeated_bytes_field.cref().get<std::span<const hpp::proto::bytes_view>>();
      expect(rep_bytes_cref_span_after_adopt.has_value());
      expect(rep_bytes_cref_span_after_adopt->data() == adopt_views.data());
    };
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
