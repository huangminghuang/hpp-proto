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
    expect(eq(hpp::proto::dynamic_message_factory_addons::parse_default_value<float>("1.5"), 1.5F));
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
    expect(41 == msg.field_value_by_name<std::int32_t>("default_int32"));
    expect(42LL == msg.field_value_by_name<std::int64_t>("default_int64"));
    expect(43U == msg.field_value_by_name<std::uint32_t>("default_uint32"));
    expect(44ULL == msg.field_value_by_name<std::uint64_t>("default_uint64"));
    expect(-45 == msg.field_value_by_name<std::int32_t>("default_sint32"));
    expect(46LL == msg.field_value_by_name<std::int64_t>("default_sint64"));
    expect(47U == msg.field_value_by_name<std::uint32_t>("default_fixed32"));
    expect(48ULL == msg.field_value_by_name<std::uint64_t>("default_fixed64"));
    expect(49 == msg.field_value_by_name<std::int32_t>("default_sfixed32"));
    expect(-50LL == msg.field_value_by_name<std::int64_t>("default_sfixed64"));
    expect(51.5F == msg.field_value_by_name<float>("default_float"));
    expect(52e3 == msg.field_value_by_name<double>("default_double"));
    expect(true == msg.field_value_by_name<bool>("default_bool"));
    expect("hello"sv == msg.field_value_by_name<std::string_view>("default_string"));
    expect("world"_bytes == msg.field_value_by_name<hpp::proto::bytes_view>("default_bytes"));
    expect("BAR"sv == msg.field_value_by_name<hpp::proto::enum_name>("default_nested_enum"));
    expect(2 == msg.field_value_by_name<hpp::proto::enum_number>("default_nested_enum"));

    expect("FOREIGN_BAR"sv == msg.field_value_by_name<hpp::proto::enum_name>("default_foreign_enum"));
    expect(5 == msg.field_value_by_name<hpp::proto::enum_number>("default_foreign_enum"));

    expect("IMPORT_BAR"sv == msg.field_value_by_name<hpp::proto::enum_name>("default_import_enum"));
    expect(8 == msg.field_value_by_name<hpp::proto::enum_number>("default_import_enum"));

    expect("abc"sv == msg.field_value_by_name<std::string_view>("default_string_piece"));
    expect("123"sv == msg.field_value_by_name<std::string_view>("default_cord"));
  };

  "oneof_field_access"_test = [&factory]() {
    using namespace std::string_view_literals;
    std::pmr::monotonic_buffer_resource memory_resource;
    auto msg = factory.get_message("protobuf_unittest.TestAllTypes", memory_resource).value();
    auto oneof_uint32_field = msg.typed_ref_by_name<::hpp::proto::uint32_field_mref>("oneof_uint32").value();
    auto oneof_nested_message_field =
        msg.typed_ref_by_name<::hpp::proto::message_field_mref>("oneof_nested_message").value();
    auto oneof_string_field = msg.typed_ref_by_name<::hpp::proto::string_field_mref>("oneof_string").value();
    auto oneof_bytes_field = msg.typed_ref_by_name<::hpp::proto::bytes_field_mref>("oneof_bytes").value();

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

    (void) oneof_nested_message_field.emplace();
    expect(!oneof_uint32_field.has_value());
    expect(oneof_nested_message_field.has_value());
    expect(!oneof_string_field.has_value());
    expect(!oneof_bytes_field.has_value());
  };

  "field_cref_get_and_field_mref_set_adopt"_test = [&factory]() {
    using namespace std::string_view_literals;
    std::pmr::monotonic_buffer_resource memory_resource;
    auto msg = factory.get_message("protobuf_unittest.TestAllTypes", memory_resource).value();

    static_assert(hpp::proto::int32_field_mref::settable_from_v<int32_t>);

    "set on scalar field_mref and read via field_cref::get"_test = [&] {
      auto optional_int32_field = msg.field_by_name("optional_int32").value();
      expect(optional_int32_field.set(123).has_value());
      expect(optional_int32_field.has_value());
      expect(optional_int32_field.get<std::int32_t>().has_value());
      expect(eq(optional_int32_field.get<std::int32_t>().value(), 123));

      expect(123 == msg.field_value_by_name<std::int32_t>("optional_int32"));
    };

    "set on field_mref wrong type"_test = [&] {
      auto optional_int32_field = msg.field_by_name("optional_int32").value();
      optional_int32_field.reset();
      expect(!optional_int32_field.has_value());
      expect(!optional_int32_field.set(3.14));
      expect(!optional_int32_field.has_value());
      expect(!optional_int32_field.set(234U));
      expect(!optional_int32_field.has_value());

      expect(0 == msg.field_value_by_name<std::int32_t>("optional_int32"));
    };

    "string set copies into the message"_test = [&] {
      auto optional_string_field = msg.field_by_name("optional_string").value();
      std::string source = "assigned";
      expect(optional_string_field.set(source).has_value());
      expect(optional_string_field.has_value());
      expect(optional_string_field.get<std::string_view>().has_value());
    };

    "adopt aliases existing storage"_test = [&] {
      auto optional_string_field = msg.field_by_name("optional_string").value();
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

    "bytes set"_test = [&] {
      auto optional_bytes_field = msg.field_by_name("optional_bytes").value();
      auto assigned_bytes = "\x01\x02\x03"_bytes;
      expect(optional_bytes_field.set(std::span<const std::byte>(assigned_bytes)).has_value());
      expect(optional_bytes_field.has_value());
      expect(optional_bytes_field.get<hpp::proto::bytes_view>().has_value());
      expect(optional_bytes_field.get<hpp::proto::bytes_view>().has_value());
      auto optional_bytes_field_value = optional_bytes_field.get<hpp::proto::bytes_view>().value();

      expect(std::ranges::equal(assigned_bytes, optional_bytes_field_value));
      expect(assigned_bytes.data() != optional_bytes_field_value.data());
    };

    "bytes adopt"_test = [&] {
      auto optional_bytes_field = msg.field_by_name("optional_bytes").value();
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

    "repeated scalar set and adopt"_test = [&] {
      auto repeated_int_field = msg.field_by_name("repeated_int32").value();
      std::array<std::int32_t, 3> ints{1, 2, 3};
      expect(repeated_int_field.set(std::span<const std::int32_t>(ints)).has_value());
      auto typed_repeated_int_field = repeated_int_field.to<hpp::proto::repeated_int32_field_mref>().value();
      expect(eq(typed_repeated_int_field.size(), std::size_t{3}));
      expect(eq(typed_repeated_int_field[0], 1));
      // set copies; mutating source should not alter stored values
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

      expect(std::ranges::equal(adopt_ints,
                                msg.field_value_by_name<std::span<const std::int32_t>>("repeated_int32").value()));
    };

    "repeated string set and adopt"_test = [&] {
      auto repeated_string_field = msg.field_by_name("repeated_string").value();
      std::array<std::string_view, 2> strs{"alpha", "beta"};
      expect(repeated_string_field.set(std::span<const std::string_view>(strs)).has_value());
      auto typed_repeated_string_field = repeated_string_field.to<hpp::proto::repeated_string_field_mref>().value();
      expect(eq(typed_repeated_string_field.size(), std::size_t{2}));
      expect(typed_repeated_string_field[1] == std::string_view{"beta"});
      // set copies; mutate source should not affect stored copy
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

    "repeated bytes set and adopt"_test = [&] {
      auto repeated_bytes_field = msg.field_by_name("repeated_bytes").value();
      using byte = std::byte;
      std::array<byte, 2> stored0{byte{0x01}, byte{0x02}};
      std::array<byte, 1> stored1{byte{0x03}};
      std::array<hpp::proto::bytes_view, 2> byte_views{
          hpp::proto::bytes_view{stored0.data(), stored0.size()},
          hpp::proto::bytes_view{stored1.data(), stored1.size()},
      };
      expect(repeated_bytes_field.set(std::span<const hpp::proto::bytes_view>(byte_views)).has_value());
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

    "enum set"_test = [&] {
      auto enum_field = msg.field_by_name("optional_nested_enum").value();
      expect(enum_field.set(hpp::proto::enum_number{1}).has_value());

      expect(enum_field.get<hpp::proto::enum_number>() == 1);
      expect("FOO"sv == enum_field.get<hpp::proto::enum_name>());

      expect(!enum_field.set(hpp::proto::enum_name{"abc"}).has_value());
      expect(enum_field.set(hpp::proto::enum_name{"BAR"}).has_value());
      expect("BAR"sv == enum_field.get<hpp::proto::enum_name>());
    };

    "repeated enum set and adopt"_test = [&] {
      auto rep_enum_field = msg.field_by_name("repeated_nested_enum").value();
      std::array<std::int32_t, 2> enums{1, 2};
      using namespace std::string_view_literals;
      std::array<std::string_view, 2> enum_names{"FOO"sv, "BAR"sv};
      expect(rep_enum_field.set(::hpp::proto::enum_numbers_range(enums)).has_value());
      expect(rep_enum_field.has_value());
      expect(std::ranges::equal(enums, rep_enum_field.get<::hpp::proto::enum_numbers_span>().value()));
      expect(std::ranges::equal(enum_names, rep_enum_field.get<::hpp::proto::enum_names_view>().value()));

      std::array<std::int32_t, 1> adopt_enums{3};
      expect(rep_enum_field.adopt(std::span<std::int32_t>(adopt_enums)).has_value());
      expect(std::ranges::equal(adopt_enums, rep_enum_field.get<::hpp::proto::enum_numbers_span>().value()));

      expect(rep_enum_field.set(::hpp::proto::enum_names_range{enum_names}).has_value());
      expect(std::ranges::equal(enum_names, rep_enum_field.get<::hpp::proto::enum_names_view>().value()));

      std::array<std::string_view, 2> partially_invalid_names{"BAZ"sv, "XXX"sv};
      expect(!rep_enum_field.set(::hpp::proto::enum_names_range{partially_invalid_names}).has_value());
      expect(std::ranges::equal(std::initializer_list<std::string_view>{"BAZ"sv},
                                rep_enum_field.get<::hpp::proto::enum_names_view>().value()));
    };

    "nested message set/get"_test = [&] {
      auto nested_msg_field =
          msg.typed_ref_by_name<::hpp::proto::message_field_mref>("optional_nested_message").value();
      expect(!nested_msg_field.has_value());
      auto nested = nested_msg_field.emplace();
      expect(nested_msg_field.has_value());

      auto bb_field = nested.field_by_name("bb").value();
      expect(bb_field.set(321).has_value());

      expect(nested.field_by_name("bb").value().get<std::int32_t>() == 321);

      auto nested_cref = nested_msg_field.get<hpp::proto::message_value_cref>().value();
      expect(nested_cref.field_by_name("bb").value().get<std::int32_t>() == 321);
    };

    "repeated nested message set/get"_test = [&] {
      auto rep_nested_field =
          msg.typed_ref_by_name<::hpp::proto::repeated_message_field_mref>("repeated_nested_message").value();
      expect(rep_nested_field.size() == 0U);

      rep_nested_field.resize(2);
      auto first = rep_nested_field[0];
      auto second = rep_nested_field[1];

      expect(first.field_by_name("bb").value().set(111).has_value());
      expect(second.field_by_name("bb").value().set(222).has_value());

      expect(std::ranges::equal(
          std::array<int32_t, 2>{111, 222},
          std::array<int32_t, 2>{rep_nested_field[0].field_by_name("bb").value().get<std::int32_t>().value(),
                                 rep_nested_field[1].field_by_name("bb").value().get<std::int32_t>().value()}));

      auto rep_cref = rep_nested_field.cref();
      expect(rep_cref.size() == 2U);
      expect(rep_cref[0].field_by_name("bb").value().get<std::int32_t>() == 111);
      expect(rep_cref[1].field_by_name("bb").value().get<std::int32_t>() == 222);
    };
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
