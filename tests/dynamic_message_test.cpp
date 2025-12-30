#include "test_util.hpp"
#include <algorithm>
#include <array>
#include <boost/ut.hpp>
#include <hpp_proto/dynamic_message/binpb.hpp>
#include <hpp_proto/dynamic_message/json.hpp>
#include <limits>
#include <memory_resource>
#include <span>
#include <string>
#include <system_error>
#include <utility>
using namespace boost::ut;

template <typename Exp>
decltype(auto) expect_ok(Exp &&exp) {
  expect(fatal(exp.has_value()));
  return std::forward<Exp>(exp).value(); // NOLINT
}

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

  hpp::proto::dynamic_message_factory factory;
  expect(factory.init(read_file("unittest.desc.binpb")));

  "unit"_test = [&factory](const std::string &message_name) -> void {
    using namespace std::string_literals;
    std::string data = read_file("data/"s + message_name + ".binpb");

    std::pmr::monotonic_buffer_resource memory_resource;
    auto optional_msg = factory.get_message(message_name, memory_resource);
    // if using protoc without edition support, TestAllTypesLite and TestPackedTypesLite
    // would be unavailable.
    if (optional_msg.has_value()) {
      hpp::proto::message_value_mref message = expect_ok(optional_msg);
      auto r = hpp::proto::read_binpb(message, data);
      expect(fatal(r.ok()));

      std::string new_data;
      r = hpp::proto::write_binpb(message.cref(), new_data);
      expect(fatal(r.ok()));
      expect(eq(data, new_data));

      std::string str;
      auto err = glz::write_json(message, str);
      expect(!err);

      auto json = read_file("data/"s + message_name + ".json");
      expect(json == str);

      std::pmr::monotonic_buffer_resource memory_resource2;
      auto optional_msg2 = factory.get_message(message_name, memory_resource2);
      hpp::proto::message_value_mref message2 = expect_ok(optional_msg2);

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

  "basic_serialization"_test = [&factory] {
    using namespace std::string_view_literals;
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    auto expect_roundtrip_ok = [&](std::string_view msg_name, std::string_view data, auto verify) {
      std::pmr::monotonic_buffer_resource mr1;
      auto msg1 = expect_ok(factory.get_message(msg_name, mr1));
      expect(::hpp::proto::read_binpb(msg1, data).ok());
      verify(msg1);

      std::string out;
      expect(::hpp::proto::write_binpb(msg1.cref(), out).ok());

      std::pmr::monotonic_buffer_resource mr2;
      auto msg2 = expect_ok(factory.get_message(msg_name, mr2));
      expect(::hpp::proto::read_binpb(msg2, out).ok());
      verify(msg2);
    };

    auto expect_invalid = [&](std::string_view msg_name, std::string_view data) {
      std::pmr::monotonic_buffer_resource mr;
      auto msg = expect_ok(factory.get_message(msg_name, mr));
      expect(!::hpp::proto::read_binpb(msg, data).ok());
    };

    auto expect_read_ok = [&](std::string_view msg_name, std::string_view data, auto verify) {
      std::pmr::monotonic_buffer_resource mr1;
      auto msg1 = expect_ok(factory.get_message(msg_name, mr1));
      expect(::hpp::proto::read_binpb(msg1, data).ok());
      verify(msg1);
    };

    auto expect_write_empty = [&](std::string_view msg_name, std::string_view data) {
      std::pmr::monotonic_buffer_resource mr1;
      auto msg1 = expect_ok(factory.get_message(msg_name, mr1));
      expect(::hpp::proto::read_binpb(msg1, data).ok());

      std::string out;
      expect(::hpp::proto::write_binpb(msg1.cref(), out).ok());
      expect(out.empty());
    };

    "optional_int32"_test = [&] {
      expect_roundtrip_ok("protobuf_unittest.TestAllTypes", "\x08\x01"sv,
                          [](const ::hpp::proto::message_value_mref &m) {
                            expect(1 == m.field_value_by_name<int32_t>("optional_int32"));
                          });
      expect_invalid("protobuf_unittest.TestAllTypes", "\x09\x01"sv);
      // implicit defaulted value should not be serialized
      expect_write_empty("proto3_unittest.TestAllTypes", "\x08\x00"sv);
    };

    "optional_fixed32"_test = [&] {
      expect_roundtrip_ok("protobuf_unittest.TestAllTypes", "\x3d\x01\x00\x00\x00"sv,
                          [](const ::hpp::proto::message_value_mref &m) {
                            expect(1U == m.field_value_by_name<std::uint32_t>("optional_fixed32"));
                          });
      expect_invalid("protobuf_unittest.TestAllTypes", "\x3e\x01\x00\x00\x00"sv);

      // implicit defaulted value should not be serialized
      expect_write_empty("proto3_unittest.TestAllTypes", "\x3d\x00\x00\x00\x00"sv);
    };

    "optional_string"_test = [&] {
      expect_roundtrip_ok("protobuf_unittest.TestAllTypes", "\x72\x01\x65"sv,
                          [](const ::hpp::proto::message_value_mref &m) {
                            expect("e"sv == m.field_value_by_name<std::string_view>("optional_string"));
                          });
      expect_invalid("protobuf_unittest.TestAllTypes", "\x70\x01\x65"sv);

      // implicit defaulted value should not be serialized
      expect_write_empty("proto3_unittest.TestAllTypes", "\x72\x00"sv);

      // override
      expect_read_ok("protobuf_unittest.TestAllTypes", "\x72\x01\x65\x72\x01\x66"sv,
                     [](const ::hpp::proto::message_value_mref &m) {
                       expect("f"sv == m.field_value_by_name<std::string_view>("optional_string"));
                     });
    };

    "optional_bytes"_test = [&] {
      expect_roundtrip_ok("protobuf_unittest.TestAllTypes", "\x7a\x01\x65"sv,
                          [](const ::hpp::proto::message_value_mref &m) {
                            expect("e"_bytes == m.field_value_by_name<hpp::proto::bytes_view>("optional_bytes"));
                          });
      expect_invalid("protobuf_unittest.TestAllTypes", "\x7b\x01\x65"sv);
      // implicit defaulted value should not be serialized
      expect_write_empty("proto3_unittest.TestAllTypes", "\x7a\x00"sv);

      // override test
      expect_read_ok("protobuf_unittest.TestAllTypes", "\x7a\x01\x65\x7a\x01\x66"sv,
                     [](const ::hpp::proto::message_value_mref &m) {
                       expect("f"_bytes == m.field_value_by_name<hpp::proto::bytes_view>("optional_bytes"));
                     });
    };

    "optional_nested_enum"_test = [&] {
      expect_roundtrip_ok("protobuf_unittest.TestAllTypes", "\xa8\x01\x01"sv,
                          [](const ::hpp::proto::message_value_mref &m) {
                            expect(1 == m.field_value_by_name<hpp::proto::enum_number>("optional_nested_enum"));
                          });
      expect_roundtrip_ok("protobuf_unittest.TestAllTypes", "\xa8\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"sv,
                          [](const ::hpp::proto::message_value_mref &m) {
                            expect(-1 == m.field_value_by_name<hpp::proto::enum_number>("optional_nested_enum"));
                          });
      expect_invalid("protobuf_unittest.TestAllTypes", "\xa9\x01\x01"sv);

      // implicit defaulted value should not be serialized
      expect_write_empty("proto3_unittest.TestAllTypes", "\xa8\x01\x00"sv);
    };

    "optional_nested_message"_test = [&] {
      expect_roundtrip_ok(
          "protobuf_unittest.TestAllTypes", "\x92\x01\x02\x08\x01"sv, [](const ::hpp::proto::message_value_mref &m) {
            auto nested = expect_ok(m.typed_ref_by_name<hpp::proto::message_field_mref>("optional_nested_message"));
            expect(nested.has_value());
            expect(1 == nested->field_value_by_name<std::int32_t>("bb"));
          });
      expect_invalid("protobuf_unittest.TestAllTypes", "\x91\x01\x02\x08\x01"sv);
    };

    "OptionalGroup"_test = [&] {
      expect_roundtrip_ok("protobuf_unittest.TestAllTypes", "\x83\x01\x88\x01\x01\x84\x01"sv,
                          [](const ::hpp::proto::message_value_mref &m) {
                            auto group_field =
                                expect_ok(m.typed_ref_by_name<hpp::proto::message_field_mref>("optionalgroup"));
                            expect(group_field.has_value());
                            expect(1 == group_field->field_value_by_name<std::int32_t>("a"));
                          });
      expect_invalid("protobuf_unittest.TestAllTypes", "\x84\x01\x88\x01\x01\x84\x01"sv);
      expect_invalid("protobuf_unittest.TestAllTypes", "\x83\x01\x88\x01\x01\x83\x01"sv);
    };

    "repeated_int32"_test = [&] {
      expect_roundtrip_ok(
          "protobuf_unittest.TestAllTypes", "\xf8\x01\x01"sv, [](const ::hpp::proto::message_value_mref &m) {
            auto vals = expect_ok(m.field_value_by_name<std::span<const std::int32_t>>("repeated_int32"));
            expect(eq(vals.size(), 1));
            expect(eq(vals[0], 1));
          });
      expect_invalid("protobuf_unittest.TestAllTypes", "\xf9\x01\x01"sv);

      "read_packed_repeated_int32"_test = [&] {
        expect_read_ok("protobuf_unittest.TestAllTypes", "\xfa\x01\x01\x01"sv,
                       [](const ::hpp::proto::message_value_mref &m) {
                         auto vals = expect_ok(m.field_value_by_name<std::span<const std::int32_t>>("repeated_int32"));
                         expect(eq(vals.size(), 1));
                         expect(eq(vals[0], 1));
                       });
      };

      // append test
      "append_unpacked"_test = [&] {
        expect_read_ok("protobuf_unittest.TestAllTypes", "\xf8\x01\x01\xf8\x01\x02"sv,
                       [](const ::hpp::proto::message_value_mref &m) {
                         auto vals = expect_ok(m.field_value_by_name<std::span<const std::int32_t>>("repeated_int32"));
                         expect(std::ranges::equal(vals, std::array<int32_t, 2>{1, 2}));
                       });
      };

      "append_packed"_test = [&] {
        expect_read_ok("protobuf_unittest.TestAllTypes", "\xfa\x01\x01\x01\xfa\x01\x01\x02"sv,
                       [](const ::hpp::proto::message_value_mref &m) {
                         auto vals = expect_ok(m.field_value_by_name<std::span<const std::int32_t>>("repeated_int32"));
                         expect(std::ranges::equal(vals, std::array<int32_t, 2>{1, 2}));
                       });
      };
    };

    "repeated_int64"_test = [&] {
      expect_roundtrip_ok(
          "protobuf_unittest.TestAllTypes", "\x80\x02\x01"sv, [](const ::hpp::proto::message_value_mref &m) {
            auto vals = expect_ok(m.field_value_by_name<std::span<const std::int64_t>>("repeated_int64"));
            expect(eq(vals.size(), 1));
            expect(eq(vals[0], 1));
          });
      expect_invalid("protobuf_unittest.TestAllTypes", "\x81\x02\x01"sv);

      // append test
      "append_unpacked"_test = [&] {
        expect_read_ok("protobuf_unittest.TestAllTypes", "\x80\x02\x01\x80\x02\x02"sv,
                       [](const ::hpp::proto::message_value_mref &m) {
                         auto vals = expect_ok(m.field_value_by_name<std::span<const std::int64_t>>("repeated_int64"));
                         expect(std::ranges::equal(vals, std::array<int64_t, 2>{1, 2}));
                       });
      };
    };

    "repeated_string"_test = [&] {
      expect_roundtrip_ok(
          "protobuf_unittest.TestAllTypes", "\xe2\x02\x01\x65"sv, [](const ::hpp::proto::message_value_mref &m) {
            auto vals = expect_ok(m.field_value_by_name<std::span<const std::string_view>>("repeated_string"));
            expect(std::ranges::equal(vals, std::array<std::string_view, 1>{"e"sv}));
          });
      expect_invalid("protobuf_unittest.TestAllTypes", "\xe1\x02\x01\x65"sv);
      "append"_test = [&] {
        expect_read_ok("protobuf_unittest.TestAllTypes", "\xe2\x02\x01\x65\xe2\x02\x01\x66"sv,
                       [](const ::hpp::proto::message_value_mref &m) {
                         auto vals =
                             expect_ok(m.field_value_by_name<std::span<const std::string_view>>("repeated_string"));
                         expect(std::ranges::equal(vals, std::array<std::string_view, 2>{"e"sv, "f"sv}));
                       });
      };
    };

    "repeated_bytes"_test = [&] {
      expect_roundtrip_ok(
          "protobuf_unittest.TestAllTypes", "\xea\x02\x01\x65"sv, [](const ::hpp::proto::message_value_mref &m) {
            auto vals = expect_ok(m.field_value_by_name<std::span<const hpp::proto::bytes_view>>("repeated_bytes"));
            expect(std::ranges::equal(vals, std::array<hpp::proto::bytes_view, 1>{"e"_bytes}));
          });
      expect_invalid("protobuf_unittest.TestAllTypes", "\xeb\x02\x01\x65"sv);
      "append"_test = [&] {
        expect_read_ok("protobuf_unittest.TestAllTypes", "\xea\x02\x01\x65\xea\x02\x01\x66"sv,
                       [](const ::hpp::proto::message_value_mref &m) {
                         auto vals = expect_ok(
                             m.field_value_by_name<std::span<const hpp::proto::bytes_view>>("repeated_bytes"));
                         expect(std::ranges::equal(vals, std::array<hpp::proto::bytes_view, 2>{"e"_bytes, "f"_bytes}));
                       });
      };
    };

    "repeated_nested_enum"_test = [&] {
      expect_roundtrip_ok(
          "protobuf_unittest.TestAllTypes", "\x98\x03\x01\x98\x03\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"sv,
          [](const ::hpp::proto::message_value_mref &m) {
            auto vals = expect_ok(m.field_value_by_name<hpp::proto::enum_numbers_span>("repeated_nested_enum"));
            expect(std::ranges::equal(vals, std::array<std::int32_t, 2>{1, -1}));
          });
      "skip_unknown_value"_test = [&] {
        expect_read_ok(
            "protobuf_unittest.TestAllTypes", "\x98\x03\x05"sv, [](const ::hpp::proto::message_value_mref &m) {
              auto vals = expect_ok(m.field_value_by_name<hpp::proto::enum_numbers_span>("repeated_nested_enum"));
              expect(vals.empty());
            });
      };

      "append_packed_known_values"_test = [&] {
        expect_read_ok("protobuf_unittest.TestAllTypes", "\x98\x03\x01\x9a\x03\x01\x02"sv,
                       [](const ::hpp::proto::message_value_mref &m) {
                         auto vals =
                             expect_ok(m.field_value_by_name<hpp::proto::enum_numbers_span>("repeated_nested_enum"));
                         expect(std::ranges::equal(vals, std::array<std::int32_t, 2>{1, 2}));
                       });
      };

      "append_some_packed_unknown_values"_test = [&] {
        expect_read_ok("protobuf_unittest.TestAllTypes", "\x98\x03\x01\x9a\x03\x02\x02\x09"sv,
                       [](const ::hpp::proto::message_value_mref &m) {
                         auto vals =
                             expect_ok(m.field_value_by_name<hpp::proto::enum_numbers_span>("repeated_nested_enum"));
                         expect(std::ranges::equal(vals, std::array<std::int32_t, 2>{1, 2}));
                       });
      };
    };
    "packed_int32"_test = [&] {
      expect_roundtrip_ok("protobuf_unittest.TestPackedTypes", "\xd2\x05\x02\x01\x02"sv,
                          [&](const ::hpp::proto::message_value_mref &m) {
                            auto vals = expect_ok(m.field_value_by_name<std::span<const int32_t>>("packed_int32"));
                            expect(std::ranges::equal(vals, std::array<std::int32_t, 2>{1, 2}));
                          });

      std::pmr::monotonic_buffer_resource mr1;
      auto msg1 = expect_ok(factory.get_message("protobuf_unittest.TestPackedTypes", mr1));

      "unpacked read"_test = [&] {
        expect(::hpp::proto::read_binpb(msg1, "\xd0\x05\x01\xd0\x05\x02").ok());
        auto vals = expect_ok(msg1.field_value_by_name<std::span<const int32_t>>("packed_int32"));
        expect(std::ranges::equal(vals, std::array<std::int32_t, 2>{1, 2}));
      };

      "packed_int32 invalid tag type"_test = [&] {
        expect(!::hpp::proto::read_binpb(msg1, "\xd1\x05\x02\x01\x02"sv).ok());
      };
    };
    "packed_enum"_test = [&] {
      expect_roundtrip_ok("protobuf_unittest.TestPackedTypes", "\xba\x06\x02\x04\x05"sv,
                          [&](const ::hpp::proto::message_value_mref &m) {
                            auto vals = expect_ok(m.field_value_by_name<hpp::proto::enum_numbers_span>("packed_enum"));
                            expect(std::ranges::equal(vals, std::array<std::int32_t, 2>{4, 5}));
                          });
    };

    "map"_test = [&] {
      expect_roundtrip_ok("protobuf_unittest.TestMap", "\x0a\x04\x08\x01\x10\x02"sv,
                          [&](const ::hpp::proto::message_value_mref &m) {
                            hpp::proto::repeated_message_field_mref map_int32_int32 =
                                m.typed_ref_by_name<hpp::proto::repeated_message_field_mref>("map_int32_int32").value();
                            expect(eq(1, map_int32_int32.size()));
                            hpp::proto::message_value_mref entry = map_int32_int32[0];
                            expect(eq(1, entry.field_value_by_number<std::int32_t>(1).value()));
                            expect(eq(2, entry.field_value_by_number<std::int32_t>(2).value()));
                          });

      // missing mapped
      expect_read_ok("protobuf_unittest.TestMap", "\x0a\x02\x08\x01"sv, [&](const ::hpp::proto::message_value_mref &m) {
        hpp::proto::repeated_message_field_mref map_int32_int32 =
            m.typed_ref_by_name<hpp::proto::repeated_message_field_mref>("map_int32_int32").value();
        expect(eq(1, map_int32_int32.size()));
        hpp::proto::message_value_mref entry = map_int32_int32[0];
        expect(eq(1, entry.field_value_by_number<std::int32_t>(1).value()));
        expect(eq(0, entry.field_value_by_number<std::int32_t>(2).value()));
      });
      // missing key
      expect_invalid("protobuf_unittest.TestMap", "\x0a\x02\x10\x01"sv);
      // missing key and mapped
      expect_invalid("protobuf_unittest.TestMap", "\x0a\x00"sv);
    };
  };

  "default_value"_test = [&factory]() {
    using namespace std::string_view_literals;
    std::pmr::monotonic_buffer_resource memory_resource;
    auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
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

  "expected lookup pattern"_test = [&factory]() {
    std::pmr::monotonic_buffer_resource memory_resource;
    auto maybe_msg = factory.get_message("protobuf_unittest.TestAllTypes", memory_resource);
    expect(maybe_msg.has_value());
    auto msg = *maybe_msg;

    if (auto field = msg.field_by_name("optional_int32")) {
      expect(field->set(123).has_value());
      auto val = field->get<std::int32_t>();
      expect(val.has_value());
      expect(123 == val);
    } else {
      expect(false) << "optional_int32 missing";
    }

    auto missing = msg.field_by_name("no_such_field");
    expect(!missing.has_value());
  };

  "repeated regrow keeps values"_test = [&factory]() {
    std::pmr::monotonic_buffer_resource memory_resource;
    auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));

    // scalars
    if (auto rep = msg.typed_ref_by_name<hpp::proto::repeated_int32_field_mref>("repeated_int32")) {
      auto &mref = *rep;
      mref.push_back(7);
      mref.push_back(8);
      expect(eq(mref.size(), std::size_t{2}));
      expect(eq(mref[0], 7));
      expect(eq(mref[1], 8));
    } else {
      expect(false) << "repeated_int32 missing";
    }
    // strings
    auto str_mref = expect_ok(msg.typed_ref_by_name<hpp::proto::repeated_string_field_mref>("repeated_string"));
    str_mref.clear();
    using namespace std::string_view_literals;
    str_mref.push_back("foo"sv);
    str_mref.push_back("bar"sv);
    auto old_str_cap = str_mref.capacity();
    str_mref.reserve(old_str_cap + 4);
    expect(eq(str_mref.size(), std::size_t{2}));
    expect(eq(static_cast<std::string_view>(str_mref[0]), "foo"sv));
    expect(eq(static_cast<std::string_view>(str_mref[1]), "bar"sv));

    // bytes
    auto bytes_mref = expect_ok(msg.typed_ref_by_name<hpp::proto::repeated_bytes_field_mref>("repeated_bytes"));
    bytes_mref.clear();
    std::array<std::byte, 2> b1{std::byte{0x01}, std::byte{0x02}};
    std::array<std::byte, 3> b2{std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
    bytes_mref.push_back(b1);
    bytes_mref.push_back(b2);
    auto old_bytes_cap = bytes_mref.capacity();
    bytes_mref.reserve(old_bytes_cap + 3);
    expect(eq(bytes_mref.size(), std::size_t{2}));
    expect(std::ranges::equal(b1, static_cast<hpp::proto::bytes_view>(bytes_mref[0])));
    expect(std::ranges::equal(b2, static_cast<hpp::proto::bytes_view>(bytes_mref[1])));

    // enums
    auto enum_mref = expect_ok(msg.typed_ref_by_name<hpp::proto::repeated_enum_field_mref>("repeated_nested_enum"));
    enum_mref.clear();
    enum_mref.push_back(hpp::proto::enum_number{1});
    enum_mref.push_back(hpp::proto::enum_number{2});
    auto old_enum_cap = enum_mref.capacity();
    enum_mref.reserve(old_enum_cap + 3);
    expect(eq(enum_mref.size(), std::size_t{2}));
    auto nums = expect_ok(enum_mref.cref().get<hpp::proto::enum_numbers_span>());
    expect(std::ranges::equal(nums, std::array<int32_t, 2>{1, 2}));

    // messages
    auto msg_mref =
        expect_ok(msg.typed_ref_by_name<hpp::proto::repeated_message_field_mref>("repeated_nested_message"));
    msg_mref.clear();
    msg_mref.resize(2);
    expect(msg_mref[0].set_field_by_name("bb", 5).has_value());
    expect(msg_mref[1].set_field_by_name("bb", 6).has_value());
    auto old_msg_cap = msg_mref.capacity();
    msg_mref.reserve(old_msg_cap + 3);
    expect(eq(msg_mref.size(), std::size_t{2}));
    expect(5 == msg_mref[0].field_value_by_name<std::int32_t>("bb"));
    expect(6 == msg_mref[1].field_value_by_name<std::int32_t>("bb"));
  };

  "oneof_field_access"_test = [&factory]() {
    using namespace std::string_view_literals;
    std::pmr::monotonic_buffer_resource memory_resource;
    auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
    auto oneof_uint32_field = expect_ok(msg.typed_ref_by_name<::hpp::proto::uint32_field_mref>("oneof_uint32"));
    auto oneof_nested_message_field =
        expect_ok(msg.typed_ref_by_name<::hpp::proto::message_field_mref>("oneof_nested_message"));
    auto oneof_string_field = expect_ok(msg.typed_ref_by_name<::hpp::proto::string_field_mref>("oneof_string"));
    auto oneof_bytes_field = expect_ok(msg.typed_ref_by_name<::hpp::proto::bytes_field_mref>("oneof_bytes"));

    expect(!oneof_uint32_field.has_value());
    expect(!oneof_nested_message_field.has_value());
    expect(!oneof_string_field.has_value());
    expect(!oneof_bytes_field.has_value());

    oneof_uint32_field.set(1);
    expect(oneof_uint32_field.has_value());
    expect(1 == oneof_uint32_field.value());
    expect(!oneof_nested_message_field.has_value());
    expect(!oneof_string_field.has_value());
    expect(!oneof_bytes_field.has_value());

    oneof_string_field.adopt("abc");
    expect(!oneof_uint32_field.has_value());
    expect(!oneof_nested_message_field.has_value());
    expect(oneof_string_field.has_value());
    expect("abc"sv == oneof_string_field.value());
    expect(!oneof_bytes_field.has_value());

    oneof_bytes_field.adopt("def"_bytes);
    expect(!oneof_uint32_field.has_value());
    expect(!oneof_nested_message_field.has_value());
    expect(!oneof_string_field.has_value());
    expect(oneof_bytes_field.has_value());
    expect("def"_bytes == oneof_bytes_field.value());

    auto nested = oneof_nested_message_field.emplace();
    expect(nested.set_field_by_name("bb", 1).has_value());
    expect(!oneof_uint32_field.has_value());
    expect(oneof_nested_message_field.has_value());
    expect(1 == oneof_nested_message_field->field_value_by_name<std::int32_t>("bb"sv));
    expect(!oneof_string_field.has_value());
    expect(!oneof_bytes_field.has_value());
  };

  "descriptor_lookup_helpers"_test = [&factory]() {
    std::pmr::monotonic_buffer_resource memory_resource;
    auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
    const auto &cref = msg.cref();

    const auto *json_desc = msg.field_descriptor_by_json_name("optionalInt32");
    expect(json_desc != nullptr);
    expect(eq(json_desc->proto().name, std::string_view{"optional_int32"}));
    expect(cref.field_descriptor_by_json_name("optionalInt32") == json_desc);
    expect(cref.field_descriptor_by_name("optional_int32") == json_desc);
    expect(cref.field_descriptor_by_json_name("missingField") == nullptr);
    expect(cref.field_descriptor_by_name("missing_field") == nullptr);

    const auto field_number = static_cast<std::uint32_t>(json_desc->proto().number);
    expect(msg.field_descriptor_by_number(field_number) == json_desc);
    expect(cref.field_descriptor_by_number(field_number) == json_desc);
    expect(msg.field_descriptor_by_number(999999) == nullptr);

    const auto *oneof_desc = cref.oneof_descriptor("oneof_field");
    expect(oneof_desc != nullptr);
    expect(eq(oneof_desc->proto().name, std::string_view{"oneof_field"}));
    expect(cref.oneof_descriptor("missing_oneof") == nullptr);
  };

  "field_cref_get_and_field_mref_set_adopt"_test = [&factory]() {
    using namespace std::string_view_literals;

    static_assert(hpp::proto::int32_field_mref::settable_from_v<int32_t>);

    "set on scalar field_mref and read via field_cref::get"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto optional_int32_field = expect_ok(msg.field_by_name("optional_int32"));
      expect(optional_int32_field.set(123).has_value());
      expect(optional_int32_field.has_value());
      expect(optional_int32_field.get<std::int32_t>().has_value());
      expect(eq(expect_ok(optional_int32_field.get<std::int32_t>()), 123));

      expect(123 == msg.field_value_by_name<std::int32_t>("optional_int32"));
    };

    "set on field_mref wrong type"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto optional_int32_field = expect_ok(msg.field_by_name("optional_int32"));
      optional_int32_field.reset();
      expect(!optional_int32_field.has_value());
      expect(!optional_int32_field.set(3.14));
      expect(!optional_int32_field.has_value());
      expect(!optional_int32_field.set(234U));
      expect(!optional_int32_field.has_value());

      expect(0 == msg.field_value_by_name<std::int32_t>("optional_int32"));
    };

    "string set copies into the message"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto optional_string_field = expect_ok(msg.field_by_name("optional_string"));
      std::string source = "assigned";
      expect(optional_string_field.set(source).has_value());
      expect(optional_string_field.has_value());
      expect(optional_string_field.get<std::string_view>().has_value());
    };

    "adopt aliases existing storage"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto optional_string_field = expect_ok(msg.field_by_name("optional_string"));
      optional_string_field.reset();
      expect(!optional_string_field.has_value());
      std::string_view adopted_string_view = "adopted"sv;
      expect(optional_string_field.adopt(adopted_string_view).has_value());
      expect(optional_string_field.has_value());
      expect(optional_string_field.get<std::string_view>().has_value());
      auto optional_string_field_value = expect_ok(optional_string_field.get<std::string_view>());
      expect(eq(optional_string_field_value, std::string_view{"adopted"}));
      expect(optional_string_field_value.data() == adopted_string_view.data());
    };

    "bytes set"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto optional_bytes_field = expect_ok(msg.field_by_name("optional_bytes"));
      auto assigned_bytes = "\x01\x02\x03"_bytes;
      expect(optional_bytes_field.set(std::span<const std::byte>(assigned_bytes)).has_value());
      expect(optional_bytes_field.has_value());
      expect(optional_bytes_field.get<hpp::proto::bytes_view>().has_value());
      expect(optional_bytes_field.get<hpp::proto::bytes_view>().has_value());
      auto optional_bytes_field_value = expect_ok(optional_bytes_field.get<hpp::proto::bytes_view>());

      expect(std::ranges::equal(assigned_bytes, optional_bytes_field_value));
      expect(assigned_bytes.data() != optional_bytes_field_value.data());
    };

    "bytes adopt"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto optional_bytes_field = expect_ok(msg.field_by_name("optional_bytes"));
      optional_bytes_field.reset();
      expect(!optional_bytes_field.has_value());
      auto adopted_bytes = "\x0A\x0B"_bytes;
      expect(optional_bytes_field.adopt(std::span<const std::byte>(adopted_bytes)).has_value());
      expect(optional_bytes_field.has_value());
      expect(optional_bytes_field.get<hpp::proto::bytes_view>().has_value());

      auto optional_bytes_field_value = expect_ok(optional_bytes_field.get<hpp::proto::bytes_view>());
      expect(adopted_bytes.size() == optional_bytes_field_value.size());
      expect(adopted_bytes.data() == optional_bytes_field_value.data());
    };

    "repeated scalar set and adopt"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto repeated_int_field = expect_ok(msg.field_by_name("repeated_int32"));
      std::array<std::int32_t, 3> ints{1, 2, 3};
      expect(repeated_int_field.set(std::span<const std::int32_t>(ints)).has_value());
      auto typed_repeated_int_field = expect_ok(repeated_int_field.to<hpp::proto::repeated_int32_field_mref>());
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
      typed_repeated_int_field = expect_ok(repeated_int_field.to<hpp::proto::repeated_int32_field_mref>());
      expect(eq(typed_repeated_int_field.size(), std::size_t{2}));
      expect(typed_repeated_int_field.data() == adopt_ints.data());
      expect(eq(typed_repeated_int_field[1], std::int32_t{8}));
      auto rep_int_cref_span_after_adopt = repeated_int_field.cref().get<std::span<const std::int32_t>>();
      expect(rep_int_cref_span_after_adopt.has_value());
      expect(rep_int_cref_span_after_adopt->data() == adopt_ints.data());

      expect(std::ranges::equal(adopt_ints,
                                expect_ok(msg.field_value_by_name<std::span<const std::int32_t>>("repeated_int32"))));
    };

    "repeated string set and adopt"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto repeated_string_field = expect_ok(msg.field_by_name("repeated_string"));
      std::array<std::string_view, 2> strs{"alpha", "beta"};
      expect(repeated_string_field.set(std::span<const std::string_view>(strs)).has_value());
      auto typed_repeated_string_field = expect_ok(repeated_string_field.to<hpp::proto::repeated_string_field_mref>());
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
      typed_repeated_string_field = expect_ok(repeated_string_field.to<hpp::proto::repeated_string_field_mref>());
      expect(eq(typed_repeated_string_field.size(), std::size_t{1}));
      expect(typed_repeated_string_field[0] == std::string_view{"gamma"});
      expect(typed_repeated_string_field.data() == adopt_strs.data());
      auto rep_string_cref_span_after_adopt = repeated_string_field.cref().get<std::span<const std::string_view>>();
      expect(rep_string_cref_span_after_adopt.has_value());
      expect(rep_string_cref_span_after_adopt->data() == adopt_strs.data());
    };

    "repeated bytes set and adopt"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto repeated_bytes_field = expect_ok(msg.field_by_name("repeated_bytes"));
      using byte = std::byte;
      std::array<byte, 2> stored0{byte{0x01}, byte{0x02}};
      std::array<byte, 1> stored1{byte{0x03}};
      std::array<hpp::proto::bytes_view, 2> byte_views{
          hpp::proto::bytes_view{stored0.data(), stored0.size()},
          hpp::proto::bytes_view{stored1.data(), stored1.size()},
      };
      expect(repeated_bytes_field.set(std::span<const hpp::proto::bytes_view>(byte_views)).has_value());
      auto typed_repeated_bytes_field = expect_ok(repeated_bytes_field.to<hpp::proto::repeated_bytes_field_mref>());
      expect(eq(typed_repeated_bytes_field.size(), std::size_t{2}));
      expect(typed_repeated_bytes_field[0] == byte_views[0]);
      auto rep_bytes_cref_span = repeated_bytes_field.cref().get<std::span<const hpp::proto::bytes_view>>();
      expect(rep_bytes_cref_span.has_value());
      expect(eq(rep_bytes_cref_span->size(), std::size_t{2}));

      std::array<byte, 3> adopted_storage{byte{0x0A}, byte{0x0B}, byte{0x0C}};
      std::array<hpp::proto::bytes_view, 1> adopt_views{
          hpp::proto::bytes_view{adopted_storage.data(), adopted_storage.size()}};
      expect(repeated_bytes_field.adopt(std::span<hpp::proto::bytes_view>(adopt_views)).has_value());
      typed_repeated_bytes_field = expect_ok(repeated_bytes_field.to<hpp::proto::repeated_bytes_field_mref>());
      expect(eq(typed_repeated_bytes_field.size(), std::size_t{1}));
      expect(typed_repeated_bytes_field[0] == adopt_views[0]);
      expect(typed_repeated_bytes_field.data() == adopt_views.data());
      auto rep_bytes_cref_span_after_adopt = repeated_bytes_field.cref().get<std::span<const hpp::proto::bytes_view>>();
      expect(rep_bytes_cref_span_after_adopt.has_value());
      expect(rep_bytes_cref_span_after_adopt->data() == adopt_views.data());
    };

    "repeated reserve keeps size and grows capacity"_test = [&factory]() {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      // scalars
      auto repeated_int_field = expect_ok(msg.field_by_name("repeated_int32"));
      auto int_mref = expect_ok(repeated_int_field.to<hpp::proto::repeated_int32_field_mref>());
      int_mref.clear();
      auto int_cap = int_mref.capacity();
      int_mref.reserve(5);
      expect(int_mref.capacity() >= std::max<std::size_t>(int_cap, 5));
      expect(eq(int_mref.size(), std::size_t{0}));

      // enums
      auto repeated_enum_field = expect_ok(msg.field_by_name("repeated_nested_enum"));
      auto enum_mref = expect_ok(repeated_enum_field.to<hpp::proto::repeated_enum_field_mref>());
      enum_mref.clear();
      auto enum_cap = enum_mref.capacity();
      enum_mref.reserve(3);
      expect(enum_mref.capacity() >= std::max<std::size_t>(enum_cap, 3));
      expect(eq(enum_mref.size(), std::size_t{0}));

      // strings
      auto repeated_string_field = expect_ok(msg.field_by_name("repeated_string"));
      auto str_mref = expect_ok(repeated_string_field.to<hpp::proto::repeated_string_field_mref>());
      str_mref.clear();
      auto str_cap = str_mref.capacity();
      str_mref.reserve(4);
      expect(str_mref.capacity() >= std::max<std::size_t>(str_cap, 4));
      expect(eq(str_mref.size(), std::size_t{0}));

      // bytes
      auto repeated_bytes_field = expect_ok(msg.field_by_name("repeated_bytes"));
      auto bytes_mref = expect_ok(repeated_bytes_field.to<hpp::proto::repeated_bytes_field_mref>());
      bytes_mref.clear();
      auto bytes_cap = bytes_mref.capacity();
      bytes_mref.reserve(2);
      expect(bytes_mref.capacity() >= std::max<std::size_t>(bytes_cap, 2));
      expect(eq(bytes_mref.size(), std::size_t{0}));

      // messages
      auto repeated_msg_field = expect_ok(msg.field_by_name("repeated_nested_message"));
      auto msg_mref = expect_ok(repeated_msg_field.to<hpp::proto::repeated_message_field_mref>());
      msg_mref.clear();
      auto msg_cap = msg_mref.capacity();
      msg_mref.reserve(2);
      expect(msg_mref.capacity() >= std::max<std::size_t>(msg_cap, 2));
      expect(eq(msg_mref.size(), std::size_t{0}));
      msg_mref.resize(1);
      expect(eq(msg_mref.size(), std::size_t{1}));
    };

    "repeated push_back appends elements"_test = [&factory]() {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      // scalars
      auto repeated_int_field = expect_ok(msg.field_by_name("repeated_int32"));
      auto int_mref = expect_ok(repeated_int_field.to<hpp::proto::repeated_int32_field_mref>());
      int_mref.clear();
      int_mref.push_back(10);
      int_mref.push_back(20);
      expect(eq(int_mref.size(), std::size_t{2}));
      expect(std::ranges::equal(std::array<int32_t, 2>{10, 20}, std::span{int_mref.data(), int_mref.size()}));

      // enums
      auto repeated_enum_field = expect_ok(msg.field_by_name("repeated_nested_enum"));
      auto enum_mref = expect_ok(repeated_enum_field.to<hpp::proto::repeated_enum_field_mref>());
      enum_mref.clear();
      enum_mref.push_back(hpp::proto::enum_number{1});
      expect(enum_mref.push_back(hpp::proto::enum_name{"BAR"}).has_value());
      expect(std::ranges::equal(std::array<int32_t, 2>{1, 2},
                                expect_ok(enum_mref.cref().get<hpp::proto::enum_numbers_span>())));

      // strings
      auto repeated_string_field = expect_ok(msg.field_by_name("repeated_string"));
      auto str_mref = expect_ok(repeated_string_field.to<hpp::proto::repeated_string_field_mref>());
      str_mref.clear();
      using namespace std::string_view_literals;
      str_mref.push_back("foo"sv);
      str_mref.push_back("bar"sv);
      expect(eq(static_cast<std::string_view>(str_mref[0]), "foo"sv));
      expect(eq(static_cast<std::string_view>(str_mref[1]), "bar"sv));

      // bytes
      auto repeated_bytes_field = expect_ok(msg.field_by_name("repeated_bytes"));
      auto bytes_mref = expect_ok(repeated_bytes_field.to<hpp::proto::repeated_bytes_field_mref>());
      bytes_mref.clear();
      std::array<std::byte, 2> b1{std::byte{0x01}, std::byte{0x02}};
      std::array<std::byte, 3> b2{std::byte{0xFF}, std::byte{0x00}, std::byte{0xAA}};
      bytes_mref.push_back(b1);
      bytes_mref.push_back(b2);
      auto bv1 = static_cast<hpp::proto::bytes_view>(bytes_mref[0]);
      auto bv2 = static_cast<hpp::proto::bytes_view>(bytes_mref[1]);
      expect(eq(bv1.size(), std::size_t{2}));
      expect(eq(bv2.size(), std::size_t{3}));
      expect(std::ranges::equal(b1, bv1));
      expect(std::ranges::equal(b2, bv2));

      // messages
      auto repeated_msg_field = expect_ok(msg.field_by_name("repeated_nested_message"));
      auto msg_mref = expect_ok(repeated_msg_field.to<hpp::proto::repeated_message_field_mref>());
      auto first = msg_mref.emplace_back();
      auto second = msg_mref.emplace_back();
      expect(eq(msg_mref.size(), std::size_t{2}));
      expect(first.set_field_by_number(1, 7).has_value());
      expect(second.set_field_by_number(1, 8).has_value());
      expect(first.field_value_by_number<std::int32_t>(1) == 7);
      expect(second.field_value_by_number<std::int32_t>(1) == 8);

      // cleanup
    };

    "enum set"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto enum_field = expect_ok(msg.field_by_name("optional_nested_enum"));
      expect(enum_field.set(hpp::proto::enum_number{1}).has_value());

      expect(enum_field.get<hpp::proto::enum_number>() == 1);
      expect("FOO"sv == enum_field.get<hpp::proto::enum_name>());

      expect(!enum_field.set(hpp::proto::enum_name{"abc"}).has_value());
      expect(enum_field.set(hpp::proto::enum_name{"BAR"}).has_value());
      expect("BAR"sv == enum_field.get<hpp::proto::enum_name>());
    };

    "unknown enum json"_test = [&factory] {
      std::pmr::monotonic_buffer_resource mr1;
      auto msg1 = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", mr1));
      auto enum_field = expect_ok(msg1.field_by_name("optional_nested_enum"));
      expect(enum_field.set(hpp::proto::enum_number{10}).has_value());
      expect(enum_field.get<hpp::proto::enum_number>() == 10);
      expect(!enum_field.get<hpp::proto::enum_name>().has_value());

      std::string expected_json_str = R"({"optionalNestedEnum":10})";
      std::string json_buf;
      expect(::hpp::proto::write_json(msg1, json_buf).ok());
      using namespace std::string_literals;
      expect(eq(expected_json_str, json_buf));

      std::pmr::monotonic_buffer_resource mr2;
      auto msg2 = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", mr2));
      expect(::hpp::proto::read_json(msg2, expected_json_str).ok());
      expect(10 == msg2.field_value_by_name<hpp::proto::enum_number>("optional_nested_enum"));
    };

    "repeated enum set and adopt"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto rep_enum_field = expect_ok(msg.field_by_name("repeated_nested_enum"));
      std::array<std::int32_t, 2> enums{1, 2};
      using namespace std::string_view_literals;
      std::array<std::string_view, 2> enum_names{"FOO"sv, "BAR"sv};
      expect(rep_enum_field.set(::hpp::proto::enum_numbers_range(enums)).has_value());
      expect(rep_enum_field.has_value());
      expect(std::ranges::equal(enums, expect_ok(rep_enum_field.get<::hpp::proto::enum_numbers_span>())));
      expect(std::ranges::equal(enum_names, expect_ok(rep_enum_field.get<::hpp::proto::enum_names_view>())));

      std::array<std::int32_t, 1> adopt_enums{3};
      expect(rep_enum_field.adopt(std::span<std::int32_t>(adopt_enums)).has_value());
      expect(std::ranges::equal(adopt_enums, expect_ok(rep_enum_field.get<::hpp::proto::enum_numbers_span>())));

      expect(rep_enum_field.set(::hpp::proto::enum_names_range{enum_names}).has_value());
      expect(std::ranges::equal(enum_names, expect_ok(rep_enum_field.get<::hpp::proto::enum_names_view>())));

      std::array<std::string_view, 2> partially_invalid_names{"BAZ"sv, "XXX"sv};
      expect(!rep_enum_field.set(::hpp::proto::enum_names_range{partially_invalid_names}).has_value());
      expect(std::ranges::equal(std::initializer_list<std::string_view>{"BAZ"sv},
                                expect_ok(rep_enum_field.get<::hpp::proto::enum_names_view>())));
    };

    "nested message set/get"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto nested_msg_field =
          expect_ok(msg.typed_ref_by_name<::hpp::proto::message_field_mref>("optional_nested_message"));
      expect(!nested_msg_field.has_value());
      auto nested = nested_msg_field.emplace();
      expect(nested_msg_field.has_value());
      // operator-> on mref
      expect(nested_msg_field->set_field_by_name("bb", 777).has_value());

      auto bb_field = expect_ok(nested.field_by_name("bb"));
      expect(bb_field.set(321).has_value());

      expect(nested.field_value_by_name<std::int32_t>("bb") == 321);

      hpp::proto::message_value_cref nested_cref = expect_ok(nested_msg_field.get<hpp::proto::message_value_cref>());
      expect(nested_cref.field_value_by_name<std::int32_t>("bb") == 321);

      auto nested_field_cref = nested_msg_field.cref();
      expect(nested_field_cref->field_value_by_name<std::int32_t>("bb") == 321);
    };

    "arrow operators on scalar/string/bytes/enum"_test = [&factory] {
      using namespace std::string_view_literals;
      using hpp::proto::KIND_BYTES;
      using hpp::proto::KIND_ENUM;
      using hpp::proto::KIND_INT32;
      using hpp::proto::KIND_STRING;

      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));

      auto int_field = expect_ok(msg.typed_ref_by_name<hpp::proto::int32_field_mref>("optional_int32"));
      expect(!static_cast<bool>(int_field));
      expect(int_field.value() == 0);
      int_field.set(123);
      expect(static_cast<bool>(int_field));
      expect(int_field.value() == 123);

      auto str_field = expect_ok(msg.typed_ref_by_name<hpp::proto::string_field_mref>("optional_string"));
      expect(!static_cast<bool>(str_field));
      expect(str_field->empty());
      str_field.set("hello");
      expect(static_cast<bool>(str_field));
      expect(str_field->size() == 5U);

      auto bytes_field = expect_ok(msg.typed_ref_by_name<hpp::proto::bytes_field_mref>("optional_bytes"));
      expect(!static_cast<bool>(bytes_field));
      expect(bytes_field->empty());
      bytes_field.set("hi"_bytes);
      expect(static_cast<bool>(bytes_field));
      expect(bytes_field->size() == 2U);

      auto enum_field = expect_ok(msg.typed_ref_by_name<hpp::proto::enum_field_mref>("optional_nested_enum"));
      expect(!static_cast<bool>(enum_field));
      expect(enum_field->name() == "FOO"sv);
      expect(enum_field->number() == 1);
      enum_field.set(hpp::proto::enum_number{2});
      expect(static_cast<bool>(enum_field));
      expect(enum_field->number() == 2);
      expect(!enum_field->name().empty());

      auto msg_cref = msg.cref();
      auto int_cref = expect_ok(msg_cref.typed_ref_by_name<hpp::proto::int32_field_cref>("optional_int32"));
      expect(static_cast<bool>(int_cref));
      expect(int_cref.value() == 123);

      auto str_cref = expect_ok(msg_cref.typed_ref_by_name<hpp::proto::string_field_cref>("optional_string"));
      expect(static_cast<bool>(str_cref));
      expect(str_cref->size() == 5U);

      auto bytes_cref = expect_ok(msg_cref.typed_ref_by_name<hpp::proto::bytes_field_cref>("optional_bytes"));
      expect(static_cast<bool>(bytes_cref));
      expect(bytes_cref->size() == 2U);

      auto enum_cref = expect_ok(msg_cref.typed_ref_by_name<hpp::proto::enum_field_cref>("optional_nested_enum"));
      expect(static_cast<bool>(enum_cref));
      expect(enum_cref->number() == 2);
      expect(!enum_cref->name().empty());
    };

    "repeated nested message set/get"_test = [&factory] {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto msg = expect_ok(factory.get_message("protobuf_unittest.TestAllTypes", memory_resource));
      auto rep_nested_field =
          expect_ok(msg.typed_ref_by_name<::hpp::proto::repeated_message_field_mref>("repeated_nested_message"));
      expect(rep_nested_field.size() == 0U);

      rep_nested_field.resize(2);
      auto first = rep_nested_field[0];
      auto second = rep_nested_field[1];

      expect(first.set_field_by_name("bb", 111).has_value());
      expect(second.set_field_by_name("bb", 222).has_value());

      expect(std::ranges::equal(
          std::array<int32_t, 2>{111, 222},
          std::array<int32_t, 2>{expect_ok(rep_nested_field[0].field_value_by_name<std::int32_t>("bb")),
                                 expect_ok(rep_nested_field[1].field_value_by_name<std::int32_t>("bb"))}));

      auto rep_cref = rep_nested_field.cref();
      expect(rep_cref.size() == 2U);
      expect(rep_cref[0].field_value_by_name<std::int32_t>("bb") == 111);
      expect(rep_cref[1].field_value_by_name<std::int32_t>("bb") == 222);
    };

    "expected_message_mref chain"_test = [&factory]() {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto em = factory.get_message("protobuf_unittest.TestAllTypes", memory_resource);
      expect(em.has_value());

      auto chained =
          em.set_field_by_name("optional_int32", 42)
              .modify_field_by_name("optional_nested_message", [](hpp::proto::message_field_mref nested_field) {
                return hpp::proto::expected_message_mref{nested_field.emplace()}.set_field_by_name("bb", 7).done();
              });
      expect(chained.has_value());
      auto msg_chain = chained.value();
      expect(msg_chain.field_value_by_name<std::int32_t>("optional_int32") == 42);
      auto nested = msg_chain.typed_ref_by_name<hpp::proto::message_field_cref>("optional_nested_message");
      expect(nested.has_value());
      expect(nested.value()->field_value_by_name<std::int32_t>("bb") == 7);

      auto bad = em.set_field_by_name("missing_field", 1);
      expect(!bad.has_value());
    };

    "expected_message_mref observers"_test = [&factory]() {
      std::pmr::monotonic_buffer_resource memory_resource;
      auto em = factory.get_message("protobuf_unittest.TestAllTypes", memory_resource);
      expect(em.has_value());
      expect(static_cast<bool>(em));
      expect(em.done().has_value());

      // operator* and value()
      auto mref = *em;
      expect(mref.set_field_by_name("optional_int32", 5).has_value());
      expect(em.value().field_value_by_name<std::int32_t>("optional_int32") == 5);

      // operator-> presence
      expect(em.operator->() != nullptr);

      // failure path
      std::pmr::monotonic_buffer_resource mr2;
      auto em_bad = factory.get_message("unknown.message", mr2);
      expect(!em_bad.has_value());
      expect(!static_cast<bool>(em_bad));
      expect(em_bad.error() == hpp::proto::dynamic_message_errc::unknown_message_name);
      expect(!em_bad.done().has_value());
    };
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
