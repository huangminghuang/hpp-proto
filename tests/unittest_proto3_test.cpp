#include "proto2json/proto2json.h"
#include <boost/ut.hpp>
#include <google/protobuf/unittest_proto3.glz.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>

namespace ut = boost::ut;
auto to_bytes(const char *content) {
  return std::vector<std::byte>{reinterpret_cast<const std::byte *>(content),
                                reinterpret_cast<const std::byte *>(content) + strlen(content)};
}

// We selectively set/check a few representative fields rather than all fields
// as this test is only expected to cover the basics of lite support.
void SetAllFields(proto3_unittest::TestAllTypes *m) {

  m->optional_int32 = 100;
  m->optional_string = "asdf";
  m->optional_bytes = to_bytes("jkl;");
  m->optional_nested_message.emplace().bb = 42;
  m->optional_foreign_message.emplace().c = 43;
  m->optional_nested_enum = proto3_unittest::TestAllTypes::NestedEnum::BAZ;
  m->optional_foreign_enum = proto3_unittest::ForeignEnum::FOREIGN_BAZ;
  m->optional_lazy_message.emplace().bb = 45;
  m->optional_unverified_lazy_message.emplace().bb = 46;

  m->repeated_int32.push_back(100);
  m->repeated_string.push_back("asdf");
  m->repeated_bytes.emplace_back(to_bytes("jkl;"));
  m->repeated_nested_message.emplace_back().bb = 46;
  m->repeated_foreign_message.emplace_back().c = 47;
  m->repeated_nested_enum.push_back(proto3_unittest::TestAllTypes::NestedEnum::BAZ);
  m->repeated_foreign_enum.push_back(proto3_unittest::ForeignEnum::FOREIGN_BAZ);
  m->repeated_lazy_message.emplace_back().bb = 49;

  m->oneof_field = 1U;
  m->oneof_field.emplace<proto3_unittest::TestAllTypes::NestedMessage>().bb = 50;
  m->oneof_field = "test"; // only this one remains set
}

void ExpectAllFieldsSet(const proto3_unittest::TestAllTypes &m) {
  ut::expect(100 == m.optional_int32);
  ut::expect("asdf" == m.optional_string);
  ut::expect(to_bytes("jkl;") == m.optional_bytes);
  ut::expect(true == m.optional_nested_message.has_value());
  ut::expect(42 == m.optional_nested_message->bb);
  ut::expect(true == m.optional_foreign_message.has_value());
  ut::expect(43 == m.optional_foreign_message->c);
  ut::expect(proto3_unittest::TestAllTypes::NestedEnum::BAZ == m.optional_nested_enum);
  ut::expect(proto3_unittest::ForeignEnum::FOREIGN_BAZ == m.optional_foreign_enum);
  ut::expect(true == m.optional_lazy_message.has_value());
  ut::expect(45 == m.optional_lazy_message->bb);
  ut::expect(true == m.optional_unverified_lazy_message.has_value());
  ut::expect(46 == m.optional_unverified_lazy_message->bb);

  ut::expect(1 == m.repeated_int32.size());
  ut::expect(100 == m.repeated_int32[0]);
  ut::expect(1 == m.repeated_string.size());
  ut::expect("asdf" == m.repeated_string[0]);
  ut::expect(1 == m.repeated_bytes.size());
  ut::expect(to_bytes("jkl;") == m.repeated_bytes[0]);
  ut::expect(1 == m.repeated_nested_message.size());
  ut::expect(46 == m.repeated_nested_message[0].bb);
  ut::expect(1 == m.repeated_foreign_message.size());
  ut::expect(47 == m.repeated_foreign_message[0].c);
  ut::expect(1 == m.repeated_nested_enum.size());
  ut::expect(proto3_unittest::TestAllTypes::NestedEnum::BAZ == m.repeated_nested_enum[0]);
  ut::expect(1 == m.repeated_foreign_enum.size());
  ut::expect(proto3_unittest::ForeignEnum::FOREIGN_BAZ == m.repeated_foreign_enum[0]);
  ut::expect(1 == m.repeated_lazy_message.size());
  ut::expect(49 == m.repeated_lazy_message[0].bb);

  ut::expect("test" == std::get<std::string>(m.oneof_field));
}

std::string unittest_proto3_descriptorset() { 
  std::ifstream in("unittest_proto3.bin", std::ios::in | std::ios::binary);
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(in.tellg());
  in.seekg(0, std::ios::beg);
  in.read(&contents[0], contents.size());
  return contents;
}
// In this file we only test some basic functionalities of in proto3 and expect
// the rest is fully tested in proto2 unittests because proto3 shares most code
// with proto2.

ut::suite proto3_lite_test = [] {
  using namespace boost::ut::literals;

  "protobuf"_test = [] {
    proto3_unittest::TestAllTypes original;
    SetAllFields(&original);

    proto3_unittest::TestAllTypes msg;

    auto [data, in, out] = hpp::proto::data_in_out();
    using zpp::bits::success;

    ut::expect(success(out(original)));
    ut::expect(success(in(msg)));

    ExpectAllFieldsSet(msg);
  };

  "glaze"_test = [] {
    proto3_unittest::TestAllTypes original;
    SetAllFields(&original);


    auto [data, in, out] = hpp::proto::data_in_out();
    using zpp::bits::success;

    ut::expect(success(out(original)));

    auto original_json = proto_to_json(unittest_proto3_descriptorset(), "proto3_unittest.TestAllTypes",
                                       {(const char *)data.data(), data.size()}, ALWAYS_PRINT_PRIMITIVE_FIELDS);

    ut::expect(glz::write_json(original) == original_json);

    proto3_unittest::TestAllTypes msg;
    ut::expect(!glz::read_json(msg, original_json));

    ExpectAllFieldsSet(msg);
  };
};

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return result;
}