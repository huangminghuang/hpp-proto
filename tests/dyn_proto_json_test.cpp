#include <boost/ut.hpp>
#include <google/protobuf/map_unittest.pb.hpp>
#include <google/protobuf/unittest_proto3.glz.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>
#include <hpp_proto/dyn_proto_json.h>

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
  m->repeated_int32.push_back(200);
  m->repeated_int32.push_back(300);

  m->repeated_string.push_back("asdf");
  m->repeated_string.push_back("qwer");
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


google::protobuf::FileDescriptorSet descriptorset_from_file(const char *filename) {
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(in.tellg());
  in.seekg(0, std::ios::beg);
  in.read(&contents[0], contents.size());
  google::protobuf::FileDescriptorSet fileset;
  using namespace boost::ut;
  ut::expect((!hpp::proto::read_proto(fileset, contents)) >> fatal);
  return fileset;
}

ut::suite proto3_lite_test = [] {
  using namespace boost::ut::literals;

  "dyn_proto_json"_test = [] {
    proto3_unittest::TestAllTypes original;
    SetAllFields(&original);

    auto [data, in, out] = hpp::proto::data_in_out();
    using zpp::bits::success;
    ut::expect(success(out(original)));

    hpp::proto::proto_json_meta meta{descriptorset_from_file("unittest_proto3.bin")};

    std::string dyn_json;
    ut::expect(!meta.proto_to_json<glz::opts{.prettify = true}>("proto3_unittest.TestAllTypes", data, dyn_json));

    std::cout << dyn_json << "\n";
  };
};

ut::suite test_map = [] {
  using namespace boost::ut::literals;
  "dyn_proto_json"_test = [] {
    protobuf_unittest::TestMap original;
    original.map_int32_int32[1] = 1;
    original.map_int32_int32[2] = 2;
    original.map_int32_int32[3] = 3;
    original.map_int32_int32[4] = 4;

    original.map_string_string["key1"] = "value1";
    original.map_string_string["key2"] = "value2";
    original.map_string_string["key3"] = "value3";

    auto [data, in, out] = hpp::proto::data_in_out();
    using zpp::bits::success;
    ut::expect(success(out(original)));

    hpp::proto::proto_json_meta meta{descriptorset_from_file("map_unittest.bin")};

    std::string dyn_json;
    ut::expect(!meta.proto_to_json<glz::opts{.prettify = true}>("protobuf_unittest.TestMap", data, dyn_json));

    std::cout << dyn_json << "\n";
  };
};

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return result;
}