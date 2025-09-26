#include "test_util.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/dynamic_message_json.hpp>
#include <memory_resource>
using namespace boost::ut;

const boost::ut::suite dynamic_message_test = [] {
  using namespace boost::ut::literals;
  auto fileset = hpp::proto::make_file_descriptor_set(read_file("unittest.desc.binpb"));
  if (!fileset) [[unlikely]] {
    throw std::runtime_error("Failed to read descriptor set");
  }

  hpp::proto::dynamic_message_factory factory{std::move(*fileset)};
  expect(fatal(!factory.files().empty()));

  "unit"_test = [&factory](const std::string &message_name) -> void {
    using namespace std::string_literals;
    std::string data = read_file("data/"s + message_name + ".binpb");

    std::pmr::monotonic_buffer_resource memory_resource;
    hpp::proto::message_value_mref message = factory.get_message(message_name, memory_resource).value();
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
  } | std::vector<std::string>{"proto3_unittest.TestAllTypes",       "proto3_unittest.TestUnpackedTypes",
                               "protobuf_unittest.TestAllTypes",     "protobuf_unittest.TestPackedTypes",
                               "protobuf_unittest.TestMap",          "protobuf_unittest.TestUnpackedTypes",
                               "protobuf_unittest.TestAllTypesLite", "protobuf_unittest.TestPackedTypesLite"};
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}