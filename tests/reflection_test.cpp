#include "test_util.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/reflection.hpp>
#include <hpp_proto/reflection_json.hpp>
#include <memory_resource>

int main() {
    using namespace boost::ut;
    using namespace boost::ut::literals;
    auto fileset = hpp::proto::make_file_descriptor_set(read_file("unittest.desc.binpb"));
    if (!fileset) [[unlikely]] {
        std::cerr << "Failed to read descriptor set";
        return 1;
    }

    hpp::proto::reflection_descriptor_pool pool{std::move(*fileset)};
    expect(fatal(!pool.files().empty()));

    auto message_name = "protobuf_unittest.TestAllTypes";

    using namespace std::string_literals;
    std::string data = read_file("data/"s + message_name + ".binpb");

    auto desc = pool.message_by_name(message_name);
    expect(fatal(desc != nullptr));

    std::pmr::monotonic_buffer_resource memory_resource;

    hpp::proto::message_value_mref message{*desc, memory_resource};
    auto r = hpp::proto::read_proto(message, data);
    expect(fatal(r.ok()));

    std::string str;
    auto err = glz::write_json(message, str);
    expect(!err);

    auto json = read_file("data/protobuf_unittest.TestAllTypes.json");
    expect(json == str);
}