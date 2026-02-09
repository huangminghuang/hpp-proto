#include "gpb_proto_json/gpb_proto_json.hpp"
#include "map_test_util.hpp"
#include "test_util.hpp"
#include <google/protobuf/map_unittest.glz.hpp>
#include <hpp_proto/binpb.hpp>

const boost::ut::suite map_test = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;

  auto map_unittest_descriptorset = read_file("unittest.desc.binpb");

  "protobuf"_test = []<class Traits> {
    protobuf_unittest::TestMap<Traits> original;
    SetMapFields(&original);

    protobuf_unittest::TestMap<Traits> msg;

    std::vector<char> data;
    expect(hpp_proto::write_binpb(original, data).ok());
    std::pmr::monotonic_buffer_resource mr;
    expect(hpp_proto::read_binpb(msg, data, hpp_proto::alloc_from(mr)).ok());

    ExpectMapFieldsSet(msg);
  } | std::tuple<::hpp_proto::stable_traits, ::hpp_proto::non_owning_traits>();

  "glaze"_test = [&]<class Traits> {
    protobuf_unittest::TestMap<Traits> original;
    SetMapFields(&original);

    std::vector<char> data;
    expect(hpp_proto::write_binpb(original, data).ok());

    auto original_json =
        gpb_based::binpb_to_json(map_unittest_descriptorset, "protobuf_unittest.TestMap", {data.data(), data.size()});
    expect(fatal(!original_json.empty()));

    expect(eq(hpp_proto::write_json(original).value(), original_json));

    protobuf_unittest::TestMap<Traits> msg;
    std::pmr::monotonic_buffer_resource mr;
    expect(hpp_proto::read_json(msg, original_json, hpp_proto::alloc_from(mr)).ok());
    ExpectMapFieldsSet(msg);

    std::vector<char> non_null_terminated_json{original_json.begin(), original_json.end()};
    expect(hpp_proto::read_json(msg, non_null_terminated_json, hpp_proto::alloc_from(mr)).ok());
    ExpectMapFieldsSet(msg);
  } | std::tuple<::hpp_proto::stable_traits, ::hpp_proto::non_owning_traits>();
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
