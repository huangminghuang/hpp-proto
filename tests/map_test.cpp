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
    auto status = hpp_proto::read_json(msg, original_json, hpp_proto::alloc_from(mr));
    expect(status.ok()) << status.message(original_json);
    ExpectMapFieldsSet(msg);

    const std::vector<char> non_null_terminated_json{original_json.begin(), original_json.end()};
    expect(hpp_proto::read_json(msg, non_null_terminated_json, hpp_proto::alloc_from(mr)).ok());
    ExpectMapFieldsSet(msg);
  } | std::tuple<::hpp_proto::stable_traits, ::hpp_proto::non_owning_traits>();

  "segmented packed varint crash regression"_test = [] {
    constexpr auto crash = "\x3a\x05\x0d\x90\x02\xcc\x01\x90\x02\x01\x90\x28\x3d\x9a\x01\x3a"
                           "\x08\x29\x80\xa8\x12\x3d\x9a\x01\x02\x08\x30\x12\x2a\x08\x00\xa8"
                           "\x28\x3d\xda\x01\x00\x08\x34\xa8\x28\x80\x00\xa2\x12\x85\x80\x00"
                           "\xda\x01\x00\x08\x34\xa8\x28\x84\x00\xa2\x02\x85\x80\x00\x02\x85"
                           "\x80\x80\x00\xa2\x02\x85\x80\x80\x00\xa2\x23\x80\x80\x00\x90\x02"
                           "\xcc\x01\x90\x02\x01\x90\x28\x3d\x02\x85\x80\x80\x00\xa2\x02\x85"
                           "\x80\x80\x00\xa2\x23\x80\x80\x00\x90\x02\xcc\x21\x90\x01\x0f\x00"
                           "\x80\x3a\x05\x0d\x01\xf0\x00\x80\x3a\x05\x0d\x01\xa0\x08\x01\x3a"
                           "\x05\x0d\x01\x41\x80\x80"_bytes;
    constexpr std::size_t crash_split_offset = 67;
    const std::span<const std::byte> crash_span{crash.data(), crash.size()};
    const std::array<std::span<const std::byte>, 2> chunks{crash_span.first(crash_split_offset),
                                                           crash_span.subspan(crash_split_offset)};
    protobuf_unittest::TestMap<hpp_proto::stable_traits> contiguous_message;
    protobuf_unittest::TestMap<hpp_proto::stable_traits> segmented_message;

    const auto contiguous = hpp_proto::read_binpb(contiguous_message, crash);
    const auto segmented = hpp_proto::read_binpb(segmented_message, chunks);
    expect(eq(contiguous.ec, std::errc::bad_message));
    expect(eq(segmented.ec, std::errc::bad_message));
  };

  "packed varints respect destination bounds"_test = [] {
    std::array<std::byte, 2> input{std::byte{0}, std::byte{0}};
    std::array<std::int64_t, 1> output{};
    hpp_proto::pb_context<> context;
    const hpp_proto::pb_serializer::input_buffer_region<std::byte> region{std::span<const std::byte>{input}};
    const hpp_proto::pb_serializer::input_span<hpp_proto::pb_serializer::input_buffer_region<std::byte>> rest;
    hpp_proto::pb_serializer::basic_in<std::byte, hpp_proto::pb_context<>, true> archive{region, rest, 0, context};

    const auto result = archive.template parse_packed_varints_in_a_region<hpp_proto::vsint64_t>(
        archive.current, output.begin(), output.end());
    expect(eq(result.ec, std::errc::bad_message));
  };

  "packed varints reject a terminator before the current region"_test = [] {
    constexpr std::array input{std::byte{0}, std::byte{0x80}, std::byte{0x80}};
    constexpr std::size_t current_offset = 2;
    constexpr std::size_t requested_size = 2;
    const std::span<const std::byte> bytes{input};
    const auto current = bytes.subspan(current_offset);
    hpp_proto::pb_serializer::input_buffer_region<std::byte> region{
        hpp_proto::pb_serializer::input_span<std::byte>{current.data(), current.size()}, bytes.data()};

    const auto result = region.consume_packed_varints(requested_size);
    expect(result.empty());
  };
};

// NOLINTNEXTLINE(bugprone-exception-escape)
int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
