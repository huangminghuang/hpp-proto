#pragma once

#include <span>
#include <vector>

#include <google/protobuf/map_unittest.msg.hpp>
#include <google/protobuf/unittest.msg.hpp>
#include <google/protobuf/unittest_proto3.msg.hpp>
#include <google/protobuf/unittest_well_known_types.msg.hpp>

#include "common.hpp"
#include "value_extern.hpp"

namespace hpp::proto {
using alloc_option_t = alloc_from<std::pmr::monotonic_buffer_resource>;
} // namespace hpp::proto

namespace util {
struct fuzz_out_sink {
  using slice_type = std::byte;
  std::vector<std::byte> storage;
  std::size_t offset = 0;
  std::size_t remaining_total = 0;
  std::size_t chunk_size_value = 1024;

  void set_message_size(std::size_t size) {
    storage.assign(size, std::byte{});
    offset = 0;
    remaining_total = size;
  }

  std::span<std::byte> next_chunk() {
    if (remaining_total == 0) {
      return {};
    }
    const auto remaining_storage = storage.size() - offset;
    const auto granted = std::min({remaining_storage, chunk_size_value, remaining_total});
    offset += granted;
    remaining_total -= granted;
    return std::span<std::byte>(storage.data() + (offset - granted), granted);
  }

  std::size_t chunk_size() const { return chunk_size_value; }
  void finalize() {}

  std::span<const std::byte> written() const { return std::span<const std::byte>(storage.data(), storage.size()); }
};

// Non-template overloads keep binpb template instantiations in binpb_extern.cpp only.
hpp::proto::status read_binpb(proto3_unittest::TestAllTypes<hpp::proto::default_traits> &msg,
                              std::span<const std::byte> input);
hpp::proto::status read_binpb(proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                              std::span<const std::byte> input, hpp::proto::alloc_option_t option);
hpp::proto::status read_binpb(proto3_unittest::TestAllTypes<hpp::proto::default_traits> &msg,
                              std::span<std::span<const std::byte>> input);
hpp::proto::status read_binpb(proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                              std::span<std::span<const std::byte>> input, hpp::proto::alloc_option_t option);

hpp::proto::status read_binpb(protobuf_unittest::TestAllTypes<hpp::proto::default_traits> &msg,
                              std::span<const std::byte> input);
hpp::proto::status read_binpb(protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                              std::span<const std::byte> input, hpp::proto::alloc_option_t option);
hpp::proto::status read_binpb(protobuf_unittest::TestAllTypes<hpp::proto::default_traits> &msg,
                              std::span<std::span<const std::byte>> input);
hpp::proto::status read_binpb(protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                              std::span<std::span<const std::byte>> input, hpp::proto::alloc_option_t option);

hpp::proto::status read_binpb(protobuf_unittest::TestMap<hpp::proto::default_traits> &msg,
                              std::span<const std::byte> input);
hpp::proto::status read_binpb(protobuf_unittest::TestMap<hpp::proto::non_owning_traits> &msg,
                              std::span<const std::byte> input, hpp::proto::alloc_option_t option);
hpp::proto::status read_binpb(protobuf_unittest::TestMap<hpp::proto::default_traits> &msg,
                              std::span<std::span<const std::byte>> input);
hpp::proto::status read_binpb(protobuf_unittest::TestMap<hpp::proto::non_owning_traits> &msg,
                              std::span<std::span<const std::byte>> input, hpp::proto::alloc_option_t option);

hpp::proto::status read_binpb(proto2_unittest::TestWellKnownTypes<hpp::proto::default_traits> &msg,
                              std::span<const std::byte> input);
hpp::proto::status read_binpb(proto2_unittest::TestWellKnownTypes<hpp::proto::non_owning_traits> &msg,
                              std::span<const std::byte> input, hpp::proto::alloc_option_t option);
hpp::proto::status read_binpb(proto2_unittest::TestWellKnownTypes<hpp::proto::default_traits> &msg,
                              std::span<std::span<const std::byte>> input);
hpp::proto::status read_binpb(proto2_unittest::TestWellKnownTypes<hpp::proto::non_owning_traits> &msg,
                              std::span<std::span<const std::byte>> input, hpp::proto::alloc_option_t option);

hpp::proto::status read_binpb(hpp::proto::message_value_mref &msg, std::span<const std::byte> input);
hpp::proto::status read_binpb(hpp::proto::message_value_mref &msg, std::span<std::span<const std::byte>> input);

hpp::proto::status write_binpb(const proto3_unittest::TestAllTypes<hpp::proto::default_traits> &msg,
                               std::vector<std::byte> &buffer);
hpp::proto::status write_binpb(const proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                               std::vector<std::byte> &buffer);
hpp::proto::status write_binpb(const protobuf_unittest::TestAllTypes<hpp::proto::default_traits> &msg,
                               std::vector<std::byte> &buffer);
hpp::proto::status write_binpb(const protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                               std::vector<std::byte> &buffer);
hpp::proto::status write_binpb(const protobuf_unittest::TestMap<hpp::proto::default_traits> &msg,
                               std::vector<std::byte> &buffer);
hpp::proto::status write_binpb(const protobuf_unittest::TestMap<hpp::proto::non_owning_traits> &msg,
                               std::vector<std::byte> &buffer);
hpp::proto::status write_binpb(const proto2_unittest::TestWellKnownTypes<hpp::proto::default_traits> &msg,
                               std::vector<std::byte> &buffer);
hpp::proto::status write_binpb(const proto2_unittest::TestWellKnownTypes<hpp::proto::non_owning_traits> &msg,
                               std::vector<std::byte> &buffer);
hpp::proto::status write_binpb(const hpp::proto::message_value_mref &msg, std::vector<std::byte> &buffer);

hpp::proto::status write_binpb(const proto3_unittest::TestAllTypes<hpp::proto::default_traits> &msg,
                               fuzz_out_sink &sink);
hpp::proto::status write_binpb(const proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                               fuzz_out_sink &sink);
hpp::proto::status write_binpb(const protobuf_unittest::TestAllTypes<hpp::proto::default_traits> &msg,
                               fuzz_out_sink &sink);
hpp::proto::status write_binpb(const protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                               fuzz_out_sink &sink);
hpp::proto::status write_binpb(const protobuf_unittest::TestMap<hpp::proto::default_traits> &msg, fuzz_out_sink &sink);
hpp::proto::status write_binpb(const protobuf_unittest::TestMap<hpp::proto::non_owning_traits> &msg,
                               fuzz_out_sink &sink);
hpp::proto::status write_binpb(const proto2_unittest::TestWellKnownTypes<hpp::proto::default_traits> &msg,
                               fuzz_out_sink &sink);
hpp::proto::status write_binpb(const proto2_unittest::TestWellKnownTypes<hpp::proto::non_owning_traits> &msg,
                               fuzz_out_sink &sink);
hpp::proto::status write_binpb(const hpp::proto::message_value_mref &msg, fuzz_out_sink &sink);
} // namespace util
