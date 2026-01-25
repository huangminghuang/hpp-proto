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
} // namespace util
