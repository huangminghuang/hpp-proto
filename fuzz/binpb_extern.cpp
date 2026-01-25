#include "binpb_extern.hpp"
#include <google/protobuf/map_unittest.pb.hpp>
#include <google/protobuf/unittest.pb.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>
#include <google/protobuf/unittest_well_known_types.pb.hpp>

#include <hpp_proto/binpb.hpp>
#include <hpp_proto/dynamic_message/binpb.hpp>

namespace util {
using hpp::proto::status;

status read_binpb(proto3_unittest::TestAllTypes<hpp::proto::default_traits> &msg, std::span<const std::byte> input) {
  return hpp::proto::read_binpb(msg, input);
}

status read_binpb(proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg, std::span<const std::byte> input,
                  hpp::proto::alloc_option_t option) {
  return hpp::proto::read_binpb(msg, input, option);
}

status read_binpb(proto3_unittest::TestAllTypes<hpp::proto::default_traits> &msg,
                  std::span<std::span<const std::byte>> input) {
  return hpp::proto::read_binpb(msg, input);
}

status read_binpb(proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                  std::span<std::span<const std::byte>> input, hpp::proto::alloc_option_t option) {
  return hpp::proto::read_binpb(msg, input, option);
}

status read_binpb(protobuf_unittest::TestAllTypes<hpp::proto::default_traits> &msg, std::span<const std::byte> input) {
  return hpp::proto::read_binpb(msg, input);
}

status read_binpb(protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg, std::span<const std::byte> input,
                  hpp::proto::alloc_option_t option) {
  return hpp::proto::read_binpb(msg, input, option);
}

status read_binpb(protobuf_unittest::TestAllTypes<hpp::proto::default_traits> &msg,
                  std::span<std::span<const std::byte>> input) {
  return hpp::proto::read_binpb(msg, input);
}

status read_binpb(protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                  std::span<std::span<const std::byte>> input, hpp::proto::alloc_option_t option) {
  return hpp::proto::read_binpb(msg, input, option);
}

status read_binpb(protobuf_unittest::TestMap<hpp::proto::default_traits> &msg, std::span<const std::byte> input) {
  return hpp::proto::read_binpb(msg, input);
}

status read_binpb(protobuf_unittest::TestMap<hpp::proto::non_owning_traits> &msg, std::span<const std::byte> input,
                  hpp::proto::alloc_option_t option) {
  return hpp::proto::read_binpb(msg, input, option);
}

status read_binpb(protobuf_unittest::TestMap<hpp::proto::default_traits> &msg,
                  std::span<std::span<const std::byte>> input) {
  return hpp::proto::read_binpb(msg, input);
}

status read_binpb(protobuf_unittest::TestMap<hpp::proto::non_owning_traits> &msg,
                  std::span<std::span<const std::byte>> input, hpp::proto::alloc_option_t option) {
  return hpp::proto::read_binpb(msg, input, option);
}

status read_binpb(proto2_unittest::TestWellKnownTypes<hpp::proto::default_traits> &msg,
                  std::span<const std::byte> input) {
  return hpp::proto::read_binpb(msg, input);
}

status read_binpb(proto2_unittest::TestWellKnownTypes<hpp::proto::non_owning_traits> &msg,
                  std::span<const std::byte> input, hpp::proto::alloc_option_t option) {
  return hpp::proto::read_binpb(msg, input, option);
}

status read_binpb(proto2_unittest::TestWellKnownTypes<hpp::proto::default_traits> &msg,
                  std::span<std::span<const std::byte>> input) {
  return hpp::proto::read_binpb(msg, input);
}

status read_binpb(proto2_unittest::TestWellKnownTypes<hpp::proto::non_owning_traits> &msg,
                  std::span<std::span<const std::byte>> input, hpp::proto::alloc_option_t option) {
  return hpp::proto::read_binpb(msg, input, option);
}

status read_binpb(hpp::proto::message_value_mref &msg, std::span<const std::byte> input) {
  return hpp::proto::read_binpb(msg, input);
}

status read_binpb(hpp::proto::message_value_mref &msg, std::span<std::span<const std::byte>> input) {
  return hpp::proto::read_binpb(msg, input);
}

status write_binpb(const proto3_unittest::TestAllTypes<hpp::proto::default_traits> &msg,
                   std::vector<std::byte> &buffer) {
  return hpp::proto::write_binpb(msg, buffer);
}

status write_binpb(const proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                   std::vector<std::byte> &buffer) {
  return hpp::proto::write_binpb(msg, buffer);
}

status write_binpb(const protobuf_unittest::TestAllTypes<hpp::proto::default_traits> &msg,
                   std::vector<std::byte> &buffer) {
  return hpp::proto::write_binpb(msg, buffer);
}

status write_binpb(const protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                   std::vector<std::byte> &buffer) {
  return hpp::proto::write_binpb(msg, buffer);
}

status write_binpb(const protobuf_unittest::TestMap<hpp::proto::default_traits> &msg, std::vector<std::byte> &buffer) {
  return hpp::proto::write_binpb(msg, buffer);
}

status write_binpb(const protobuf_unittest::TestMap<hpp::proto::non_owning_traits> &msg,
                   std::vector<std::byte> &buffer) {
  return hpp::proto::write_binpb(msg, buffer);
}

status write_binpb(const proto2_unittest::TestWellKnownTypes<hpp::proto::default_traits> &msg,
                   std::vector<std::byte> &buffer) {
  return hpp::proto::write_binpb(msg, buffer);
}

status write_binpb(const proto2_unittest::TestWellKnownTypes<hpp::proto::non_owning_traits> &msg,
                   std::vector<std::byte> &buffer) {
  return hpp::proto::write_binpb(msg, buffer);
}

status write_binpb(const hpp::proto::message_value_mref &msg, std::vector<std::byte> &buffer) {
  return hpp::proto::write_binpb(msg, buffer);
}
} // namespace util
