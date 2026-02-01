
#pragma once

#include <hpp_proto/dynamic_message/json.hpp>
#include <hpp_proto/json.hpp>

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
// Non-template overloads keep JSON template instantiations in json_extern.cpp only,
// avoiding glz.hpp-driven codegen in other translation units.
hpp::proto::json_status read_json(proto3_unittest::TestAllTypes<hpp::proto::stable_traits> &msg,
                                  std::string_view json_view, hpp::proto::alloc_option_t);
hpp::proto::json_status read_json(proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                                  std::string_view json_view, hpp::proto::alloc_option_t option);
hpp::proto::json_status write_json(const proto3_unittest::TestAllTypes<hpp::proto::stable_traits> &msg,
                                   std::string &json_buffer);
hpp::proto::json_status write_json(const proto3_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                                   std::string &json_buffer);
hpp::proto::json_status read_json(protobuf_unittest::TestAllTypes<hpp::proto::stable_traits> &msg,
                                  std::string_view json_view, hpp::proto::alloc_option_t);
hpp::proto::json_status read_json(protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                                  std::string_view json_view, hpp::proto::alloc_option_t option);
hpp::proto::json_status write_json(const protobuf_unittest::TestAllTypes<hpp::proto::stable_traits> &msg,
                                   std::string &json_buffer);
hpp::proto::json_status write_json(const protobuf_unittest::TestAllTypes<hpp::proto::non_owning_traits> &msg,
                                   std::string &json_buffer);
hpp::proto::json_status read_json(protobuf_unittest::TestMap<hpp::proto::stable_traits> &msg,
                                  std::string_view json_view, hpp::proto::alloc_option_t);
hpp::proto::json_status read_json(protobuf_unittest::TestMap<hpp::proto::non_owning_traits> &msg,
                                  std::string_view json_view, hpp::proto::alloc_option_t option);
hpp::proto::json_status write_json(const protobuf_unittest::TestMap<hpp::proto::stable_traits> &msg,
                                   std::string &json_buffer);
hpp::proto::json_status write_json(const protobuf_unittest::TestMap<hpp::proto::non_owning_traits> &msg,
                                   std::string &json_buffer);
hpp::proto::json_status read_json(proto2_unittest::TestWellKnownTypes<hpp::proto::stable_traits> &msg,
                                  std::string_view json_view, hpp::proto::alloc_option_t);
hpp::proto::json_status read_json(proto2_unittest::TestWellKnownTypes<hpp::proto::non_owning_traits> &msg,
                                  std::string_view json_view, hpp::proto::alloc_option_t option);
hpp::proto::json_status write_json(const proto2_unittest::TestWellKnownTypes<hpp::proto::stable_traits> &msg,
                                   std::string &json_buffer);
hpp::proto::json_status write_json(const proto2_unittest::TestWellKnownTypes<hpp::proto::non_owning_traits> &msg,
                                   std::string &json_buffer);
hpp::proto::json_status read_json(hpp::proto::message_value_mref &msg, std::string_view json_view,
                                  hpp::proto::alloc_option_t);
hpp::proto::json_status write_json(const hpp::proto::message_value_mref &msg, std::string &json_buffer);
} // namespace util
