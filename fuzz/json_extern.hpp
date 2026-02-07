
#pragma once

#include <hpp_proto/dynamic_message/json.hpp>
#include <hpp_proto/json.hpp>

#include <google/protobuf/map_unittest.msg.hpp>
#include <google/protobuf/unittest.msg.hpp>
#include <google/protobuf/unittest_proto3.msg.hpp>
#include <google/protobuf/unittest_well_known_types.msg.hpp>

#include "common.hpp"
#include "value_extern.hpp"

namespace hpp_proto {
using alloc_option_t = alloc_from<std::pmr::monotonic_buffer_resource>;

} // namespace hpp_proto

namespace util {
// Non-template overloads keep JSON template instantiations in json_extern.cpp only,
// avoiding glz.hpp-driven codegen in other translation units.
hpp_proto::json_status read_json(proto3_unittest::TestAllTypes<hpp_proto::stable_traits> &msg,
                                  std::string_view json_view, hpp_proto::alloc_option_t);
hpp_proto::json_status read_json(proto3_unittest::TestAllTypes<hpp_proto::non_owning_traits> &msg,
                                  std::string_view json_view, hpp_proto::alloc_option_t option);
hpp_proto::json_status write_json(const proto3_unittest::TestAllTypes<hpp_proto::stable_traits> &msg,
                                   std::string &json_buffer);
hpp_proto::json_status write_json(const proto3_unittest::TestAllTypes<hpp_proto::non_owning_traits> &msg,
                                   std::string &json_buffer);
hpp_proto::json_status read_json(protobuf_unittest::TestAllTypes<hpp_proto::stable_traits> &msg,
                                  std::string_view json_view, hpp_proto::alloc_option_t);
hpp_proto::json_status read_json(protobuf_unittest::TestAllTypes<hpp_proto::non_owning_traits> &msg,
                                  std::string_view json_view, hpp_proto::alloc_option_t option);
hpp_proto::json_status write_json(const protobuf_unittest::TestAllTypes<hpp_proto::stable_traits> &msg,
                                   std::string &json_buffer);
hpp_proto::json_status write_json(const protobuf_unittest::TestAllTypes<hpp_proto::non_owning_traits> &msg,
                                   std::string &json_buffer);
hpp_proto::json_status read_json(protobuf_unittest::TestMap<hpp_proto::stable_traits> &msg,
                                  std::string_view json_view, hpp_proto::alloc_option_t);
hpp_proto::json_status read_json(protobuf_unittest::TestMap<hpp_proto::non_owning_traits> &msg,
                                  std::string_view json_view, hpp_proto::alloc_option_t option);
hpp_proto::json_status write_json(const protobuf_unittest::TestMap<hpp_proto::stable_traits> &msg,
                                   std::string &json_buffer);
hpp_proto::json_status write_json(const protobuf_unittest::TestMap<hpp_proto::non_owning_traits> &msg,
                                   std::string &json_buffer);
hpp_proto::json_status read_json(proto2_unittest::TestWellKnownTypes<hpp_proto::stable_traits> &msg,
                                  std::string_view json_view, hpp_proto::alloc_option_t);
hpp_proto::json_status read_json(proto2_unittest::TestWellKnownTypes<hpp_proto::non_owning_traits> &msg,
                                  std::string_view json_view, hpp_proto::alloc_option_t option);
hpp_proto::json_status write_json(const proto2_unittest::TestWellKnownTypes<hpp_proto::stable_traits> &msg,
                                   std::string &json_buffer);
hpp_proto::json_status write_json(const proto2_unittest::TestWellKnownTypes<hpp_proto::non_owning_traits> &msg,
                                   std::string &json_buffer);
hpp_proto::json_status read_json(hpp_proto::message_value_mref &msg, std::string_view json_view,
                                  hpp_proto::alloc_option_t);
hpp_proto::json_status write_json(const hpp_proto::message_value_mref &msg, std::string &json_buffer);
} // namespace util
