#include <google/protobuf/map_unittest.glz.hpp>
#include <google/protobuf/unittest.glz.hpp>
#include <google/protobuf/unittest_proto3.glz.hpp>
#include <google/protobuf/unittest_well_known_types.glz.hpp>
#include <hpp_proto/dynamic_message/json.hpp>

#include "common.hpp"
#include "json_extern.hpp"

namespace util {
using hpp_proto::json_status;
json_status read_json(proto3_unittest::TestAllTypes<hpp_proto::stable_traits> &msg, std::string_view json_view,
                      hpp_proto::alloc_option_t) {
  return hpp_proto::read_json(msg, json_view);
}

json_status read_json(proto3_unittest::TestAllTypes<hpp_proto::non_owning_traits> &msg, std::string_view json_view,
                      hpp_proto::alloc_option_t option) {
  return hpp_proto::read_json(msg, json_view, option);
}

json_status write_json(const proto3_unittest::TestAllTypes<hpp_proto::stable_traits> &msg, std::string &json_buffer) {
  return hpp_proto::write_json(msg, json_buffer);
}

json_status write_json(const proto3_unittest::TestAllTypes<hpp_proto::non_owning_traits> &msg,
                       std::string &json_buffer) {
  return hpp_proto::write_json(msg, json_buffer);
}

json_status read_json(protobuf_unittest::TestAllTypes<hpp_proto::stable_traits> &msg, std::string_view json_view,
                      hpp_proto::alloc_option_t) {
  return hpp_proto::read_json(msg, json_view);
}

json_status read_json(protobuf_unittest::TestAllTypes<hpp_proto::non_owning_traits> &msg, std::string_view json_view,
                      hpp_proto::alloc_option_t option) {
  return hpp_proto::read_json(msg, json_view, option);
}

json_status write_json(const protobuf_unittest::TestAllTypes<hpp_proto::stable_traits> &msg,
                       std::string &json_buffer) {
  return hpp_proto::write_json(msg, json_buffer);
}

json_status write_json(const protobuf_unittest::TestAllTypes<hpp_proto::non_owning_traits> &msg,
                       std::string &json_buffer) {
  return hpp_proto::write_json(msg, json_buffer);
}

json_status read_json(protobuf_unittest::TestMap<hpp_proto::stable_traits> &msg, std::string_view json_view,
                      hpp_proto::alloc_option_t) {
  return hpp_proto::read_json(msg, json_view);
}

json_status read_json(protobuf_unittest::TestMap<hpp_proto::non_owning_traits> &msg, std::string_view json_view,
                      hpp_proto::alloc_option_t option) {
  return hpp_proto::read_json(msg, json_view, option);
}

json_status write_json(const protobuf_unittest::TestMap<hpp_proto::stable_traits> &msg, std::string &json_buffer) {
  return hpp_proto::write_json(msg, json_buffer);
}

json_status write_json(const protobuf_unittest::TestMap<hpp_proto::non_owning_traits> &msg, std::string &json_buffer) {
  return hpp_proto::write_json(msg, json_buffer);
}

json_status read_json(proto2_unittest::TestWellKnownTypes<hpp_proto::stable_traits> &msg, std::string_view json_view,
                      hpp_proto::alloc_option_t) {
  return hpp_proto::read_json(msg, json_view, hpp_proto::use_factory{factory});
}

json_status read_json(proto2_unittest::TestWellKnownTypes<hpp_proto::non_owning_traits> &msg,
                      std::string_view json_view, hpp_proto::alloc_option_t option) {
  return hpp_proto::read_json(msg, json_view, option, hpp_proto::use_factory{factory});
}

json_status write_json(const proto2_unittest::TestWellKnownTypes<hpp_proto::stable_traits> &msg,
                       std::string &json_buffer) {
  return hpp_proto::write_json(msg, json_buffer, hpp_proto::use_factory{factory});
}

json_status write_json(const proto2_unittest::TestWellKnownTypes<hpp_proto::non_owning_traits> &msg,
                       std::string &json_buffer) {
  return hpp_proto::write_json(msg, json_buffer, hpp_proto::use_factory{factory});
}

json_status read_json(hpp_proto::message_value_mref &msg, std::string_view json_view, hpp_proto::alloc_option_t) {
  return hpp_proto::read_json(msg, json_view);
}

json_status write_json(const hpp_proto::message_value_mref &msg, std::string &json_buffer) {
  return hpp_proto::write_json(msg, json_buffer);
}
} // namespace util
