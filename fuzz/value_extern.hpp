#pragma once

#include <google/protobuf/struct.msg.hpp>

#include <hpp_proto/field_types.hpp>

#ifndef GOOGLE_PROTOBUF_VALUE_INSTANTIATED
// Clang requires this instantiation in every TU.
template struct google::protobuf::Value<hpp_proto::stable_traits>;
template struct google::protobuf::Value<hpp_proto::non_owning_traits>;
#define GOOGLE_PROTOBUF_VALUE_INSTANTIATED
#endif
