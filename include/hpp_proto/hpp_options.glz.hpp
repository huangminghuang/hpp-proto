// clang-format off
// Generated by the protocol buffer compiler.  DO NOT EDIT!
// NO CHECKED-IN PROTOBUF GENCODE
// generation command line:
//    protoc --plugin=protoc-gen-hpp=/path/to/protoc-gen-hpp
//           --hpp_out :${out_dir}
//           hpp_proto/hpp_options.proto

#pragma once

#include <hpp_proto/json_serializer.hpp>
#include "google/protobuf/descriptor.glz.hpp"
#include "hpp_proto/hpp_options.msg.hpp"

template <>
struct glz::meta<hpp::proto::FileOptions> {
  using T = hpp::proto::FileOptions;
  static constexpr auto value = object(
    "nonOwning", hpp::proto::as_optional_ref<&T::non_owning>,
    "namespacePrefix", &T::namespace_prefix);
};

template <>
struct glz::meta<hpp::proto::MessageOptions> {
  using T = hpp::proto::MessageOptions;
  static constexpr auto value = object(
    "nonOwning", hpp::proto::as_optional_ref<&T::non_owning>);
};

template <>
struct glz::meta<hpp::proto::FieldOptions> {
  using T = hpp::proto::FieldOptions;
  static constexpr auto value = object(
    "nonOwning", hpp::proto::as_optional_ref<&T::non_owning>);
};

// clang-format on
