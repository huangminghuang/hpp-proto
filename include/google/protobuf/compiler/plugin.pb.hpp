// Generated by the protocol buffer compiler.  DO NOT EDIT!
// NO CHECKED-IN PROTOBUF GENCODE
// generation command line:
//    protoc --plugin=protoc-gen-hpp=/Users/huang-minghuang/opensource/hpp-proto/build/debug/protoc-plugin/protoc-gen-hpp --hpp_out proto2_explicit_presence=.google.protobuf.FieldDescriptorProto.oneof_index,proto2_explicit_presence=.google.protobuf.FieldOptions.packed:${out_dir} google/protobuf/compiler/plugin.proto

#pragma once

#include <hpp_proto/pb_serializer.hpp>
#include "google/protobuf/compiler/plugin.msg.hpp"
#include "google/protobuf/descriptor.pb.hpp"


namespace google::protobuf::compiler {

auto pb_meta(const Version &) -> std::tuple<
  hpp::proto::field_meta<1, &Version::major, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &Version::minor, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<3, &Version::patch, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<4, &Version::suffix, hpp::proto::field_option::none>>;

auto pb_meta(const CodeGeneratorRequest &) -> std::tuple<
  hpp::proto::field_meta<1, &CodeGeneratorRequest::file_to_generate, hpp::proto::field_option::unpacked_repeated>,
  hpp::proto::field_meta<2, &CodeGeneratorRequest::parameter, hpp::proto::field_option::none>,
  hpp::proto::field_meta<15, &CodeGeneratorRequest::proto_file, hpp::proto::field_option::unpacked_repeated>,
  hpp::proto::field_meta<17, &CodeGeneratorRequest::source_file_descriptors, hpp::proto::field_option::unpacked_repeated>,
  hpp::proto::field_meta<3, &CodeGeneratorRequest::compiler_version, hpp::proto::field_option::explicit_presence>>;

auto pb_meta(const CodeGeneratorResponse &) -> std::tuple<
  hpp::proto::field_meta<1, &CodeGeneratorResponse::error, hpp::proto::field_option::none>,
  hpp::proto::field_meta<2, &CodeGeneratorResponse::supported_features, hpp::proto::field_option::none, hpp::proto::vuint64_t>,
  hpp::proto::field_meta<3, &CodeGeneratorResponse::minimum_edition, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<4, &CodeGeneratorResponse::maximum_edition, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<15, &CodeGeneratorResponse::file, hpp::proto::field_option::unpacked_repeated>>;

auto pb_meta(const CodeGeneratorResponse::File &) -> std::tuple<
  hpp::proto::field_meta<1, &CodeGeneratorResponse::File::name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<2, &CodeGeneratorResponse::File::insertion_point, hpp::proto::field_option::none>,
  hpp::proto::field_meta<15, &CodeGeneratorResponse::File::content, hpp::proto::field_option::none>,
  hpp::proto::field_meta<16, &CodeGeneratorResponse::File::generated_code_info, hpp::proto::field_option::explicit_presence>>;

} // namespace google::protobuf::compiler
