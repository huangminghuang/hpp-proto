// Generated by the protocol buffer compiler.  DO NOT EDIT!
// NO CHECKED-IN PROTOBUF GENCODE
// generation command line:
//    protoc --plugin=protoc-gen-hpp=/Users/huang-minghuang/opensource/hpp-proto/build/debug/protoc-plugin/protoc-gen-hpp --hpp_out proto2_explicit_presence=.google.protobuf.FieldDescriptorProto.oneof_index,proto2_explicit_presence=.google.protobuf.FieldOptions.packed:${out_dir} google/protobuf/compiler/plugin.proto

#pragma once

#include <hpp_proto/json_serializer.h>
#include "google/protobuf/descriptor.glz.hpp"
#include "google/protobuf/compiler/plugin.msg.hpp"

template <>
struct glz::meta<google::protobuf::compiler::Version> {
  using T = google::protobuf::compiler::Version;
  static constexpr auto value = object(
    "major", hpp::proto::as_optional_ref<&T::major>,
    "minor", hpp::proto::as_optional_ref<&T::minor>,
    "patch", hpp::proto::as_optional_ref<&T::patch>,
    "suffix", hpp::proto::as_optional_ref<&T::suffix>);
};

template <>
struct glz::meta<google::protobuf::compiler::CodeGeneratorRequest> {
  using T = google::protobuf::compiler::CodeGeneratorRequest;
  static constexpr auto value = object(
    "fileToGenerate", hpp::proto::as_optional_ref<&T::file_to_generate>,
    "parameter", hpp::proto::as_optional_ref<&T::parameter>,
    "protoFile", hpp::proto::as_optional_ref<&T::proto_file>,
    "sourceFileDescriptors", hpp::proto::as_optional_ref<&T::source_file_descriptors>,
    "compilerVersion", &T::compiler_version);
};

template <>
struct glz::meta<google::protobuf::compiler::CodeGeneratorResponse> {
  using T = google::protobuf::compiler::CodeGeneratorResponse;
  static constexpr auto value = object(
    "error", hpp::proto::as_optional_ref<&T::error>,
    "supportedFeatures", hpp::proto::as_optional_ref<&T::supported_features>,
    "file", hpp::proto::as_optional_ref<&T::file>);
};

template <>
struct glz::meta<google::protobuf::compiler::CodeGeneratorResponse::File> {
  using T = google::protobuf::compiler::CodeGeneratorResponse::File;
  static constexpr auto value = object(
    "name", hpp::proto::as_optional_ref<&T::name>,
    "insertionPoint", hpp::proto::as_optional_ref<&T::insertion_point>,
    "content", hpp::proto::as_optional_ref<&T::content>,
    "generatedCodeInfo", &T::generated_code_info);
};

template <>
struct glz::meta<google::protobuf::compiler::CodeGeneratorResponse::Feature> {
  using enum google::protobuf::compiler::CodeGeneratorResponse::Feature;
  static constexpr auto value = enumerate(
    "FEATURE_NONE", FEATURE_NONE,
    "FEATURE_PROTO3_OPTIONAL", FEATURE_PROTO3_OPTIONAL,
    "FEATURE_SUPPORTS_EDITIONS", FEATURE_SUPPORTS_EDITIONS);
};

