#pragma once

#include <hpp_proto/hpp_proto_json.h>
#include <google/protobuf/descriptor.glz.hpp>
#include <google/protobuf/compiler/plugin.msg.hpp>

template <>
struct glz::meta<google::protobuf::compiler::Version> {
  using T = google::protobuf::compiler::Version;
  static constexpr auto value = object(
    "major", &T::major,
    "minor", &T::minor,
    "patch", &T::patch,
    "suffix", &T::suffix);
};

template <>
struct glz::meta<google::protobuf::compiler::CodeGeneratorRequest> {
  using T = google::protobuf::compiler::CodeGeneratorRequest;
  static constexpr auto value = object(
    "fileToGenerate", &T::file_to_generate,
    "parameter", &T::parameter,
    "protoFile", &T::proto_file,
    "compilerVersion", &T::compiler_version);
};

template <>
struct glz::meta<google::protobuf::compiler::CodeGeneratorResponse> {
  using T = google::protobuf::compiler::CodeGeneratorResponse;
  static constexpr auto value = object(
    "error", &T::error,
    "supportedFeatures", [](auto &&self) -> auto& { return hpp::proto::wrap_int64(self.supported_features); },
    "file", &T::file);
};

template <>
struct glz::meta<google::protobuf::compiler::CodeGeneratorResponse::File> {
  using T = google::protobuf::compiler::CodeGeneratorResponse::File;
  static constexpr auto value = object(
    "name", &T::name,
    "insertionPoint", &T::insertion_point,
    "content", &T::content,
    "generatedCodeInfo", &T::generated_code_info);
};

template <>
struct glz::meta<google::protobuf::compiler::CodeGeneratorResponse::Feature> {
  using enum google::protobuf::compiler::CodeGeneratorResponse::Feature;
  static constexpr auto value = enumerate(
    "FEATURE_NONE", FEATURE_NONE,
    "FEATURE_PROTO3_OPTIONAL", FEATURE_PROTO3_OPTIONAL);
};

