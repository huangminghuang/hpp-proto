#pragma once

#include <hpp_proto/field_types.h>
#include "google/protobuf/descriptor.msg.hpp"

namespace google::protobuf::compiler {

using namespace hpp::proto::literals;
struct Version {
  int32_t major = {};
  int32_t minor = {};
  int32_t patch = {};
  std::string suffix = {};

  bool operator == (const Version&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARATOR

  auto operator <=> (const Version&) const = default;
#endif
};

struct CodeGeneratorResponse {
  enum class Feature {
    FEATURE_NONE = 0,
    FEATURE_PROTO3_OPTIONAL = 1,
    FEATURE_SUPPORTS_EDITIONS = 2 
  };

  struct File {
    std::string name = {};
    std::string insertion_point = {};
    std::string content = {};
    std::optional<GeneratedCodeInfo> generated_code_info;

    bool operator == (const File&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARATOR

    auto operator <=> (const File&) const = default;
#endif
  };

  std::string error = {};
  uint64_t supported_features = {};
  int32_t minimum_edition = {};
  int32_t maximum_edition = {};
  std::vector<File> file;

  bool operator == (const CodeGeneratorResponse&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARATOR

  auto operator <=> (const CodeGeneratorResponse&) const = default;
#endif
};

struct CodeGeneratorRequest {
  std::vector<std::string> file_to_generate;
  std::string parameter = {};
  std::vector<FileDescriptorProto> proto_file;
  std::vector<FileDescriptorProto> source_file_descriptors;
  std::optional<Version> compiler_version;

  bool operator == (const CodeGeneratorRequest&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARATOR

  auto operator <=> (const CodeGeneratorRequest&) const = default;
#endif
};

constexpr auto message_type_url(const Version&) { return "type.googleapis.com/google.protobuf.compiler.Version"_cts; }
constexpr auto message_type_url(const CodeGeneratorResponse::File&) { return "type.googleapis.com/google.protobuf.compiler.CodeGeneratorResponse.File"_cts; }
constexpr auto message_type_url(const CodeGeneratorResponse&) { return "type.googleapis.com/google.protobuf.compiler.CodeGeneratorResponse"_cts; }
constexpr auto message_type_url(const CodeGeneratorRequest&) { return "type.googleapis.com/google.protobuf.compiler.CodeGeneratorRequest"_cts; }
} // namespace google::protobuf::compiler
