#pragma once

#include <hpp_proto/msg_base.h>
#include <google/protobuf/descriptor.msg.hpp>

namespace google::protobuf::compiler {

using hpp::proto::literals::operator ""_hppproto_s;
struct Version {
  hpp::proto::optional<int32_t> major;
  hpp::proto::optional<int32_t> minor;
  hpp::proto::optional<int32_t> patch;
  hpp::proto::optional<std::string> suffix;

  bool operator == (const Version&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const Version&) const = default;
#endif
};

struct CodeGeneratorResponse {
  enum class Feature {
    FEATURE_NONE = 0,
    FEATURE_PROTO3_OPTIONAL = 1 
  };

  struct File {
    hpp::proto::optional<std::string> name;
    hpp::proto::optional<std::string> insertion_point;
    hpp::proto::optional<std::string> content;
    std::optional<GeneratedCodeInfo> generated_code_info;

    bool operator == (const File&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

    auto operator <=> (const File&) const = default;
#endif
  };

  hpp::proto::optional<std::string> error;
  hpp::proto::optional<uint64_t> supported_features;
  std::vector<File> file;

  bool operator == (const CodeGeneratorResponse&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const CodeGeneratorResponse&) const = default;
#endif
};

struct CodeGeneratorRequest {
  std::vector<std::string> file_to_generate;
  hpp::proto::optional<std::string> parameter;
  std::vector<FileDescriptorProto> proto_file;
  std::optional<Version> compiler_version;

  bool operator == (const CodeGeneratorRequest&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const CodeGeneratorRequest&) const = default;
#endif
};

} // namespace google::protobuf::compiler
