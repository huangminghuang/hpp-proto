#pragma once

#include <hpp_proto/pb_serializer.h>
#include <google/protobuf/compiler/plugin.msg.hpp>
#include <google/protobuf/descriptor.pb.hpp>


namespace google::protobuf::compiler {

auto pb_meta(const Version &) -> std::tuple<
  hpp::proto::field_meta<1, &Version::major, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &Version::minor, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<3, &Version::patch, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<4, &Version::suffix, hpp::proto::encoding_rule::defaulted>>;

constexpr auto pb_message_name(const Version&) { return "google.protobuf.compiler.Version"_cts; }

auto pb_meta(const CodeGeneratorRequest &) -> std::tuple<
  hpp::proto::field_meta<1, &CodeGeneratorRequest::file_to_generate, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<2, &CodeGeneratorRequest::parameter, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<15, &CodeGeneratorRequest::proto_file, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<17, &CodeGeneratorRequest::source_file_descriptors, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<3, &CodeGeneratorRequest::compiler_version, hpp::proto::encoding_rule::explicit_presence>>;

constexpr auto pb_message_name(const CodeGeneratorRequest&) { return "google.protobuf.compiler.CodeGeneratorRequest"_cts; }

auto pb_meta(const CodeGeneratorResponse &) -> std::tuple<
  hpp::proto::field_meta<1, &CodeGeneratorResponse::error, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, &CodeGeneratorResponse::supported_features, hpp::proto::encoding_rule::defaulted, hpp::proto::vuint64_t>,
  hpp::proto::field_meta<15, &CodeGeneratorResponse::file, hpp::proto::encoding_rule::unpacked_repeated>>;

constexpr auto pb_message_name(const CodeGeneratorResponse&) { return "google.protobuf.compiler.CodeGeneratorResponse"_cts; }

auto pb_meta(const CodeGeneratorResponse::File &) -> std::tuple<
  hpp::proto::field_meta<1, &CodeGeneratorResponse::File::name, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, &CodeGeneratorResponse::File::insertion_point, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<15, &CodeGeneratorResponse::File::content, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<16, &CodeGeneratorResponse::File::generated_code_info, hpp::proto::encoding_rule::explicit_presence>>;

constexpr auto pb_message_name(const CodeGeneratorResponse::File&) { return "google.protobuf.compiler.CodeGeneratorResponse.File"_cts; }

} // namespace google::protobuf::compiler
