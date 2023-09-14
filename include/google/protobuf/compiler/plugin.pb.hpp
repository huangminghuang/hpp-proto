#pragma once

#include <hpp_proto/pb_serializer.h>
#include <google/protobuf/compiler/plugin.msg.hpp>
#include <google/protobuf/descriptor.pb.hpp>


namespace google::protobuf::compiler {

using namespace zpp::bits::literals;

auto pb_meta(const Version &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<4, hpp::proto::encoding_rule::defaulted>>;

auto serialize(const Version&) -> zpp::bits::members<4>;

inline const char* pb_url(const Version&) { return "type.googleapis.com/google.protobuf.compiler.Version"; }

constexpr auto pb_message_name(const Version&) { return "google.protobuf.compiler.Version"_cts; }

auto pb_meta(const CodeGeneratorRequest &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<15, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<17, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::explicit_presence>>;

auto serialize(const CodeGeneratorRequest&) -> zpp::bits::members<5>;

inline const char* pb_url(const CodeGeneratorRequest&) { return "type.googleapis.com/google.protobuf.compiler.CodeGeneratorRequest"; }

constexpr auto pb_message_name(const CodeGeneratorRequest&) { return "google.protobuf.compiler.CodeGeneratorRequest"_cts; }

auto pb_meta(const CodeGeneratorResponse &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted, zpp::bits::vuint64_t>,
  hpp::proto::field_meta<15, hpp::proto::encoding_rule::unpacked_repeated>>;

auto serialize(const CodeGeneratorResponse&) -> zpp::bits::members<3>;

inline const char* pb_url(const CodeGeneratorResponse&) { return "type.googleapis.com/google.protobuf.compiler.CodeGeneratorResponse"; }

constexpr auto pb_message_name(const CodeGeneratorResponse&) { return "google.protobuf.compiler.CodeGeneratorResponse"_cts; }

auto pb_meta(const CodeGeneratorResponse::File &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<15, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<16, hpp::proto::encoding_rule::explicit_presence>>;

auto serialize(const CodeGeneratorResponse::File&) -> zpp::bits::members<4>;

inline const char* pb_url(const CodeGeneratorResponse::File&) { return "type.googleapis.com/google.protobuf.compiler.CodeGeneratorResponse.File"; }

constexpr auto pb_message_name(const CodeGeneratorResponse::File&) { return "google.protobuf.compiler.CodeGeneratorResponse.File"_cts; }

} // namespace google::protobuf::compiler
