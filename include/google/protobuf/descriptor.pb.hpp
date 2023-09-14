#pragma once

#include <hpp_proto/pb_serializer.h>
#include <google/protobuf/descriptor.msg.hpp>


namespace google::protobuf {

using namespace zpp::bits::literals;

auto pb_meta(const FileDescriptorSet &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::unpacked_repeated>>;

auto serialize(const FileDescriptorSet&) -> zpp::bits::members<1>;

inline const char* pb_url(const FileDescriptorSet&) { return "type.googleapis.com/google.protobuf.FileDescriptorSet"; }

constexpr auto pb_message_name(const FileDescriptorSet&) { return "google.protobuf.FileDescriptorSet"_cts; }

auto pb_meta(const FileDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<10, hpp::proto::encoding_rule::unpacked_repeated, zpp::bits::vint64_t>,
  hpp::proto::field_meta<11, hpp::proto::encoding_rule::unpacked_repeated, zpp::bits::vint64_t>,
  hpp::proto::field_meta<4, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<5, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<6, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<7, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<8, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<9, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<12, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<13, hpp::proto::encoding_rule::defaulted>>;

auto serialize(const FileDescriptorProto&) -> zpp::bits::members<13>;

inline const char* pb_url(const FileDescriptorProto&) { return "type.googleapis.com/google.protobuf.FileDescriptorProto"; }

constexpr auto pb_message_name(const FileDescriptorProto&) { return "google.protobuf.FileDescriptorProto"_cts; }

auto pb_meta(const DescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<6, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<4, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<5, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<8, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<7, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<9, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<10, hpp::proto::encoding_rule::unpacked_repeated>>;

auto serialize(const DescriptorProto&) -> zpp::bits::members<10>;

inline const char* pb_url(const DescriptorProto&) { return "type.googleapis.com/google.protobuf.DescriptorProto"; }

constexpr auto pb_message_name(const DescriptorProto&) { return "google.protobuf.DescriptorProto"_cts; }

auto pb_meta(const DescriptorProto::ExtensionRange &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::explicit_presence>>;

auto serialize(const DescriptorProto::ExtensionRange&) -> zpp::bits::members<3>;

inline const char* pb_url(const DescriptorProto::ExtensionRange&) { return "type.googleapis.com/google.protobuf.DescriptorProto.ExtensionRange"; }

constexpr auto pb_message_name(const DescriptorProto::ExtensionRange&) { return "google.protobuf.DescriptorProto.ExtensionRange"_cts; }

auto pb_meta(const DescriptorProto::ReservedRange &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>>;

auto serialize(const DescriptorProto::ReservedRange&) -> zpp::bits::members<2>;

inline const char* pb_url(const DescriptorProto::ReservedRange&) { return "type.googleapis.com/google.protobuf.DescriptorProto.ReservedRange"; }

constexpr auto pb_message_name(const DescriptorProto::ReservedRange&) { return "google.protobuf.DescriptorProto.ReservedRange"_cts; }

auto pb_meta(const ExtensionRangeOptions &) -> std::tuple<
  hpp::proto::field_meta<999, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<50, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::ExtensionRangeOptions::VerificationState::UNVERIFIED>,
  hpp::proto::field_meta<UINT32_MAX>>;

auto serialize(const ExtensionRangeOptions&) -> zpp::bits::members<5>;

inline const char* pb_url(const ExtensionRangeOptions&) { return "type.googleapis.com/google.protobuf.ExtensionRangeOptions"; }

constexpr auto pb_message_name(const ExtensionRangeOptions&) { return "google.protobuf.ExtensionRangeOptions"_cts; }

auto pb_meta(const ExtensionRangeOptions::Declaration &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<5, hpp::proto::encoding_rule::defaulted, bool>,
  hpp::proto::field_meta<6, hpp::proto::encoding_rule::defaulted, bool>>;

auto serialize(const ExtensionRangeOptions::Declaration&) -> zpp::bits::members<5>;

inline const char* pb_url(const ExtensionRangeOptions::Declaration&) { return "type.googleapis.com/google.protobuf.ExtensionRangeOptions.Declaration"; }

constexpr auto pb_message_name(const ExtensionRangeOptions::Declaration&) { return "google.protobuf.ExtensionRangeOptions.Declaration"_cts; }

auto pb_meta(const FieldDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<4, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FieldDescriptorProto::Label::LABEL_OPTIONAL>,
  hpp::proto::field_meta<5, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FieldDescriptorProto::Type::TYPE_DOUBLE>,
  hpp::proto::field_meta<6, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<7, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<9, hpp::proto::encoding_rule::explicit_presence, zpp::bits::vint64_t>,
  hpp::proto::field_meta<10, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<8, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<17, hpp::proto::encoding_rule::defaulted, bool>>;

auto serialize(const FieldDescriptorProto&) -> zpp::bits::members<11>;

inline const char* pb_url(const FieldDescriptorProto&) { return "type.googleapis.com/google.protobuf.FieldDescriptorProto"; }

constexpr auto pb_message_name(const FieldDescriptorProto&) { return "google.protobuf.FieldDescriptorProto"_cts; }

auto pb_meta(const OneofDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::explicit_presence>>;

auto serialize(const OneofDescriptorProto&) -> zpp::bits::members<2>;

inline const char* pb_url(const OneofDescriptorProto&) { return "type.googleapis.com/google.protobuf.OneofDescriptorProto"; }

constexpr auto pb_message_name(const OneofDescriptorProto&) { return "google.protobuf.OneofDescriptorProto"_cts; }

auto pb_meta(const EnumDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<4, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<5, hpp::proto::encoding_rule::unpacked_repeated>>;

auto serialize(const EnumDescriptorProto&) -> zpp::bits::members<5>;

inline const char* pb_url(const EnumDescriptorProto&) { return "type.googleapis.com/google.protobuf.EnumDescriptorProto"; }

constexpr auto pb_message_name(const EnumDescriptorProto&) { return "google.protobuf.EnumDescriptorProto"_cts; }

auto pb_meta(const EnumDescriptorProto::EnumReservedRange &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>>;

auto serialize(const EnumDescriptorProto::EnumReservedRange&) -> zpp::bits::members<2>;

inline const char* pb_url(const EnumDescriptorProto::EnumReservedRange&) { return "type.googleapis.com/google.protobuf.EnumDescriptorProto.EnumReservedRange"; }

constexpr auto pb_message_name(const EnumDescriptorProto::EnumReservedRange&) { return "google.protobuf.EnumDescriptorProto.EnumReservedRange"_cts; }

auto pb_meta(const EnumValueDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::explicit_presence>>;

auto serialize(const EnumValueDescriptorProto&) -> zpp::bits::members<3>;

inline const char* pb_url(const EnumValueDescriptorProto&) { return "type.googleapis.com/google.protobuf.EnumValueDescriptorProto"; }

constexpr auto pb_message_name(const EnumValueDescriptorProto&) { return "google.protobuf.EnumValueDescriptorProto"_cts; }

auto pb_meta(const ServiceDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::explicit_presence>>;

auto serialize(const ServiceDescriptorProto&) -> zpp::bits::members<3>;

inline const char* pb_url(const ServiceDescriptorProto&) { return "type.googleapis.com/google.protobuf.ServiceDescriptorProto"; }

constexpr auto pb_message_name(const ServiceDescriptorProto&) { return "google.protobuf.ServiceDescriptorProto"_cts; }

auto pb_meta(const MethodDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<4, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<5, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<6, hpp::proto::encoding_rule::defaulted, bool, false>>;

auto serialize(const MethodDescriptorProto&) -> zpp::bits::members<6>;

inline const char* pb_url(const MethodDescriptorProto&) { return "type.googleapis.com/google.protobuf.MethodDescriptorProto"; }

constexpr auto pb_message_name(const MethodDescriptorProto&) { return "google.protobuf.MethodDescriptorProto"_cts; }

auto pb_meta(const FileOptions &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<8, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<10, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<20, hpp::proto::encoding_rule::defaulted, bool>,
  hpp::proto::field_meta<27, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<9, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FileOptions::OptimizeMode::SPEED>,
  hpp::proto::field_meta<11, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<16, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<17, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<18, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<42, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<23, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<31, hpp::proto::encoding_rule::defaulted, bool, true>,
  hpp::proto::field_meta<36, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<37, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<39, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<40, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<41, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<44, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<45, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<50, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<999, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX>>;

auto serialize(const FileOptions&) -> zpp::bits::members<23>;

inline const char* pb_url(const FileOptions&) { return "type.googleapis.com/google.protobuf.FileOptions"; }

constexpr auto pb_message_name(const FileOptions&) { return "google.protobuf.FileOptions"_cts; }

auto pb_meta(const MessageOptions &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<7, hpp::proto::encoding_rule::defaulted, bool>,
  hpp::proto::field_meta<11, hpp::proto::encoding_rule::defaulted, bool>,
  hpp::proto::field_meta<12, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<999, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX>>;

auto serialize(const MessageOptions&) -> zpp::bits::members<8>;

inline const char* pb_url(const MessageOptions&) { return "type.googleapis.com/google.protobuf.MessageOptions"; }

constexpr auto pb_message_name(const MessageOptions&) { return "google.protobuf.MessageOptions"_cts; }

auto pb_meta(const FieldOptions &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FieldOptions::CType::STRING>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::explicit_presence, bool>,
  hpp::proto::field_meta<6, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FieldOptions::JSType::JS_NORMAL>,
  hpp::proto::field_meta<5, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<15, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<10, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<16, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<17, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FieldOptions::OptionRetention::RETENTION_UNKNOWN>,
  hpp::proto::field_meta<19, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<20, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<21, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<999, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX>>;

auto serialize(const FieldOptions&) -> zpp::bits::members<14>;

inline const char* pb_url(const FieldOptions&) { return "type.googleapis.com/google.protobuf.FieldOptions"; }

constexpr auto pb_message_name(const FieldOptions&) { return "google.protobuf.FieldOptions"_cts; }

auto pb_meta(const FieldOptions::EditionDefault &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted>>;

auto serialize(const FieldOptions::EditionDefault&) -> zpp::bits::members<2>;

inline const char* pb_url(const FieldOptions::EditionDefault&) { return "type.googleapis.com/google.protobuf.FieldOptions.EditionDefault"; }

constexpr auto pb_message_name(const FieldOptions::EditionDefault&) { return "google.protobuf.FieldOptions.EditionDefault"_cts; }

auto pb_meta(const OneofOptions &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<999, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX>>;

auto serialize(const OneofOptions&) -> zpp::bits::members<3>;

inline const char* pb_url(const OneofOptions&) { return "type.googleapis.com/google.protobuf.OneofOptions"; }

constexpr auto pb_message_name(const OneofOptions&) { return "google.protobuf.OneofOptions"_cts; }

auto pb_meta(const EnumOptions &) -> std::tuple<
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted, bool>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<6, hpp::proto::encoding_rule::defaulted, bool>,
  hpp::proto::field_meta<7, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<999, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX>>;

auto serialize(const EnumOptions&) -> zpp::bits::members<6>;

inline const char* pb_url(const EnumOptions&) { return "type.googleapis.com/google.protobuf.EnumOptions"; }

constexpr auto pb_message_name(const EnumOptions&) { return "google.protobuf.EnumOptions"_cts; }

auto pb_meta(const EnumValueOptions &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<999, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX>>;

auto serialize(const EnumValueOptions&) -> zpp::bits::members<5>;

inline const char* pb_url(const EnumValueOptions&) { return "type.googleapis.com/google.protobuf.EnumValueOptions"; }

constexpr auto pb_message_name(const EnumValueOptions&) { return "google.protobuf.EnumValueOptions"_cts; }

auto pb_meta(const ServiceOptions &) -> std::tuple<
  hpp::proto::field_meta<34, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<33, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<999, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX>>;

auto serialize(const ServiceOptions&) -> zpp::bits::members<4>;

inline const char* pb_url(const ServiceOptions&) { return "type.googleapis.com/google.protobuf.ServiceOptions"; }

constexpr auto pb_message_name(const ServiceOptions&) { return "google.protobuf.ServiceOptions"_cts; }

auto pb_meta(const MethodOptions &) -> std::tuple<
  hpp::proto::field_meta<33, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<34, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::MethodOptions::IdempotencyLevel::IDEMPOTENCY_UNKNOWN>,
  hpp::proto::field_meta<35, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<999, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX>>;

auto serialize(const MethodOptions&) -> zpp::bits::members<5>;

inline const char* pb_url(const MethodOptions&) { return "type.googleapis.com/google.protobuf.MethodOptions"; }

constexpr auto pb_message_name(const MethodOptions&) { return "google.protobuf.MethodOptions"_cts; }

auto pb_meta(const UninterpretedOption &) -> std::tuple<
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<4, hpp::proto::encoding_rule::defaulted, zpp::bits::vuint64_t>,
  hpp::proto::field_meta<5, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<6, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<7, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<8, hpp::proto::encoding_rule::defaulted>>;

auto serialize(const UninterpretedOption&) -> zpp::bits::members<7>;

inline const char* pb_url(const UninterpretedOption&) { return "type.googleapis.com/google.protobuf.UninterpretedOption"; }

constexpr auto pb_message_name(const UninterpretedOption&) { return "google.protobuf.UninterpretedOption"_cts; }

auto pb_meta(const UninterpretedOption::NamePart &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted, bool>>;

auto serialize(const UninterpretedOption::NamePart&) -> zpp::bits::members<2>;

inline const char* pb_url(const UninterpretedOption::NamePart&) { return "type.googleapis.com/google.protobuf.UninterpretedOption.NamePart"; }

constexpr auto pb_message_name(const UninterpretedOption::NamePart&) { return "google.protobuf.UninterpretedOption.NamePart"_cts; }

auto pb_meta(const FeatureSet &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FeatureSet::FieldPresence::FIELD_PRESENCE_UNKNOWN>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FeatureSet::EnumType::ENUM_TYPE_UNKNOWN>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FeatureSet::RepeatedFieldEncoding::REPEATED_FIELD_ENCODING_UNKNOWN>,
  hpp::proto::field_meta<4, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FeatureSet::StringFieldValidation::STRING_FIELD_VALIDATION_UNKNOWN>,
  hpp::proto::field_meta<5, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FeatureSet::MessageEncoding::MESSAGE_ENCODING_UNKNOWN>,
  hpp::proto::field_meta<6, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FeatureSet::JsonFormat::JSON_FORMAT_UNKNOWN>,
  hpp::proto::field_meta<999, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<UINT32_MAX>>;

auto serialize(const FeatureSet&) -> zpp::bits::members<8>;

inline const char* pb_url(const FeatureSet&) { return "type.googleapis.com/google.protobuf.FeatureSet"; }

constexpr auto pb_message_name(const FeatureSet&) { return "google.protobuf.FeatureSet"_cts; }

auto pb_meta(const SourceCodeInfo &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::unpacked_repeated>>;

auto serialize(const SourceCodeInfo&) -> zpp::bits::members<1>;

inline const char* pb_url(const SourceCodeInfo&) { return "type.googleapis.com/google.protobuf.SourceCodeInfo"; }

constexpr auto pb_message_name(const SourceCodeInfo&) { return "google.protobuf.SourceCodeInfo"_cts; }

auto pb_meta(const SourceCodeInfo::Location &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<4, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<6, hpp::proto::encoding_rule::unpacked_repeated>>;

auto serialize(const SourceCodeInfo::Location&) -> zpp::bits::members<5>;

inline const char* pb_url(const SourceCodeInfo::Location&) { return "type.googleapis.com/google.protobuf.SourceCodeInfo.Location"; }

constexpr auto pb_message_name(const SourceCodeInfo::Location&) { return "google.protobuf.SourceCodeInfo.Location"_cts; }

auto pb_meta(const GeneratedCodeInfo &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::unpacked_repeated>>;

auto serialize(const GeneratedCodeInfo&) -> zpp::bits::members<1>;

inline const char* pb_url(const GeneratedCodeInfo&) { return "type.googleapis.com/google.protobuf.GeneratedCodeInfo"; }

constexpr auto pb_message_name(const GeneratedCodeInfo&) { return "google.protobuf.GeneratedCodeInfo"_cts; }

auto pb_meta(const GeneratedCodeInfo::Annotation &) -> std::tuple<
  hpp::proto::field_meta<1, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<2, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<3, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<4, hpp::proto::encoding_rule::defaulted, zpp::bits::vint64_t>,
  hpp::proto::field_meta<5, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::GeneratedCodeInfo::Annotation::Semantic::NONE>>;

auto serialize(const GeneratedCodeInfo::Annotation&) -> zpp::bits::members<5>;

inline const char* pb_url(const GeneratedCodeInfo::Annotation&) { return "type.googleapis.com/google.protobuf.GeneratedCodeInfo.Annotation"; }

constexpr auto pb_message_name(const GeneratedCodeInfo::Annotation&) { return "google.protobuf.GeneratedCodeInfo.Annotation"_cts; }

} // namespace google::protobuf
