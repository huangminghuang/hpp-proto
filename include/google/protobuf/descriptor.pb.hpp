#pragma once

#include <hpp_proto/pb_serializer.h>
#include <google/protobuf/descriptor.msg.hpp>


namespace google::protobuf {

auto pb_meta(const FileDescriptorSet &) -> std::tuple<
  hpp::proto::field_meta<1, &FileDescriptorSet::file, hpp::proto::encoding_rule::unpacked_repeated>>;

constexpr auto pb_message_name(const FileDescriptorSet&) { return "google.protobuf.FileDescriptorSet"_cts; }

auto pb_meta(const FileDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &FileDescriptorProto::name, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, &FileDescriptorProto::package, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<3, &FileDescriptorProto::dependency, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<10, &FileDescriptorProto::public_dependency, hpp::proto::encoding_rule::unpacked_repeated, hpp::proto::vint64_t>,
  hpp::proto::field_meta<11, &FileDescriptorProto::weak_dependency, hpp::proto::encoding_rule::unpacked_repeated, hpp::proto::vint64_t>,
  hpp::proto::field_meta<4, &FileDescriptorProto::message_type, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<5, &FileDescriptorProto::enum_type, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<6, &FileDescriptorProto::service, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<7, &FileDescriptorProto::extension, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<8, &FileDescriptorProto::options, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<9, &FileDescriptorProto::source_code_info, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<12, &FileDescriptorProto::syntax, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<13, &FileDescriptorProto::edition, hpp::proto::encoding_rule::defaulted>>;

constexpr auto pb_message_name(const FileDescriptorProto&) { return "google.protobuf.FileDescriptorProto"_cts; }

auto pb_meta(const DescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &DescriptorProto::name, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, &DescriptorProto::field, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<6, &DescriptorProto::extension, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<3, &DescriptorProto::nested_type, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<4, &DescriptorProto::enum_type, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<5, &DescriptorProto::extension_range, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<8, &DescriptorProto::oneof_decl, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<7, &DescriptorProto::options, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<9, &DescriptorProto::reserved_range, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<10, &DescriptorProto::reserved_name, hpp::proto::encoding_rule::unpacked_repeated>>;

constexpr auto pb_message_name(const DescriptorProto&) { return "google.protobuf.DescriptorProto"_cts; }

auto pb_meta(const DescriptorProto::ExtensionRange &) -> std::tuple<
  hpp::proto::field_meta<1, &DescriptorProto::ExtensionRange::start, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &DescriptorProto::ExtensionRange::end, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<3, &DescriptorProto::ExtensionRange::options, hpp::proto::encoding_rule::explicit_presence>>;

constexpr auto pb_message_name(const DescriptorProto::ExtensionRange&) { return "google.protobuf.DescriptorProto.ExtensionRange"_cts; }

auto pb_meta(const DescriptorProto::ReservedRange &) -> std::tuple<
  hpp::proto::field_meta<1, &DescriptorProto::ReservedRange::start, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &DescriptorProto::ReservedRange::end, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>>;

constexpr auto pb_message_name(const DescriptorProto::ReservedRange&) { return "google.protobuf.DescriptorProto.ReservedRange"_cts; }

auto pb_meta(const ExtensionRangeOptions &) -> std::tuple<
  hpp::proto::field_meta<999, &ExtensionRangeOptions::uninterpreted_option, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<2, &ExtensionRangeOptions::declaration, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<50, &ExtensionRangeOptions::features, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<3, &ExtensionRangeOptions::verification, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::ExtensionRangeOptions::VerificationState::UNVERIFIED>,
  hpp::proto::field_meta<UINT32_MAX, &ExtensionRangeOptions::extensions>>;

constexpr auto pb_message_name(const ExtensionRangeOptions&) { return "google.protobuf.ExtensionRangeOptions"_cts; }

auto pb_meta(const ExtensionRangeOptions::Declaration &) -> std::tuple<
  hpp::proto::field_meta<1, &ExtensionRangeOptions::Declaration::number, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &ExtensionRangeOptions::Declaration::full_name, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<3, &ExtensionRangeOptions::Declaration::type, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<5, &ExtensionRangeOptions::Declaration::reserved, hpp::proto::encoding_rule::defaulted, bool>,
  hpp::proto::field_meta<6, &ExtensionRangeOptions::Declaration::repeated, hpp::proto::encoding_rule::defaulted, bool>>;

constexpr auto pb_message_name(const ExtensionRangeOptions::Declaration&) { return "google.protobuf.ExtensionRangeOptions.Declaration"_cts; }

auto pb_meta(const FieldDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &FieldDescriptorProto::name, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<3, &FieldDescriptorProto::number, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<4, &FieldDescriptorProto::label, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FieldDescriptorProto::Label::LABEL_OPTIONAL>,
  hpp::proto::field_meta<5, &FieldDescriptorProto::type, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FieldDescriptorProto::Type::TYPE_DOUBLE>,
  hpp::proto::field_meta<6, &FieldDescriptorProto::type_name, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, &FieldDescriptorProto::extendee, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<7, &FieldDescriptorProto::default_value, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<9, &FieldDescriptorProto::oneof_index, hpp::proto::encoding_rule::explicit_presence, hpp::proto::vint64_t>,
  hpp::proto::field_meta<10, &FieldDescriptorProto::json_name, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<8, &FieldDescriptorProto::options, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<17, &FieldDescriptorProto::proto3_optional, hpp::proto::encoding_rule::defaulted, bool>>;

constexpr auto pb_message_name(const FieldDescriptorProto&) { return "google.protobuf.FieldDescriptorProto"_cts; }

auto pb_meta(const OneofDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &OneofDescriptorProto::name, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, &OneofDescriptorProto::options, hpp::proto::encoding_rule::explicit_presence>>;

constexpr auto pb_message_name(const OneofDescriptorProto&) { return "google.protobuf.OneofDescriptorProto"_cts; }

auto pb_meta(const EnumDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &EnumDescriptorProto::name, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, &EnumDescriptorProto::value, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<3, &EnumDescriptorProto::options, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<4, &EnumDescriptorProto::reserved_range, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<5, &EnumDescriptorProto::reserved_name, hpp::proto::encoding_rule::unpacked_repeated>>;

constexpr auto pb_message_name(const EnumDescriptorProto&) { return "google.protobuf.EnumDescriptorProto"_cts; }

auto pb_meta(const EnumDescriptorProto::EnumReservedRange &) -> std::tuple<
  hpp::proto::field_meta<1, &EnumDescriptorProto::EnumReservedRange::start, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &EnumDescriptorProto::EnumReservedRange::end, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>>;

constexpr auto pb_message_name(const EnumDescriptorProto::EnumReservedRange&) { return "google.protobuf.EnumDescriptorProto.EnumReservedRange"_cts; }

auto pb_meta(const EnumValueDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &EnumValueDescriptorProto::name, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, &EnumValueDescriptorProto::number, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<3, &EnumValueDescriptorProto::options, hpp::proto::encoding_rule::explicit_presence>>;

constexpr auto pb_message_name(const EnumValueDescriptorProto&) { return "google.protobuf.EnumValueDescriptorProto"_cts; }

auto pb_meta(const ServiceDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &ServiceDescriptorProto::name, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, &ServiceDescriptorProto::method, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<3, &ServiceDescriptorProto::options, hpp::proto::encoding_rule::explicit_presence>>;

constexpr auto pb_message_name(const ServiceDescriptorProto&) { return "google.protobuf.ServiceDescriptorProto"_cts; }

auto pb_meta(const MethodDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &MethodDescriptorProto::name, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, &MethodDescriptorProto::input_type, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<3, &MethodDescriptorProto::output_type, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<4, &MethodDescriptorProto::options, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<5, &MethodDescriptorProto::client_streaming, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<6, &MethodDescriptorProto::server_streaming, hpp::proto::encoding_rule::defaulted, bool, false>>;

constexpr auto pb_message_name(const MethodDescriptorProto&) { return "google.protobuf.MethodDescriptorProto"_cts; }

auto pb_meta(const FileOptions &) -> std::tuple<
  hpp::proto::field_meta<1, &FileOptions::java_package, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<8, &FileOptions::java_outer_classname, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<10, &FileOptions::java_multiple_files, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<20, &FileOptions::java_generate_equals_and_hash, hpp::proto::encoding_rule::defaulted, bool>,
  hpp::proto::field_meta<27, &FileOptions::java_string_check_utf8, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<9, &FileOptions::optimize_for, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FileOptions::OptimizeMode::SPEED>,
  hpp::proto::field_meta<11, &FileOptions::go_package, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<16, &FileOptions::cc_generic_services, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<17, &FileOptions::java_generic_services, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<18, &FileOptions::py_generic_services, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<42, &FileOptions::php_generic_services, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<23, &FileOptions::deprecated, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<31, &FileOptions::cc_enable_arenas, hpp::proto::encoding_rule::defaulted, bool, true>,
  hpp::proto::field_meta<36, &FileOptions::objc_class_prefix, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<37, &FileOptions::csharp_namespace, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<39, &FileOptions::swift_prefix, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<40, &FileOptions::php_class_prefix, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<41, &FileOptions::php_namespace, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<44, &FileOptions::php_metadata_namespace, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<45, &FileOptions::ruby_package, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<50, &FileOptions::features, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<999, &FileOptions::uninterpreted_option, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX, &FileOptions::extensions>>;

constexpr auto pb_message_name(const FileOptions&) { return "google.protobuf.FileOptions"_cts; }

auto pb_meta(const MessageOptions &) -> std::tuple<
  hpp::proto::field_meta<1, &MessageOptions::message_set_wire_format, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<2, &MessageOptions::no_standard_descriptor_accessor, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<3, &MessageOptions::deprecated, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<7, &MessageOptions::map_entry, hpp::proto::encoding_rule::defaulted, bool>,
  hpp::proto::field_meta<11, &MessageOptions::deprecated_legacy_json_field_conflicts, hpp::proto::encoding_rule::defaulted, bool>,
  hpp::proto::field_meta<12, &MessageOptions::features, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<999, &MessageOptions::uninterpreted_option, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX, &MessageOptions::extensions>>;

constexpr auto pb_message_name(const MessageOptions&) { return "google.protobuf.MessageOptions"_cts; }

auto pb_meta(const FieldOptions &) -> std::tuple<
  hpp::proto::field_meta<1, &FieldOptions::ctype, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FieldOptions::CType::STRING>,
  hpp::proto::field_meta<2, &FieldOptions::packed, hpp::proto::encoding_rule::explicit_presence, bool>,
  hpp::proto::field_meta<6, &FieldOptions::jstype, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FieldOptions::JSType::JS_NORMAL>,
  hpp::proto::field_meta<5, &FieldOptions::lazy, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<15, &FieldOptions::unverified_lazy, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<3, &FieldOptions::deprecated, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<10, &FieldOptions::weak, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<16, &FieldOptions::debug_redact, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<17, &FieldOptions::retention, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FieldOptions::OptionRetention::RETENTION_UNKNOWN>,
  hpp::proto::field_meta<19, &FieldOptions::targets, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<20, &FieldOptions::edition_defaults, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<21, &FieldOptions::features, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<999, &FieldOptions::uninterpreted_option, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX, &FieldOptions::extensions>>;

constexpr auto pb_message_name(const FieldOptions&) { return "google.protobuf.FieldOptions"_cts; }

auto pb_meta(const FieldOptions::EditionDefault &) -> std::tuple<
  hpp::proto::field_meta<1, &FieldOptions::EditionDefault::edition, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, &FieldOptions::EditionDefault::value, hpp::proto::encoding_rule::defaulted>>;

constexpr auto pb_message_name(const FieldOptions::EditionDefault&) { return "google.protobuf.FieldOptions.EditionDefault"_cts; }

auto pb_meta(const OneofOptions &) -> std::tuple<
  hpp::proto::field_meta<1, &OneofOptions::features, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<999, &OneofOptions::uninterpreted_option, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX, &OneofOptions::extensions>>;

constexpr auto pb_message_name(const OneofOptions&) { return "google.protobuf.OneofOptions"_cts; }

auto pb_meta(const EnumOptions &) -> std::tuple<
  hpp::proto::field_meta<2, &EnumOptions::allow_alias, hpp::proto::encoding_rule::defaulted, bool>,
  hpp::proto::field_meta<3, &EnumOptions::deprecated, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<6, &EnumOptions::deprecated_legacy_json_field_conflicts, hpp::proto::encoding_rule::defaulted, bool>,
  hpp::proto::field_meta<7, &EnumOptions::features, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<999, &EnumOptions::uninterpreted_option, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX, &EnumOptions::extensions>>;

constexpr auto pb_message_name(const EnumOptions&) { return "google.protobuf.EnumOptions"_cts; }

auto pb_meta(const EnumValueOptions &) -> std::tuple<
  hpp::proto::field_meta<1, &EnumValueOptions::deprecated, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<2, &EnumValueOptions::features, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<3, &EnumValueOptions::debug_redact, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<999, &EnumValueOptions::uninterpreted_option, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX, &EnumValueOptions::extensions>>;

constexpr auto pb_message_name(const EnumValueOptions&) { return "google.protobuf.EnumValueOptions"_cts; }

auto pb_meta(const ServiceOptions &) -> std::tuple<
  hpp::proto::field_meta<34, &ServiceOptions::features, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<33, &ServiceOptions::deprecated, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<999, &ServiceOptions::uninterpreted_option, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX, &ServiceOptions::extensions>>;

constexpr auto pb_message_name(const ServiceOptions&) { return "google.protobuf.ServiceOptions"_cts; }

auto pb_meta(const MethodOptions &) -> std::tuple<
  hpp::proto::field_meta<33, &MethodOptions::deprecated, hpp::proto::encoding_rule::defaulted, bool, false>,
  hpp::proto::field_meta<34, &MethodOptions::idempotency_level, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::MethodOptions::IdempotencyLevel::IDEMPOTENCY_UNKNOWN>,
  hpp::proto::field_meta<35, &MethodOptions::features, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<999, &MethodOptions::uninterpreted_option, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<UINT32_MAX, &MethodOptions::extensions>>;

constexpr auto pb_message_name(const MethodOptions&) { return "google.protobuf.MethodOptions"_cts; }

auto pb_meta(const UninterpretedOption &) -> std::tuple<
  hpp::proto::field_meta<2, &UninterpretedOption::name, hpp::proto::encoding_rule::unpacked_repeated>,
  hpp::proto::field_meta<3, &UninterpretedOption::identifier_value, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<4, &UninterpretedOption::positive_int_value, hpp::proto::encoding_rule::defaulted, hpp::proto::vuint64_t>,
  hpp::proto::field_meta<5, &UninterpretedOption::negative_int_value, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<6, &UninterpretedOption::double_value, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<7, &UninterpretedOption::string_value, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<8, &UninterpretedOption::aggregate_value, hpp::proto::encoding_rule::defaulted>>;

constexpr auto pb_message_name(const UninterpretedOption&) { return "google.protobuf.UninterpretedOption"_cts; }

auto pb_meta(const UninterpretedOption::NamePart &) -> std::tuple<
  hpp::proto::field_meta<1, &UninterpretedOption::NamePart::name_part, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<2, &UninterpretedOption::NamePart::is_extension, hpp::proto::encoding_rule::defaulted, bool>>;

constexpr auto pb_message_name(const UninterpretedOption::NamePart&) { return "google.protobuf.UninterpretedOption.NamePart"_cts; }

auto pb_meta(const FeatureSet &) -> std::tuple<
  hpp::proto::field_meta<1, &FeatureSet::field_presence, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FeatureSet::FieldPresence::FIELD_PRESENCE_UNKNOWN>,
  hpp::proto::field_meta<2, &FeatureSet::enum_type, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FeatureSet::EnumType::ENUM_TYPE_UNKNOWN>,
  hpp::proto::field_meta<3, &FeatureSet::repeated_field_encoding, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FeatureSet::RepeatedFieldEncoding::REPEATED_FIELD_ENCODING_UNKNOWN>,
  hpp::proto::field_meta<4, &FeatureSet::string_field_validation, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FeatureSet::StringFieldValidation::STRING_FIELD_VALIDATION_UNKNOWN>,
  hpp::proto::field_meta<5, &FeatureSet::message_encoding, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FeatureSet::MessageEncoding::MESSAGE_ENCODING_UNKNOWN>,
  hpp::proto::field_meta<6, &FeatureSet::json_format, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::FeatureSet::JsonFormat::JSON_FORMAT_UNKNOWN>,
  hpp::proto::field_meta<999, &FeatureSet::raw_features, hpp::proto::encoding_rule::explicit_presence>,
  hpp::proto::field_meta<UINT32_MAX, &FeatureSet::extensions>>;

constexpr auto pb_message_name(const FeatureSet&) { return "google.protobuf.FeatureSet"_cts; }

auto pb_meta(const SourceCodeInfo &) -> std::tuple<
  hpp::proto::field_meta<1, &SourceCodeInfo::location, hpp::proto::encoding_rule::unpacked_repeated>>;

constexpr auto pb_message_name(const SourceCodeInfo&) { return "google.protobuf.SourceCodeInfo"_cts; }

auto pb_meta(const SourceCodeInfo::Location &) -> std::tuple<
  hpp::proto::field_meta<1, &SourceCodeInfo::Location::path, hpp::proto::encoding_rule::packed_repeated, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &SourceCodeInfo::Location::span, hpp::proto::encoding_rule::packed_repeated, hpp::proto::vint64_t>,
  hpp::proto::field_meta<3, &SourceCodeInfo::Location::leading_comments, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<4, &SourceCodeInfo::Location::trailing_comments, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<6, &SourceCodeInfo::Location::leading_detached_comments, hpp::proto::encoding_rule::unpacked_repeated>>;

constexpr auto pb_message_name(const SourceCodeInfo::Location&) { return "google.protobuf.SourceCodeInfo.Location"_cts; }

auto pb_meta(const GeneratedCodeInfo &) -> std::tuple<
  hpp::proto::field_meta<1, &GeneratedCodeInfo::annotation, hpp::proto::encoding_rule::unpacked_repeated>>;

constexpr auto pb_message_name(const GeneratedCodeInfo&) { return "google.protobuf.GeneratedCodeInfo"_cts; }

auto pb_meta(const GeneratedCodeInfo::Annotation &) -> std::tuple<
  hpp::proto::field_meta<1, &GeneratedCodeInfo::Annotation::path, hpp::proto::encoding_rule::packed_repeated, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &GeneratedCodeInfo::Annotation::source_file, hpp::proto::encoding_rule::defaulted>,
  hpp::proto::field_meta<3, &GeneratedCodeInfo::Annotation::begin, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<4, &GeneratedCodeInfo::Annotation::end, hpp::proto::encoding_rule::defaulted, hpp::proto::vint64_t>,
  hpp::proto::field_meta<5, &GeneratedCodeInfo::Annotation::semantic, hpp::proto::encoding_rule::defaulted, void, ::google::protobuf::GeneratedCodeInfo::Annotation::Semantic::NONE>>;

constexpr auto pb_message_name(const GeneratedCodeInfo::Annotation&) { return "google.protobuf.GeneratedCodeInfo.Annotation"_cts; }

} // namespace google::protobuf
