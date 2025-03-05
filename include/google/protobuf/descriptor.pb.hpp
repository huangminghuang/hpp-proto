// clang-format off
// Generated by the protocol buffer compiler.  DO NOT EDIT!
// NO CHECKED-IN PROTOBUF GENCODE
// generation command line:
//    protoc --plugin=protoc-gen-hpp=/path/to/protoc-gen-hpp
//           --hpp_out proto2_explicit_presence=.google.protobuf.FieldDescriptorProto.oneof_index,proto2_explicit_presence=.google.protobuf.FieldOptions.packed,export_request=descriptor.request.binpb:${out_dir}
//           google/protobuf/descriptor.proto

#pragma once

#include <hpp_proto/pb_serializer.hpp>
#include "google/protobuf/descriptor.msg.hpp"


namespace google::protobuf {

auto pb_meta(const FileDescriptorSet &) -> std::tuple<
  hpp::proto::field_meta<1, &FileDescriptorSet::file, hpp::proto::field_option::none>,
  hpp::proto::field_meta<UINT32_MAX, &FileDescriptorSet::extensions>>;

auto pb_meta(const FileDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &FileDescriptorProto::name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<2, &FileDescriptorProto::package, hpp::proto::field_option::none>,
  hpp::proto::field_meta<3, &FileDescriptorProto::dependency, hpp::proto::field_option::none>,
  hpp::proto::field_meta<10, &FileDescriptorProto::public_dependency, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<11, &FileDescriptorProto::weak_dependency, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<4, &FileDescriptorProto::message_type, hpp::proto::field_option::none>,
  hpp::proto::field_meta<5, &FileDescriptorProto::enum_type, hpp::proto::field_option::none>,
  hpp::proto::field_meta<6, &FileDescriptorProto::service, hpp::proto::field_option::none>,
  hpp::proto::field_meta<7, &FileDescriptorProto::extension, hpp::proto::field_option::none>,
  hpp::proto::field_meta<8, &FileDescriptorProto::options, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<9, &FileDescriptorProto::source_code_info, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<12, &FileDescriptorProto::syntax, hpp::proto::field_option::none>,
  hpp::proto::field_meta<14, &FileDescriptorProto::edition, hpp::proto::field_option::closed_enum, void, ::google::protobuf::Edition::EDITION_UNKNOWN>>;

auto pb_meta(const DescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &DescriptorProto::name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<2, &DescriptorProto::field, hpp::proto::field_option::none>,
  hpp::proto::field_meta<6, &DescriptorProto::extension, hpp::proto::field_option::none>,
  hpp::proto::field_meta<3, &DescriptorProto::nested_type, hpp::proto::field_option::none>,
  hpp::proto::field_meta<4, &DescriptorProto::enum_type, hpp::proto::field_option::none>,
  hpp::proto::field_meta<5, &DescriptorProto::extension_range, hpp::proto::field_option::none>,
  hpp::proto::field_meta<8, &DescriptorProto::oneof_decl, hpp::proto::field_option::none>,
  hpp::proto::field_meta<7, &DescriptorProto::options, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<9, &DescriptorProto::reserved_range, hpp::proto::field_option::none>,
  hpp::proto::field_meta<10, &DescriptorProto::reserved_name, hpp::proto::field_option::none>>;

auto pb_meta(const DescriptorProto::ExtensionRange &) -> std::tuple<
  hpp::proto::field_meta<1, &DescriptorProto::ExtensionRange::start, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &DescriptorProto::ExtensionRange::end, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<3, &DescriptorProto::ExtensionRange::options, hpp::proto::field_option::explicit_presence>>;

auto pb_meta(const DescriptorProto::ReservedRange &) -> std::tuple<
  hpp::proto::field_meta<1, &DescriptorProto::ReservedRange::start, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &DescriptorProto::ReservedRange::end, hpp::proto::field_option::none, hpp::proto::vint64_t>>;

auto pb_meta(const ExtensionRangeOptions &) -> std::tuple<
  hpp::proto::field_meta<999, &ExtensionRangeOptions::uninterpreted_option, hpp::proto::field_option::none>,
  hpp::proto::field_meta<2, &ExtensionRangeOptions::declaration, hpp::proto::field_option::none>,
  hpp::proto::field_meta<50, &ExtensionRangeOptions::features, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<3, &ExtensionRangeOptions::verification, hpp::proto::field_option::closed_enum, void, ::google::protobuf::ExtensionRangeOptions::VerificationState::UNVERIFIED>,
  hpp::proto::field_meta<UINT32_MAX, &ExtensionRangeOptions::extensions>>;

auto pb_meta(const ExtensionRangeOptions::Declaration &) -> std::tuple<
  hpp::proto::field_meta<1, &ExtensionRangeOptions::Declaration::number, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &ExtensionRangeOptions::Declaration::full_name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<3, &ExtensionRangeOptions::Declaration::type, hpp::proto::field_option::none>,
  hpp::proto::field_meta<5, &ExtensionRangeOptions::Declaration::reserved, hpp::proto::field_option::none, bool>,
  hpp::proto::field_meta<6, &ExtensionRangeOptions::Declaration::repeated, hpp::proto::field_option::none, bool>>;

auto pb_meta(const FieldDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &FieldDescriptorProto::name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<3, &FieldDescriptorProto::number, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<4, &FieldDescriptorProto::label, hpp::proto::field_option::closed_enum, void, ::google::protobuf::FieldDescriptorProto::Label::LABEL_OPTIONAL>,
  hpp::proto::field_meta<5, &FieldDescriptorProto::type, hpp::proto::field_option::closed_enum, void, ::google::protobuf::FieldDescriptorProto::Type::TYPE_DOUBLE>,
  hpp::proto::field_meta<6, &FieldDescriptorProto::type_name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<2, &FieldDescriptorProto::extendee, hpp::proto::field_option::none>,
  hpp::proto::field_meta<7, &FieldDescriptorProto::default_value, hpp::proto::field_option::none>,
  hpp::proto::field_meta<9, &FieldDescriptorProto::oneof_index, hpp::proto::field_option::explicit_presence, hpp::proto::vint64_t>,
  hpp::proto::field_meta<10, &FieldDescriptorProto::json_name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<8, &FieldDescriptorProto::options, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<17, &FieldDescriptorProto::proto3_optional, hpp::proto::field_option::none, bool>>;

auto pb_meta(const OneofDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &OneofDescriptorProto::name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<2, &OneofDescriptorProto::options, hpp::proto::field_option::explicit_presence>>;

auto pb_meta(const EnumDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &EnumDescriptorProto::name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<2, &EnumDescriptorProto::value, hpp::proto::field_option::none>,
  hpp::proto::field_meta<3, &EnumDescriptorProto::options, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<4, &EnumDescriptorProto::reserved_range, hpp::proto::field_option::none>,
  hpp::proto::field_meta<5, &EnumDescriptorProto::reserved_name, hpp::proto::field_option::none>>;

auto pb_meta(const EnumDescriptorProto::EnumReservedRange &) -> std::tuple<
  hpp::proto::field_meta<1, &EnumDescriptorProto::EnumReservedRange::start, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &EnumDescriptorProto::EnumReservedRange::end, hpp::proto::field_option::none, hpp::proto::vint64_t>>;

auto pb_meta(const EnumValueDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &EnumValueDescriptorProto::name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<2, &EnumValueDescriptorProto::number, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<3, &EnumValueDescriptorProto::options, hpp::proto::field_option::explicit_presence>>;

auto pb_meta(const ServiceDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &ServiceDescriptorProto::name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<2, &ServiceDescriptorProto::method, hpp::proto::field_option::none>,
  hpp::proto::field_meta<3, &ServiceDescriptorProto::options, hpp::proto::field_option::explicit_presence>>;

auto pb_meta(const MethodDescriptorProto &) -> std::tuple<
  hpp::proto::field_meta<1, &MethodDescriptorProto::name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<2, &MethodDescriptorProto::input_type, hpp::proto::field_option::none>,
  hpp::proto::field_meta<3, &MethodDescriptorProto::output_type, hpp::proto::field_option::none>,
  hpp::proto::field_meta<4, &MethodDescriptorProto::options, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<5, &MethodDescriptorProto::client_streaming, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<6, &MethodDescriptorProto::server_streaming, hpp::proto::field_option::none, bool, false>>;

auto pb_meta(const FileOptions &) -> std::tuple<
  hpp::proto::field_meta<1, &FileOptions::java_package, hpp::proto::field_option::none>,
  hpp::proto::field_meta<8, &FileOptions::java_outer_classname, hpp::proto::field_option::none>,
  hpp::proto::field_meta<10, &FileOptions::java_multiple_files, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<20, &FileOptions::java_generate_equals_and_hash, hpp::proto::field_option::none, bool>,
  hpp::proto::field_meta<27, &FileOptions::java_string_check_utf8, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<9, &FileOptions::optimize_for, hpp::proto::field_option::closed_enum, void, ::google::protobuf::FileOptions::OptimizeMode::SPEED>,
  hpp::proto::field_meta<11, &FileOptions::go_package, hpp::proto::field_option::none>,
  hpp::proto::field_meta<16, &FileOptions::cc_generic_services, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<17, &FileOptions::java_generic_services, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<18, &FileOptions::py_generic_services, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<23, &FileOptions::deprecated, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<31, &FileOptions::cc_enable_arenas, hpp::proto::field_option::none, bool, true>,
  hpp::proto::field_meta<36, &FileOptions::objc_class_prefix, hpp::proto::field_option::none>,
  hpp::proto::field_meta<37, &FileOptions::csharp_namespace, hpp::proto::field_option::none>,
  hpp::proto::field_meta<39, &FileOptions::swift_prefix, hpp::proto::field_option::none>,
  hpp::proto::field_meta<40, &FileOptions::php_class_prefix, hpp::proto::field_option::none>,
  hpp::proto::field_meta<41, &FileOptions::php_namespace, hpp::proto::field_option::none>,
  hpp::proto::field_meta<44, &FileOptions::php_metadata_namespace, hpp::proto::field_option::none>,
  hpp::proto::field_meta<45, &FileOptions::ruby_package, hpp::proto::field_option::none>,
  hpp::proto::field_meta<50, &FileOptions::features, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<999, &FileOptions::uninterpreted_option, hpp::proto::field_option::none>,
  hpp::proto::field_meta<UINT32_MAX, &FileOptions::extensions>>;

auto pb_meta(const MessageOptions &) -> std::tuple<
  hpp::proto::field_meta<1, &MessageOptions::message_set_wire_format, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<2, &MessageOptions::no_standard_descriptor_accessor, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<3, &MessageOptions::deprecated, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<7, &MessageOptions::map_entry, hpp::proto::field_option::none, bool>,
  hpp::proto::field_meta<11, &MessageOptions::deprecated_legacy_json_field_conflicts, hpp::proto::field_option::none, bool>,
  hpp::proto::field_meta<12, &MessageOptions::features, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<999, &MessageOptions::uninterpreted_option, hpp::proto::field_option::none>,
  hpp::proto::field_meta<UINT32_MAX, &MessageOptions::extensions>>;

auto pb_meta(const FieldOptions &) -> std::tuple<
  hpp::proto::field_meta<1, &FieldOptions::ctype, hpp::proto::field_option::closed_enum, void, ::google::protobuf::FieldOptions::CType::STRING>,
  hpp::proto::field_meta<2, &FieldOptions::packed, hpp::proto::field_option::explicit_presence, bool>,
  hpp::proto::field_meta<6, &FieldOptions::jstype, hpp::proto::field_option::closed_enum, void, ::google::protobuf::FieldOptions::JSType::JS_NORMAL>,
  hpp::proto::field_meta<5, &FieldOptions::lazy, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<15, &FieldOptions::unverified_lazy, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<3, &FieldOptions::deprecated, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<10, &FieldOptions::weak, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<16, &FieldOptions::debug_redact, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<17, &FieldOptions::retention, hpp::proto::field_option::closed_enum, void, ::google::protobuf::FieldOptions::OptionRetention::RETENTION_UNKNOWN>,
  hpp::proto::field_meta<19, &FieldOptions::targets, hpp::proto::field_option::closed_enum>,
  hpp::proto::field_meta<20, &FieldOptions::edition_defaults, hpp::proto::field_option::none>,
  hpp::proto::field_meta<21, &FieldOptions::features, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<22, &FieldOptions::feature_support, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<999, &FieldOptions::uninterpreted_option, hpp::proto::field_option::none>,
  hpp::proto::field_meta<UINT32_MAX, &FieldOptions::extensions>>;

auto pb_meta(const FieldOptions::EditionDefault &) -> std::tuple<
  hpp::proto::field_meta<3, &FieldOptions::EditionDefault::edition, hpp::proto::field_option::closed_enum, void, ::google::protobuf::Edition::EDITION_UNKNOWN>,
  hpp::proto::field_meta<2, &FieldOptions::EditionDefault::value, hpp::proto::field_option::none>>;

auto pb_meta(const FieldOptions::FeatureSupport &) -> std::tuple<
  hpp::proto::field_meta<1, &FieldOptions::FeatureSupport::edition_introduced, hpp::proto::field_option::closed_enum, void, ::google::protobuf::Edition::EDITION_UNKNOWN>,
  hpp::proto::field_meta<2, &FieldOptions::FeatureSupport::edition_deprecated, hpp::proto::field_option::closed_enum, void, ::google::protobuf::Edition::EDITION_UNKNOWN>,
  hpp::proto::field_meta<3, &FieldOptions::FeatureSupport::deprecation_warning, hpp::proto::field_option::none>,
  hpp::proto::field_meta<4, &FieldOptions::FeatureSupport::edition_removed, hpp::proto::field_option::closed_enum, void, ::google::protobuf::Edition::EDITION_UNKNOWN>>;

auto pb_meta(const OneofOptions &) -> std::tuple<
  hpp::proto::field_meta<1, &OneofOptions::features, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<999, &OneofOptions::uninterpreted_option, hpp::proto::field_option::none>,
  hpp::proto::field_meta<UINT32_MAX, &OneofOptions::extensions>>;

auto pb_meta(const EnumOptions &) -> std::tuple<
  hpp::proto::field_meta<2, &EnumOptions::allow_alias, hpp::proto::field_option::none, bool>,
  hpp::proto::field_meta<3, &EnumOptions::deprecated, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<6, &EnumOptions::deprecated_legacy_json_field_conflicts, hpp::proto::field_option::none, bool>,
  hpp::proto::field_meta<7, &EnumOptions::features, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<999, &EnumOptions::uninterpreted_option, hpp::proto::field_option::none>,
  hpp::proto::field_meta<UINT32_MAX, &EnumOptions::extensions>>;

auto pb_meta(const EnumValueOptions &) -> std::tuple<
  hpp::proto::field_meta<1, &EnumValueOptions::deprecated, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<2, &EnumValueOptions::features, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<3, &EnumValueOptions::debug_redact, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<4, &EnumValueOptions::feature_support, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<999, &EnumValueOptions::uninterpreted_option, hpp::proto::field_option::none>,
  hpp::proto::field_meta<UINT32_MAX, &EnumValueOptions::extensions>>;

auto pb_meta(const ServiceOptions &) -> std::tuple<
  hpp::proto::field_meta<34, &ServiceOptions::features, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<33, &ServiceOptions::deprecated, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<999, &ServiceOptions::uninterpreted_option, hpp::proto::field_option::none>,
  hpp::proto::field_meta<UINT32_MAX, &ServiceOptions::extensions>>;

auto pb_meta(const MethodOptions &) -> std::tuple<
  hpp::proto::field_meta<33, &MethodOptions::deprecated, hpp::proto::field_option::none, bool, false>,
  hpp::proto::field_meta<34, &MethodOptions::idempotency_level, hpp::proto::field_option::closed_enum, void, ::google::protobuf::MethodOptions::IdempotencyLevel::IDEMPOTENCY_UNKNOWN>,
  hpp::proto::field_meta<35, &MethodOptions::features, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<999, &MethodOptions::uninterpreted_option, hpp::proto::field_option::none>,
  hpp::proto::field_meta<UINT32_MAX, &MethodOptions::extensions>>;

auto pb_meta(const UninterpretedOption &) -> std::tuple<
  hpp::proto::field_meta<2, &UninterpretedOption::name, hpp::proto::field_option::none>,
  hpp::proto::field_meta<3, &UninterpretedOption::identifier_value, hpp::proto::field_option::none>,
  hpp::proto::field_meta<4, &UninterpretedOption::positive_int_value, hpp::proto::field_option::none, hpp::proto::vuint64_t>,
  hpp::proto::field_meta<5, &UninterpretedOption::negative_int_value, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<6, &UninterpretedOption::double_value, hpp::proto::field_option::none>,
  hpp::proto::field_meta<7, &UninterpretedOption::string_value, hpp::proto::field_option::none>,
  hpp::proto::field_meta<8, &UninterpretedOption::aggregate_value, hpp::proto::field_option::none>>;

auto pb_meta(const UninterpretedOption::NamePart &) -> std::tuple<
  hpp::proto::field_meta<1, &UninterpretedOption::NamePart::name_part, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<2, &UninterpretedOption::NamePart::is_extension, hpp::proto::field_option::explicit_presence, bool>>;

auto pb_meta(const FeatureSet &) -> std::tuple<
  hpp::proto::field_meta<1, &FeatureSet::field_presence, hpp::proto::field_option::closed_enum, void, ::google::protobuf::FeatureSet::FieldPresence::FIELD_PRESENCE_UNKNOWN>,
  hpp::proto::field_meta<2, &FeatureSet::enum_type, hpp::proto::field_option::closed_enum, void, ::google::protobuf::FeatureSet::EnumType::ENUM_TYPE_UNKNOWN>,
  hpp::proto::field_meta<3, &FeatureSet::repeated_field_encoding, hpp::proto::field_option::closed_enum, void, ::google::protobuf::FeatureSet::RepeatedFieldEncoding::REPEATED_FIELD_ENCODING_UNKNOWN>,
  hpp::proto::field_meta<4, &FeatureSet::utf8_validation, hpp::proto::field_option::closed_enum, void, ::google::protobuf::FeatureSet::Utf8Validation::UTF8_VALIDATION_UNKNOWN>,
  hpp::proto::field_meta<5, &FeatureSet::message_encoding, hpp::proto::field_option::closed_enum, void, ::google::protobuf::FeatureSet::MessageEncoding::MESSAGE_ENCODING_UNKNOWN>,
  hpp::proto::field_meta<6, &FeatureSet::json_format, hpp::proto::field_option::closed_enum, void, ::google::protobuf::FeatureSet::JsonFormat::JSON_FORMAT_UNKNOWN>,
  hpp::proto::field_meta<UINT32_MAX, &FeatureSet::extensions>>;

auto pb_meta(const FeatureSetDefaults &) -> std::tuple<
  hpp::proto::field_meta<1, &FeatureSetDefaults::defaults, hpp::proto::field_option::none>,
  hpp::proto::field_meta<4, &FeatureSetDefaults::minimum_edition, hpp::proto::field_option::closed_enum, void, ::google::protobuf::Edition::EDITION_UNKNOWN>,
  hpp::proto::field_meta<5, &FeatureSetDefaults::maximum_edition, hpp::proto::field_option::closed_enum, void, ::google::protobuf::Edition::EDITION_UNKNOWN>>;

auto pb_meta(const FeatureSetDefaults::FeatureSetEditionDefault &) -> std::tuple<
  hpp::proto::field_meta<3, &FeatureSetDefaults::FeatureSetEditionDefault::edition, hpp::proto::field_option::closed_enum, void, ::google::protobuf::Edition::EDITION_UNKNOWN>,
  hpp::proto::field_meta<4, &FeatureSetDefaults::FeatureSetEditionDefault::overridable_features, hpp::proto::field_option::explicit_presence>,
  hpp::proto::field_meta<5, &FeatureSetDefaults::FeatureSetEditionDefault::fixed_features, hpp::proto::field_option::explicit_presence>>;

auto pb_meta(const SourceCodeInfo &) -> std::tuple<
  hpp::proto::field_meta<1, &SourceCodeInfo::location, hpp::proto::field_option::none>,
  hpp::proto::field_meta<UINT32_MAX, &SourceCodeInfo::extensions>>;

auto pb_meta(const SourceCodeInfo::Location &) -> std::tuple<
  hpp::proto::field_meta<1, &SourceCodeInfo::Location::path, hpp::proto::field_option::is_packed, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &SourceCodeInfo::Location::span, hpp::proto::field_option::is_packed, hpp::proto::vint64_t>,
  hpp::proto::field_meta<3, &SourceCodeInfo::Location::leading_comments, hpp::proto::field_option::none>,
  hpp::proto::field_meta<4, &SourceCodeInfo::Location::trailing_comments, hpp::proto::field_option::none>,
  hpp::proto::field_meta<6, &SourceCodeInfo::Location::leading_detached_comments, hpp::proto::field_option::none>>;

auto pb_meta(const GeneratedCodeInfo &) -> std::tuple<
  hpp::proto::field_meta<1, &GeneratedCodeInfo::annotation, hpp::proto::field_option::none>>;

auto pb_meta(const GeneratedCodeInfo::Annotation &) -> std::tuple<
  hpp::proto::field_meta<1, &GeneratedCodeInfo::Annotation::path, hpp::proto::field_option::is_packed, hpp::proto::vint64_t>,
  hpp::proto::field_meta<2, &GeneratedCodeInfo::Annotation::source_file, hpp::proto::field_option::none>,
  hpp::proto::field_meta<3, &GeneratedCodeInfo::Annotation::begin, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<4, &GeneratedCodeInfo::Annotation::end, hpp::proto::field_option::none, hpp::proto::vint64_t>,
  hpp::proto::field_meta<5, &GeneratedCodeInfo::Annotation::semantic, hpp::proto::field_option::closed_enum, void, ::google::protobuf::GeneratedCodeInfo::Annotation::Semantic::NONE>>;

} // namespace google::protobuf
// clang-format on
