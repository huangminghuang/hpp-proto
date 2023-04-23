#pragma once

#include <glaze/glaze.hpp>
#include <google/protobuf/descriptor.msg.hpp>

template <>
struct glz::meta<google::protobuf::FileDescriptorSet> {
  using T = google::protobuf::FileDescriptorSet;
  static constexpr auto value = object(
    "file", &T::file);
};

template <>
struct glz::meta<google::protobuf::FileDescriptorProto> {
  using T = google::protobuf::FileDescriptorProto;
  static constexpr auto value = object(
    "name", &T::name,
    "package", &T::package,
    "dependency", &T::dependency,
    "public_dependency", &T::public_dependency,
    "weak_dependency", &T::weak_dependency,
    "message_type", &T::message_type,
    "enum_type", &T::enum_type,
    "service", &T::service,
    "extension", &T::extension,
    "options", &T::options,
    "source_code_info", &T::source_code_info,
    "syntax", &T::syntax,
    "edition", &T::edition);
};

template <>
struct glz::meta<google::protobuf::DescriptorProto> {
  using T = google::protobuf::DescriptorProto;
  static constexpr auto value = object(
    "name", &T::name,
    "field", &T::field,
    "extension", &T::extension,
    "nested_type", &T::nested_type,
    "enum_type", &T::enum_type,
    "extension_range", &T::extension_range,
    "oneof_decl", &T::oneof_decl,
    "options", &T::options,
    "reserved_range", &T::reserved_range,
    "reserved_name", &T::reserved_name);
};

template <>
struct glz::meta<google::protobuf::DescriptorProto::ExtensionRange> {
  using T = google::protobuf::DescriptorProto::ExtensionRange;
  static constexpr auto value = object(
    "start", &T::start,
    "end", &T::end,
    "options", &T::options);
};

template <>
struct glz::meta<google::protobuf::DescriptorProto::ReservedRange> {
  using T = google::protobuf::DescriptorProto::ReservedRange;
  static constexpr auto value = object(
    "start", &T::start,
    "end", &T::end);
};

template <>
struct glz::meta<google::protobuf::ExtensionRangeOptions> {
  using T = google::protobuf::ExtensionRangeOptions;
  static constexpr auto value = object(
    "uninterpreted_option", &T::uninterpreted_option);
};

template <>
struct glz::meta<google::protobuf::FieldDescriptorProto> {
  using T = google::protobuf::FieldDescriptorProto;
  static constexpr auto value = object(
    "name", &T::name,
    "number", &T::number,
    "label", &T::label,
    "type", &T::type,
    "type_name", &T::type_name,
    "extendee", &T::extendee,
    "default_value", &T::default_value,
    "oneof_index", &T::oneof_index,
    "json_name", &T::json_name,
    "options", &T::options,
    "proto3_optional", &T::proto3_optional);
};

template <>
struct glz::meta<google::protobuf::FieldDescriptorProto::Type> {
  using enum google::protobuf::FieldDescriptorProto::Type;
  static constexpr auto value = enumerate(
    "TYPE_DOUBLE", TYPE_DOUBLE,
    "TYPE_FLOAT", TYPE_FLOAT,
    "TYPE_INT64", TYPE_INT64,
    "TYPE_UINT64", TYPE_UINT64,
    "TYPE_INT32", TYPE_INT32,
    "TYPE_FIXED64", TYPE_FIXED64,
    "TYPE_FIXED32", TYPE_FIXED32,
    "TYPE_BOOL", TYPE_BOOL,
    "TYPE_STRING", TYPE_STRING,
    "TYPE_GROUP", TYPE_GROUP,
    "TYPE_MESSAGE", TYPE_MESSAGE,
    "TYPE_BYTES", TYPE_BYTES,
    "TYPE_UINT32", TYPE_UINT32,
    "TYPE_ENUM", TYPE_ENUM,
    "TYPE_SFIXED32", TYPE_SFIXED32,
    "TYPE_SFIXED64", TYPE_SFIXED64,
    "TYPE_SINT32", TYPE_SINT32,
    "TYPE_SINT64", TYPE_SINT64);
};

template <>
struct glz::meta<google::protobuf::FieldDescriptorProto::Label> {
  using enum google::protobuf::FieldDescriptorProto::Label;
  static constexpr auto value = enumerate(
    "LABEL_OPTIONAL", LABEL_OPTIONAL,
    "LABEL_REQUIRED", LABEL_REQUIRED,
    "LABEL_REPEATED", LABEL_REPEATED);
};

template <>
struct glz::meta<google::protobuf::OneofDescriptorProto> {
  using T = google::protobuf::OneofDescriptorProto;
  static constexpr auto value = object(
    "name", &T::name,
    "options", &T::options);
};

template <>
struct glz::meta<google::protobuf::EnumDescriptorProto> {
  using T = google::protobuf::EnumDescriptorProto;
  static constexpr auto value = object(
    "name", &T::name,
    "value", &T::value,
    "options", &T::options,
    "reserved_range", &T::reserved_range,
    "reserved_name", &T::reserved_name);
};

template <>
struct glz::meta<google::protobuf::EnumDescriptorProto::EnumReservedRange> {
  using T = google::protobuf::EnumDescriptorProto::EnumReservedRange;
  static constexpr auto value = object(
    "start", &T::start,
    "end", &T::end);
};

template <>
struct glz::meta<google::protobuf::EnumValueDescriptorProto> {
  using T = google::protobuf::EnumValueDescriptorProto;
  static constexpr auto value = object(
    "name", &T::name,
    "number", &T::number,
    "options", &T::options);
};

template <>
struct glz::meta<google::protobuf::ServiceDescriptorProto> {
  using T = google::protobuf::ServiceDescriptorProto;
  static constexpr auto value = object(
    "name", &T::name,
    "method", &T::method,
    "options", &T::options);
};

template <>
struct glz::meta<google::protobuf::MethodDescriptorProto> {
  using T = google::protobuf::MethodDescriptorProto;
  static constexpr auto value = object(
    "name", &T::name,
    "input_type", &T::input_type,
    "output_type", &T::output_type,
    "options", &T::options,
    "client_streaming", &T::client_streaming,
    "server_streaming", &T::server_streaming);
};

template <>
struct glz::meta<google::protobuf::FileOptions> {
  using T = google::protobuf::FileOptions;
  static constexpr auto value = object(
    "java_package", &T::java_package,
    "java_outer_classname", &T::java_outer_classname,
    "java_multiple_files", &T::java_multiple_files,
    "java_generate_equals_and_hash", &T::java_generate_equals_and_hash,
    "java_string_check_utf8", &T::java_string_check_utf8,
    "optimize_for", &T::optimize_for,
    "go_package", &T::go_package,
    "cc_generic_services", &T::cc_generic_services,
    "java_generic_services", &T::java_generic_services,
    "py_generic_services", &T::py_generic_services,
    "php_generic_services", &T::php_generic_services,
    "deprecated", &T::deprecated,
    "cc_enable_arenas", &T::cc_enable_arenas,
    "objc_class_prefix", &T::objc_class_prefix,
    "csharp_namespace", &T::csharp_namespace,
    "swift_prefix", &T::swift_prefix,
    "php_class_prefix", &T::php_class_prefix,
    "php_namespace", &T::php_namespace,
    "php_metadata_namespace", &T::php_metadata_namespace,
    "ruby_package", &T::ruby_package,
    "uninterpreted_option", &T::uninterpreted_option);
};

template <>
struct glz::meta<google::protobuf::FileOptions::OptimizeMode> {
  using enum google::protobuf::FileOptions::OptimizeMode;
  static constexpr auto value = enumerate(
    "SPEED", SPEED,
    "CODE_SIZE", CODE_SIZE,
    "LITE_RUNTIME", LITE_RUNTIME);
};

template <>
struct glz::meta<google::protobuf::MessageOptions> {
  using T = google::protobuf::MessageOptions;
  static constexpr auto value = object(
    "message_set_wire_format", &T::message_set_wire_format,
    "no_standard_descriptor_accessor", &T::no_standard_descriptor_accessor,
    "deprecated", &T::deprecated,
    "map_entry", &T::map_entry,
    "deprecated_legacy_json_field_conflicts", &T::deprecated_legacy_json_field_conflicts,
    "uninterpreted_option", &T::uninterpreted_option);
};

template <>
struct glz::meta<google::protobuf::FieldOptions> {
  using T = google::protobuf::FieldOptions;
  static constexpr auto value = object(
    "ctype", &T::ctype,
    "packed", &T::packed,
    "jstype", &T::jstype,
    "lazy", &T::lazy,
    "unverified_lazy", &T::unverified_lazy,
    "deprecated", &T::deprecated,
    "weak", &T::weak,
    "debug_redact", &T::debug_redact,
    "retention", &T::retention,
    "target", &T::target,
    "uninterpreted_option", &T::uninterpreted_option);
};

template <>
struct glz::meta<google::protobuf::FieldOptions::CType> {
  using enum google::protobuf::FieldOptions::CType;
  static constexpr auto value = enumerate(
    "STRING", STRING,
    "CORD", CORD,
    "STRING_PIECE", STRING_PIECE);
};

template <>
struct glz::meta<google::protobuf::FieldOptions::JSType> {
  using enum google::protobuf::FieldOptions::JSType;
  static constexpr auto value = enumerate(
    "JS_NORMAL", JS_NORMAL,
    "JS_STRING", JS_STRING,
    "JS_NUMBER", JS_NUMBER);
};

template <>
struct glz::meta<google::protobuf::FieldOptions::OptionRetention> {
  using enum google::protobuf::FieldOptions::OptionRetention;
  static constexpr auto value = enumerate(
    "RETENTION_UNKNOWN", RETENTION_UNKNOWN,
    "RETENTION_RUNTIME", RETENTION_RUNTIME,
    "RETENTION_SOURCE", RETENTION_SOURCE);
};

template <>
struct glz::meta<google::protobuf::FieldOptions::OptionTargetType> {
  using enum google::protobuf::FieldOptions::OptionTargetType;
  static constexpr auto value = enumerate(
    "TARGET_TYPE_UNKNOWN", TARGET_TYPE_UNKNOWN,
    "TARGET_TYPE_FILE", TARGET_TYPE_FILE,
    "TARGET_TYPE_EXTENSION_RANGE", TARGET_TYPE_EXTENSION_RANGE,
    "TARGET_TYPE_MESSAGE", TARGET_TYPE_MESSAGE,
    "TARGET_TYPE_FIELD", TARGET_TYPE_FIELD,
    "TARGET_TYPE_ONEOF", TARGET_TYPE_ONEOF,
    "TARGET_TYPE_ENUM", TARGET_TYPE_ENUM,
    "TARGET_TYPE_ENUM_ENTRY", TARGET_TYPE_ENUM_ENTRY,
    "TARGET_TYPE_SERVICE", TARGET_TYPE_SERVICE,
    "TARGET_TYPE_METHOD", TARGET_TYPE_METHOD);
};

template <>
struct glz::meta<google::protobuf::OneofOptions> {
  using T = google::protobuf::OneofOptions;
  static constexpr auto value = object(
    "uninterpreted_option", &T::uninterpreted_option);
};

template <>
struct glz::meta<google::protobuf::EnumOptions> {
  using T = google::protobuf::EnumOptions;
  static constexpr auto value = object(
    "allow_alias", &T::allow_alias,
    "deprecated", &T::deprecated,
    "deprecated_legacy_json_field_conflicts", &T::deprecated_legacy_json_field_conflicts,
    "uninterpreted_option", &T::uninterpreted_option);
};

template <>
struct glz::meta<google::protobuf::EnumValueOptions> {
  using T = google::protobuf::EnumValueOptions;
  static constexpr auto value = object(
    "deprecated", &T::deprecated,
    "uninterpreted_option", &T::uninterpreted_option);
};

template <>
struct glz::meta<google::protobuf::ServiceOptions> {
  using T = google::protobuf::ServiceOptions;
  static constexpr auto value = object(
    "deprecated", &T::deprecated,
    "uninterpreted_option", &T::uninterpreted_option);
};

template <>
struct glz::meta<google::protobuf::MethodOptions> {
  using T = google::protobuf::MethodOptions;
  static constexpr auto value = object(
    "deprecated", &T::deprecated,
    "idempotency_level", &T::idempotency_level,
    "uninterpreted_option", &T::uninterpreted_option);
};

template <>
struct glz::meta<google::protobuf::MethodOptions::IdempotencyLevel> {
  using enum google::protobuf::MethodOptions::IdempotencyLevel;
  static constexpr auto value = enumerate(
    "IDEMPOTENCY_UNKNOWN", IDEMPOTENCY_UNKNOWN,
    "NO_SIDE_EFFECTS", NO_SIDE_EFFECTS,
    "IDEMPOTENT", IDEMPOTENT);
};

template <>
struct glz::meta<google::protobuf::UninterpretedOption> {
  using T = google::protobuf::UninterpretedOption;
  static constexpr auto value = object(
    "name", &T::name,
    "identifier_value", &T::identifier_value,
    "positive_int_value", &T::positive_int_value,
    "negative_int_value", &T::negative_int_value,
    "double_value", &T::double_value,
    "string_value", &T::string_value,
    "aggregate_value", &T::aggregate_value);
};

template <>
struct glz::meta<google::protobuf::UninterpretedOption::NamePart> {
  using T = google::protobuf::UninterpretedOption::NamePart;
  static constexpr auto value = object(
    "name_part", &T::name_part,
    "is_extension", &T::is_extension);
};

template <>
struct glz::meta<google::protobuf::SourceCodeInfo> {
  using T = google::protobuf::SourceCodeInfo;
  static constexpr auto value = object(
    "location", &T::location);
};

template <>
struct glz::meta<google::protobuf::SourceCodeInfo::Location> {
  using T = google::protobuf::SourceCodeInfo::Location;
  static constexpr auto value = object(
    "path", &T::path,
    "span", &T::span,
    "leading_comments", &T::leading_comments,
    "trailing_comments", &T::trailing_comments,
    "leading_detached_comments", &T::leading_detached_comments);
};

template <>
struct glz::meta<google::protobuf::GeneratedCodeInfo> {
  using T = google::protobuf::GeneratedCodeInfo;
  static constexpr auto value = object(
    "annotation", &T::annotation);
};

template <>
struct glz::meta<google::protobuf::GeneratedCodeInfo::Annotation> {
  using T = google::protobuf::GeneratedCodeInfo::Annotation;
  static constexpr auto value = object(
    "path", &T::path,
    "source_file", &T::source_file,
    "begin", &T::begin,
    "end", &T::end,
    "semantic", &T::semantic);
};

template <>
struct glz::meta<google::protobuf::GeneratedCodeInfo::Annotation::Semantic> {
  using enum google::protobuf::GeneratedCodeInfo::Annotation::Semantic;
  static constexpr auto value = enumerate(
    "NONE", NONE,
    "SET", SET,
    "ALIAS", ALIAS);
};

