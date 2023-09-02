#pragma once

#include <hpp_proto/json_serializer.h>
#include <google/protobuf/descriptor.msg.hpp>

template <>
struct glz::meta<google::protobuf::FileDescriptorSet> {
  using T = google::protobuf::FileDescriptorSet;
  static constexpr auto value = object(
    "file", hpp::proto::as_optional_ref<&T::file>());
};

template <>
struct glz::meta<google::protobuf::FileDescriptorProto> {
  using T = google::protobuf::FileDescriptorProto;
  static constexpr auto value = object(
    "name", hpp::proto::as_optional_ref<&T::name>(),
    "package", hpp::proto::as_optional_ref<&T::package>(),
    "dependency", hpp::proto::as_optional_ref<&T::dependency>(),
    "publicDependency", hpp::proto::as_optional_ref<&T::public_dependency>(),
    "weakDependency", hpp::proto::as_optional_ref<&T::weak_dependency>(),
    "messageType", hpp::proto::as_optional_ref<&T::message_type>(),
    "enumType", hpp::proto::as_optional_ref<&T::enum_type>(),
    "service", hpp::proto::as_optional_ref<&T::service>(),
    "extension", hpp::proto::as_optional_ref<&T::extension>(),
    "options", &T::options,
    "sourceCodeInfo", &T::source_code_info,
    "syntax", hpp::proto::as_optional_ref<&T::syntax>(),
    "edition", hpp::proto::as_optional_ref<&T::edition>());
};

template <>
struct glz::meta<google::protobuf::DescriptorProto> {
  using T = google::protobuf::DescriptorProto;
  static constexpr auto value = object(
    "name", hpp::proto::as_optional_ref<&T::name>(),
    "field", hpp::proto::as_optional_ref<&T::field>(),
    "extension", hpp::proto::as_optional_ref<&T::extension>(),
    "nestedType", hpp::proto::as_optional_ref<&T::nested_type>(),
    "enumType", hpp::proto::as_optional_ref<&T::enum_type>(),
    "extensionRange", hpp::proto::as_optional_ref<&T::extension_range>(),
    "oneofDecl", hpp::proto::as_optional_ref<&T::oneof_decl>(),
    "options", &T::options,
    "reservedRange", hpp::proto::as_optional_ref<&T::reserved_range>(),
    "reservedName", hpp::proto::as_optional_ref<&T::reserved_name>());
};

template <>
struct glz::meta<google::protobuf::DescriptorProto::ExtensionRange> {
  using T = google::protobuf::DescriptorProto::ExtensionRange;
  static constexpr auto value = object(
    "start", hpp::proto::as_optional_ref<&T::start>(),
    "end", hpp::proto::as_optional_ref<&T::end>(),
    "options", &T::options);
};

template <>
struct glz::meta<google::protobuf::DescriptorProto::ReservedRange> {
  using T = google::protobuf::DescriptorProto::ReservedRange;
  static constexpr auto value = object(
    "start", hpp::proto::as_optional_ref<&T::start>(),
    "end", hpp::proto::as_optional_ref<&T::end>());
};

template <>
struct glz::meta<google::protobuf::ExtensionRangeOptions> {
  using T = google::protobuf::ExtensionRangeOptions;
  static constexpr auto value = object(
    "uninterpretedOption", hpp::proto::as_optional_ref<&T::uninterpreted_option>(),
    "declaration", hpp::proto::as_optional_ref<&T::declaration>(),
    "verification", hpp::proto::as_optional_ref<&T::verification, ::google::protobuf::ExtensionRangeOptions::VerificationState::UNVERIFIED>());
};

template <>
struct glz::meta<google::protobuf::ExtensionRangeOptions::Declaration> {
  using T = google::protobuf::ExtensionRangeOptions::Declaration;
  static constexpr auto value = object(
    "number", hpp::proto::as_optional_ref<&T::number>(),
    "fullName", hpp::proto::as_optional_ref<&T::full_name>(),
    "type", hpp::proto::as_optional_ref<&T::type>(),
    "isRepeated", hpp::proto::as_optional_ref<&T::is_repeated>(),
    "reserved", hpp::proto::as_optional_ref<&T::reserved>(),
    "repeated", hpp::proto::as_optional_ref<&T::repeated>());
};

template <>
struct glz::meta<google::protobuf::ExtensionRangeOptions::VerificationState> {
  using enum google::protobuf::ExtensionRangeOptions::VerificationState;
  static constexpr auto value = enumerate(
    "DECLARATION", DECLARATION,
    "UNVERIFIED", UNVERIFIED);
};

template <>
struct glz::meta<google::protobuf::FieldDescriptorProto> {
  using T = google::protobuf::FieldDescriptorProto;
  static constexpr auto value = object(
    "name", hpp::proto::as_optional_ref<&T::name>(),
    "number", hpp::proto::as_optional_ref<&T::number>(),
    "label", hpp::proto::as_optional_ref<&T::label, ::google::protobuf::FieldDescriptorProto::Label::LABEL_OPTIONAL>(),
    "type", hpp::proto::as_optional_ref<&T::type, ::google::protobuf::FieldDescriptorProto::Type::TYPE_DOUBLE>(),
    "typeName", hpp::proto::as_optional_ref<&T::type_name>(),
    "extendee", hpp::proto::as_optional_ref<&T::extendee>(),
    "defaultValue", hpp::proto::as_optional_ref<&T::default_value>(),
    "oneofIndex", &T::oneof_index,
    "jsonName", hpp::proto::as_optional_ref<&T::json_name>(),
    "options", &T::options,
    "proto3Optional", hpp::proto::as_optional_ref<&T::proto3_optional>());
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
    "name", hpp::proto::as_optional_ref<&T::name>(),
    "options", &T::options);
};

template <>
struct glz::meta<google::protobuf::EnumDescriptorProto> {
  using T = google::protobuf::EnumDescriptorProto;
  static constexpr auto value = object(
    "name", hpp::proto::as_optional_ref<&T::name>(),
    "value", hpp::proto::as_optional_ref<&T::value>(),
    "options", &T::options,
    "reservedRange", hpp::proto::as_optional_ref<&T::reserved_range>(),
    "reservedName", hpp::proto::as_optional_ref<&T::reserved_name>());
};

template <>
struct glz::meta<google::protobuf::EnumDescriptorProto::EnumReservedRange> {
  using T = google::protobuf::EnumDescriptorProto::EnumReservedRange;
  static constexpr auto value = object(
    "start", hpp::proto::as_optional_ref<&T::start>(),
    "end", hpp::proto::as_optional_ref<&T::end>());
};

template <>
struct glz::meta<google::protobuf::EnumValueDescriptorProto> {
  using T = google::protobuf::EnumValueDescriptorProto;
  static constexpr auto value = object(
    "name", hpp::proto::as_optional_ref<&T::name>(),
    "number", hpp::proto::as_optional_ref<&T::number>(),
    "options", &T::options);
};

template <>
struct glz::meta<google::protobuf::ServiceDescriptorProto> {
  using T = google::protobuf::ServiceDescriptorProto;
  static constexpr auto value = object(
    "name", hpp::proto::as_optional_ref<&T::name>(),
    "method", hpp::proto::as_optional_ref<&T::method>(),
    "options", &T::options);
};

template <>
struct glz::meta<google::protobuf::MethodDescriptorProto> {
  using T = google::protobuf::MethodDescriptorProto;
  static constexpr auto value = object(
    "name", hpp::proto::as_optional_ref<&T::name>(),
    "inputType", hpp::proto::as_optional_ref<&T::input_type>(),
    "outputType", hpp::proto::as_optional_ref<&T::output_type>(),
    "options", &T::options,
    "clientStreaming", hpp::proto::as_optional_ref<&T::client_streaming, false>(),
    "serverStreaming", hpp::proto::as_optional_ref<&T::server_streaming, false>());
};

template <>
struct glz::meta<google::protobuf::FileOptions> {
  using T = google::protobuf::FileOptions;
  static constexpr auto value = object(
    "javaPackage", hpp::proto::as_optional_ref<&T::java_package>(),
    "javaOuterClassname", hpp::proto::as_optional_ref<&T::java_outer_classname>(),
    "javaMultipleFiles", hpp::proto::as_optional_ref<&T::java_multiple_files, false>(),
    "javaGenerateEqualsAndHash", hpp::proto::as_optional_ref<&T::java_generate_equals_and_hash>(),
    "javaStringCheckUtf8", hpp::proto::as_optional_ref<&T::java_string_check_utf8, false>(),
    "optimizeFor", hpp::proto::as_optional_ref<&T::optimize_for, ::google::protobuf::FileOptions::OptimizeMode::SPEED>(),
    "goPackage", hpp::proto::as_optional_ref<&T::go_package>(),
    "ccGenericServices", hpp::proto::as_optional_ref<&T::cc_generic_services, false>(),
    "javaGenericServices", hpp::proto::as_optional_ref<&T::java_generic_services, false>(),
    "pyGenericServices", hpp::proto::as_optional_ref<&T::py_generic_services, false>(),
    "phpGenericServices", hpp::proto::as_optional_ref<&T::php_generic_services, false>(),
    "deprecated", hpp::proto::as_optional_ref<&T::deprecated, false>(),
    "ccEnableArenas", hpp::proto::as_optional_ref<&T::cc_enable_arenas, true>(),
    "objcClassPrefix", hpp::proto::as_optional_ref<&T::objc_class_prefix>(),
    "csharpNamespace", hpp::proto::as_optional_ref<&T::csharp_namespace>(),
    "swiftPrefix", hpp::proto::as_optional_ref<&T::swift_prefix>(),
    "phpClassPrefix", hpp::proto::as_optional_ref<&T::php_class_prefix>(),
    "phpNamespace", hpp::proto::as_optional_ref<&T::php_namespace>(),
    "phpMetadataNamespace", hpp::proto::as_optional_ref<&T::php_metadata_namespace>(),
    "rubyPackage", hpp::proto::as_optional_ref<&T::ruby_package>(),
    "uninterpretedOption", hpp::proto::as_optional_ref<&T::uninterpreted_option>());
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
    "messageSetWireFormat", hpp::proto::as_optional_ref<&T::message_set_wire_format, false>(),
    "noStandardDescriptorAccessor", hpp::proto::as_optional_ref<&T::no_standard_descriptor_accessor, false>(),
    "deprecated", hpp::proto::as_optional_ref<&T::deprecated, false>(),
    "mapEntry", hpp::proto::as_optional_ref<&T::map_entry>(),
    "deprecatedLegacyJsonFieldConflicts", hpp::proto::as_optional_ref<&T::deprecated_legacy_json_field_conflicts>(),
    "uninterpretedOption", hpp::proto::as_optional_ref<&T::uninterpreted_option>());
};

template <>
struct glz::meta<google::protobuf::FieldOptions> {
  using T = google::protobuf::FieldOptions;
  static constexpr auto value = object(
    "ctype", hpp::proto::as_optional_ref<&T::ctype, ::google::protobuf::FieldOptions::CType::STRING>(),
    "packed", &T::packed,
    "jstype", hpp::proto::as_optional_ref<&T::jstype, ::google::protobuf::FieldOptions::JSType::JS_NORMAL>(),
    "lazy", hpp::proto::as_optional_ref<&T::lazy, false>(),
    "unverifiedLazy", hpp::proto::as_optional_ref<&T::unverified_lazy, false>(),
    "deprecated", hpp::proto::as_optional_ref<&T::deprecated, false>(),
    "weak", hpp::proto::as_optional_ref<&T::weak, false>(),
    "debugRedact", hpp::proto::as_optional_ref<&T::debug_redact, false>(),
    "retention", hpp::proto::as_optional_ref<&T::retention, ::google::protobuf::FieldOptions::OptionRetention::RETENTION_UNKNOWN>(),
    "target", hpp::proto::as_optional_ref<&T::target, ::google::protobuf::FieldOptions::OptionTargetType::TARGET_TYPE_UNKNOWN>(),
    "targets", hpp::proto::as_optional_ref<&T::targets>(),
    "uninterpretedOption", hpp::proto::as_optional_ref<&T::uninterpreted_option>());
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
    "uninterpretedOption", hpp::proto::as_optional_ref<&T::uninterpreted_option>());
};

template <>
struct glz::meta<google::protobuf::EnumOptions> {
  using T = google::protobuf::EnumOptions;
  static constexpr auto value = object(
    "allowAlias", hpp::proto::as_optional_ref<&T::allow_alias>(),
    "deprecated", hpp::proto::as_optional_ref<&T::deprecated, false>(),
    "deprecatedLegacyJsonFieldConflicts", hpp::proto::as_optional_ref<&T::deprecated_legacy_json_field_conflicts>(),
    "uninterpretedOption", hpp::proto::as_optional_ref<&T::uninterpreted_option>());
};

template <>
struct glz::meta<google::protobuf::EnumValueOptions> {
  using T = google::protobuf::EnumValueOptions;
  static constexpr auto value = object(
    "deprecated", hpp::proto::as_optional_ref<&T::deprecated, false>(),
    "uninterpretedOption", hpp::proto::as_optional_ref<&T::uninterpreted_option>());
};

template <>
struct glz::meta<google::protobuf::ServiceOptions> {
  using T = google::protobuf::ServiceOptions;
  static constexpr auto value = object(
    "deprecated", hpp::proto::as_optional_ref<&T::deprecated, false>(),
    "uninterpretedOption", hpp::proto::as_optional_ref<&T::uninterpreted_option>());
};

template <>
struct glz::meta<google::protobuf::MethodOptions> {
  using T = google::protobuf::MethodOptions;
  static constexpr auto value = object(
    "deprecated", hpp::proto::as_optional_ref<&T::deprecated, false>(),
    "idempotencyLevel", hpp::proto::as_optional_ref<&T::idempotency_level, ::google::protobuf::MethodOptions::IdempotencyLevel::IDEMPOTENCY_UNKNOWN>(),
    "uninterpretedOption", hpp::proto::as_optional_ref<&T::uninterpreted_option>());
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
    "name", hpp::proto::as_optional_ref<&T::name>(),
    "identifierValue", hpp::proto::as_optional_ref<&T::identifier_value>(),
    "positiveIntValue", hpp::proto::as_optional_ref<&T::positive_int_value>(),
    "negativeIntValue", hpp::proto::as_optional_ref<&T::negative_int_value>(),
    "doubleValue", hpp::proto::as_optional_ref<&T::double_value>(),
    "stringValue", hpp::proto::as_optional_ref<&T::string_value>(),
    "aggregateValue", hpp::proto::as_optional_ref<&T::aggregate_value>());
};

template <>
struct glz::meta<google::protobuf::UninterpretedOption::NamePart> {
  using T = google::protobuf::UninterpretedOption::NamePart;
  static constexpr auto value = object(
    "namePart", &T::name_part,
    "isExtension", &T::is_extension);
};

template <>
struct glz::meta<google::protobuf::SourceCodeInfo> {
  using T = google::protobuf::SourceCodeInfo;
  static constexpr auto value = object(
    "location", hpp::proto::as_optional_ref<&T::location>());
};

template <>
struct glz::meta<google::protobuf::SourceCodeInfo::Location> {
  using T = google::protobuf::SourceCodeInfo::Location;
  static constexpr auto value = object(
    "path", hpp::proto::as_optional_ref<&T::path>(),
    "span", hpp::proto::as_optional_ref<&T::span>(),
    "leadingComments", hpp::proto::as_optional_ref<&T::leading_comments>(),
    "trailingComments", hpp::proto::as_optional_ref<&T::trailing_comments>(),
    "leadingDetachedComments", hpp::proto::as_optional_ref<&T::leading_detached_comments>());
};

template <>
struct glz::meta<google::protobuf::GeneratedCodeInfo> {
  using T = google::protobuf::GeneratedCodeInfo;
  static constexpr auto value = object(
    "annotation", hpp::proto::as_optional_ref<&T::annotation>());
};

template <>
struct glz::meta<google::protobuf::GeneratedCodeInfo::Annotation> {
  using T = google::protobuf::GeneratedCodeInfo::Annotation;
  static constexpr auto value = object(
    "path", hpp::proto::as_optional_ref<&T::path>(),
    "sourceFile", hpp::proto::as_optional_ref<&T::source_file>(),
    "begin", hpp::proto::as_optional_ref<&T::begin>(),
    "end", hpp::proto::as_optional_ref<&T::end>(),
    "semantic", hpp::proto::as_optional_ref<&T::semantic, ::google::protobuf::GeneratedCodeInfo::Annotation::Semantic::NONE>());
};

template <>
struct glz::meta<google::protobuf::GeneratedCodeInfo::Annotation::Semantic> {
  using enum google::protobuf::GeneratedCodeInfo::Annotation::Semantic;
  static constexpr auto value = enumerate(
    "NONE", NONE,
    "SET", SET,
    "ALIAS", ALIAS);
};

