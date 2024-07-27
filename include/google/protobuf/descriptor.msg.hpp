// Generated by the protocol buffer compiler.  DO NOT EDIT!
// NO CHECKED-IN PROTOBUF GENCODE
// generation command line:
//    protoc --plugin=protoc-gen-hpp=/Users/huang-minghuang/opensource/hpp-proto/build/debug/protoc-plugin/protoc-gen-hpp --hpp_out proto2_explicit_presence=.google.protobuf.FieldDescriptorProto.oneof_index,proto2_explicit_presence=.google.protobuf.FieldOptions.packed:${out_dir} google/protobuf/descriptor.proto

#pragma once

#include <hpp_proto/field_types.h>

namespace google::protobuf {

using namespace hpp::proto::literals;
struct UninterpretedOption {
  struct NamePart {
    std::string name_part = {};
    bool is_extension = {};

    bool operator == (const NamePart&) const = default;
  };

  std::vector<NamePart> name;
  std::string identifier_value = {};
  uint64_t positive_int_value = {};
  int64_t negative_int_value = {};
  double double_value = {};
  hpp::proto::bytes string_value = {};
  std::string aggregate_value = {};

  bool operator == (const UninterpretedOption&) const = default;
};

struct FeatureSet {
  enum class FieldPresence {
    FIELD_PRESENCE_UNKNOWN = 0,
    EXPLICIT = 1,
    IMPLICIT = 2,
    LEGACY_REQUIRED = 3 
  };

  enum class EnumType {
    ENUM_TYPE_UNKNOWN = 0,
    OPEN = 1,
    CLOSED = 2 
  };

  enum class RepeatedFieldEncoding {
    REPEATED_FIELD_ENCODING_UNKNOWN = 0,
    PACKED = 1,
    EXPANDED = 2 
  };

  enum class StringFieldValidation {
    STRING_FIELD_VALIDATION_UNKNOWN = 0,
    MANDATORY = 1,
    HINT = 2,
    NONE = 3 
  };

  enum class MessageEncoding {
    MESSAGE_ENCODING_UNKNOWN = 0,
    LENGTH_PREFIXED = 1,
    DELIMITED = 2 
  };

  enum class JsonFormat {
    JSON_FORMAT_UNKNOWN = 0,
    ALLOW = 1,
    LEGACY_BEST_EFFORT = 2 
  };

  FieldPresence field_presence = FieldPresence::FIELD_PRESENCE_UNKNOWN;
  EnumType enum_type = EnumType::ENUM_TYPE_UNKNOWN;
  RepeatedFieldEncoding repeated_field_encoding = RepeatedFieldEncoding::REPEATED_FIELD_ENCODING_UNKNOWN;
  StringFieldValidation string_field_validation = StringFieldValidation::STRING_FIELD_VALIDATION_UNKNOWN;
  MessageEncoding message_encoding = MessageEncoding::MESSAGE_ENCODING_UNKNOWN;
  JsonFormat json_format = JsonFormat::JSON_FORMAT_UNKNOWN;
  hpp::proto::heap_based_optional<FeatureSet> raw_features;

  struct extension_t {
    using pb_extension = FeatureSet;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  [[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  template<typename Meta>  requires Meta::is_repeated  [[nodiscard]] auto set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const FeatureSet&) const = default;
};

struct SourceCodeInfo {
  struct Location {
    std::vector<int32_t> path;
    std::vector<int32_t> span;
    std::string leading_comments = {};
    std::string trailing_comments = {};
    std::vector<std::string> leading_detached_comments;

    bool operator == (const Location&) const = default;
  };

  std::vector<Location> location;

  bool operator == (const SourceCodeInfo&) const = default;
};

struct GeneratedCodeInfo {
  struct Annotation {
    enum class Semantic {
      NONE = 0,
      SET = 1,
      ALIAS = 2 
    };

    std::vector<int32_t> path;
    std::string source_file = {};
    int32_t begin = {};
    int32_t end = {};
    Semantic semantic = Semantic::NONE;

    bool operator == (const Annotation&) const = default;
  };

  std::vector<Annotation> annotation;

  bool operator == (const GeneratedCodeInfo&) const = default;
};

struct MethodOptions {
  enum class IdempotencyLevel {
    IDEMPOTENCY_UNKNOWN = 0,
    NO_SIDE_EFFECTS = 1,
    IDEMPOTENT = 2 
  };

  bool deprecated = false;
  IdempotencyLevel idempotency_level = IdempotencyLevel::IDEMPOTENCY_UNKNOWN;
  std::optional<FeatureSet> features;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = MethodOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  [[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  template<typename Meta>  requires Meta::is_repeated  [[nodiscard]] auto set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const MethodOptions&) const = default;
};

struct ServiceOptions {
  std::optional<FeatureSet> features;
  bool deprecated = false;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = ServiceOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  [[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  template<typename Meta>  requires Meta::is_repeated  [[nodiscard]] auto set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const ServiceOptions&) const = default;
};

struct EnumValueOptions {
  bool deprecated = false;
  std::optional<FeatureSet> features;
  bool debug_redact = false;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = EnumValueOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  [[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  template<typename Meta>  requires Meta::is_repeated  [[nodiscard]] auto set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const EnumValueOptions&) const = default;
};

struct EnumOptions {
  bool allow_alias = {};
  bool deprecated = false;
  bool deprecated_legacy_json_field_conflicts = {};
  std::optional<FeatureSet> features;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = EnumOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  [[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  template<typename Meta>  requires Meta::is_repeated  [[nodiscard]] auto set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const EnumOptions&) const = default;
};

struct OneofOptions {
  std::optional<FeatureSet> features;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = OneofOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  [[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  template<typename Meta>  requires Meta::is_repeated  [[nodiscard]] auto set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const OneofOptions&) const = default;
};

struct FieldOptions {
  enum class CType {
    STRING = 0,
    CORD = 1,
    STRING_PIECE = 2 
  };

  enum class JSType {
    JS_NORMAL = 0,
    JS_STRING = 1,
    JS_NUMBER = 2 
  };

  enum class OptionRetention {
    RETENTION_UNKNOWN = 0,
    RETENTION_RUNTIME = 1,
    RETENTION_SOURCE = 2 
  };

  enum class OptionTargetType {
    TARGET_TYPE_UNKNOWN = 0,
    TARGET_TYPE_FILE = 1,
    TARGET_TYPE_EXTENSION_RANGE = 2,
    TARGET_TYPE_MESSAGE = 3,
    TARGET_TYPE_FIELD = 4,
    TARGET_TYPE_ONEOF = 5,
    TARGET_TYPE_ENUM = 6,
    TARGET_TYPE_ENUM_ENTRY = 7,
    TARGET_TYPE_SERVICE = 8,
    TARGET_TYPE_METHOD = 9 
  };

  struct EditionDefault {
    std::string edition = {};
    std::string value = {};

    bool operator == (const EditionDefault&) const = default;
  };

  CType ctype = CType::STRING;
  hpp::proto::optional<bool> packed;
  JSType jstype = JSType::JS_NORMAL;
  bool lazy = false;
  bool unverified_lazy = false;
  bool deprecated = false;
  bool weak = false;
  bool debug_redact = false;
  OptionRetention retention = OptionRetention::RETENTION_UNKNOWN;
  std::vector<OptionTargetType> targets;
  std::vector<EditionDefault> edition_defaults;
  std::optional<FeatureSet> features;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = FieldOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  [[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  template<typename Meta>  requires Meta::is_repeated  [[nodiscard]] auto set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const FieldOptions&) const = default;
};

struct MessageOptions {
  bool message_set_wire_format = false;
  bool no_standard_descriptor_accessor = false;
  bool deprecated = false;
  bool map_entry = {};
  bool deprecated_legacy_json_field_conflicts = {};
  std::optional<FeatureSet> features;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = MessageOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  [[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  template<typename Meta>  requires Meta::is_repeated  [[nodiscard]] auto set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const MessageOptions&) const = default;
};

struct FileOptions {
  enum class OptimizeMode {
    SPEED = 1,
    CODE_SIZE = 2,
    LITE_RUNTIME = 3 
  };

  std::string java_package = {};
  std::string java_outer_classname = {};
  bool java_multiple_files = false;
  bool java_generate_equals_and_hash = {};
  bool java_string_check_utf8 = false;
  OptimizeMode optimize_for = OptimizeMode::SPEED;
  std::string go_package = {};
  bool cc_generic_services = false;
  bool java_generic_services = false;
  bool py_generic_services = false;
  bool php_generic_services = false;
  bool deprecated = false;
  bool cc_enable_arenas = true;
  std::string objc_class_prefix = {};
  std::string csharp_namespace = {};
  std::string swift_prefix = {};
  std::string php_class_prefix = {};
  std::string php_namespace = {};
  std::string php_metadata_namespace = {};
  std::string ruby_package = {};
  std::optional<FeatureSet> features;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = FileOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  [[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  template<typename Meta>  requires Meta::is_repeated  [[nodiscard]] auto set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const FileOptions&) const = default;
};

struct MethodDescriptorProto {
  std::string name = {};
  std::string input_type = {};
  std::string output_type = {};
  std::optional<MethodOptions> options;
  bool client_streaming = false;
  bool server_streaming = false;

  bool operator == (const MethodDescriptorProto&) const = default;
};

struct ServiceDescriptorProto {
  std::string name = {};
  std::vector<MethodDescriptorProto> method;
  std::optional<ServiceOptions> options;

  bool operator == (const ServiceDescriptorProto&) const = default;
};

struct EnumValueDescriptorProto {
  std::string name = {};
  int32_t number = {};
  std::optional<EnumValueOptions> options;

  bool operator == (const EnumValueDescriptorProto&) const = default;
};

struct EnumDescriptorProto {
  struct EnumReservedRange {
    int32_t start = {};
    int32_t end = {};

    bool operator == (const EnumReservedRange&) const = default;
  };

  std::string name = {};
  std::vector<EnumValueDescriptorProto> value;
  std::optional<EnumOptions> options;
  std::vector<EnumReservedRange> reserved_range;
  std::vector<std::string> reserved_name;

  bool operator == (const EnumDescriptorProto&) const = default;
};

struct OneofDescriptorProto {
  std::string name = {};
  std::optional<OneofOptions> options;

  bool operator == (const OneofDescriptorProto&) const = default;
};

struct FieldDescriptorProto {
  enum class Type {
    TYPE_DOUBLE = 1,
    TYPE_FLOAT = 2,
    TYPE_INT64 = 3,
    TYPE_UINT64 = 4,
    TYPE_INT32 = 5,
    TYPE_FIXED64 = 6,
    TYPE_FIXED32 = 7,
    TYPE_BOOL = 8,
    TYPE_STRING = 9,
    TYPE_GROUP = 10,
    TYPE_MESSAGE = 11,
    TYPE_BYTES = 12,
    TYPE_UINT32 = 13,
    TYPE_ENUM = 14,
    TYPE_SFIXED32 = 15,
    TYPE_SFIXED64 = 16,
    TYPE_SINT32 = 17,
    TYPE_SINT64 = 18 
  };

  enum class Label {
    LABEL_OPTIONAL = 1,
    LABEL_REQUIRED = 2,
    LABEL_REPEATED = 3 
  };

  std::string name = {};
  int32_t number = {};
  Label label = Label::LABEL_OPTIONAL;
  Type type = Type::TYPE_DOUBLE;
  std::string type_name = {};
  std::string extendee = {};
  std::string default_value = {};
  hpp::proto::optional<int32_t> oneof_index;
  std::string json_name = {};
  std::optional<FieldOptions> options;
  bool proto3_optional = {};

  bool operator == (const FieldDescriptorProto&) const = default;
};

struct ExtensionRangeOptions {
  enum class VerificationState {
    DECLARATION = 0,
    UNVERIFIED = 1 
  };

  struct Declaration {
    int32_t number = {};
    std::string full_name = {};
    std::string type = {};
    bool reserved = {};
    bool repeated = {};

    bool operator == (const Declaration&) const = default;
  };

  std::vector<UninterpretedOption> uninterpreted_option;
  std::vector<Declaration> declaration;
  std::optional<FeatureSet> features;
  VerificationState verification = VerificationState::UNVERIFIED;

  struct extension_t {
    using pb_extension = ExtensionRangeOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  [[nodiscard]] auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  [[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  template<typename Meta>  requires Meta::is_repeated  [[nodiscard]] auto set_extension(Meta meta, std::initializer_list<typename Meta::element_type> value) {
    return meta.write(extensions, std::span{value.begin(), value.end()});
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const ExtensionRangeOptions&) const = default;
};

struct DescriptorProto {
  struct ExtensionRange {
    int32_t start = {};
    int32_t end = {};
    std::optional<ExtensionRangeOptions> options;

    bool operator == (const ExtensionRange&) const = default;
  };

  struct ReservedRange {
    int32_t start = {};
    int32_t end = {};

    bool operator == (const ReservedRange&) const = default;
  };

  std::string name = {};
  std::vector<FieldDescriptorProto> field;
  std::vector<FieldDescriptorProto> extension;
  std::vector<DescriptorProto> nested_type;
  std::vector<EnumDescriptorProto> enum_type;
  std::vector<ExtensionRange> extension_range;
  std::vector<OneofDescriptorProto> oneof_decl;
  std::optional<MessageOptions> options;
  std::vector<ReservedRange> reserved_range;
  std::vector<std::string> reserved_name;

  bool operator == (const DescriptorProto&) const = default;
};

struct FileDescriptorProto {
  std::string name = {};
  std::string package = {};
  std::vector<std::string> dependency;
  std::vector<int32_t> public_dependency;
  std::vector<int32_t> weak_dependency;
  std::vector<DescriptorProto> message_type;
  std::vector<EnumDescriptorProto> enum_type;
  std::vector<ServiceDescriptorProto> service;
  std::vector<FieldDescriptorProto> extension;
  std::optional<FileOptions> options;
  std::optional<SourceCodeInfo> source_code_info;
  std::string syntax = {};
  std::string edition = {};

  bool operator == (const FileDescriptorProto&) const = default;
};

struct FileDescriptorSet {
  std::vector<FileDescriptorProto> file;

  bool operator == (const FileDescriptorSet&) const = default;
};

constexpr auto message_type_url(const UninterpretedOption::NamePart&) { return "type.googleapis.com/google.protobuf.UninterpretedOption.NamePart"_cts; }
constexpr auto message_type_url(const UninterpretedOption&) { return "type.googleapis.com/google.protobuf.UninterpretedOption"_cts; }
constexpr auto message_type_url(const FeatureSet&) { return "type.googleapis.com/google.protobuf.FeatureSet"_cts; }
constexpr auto message_type_url(const SourceCodeInfo::Location&) { return "type.googleapis.com/google.protobuf.SourceCodeInfo.Location"_cts; }
constexpr auto message_type_url(const SourceCodeInfo&) { return "type.googleapis.com/google.protobuf.SourceCodeInfo"_cts; }
constexpr auto message_type_url(const GeneratedCodeInfo::Annotation&) { return "type.googleapis.com/google.protobuf.GeneratedCodeInfo.Annotation"_cts; }
constexpr auto message_type_url(const GeneratedCodeInfo&) { return "type.googleapis.com/google.protobuf.GeneratedCodeInfo"_cts; }
constexpr auto message_type_url(const MethodOptions&) { return "type.googleapis.com/google.protobuf.MethodOptions"_cts; }
constexpr auto message_type_url(const ServiceOptions&) { return "type.googleapis.com/google.protobuf.ServiceOptions"_cts; }
constexpr auto message_type_url(const EnumValueOptions&) { return "type.googleapis.com/google.protobuf.EnumValueOptions"_cts; }
constexpr auto message_type_url(const EnumOptions&) { return "type.googleapis.com/google.protobuf.EnumOptions"_cts; }
constexpr auto message_type_url(const OneofOptions&) { return "type.googleapis.com/google.protobuf.OneofOptions"_cts; }
constexpr auto message_type_url(const FieldOptions::EditionDefault&) { return "type.googleapis.com/google.protobuf.FieldOptions.EditionDefault"_cts; }
constexpr auto message_type_url(const FieldOptions&) { return "type.googleapis.com/google.protobuf.FieldOptions"_cts; }
constexpr auto message_type_url(const MessageOptions&) { return "type.googleapis.com/google.protobuf.MessageOptions"_cts; }
constexpr auto message_type_url(const FileOptions&) { return "type.googleapis.com/google.protobuf.FileOptions"_cts; }
constexpr auto message_type_url(const MethodDescriptorProto&) { return "type.googleapis.com/google.protobuf.MethodDescriptorProto"_cts; }
constexpr auto message_type_url(const ServiceDescriptorProto&) { return "type.googleapis.com/google.protobuf.ServiceDescriptorProto"_cts; }
constexpr auto message_type_url(const EnumValueDescriptorProto&) { return "type.googleapis.com/google.protobuf.EnumValueDescriptorProto"_cts; }
constexpr auto message_type_url(const EnumDescriptorProto::EnumReservedRange&) { return "type.googleapis.com/google.protobuf.EnumDescriptorProto.EnumReservedRange"_cts; }
constexpr auto message_type_url(const EnumDescriptorProto&) { return "type.googleapis.com/google.protobuf.EnumDescriptorProto"_cts; }
constexpr auto message_type_url(const OneofDescriptorProto&) { return "type.googleapis.com/google.protobuf.OneofDescriptorProto"_cts; }
constexpr auto message_type_url(const FieldDescriptorProto&) { return "type.googleapis.com/google.protobuf.FieldDescriptorProto"_cts; }
constexpr auto message_type_url(const ExtensionRangeOptions::Declaration&) { return "type.googleapis.com/google.protobuf.ExtensionRangeOptions.Declaration"_cts; }
constexpr auto message_type_url(const ExtensionRangeOptions&) { return "type.googleapis.com/google.protobuf.ExtensionRangeOptions"_cts; }
constexpr auto message_type_url(const DescriptorProto::ExtensionRange&) { return "type.googleapis.com/google.protobuf.DescriptorProto.ExtensionRange"_cts; }
constexpr auto message_type_url(const DescriptorProto::ReservedRange&) { return "type.googleapis.com/google.protobuf.DescriptorProto.ReservedRange"_cts; }
constexpr auto message_type_url(const DescriptorProto&) { return "type.googleapis.com/google.protobuf.DescriptorProto"_cts; }
constexpr auto message_type_url(const FileDescriptorProto&) { return "type.googleapis.com/google.protobuf.FileDescriptorProto"_cts; }
constexpr auto message_type_url(const FileDescriptorSet&) { return "type.googleapis.com/google.protobuf.FileDescriptorSet"_cts; }
} // namespace google::protobuf
