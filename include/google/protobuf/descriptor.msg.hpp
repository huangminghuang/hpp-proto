#pragma once

#include <hpp_proto/msg_base.h>

namespace google::protobuf {

using hpp::proto::literals::operator ""_hppproto_s;
struct UninterpretedOption {
  struct NamePart {
    std::string name_part = {};
    bool is_extension = {};

    bool operator == (const NamePart&) const = default;
  };

  std::vector<NamePart> name;
  hpp::proto::optional<std::string> identifier_value;
  hpp::proto::optional<uint64_t> positive_int_value;
  hpp::proto::optional<int64_t> negative_int_value;
  hpp::proto::optional<double> double_value;
  hpp::proto::optional<std::vector<std::byte>> string_value;
  hpp::proto::optional<std::string> aggregate_value;

  bool operator == (const UninterpretedOption&) const = default;
};

struct SourceCodeInfo {
  struct Location {
    std::vector<int32_t> path;
    std::vector<int32_t> span;
    hpp::proto::optional<std::string> leading_comments;
    hpp::proto::optional<std::string> trailing_comments;
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
    hpp::proto::optional<std::string> source_file;
    hpp::proto::optional<int32_t> begin;
    hpp::proto::optional<int32_t> end;
    hpp::proto::optional<Semantic> semantic;

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

  hpp::proto::optional<bool,false> deprecated;
  hpp::proto::optional<IdempotencyLevel,::google::protobuf::MethodOptions::IdempotencyLevel::IDEMPOTENCY_UNKNOWN> idempotency_level;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = MethodOptions;
    std::map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  auto get_extension(auto meta) {
    return meta.read(extensions);
  }
  auto set_extension(auto meta, auto &&value) {
    return meta.write(extensions, value);
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const MethodOptions&) const = default;
};

struct ServiceOptions {
  hpp::proto::optional<bool,false> deprecated;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = ServiceOptions;
    std::map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  auto get_extension(auto meta) {
    return meta.read(extensions);
  }
  auto set_extension(auto meta, auto &&value) {
    return meta.write(extensions, value);
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const ServiceOptions&) const = default;
};

struct EnumValueOptions {
  hpp::proto::optional<bool,false> deprecated;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = EnumValueOptions;
    std::map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  auto get_extension(auto meta) {
    return meta.read(extensions);
  }
  auto set_extension(auto meta, auto &&value) {
    return meta.write(extensions, value);
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const EnumValueOptions&) const = default;
};

struct EnumOptions {
  hpp::proto::optional<bool> allow_alias;
  hpp::proto::optional<bool,false> deprecated;
  hpp::proto::optional<bool> deprecated_legacy_json_field_conflicts;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = EnumOptions;
    std::map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  auto get_extension(auto meta) {
    return meta.read(extensions);
  }
  auto set_extension(auto meta, auto &&value) {
    return meta.write(extensions, value);
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const EnumOptions&) const = default;
};

struct OneofOptions {
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = OneofOptions;
    std::map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  auto get_extension(auto meta) {
    return meta.read(extensions);
  }
  auto set_extension(auto meta, auto &&value) {
    return meta.write(extensions, value);
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

  hpp::proto::optional<CType,::google::protobuf::FieldOptions::CType::STRING> ctype;
  hpp::proto::optional<bool> packed;
  hpp::proto::optional<JSType,::google::protobuf::FieldOptions::JSType::JS_NORMAL> jstype;
  hpp::proto::optional<bool,false> lazy;
  hpp::proto::optional<bool,false> unverified_lazy;
  hpp::proto::optional<bool,false> deprecated;
  hpp::proto::optional<bool,false> weak;
  hpp::proto::optional<bool,false> debug_redact;
  hpp::proto::optional<OptionRetention> retention;
  hpp::proto::optional<OptionTargetType> target;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = FieldOptions;
    std::map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  auto get_extension(auto meta) {
    return meta.read(extensions);
  }
  auto set_extension(auto meta, auto &&value) {
    return meta.write(extensions, value);
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const FieldOptions&) const = default;
};

struct MessageOptions {
  hpp::proto::optional<bool,false> message_set_wire_format;
  hpp::proto::optional<bool,false> no_standard_descriptor_accessor;
  hpp::proto::optional<bool,false> deprecated;
  hpp::proto::optional<bool> map_entry;
  hpp::proto::optional<bool> deprecated_legacy_json_field_conflicts;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = MessageOptions;
    std::map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  auto get_extension(auto meta) {
    return meta.read(extensions);
  }
  auto set_extension(auto meta, auto &&value) {
    return meta.write(extensions, value);
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

  hpp::proto::optional<std::string> java_package;
  hpp::proto::optional<std::string> java_outer_classname;
  hpp::proto::optional<bool,false> java_multiple_files;
  hpp::proto::optional<bool> java_generate_equals_and_hash;
  hpp::proto::optional<bool,false> java_string_check_utf8;
  hpp::proto::optional<OptimizeMode,::google::protobuf::FileOptions::OptimizeMode::SPEED> optimize_for;
  hpp::proto::optional<std::string> go_package;
  hpp::proto::optional<bool,false> cc_generic_services;
  hpp::proto::optional<bool,false> java_generic_services;
  hpp::proto::optional<bool,false> py_generic_services;
  hpp::proto::optional<bool,false> php_generic_services;
  hpp::proto::optional<bool,false> deprecated;
  hpp::proto::optional<bool,true> cc_enable_arenas;
  hpp::proto::optional<std::string> objc_class_prefix;
  hpp::proto::optional<std::string> csharp_namespace;
  hpp::proto::optional<std::string> swift_prefix;
  hpp::proto::optional<std::string> php_class_prefix;
  hpp::proto::optional<std::string> php_namespace;
  hpp::proto::optional<std::string> php_metadata_namespace;
  hpp::proto::optional<std::string> ruby_package;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = FileOptions;
    std::map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  auto get_extension(auto meta) {
    return meta.read(extensions);
  }
  auto set_extension(auto meta, auto &&value) {
    return meta.write(extensions, value);
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const FileOptions&) const = default;
};

struct MethodDescriptorProto {
  hpp::proto::optional<std::string> name;
  hpp::proto::optional<std::string> input_type;
  hpp::proto::optional<std::string> output_type;
  std::optional<MethodOptions> options;
  hpp::proto::optional<bool,false> client_streaming;
  hpp::proto::optional<bool,false> server_streaming;

  bool operator == (const MethodDescriptorProto&) const = default;
};

struct ServiceDescriptorProto {
  hpp::proto::optional<std::string> name;
  std::vector<MethodDescriptorProto> method;
  std::optional<ServiceOptions> options;

  bool operator == (const ServiceDescriptorProto&) const = default;
};

struct EnumValueDescriptorProto {
  hpp::proto::optional<std::string> name;
  hpp::proto::optional<int32_t> number;
  std::optional<EnumValueOptions> options;

  bool operator == (const EnumValueDescriptorProto&) const = default;
};

struct EnumDescriptorProto {
  struct EnumReservedRange {
    hpp::proto::optional<int32_t> start;
    hpp::proto::optional<int32_t> end;

    bool operator == (const EnumReservedRange&) const = default;
  };

  hpp::proto::optional<std::string> name;
  std::vector<EnumValueDescriptorProto> value;
  std::optional<EnumOptions> options;
  std::vector<EnumReservedRange> reserved_range;
  std::vector<std::string> reserved_name;

  bool operator == (const EnumDescriptorProto&) const = default;
};

struct OneofDescriptorProto {
  hpp::proto::optional<std::string> name;
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

  hpp::proto::optional<std::string> name;
  hpp::proto::optional<int32_t> number;
  hpp::proto::optional<Label> label;
  hpp::proto::optional<Type> type;
  hpp::proto::optional<std::string> type_name;
  hpp::proto::optional<std::string> extendee;
  hpp::proto::optional<std::string> default_value;
  hpp::proto::optional<int32_t> oneof_index;
  hpp::proto::optional<std::string> json_name;
  std::optional<FieldOptions> options;
  hpp::proto::optional<bool> proto3_optional;

  bool operator == (const FieldDescriptorProto&) const = default;
};

struct ExtensionRangeOptions {
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = ExtensionRangeOptions;
    std::map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
  } extensions;

  auto get_extension(auto meta) {
    return meta.read(extensions);
  }
  auto set_extension(auto meta, auto &&value) {
    return meta.write(extensions, value);
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const ExtensionRangeOptions&) const = default;
};

struct DescriptorProto {
  struct ExtensionRange {
    hpp::proto::optional<int32_t> start;
    hpp::proto::optional<int32_t> end;
    std::optional<ExtensionRangeOptions> options;

    bool operator == (const ExtensionRange&) const = default;
  };

  struct ReservedRange {
    hpp::proto::optional<int32_t> start;
    hpp::proto::optional<int32_t> end;

    bool operator == (const ReservedRange&) const = default;
  };

  hpp::proto::optional<std::string> name;
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
  hpp::proto::optional<std::string> name;
  hpp::proto::optional<std::string> package;
  std::vector<std::string> dependency;
  std::vector<int32_t> public_dependency;
  std::vector<int32_t> weak_dependency;
  std::vector<DescriptorProto> message_type;
  std::vector<EnumDescriptorProto> enum_type;
  std::vector<ServiceDescriptorProto> service;
  std::vector<FieldDescriptorProto> extension;
  std::optional<FileOptions> options;
  std::optional<SourceCodeInfo> source_code_info;
  hpp::proto::optional<std::string> syntax;
  hpp::proto::optional<std::string> edition;

  bool operator == (const FileDescriptorProto&) const = default;
};

struct FileDescriptorSet {
  std::vector<FileDescriptorProto> file;

  bool operator == (const FileDescriptorSet&) const = default;
};

} // namespace google::protobuf
