#pragma once

#include <hpp_proto/msg_base.h>

namespace google::protobuf {

using hpp::proto::literals::operator ""_hppproto_s;
struct UninterpretedOption {
  struct NamePart {
    std::string name_part = {};
    bool is_extension = {};

    bool operator == (const NamePart&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

    auto operator <=> (const NamePart&) const = default;
#endif
  };

  std::vector<NamePart> name;
  std::optional<std::string> identifier_value;
  std::optional<uint64_t> positive_int_value;
  std::optional<int64_t> negative_int_value;
  std::optional<double> double_value;
  std::optional<hpp::proto::bytes> string_value;
  std::optional<std::string> aggregate_value;

  bool operator == (const UninterpretedOption&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const UninterpretedOption&) const = default;
#endif
};

struct SourceCodeInfo {
  struct Location {
    std::vector<int32_t> path;
    std::vector<int32_t> span;
    std::optional<std::string> leading_comments;
    std::optional<std::string> trailing_comments;
    std::vector<std::string> leading_detached_comments;

    bool operator == (const Location&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

    auto operator <=> (const Location&) const = default;
#endif
  };

  std::vector<Location> location;

  bool operator == (const SourceCodeInfo&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const SourceCodeInfo&) const = default;
#endif
};

struct GeneratedCodeInfo {
  struct Annotation {
    enum class Semantic {
      NONE = 0,
      SET = 1,
      ALIAS = 2 
    };

    std::vector<int32_t> path;
    std::optional<std::string> source_file;
    std::optional<int32_t> begin;
    std::optional<int32_t> end;
    std::optional<Semantic> semantic;

    bool operator == (const Annotation&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

    auto operator <=> (const Annotation&) const = default;
#endif
  };

  std::vector<Annotation> annotation;

  bool operator == (const GeneratedCodeInfo&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const GeneratedCodeInfo&) const = default;
#endif
};

struct MethodOptions {
  enum class IdempotencyLevel {
    IDEMPOTENCY_UNKNOWN = 0,
    NO_SIDE_EFFECTS = 1,
    IDEMPOTENT = 2 
  };

  hpp::proto::optional<bool,false> deprecated;
  hpp::proto::optional<IdempotencyLevel,IdempotencyLevel::IDEMPOTENCY_UNKNOWN> idempotency_level;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = MethodOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR
  auto operator <=> (const extension_t&) const = default;
#endif
  } extensions;

  auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const MethodOptions&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const MethodOptions&) const = default;
#endif
};

struct ServiceOptions {
  hpp::proto::optional<bool,false> deprecated;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = ServiceOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR
  auto operator <=> (const extension_t&) const = default;
#endif
  } extensions;

  auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const ServiceOptions&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const ServiceOptions&) const = default;
#endif
};

struct EnumValueOptions {
  hpp::proto::optional<bool,false> deprecated;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = EnumValueOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR
  auto operator <=> (const extension_t&) const = default;
#endif
  } extensions;

  auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const EnumValueOptions&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const EnumValueOptions&) const = default;
#endif
};

struct EnumOptions {
  std::optional<bool> allow_alias;
  hpp::proto::optional<bool,false> deprecated;
  std::optional<bool> deprecated_legacy_json_field_conflicts;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = EnumOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR
  auto operator <=> (const extension_t&) const = default;
#endif
  } extensions;

  auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const EnumOptions&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const EnumOptions&) const = default;
#endif
};

struct OneofOptions {
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = OneofOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR
  auto operator <=> (const extension_t&) const = default;
#endif
  } extensions;

  auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const OneofOptions&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const OneofOptions&) const = default;
#endif
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

  hpp::proto::optional<CType,CType::STRING> ctype;
  std::optional<bool> packed;
  hpp::proto::optional<JSType,JSType::JS_NORMAL> jstype;
  hpp::proto::optional<bool,false> lazy;
  hpp::proto::optional<bool,false> unverified_lazy;
  hpp::proto::optional<bool,false> deprecated;
  hpp::proto::optional<bool,false> weak;
  hpp::proto::optional<bool,false> debug_redact;
  std::optional<OptionRetention> retention;
  std::optional<OptionTargetType> target;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = FieldOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR
  auto operator <=> (const extension_t&) const = default;
#endif
  } extensions;

  auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const FieldOptions&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const FieldOptions&) const = default;
#endif
};

struct MessageOptions {
  hpp::proto::optional<bool,false> message_set_wire_format;
  hpp::proto::optional<bool,false> no_standard_descriptor_accessor;
  hpp::proto::optional<bool,false> deprecated;
  std::optional<bool> map_entry;
  std::optional<bool> deprecated_legacy_json_field_conflicts;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = MessageOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR
  auto operator <=> (const extension_t&) const = default;
#endif
  } extensions;

  auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const MessageOptions&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const MessageOptions&) const = default;
#endif
};

struct FileOptions {
  enum class OptimizeMode {
    SPEED = 1,
    CODE_SIZE = 2,
    LITE_RUNTIME = 3 
  };

  std::optional<std::string> java_package;
  std::optional<std::string> java_outer_classname;
  hpp::proto::optional<bool,false> java_multiple_files;
  std::optional<bool> java_generate_equals_and_hash;
  hpp::proto::optional<bool,false> java_string_check_utf8;
  hpp::proto::optional<OptimizeMode,OptimizeMode::SPEED> optimize_for;
  std::optional<std::string> go_package;
  hpp::proto::optional<bool,false> cc_generic_services;
  hpp::proto::optional<bool,false> java_generic_services;
  hpp::proto::optional<bool,false> py_generic_services;
  hpp::proto::optional<bool,false> php_generic_services;
  hpp::proto::optional<bool,false> deprecated;
  hpp::proto::optional<bool,true> cc_enable_arenas;
  std::optional<std::string> objc_class_prefix;
  std::optional<std::string> csharp_namespace;
  std::optional<std::string> swift_prefix;
  std::optional<std::string> php_class_prefix;
  std::optional<std::string> php_namespace;
  std::optional<std::string> php_metadata_namespace;
  std::optional<std::string> ruby_package;
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = FileOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR
  auto operator <=> (const extension_t&) const = default;
#endif
  } extensions;

  auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const FileOptions&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const FileOptions&) const = default;
#endif
};

struct MethodDescriptorProto {
  std::optional<std::string> name;
  std::optional<std::string> input_type;
  std::optional<std::string> output_type;
  std::optional<MethodOptions> options;
  hpp::proto::optional<bool,false> client_streaming;
  hpp::proto::optional<bool,false> server_streaming;

  bool operator == (const MethodDescriptorProto&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const MethodDescriptorProto&) const = default;
#endif
};

struct ServiceDescriptorProto {
  std::optional<std::string> name;
  std::vector<MethodDescriptorProto> method;
  std::optional<ServiceOptions> options;

  bool operator == (const ServiceDescriptorProto&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const ServiceDescriptorProto&) const = default;
#endif
};

struct EnumValueDescriptorProto {
  std::optional<std::string> name;
  std::optional<int32_t> number;
  std::optional<EnumValueOptions> options;

  bool operator == (const EnumValueDescriptorProto&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const EnumValueDescriptorProto&) const = default;
#endif
};

struct EnumDescriptorProto {
  struct EnumReservedRange {
    std::optional<int32_t> start;
    std::optional<int32_t> end;

    bool operator == (const EnumReservedRange&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

    auto operator <=> (const EnumReservedRange&) const = default;
#endif
  };

  std::optional<std::string> name;
  std::vector<EnumValueDescriptorProto> value;
  std::optional<EnumOptions> options;
  std::vector<EnumReservedRange> reserved_range;
  std::vector<std::string> reserved_name;

  bool operator == (const EnumDescriptorProto&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const EnumDescriptorProto&) const = default;
#endif
};

struct OneofDescriptorProto {
  std::optional<std::string> name;
  std::optional<OneofOptions> options;

  bool operator == (const OneofDescriptorProto&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const OneofDescriptorProto&) const = default;
#endif
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

  std::optional<std::string> name;
  std::optional<int32_t> number;
  std::optional<Label> label;
  std::optional<Type> type;
  std::optional<std::string> type_name;
  std::optional<std::string> extendee;
  std::optional<std::string> default_value;
  std::optional<int32_t> oneof_index;
  std::optional<std::string> json_name;
  std::optional<FieldOptions> options;
  std::optional<bool> proto3_optional;

  bool operator == (const FieldDescriptorProto&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const FieldDescriptorProto&) const = default;
#endif
};

struct ExtensionRangeOptions {
  std::vector<UninterpretedOption> uninterpreted_option;

  struct extension_t {
    using pb_extension = ExtensionRangeOptions;
    hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;
    bool operator==(const extension_t &other) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR
  auto operator <=> (const extension_t&) const = default;
#endif
  } extensions;

  auto get_extension(auto meta) const {
    return meta.read(extensions);
  }
  template<typename Meta>  auto set_extension(Meta meta, typename Meta::set_value_type &&value) {
    return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));
  }
  bool has_extension(auto meta) const {
    return meta.element_of(extensions);
  }

  bool operator == (const ExtensionRangeOptions&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const ExtensionRangeOptions&) const = default;
#endif
};

struct DescriptorProto {
  struct ExtensionRange {
    std::optional<int32_t> start;
    std::optional<int32_t> end;
    std::optional<ExtensionRangeOptions> options;

    bool operator == (const ExtensionRange&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

    auto operator <=> (const ExtensionRange&) const = default;
#endif
  };

  struct ReservedRange {
    std::optional<int32_t> start;
    std::optional<int32_t> end;

    bool operator == (const ReservedRange&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

    auto operator <=> (const ReservedRange&) const = default;
#endif
  };

  std::optional<std::string> name;
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
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const DescriptorProto&) const = default;
#endif
};

struct FileDescriptorProto {
  std::optional<std::string> name;
  std::optional<std::string> package;
  std::vector<std::string> dependency;
  std::vector<int32_t> public_dependency;
  std::vector<int32_t> weak_dependency;
  std::vector<DescriptorProto> message_type;
  std::vector<EnumDescriptorProto> enum_type;
  std::vector<ServiceDescriptorProto> service;
  std::vector<FieldDescriptorProto> extension;
  std::optional<FileOptions> options;
  std::optional<SourceCodeInfo> source_code_info;
  std::optional<std::string> syntax;
  std::optional<std::string> edition;

  bool operator == (const FileDescriptorProto&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const FileDescriptorProto&) const = default;
#endif
};

struct FileDescriptorSet {
  std::vector<FileDescriptorProto> file;

  bool operator == (const FileDescriptorSet&) const = default;
#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR

  auto operator <=> (const FileDescriptorSet&) const = default;
#endif
};

} // namespace google::protobuf
