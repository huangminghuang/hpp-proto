// MIT License
//
// Copyright (c) 2024 Huang-Ming Huang
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once
#include <cassert>
#include <google/protobuf/descriptor.pb.hpp>
#include <iostream>
namespace hpp::proto {

template <typename FlatMap>
void initial_reserve(FlatMap &m, std::size_t s) {
  assert(m.empty());
  typename FlatMap::key_container_type keys;
  typename FlatMap::mapped_container_type values;
  keys.reserve(s);
  values.reserve(s);
  m.replace(std::move(keys), std::move(values));
}

struct string_view_comp {
  using is_transparent = void;
  bool operator()(const std::string &lhs, const std::string &rhs) const { return lhs < rhs; }
  bool operator()(const std::string_view &lhs, const std::string &rhs) const { return lhs.compare(rhs) < 0; }
  bool operator()(const std::string &lhs, const std::string_view &rhs) const { return lhs.compare(rhs) < 0; }
};

// NOLINTBEGIN(bugprone-unchecked-optional-access)
template <typename AddOns>
struct descriptor_pool {
  static google::protobuf::FeatureSet merge_features(google::protobuf::FeatureSet features, const auto &options) {
    if (options.has_value()) {
      const auto &overriding_features = options->features;
      if (overriding_features.has_value()) {
        hpp::proto::merge(features, *options->features);
      }
    }
    return features;
  }

  enum field_option_mask_t : uint8_t {
    MASK_EXPLICIT_PRESENCE = 1,
    MASK_REPEATED = 2,
    MASK_PACKED = 4,
    MASK_UTF8_VALIDATION = 8,
    MASK_DELIMITED = 16,
    MASK_REQUIRED = 32,
    MASK_MAP_ENTRY = 64
  };

  struct message_descriptor_t;
  struct enum_descriptor_t;
  struct file_descriptor_t;
  struct field_descriptor_t : AddOns::template field_descriptor<field_descriptor_t> {
    using pool_type = descriptor_pool;
    using base_type = AddOns::template field_descriptor<field_descriptor_t>;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const google::protobuf::FieldDescriptorProto &proto;
    google::protobuf::FieldOptions options;
    message_descriptor_t *parent_message = nullptr;
    void *type_descriptor = nullptr;
    message_descriptor_t *extendee_descriptor = nullptr;
    uint8_t field_option_bitset = 0;
    field_descriptor_t(const google::protobuf::FieldDescriptorProto &proto, const std::string &parent_name,
                       message_descriptor_t *parent, const auto &inherited_options)
        : base_type(proto, parent_name), proto(proto),
          options(proto.options.value_or(google::protobuf::FieldOptions{})), parent_message(parent) {
      options.features = merge_features(inherited_options.features.value(), proto.options);
      if constexpr (requires { AddOns::adapt_option_extensions(options.extensions, inherited_options.extensions); }) {
        google::protobuf::FieldOptions::extension_t extensions;
        AddOns::adapt_option_extensions(extensions, inherited_options.extensions);
        options.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(), extensions.fields.end());
      }

      setup_presence();
      setup_repeated();
      setup_utf8_validation();
      setup_delimited();
      setup_required();

      if constexpr (requires { base_type::on_descriptor_created(proto, options); }) {
        base_type::on_descriptor_created(proto, options);
      }
    }

    [[nodiscard]] message_descriptor_t *message_field_type_descriptor() const {
      assert(proto.type == google::protobuf::FieldDescriptorProto::Type::TYPE_MESSAGE ||
             proto.type == google::protobuf::FieldDescriptorProto::Type::TYPE_GROUP);
      return static_cast<message_descriptor_t *>(type_descriptor);
    }

    [[nodiscard]] enum_descriptor_t *enum_field_type_descriptor() const {
      assert(proto.type == google::protobuf::FieldDescriptorProto::Type::TYPE_ENUM);
      return static_cast<enum_descriptor_t *>(type_descriptor);
    }

    void setup_presence() {
      using enum google::protobuf::FieldDescriptorProto::Type;
      using enum google::protobuf::FieldDescriptorProto::Label;
      using enum google::protobuf::FeatureSet::FieldPresence;
      if (proto.label == LABEL_OPTIONAL) {
        if (proto.type == TYPE_GROUP || proto.type == TYPE_MESSAGE || proto.proto3_optional ||
            proto.oneof_index.has_value() || options.features->field_presence == EXPLICIT ||
            options.features->field_presence == FIELD_PRESENCE_UNKNOWN) {
          field_option_bitset |= MASK_EXPLICIT_PRESENCE;
        }
      }
    }

    void setup_repeated() {
      using enum google::protobuf::FieldDescriptorProto::Type;
      using enum google::protobuf::FieldDescriptorProto::Label;
      if (proto.label != LABEL_REPEATED) {
        return;
      }
      field_option_bitset |= MASK_REPEATED;

      auto type = proto.type;
      if (type == TYPE_MESSAGE || type == TYPE_STRING || type == TYPE_BYTES || type == TYPE_GROUP) {
        return;
      }
      if (proto.options.has_value() && proto.options->packed.has_value() && proto.options->packed.value()) {
        field_option_bitset |= MASK_PACKED;
        return;
      }
      if (options.features->repeated_field_encoding == google::protobuf::FeatureSet::RepeatedFieldEncoding::PACKED) {
        field_option_bitset |= MASK_PACKED;
      }
    }

    void setup_utf8_validation() {
      if (proto.type == google::protobuf::FieldDescriptorProto::Type::TYPE_STRING &&
          options.features.value().utf8_validation == google::protobuf::FeatureSet::Utf8Validation::VERIFY) {
        field_option_bitset |= MASK_UTF8_VALIDATION;
      }
    }

    void setup_delimited() {
      if (proto.type == google::protobuf::FieldDescriptorProto::Type::TYPE_GROUP ||
          (proto.type == google::protobuf::FieldDescriptorProto::Type::TYPE_MESSAGE &&
           options.features.value().message_encoding == google::protobuf::FeatureSet::MessageEncoding::DELIMITED)) {
        field_option_bitset |= MASK_DELIMITED;
      }
    }

    void setup_required() {
      if (proto.label == google::protobuf::FieldDescriptorProto::Label::LABEL_REQUIRED ||
          options.features->field_presence == google::protobuf::FeatureSet::FieldPresence::LEGACY_REQUIRED) {
        field_option_bitset |= MASK_REQUIRED;
      }
    }

    [[nodiscard]] bool repeated_expanded() const {
      return (field_option_bitset & MASK_PACKED & MASK_REPEATED) == MASK_REPEATED;
    }
    [[nodiscard]] bool is_packed() const { return (field_option_bitset & MASK_PACKED) != 0; }
    [[nodiscard]] constexpr bool is_repeated() const { return (field_option_bitset & MASK_REPEATED) != 0; }
    [[nodiscard]] bool requires_utf8_validation() const { return (field_option_bitset & MASK_UTF8_VALIDATION) != 0; }
    [[nodiscard]] bool is_delimited() const { return (field_option_bitset & MASK_DELIMITED) != 0; }
    [[nodiscard]] bool is_map_entry() const { return (field_option_bitset & MASK_MAP_ENTRY) != 0; }
    [[nodiscard]] bool explicit_presence() const { return (field_option_bitset & MASK_EXPLICIT_PRESENCE) != 0; }
    [[nodiscard]] bool is_required() const { return (field_option_bitset & MASK_REQUIRED) != 0; }
  };

  struct oneof_descriptor_t : AddOns::template oneof_descriptor<oneof_descriptor_t, field_descriptor_t> {
    using pool_type = descriptor_pool;
    using base_type = AddOns::template oneof_descriptor<oneof_descriptor_t, field_descriptor_t>;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const google::protobuf::OneofDescriptorProto &proto;
    google::protobuf::OneofOptions options;
    explicit oneof_descriptor_t(const google::protobuf::OneofDescriptorProto &proto,
                                const google::protobuf::MessageOptions &inherited_options)
        : base_type(proto), proto(proto), options(proto.options.value_or(google::protobuf::OneofOptions{})) {
      options.features = merge_features(inherited_options.features.value(), proto.options);
      if constexpr (requires { AddOns::adapt_option_extensions(options.extensions, inherited_options.extensions); }) {
        google::protobuf::OneofOptions::extension_t extensions;
        AddOns::adapt_option_extensions(extensions, inherited_options.extensions);
        options.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(), extensions.fields.end());
      }
      if constexpr (requires { base_type::on_descriptor_created(proto, options); }) {
        base_type::on_descriptor_created(proto, options);
      }
    }
  };

  struct enum_descriptor_t : AddOns::template enum_descriptor<enum_descriptor_t> {
    using pool_type = descriptor_pool;
    using base_type = AddOns::template enum_descriptor<enum_descriptor_t>;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const google::protobuf::EnumDescriptorProto &proto;
    google::protobuf::EnumOptions options;
    file_descriptor_t *parent_file;
    explicit enum_descriptor_t(const google::protobuf::EnumDescriptorProto &proto, const auto &inherited_options,
                               file_descriptor_t *parent_file)
        : base_type(proto), proto(proto), options(proto.options.value_or(google::protobuf::EnumOptions{})),
          parent_file(parent_file) {
      options.features = merge_features(inherited_options.features.value(), proto.options);
      if constexpr (requires { AddOns::adapt_option_extensions(options.extensions, inherited_options.extensions); }) {
        google::protobuf::EnumOptions::extension_t extensions;
        AddOns::adapt_option_extensions(extensions, inherited_options.extensions);
        options.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(), extensions.fields.end());
      }
      if constexpr (requires { base_type::on_descriptor_created(proto, options); }) {
        base_type::on_descriptor_created(proto, options);
      }
    }

    [[nodiscard]] bool is_closed() const {
      return options.features.value().enum_type == google::protobuf::FeatureSet::EnumType::CLOSED;
    }
  };

  struct message_descriptor_t : AddOns::template message_descriptor<message_descriptor_t, enum_descriptor_t,
                                                                    oneof_descriptor_t, field_descriptor_t> {
    using pool_type = descriptor_pool;
    using base_type = AddOns::template message_descriptor<message_descriptor_t, enum_descriptor_t, oneof_descriptor_t,
                                                          field_descriptor_t>;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const google::protobuf::DescriptorProto &proto;
    google::protobuf::MessageOptions options;
    file_descriptor_t *parent_file;
    message_descriptor_t *parent_message;

    explicit message_descriptor_t(const google::protobuf::DescriptorProto &proto, const auto &inherited_options,
                                  file_descriptor_t *parent_file, message_descriptor_t *parent_message)
        : base_type(proto), proto(proto), options(proto.options.value_or(google::protobuf::MessageOptions{})),
          parent_file(parent_file), parent_message(parent_message) {
      setup_options(inherited_options);
    }

    void setup_options(const google::protobuf::MessageOptions &inherited_options) {
      options.features = merge_features(inherited_options.features.value(), proto.options);
      options.extensions.fields.insert(hpp::proto::sorted_unique, inherited_options.extensions.fields.begin(),
                                       inherited_options.extensions.fields.end());
    }

    void setup_options(const google::protobuf::FileOptions &inherited_options) {
      options.features = merge_features(inherited_options.features.value(), proto.options);
      if constexpr (requires { AddOns::adapt_option_extensions(options.extensions, inherited_options.extensions); }) {
        google::protobuf::MessageOptions::extension_t extensions;
        AddOns::adapt_option_extensions(extensions, inherited_options.extensions);
        options.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(), extensions.fields.end());
      }
      if constexpr (requires { base_type::on_descriptor_created(proto, options); }) {
        base_type::on_descriptor_created(proto, options);
      }
    }

    bool is_map_entry() const { return proto.options.has_value() && proto.options->map_entry; }
  };

  struct file_descriptor_t : AddOns::template file_descriptor<file_descriptor_t, message_descriptor_t,
                                                              enum_descriptor_t, field_descriptor_t> {
    using pool_type = descriptor_pool;
    using base_type = AddOns::template file_descriptor<file_descriptor_t, message_descriptor_t, enum_descriptor_t,
                                                       field_descriptor_t>;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const google::protobuf::FileDescriptorProto &proto;
    google::protobuf::FileOptions options;
    explicit file_descriptor_t(const google::protobuf::FileDescriptorProto &proto,
                               const google::protobuf::FeatureSet &default_features)
        : base_type(proto), proto(proto), options(proto.options.value_or(google::protobuf::FileOptions{})) {
      options.features = merge_features(default_features, proto.options);
      if constexpr (requires { AddOns::default_file_options_extensions(); }) {
        auto extensions = AddOns::default_file_options_extensions();
        options.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(), extensions.fields.end());
      }
      if constexpr (requires { base_type::on_descriptor_created(proto, options); }) {
        base_type::on_descriptor_created(proto, options);
      }
    }
  };

  struct descriptor_counter {
    std::size_t files = 0;
    std::size_t messages = 0;
    std::size_t fields = 0;
    std::size_t oneofs = 0;
    std::size_t enums = 0;

    explicit descriptor_counter(const std::vector<google::protobuf::FileDescriptorProto> &proto_files) {
      for (const auto &f : proto_files) {
        count_file(f);
      }
    }

    void count_file(const google::protobuf::FileDescriptorProto &file) {
      files++;
      for (const auto &m : file.message_type) {
        count_message(m);
      }
      enums += file.enum_type.size();
      fields += file.extension.size();
    }

    void count_message(const google::protobuf::DescriptorProto &message) {
      messages++;
      for (const auto &m : message.nested_type) {
        count_message(m);
      }
      enums += message.enum_type.size();
      fields += message.field.size() + message.extension.size();
      oneofs += message.oneof_decl.size();
    }
  };

  std::vector<file_descriptor_t> files;
  std::vector<message_descriptor_t> messages;
  std::vector<enum_descriptor_t> enums;
  std::vector<oneof_descriptor_t> oneofs;
  std::vector<field_descriptor_t> fields;

  flat_map<std::string, file_descriptor_t *, string_view_comp> file_map;
  flat_map<std::string, message_descriptor_t *, string_view_comp> message_map;
  flat_map<std::string, enum_descriptor_t *, string_view_comp> enum_map;
  google::protobuf::Edition current_edition = {};

  google::protobuf::FeatureSet select_features(const google::protobuf::FileDescriptorProto &file) {
    using namespace std::string_view_literals;
    static const google::protobuf::FeatureSetDefaults cpp_edition_defaults =
        hpp::proto::read_proto<google::protobuf::FeatureSetDefaults>(
            // from https://github.com/protocolbuffers/protobuf/blob/v28.2/src/google/protobuf/cpp_edition_defaults.h
            "\n\035\030\204\007\"\003\302>\000*\023\010\001\020\002\030\002 \003(\0010\002\302>\004\010\001\020\003\n\035\030\347\007\"\003\302>\000*\023\010\002\020\001\030\001 \002(\0010\001\302>\004\010\000\020\003\n\035\030\350\007\"\023\010\001\020\001\030\001 \002(\0010\001\302>\004\010\000\020\003*\003\302>\000\n\035\030\351\007\"\023\010\001\020\001\030\001 \002(\0010\001\302>\004\010\000\020\001*\003\302>\000 \346\007(\351\007"sv)
            .value();

    current_edition = google::protobuf::Edition::EDITION_LEGACY;
    if (file.syntax == "proto3") {
      current_edition = google::protobuf::Edition::EDITION_PROTO3;
    } else if (file.syntax == "editions") {
      current_edition = file.edition;
    }
    for (const auto &default_features : cpp_edition_defaults.defaults) {
      if (default_features.edition == current_edition) {
        if (current_edition <= google::protobuf::Edition::EDITION_PROTO3) {
          return default_features.fixed_features.value();
        }

        auto features = default_features.overridable_features.value_or(google::protobuf::FeatureSet{});
        return merge_features(features, file.options);
      }
    }
    throw std::runtime_error(std::string{"unsupported edition used by "} + file.name);
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
  explicit descriptor_pool(const std::vector<google::protobuf::FileDescriptorProto> &proto_files) {
    const descriptor_counter counter(proto_files);
    files.reserve(counter.files);
    messages.reserve(counter.messages);
    enums.reserve(counter.enums);
    oneofs.reserve(counter.oneofs);
    fields.reserve(counter.fields);
    initial_reserve(file_map, counter.files);
    initial_reserve(message_map, counter.messages);
    initial_reserve(enum_map, counter.enums);

    for (const auto &proto : proto_files) {
      if (!proto.name.empty() && file_map.count(proto.name) == 0) {
        build(files.emplace_back(proto, select_features(proto)));
      }
    }

    for (auto [name, msg] : message_map) {
      build_fields(*msg, name);
      build_extensions(*msg, name);
    }

    for (auto [name, f] : file_map) {
      build_extensions(*f, f->proto.package);
    }

    for (auto &f : fields) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      if (f.proto.type == TYPE_MESSAGE || f.proto.type == TYPE_GROUP) {
        auto desc = find_type(message_map, f.proto.type_name.substr(1));
        if (desc) {
          f.type_descriptor = desc;
          if (desc->is_map_entry()) {
            f.field_option_bitset |= MASK_MAP_ENTRY;
          }
        }
      } else if (f.proto.type == TYPE_ENUM) {
        f.type_descriptor = find_type(enum_map, f.proto.type_name.substr(1));
      }

      if (!f.proto.extendee.empty()) {
        f.extendee_descriptor = find_type(message_map, f.proto.extendee.substr(1));
      }
    }

    assert(messages.size() == counter.messages);
  }

  constexpr ~descriptor_pool() = default;
  descriptor_pool(const descriptor_pool &) = delete;
  descriptor_pool(descriptor_pool &&) = delete;
  descriptor_pool &operator=(const descriptor_pool &) = delete;
  descriptor_pool &operator=(descriptor_pool &&) = delete;

  const message_descriptor_t *message_by_name(std::string_view name) const {
    auto itr = message_map.find(name);
    return itr == message_map.end() ? nullptr : itr->second;
  }

  const message_descriptor_t *enum_by_name(std::string_view name) const {
    auto itr = enum_map.find(name);
    return itr == enum_map.end() ? nullptr : itr->second;
  }

  const file_descriptor_t *file_by_name(std::string_view name) const {
    auto itr = file_map.find(name);
    return itr == file_map.end() ? nullptr : itr->second;
  }

  void build(file_descriptor_t &descriptor) {
    file_map.try_emplace(descriptor.proto.name, &descriptor);
    const std::string package = descriptor.proto.package;
    for (auto &proto : descriptor.proto.message_type) {
      std::string const scope = !package.empty() ? package + "." + proto.name : proto.name;
      auto &message =
          messages.emplace_back(proto, descriptor.options, &descriptor, static_cast<message_descriptor_t *>(nullptr));
      build(message, scope);
      descriptor.add_message(message);
    }

    for (auto &proto : descriptor.proto.enum_type) {
      const std::string scope = !package.empty() ? package + "." + proto.name : proto.name;
      auto &e = enums.emplace_back(proto, descriptor.options, &descriptor);
      enum_map.try_emplace(scope, &e);
      descriptor.add_enum(e);
    }
  }

  void build(message_descriptor_t &descriptor, const std::string &scope) {
    message_map.try_emplace(scope, &descriptor);
    for (auto &proto : descriptor.proto.nested_type) {
      const std::string new_scope = scope.empty() ? proto.name : scope + "." + proto.name;
      auto &message = messages.emplace_back(proto, descriptor.options, descriptor.parent_file, &descriptor);
      build(message, new_scope);
      descriptor.add_message(message);
    }

    for (auto &proto : descriptor.proto.enum_type) {
      const std::string new_scope = scope.empty() ? proto.name : scope + "." + proto.name;
      auto &e = enums.emplace_back(proto, descriptor.options, descriptor.parent_file);
      enum_map.try_emplace(new_scope, &e);
      descriptor.add_enum(e);
    }

    for (auto &proto : descriptor.proto.oneof_decl) {
      descriptor.add_oneof(oneofs.emplace_back(proto, descriptor.options));
    }
  }

  template <typename FlatMap>
  typename FlatMap::mapped_type find_type(FlatMap &types, const std::string &qualified_name) {
    auto itr = types.find(qualified_name);
    assert(itr != types.end() && "unable to find type");
    return itr->second;
  }

  void build_fields(message_descriptor_t &descriptor, const std::string &qualified_name) {
    for (auto &proto : descriptor.proto.field) {
      descriptor.add_field(fields.emplace_back(proto, qualified_name, &descriptor, descriptor.options));
    }
  };

  void build_extensions(auto &parent, const std::string &scope) {
    for (auto &proto : parent.proto.extension) {
      message_descriptor_t *msg_desc = nullptr;
      if constexpr (std::same_as<decltype(&parent), message_descriptor_t *>) {
        msg_desc = &parent;
      }
      parent.add_extension(fields.emplace_back(proto, scope, msg_desc, parent.options));
    }
  }
};
// NOLINTEND(bugprone-unchecked-optional-access)
} // namespace hpp::proto
