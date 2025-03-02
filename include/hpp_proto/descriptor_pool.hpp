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
void reserve(FlatMap &m, std::size_t s) {
  typename FlatMap::key_container_type keys;
  typename FlatMap::mapped_container_type values;
  keys.reserve(s);
  values.reserve(s);
  m.replace(std::move(keys), std::move(values));
}

// NOLINTBEGIN(bugprone-unchecked-optional-access)
template <typename AddOns>
struct descriptor_pool {
  static google::protobuf::FeatureSet merge_features(google::protobuf::FeatureSet features, const auto &options) {
    if (options.has_value()) {
      const auto &overriding_features = options->features;
      if (overriding_features.has_value()) {
        auto overriding_bytes = hpp::proto::write_proto(*overriding_features).value();
        (void)hpp::proto::merge_proto(features, overriding_bytes).ok();
      }
    }
    return features;
  }
  struct field_descriptor_t : AddOns::template field_descriptor<field_descriptor_t> {
    using pool_type = descriptor_pool;
    using base_type = AddOns::template field_descriptor<field_descriptor_t>;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const google::protobuf::FieldDescriptorProto &proto;
    google::protobuf::FieldOptions options;
    field_descriptor_t(const google::protobuf::FieldDescriptorProto &proto, const std::string &parent_name,
                       const auto &inherited_options)
        : base_type(proto, parent_name), proto(proto),
          options(proto.options.value_or(google::protobuf::FieldOptions{})) {
      options.features = merge_features(inherited_options.features.value(), proto.options);
      if constexpr (requires { AddOns::adapt_option_extensions(options.extensions, inherited_options.extensions);}) {
        google::protobuf::FieldOptions::extension_t extensions;
        AddOns::adapt_option_extensions(extensions, inherited_options.extensions);
        options.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(), extensions.fields.end());
      }

      if constexpr (requires { base_type::on_descriptor_created(proto, options);}) {
        base_type::on_descriptor_created(proto, options);
      }
    }

    // return true if it is an optional explicit presence field
    [[nodiscard]] bool has_presence() const {
      using enum google::protobuf::FieldDescriptorProto::Type;
      using enum google::protobuf::FieldDescriptorProto::Label;
      using enum google::protobuf::FeatureSet::FieldPresence;
      if (proto.label == LABEL_OPTIONAL) {
        return (proto.type == TYPE_GROUP || proto.type == TYPE_MESSAGE || proto.proto3_optional ||
                proto.oneof_index.has_value() || options.features->field_presence == EXPLICIT ||
                options.features->field_presence == FIELD_PRESENCE_UNKNOWN);
      } else if (proto.label == LABEL_REPEATED || proto.label == LABEL_REQUIRED) {
        return false;
      }

      unreachable();
    }

    [[nodiscard]] bool is_required() const {
      return proto.label == google::protobuf::FieldDescriptorProto::Label::LABEL_REQUIRED ||
             options.features->field_presence == google::protobuf::FeatureSet::FieldPresence::LEGACY_REQUIRED;
    }

    [[nodiscard]] bool repeated_expanded() const {
      using enum google::protobuf::FieldDescriptorProto::Type;
      using enum google::protobuf::FieldDescriptorProto::Label;
      auto type = proto.type;
      if (proto.label == LABEL_REPEATED) {
        if (type != TYPE_MESSAGE && type != TYPE_STRING && type != TYPE_BYTES && type != TYPE_GROUP) {
          if (proto.options.has_value() && proto.options->packed.has_value()) {
            return !proto.options->packed.value();
          } else {
            return options.features->repeated_field_encoding ==
                   google::protobuf::FeatureSet::RepeatedFieldEncoding::EXPANDED;
          }
        } else {
          return true;
        }
      }
      return false;
    }

    [[nodiscard]] bool is_packed() const {
      using enum google::protobuf::FieldDescriptorProto::Type;
      using enum google::protobuf::FieldDescriptorProto::Label;
      auto type = proto.type;
      if (proto.label == LABEL_REPEATED) {
        if (type != TYPE_MESSAGE && type != TYPE_STRING && type != TYPE_BYTES && type != TYPE_GROUP) {
          if (proto.options.has_value() && proto.options->packed.has_value()) {
            return proto.options->packed.value();
          } else {
            return options.features->repeated_field_encoding ==
                   google::protobuf::FeatureSet::RepeatedFieldEncoding::PACKED;
          }
        }
      }
      return false;
    }

    [[nodiscard]] bool requires_utf8_validation() const {
      return proto.type == google::protobuf::FieldDescriptorProto::Type::TYPE_STRING &&
             options.features.value().utf8_validation == google::protobuf::FeatureSet::Utf8Validation::VERIFY;
    }

    [[nodiscard]] bool is_delimited() const {
      return proto.type == google::protobuf::FieldDescriptorProto::Type::TYPE_GROUP ||
             (proto.type == google::protobuf::FieldDescriptorProto::Type::TYPE_MESSAGE &&
              options.features.value().message_encoding == google::protobuf::FeatureSet::MessageEncoding::DELIMITED);
    }
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
      if constexpr (requires { AddOns::adapt_option_extensions(options.extensions, inherited_options.extensions);}) {
        google::protobuf::OneofOptions::extension_t extensions;
        AddOns::adapt_option_extensions(extensions, inherited_options.extensions);
        options.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(), extensions.fields.end());
      }
      if constexpr (requires { base_type::on_descriptor_created(proto, options);}) {
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
    explicit enum_descriptor_t(const google::protobuf::EnumDescriptorProto &proto, const auto &inherited_options)
        : base_type(proto), proto(proto), options(proto.options.value_or(google::protobuf::EnumOptions{})) {
      options.features = merge_features(inherited_options.features.value(), proto.options);
      if constexpr (requires { AddOns::adapt_option_extensions(options.extensions, inherited_options.extensions);}) {
        google::protobuf::EnumOptions::extension_t extensions;
        AddOns::adapt_option_extensions(extensions, inherited_options.extensions);
        options.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(), extensions.fields.end());
      }
      if constexpr (requires { base_type::on_descriptor_created(proto, options);}) {
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

    explicit message_descriptor_t(const google::protobuf::DescriptorProto &proto, const google::protobuf::MessageOptions &inherited_options)
        : base_type(proto), proto(proto), options(proto.options.value_or(google::protobuf::MessageOptions{})) {
      options.features = merge_features(inherited_options.features.value(), proto.options);
      options.extensions.fields.insert(hpp::proto::sorted_unique, inherited_options.extensions.fields.begin(), inherited_options.extensions.fields.end());
    }

    explicit message_descriptor_t(const google::protobuf::DescriptorProto &proto, const google::protobuf::FileOptions &inherited_options)
        : base_type(proto), proto(proto), options(proto.options.value_or(google::protobuf::MessageOptions{})) {
      options.features = merge_features(inherited_options.features.value(), proto.options);
      if constexpr (requires { AddOns::adapt_option_extensions(options.extensions, inherited_options.extensions);}) {
        google::protobuf::MessageOptions::extension_t extensions;
        AddOns::adapt_option_extensions(extensions, inherited_options.extensions);
        options.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(), extensions.fields.end());
      }
      if constexpr (requires { base_type::on_descriptor_created(proto, options);}) {
        base_type::on_descriptor_created(proto, options);
      }
    }
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
      if constexpr (requires { base_type::on_descriptor_created(proto, options);}) {
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

    explicit descriptor_counter(const std::vector<google::protobuf::FileDescriptorProto> &proto_files)
        : files(proto_files.size()) {
      for (const auto &f : proto_files) {
        count(f.message_type);
        enums += f.enum_type.size();
        fields += f.extension.size();
      }
    }

    void count(const std::vector<google::protobuf::DescriptorProto> &proto_messages) {
      messages += proto_messages.size();
      for (const auto &m : proto_messages) {
        count(m.nested_type);
        enums += m.enum_type.size();
        fields += m.field.size() + m.extension.size();
        oneofs += m.oneof_decl.size();
      }
    }
  };

  std::vector<file_descriptor_t> files;
  std::vector<message_descriptor_t> messages;
  std::vector<enum_descriptor_t> enums;
  std::vector<oneof_descriptor_t> oneofs;
  std::vector<field_descriptor_t> fields;

  flat_map<std::string, file_descriptor_t *> file_map;
  flat_map<std::string, message_descriptor_t *> message_map;
  flat_map<std::string, enum_descriptor_t *> enum_map;
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
    reserve(file_map, counter.files);
    reserve(message_map, counter.messages);
    reserve(enum_map, counter.enums);

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

    assert(messages.size() == counter.messages);
  }

  constexpr ~descriptor_pool() = default;
  descriptor_pool(const descriptor_pool &) = delete;
  descriptor_pool(descriptor_pool &&) = delete;
  descriptor_pool &operator=(const descriptor_pool &) = delete;
  descriptor_pool &operator=(descriptor_pool &&) = delete;

  void build(file_descriptor_t &descriptor) {
    file_map.try_emplace(descriptor.proto.name, &descriptor);
    const std::string package = descriptor.proto.package;
    for (auto &proto : descriptor.proto.message_type) {
      std::string const name = !package.empty() ? "." + package + "." + proto.name : "." + proto.name;
      auto &message = messages.emplace_back(proto, descriptor.options);
      build(message, name);
      descriptor.add_message(message);
    }

    for (auto &proto : descriptor.proto.enum_type) {
      const std::string name = !package.empty() ? "." + package + "." + proto.name : proto.name;
      auto &e = enums.emplace_back(proto, descriptor.options);
      enum_map.try_emplace(name, &e);
      descriptor.add_enum(e);
    }
  }

  void build(message_descriptor_t &descriptor, const std::string &scope) {
    message_map.try_emplace(scope, &descriptor);
    for (auto &proto : descriptor.proto.nested_type) {
      const std::string name = scope + "." + proto.name;
      auto &message = messages.emplace_back(proto, descriptor.options);
      build(message, name);
      descriptor.add_message(message);
    }

    for (auto &proto : descriptor.proto.enum_type) {
      const std::string name = scope + "." + proto.name;
      auto &e = enums.emplace_back(proto, descriptor.options);
      enum_map.try_emplace(name, &e);
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
      descriptor.add_field(fields.emplace_back(proto, qualified_name, descriptor.options));
    }
  };

  void build_extensions(auto &parent, const std::string &scope) {
    for (auto &proto : parent.proto.extension) {
      parent.add_extension(fields.emplace_back(proto, scope, parent.options));
    }
  }
};
// NOLINTEND(bugprone-unchecked-optional-access)
} // namespace hpp::proto
