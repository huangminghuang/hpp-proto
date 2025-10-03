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
#include <expected>
#include <google/protobuf/descriptor.pb.hpp>
#include <iostream>
#include <unordered_map>
namespace hpp::proto {

struct deref_pointer {
  template <typename T>
  T &operator()(T *pointer) {
    return *pointer;
  }
};

template <typename FlatMap>
void initial_reserve(FlatMap &m, std::size_t s) {
  assert(m.empty());
  typename FlatMap::key_container_type keys;
  typename FlatMap::mapped_container_type values;
  keys.reserve(s);
  values.reserve(s);
  m.replace(std::move(keys), std::move(values));
}

template <typename AddOns>
class descriptor_pool {
  enum field_option_mask_t : uint8_t {
    MASK_EXPLICIT_PRESENCE = 1,
    MASK_REPEATED = 2,
    MASK_PACKED = 4,
    MASK_UTF8_VALIDATION = 8,
    MASK_DELIMITED = 16,
    MASK_REQUIRED = 32,
    MASK_MAP_ENTRY = 64
  };

public:
  struct string_view_comp {
    using is_transparent = void;
    bool operator()(const std::string &lhs, const std::string &rhs) const { return lhs < rhs; }
    bool operator()(const std::string_view &lhs, const std::string &rhs) const { return lhs.compare(rhs) < 0; }
    bool operator()(const std::string &lhs, const std::string_view &rhs) const { return lhs.compare(rhs) < 0; }
  };

  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  class message_descriptor_t;
  class enum_descriptor_t;
  class file_descriptor_t;
  class field_descriptor_t : public AddOns::template field_descriptor<field_descriptor_t> {
  public:
    using pool_type = descriptor_pool;
    using base_type = AddOns::template field_descriptor<field_descriptor_t>;
    field_descriptor_t(const google::protobuf::FieldDescriptorProto &proto, const std::string &parent_name,
                       message_descriptor_t *parent, const auto &inherited_options)
        : base_type(proto, parent_name), proto_(proto),
          options_(proto.options.value_or(google::protobuf::FieldOptions{})), parent_message_(parent) {
      options_.features = merge_features(inherited_options.features.value(), proto.options);
      if constexpr (requires { AddOns::adapt_option_extensions(options_.extensions, inherited_options.extensions); }) {
        google::protobuf::FieldOptions::extension_t extensions;
        AddOns::adapt_option_extensions(extensions, inherited_options.extensions);
        options_.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(),
                                          extensions.fields.end());
      }

      setup_presence();
      setup_repeated();
      setup_utf8_validation();
      setup_delimited();
      setup_required();

      if constexpr (requires { base_type::on_options_resolved(proto_, options_); }) {
        base_type::on_options_resolved(proto_, options_);
      }
    }

    field_descriptor_t(const field_descriptor_t &) = delete;
    field_descriptor_t(field_descriptor_t &&) = default;
    ~field_descriptor_t() = default;
    field_descriptor_t &operator=(const field_descriptor_t &) = delete;
    field_descriptor_t &operator=(field_descriptor_t &&) = default;

    [[nodiscard]] const google::protobuf::FieldDescriptorProto &proto() const { return proto_; }
    [[nodiscard]] const google::protobuf::FieldOptions &options() const { return options_; }
    [[nodiscard]] message_descriptor_t *parent_message() const { return parent_message_; }
    [[nodiscard]] bool is_message_or_enum() const { return type_descriptor_ != nullptr; }
    [[nodiscard]] message_descriptor_t *extendee_descriptor() const { return extendee_descriptor_; }

    [[nodiscard]] message_descriptor_t *message_field_type_descriptor() const {
      assert(proto_.type == google::protobuf::FieldDescriptorProto::Type::TYPE_MESSAGE ||
             proto_.type == google::protobuf::FieldDescriptorProto::Type::TYPE_GROUP);
      return static_cast<message_descriptor_t *>(type_descriptor_);
    }

    [[nodiscard]] enum_descriptor_t *enum_field_type_descriptor() const {
      assert(proto_.type == google::protobuf::FieldDescriptorProto::Type::TYPE_ENUM);
      return static_cast<enum_descriptor_t *>(type_descriptor_);
    }

    [[nodiscard]] bool repeated_expanded() const {
      return (field_option_bitset_ & MASK_PACKED & MASK_REPEATED) == MASK_REPEATED;
    }
    [[nodiscard]] bool is_packed() const { return (field_option_bitset_ & MASK_PACKED) != 0; }
    [[nodiscard]] constexpr bool is_repeated() const { return (field_option_bitset_ & MASK_REPEATED) != 0; }
    [[nodiscard]] bool requires_utf8_validation() const { return (field_option_bitset_ & MASK_UTF8_VALIDATION) != 0; }
    [[nodiscard]] bool is_delimited() const { return (field_option_bitset_ & MASK_DELIMITED) != 0; }
    [[nodiscard]] bool is_map_entry() const { return (field_option_bitset_ & MASK_MAP_ENTRY) != 0; }
    [[nodiscard]] bool explicit_presence() const { return (field_option_bitset_ & MASK_EXPLICIT_PRESENCE) != 0; }
    [[nodiscard]] bool is_required() const { return (field_option_bitset_ & MASK_REQUIRED) != 0; }

  private:
    friend class descriptor_pool;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const google::protobuf::FieldDescriptorProto &proto_;
    google::protobuf::FieldOptions options_;
    message_descriptor_t *parent_message_ = nullptr;
    void *type_descriptor_ = nullptr;
    message_descriptor_t *extendee_descriptor_ = nullptr;
    uint8_t field_option_bitset_ = 0;

    void setup_presence() {
      using enum google::protobuf::FieldDescriptorProto::Type;
      using enum google::protobuf::FieldDescriptorProto::Label;
      using enum google::protobuf::FeatureSet::FieldPresence;
      if (proto_.label == LABEL_OPTIONAL) {
        if (proto_.type == TYPE_GROUP || proto_.type == TYPE_MESSAGE || proto_.proto3_optional ||
            proto_.oneof_index.has_value() || options_.features->field_presence == EXPLICIT ||
            options_.features->field_presence == FIELD_PRESENCE_UNKNOWN) {
          field_option_bitset_ |= MASK_EXPLICIT_PRESENCE;
        }
      }
    }

    void setup_repeated() {
      using enum google::protobuf::FieldDescriptorProto::Type;
      using enum google::protobuf::FieldDescriptorProto::Label;
      if (proto_.label != LABEL_REPEATED) {
        return;
      }
      field_option_bitset_ |= MASK_REPEATED;

      auto type = proto_.type;
      if (type == TYPE_MESSAGE || type == TYPE_STRING || type == TYPE_BYTES || type == TYPE_GROUP) {
        return;
      }
      if (proto_.options.has_value() && proto_.options->packed.has_value() && proto_.options->packed.value()) {
        field_option_bitset_ |= MASK_PACKED;
        return;
      }
      if (options_.features->repeated_field_encoding == google::protobuf::FeatureSet::RepeatedFieldEncoding::PACKED) {
        field_option_bitset_ |= MASK_PACKED;
      }
    }

    void setup_utf8_validation() {
      if (proto_.type == google::protobuf::FieldDescriptorProto::Type::TYPE_STRING &&
          options_.features.value().utf8_validation == google::protobuf::FeatureSet::Utf8Validation::VERIFY) {
        field_option_bitset_ |= MASK_UTF8_VALIDATION;
      }
    }

    void setup_delimited() {
      if (proto_.type == google::protobuf::FieldDescriptorProto::Type::TYPE_GROUP ||
          (proto_.type == google::protobuf::FieldDescriptorProto::Type::TYPE_MESSAGE &&
           options_.features.value().message_encoding == google::protobuf::FeatureSet::MessageEncoding::DELIMITED)) {
        field_option_bitset_ |= MASK_DELIMITED;
      }
    }

    void setup_required() {
      if (proto_.label == google::protobuf::FieldDescriptorProto::Label::LABEL_REQUIRED ||
          options_.features->field_presence == google::protobuf::FeatureSet::FieldPresence::LEGACY_REQUIRED) {
        field_option_bitset_ |= MASK_REQUIRED;
      }
    }
  };

  class oneof_descriptor_t : public AddOns::template oneof_descriptor<oneof_descriptor_t, field_descriptor_t> {
  public:
    using pool_type = descriptor_pool;
    using base_type = AddOns::template oneof_descriptor<oneof_descriptor_t, field_descriptor_t>;
    explicit oneof_descriptor_t(const google::protobuf::OneofDescriptorProto &proto,
                                const google::protobuf::MessageOptions &inherited_options)
        : base_type(proto), proto_(proto), options_(proto.options.value_or(google::protobuf::OneofOptions{})) {
      options_.features = merge_features(inherited_options.features.value(), proto.options);
      if constexpr (requires { AddOns::adapt_option_extensions(options_.extensions, inherited_options.extensions); }) {
        google::protobuf::OneofOptions::extension_t extensions;
        AddOns::adapt_option_extensions(extensions, inherited_options.extensions);
        options_.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(),
                                          extensions.fields.end());
      }
      if constexpr (requires { base_type::on_options_resolved(proto_, options_); }) {
        base_type::on_options_resolved(proto_, options_);
      }
    }

    oneof_descriptor_t(const oneof_descriptor_t &) = delete;
    oneof_descriptor_t(oneof_descriptor_t &&) = default;
    oneof_descriptor_t &operator=(const oneof_descriptor_t &) = delete;
    oneof_descriptor_t &operator=(oneof_descriptor_t &&) = default;

    [[nodiscard]] const google::protobuf::OneofDescriptorProto &proto() const { return proto_; }
    [[nodiscard]] const google::protobuf::OneofOptions &options() const { return options_; }

    /**
     * @brief Returns a view that transforms the elements of fields_ by dereferencing pointers.
     *
     * This function provides a lazy view over the fields_ container, applying the deref_pointer
     * functor to each element. The resulting view allows iteration over the dereferenced objects
     * without copying or modifying the underlying container.
     *
     * @return A std::views::transform view of fields_ with elements dereferenced.
     */
    [[nodiscard]] auto fields() const { return std::views::transform(fields_, deref_pointer{}); }

  private:
    friend class descriptor_pool;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const google::protobuf::OneofDescriptorProto &proto_;
    google::protobuf::OneofOptions options_;
    std::vector<field_descriptor_t *> fields_;
  };

  class enum_descriptor_t : public AddOns::template enum_descriptor<enum_descriptor_t> {
  public:
    using pool_type = descriptor_pool;
    using base_type = AddOns::template enum_descriptor<enum_descriptor_t>;
    explicit enum_descriptor_t(const google::protobuf::EnumDescriptorProto &proto, const auto &inherited_options,
                               file_descriptor_t *parent_file, message_descriptor_t *parent_message)
        : base_type(proto), proto_(proto), options_(proto.options.value_or(google::protobuf::EnumOptions{})),
          parent_file_(parent_file), parent_message_(parent_message) {
      options_.features = merge_features(inherited_options.features.value(), proto.options);
      if constexpr (requires { AddOns::adapt_option_extensions(options_.extensions, inherited_options.extensions); }) {
        google::protobuf::EnumOptions::extension_t extensions;
        AddOns::adapt_option_extensions(extensions, inherited_options.extensions);
        options_.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(),
                                          extensions.fields.end());
      }
      if constexpr (requires { base_type::on_options_resolved(proto_, options_); }) {
        base_type::on_options_resolved(proto_, options_);
      }
    }

    enum_descriptor_t(const enum_descriptor_t &) = delete;
    enum_descriptor_t(enum_descriptor_t &&) = default;
    enum_descriptor_t &operator=(const enum_descriptor_t &) = delete;
    enum_descriptor_t &operator=(enum_descriptor_t &&) = default;

    [[nodiscard]] const google::protobuf::EnumDescriptorProto &proto() const { return proto_; }
    [[nodiscard]] const google::protobuf::EnumOptions &options() const { return options_; }
    [[nodiscard]] file_descriptor_t *parent_file() const { return parent_file_; }
    [[nodiscard]] message_descriptor_t *parent_message() const { return parent_message_; }

    [[nodiscard]] bool is_closed() const {
      return options_.features.value().enum_type == google::protobuf::FeatureSet::EnumType::CLOSED;
    }

    [[nodiscard]] bool valid_enum_value(uint32_t v) const {
      return !is_closed() ||
             std::ranges::contains(proto_.value, static_cast<int32_t>(v), [](const auto &item) { return item.number; });
    }

  private:
    friend class descriptor_pool;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const google::protobuf::EnumDescriptorProto &proto_;
    google::protobuf::EnumOptions options_;
    file_descriptor_t *parent_file_;
    message_descriptor_t *parent_message_;
  };

  class message_descriptor_t : public AddOns::template message_descriptor<message_descriptor_t, enum_descriptor_t,
                                                                          oneof_descriptor_t, field_descriptor_t> {
  public:
    using pool_type = descriptor_pool;
    using base_type = AddOns::template message_descriptor<message_descriptor_t, enum_descriptor_t, oneof_descriptor_t,
                                                          field_descriptor_t>;

    explicit message_descriptor_t(const google::protobuf::DescriptorProto &proto, const auto &inherited_options,
                                  file_descriptor_t *parent_file, message_descriptor_t *parent_message)
        : base_type(proto), proto_(proto), options_(proto.options.value_or(google::protobuf::MessageOptions{})),
          parent_file_(parent_file), parent_message_(parent_message) {
      setup_options(inherited_options);
      if constexpr (requires { base_type::on_options_resolved(proto_, options_); }) {
        base_type::on_options_resolved(proto_, options_);
      }
    }

    message_descriptor_t(const message_descriptor_t &) = delete;
    message_descriptor_t(message_descriptor_t &&) = default;
    ~message_descriptor_t() = default;
    message_descriptor_t &operator=(const message_descriptor_t &) = delete;
    message_descriptor_t &operator=(message_descriptor_t &&) = default;

    [[nodiscard]] const google::protobuf::DescriptorProto &proto() const { return proto_; }
    [[nodiscard]] const google::protobuf::MessageOptions &options() const { return options_; }
    [[nodiscard]] file_descriptor_t *parent_file() const { return parent_file_; }
    [[nodiscard]] message_descriptor_t *parent_message() const { return parent_message_; }
    [[nodiscard]] message_descriptor_t &root_message() { 
      auto result = this;
      for (; result->parent_message_ != nullptr; result = result->parent_message_);
      return *result; 
    }

    [[nodiscard]] bool is_map_entry() const { return proto_.options.has_value() && proto_.options->map_entry; }

    [[nodiscard]] auto fields() const { return std::views::transform(fields_, deref_pointer{}); }
    [[nodiscard]] auto enums() const { return std::views::transform(enums_, deref_pointer{}); }
    [[nodiscard]] auto oneofs() const { return std::views::transform(oneofs_, deref_pointer{}); }
    [[nodiscard]] auto messages() const { return std::views::transform(messages_, deref_pointer{}); }
    [[nodiscard]] auto extensions() const { return std::views::transform(extensions_, deref_pointer{}); }

  private:
    friend class descriptor_pool;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const google::protobuf::DescriptorProto &proto_;
    google::protobuf::MessageOptions options_;
    file_descriptor_t *parent_file_;
    message_descriptor_t *parent_message_;
    std::vector<field_descriptor_t *> fields_;
    std::vector<enum_descriptor_t *> enums_;
    std::vector<message_descriptor_t *> messages_;
    std::vector<oneof_descriptor_t *> oneofs_;
    std::vector<field_descriptor_t *> extensions_;

    void setup_options(const google::protobuf::MessageOptions &inherited_options) {
      options_.features = merge_features(inherited_options.features.value(), proto_.options);
      options_.extensions.fields.insert(hpp::proto::sorted_unique, inherited_options.extensions.fields.begin(),
                                        inherited_options.extensions.fields.end());
    }

    void setup_options(const google::protobuf::FileOptions &inherited_options) {
      options_.features = merge_features(inherited_options.features.value(), proto_.options);
      if constexpr (requires { AddOns::adapt_option_extensions(options_.extensions, inherited_options.extensions); }) {
        google::protobuf::MessageOptions::extension_t extensions;
        AddOns::adapt_option_extensions(extensions, inherited_options.extensions);
        options_.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(),
                                          extensions.fields.end());
      }
    }
  };

  class file_descriptor_t : public AddOns::template file_descriptor<file_descriptor_t, message_descriptor_t,
                                                                    enum_descriptor_t, field_descriptor_t> {
  public:
    using pool_type = descriptor_pool;
    using base_type = AddOns::template file_descriptor<file_descriptor_t, message_descriptor_t, enum_descriptor_t,
                                                       field_descriptor_t>;
    explicit file_descriptor_t(const google::protobuf::FileDescriptorProto &proto,
                               const google::protobuf::FeatureSet &default_features)
        : base_type(proto), proto_(proto), options_(proto.options.value_or(google::protobuf::FileOptions{})) {
      options_.features = merge_features(default_features, proto.options);
      if constexpr (requires { AddOns::default_file_options_extensions(); }) {
        auto extensions = AddOns::default_file_options_extensions();
        options_.extensions.fields.insert(hpp::proto::sorted_unique, extensions.fields.begin(),
                                          extensions.fields.end());
      }
      if constexpr (requires { base_type::on_options_resolved(proto_, options_); }) {
        base_type::on_options_resolved(proto_, options_);
      }
    }

    file_descriptor_t(const file_descriptor_t &) = delete;
    file_descriptor_t(file_descriptor_t &&) = default;
    ~file_descriptor_t() = default;
    file_descriptor_t &operator=(const file_descriptor_t &) = delete;
    file_descriptor_t &operator=(file_descriptor_t &&) = default;

    [[nodiscard]] const google::protobuf::FileDescriptorProto &proto() const { return proto_; }
    [[nodiscard]] const google::protobuf::FileOptions &options() const { return options_; }

    [[nodiscard]] auto enums() const { return std::views::transform(enums_, deref_pointer{}); }
    [[nodiscard]] auto messages() const { return std::views::transform(messages_, deref_pointer{}); }
    [[nodiscard]] auto extensions() const { return std::views::transform(extensions_, deref_pointer{}); }
    [[nodiscard]] auto dependencies() const { return std::views::transform(dependencies_, deref_pointer{}); }
    [[nodiscard]] const descriptor_pool &descriptor_pool() const { return *descriptor_pool_; }

  private:
    friend class descriptor_pool;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const google::protobuf::FileDescriptorProto &proto_;
    google::protobuf::FileOptions options_;
    std::vector<enum_descriptor_t *> enums_;
    std::vector<message_descriptor_t *> messages_;
    std::vector<field_descriptor_t *> extensions_;
    std::vector<file_descriptor_t *> dependencies_;
    const class descriptor_pool *descriptor_pool_ = nullptr;
  };

  explicit descriptor_pool(std::vector<google::protobuf::FileDescriptorProto> &&proto_files)
      : proto_files_(std::move(proto_files)) {
    init(proto_files_);
  }

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  explicit descriptor_pool(google::protobuf::FileDescriptorSet &&fileset) : descriptor_pool(std::move(fileset.file)) {}

  constexpr ~descriptor_pool() = default;
  descriptor_pool(const descriptor_pool &) = delete;
  descriptor_pool(descriptor_pool &&) = delete;
  descriptor_pool &operator=(const descriptor_pool &) = delete;
  descriptor_pool &operator=(descriptor_pool &&) = delete;

  [[nodiscard]] const message_descriptor_t *get_message_descriptor(std::string_view name) const {
    auto itr = message_map_.find(name);
    return itr == message_map_.end() ? nullptr : itr->second;
  }

  [[nodiscard]] message_descriptor_t *get_message_descriptor(std::string_view name) {
    auto itr = message_map_.find(name);
    return itr == message_map_.end() ? nullptr : itr->second;
  }

  [[nodiscard]] const enum_descriptor_t *get_enum_descriptor(std::string_view name) const {
    auto itr = enum_map_.find(name);
    return itr == enum_map_.end() ? nullptr : itr->second;
  }

  [[nodiscard]] enum_descriptor_t *get_enum_descriptor(std::string_view name) {
    auto itr = enum_map_.find(name);
    return itr == enum_map_.end() ? nullptr : itr->second;
  }

  [[nodiscard]] const file_descriptor_t *get_file_descriptor(std::string_view name) const {
    auto itr = file_map_.find(name);
    return itr == file_map_.end() ? nullptr : itr->second;
  }

  [[nodiscard]] file_descriptor_t *get_file_descriptor(std::string_view name) {
    auto itr = file_map_.find(name);
    return itr == file_map_.end() ? nullptr : itr->second;
  }

  std::span<file_descriptor_t> files() { return files_; }
  std::span<message_descriptor_t> messages() { return messages_; }
  std::span<enum_descriptor_t> enums() { return enums_; }
  std::span<oneof_descriptor_t> oneofs() { return oneofs_; }
  std::span<field_descriptor_t> fields() { return fields_; }

  [[nodiscard]] const flat_map<std::string, message_descriptor_t *, string_view_comp> &message_map() const {
    return message_map_;
  }
  [[nodiscard]] const flat_map<std::string, enum_descriptor_t *, string_view_comp> &enum_map() const {
    return enum_map_;
  }

private:
  void init(const std::vector<google::protobuf::FileDescriptorProto> &proto_files) {
    const descriptor_counter counter(proto_files);
    files_.reserve(counter.files);
    messages_.reserve(counter.messages);
    enums_.reserve(counter.enums);
    oneofs_.reserve(counter.oneofs);
    fields_.reserve(counter.fields);
    initial_reserve(file_map_, counter.files);
    initial_reserve(message_map_, counter.messages);
    initial_reserve(enum_map_, counter.enums);

    for (const auto &proto : proto_files) {
      if (!proto.name.empty() && file_map_.count(proto.name) == 0) {
        build(files_.emplace_back(proto, select_features(proto)));
      }
    }

    for (auto &file : files_) {
      file.descriptor_pool_ = this;
      file.dependencies_.resize(file.proto().dependency.size());
      std::transform(file.proto().dependency.begin(), file.proto().dependency.end(), file.dependencies_.begin(),
                     [this](auto &dep) { return this->get_file_descriptor(dep); });
    }

    for (auto [name, msg] : message_map_) {
      build_fields(*msg, name);
      build_extensions(*msg, name);
    }

    for (auto [name, f] : file_map_) {
      build_extensions(*f, f->proto_.package);
    }

    for (auto &f : fields_) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      if (f.proto_.type == TYPE_MESSAGE || f.proto_.type == TYPE_GROUP) {
        auto desc = find_type(message_map_, f.proto_.type_name.substr(1));
        if (desc) {
          f.type_descriptor_ = desc;
          if (desc->is_map_entry()) {
            f.field_option_bitset_ |= MASK_MAP_ENTRY;
          }
        }
      } else if (f.proto_.type == TYPE_ENUM) {
        f.type_descriptor_ = find_type(enum_map_, f.proto_.type_name.substr(1));
      }

      if (!f.proto_.extendee.empty()) {
        f.extendee_descriptor_ = find_type(message_map_, f.proto_.extendee.substr(1));
      }
    }

    assert(messages_.size() == counter.messages);
  }

  static google::protobuf::FeatureSet merge_features(google::protobuf::FeatureSet features, const auto &options) {
    if (options.has_value()) {
      const auto &overriding_features = options->features;
      if (overriding_features.has_value()) {
        hpp::proto::merge(features, *options->features);
      }
    }
    return features;
  }

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

  std::vector<google::protobuf::FileDescriptorProto> proto_files_;
  std::vector<file_descriptor_t> files_;
  std::vector<message_descriptor_t> messages_;
  std::vector<enum_descriptor_t> enums_;
  std::vector<oneof_descriptor_t> oneofs_;
  std::vector<field_descriptor_t> fields_;

  flat_map<std::string, file_descriptor_t *, string_view_comp> file_map_;
  flat_map<std::string, message_descriptor_t *, string_view_comp> message_map_;
  flat_map<std::string, enum_descriptor_t *, string_view_comp> enum_map_;
  google::protobuf::Edition current_edition_ = {};

  google::protobuf::FeatureSet select_features(const google::protobuf::FileDescriptorProto &file) {
    using namespace std::string_view_literals;
    static const google::protobuf::FeatureSetDefaults cpp_edition_defaults =
        hpp::proto::read_proto<google::protobuf::FeatureSetDefaults>(
            // from https://github.com/protocolbuffers/protobuf/blob/v28.2/src/google/protobuf/cpp_edition_defaults.h
            "\n\035\030\204\007\"\003\302>\000*\023\010\001\020\002\030\002 \003(\0010\002\302>\004\010\001\020\003\n\035\030\347\007\"\003\302>\000*\023\010\002\020\001\030\001 \002(\0010\001\302>\004\010\000\020\003\n\035\030\350\007\"\023\010\001\020\001\030\001 \002(\0010\001\302>\004\010\000\020\003*\003\302>\000\n\035\030\351\007\"\023\010\001\020\001\030\001 \002(\0010\001\302>\004\010\000\020\001*\003\302>\000 \346\007(\351\007"sv)
            .value();

    current_edition_ = google::protobuf::Edition::EDITION_LEGACY;
    if (file.syntax == "proto3") {
      current_edition_ = google::protobuf::Edition::EDITION_PROTO3;
    } else if (file.syntax == "editions") {
      current_edition_ = file.edition;
    }
    for (const auto &default_features : cpp_edition_defaults.defaults) {
      if (default_features.edition == current_edition_) {
        if (current_edition_ <= google::protobuf::Edition::EDITION_PROTO3) {
          return default_features.fixed_features.value();
        }

        auto features = default_features.overridable_features.value_or(google::protobuf::FeatureSet{});
        return merge_features(features, file.options);
      }
    }
    throw std::runtime_error(std::string{"unsupported edition used by "} + file.name);
  }

  void build(file_descriptor_t &descriptor) {
    file_map_.try_emplace(descriptor.proto_.name, &descriptor);
    const std::string package = descriptor.proto_.package;
    descriptor.messages_.reserve(descriptor.proto_.message_type.size());
    for (auto &proto : descriptor.proto_.message_type) {
      std::string const scope = !package.empty() ? package + "." + proto.name : proto.name;
      auto &message =
          messages_.emplace_back(proto, descriptor.options_, &descriptor, static_cast<message_descriptor_t *>(nullptr));
      build(message, scope);
      descriptor.messages_.push_back(&message);
    }

    descriptor.enums_.reserve(descriptor.proto_.enum_type.size());
    for (auto &proto : descriptor.proto_.enum_type) {
      const std::string scope = !package.empty() ? package + "." + proto.name : proto.name;
      auto &e = enums_.emplace_back(proto, descriptor.options_, &descriptor, nullptr);
      enum_map_.try_emplace(scope, &e);
      descriptor.enums_.push_back(&e);
    }
  }

  void build(message_descriptor_t &descriptor, const std::string &scope) {
    descriptor.oneofs_.reserve(descriptor.proto_.oneof_decl.size());
    for (auto &proto : descriptor.proto_.oneof_decl) {
      auto &oneof = oneofs_.emplace_back(proto, descriptor.options_);
      descriptor.oneofs_.push_back(&oneof);
    }

    message_map_.try_emplace(scope, &descriptor);
    descriptor.messages_.reserve(descriptor.proto_.nested_type.size());
    for (auto &proto : descriptor.proto_.nested_type) {
      const std::string new_scope = scope.empty() ? proto.name : scope + "." + proto.name;
      auto &message = messages_.emplace_back(proto, descriptor.options_, descriptor.parent_file_, &descriptor);
      build(message, new_scope);
      descriptor.messages_.push_back(&message);
    }

    descriptor.enums_.reserve(descriptor.proto_.enum_type.size());
    for (auto &proto : descriptor.proto_.enum_type) {
      const std::string new_scope = scope.empty() ? proto.name : scope + "." + proto.name;
      auto &e = enums_.emplace_back(proto, descriptor.options_, descriptor.parent_file_, &descriptor);
      enum_map_.try_emplace(new_scope, &e);
      descriptor.enums_.push_back(&e);
    }
  }

  template <typename FlatMap>
  typename FlatMap::mapped_type find_type(FlatMap &types, const std::string &qualified_name) {
    auto itr = types.find(qualified_name);
    assert(itr != types.end() && "unable to find type");
    return itr->second;
  }

  void build_fields(message_descriptor_t &descriptor, const std::string &qualified_name) {
    descriptor.fields_.reserve(descriptor.proto_.field.size());
    for (auto &proto : descriptor.proto_.field) {
      auto &field = fields_.emplace_back(proto, qualified_name, &descriptor, descriptor.options_);
      descriptor.fields_.push_back(&field);
      if (proto.oneof_index.has_value()) {
        descriptor.oneofs_[static_cast<std::size_t>(*proto.oneof_index)]->fields_.push_back(&field);
      }
    }
  };

  void build_extensions(auto &parent, const std::string &scope) {
    for (auto &proto : parent.proto_.extension) {
      message_descriptor_t *msg_desc = nullptr;
      if constexpr (std::same_as<decltype(&parent), message_descriptor_t *>) {
        msg_desc = &parent;
      }
      auto &field = fields_.emplace_back(proto, scope, msg_desc, parent.options_);
      parent.extensions_.push_back(&field);
    }
  }
  // NOLINTEND(bugprone-unchecked-optional-access)
};

struct file_descriptor_pb {
  std::string_view value;

  constexpr bool operator==(const file_descriptor_pb &) const = default;
  constexpr bool operator<(const file_descriptor_pb &other) const { return value < other.value; };
};

namespace concepts {
template <typename T>
concept input_bytes_range =
    std::ranges::input_range<T> && contiguous_byte_range<typename std::ranges::range_value_t<T>>;

template <typename T>
concept file_descriptor_pb_array =
    std::ranges::input_range<T> && std::same_as<typename std::ranges::range_value_t<T>, file_descriptor_pb>;
} // namespace concepts

std::expected<google::protobuf::FileDescriptorSet, hpp::proto::status>
make_file_descriptor_set(concepts::contiguous_byte_range auto const &stream) {
  google::protobuf::FileDescriptorSet fileset;
  if (auto ec = read_proto(fileset, stream); !ec.ok()) [[unlikely]] {
    return std::unexpected(ec);
  }
  return fileset;
}

std::expected<google::protobuf::FileDescriptorSet, hpp::proto::status>
make_file_descriptor_set(concepts::segmented_byte_range auto const &stream_range) {
  google::protobuf::FileDescriptorSet fileset;
  for (const auto &stream : stream_range) {
    google::protobuf::FileDescriptorSet tmp;
    if (auto ec = read_proto(tmp, stream); !ec.ok()) [[unlikely]] {
      return std::unexpected(ec);
    }
    fileset.file.insert(fileset.file.end(), tmp.file.begin(), tmp.file.end());
  }
  // double check if we have duplicated files
  std::unordered_map<std::string, google::protobuf::FileDescriptorProto *> file_map;
  auto itr = fileset.file.begin();
  auto last = fileset.file.end();
  for (; itr != last; ++itr) {
    auto [map_itr, inserted] = file_map.try_emplace(itr->name, &(*itr));
    if (!inserted) {
      if (*map_itr->second != *itr) [[unlikely]] {
        // in this case, we have two files with identical names but different content
        return std::unexpected(std::errc::invalid_argument);
      } else {
        std::rotate(itr, itr + 1, last);
        --last;
      }
    }
  }
  fileset.file.erase(last, fileset.file.end());
  return fileset;
}

std::expected<google::protobuf::FileDescriptorSet, hpp::proto::status>
make_file_descriptor_set(concepts::file_descriptor_pb_array auto const &...args) {
  constexpr auto s = (std::tuple_size_v<std::remove_cvref_t<decltype(args)>> + ...);
  std::array<file_descriptor_pb, s> tmp;
  auto it = tmp.begin();
  ((it = std::copy(args.begin(), args.end(), it)), ...);

  std::sort(tmp.begin(), it);
  auto last = std::unique(tmp.begin(), tmp.end());
  auto size = static_cast<std::size_t>(last - tmp.begin());

  google::protobuf::FileDescriptorSet fileset;
  fileset.file.resize(size);

  for (std::size_t i = 0; i < size; ++i) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    if (auto ec = read_proto(fileset.file[i], tmp[i].value); !ec.ok()) [[unlikely]] {
      return std::unexpected(ec);
    }
  }
  return fileset;
}

} // namespace hpp::proto
