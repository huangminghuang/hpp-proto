// MIT License
//
// Copyright (c) Huang-Ming Huang
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
#include <iostream>
#include <memory_resource>
#include <system_error>
#include <unordered_set>

#include <google/protobuf/descriptor.pb.hpp>
#include <hpp_proto/file_descriptor_pb.hpp>
#include <hpp_proto/merge.hpp>
namespace hpp_proto {

struct deref_pointer {
  template <typename T>
  T &operator()(T *pointer) {
    return *pointer;
  }
};

struct distinct_file_tag_t {};
constexpr distinct_file_tag_t distinct_file_tag;
template <typename AddOns>
class descriptor_pool {
  enum class field_option_mask : uint8_t {
    MASK_EXPLICIT_PRESENCE = 1,
    MASK_REPEATED = 2,
    MASK_PACKED = 4,
    MASK_UTF8_VALIDATION = 8,
    MASK_DELIMITED = 16,
    MASK_REQUIRED = 32,
    MASK_MAP_ENTRY = 64
  };

  static constexpr uint8_t mask(field_option_mask value) { return static_cast<uint8_t>(value); }

  static constexpr bool has_mask(uint8_t bitset, field_option_mask value) { return (bitset & mask(value)) != 0; }

  using string_t = AddOns::string_t;
  template <typename T>
  using vector_t = AddOns::template vector_t<T>;

  template <typename T, typename U>
  using map_t = AddOns::template map_t<T, U>;

public:
  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  using traits_type = typename AddOns::traits_type;
  using FieldDescriptorProto = google::protobuf::FieldDescriptorProto<traits_type>;
  using FieldOptions = google::protobuf::FieldOptions<traits_type>;
  using FeatureSet = google::protobuf::FeatureSet<traits_type>;
  using OneofDescriptorProto = google::protobuf::OneofDescriptorProto<traits_type>;
  using OneofOptions = google::protobuf::OneofOptions<traits_type>;
  using EnumDescriptorProto = google::protobuf::EnumDescriptorProto<traits_type>;
  using EnumValueOptions = google::protobuf::EnumValueOptions<traits_type>;
  using EnumOptions = google::protobuf::EnumOptions<traits_type>;
  using DescriptorProto = google::protobuf::DescriptorProto<traits_type>;
  using MessageOptions = google::protobuf::MessageOptions<traits_type>;
  using FileDescriptorProto = google::protobuf::FileDescriptorProto<traits_type>;
  using FileOptions = google::protobuf::FileOptions<traits_type>;
  using FileDescriptorSet = google::protobuf::FileDescriptorSet<traits_type>;

  class message_descriptor_t;
  class enum_descriptor_t;
  class file_descriptor_t;
  class field_descriptor_base {
  public:
    field_descriptor_base(const FieldDescriptorProto &proto, message_descriptor_t *parent,
                          const auto &inherited_options)
        : proto_(proto), parent_message_(parent), options_(proto.options.value_or(FieldOptions{})) {
      options_.features = merge_features(inherited_options.features.value(), proto.options);

      setup_presence();
      setup_repeated();
      setup_utf8_validation();
      setup_delimited();
      setup_required();
    }

    field_descriptor_base(const field_descriptor_base &) = delete;
    field_descriptor_base(field_descriptor_base &&) = default;
    ~field_descriptor_base() = default;
    field_descriptor_base &operator=(const field_descriptor_base &) = delete;
    field_descriptor_base &operator=(field_descriptor_base &&) = default;

    [[nodiscard]] const FieldDescriptorProto &proto() const { return proto_; }
    [[nodiscard]] const FieldOptions &options() const { return options_; }
    [[nodiscard]] message_descriptor_t *parent_message() const { return parent_message_; }
    [[nodiscard]] bool is_message_or_enum() const { return type_descriptor_ != nullptr; }
    [[nodiscard]] message_descriptor_t *extendee_descriptor() const { return extendee_descriptor_; }

    [[nodiscard]] message_descriptor_t *message_field_type_descriptor() const {
      return (proto_.type == FieldDescriptorProto::Type::TYPE_MESSAGE ||
              proto_.type == FieldDescriptorProto::Type::TYPE_GROUP)
                 ? static_cast<message_descriptor_t *>(type_descriptor_)
                 : nullptr;
    }

    [[nodiscard]] enum_descriptor_t *enum_field_type_descriptor() const {
      return (proto_.type == FieldDescriptorProto::Type::TYPE_ENUM) ? static_cast<enum_descriptor_t *>(type_descriptor_)
                                                                    : nullptr;
    }

    [[nodiscard]] bool repeated_expanded() const {
      return has_mask(field_option_bitset_, field_option_mask::MASK_REPEATED) &&
             !has_mask(field_option_bitset_, field_option_mask::MASK_PACKED);
    }
    [[nodiscard]] bool is_packed() const { return has_mask(field_option_bitset_, field_option_mask::MASK_PACKED); }
    [[nodiscard]] constexpr bool is_repeated() const {
      return has_mask(field_option_bitset_, field_option_mask::MASK_REPEATED);
    }
    [[nodiscard]] bool requires_utf8_validation() const {
      return has_mask(field_option_bitset_, field_option_mask::MASK_UTF8_VALIDATION);
    }
    [[nodiscard]] bool is_delimited() const {
      return has_mask(field_option_bitset_, field_option_mask::MASK_DELIMITED);
    }
    [[nodiscard]] bool is_map_entry() const {
      return has_mask(field_option_bitset_, field_option_mask::MASK_MAP_ENTRY);
    }
    [[nodiscard]] bool explicit_presence() const {
      return has_mask(field_option_bitset_, field_option_mask::MASK_EXPLICIT_PRESENCE);
    }
    [[nodiscard]] bool is_required() const { return has_mask(field_option_bitset_, field_option_mask::MASK_REQUIRED); }

    void set_explicit_presence() { field_option_bitset_ |= mask(field_option_mask::MASK_EXPLICIT_PRESENCE); }

  private:
    void setup_presence() {
      if (proto_.label == FieldDescriptorProto::Label::LABEL_OPTIONAL) {
        if (proto_.type == FieldDescriptorProto::Type::TYPE_GROUP ||
            proto_.type == FieldDescriptorProto::Type::TYPE_MESSAGE || proto_.proto3_optional ||
            proto_.oneof_index.has_value() ||
            options_.features->field_presence == FeatureSet::FieldPresence::EXPLICIT ||
            options_.features->field_presence == FeatureSet::FieldPresence::FIELD_PRESENCE_UNKNOWN) {
          field_option_bitset_ |= mask(field_option_mask::MASK_EXPLICIT_PRESENCE);
        }
      }
    }

    void setup_repeated() {
      if (proto_.label != FieldDescriptorProto::Label::LABEL_REPEATED) {
        return;
      }
      field_option_bitset_ |= mask(field_option_mask::MASK_REPEATED);

      auto type = proto_.type;
      if (type == FieldDescriptorProto::Type::TYPE_MESSAGE || type == FieldDescriptorProto::Type::TYPE_STRING ||
          type == FieldDescriptorProto::Type::TYPE_BYTES || type == FieldDescriptorProto::Type::TYPE_GROUP) {
        return;
      }
      if (proto_.options.has_value() && proto_.options->packed.has_value() && proto_.options->packed.value()) {
        field_option_bitset_ |= mask(field_option_mask::MASK_PACKED);
        return;
      }
      if (options_.features->repeated_field_encoding == FeatureSet::RepeatedFieldEncoding::PACKED) {
        field_option_bitset_ |= mask(field_option_mask::MASK_PACKED);
      }
    }

    void setup_utf8_validation() {
      if (proto_.type == FieldDescriptorProto::Type::TYPE_STRING &&
          options_.features.value().utf8_validation == FeatureSet::Utf8Validation::VERIFY) {
        field_option_bitset_ |= mask(field_option_mask::MASK_UTF8_VALIDATION);
      }
    }

    void setup_delimited() {
      if (proto_.type == FieldDescriptorProto::Type::TYPE_GROUP ||
          (proto_.type == FieldDescriptorProto::Type::TYPE_MESSAGE &&
           options_.features.value().message_encoding == FeatureSet::MessageEncoding::DELIMITED)) {
        field_option_bitset_ |= mask(field_option_mask::MASK_DELIMITED);
      }
    }

    void setup_required() {
      if (proto_.label == FieldDescriptorProto::Label::LABEL_REQUIRED ||
          options_.features->field_presence == FeatureSet::FieldPresence::LEGACY_REQUIRED) {
        field_option_bitset_ |= mask(field_option_mask::MASK_REQUIRED);
      }
    }

    friend class descriptor_pool;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const FieldDescriptorProto &proto_;
    message_descriptor_t *parent_message_ = nullptr;
    void *type_descriptor_ = nullptr;
    message_descriptor_t *extendee_descriptor_ = nullptr;
    uint8_t field_option_bitset_ = 0;

  protected:
    FieldOptions options_;
  };

  class field_descriptor_t : public field_descriptor_base,
                             public AddOns::template field_descriptor<field_descriptor_t> {
  public:
    using addon_type = AddOns::template field_descriptor<field_descriptor_t>;
    field_descriptor_t(const FieldDescriptorProto &proto, message_descriptor_t *parent, const auto &inherited_options)
        : field_descriptor_base(proto, parent, inherited_options), addon_type(*this, inherited_options) {}
  };

  class oneof_descriptor_base {
  public:
    explicit oneof_descriptor_base(const OneofDescriptorProto &proto, const MessageOptions &inherited_options)
        : proto_(proto), options_(proto.options.value_or(OneofOptions{})) {
      options_.features = merge_features(inherited_options.features.value(), proto.options);
    }

    ~oneof_descriptor_base() = default;
    oneof_descriptor_base(const oneof_descriptor_base &) = delete;
    oneof_descriptor_base(oneof_descriptor_base &&) = default;
    oneof_descriptor_base &operator=(const oneof_descriptor_base &) = delete;
    oneof_descriptor_base &operator=(oneof_descriptor_base &&) = default;

    [[nodiscard]] const OneofDescriptorProto &proto() const { return proto_; }
    [[nodiscard]] const OneofOptions &options() const { return options_; }
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
    const OneofDescriptorProto &proto_;
    vector_t<field_descriptor_t *> fields_;

  protected:
    OneofOptions options_;
  };

  class oneof_descriptor_t : public oneof_descriptor_base,
                             public AddOns::template oneof_descriptor<oneof_descriptor_t> {
    using addon_type = AddOns::template oneof_descriptor<oneof_descriptor_t>;

  public:
    oneof_descriptor_t(const OneofDescriptorProto &proto, const MessageOptions &inherited_options)
        : oneof_descriptor_base(proto, inherited_options), addon_type(*this, inherited_options) {}
  };

  class enum_descriptor_base {
  public:
    explicit enum_descriptor_base(const EnumDescriptorProto &proto, string_t &&full_name, const auto &inherited_options,
                                  file_descriptor_t *parent_file, message_descriptor_t *parent_message)
        : proto_(proto), full_name_(std::move(full_name)), parent_file_(parent_file), parent_message_(parent_message),
          options_(proto.options.value_or(EnumOptions{})) {
      options_.features = merge_features(inherited_options.features.value(), proto.options);
    }
    ~enum_descriptor_base() = default;
    enum_descriptor_base(const enum_descriptor_base &) = delete;
    enum_descriptor_base(enum_descriptor_base &&) = default;
    enum_descriptor_base &operator=(const enum_descriptor_base &) = delete;
    enum_descriptor_base &operator=(enum_descriptor_base &&) = default;

    [[nodiscard]] const EnumDescriptorProto &proto() const { return proto_; }
    [[nodiscard]] const EnumOptions &options() const { return options_; }
    [[nodiscard]] std::string_view full_name() const { return full_name_; }
    [[nodiscard]] file_descriptor_t *parent_file() const { return parent_file_; }
    [[nodiscard]] message_descriptor_t *parent_message() const { return parent_message_; }

    [[nodiscard]] bool is_closed() const { return options_.features.value().enum_type == FeatureSet::EnumType::CLOSED; }

    [[nodiscard]] bool valid_enum_value(int32_t v) const {
      return !is_closed() || std::ranges::contains(proto_.value, v, [](const auto &item) { return item.number; });
    }

  private:
    friend class descriptor_pool;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const EnumDescriptorProto &proto_;
    string_t full_name_;
    file_descriptor_t *parent_file_;
    message_descriptor_t *parent_message_;

  protected:
    EnumOptions options_;
  };

  class enum_descriptor_t : public enum_descriptor_base, public AddOns::template enum_descriptor<enum_descriptor_t> {
  public:
    using addon_type = AddOns::template enum_descriptor<enum_descriptor_t>;
    explicit enum_descriptor_t(const EnumDescriptorProto &proto, string_t &&full_name, const auto &inherited_options,
                               file_descriptor_t *parent_file, message_descriptor_t *parent_message)
        : enum_descriptor_base(proto, std::move(full_name), inherited_options, parent_file, parent_message),
          addon_type(*this, inherited_options) {}
  };

  class message_descriptor_base {
  public:
    explicit message_descriptor_base(const DescriptorProto &proto, string_t full_name, const auto &inherited_options,
                                     file_descriptor_t *parent_file, message_descriptor_t *parent_message)
        : proto_(proto), full_name_(std::move(full_name)), parent_file_(parent_file), parent_message_(parent_message),
          options_(proto.options.value_or(MessageOptions{})) {
      options_.features = merge_features(inherited_options.features.value(), proto_.options);
    }

    message_descriptor_base(const message_descriptor_base &) = delete;
    message_descriptor_base(message_descriptor_base &&) = default;
    ~message_descriptor_base() = default;
    message_descriptor_base &operator=(const message_descriptor_base &) = delete;
    message_descriptor_base &operator=(message_descriptor_base &&) = default;

    [[nodiscard]] const DescriptorProto &proto() const { return proto_; }
    [[nodiscard]] const MessageOptions &options() const { return options_; }
    [[nodiscard]] std::string_view full_name() const { return full_name_; }
    [[nodiscard]] file_descriptor_t *parent_file() const { return parent_file_; }
    [[nodiscard]] message_descriptor_t *parent_message() const { return parent_message_; }
    [[nodiscard]] message_descriptor_t &root_message() {
      auto result = this;
      while (result->parent_message_ != nullptr) {
        result = result->parent_message_;
      }
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
    const DescriptorProto &proto_;
    string_t full_name_;
    file_descriptor_t *parent_file_;
    message_descriptor_t *parent_message_;
    vector_t<field_descriptor_t *> fields_;
    vector_t<enum_descriptor_t *> enums_;
    vector_t<oneof_descriptor_t *> oneofs_;
    vector_t<message_descriptor_t *> messages_;
    vector_t<field_descriptor_t *> extensions_;

  protected:
    MessageOptions options_;
  };

  class message_descriptor_t : public message_descriptor_base,
                               public AddOns::template message_descriptor<message_descriptor_t> {
  public:
    using addon_type = AddOns::template message_descriptor<message_descriptor_t>;
    using field_type = field_descriptor_t;

    explicit message_descriptor_t(const DescriptorProto &proto, string_t &&full_name, const auto &inherited_options,
                                  file_descriptor_t *parent_file, message_descriptor_t *parent_message)
        : message_descriptor_base(proto, std::move(full_name), inherited_options, parent_file, parent_message),
          addon_type(*this, inherited_options) {}
  };

  class file_descriptor_base {
  public:
    explicit file_descriptor_base(const FileDescriptorProto &proto, const FeatureSet &default_features)
        : proto_(proto), options_(proto.options.value_or(FileOptions{})) {
      options_.features = merge_features(default_features, proto.options);
    }

    file_descriptor_base(const file_descriptor_base &) = delete;
    file_descriptor_base(file_descriptor_base &&) = default;
    ~file_descriptor_base() = default;
    file_descriptor_base &operator=(const file_descriptor_base &) = delete;
    file_descriptor_base &operator=(file_descriptor_base &&) = default;

    [[nodiscard]] const FileDescriptorProto &proto() const { return proto_; }
    [[nodiscard]] const FileOptions &options() const { return options_; }

    [[nodiscard]] auto enums() const { return std::views::transform(enums_, deref_pointer{}); }
    [[nodiscard]] auto messages() const { return std::views::transform(messages_, deref_pointer{}); }
    [[nodiscard]] auto extensions() const { return std::views::transform(extensions_, deref_pointer{}); }
    [[nodiscard]] auto dependencies() const { return std::views::transform(dependencies_, deref_pointer{}); }
    [[nodiscard]] const descriptor_pool &get_descriptor_pool() const { return *descriptor_pool_; }

  private:
    friend class descriptor_pool;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const FileDescriptorProto &proto_;
    vector_t<enum_descriptor_t *> enums_;
    vector_t<message_descriptor_t *> messages_;
    vector_t<field_descriptor_t *> extensions_;
    vector_t<file_descriptor_t *> dependencies_;
    const class descriptor_pool *descriptor_pool_ = nullptr;

  protected:
    FileOptions options_;
  };

  class file_descriptor_t : public file_descriptor_base, public AddOns::template file_descriptor<file_descriptor_t> {
  public:
    using addon_type = AddOns::template file_descriptor<file_descriptor_t>;
    explicit file_descriptor_t(const FileDescriptorProto &proto, const FeatureSet &default_features)
        : file_descriptor_base(proto, default_features), addon_type(*this) {}
  };

  static std::expected<FileDescriptorSet, std::errc>
  make_file_descriptor_set(concepts::file_descriptor_pb_range auto const &unique_descs, distinct_file_tag_t,
                           concepts::is_option_type auto &&...option) {
    std::expected<FileDescriptorSet, status> result;
    pb_context ctx{std::forward<decltype(option)>(option)...};
    decltype(auto) files = detail::as_modifiable(ctx, result->file);
    files.resize(std::ranges::size(unique_descs));
    std::size_t i = 0;
    for (const auto &desc : unique_descs) {
      if (auto ec = read_binpb(files[i++], desc.value, ctx); !ec.ok()) {
        result = std::unexpected(ec);
        return result;
      }
    }
    return result;
  }

  template <std::ranges::forward_range Range>
    requires std::same_as<std::ranges::range_value_t<Range>, file_descriptor_pb>
  static std::expected<FileDescriptorSet, std::errc>
  make_file_descriptor_set(Range const &descs, concepts::is_option_type auto &&...option) {
    std::unordered_set<file_descriptor_pb> unique_files;
    unique_files.insert(std::ranges::begin(descs), std::ranges::end(descs));

    return make_file_descriptor_set(unique_files, distinct_file_tag, std::forward<decltype(option)>(option)...);
  }

  constexpr ~descriptor_pool() = default;
  descriptor_pool(const descriptor_pool &) = delete;
  descriptor_pool(descriptor_pool &&) = default;
  descriptor_pool &operator=(const descriptor_pool &) = delete;
  descriptor_pool &operator=(descriptor_pool &&) = default;

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
  [[nodiscard]] std::span<const file_descriptor_t> files() const { return files_; }
  std::span<message_descriptor_t> messages() { return messages_; }
  [[nodiscard]] std::span<const message_descriptor_t> messages() const { return messages_; }
  std::span<enum_descriptor_t> enums() { return enums_; }
  [[nodiscard]] std::span<const enum_descriptor_t> enums() const { return enums_; }
  std::span<oneof_descriptor_t> oneofs() { return oneofs_; }
  [[nodiscard]] std::span<const oneof_descriptor_t> oneofs() const { return oneofs_; }
  std::span<field_descriptor_t> fields() { return fields_; }
  [[nodiscard]] std::span<const field_descriptor_t> fields() const { return fields_; }

  [[nodiscard]] const map_t<std::string_view, message_descriptor_t *> &message_map() const { return message_map_; }
  [[nodiscard]] const map_t<std::string_view, enum_descriptor_t *> &enum_map() const { return enum_map_; }

  descriptor_pool() = default;

  /**
   * @brief Initialize the pool from a FileDescriptorSet.
   *
   * @return status::ok() on success; std::errc::bad_message if the descriptor set is invalid.
   */
  [[nodiscard]] status init(FileDescriptorSet &&fileset)
    requires(!std::is_trivially_destructible_v<FileDescriptorSet>)
  {
    fileset_.file = std::move(fileset).file;
    return init();
  }

  /**
   * @brief Initialize the pool from a FileDescriptorSet using a PMR default resource.
   *
   * @return status::ok() on success; std::errc::bad_message if the descriptor set is invalid.
   */
  [[nodiscard]] status init(FileDescriptorSet &&fileset, std::pmr::memory_resource &mr) {
    fileset_.file = std::move(fileset).file;
    default_resource_guard guard{mr};
    return init();
  }

private:
  friend class dynamic_message_factory;
  struct descriptor_counter {
    std::size_t files = 0;
    std::size_t messages = 0;
    std::size_t fields = 0;
    std::size_t oneofs = 0;
    std::size_t enums = 0;

    explicit descriptor_counter(const FileDescriptorSet &fileset) {
      for (const auto &f : fileset.file) {
        count_file(f);
      }
    }

    void count_file(const FileDescriptorProto &file) {
      files++;
      for (const auto &m : file.message_type) {
        count_message(m);
      }
      enums += file.enum_type.size();
      fields += file.extension.size();
    }

    void count_message(const DescriptorProto &message) {
      messages++;
      for (const auto &m : message.nested_type) {
        count_message(m);
      }
      enums += message.enum_type.size();
      fields += message.field.size() + message.extension.size();
      oneofs += message.oneof_decl.size();
    }
  };

  status init() {
    files_.clear();
    messages_.clear();
    enums_.clear();
    oneofs_.clear();
    fields_.clear();
    file_map_.clear();
    message_map_.clear();
    enum_map_.clear();

    const descriptor_counter counter(fileset_);
    reserve_storage(counter);
    if (auto result = build_files_from_fileset(); !result.ok()) {
      return result;
    }
    if (auto result = link_file_dependencies(); !result.ok()) {
      return result;
    }
    if (auto result = build_message_fields_and_extensions(); !result.ok()) {
      return result;
    }
    if (auto result = build_file_extensions(); !result.ok()) {
      return result;
    }
    if (auto result = resolve_field_types(); !result.ok()) {
      return result;
    }

    assert(messages_.size() == counter.messages);
    return {};
  }

  void reserve_storage(const descriptor_counter &counter) {
    files_.reserve(counter.files);
    messages_.reserve(counter.messages);
    enums_.reserve(counter.enums);
    oneofs_.reserve(counter.oneofs);
    fields_.reserve(counter.fields);
    if constexpr (concepts::reservable_flat_map<map_t<std::string_view, message_descriptor_t *>>) {
      reserve(file_map_, counter.files);
      reserve(message_map_, counter.messages);
      reserve(enum_map_, counter.enums);
    }
  }

  status build_files_from_fileset() {
    for (const auto &proto : fileset_.file) {
      if (proto.name.empty()) {
        return std::errc::bad_message;
      }
      if (file_map_.count(proto.name) != 0) {
        return std::errc::bad_message;
      }
      auto features = select_features(proto);
      if (!features.has_value()) {
        return features.error();
      }
      auto result = build(files_.emplace_back(proto, std::move(features).value()));
      if (!result.ok()) {
        return result;
      }
    }
    return {};
  }

  status link_file_dependencies() {
    for (auto &file : files_) {
      file.descriptor_pool_ = this;
      file.dependencies_.resize(file.proto().dependency.size());
      std::transform(file.proto().dependency.begin(), file.proto().dependency.end(), file.dependencies_.begin(),
                     [this](auto &dep) { return this->get_file_descriptor(dep); });
      if (std::ranges::any_of(file.dependencies_, [](const auto *dep) { return dep == nullptr; })) {
        return std::errc::bad_message;
      }
    }
    return {};
  }

  status build_message_fields_and_extensions() {
    for (auto &entry : message_map_) {
      auto *msg = entry.second;
      if (auto result = build_fields(*msg); !result.ok()) {
        return result;
      }
      if (auto result = build_extensions(*msg); !result.ok()) {
        return result;
      }
    }
    return {};
  }

  status build_file_extensions() {
    for (auto &entry : file_map_) {
      auto *f = entry.second;
      if (auto result = build_extensions(*f); !result.ok()) {
        return result;
      }
    }
    return {};
  }

  status resolve_field_types() {
    for (auto &f : fields_) {
      if (f.proto_.type == FieldDescriptorProto::Type::TYPE_MESSAGE ||
          f.proto_.type == FieldDescriptorProto::Type::TYPE_GROUP) {
        auto desc = find_type(message_map_, f.proto_.type_name.substr(1));
        if (!desc) {
          return std::errc::bad_message;
        }
        f.type_descriptor_ = desc;
        if (desc->is_map_entry()) {
          f.field_option_bitset_ |= mask(field_option_mask::MASK_MAP_ENTRY);
        }
      } else if (f.proto_.type == FieldDescriptorProto::Type::TYPE_ENUM) {
        auto desc = find_type(enum_map_, f.proto_.type_name.substr(1));
        if (!desc) {
          return std::errc::bad_message;
        }
        f.type_descriptor_ = desc;
      }

      if (!f.proto_.extendee.empty()) {
        auto desc = find_type(message_map_, f.proto_.extendee.substr(1));
        if (!desc) {
          return std::errc::bad_message;
        }
        f.extendee_descriptor_ = desc;
      }
    }
    return {};
  }

  static FeatureSet merge_features(FeatureSet features, const auto &options) {
    if (options.has_value()) {
      const auto &overriding_features = options->features;
      if (overriding_features.has_value()) {
        if constexpr (std::is_trivially_destructible_v<FeatureSet>) {
          hpp_proto::merge(features, *options->features, hpp_proto::alloc_from(*std::pmr::get_default_resource()));
        } else {
          hpp_proto::merge(features, *options->features);
        }
      }
    }
    return features;
  }

  FileDescriptorSet fileset_;
  vector_t<file_descriptor_t> files_;
  vector_t<message_descriptor_t> messages_;
  vector_t<enum_descriptor_t> enums_;
  vector_t<oneof_descriptor_t> oneofs_;
  vector_t<field_descriptor_t> fields_;

  map_t<std::string_view, file_descriptor_t *> file_map_;
  map_t<std::string_view, message_descriptor_t *> message_map_;
  map_t<std::string_view, enum_descriptor_t *> enum_map_;
  google::protobuf::Edition current_edition_ = {};

  class default_resource_guard {
  public:
    explicit default_resource_guard(std::pmr::memory_resource &resource) : prev_(std::pmr::get_default_resource()) {
      std::pmr::set_default_resource(&resource);
    }
    ~default_resource_guard() { std::pmr::set_default_resource(prev_); }
    default_resource_guard(const default_resource_guard &) = delete;
    default_resource_guard &operator=(const default_resource_guard &) = delete;
    default_resource_guard(default_resource_guard &&) = delete;
    default_resource_guard &operator=(default_resource_guard &&) = delete;

  private:
    std::pmr::memory_resource *prev_;
  };

  static google::protobuf::FeatureSetDefaults<traits_type> get_cpp_edition_defaults() {
    // from https://github.com/protocolbuffers/protobuf/blob/v33.0/src/google/protobuf/cpp_edition_defaults.h
    //"\n#\030\204\007\"\003\302>\000*\031\010\001\020\002\030\002
    //\003(\0010\0028\002@\001\302>\006\010\001\020\003\030\000\n#\030\347\007\"\003\302>\000*\031\010\002\020\001\030\001
    //\002(\0010\0018\002@\001\302>\006\010\000\020\003\030\000\n#\030\350\007\"\023\010\001\020\001\030\001
    //\002(\0010\001\302>\004\010\000\020\003*\t8\002@\001\302>\002\030\000\n#\030\351\007\"\031\010\001\020\001\030\001
    //\002(\0010\0018\001@\002\302>\006\010\000\020\001\030\001*\003\302>\000 \346\007(\351\007"sv
    using namespace google::protobuf::FeatureSet_;
    using namespace VisibilityFeature_;
    static auto default_feature_set =
        std::initializer_list<typename google::protobuf::FeatureSetDefaults<traits_type>::FeatureSetEditionDefault>{
            {.edition = google::protobuf::Edition::EDITION_LEGACY,
             .overridable_features = {},
             .fixed_features = FeatureSet{.field_presence = FieldPresence::EXPLICIT,
                                          .enum_type = EnumType::CLOSED,
                                          .repeated_field_encoding = RepeatedFieldEncoding::EXPANDED,
                                          .utf8_validation = Utf8Validation::NONE,
                                          .message_encoding = MessageEncoding::LENGTH_PREFIXED,
                                          .json_format = JsonFormat::LEGACY_BEST_EFFORT,
                                          .enforce_naming_style = EnforceNamingStyle::STYLE_LEGACY,
                                          .default_symbol_visibility = DefaultSymbolVisibility::EXPORT_ALL,
                                          .unknown_fields_ = {}},
             .unknown_fields_ = {}},
            {.edition = google::protobuf::Edition::EDITION_PROTO3,
             .overridable_features = {},
             .fixed_features = FeatureSet{.field_presence = FieldPresence::IMPLICIT,
                                          .enum_type = EnumType::OPEN,
                                          .repeated_field_encoding = RepeatedFieldEncoding::PACKED,
                                          .utf8_validation = Utf8Validation::VERIFY,
                                          .message_encoding = MessageEncoding::LENGTH_PREFIXED,
                                          .json_format = JsonFormat::ALLOW,
                                          .enforce_naming_style = EnforceNamingStyle::STYLE_LEGACY,
                                          .default_symbol_visibility = DefaultSymbolVisibility::EXPORT_ALL,
                                          .unknown_fields_ = {}},
             .unknown_fields_ = {}},
            {.edition = google::protobuf::Edition::EDITION_2023,
             .overridable_features = FeatureSet{.field_presence = FieldPresence::EXPLICIT,
                                                .enum_type = EnumType::OPEN,
                                                .repeated_field_encoding = RepeatedFieldEncoding::PACKED,
                                                .utf8_validation = Utf8Validation::VERIFY,
                                                .message_encoding = MessageEncoding::LENGTH_PREFIXED,
                                                .json_format = JsonFormat::ALLOW,
                                                .enforce_naming_style = EnforceNamingStyle::STYLE_LEGACY,
                                                .default_symbol_visibility = DefaultSymbolVisibility::EXPORT_ALL,
                                                .unknown_fields_ = {}},
             .fixed_features = {},
             .unknown_fields_ = {}},
            {.edition = google::protobuf::Edition::EDITION_2024,
             .overridable_features = FeatureSet{.field_presence = FieldPresence::EXPLICIT,
                                                .enum_type = EnumType::OPEN,
                                                .repeated_field_encoding = RepeatedFieldEncoding::PACKED,
                                                .utf8_validation = Utf8Validation::VERIFY,
                                                .message_encoding = MessageEncoding::LENGTH_PREFIXED,
                                                .json_format = JsonFormat::ALLOW,
                                                .enforce_naming_style = EnforceNamingStyle::STYLE2024,
                                                .default_symbol_visibility = DefaultSymbolVisibility::EXPORT_TOP_LEVEL,
                                                .unknown_fields_ = {}},
             .fixed_features = {},
             .unknown_fields_ = {}}};
    return {.defaults = default_feature_set,
            .minimum_edition = google::protobuf::Edition::EDITION_PROTO2,
            .maximum_edition = google::protobuf::Edition::EDITION_2024,
            .unknown_fields_ = {}};
  }

  std::expected<FeatureSet, status> select_features(const FileDescriptorProto &file) {
    static const auto cpp_edition_defaults = get_cpp_edition_defaults();
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

        auto features = default_features.overridable_features.value_or(FeatureSet{});
        return merge_features(features, file.options);
      }
    }
    return std::unexpected(status{std::errc::bad_message});
  }

  static string_t join_by_dot(std::string_view x, std::string_view y) {
    string_t result;
    result.resize(x.size() + y.size() + 1);
    auto it = std::copy(x.begin(), x.end(), result.begin());
    *it++ = '.';
    std::copy(y.begin(), y.end(), it);
    return result;
  }

  static constexpr bool is_valid_field_number(int32_t number) noexcept {
    // Protobuf valid field-number range:
    // [1, 536870911], excluding the reserved range [19000, 19999].
    return number >= 1 && number <= 536'870'911 && (number < 19'000 || number > 19'999);
  }

  status build(file_descriptor_t &descriptor) {
    [[maybe_unused]] const auto inserted = file_map_.try_emplace(descriptor.proto_.name, &descriptor).second;
    assert(inserted);
    const auto package = descriptor.proto_.package;
    descriptor.messages_.reserve(descriptor.proto_.message_type.size());
    for (auto &proto : descriptor.proto_.message_type) {
      if (proto.name.empty()) {
        return std::errc::bad_message;
      }
      string_t scope = !package.empty() ? join_by_dot(package, proto.name) : string_t{proto.name};
      auto &message = messages_.emplace_back(proto, std::move(scope), descriptor.options_, &descriptor,
                                             static_cast<message_descriptor_t *>(nullptr));
      auto result = build(message);
      if (!result.ok()) {
        return result;
      }
      descriptor.messages_.push_back(&message);
    }

    descriptor.enums_.reserve(descriptor.proto_.enum_type.size());
    for (auto &proto : descriptor.proto_.enum_type) {
      if (proto.name.empty()) {
        return std::errc::bad_message;
      }
      string_t scope = !package.empty() ? join_by_dot(package, proto.name) : string_t{proto.name};
      auto &e = enums_.emplace_back(proto, std::move(scope), descriptor.options_, &descriptor, nullptr);
      if (!enum_map_.try_emplace(e.full_name(), &e).second) {
        return std::errc::bad_message;
      }
      descriptor.enums_.push_back(&e);
    }
    return {};
  }

  status build(message_descriptor_t &descriptor) {
    descriptor.oneofs_.reserve(descriptor.proto_.oneof_decl.size());
    for (auto &proto : descriptor.proto_.oneof_decl) {
      auto &oneof = oneofs_.emplace_back(proto, descriptor.options_);
      descriptor.oneofs_.push_back(&oneof);
    }

    if (!message_map_.try_emplace(descriptor.full_name(), &descriptor).second) {
      return std::errc::bad_message;
    }
    descriptor.messages_.reserve(descriptor.proto_.nested_type.size());
    for (auto &proto : descriptor.proto_.nested_type) {
      if (proto.name.empty()) {
        return std::errc::bad_message;
      }
      auto &message = messages_.emplace_back(proto, join_by_dot(descriptor.full_name(), proto.name),
                                             descriptor.options_, descriptor.parent_file_, &descriptor);
      auto result = build(message);
      if (!result.ok()) {
        return result;
      }
      descriptor.messages_.push_back(&message);
    }

    descriptor.enums_.reserve(descriptor.proto_.enum_type.size());
    for (auto &proto : descriptor.proto_.enum_type) {
      if (proto.name.empty()) {
        return std::errc::bad_message;
      }
      auto &e = enums_.emplace_back(proto, join_by_dot(descriptor.full_name(), proto.name), descriptor.options_,
                                    descriptor.parent_file_, &descriptor);
      if (!enum_map_.try_emplace(e.full_name(), &e).second) {
        return std::errc::bad_message;
      }
      descriptor.enums_.push_back(&e);
    }
    return {};
  }

  template <typename FlatMap>
  typename FlatMap::mapped_type find_type(FlatMap &types, std::string_view qualified_name) {
    auto itr = types.find(qualified_name);
    return itr == types.end() ? nullptr : itr->second;
  }

  status build_fields(message_descriptor_t &descriptor) {
    descriptor.fields_.reserve(descriptor.proto_.field.size());
    std::unordered_set<int32_t> seen_field_numbers;
    seen_field_numbers.reserve(descriptor.proto_.field.size());
    for (auto &proto : descriptor.proto_.field) {
      if (!is_valid_field_number(proto.number)) {
        return std::errc::bad_message;
      }
      if (!seen_field_numbers.insert(proto.number).second) {
        return std::errc::bad_message;
      }
      auto &field = fields_.emplace_back(proto, &descriptor, descriptor.options_);
      if (descriptor.is_map_entry()) {
        field.set_explicit_presence();
      }
      descriptor.fields_.push_back(&field);
      if (proto.oneof_index.has_value()) {
        if (proto.label == FieldDescriptorProto::Label::LABEL_REPEATED) {
          return std::errc::bad_message;
        }
        const auto index = static_cast<std::size_t>(*proto.oneof_index);
        if (index >= descriptor.oneofs_.size()) {
          return std::errc::bad_message;
        }
        descriptor.oneofs_[index]->fields_.push_back(&field);
      }
    }
    if (std::ranges::any_of(descriptor.oneofs_, [](const auto *oneof) { return oneof->fields_.empty(); })) {
      return std::errc::bad_message;
    }
    return {};
  };

  status build_extensions(auto &parent) {
    for (auto &proto : parent.proto_.extension) {
      if (!is_valid_field_number(proto.number)) {
        return std::errc::bad_message;
      }
      message_descriptor_t *msg_desc = nullptr;
      if constexpr (std::same_as<decltype(&parent), message_descriptor_t *>) {
        msg_desc = &parent;
      }
      auto &field = fields_.emplace_back(proto, msg_desc, parent.options_);
      parent.extensions_.push_back(&field);
    }
    return {};
  }
  // NOLINTEND(bugprone-unchecked-optional-access)
};

} // namespace hpp_proto
