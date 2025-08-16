#pragma once
#include <compare>
#include <utility>
#include <variant>

#include <hpp_proto/descriptor_pool.hpp>

namespace hpp::proto::reflection {
enum field_kind_t {
  KIND_DOUBLE,
  KIND_FLOAT,
  KIND_UINT64,
  KIND_INT64,
  KIND_UINT32,
  KIND_INT32,
  KIND_BOOL,
  KIND_STRING,
  KIND_BYTES,
  KIND_ENUM,
  KIND_MESSAGE,
  KIND_REPEATED_DOUBLE,
  KIND_REPEATED_FLOAT,
  KIND_REPEATED_UINT64,
  KIND_REPEATED_INT64,
  KIND_REPEATED_UINT32,
  KIND_REPEATED_INT32,
  KIND_REPEATED_BOOL,
  KIND_REPEATED_STRING,
  KIND_REPEATED_BYTES,
  KIND_REPEATED_ENUM,
  KIND_REPEATED_MESSAGE
};

struct reflection_addons {
  template <typename Derived>
  struct field_descriptor {
    std::variant<bool, std::string, int32_t, uint32_t, int64_t, uint64_t, double, float, std::vector<std::byte>>
        default_value;
    field_kind_t field_kind = KIND_DOUBLE;
    /// slot represents the index to the field memory storage of a message; all non-oneof fields use different slot,
    /// fields of the same oneof type share the same slot.
    uint32_t storage_slot = 0;
    uint16_t oneof_ordinal = 0;
    field_descriptor(const google::protobuf::FieldDescriptorProto &, const std::string &) {
      set_kind_and_default_value();
    }

    void set_kind_and_default_value() {
      using enum google::protobuf::FieldDescriptorProto::Type;
      using namespace std::string_literals;
      const auto &proto = static_cast<Derived *>(this)->proto();
      const auto &default_value_opt = proto.default_value;
      switch (proto.type) {
      case TYPE_MESSAGE:
      case TYPE_GROUP:
        field_kind = KIND_MESSAGE;
        break;
      case TYPE_ENUM:
        field_kind = KIND_ENUM;
        break;
      case TYPE_DOUBLE:
        default_value = std::stod(default_value_opt.empty() ? "0.0"s : default_value_opt);
        field_kind = KIND_DOUBLE;
        break;
      case TYPE_FLOAT:
        default_value = std::stof(default_value_opt.empty() ? "0.0"s : default_value_opt);
        field_kind = KIND_FLOAT;
        break;
      case TYPE_INT64:
      case TYPE_SFIXED64:
      case TYPE_SINT64:
        default_value = std::stoll(default_value_opt.empty() ? "0"s : default_value_opt);
        field_kind = KIND_INT64;
        break;
      case TYPE_UINT64:
      case TYPE_FIXED64:
        default_value = std::stoull(default_value_opt.empty() ? "0"s : default_value_opt);
        field_kind = KIND_UINT64;
        break;
      case TYPE_INT32:
      case TYPE_SFIXED32:
      case TYPE_SINT32:
        default_value = std::stoi(default_value_opt.empty() ? "0"s : default_value_opt);
        field_kind = KIND_INT32;
        break;
      case TYPE_UINT32:
      case TYPE_FIXED32:
        default_value = std::stoul(default_value_opt.empty() ? "0"s : default_value_opt);
        field_kind = KIND_UINT32;
        break;
      case TYPE_BOOL:
        default_value = proto.default_value == "true";
        field_kind = KIND_BOOL;
        break;
      case TYPE_STRING:
        default_value = default_value_opt;
        field_kind = KIND_STRING;
        break;
      case TYPE_BYTES:
        if (!default_value_opt.empty()) {
          auto const view = detail::bit_cast_view<std::byte>(default_value_opt);
          default_value.emplace<std::vector<std::byte>>(view.begin(), view.end());
        }
        field_kind = KIND_BYTES;
        break;
      }

      using enum google::protobuf::FieldDescriptorProto::Label;
      if (proto.label == LABEL_REPEATED) {
        field_kind = static_cast<field_kind_t>(field_kind + KIND_REPEATED_DOUBLE);
      }
    }
  };

  template <typename EnumD>
  struct enum_descriptor {
    explicit enum_descriptor(const google::protobuf::EnumDescriptorProto &) {}

    const int *value_of(const std::string_view name) const {
      const auto &proto = static_cast<const EnumD *>(this)->proto();
      for (const auto &ev : proto.value) {
        if (ev.name == name) {
          return &ev.number;
        }
      }
      return nullptr;
    }

    const char *name_of(int32_t value) const {
      const auto &proto = static_cast<const EnumD *>(this)->proto();
      for (const auto &ev : proto.value) {
        if (ev.number == value) {
          return ev.name.c_str();
        }
      }
      return nullptr;
    }
  };

  template <typename OneofD, typename FieldD>
  struct oneof_descriptor {
    std::vector<FieldD *> fields;
    explicit oneof_descriptor(const google::protobuf::OneofDescriptorProto &) {}
    uint32_t storage_slot() const { return fields.front().storage_slot; }
  };

  template <typename MessageD, typename EnumD, typename OneofD, typename FieldD>
  struct message_descriptor {
    std::vector<FieldD *> fields;
    std::vector<OneofD *> oneofs;
    uint32_t num_slots = 0;
    bool is_map_entry = false;

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
    explicit message_descriptor(const google::protobuf::DescriptorProto &proto)
        : is_map_entry(proto.options.has_value() && proto.options->map_entry) {
      fields.reserve(proto.field.size() + proto.extension.size());
      oneofs.reserve(proto.oneof_decl.size());
    }
    void add_field(FieldD &f) {
      if (f.proto().oneof_index.has_value()) {
        auto &oneof_descriptor = *oneofs[static_cast<std::size_t>(f.proto().oneof_index.value())];
        oneof_descriptor.fields.push_back(&f);

        FieldD *prev_field = nullptr;
        if (!fields.empty()) {
          prev_field = fields.back();
        }

        if (f.proto().oneof_index != prev_field->proto().oneof_index) {
          f.storage_slot = num_slots++;
        } else {
          f.storage_slot = num_slots - 1;
        }
        f.oneof_ordinal = oneof_descriptor.fields.size();
      } else {
        f.storage_slot = num_slots++;
      }
      fields.push_back(&f);
    }

    void add_enum(EnumD &) {}
    void add_message(MessageD &) {}
    void add_oneof(OneofD &o) { oneofs.push_back(&o); }
    void add_extension(FieldD &f) { fields.push_back(&f); }
  };

  template <typename FileD, typename MessageD, typename EnumD, typename FieldD>
  struct file_descriptor {
    explicit file_descriptor(const google::protobuf::FileDescriptorProto &) {}
    void add_enum(EnumD &) {}
    void add_message(MessageD &) {}
    void add_extension(FieldD &) {}
  };
};

using descriptor_pool_t = descriptor_pool<reflection_addons>;
using field_descriptor_t = descriptor_pool_t::field_descriptor_t;
using enum_descriptor_t = descriptor_pool_t::enum_descriptor_t;
using oneof_descriptor_t = descriptor_pool_t::oneof_descriptor_t;
using message_descriptor_t = descriptor_pool_t::message_descriptor_t;

template <typename T>
struct scalar_storage_base {
  T content_;
  alignas(8) uint64_t present_;
};

template <typename T>
struct repeated_storage_base {
  T *content_;
  alignas(8) uint64_t size_;
};

using bytes_storage_t = repeated_storage_base<const std::byte>;
using string_storage_t = repeated_storage_base<const char>;

union value_storage {
  scalar_storage_base<int64_t> of_int64;
  scalar_storage_base<uint64_t> of_uint64;
  scalar_storage_base<int32_t> of_int32;
  scalar_storage_base<uint32_t> of_uint32;
  scalar_storage_base<double> of_double;
  scalar_storage_base<float> of_float;
  scalar_storage_base<bool> of_bool;
  scalar_storage_base<value_storage *> of_message; ///< used for message and group types
  bytes_storage_t of_bytes;
  string_storage_t of_string;
  repeated_storage_base<int64_t> of_repeated_int64;
  repeated_storage_base<uint64_t> of_repeated_uint64;
  repeated_storage_base<int32_t> of_repeated_int32;
  repeated_storage_base<uint32_t> of_repeated_uint32;
  repeated_storage_base<double> of_repeated_double;
  repeated_storage_base<float> of_repeated_float;
  repeated_storage_base<bool> of_repeated_bool;
  repeated_storage_base<std::span<const std::byte>> of_repeated_bytes;
  repeated_storage_base<std::string_view> of_repeated_string;
  repeated_storage_base<value_storage> of_repeated_message;

  struct {
    value_storage *content_;
    uint64_t ordinal_;
  } of_oneof;
  value_storage() : of_int64{} {}
};

class field_cref {
  const field_descriptor_t &descriptor_;
  const value_storage &storage_;

public:
  field_cref(const field_descriptor_t &descriptor, const value_storage &storage)
      : descriptor_(descriptor), storage_(storage) {}

  field_cref(const field_cref &) = default;
  field_cref(field_cref &&) = default;
  ~field_cref() = default;

  field_kind_t field_kind() const { return descriptor_.field_kind; }

  const field_descriptor_t &descriptor() const { return descriptor_; }

  template <typename T>
  std::optional<T> to() const {
    if (T::field_kind == field_kind()) {
      return T(descriptor_, storage_);
    }
    return std::nullopt;
  }

  auto visit(auto &&v);
}; // class field_mref

class field_mref {
  const field_descriptor_t &descriptor_;
  value_storage &storage_;
  std::pmr::monotonic_buffer_resource &memory_resource_;

public:
  field_mref(const field_descriptor_t &descriptor, value_storage &storage, std::pmr::monotonic_buffer_resource &mr)
      : descriptor_(descriptor), storage_(storage), memory_resource_(mr) {}

  field_mref(const field_mref &) = default;
  field_mref(field_mref &&) = default;
  ~field_mref() = default;

  void reset() { storage_.of_int64.present_ = 0; }
  field_kind_t field_kind() const { return descriptor_.field_kind; }

  const field_descriptor_t &descriptor() const { return descriptor_; }

  template <typename T>
  std::optional<T> to() const {
    if (T::field_kind == field_kind()) {
      return T(descriptor_, storage_, memory_resource_);
    }
    return std::nullopt;
  }

  field_cref cref() const { return {descriptor_, storage_}; }
  operator field_cref() const { return cref(); }
  auto visit(auto &&v);
}; // class field_mref

template <typename T, field_kind_t Kind>
class scalar_field_cref {
  const field_descriptor_t &descriptor_;
  const scalar_storage_base<T> &storage_;

public:
  static constexpr field_kind_t field_kind = Kind;

  scalar_field_cref(const field_descriptor_t &descriptor, const scalar_storage_base<T> &storage)
      : descriptor_(descriptor), storage_(storage) {
    assert(descriptor.field_kind == field_kind);
  }

  scalar_field_cref(const field_descriptor_t &descriptor, const value_storage &storage)
      : scalar_field_cref(descriptor, reinterpret_cast<const scalar_storage_base<T> &>(storage)) {}

  scalar_field_cref(const scalar_field_cref &) = default;
  scalar_field_cref(scalar_field_cref &&) = default;
  ~scalar_field_cref() = default;

  bool has_value() const { return storage_.present_ != 0; }
  T value() const { return storage_.content_; }

  const field_descriptor_t &descriptor() const { return descriptor_; }
};

template <typename T, field_kind_t Kind>
class scalar_field_mref {
  const field_descriptor_t &descriptor_;
  scalar_storage_base<T> &storage_;

public:
  static constexpr field_kind_t field_kind = Kind;
  scalar_field_mref(const field_descriptor_t &descriptor, value_storage &storage, std::pmr::monotonic_buffer_resource &)
      : descriptor_(descriptor), storage_(reinterpret_cast<scalar_storage_base<T> &>(storage)) {
    assert(descriptor.field_kind == field_kind);
  }

  static void init_storage(const field_descriptor_t &descriptor, value_storage &storage) {
    scalar_storage_base<T> &storage_base = reinterpret_cast<scalar_storage_base<T> &>(storage);
    storage_base.content_ = std::get<T>(descriptor.default_value);
  }

  scalar_field_mref(const scalar_field_mref &) = default;
  scalar_field_mref(scalar_field_mref &&) = default;
  ~scalar_field_mref() = default;
  scalar_field_mref &operator=(T value) {
    storage_.content_ = value;
    storage_.present_ = 1;
    return *this;
  }

  scalar_field_cref<T, Kind> cref() const { return {descriptor_, storage_}; }
  operator scalar_field_cref<T, Kind>() const { return cref(); }

  bool has_value() const { return storage_.present_ != 0; }
  T &value() const { return storage_.content_; }
  void reset() {
    storage_.present_ = 0;
    storage_.content_ = std::get<T>(descriptor_.default_value);
  }

  T &emplace(T v) {
    storage_.content_ = v;
    storage_.present_ = 1;
    return storage_.content_;
  }

  const field_descriptor_t &descriptor() const { return descriptor_; }
};

class string_field_cref {
  const field_descriptor_t &descriptor_;
  const string_storage_t &storage_;

public:
  constexpr static field_kind_t field_kind = field_kind_t::KIND_STRING;
  string_field_cref(const field_descriptor_t &descriptor, const string_storage_t &storage)
      : descriptor_(descriptor), storage_(storage) {
    assert(descriptor.field_kind == field_kind);
  }
  string_field_cref(const field_descriptor_t &descriptor, const value_storage &storage)
      : string_field_cref(descriptor, storage.of_string) {}

  string_field_cref(const string_field_cref &) = default;
  string_field_cref(string_field_cref &&) = default;
  ~string_field_cref() = default;

  bool has_value() const { return storage_.size_ != 0; }
  std::size_t size() const { return storage_.size_ - 1; }

  std::string_view value() const {
    if (storage_.size_ == 0) {
      auto &default_value = std::get<std::string>(descriptor_.default_value);
      return default_value;
    }
    return {storage_.content_, storage_.size_ - 1};
  }

  const field_descriptor_t &descriptor() const { return descriptor_; }
};

class string_field_mref {
  const field_descriptor_t &descriptor_;
  string_storage_t &storage_;
  std::pmr::monotonic_buffer_resource &memory_resource_;

public:
  constexpr static field_kind_t field_kind = field_kind_t::KIND_STRING;
  string_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                    std::pmr::monotonic_buffer_resource &mr)
      : descriptor_(descriptor), storage_(storage.of_string), memory_resource_(mr) {
    assert(descriptor.field_kind == field_kind);
  }

  static void init_storage(const field_descriptor_t &, value_storage &storage) {
    string_storage_t &storage_base = storage.of_string;
    storage_base.content_ = nullptr;
    storage_base.size_ = 0;
  }

  string_field_mref(const string_field_mref &) = default;
  string_field_mref(string_field_mref &&) = default;
  ~string_field_mref() = default;

  string_field_mref &operator=(std::string_view v) {
    emplace(v);
    return *this;
  }

  string_field_cref cref() const { return string_field_cref{descriptor_, storage_}; }
  operator string_field_cref() const { return cref(); }

  bool has_value() const { return storage_.size_ != 0; }
  std::string_view value() const { return cref().value(); }

  std::string_view emplace(std::string_view v) {
    storage_.content_ = v.data();
    storage_.size_ = v.size() + 1;
    return {storage_.content_, storage_.size_};
  }

  void reset() {
    storage_.content_ = nullptr;
    storage_.size_ = 0;
  }

  const field_descriptor_t &descriptor() const { return descriptor_; }
};

class bytes_field_cref {
  const field_descriptor_t &descriptor_;
  const bytes_storage_t &storage_;

public:
  constexpr static field_kind_t field_kind = field_kind_t::KIND_BYTES;
  bytes_field_cref(const field_descriptor_t &descriptor, const bytes_storage_t &storage)
      : descriptor_(descriptor), storage_(storage) {
    assert(descriptor.field_kind == field_kind);
  }
  bytes_field_cref(const field_descriptor_t &descriptor, const value_storage &storage)
      : bytes_field_cref(descriptor, storage.of_bytes) {}

  bytes_field_cref(const bytes_field_cref &) = default;
  bytes_field_cref(bytes_field_cref &&) = default;
  ~bytes_field_cref() = default;

  bool has_value() const { return storage_.size_ != 0; }
  std::span<const std::byte> value() const {
    if (storage_.content_ == 0) {
      auto &default_value = std::get<std::vector<std::byte>>(descriptor_.default_value);
      return std::span<const std::byte>(default_value.data(), default_value.size());
    }
    return std::span<const std::byte>(storage_.content_, storage_.size_ - 1);
  }

  const field_descriptor_t &descriptor() const { return descriptor_; }
};

class bytes_field_mref {
  const field_descriptor_t &descriptor_;
  bytes_storage_t &storage_;
  std::pmr::monotonic_buffer_resource &memory_resource_;

public:
  constexpr static field_kind_t field_kind = field_kind_t::KIND_BYTES;
  bytes_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                   std::pmr::monotonic_buffer_resource &mr)
      : descriptor_(descriptor), storage_(storage.of_bytes), memory_resource_(mr) {
    assert(descriptor.field_kind == field_kind);
  }
  static void init_storage(const field_descriptor_t &, value_storage &storage) {
    bytes_storage_t &storage_base = storage.of_bytes;
    storage_base.content_ = nullptr;
    storage_base.size_ = 0;
  }
  bytes_field_mref(const bytes_field_mref &) = default;
  bytes_field_mref(bytes_field_mref &&) = default;
  ~bytes_field_mref() = default;
  bytes_field_mref &operator=(std::span<const std::byte> value) {
    emplace(value);
    return *this;
  }
  bytes_field_cref cref() const { return bytes_field_cref(descriptor_, storage_); }
  operator bytes_field_cref() const { return cref(); }

  bool has_value() const { return storage_.size_ != 0; }
  std::span<const std::byte> value() const { return cref().value(); }

  std::span<const std::byte> emplace(std::span<const std::byte> v) {
    storage_.content_ = v.data();
    storage_.size_ = v.size() + 1;
    return {storage_.content_, storage_.size_ - 1};
  }

  void reset() {
    storage_.content_ = nullptr;
    storage_.size_ = 0;
  }

  const field_descriptor_t &descriptor() const { return descriptor_; }
};

class enum_value_cref {
  const enum_descriptor_t &descriptor_;
  int32_t number_;

public:
  enum_value_cref(const enum_descriptor_t &descriptor, int32_t number) : descriptor_(descriptor), number_(number) {}
  enum_value_cref(const enum_value_cref &) = default;
  enum_value_cref(enum_value_cref &&) = default;
  ~enum_value_cref() = default;

  explicit operator int32_t() const { return number_; }

  int32_t number() const { return number_; }
  const char *name() const { return descriptor_.name_of(number_); }
};

class enum_value_mref {
  const enum_descriptor_t &descriptor_;
  int32_t &number_;

public:
  enum_value_mref(const enum_descriptor_t &descriptor, int32_t &number) : descriptor_(descriptor), number_(number) {}
  enum_value_mref(const enum_value_mref &) = default;
  enum_value_mref(enum_value_mref &&) = default;
  ~enum_value_mref() = default;

  enum_value_mref &operator=(int32_t number) {
    number_ = number;
    return *this;
  };

  const int32_t *number_by_name(const char *name) const { return descriptor_.value_of(name); }

  explicit operator int32_t() const { return number_; }
  int32_t number() const { return number_; }
  const char *name() const { return descriptor_.name_of(number_); }

  const enum_descriptor_t &descriptor() const { return descriptor_; }
};

class enum_field_cref {
  const field_descriptor_t &descriptor_;
  const scalar_storage_base<int32_t> &storage_;

  const enum_descriptor_t *enum_descriptor() const { return descriptor_.enum_field_type_descriptor(); }

public:
  constexpr static field_kind_t field_kind = field_kind_t::KIND_ENUM;
  enum_field_cref(const field_descriptor_t &descriptor, const scalar_storage_base<int32_t> &storage)
      : descriptor_(descriptor), storage_(storage) {
    assert(descriptor.field_kind == field_kind);
  }
  enum_field_cref(const field_descriptor_t &descriptor, const value_storage &storage)
      : enum_field_cref(descriptor, storage.of_int32) {}

  enum_field_cref(const enum_field_cref &) = default;
  enum_field_cref(enum_field_cref &&) = default;

  ~enum_field_cref() = default;

  bool has_value() const { return storage_.present_ != 0; }
  enum_value_cref value() const { return {*enum_descriptor(), storage_.content_}; }

  const field_descriptor_t &descriptor() const { return descriptor_; }
};

class enum_field_mref {
  const field_descriptor_t &descriptor_;
  scalar_storage_base<int32_t> &storage_;

public:
  constexpr static field_kind_t field_kind = field_kind_t::KIND_ENUM;
  enum_field_mref(const field_descriptor_t &descriptor, value_storage &storage, std::pmr::monotonic_buffer_resource &)
      : descriptor_(descriptor), storage_(storage.of_int32) {
    assert(descriptor.field_kind == field_kind);
  }

  static void init_storage(const field_descriptor_t &descriptor, value_storage &storage) {
    storage.of_int32.content_ = std::get<int32_t>(descriptor.default_value);
  }

  enum_field_mref(const enum_field_mref &) = default;
  enum_field_mref(enum_field_mref &&) = default;
  ~enum_field_mref() = default;
  enum_field_mref &operator=(int32_t value) {
    storage_.content_ = value;
    storage_.present_ = 1;
    return *this;
  }

  enum_field_cref cref() const { return enum_field_cref{descriptor_, storage_}; }
  operator enum_field_cref() const { return cref(); }

  bool has_value() const { return storage_.present_ != 0; }
  enum_value_mref value() const { return {*descriptor_.enum_field_type_descriptor(), storage_.content_}; }

  void reset() {
    storage_.present_ = 0;
    storage_.content_ = std::get<int32_t>(descriptor_.default_value);
  }
  const field_descriptor_t &descriptor() const { return descriptor_; }
};

template <typename T, field_kind_t Kind>
class repeated_scalar_field_cref : public std::ranges::view_interface<repeated_scalar_field_cref<T, Kind>> {
  const field_descriptor_t &descriptor_;
  const repeated_storage_base<T> &storage_;

public:
  static constexpr field_kind_t field_kind = Kind;
  repeated_scalar_field_cref(const field_descriptor_t &descriptor, const repeated_storage_base<T> &storage)
      : descriptor_(descriptor), storage_(storage) {
    assert(descriptor.field_kind == field_kind);
  }
  repeated_scalar_field_cref(const field_descriptor_t &descriptor, const value_storage &storage)
      : repeated_scalar_field_cref(descriptor, reinterpret_cast<const repeated_storage_base<T> &>(storage)) {}

  repeated_scalar_field_cref(const repeated_scalar_field_cref &) = default;
  repeated_scalar_field_cref(repeated_scalar_field_cref &&) = default;
  ~repeated_scalar_field_cref() = default;

  std::size_t size() const { return storage_.size_; }
  const T *begin() { return storage_.content_; }
  const T *end() { return storage_.content_ + storage_.size_; }

  const field_descriptor_t &descriptor() const { return descriptor_; }
};

template <typename T, field_kind_t Kind>
class repeated_scalar_field_mref : public std::ranges::view_interface<repeated_scalar_field_mref<T, Kind>> {
  const field_descriptor_t &descriptor_;
  repeated_storage_base<T> &storage_;
  std::pmr::monotonic_buffer_resource &memory_resource_;

public:
  static constexpr field_kind_t field_kind = Kind;
  repeated_scalar_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                             std::pmr::monotonic_buffer_resource &mr)
      : descriptor_(descriptor), storage_(reinterpret_cast<repeated_storage_base<T> &>(storage)), memory_resource_(mr) {
    assert(descriptor.field_kind == field_kind);
  }

  static void init_storage(const field_descriptor_t &, value_storage &storage) {
    repeated_storage_base<T> &storage_base = reinterpret_cast<repeated_storage_base<T> &>(storage);
    storage_base.content_ = nullptr;
    storage_base.size_ = 0;
  }

  repeated_scalar_field_mref(const repeated_scalar_field_mref &) = default;
  repeated_scalar_field_mref(repeated_scalar_field_mref &&) = default;
  ~repeated_scalar_field_mref() = default;

  repeated_scalar_field_cref<T, Kind> cref() const {
    return repeated_scalar_field_cref<T, Kind>{descriptor_, storage_};
  }
  operator repeated_scalar_field_cref<T, Kind>() const { return cref(); }

  void resize(std::size_t n) {
    if (storage_.size_ < n) {
      auto new_data = static_cast<T *>(memory_resource_.allocate(n * sizeof(T), alignof(T)));
      std::uninitialized_default_construct(new_data, new_data + n);
      storage_.content_ = new_data;
    }
    storage_.size_ = n;
  }

  std::size_t size() const { return storage_.size_; }
  T *begin() { return storage_.content_; }
  T *end() { return storage_.content_ + storage_.size_; }

  void reset() {
    storage_.content_ = nullptr;
    storage_.size_ = 0;
  }
  const field_descriptor_t &descriptor() const { return descriptor_; }
};

template <typename Field>
class repeated_field_iterator {
  const Field *field_ = nullptr;
  std::size_t index_ = 0;

public:
  using iterator_category = std::random_access_iterator_tag;
  using value_type = Field::reference;
  using difference_type = std::ptrdiff_t;
  using reference = Field::reference;
  using pointer = void;
  repeated_field_iterator(const Field *field, std::size_t index) : field_(field), index_(index) {}
  repeated_field_iterator(const repeated_field_iterator &) = default;
  repeated_field_iterator(repeated_field_iterator &&) = default;
  repeated_field_iterator &operator=(const repeated_field_iterator &) = default;
  repeated_field_iterator &operator=(repeated_field_iterator &&) = default;
  ~repeated_field_iterator() = default;
  repeated_field_iterator &operator++() {
    ++index_;
    return *this;
  }
  repeated_field_iterator operator++(int) {
    repeated_field_iterator tmp = *this;
    ++(*this);
    return tmp;
  }
  repeated_field_iterator &operator--() {
    --index_;
    return *this;
  }
  repeated_field_iterator operator--(int) {
    repeated_field_iterator tmp = *this;
    --(*this);
    return tmp;
  }
  repeated_field_iterator &operator+=(std::ptrdiff_t n) {
    index_ += n;
    return *this;
  }
  repeated_field_iterator &operator-=(std::ptrdiff_t n) {
    index_ -= n;
    return *this;
  }
  repeated_field_iterator operator+(std::ptrdiff_t n) const {
    repeated_field_iterator tmp = *this;
    tmp += n;
    return tmp;
  }
  repeated_field_iterator operator-(std::ptrdiff_t n) const {
    repeated_field_iterator tmp = *this;
    tmp -= n;
    return tmp;
  }
  std::ptrdiff_t operator-(const repeated_field_iterator &other) const { return index_ - other.index_; }

  std::strong_ordering operator<=>(const repeated_field_iterator &other) const {
    assert(field_ == other.field_);
    return index_ <=> other.index_;
  }

  reference operator*() const { return (*field_)[index_]; }
};

class repeated_enum_field_cref : public std::ranges::view_interface<repeated_enum_field_cref> {
  const field_descriptor_t &descriptor_;
  const repeated_storage_base<int32_t> &storage_;

public:
  using reference = enum_value_cref;
  using iterator = repeated_field_iterator<repeated_enum_field_cref>;
  static constexpr field_kind_t field_kind = field_kind_t::KIND_REPEATED_ENUM;
  repeated_enum_field_cref(const field_descriptor_t &descriptor, const repeated_storage_base<int32_t> &storage)
      : descriptor_(descriptor), storage_(storage) {
    assert(descriptor.field_kind == field_kind);
  }

  repeated_enum_field_cref(const field_descriptor_t &descriptor, const value_storage &storage)
      : repeated_enum_field_cref(descriptor, storage.of_repeated_int32) {}

  repeated_enum_field_cref(const repeated_enum_field_cref &) = default;
  repeated_enum_field_cref(repeated_enum_field_cref &&) = default;
  ~repeated_enum_field_cref() = default;

  std::size_t size() const { return storage_.size_; }
  iterator begin() const { return {this, 0}; }
  iterator end() const { return {this, storage_.size_}; }
  reference operator[](std::size_t index) const {
    return {*descriptor_.enum_field_type_descriptor(), storage_.content_[index]};
  }

  const field_descriptor_t &descriptor() const { return descriptor_; }
};

class repeated_enum_field_mref : public std::ranges::view_interface<repeated_enum_field_mref> {
  const field_descriptor_t &descriptor_;
  repeated_storage_base<int32_t> &storage_;
  std::pmr::monotonic_buffer_resource &memory_resource_;

  const enum_descriptor_t *enum_descriptor() const { return descriptor_.enum_field_type_descriptor(); }

public:
  static constexpr field_kind_t field_kind = field_kind_t::KIND_REPEATED_ENUM;
  using reference = enum_value_mref;
  using iterator = repeated_field_iterator<repeated_enum_field_mref>;

  repeated_enum_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                           std::pmr::monotonic_buffer_resource &mr)
      : descriptor_(descriptor), storage_(reinterpret_cast<repeated_storage_base<int32_t> &>(storage)),
        memory_resource_(mr) {
    assert(descriptor.field_kind == field_kind);
  }

  static void init_storage(const field_descriptor_t &, value_storage &storage) {
    repeated_storage_base<int32_t> &storage_base = storage.of_repeated_int32;
    storage_base.content_ = nullptr;
    storage_base.size_ = 0;
  }

  repeated_enum_field_mref(const repeated_enum_field_mref &) = default;
  repeated_enum_field_mref(repeated_enum_field_mref &&) = default;
  ~repeated_enum_field_mref() = default;

  repeated_enum_field_cref cref() const { return repeated_enum_field_cref{descriptor_, storage_}; }
  operator repeated_enum_field_cref() const { return cref(); }

  void resize(std::size_t n) {
    if (storage_.size_ < n) {
      auto new_data = static_cast<int32_t *>(memory_resource_.allocate(n * sizeof(int32_t), alignof(int32_t)));
      std::uninitialized_default_construct(new_data, new_data + n);
      storage_.content_ = new_data;
    }
    storage_.size_ = n;
  }

  std::size_t size() const { return storage_.size_; }
  iterator begin() { return {this, 0}; }
  iterator end() { return {this, storage_.size_}; }
  reference operator[](std::size_t index) const { return {*enum_descriptor(), storage_.content_[index]}; }

  void reset() {
    storage_.content_ = nullptr;
    storage_.size_ = 0;
  }
  const field_descriptor_t &descriptor() const { return descriptor_; }
};

class oneof_field_mref {
  const oneof_descriptor_t &descriptor_;
  value_storage &storage_;
  std::pmr::monotonic_buffer_resource &memory_resource_;

public:
  oneof_field_mref(const oneof_descriptor_t &descriptor, value_storage &storage,
                   std::pmr::monotonic_buffer_resource &memory_resource)
      : descriptor_(descriptor), storage_(storage), memory_resource_(memory_resource) {}

  oneof_field_mref(const oneof_field_mref &) = default;
  oneof_field_mref(oneof_field_mref &&) = default;
  ~oneof_field_mref() = default;

  std::optional<field_mref> mref_by_name(std::string_view name);
  std::optional<field_mref> mref_by_number(uint32_t number);

  auto visit(auto &&visitor) const {
    if (storage_.of_oneof.ordinal_ > 0) {
      const auto *desc = descriptor_.fields[storage_.of_oneof.ordinal_ - 1];
      field_mref{*desc, *storage_.of_oneof.content_, memory_resource_}.visit(visitor);
    }
  }
};

class message_value_cref {
  const message_descriptor_t &descriptor_;
  const value_storage *storage_;
  std::size_t num_slots() const { return descriptor_.num_slots; }

  const value_storage &storage_for(const field_descriptor_t &desc) const {
    return storage_[desc.storage_slot * sizeof(value_storage)];
  }

public:
  message_value_cref(const message_descriptor_t &descriptor, const value_storage *storage)
      : descriptor_(descriptor), storage_(storage) {}
  message_value_cref(const message_value_cref &) = default;
  message_value_cref(message_value_cref &&) = default;
  ~message_value_cref() = default;
  const message_descriptor_t &descriptor() const { return descriptor_; }

  field_cref field_cref_for(const field_descriptor_t &desc) const {
    auto &storage = storage_for(desc);
    if (desc.oneof_ordinal && storage.of_oneof.ordinal_ && storage.of_oneof.content_) {
      return field_cref(desc, *storage.of_oneof.content_);
    } else {
      return field_cref(desc, storage);
    }
  }

  std::optional<field_cref> field_cref_by_name(std::string_view name) const {
    auto it =
        std::ranges::find_if(descriptor_.fields, [&name](const auto &field) { return field->proto().name == name; });
    if (it != descriptor_.fields.end()) {
      return field_cref_for(**it);
    }
    return std::nullopt;
  }

  std::optional<field_cref> field_cref_by_number(int32_t number) const {
    auto it =
        std::ranges::find_if(descriptor_.fields, [number](const auto &field) { return field->proto().number == number; });
    if (it != descriptor_.fields.end()) {
      return field_cref_for(**it);
    }
    return std::nullopt;
  }

  void for_each_field(auto &&unary_function) const {
    for (auto *desc : descriptor_.fields) {
      auto &storage = storage_for(*desc);
      if (!storage.of_uint64.present_)
        continue;

      unary_function(field_cref_for(*desc));
    }
  }
};

class message_value_mref {
  const message_descriptor_t &descriptor_;
  value_storage *storage_;
  std::pmr::monotonic_buffer_resource &memory_resource_;

  std::size_t num_slots() const { return descriptor_.num_slots; }

  value_storage &storage_for(const field_descriptor_t &desc) const {
    return storage_[desc.storage_slot * sizeof(value_storage)];
  }

  static void init_field_storage(const field_descriptor_t &descriptor, value_storage &storage);

public:
  message_value_mref(const message_descriptor_t &descriptor, value_storage *storage,
                     std::pmr::monotonic_buffer_resource &memory_resource)
      : descriptor_(descriptor), storage_(storage), memory_resource_(memory_resource) {}
  message_value_mref(const message_value_mref &) = default;
  message_value_mref(message_value_mref &&) = default;
  ~message_value_mref() = default;
  const message_descriptor_t &descriptor() const { return descriptor_; }

  message_value_cref cref() const { return {descriptor_, storage_}; }
  operator message_value_cref() const { return cref(); }

  void reset() const {
    for (const auto *field_descriptor : descriptor_.fields) {
      auto &storage = storage_for(*field_descriptor);
      if (field_descriptor->oneof_ordinal) {
        storage.of_oneof.content_ = nullptr;
        storage.of_oneof.ordinal_ = 0;
      } else {
        init_field_storage(*field_descriptor, storage);
      }
    }
  }

  field_mref field_mref_for(const field_descriptor_t &desc) const {
    auto &storage = storage_for(desc);
    if (desc.oneof_ordinal && desc.oneof_ordinal != storage.of_oneof.ordinal_) {
      if (storage.of_oneof.content_ == nullptr) {
        storage.of_oneof.content_ =
            static_cast<value_storage *>(memory_resource_.allocate(sizeof(value_storage), alignof(value_storage)));
      }
      storage.of_oneof.ordinal_ = desc.oneof_ordinal;
      init_field_storage(desc, *storage.of_oneof.content_);
    }
    return field_mref(desc, storage, memory_resource_);
  }

  std::optional<field_cref> field_mref_by_name(std::string_view name) const {
    auto it =
        std::ranges::find_if(descriptor_.fields, [&name](const auto &field) { return field->proto().name == name; });
    if (it != descriptor_.fields.end()) {
      return field_mref_for(**it);
    }
    return std::nullopt;
  }

  std::optional<field_cref> field_mref_by_number(int32_t number) const {
    auto it =
        std::ranges::find_if(descriptor_.fields, [number](const auto &field) { return field->proto().number == number; });
    if (it != descriptor_.fields.end()) {
      return field_mref_for(**it);
    }
    return std::nullopt;
  }

  void for_each_field(auto &&unary_function) const {
    for (auto *desc : descriptor_.fields) {
      auto &storage = storage_for(*desc);
      if (desc->oneof_ordinal) {
        if (desc->oneof_ordinal == storage.of_oneof.ordinal_ ||
            (desc->oneof_ordinal == 1 && storage.of_oneof.ordinal_ == 0)) {
          auto *oneof_desc = descriptor_.oneofs[desc->proto().oneof_index];
          unary_function(oneof_field_mref{*oneof_desc, storage, memory_resource_});
          return;
        }
      }
      unary_function(field_mref(*desc, storage, memory_resource_));
    }
  }
};

class message_field_cref {
  const field_descriptor_t &descriptor_;
  const scalar_storage_base<value_storage *> &storage_;
  std::size_t num_slots() const { return descriptor_.message_field_type_descriptor()->num_slots; }

public:
  static constexpr field_kind_t field_kind = field_kind_t::KIND_MESSAGE;
  message_field_cref(const field_descriptor_t &descriptor, const scalar_storage_base<value_storage *> &storage)
      : descriptor_(descriptor), storage_(storage) {
    assert(descriptor.field_kind == field_kind);
  }

  message_field_cref(const field_descriptor_t &descriptor, const value_storage &storage)
      : message_field_cref(descriptor, storage.of_message) {}

  message_field_cref(const message_field_cref &) = default;
  message_field_cref(message_field_cref &&) = default;
  ~message_field_cref() = default;

  bool has_value() const { return storage_.present_ != 0; }
  const field_descriptor_t &descriptor() const { return descriptor_; }
  message_value_cref value() const { return {*descriptor_.message_field_type_descriptor(), storage_.content_}; }
};

class message_field_mref {
  const field_descriptor_t &descriptor_;
  scalar_storage_base<value_storage *> &storage_;
  std::pmr::monotonic_buffer_resource &memory_resource_;
  std::size_t num_slots() const { return descriptor_.message_field_type_descriptor()->num_slots; }

public:
  static constexpr field_kind_t field_kind = field_kind_t::KIND_MESSAGE;
  message_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                     std::pmr::monotonic_buffer_resource &mr)
      : descriptor_(descriptor), storage_(storage.of_message), memory_resource_(mr) {
    assert(descriptor.field_kind == field_kind);
  }

  static void init_storage(const field_descriptor_t &, value_storage &storage) {
    scalar_storage_base<value_storage *> &storage_base = storage.of_message;
    storage_base.content_ = nullptr;
    storage_base.present_ = 0;
  }

  message_field_mref(const message_field_mref &) = default;
  message_field_mref(message_field_mref &&) = default;
  ~message_field_mref() = default;

  message_value_mref emplace() {
    if (storage_.content_ == nullptr) {
      storage_.content_ = static_cast<value_storage *>(
          memory_resource_.allocate(sizeof(value_storage) * num_slots(), alignof(value_storage)));
    }
    storage_.present_ = 1;
    auto result = value();
    result.reset();
    return result;
  }
  bool has_value() const { return storage_.present_ != 0; }
  void reset() { storage_.present_ = 0; }
  const field_descriptor_t &descriptor() const { return descriptor_; }
  message_value_mref value() const {
    return {*descriptor_.message_field_type_descriptor(), storage_.content_, memory_resource_};
  }
};

class repeated_message_field_cref : std::ranges::view_interface<repeated_message_field_cref> {
  const field_descriptor_t &descriptor_;
  const repeated_storage_base<value_storage> &storage_;
  std::size_t num_slots() const { return descriptor_.message_field_type_descriptor()->num_slots; }

public:
  static constexpr field_kind_t field_kind = field_kind_t::KIND_REPEATED_MESSAGE;
  using reference = message_value_cref;
  using iterator = repeated_field_iterator<repeated_message_field_cref>;
  repeated_message_field_cref(const field_descriptor_t &descriptor, const repeated_storage_base<value_storage> &storage)
      : descriptor_(descriptor), storage_(storage) {
    assert(descriptor.field_kind == field_kind);
  }

  repeated_message_field_cref(const field_descriptor_t &descriptor, const value_storage &storage)
      : repeated_message_field_cref(descriptor, storage.of_repeated_message) {}

  repeated_message_field_cref(const repeated_message_field_cref &) = default;
  repeated_message_field_cref(repeated_message_field_cref &&) = default;
  ~repeated_message_field_cref() = default;

  std::size_t size() const { return storage_.size_; }
  message_value_cref operator[](std::size_t index) const {
    assert(index < size());
    return message_value_cref(*descriptor_.message_field_type_descriptor(), &storage_.content_[index * num_slots()]);
  }
  iterator begin() const { return {this, 0}; }
  iterator end() const { return {this, size()}; }

  const field_descriptor_t &descriptor() const { return descriptor_; }
};

class repeated_message_field_mref : std::ranges::view_interface<repeated_message_field_mref> {
  const field_descriptor_t &descriptor_;
  repeated_storage_base<value_storage> &storage_;
  std::pmr::monotonic_buffer_resource &memory_resource_;

  std::size_t num_slots() const { return descriptor_.message_field_type_descriptor()->num_slots; }

public:
  static constexpr field_kind_t field_kind = field_kind_t::KIND_REPEATED_MESSAGE;
  using reference = message_value_mref;
  using iterator = repeated_field_iterator<repeated_message_field_mref>;
  repeated_message_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                              std::pmr::monotonic_buffer_resource &mr)
      : descriptor_(descriptor), storage_(storage.of_repeated_message), memory_resource_(mr) {
    assert(descriptor.field_kind == field_kind);
  }

  static void init_storage(const field_descriptor_t &, value_storage &storage) {
    repeated_storage_base<value_storage> &storage_base = storage.of_repeated_message;
    storage_base.content_ = nullptr;
    storage_base.size_ = 0;
  }

  repeated_message_field_mref(const repeated_message_field_mref &) = default;
  repeated_message_field_mref(repeated_message_field_mref &&) = default;
  ~repeated_message_field_mref() = default;

  repeated_message_field_cref cref() const { return {descriptor_, storage_}; }
  operator repeated_message_field_cref() const { return cref(); }

  void resize(std::size_t n) {
    auto old_size = size();
    if (old_size < n) {
      auto new_data = static_cast<value_storage *>(
          memory_resource_.allocate(n * num_slots() * sizeof(value_storage), alignof(value_storage)));
      std::ranges::copy(std::span{storage_.content_, storage_.size_}, new_data);
      storage_.content_ = new_data;
      storage_.size_ = n;
      for (std::size_t i = old_size; i < size(); ++i) {
        (*this)[i].reset();
      }
    } else if (old_size > n) {
      storage_.size_ = n;
    }
  }

  std::size_t size() const { return storage_.size_; }
  message_value_mref operator[](std::size_t index) const {
    assert(index < size());
    return message_value_mref(*descriptor_.message_field_type_descriptor(), &storage_.content_[index * num_slots()],
                              memory_resource_);
  }
  iterator begin() const { return {this, 0}; }
  iterator end() const { return {this, size()}; }

  void reset() { storage_.size_ = 0; }
  const field_descriptor_t &descriptor() const { return descriptor_; }
};

using double_field_cref = scalar_field_cref<double, KIND_DOUBLE>;
using float_field_cref = scalar_field_cref<float, KIND_FLOAT>;
using int64_field_cref = scalar_field_cref<int64_t, KIND_INT64>;
using uint64_field_cref = scalar_field_cref<uint64_t, KIND_UINT64>;
using int32_field_cref = scalar_field_cref<int32_t, KIND_INT32>;
using uint32_field_cref = scalar_field_cref<uint32_t, KIND_UINT32>;
using bool_field_cref = scalar_field_cref<bool, KIND_BOOL>;
using repeated_double_field_cref = repeated_scalar_field_cref<double, KIND_REPEATED_DOUBLE>;
using repeated_float_field_cref = repeated_scalar_field_cref<float, KIND_REPEATED_FLOAT>;
using repeated_int64_field_cref = repeated_scalar_field_cref<int64_t, KIND_REPEATED_INT64>;
using repeated_uint64_field_cref = repeated_scalar_field_cref<uint64_t, KIND_REPEATED_UINT64>;
using repeated_int32_field_cref = repeated_scalar_field_cref<int32_t, KIND_REPEATED_INT32>;
using repeated_uint32_field_cref = repeated_scalar_field_cref<uint32_t, KIND_REPEATED_UINT32>;
using repeated_bool_field_cref = repeated_scalar_field_cref<bool, KIND_REPEATED_BOOL>;
using repeated_string_field_cref = repeated_scalar_field_cref<std::string_view, KIND_REPEATED_STRING>;
using repeated_bytes_field_cref = repeated_scalar_field_cref<std::span<const std::byte>, KIND_REPEATED_BYTES>;

using double_field_mref = scalar_field_mref<double, KIND_DOUBLE>;
using float_field_mref = scalar_field_mref<float, KIND_FLOAT>;
using int64_field_mref = scalar_field_mref<int64_t, KIND_INT64>;
using uint64_field_mref = scalar_field_mref<uint64_t, KIND_UINT64>;
using int32_field_mref = scalar_field_mref<int32_t, KIND_INT32>;
using uint32_field_mref = scalar_field_mref<uint32_t, KIND_UINT32>;
using bool_field_mref = scalar_field_mref<bool, KIND_BOOL>;
using repeated_double_field_mref = repeated_scalar_field_mref<double, KIND_REPEATED_DOUBLE>;
using repeated_float_field_mref = repeated_scalar_field_mref<float, KIND_REPEATED_FLOAT>;
using repeated_int64_field_mref = repeated_scalar_field_mref<int64_t, KIND_REPEATED_INT64>;
using repeated_uint64_field_mref = repeated_scalar_field_mref<uint64_t, KIND_REPEATED_UINT64>;
using repeated_int32_field_mref = repeated_scalar_field_mref<int32_t, KIND_REPEATED_INT32>;
using repeated_uint32_field_mref = repeated_scalar_field_mref<uint32_t, KIND_REPEATED_UINT32>;
using repeated_bool_field_mref = repeated_scalar_field_mref<bool, KIND_REPEATED_BOOL>;
using repeated_string_field_mref = repeated_scalar_field_mref<std::string_view, KIND_REPEATED_STRING>;
using repeated_bytes_field_mref = repeated_scalar_field_mref<std::span<std::byte>, KIND_REPEATED_BYTES>;

inline void message_value_mref::init_field_storage(const field_descriptor_t &descriptor, value_storage &storage) {
  using init_storage_func = void (*)(const field_descriptor_t &, value_storage &);
  static init_storage_func init_storage_funcs[] = {&double_field_mref::init_storage,
                                                   &float_field_mref::init_storage,
                                                   &int64_field_mref::init_storage,
                                                   &uint64_field_mref::init_storage,
                                                   &int32_field_mref::init_storage,
                                                   &uint32_field_mref::init_storage,
                                                   &bool_field_mref::init_storage,
                                                   &string_field_mref::init_storage,
                                                   &bytes_field_mref::init_storage,
                                                   &enum_field_mref::init_storage,
                                                   &message_field_mref::init_storage,
                                                   &repeated_double_field_mref::init_storage,
                                                   &repeated_float_field_mref::init_storage,
                                                   &repeated_int64_field_mref::init_storage,
                                                   &repeated_uint64_field_mref::init_storage,
                                                   &repeated_int32_field_mref::init_storage,
                                                   &repeated_uint32_field_mref::init_storage,
                                                   &repeated_bool_field_mref::init_storage,
                                                   &repeated_string_field_mref::init_storage,
                                                   &repeated_bytes_field_mref::init_storage,
                                                   &repeated_enum_field_mref::init_storage,
                                                   &repeated_message_field_mref::init_storage};
  init_storage_funcs[descriptor.field_kind](descriptor, storage);
}

inline auto field_cref::visit(auto &&visitor) {
  switch (descriptor_.field_kind) {
  case KIND_DOUBLE:
    return visitor(double_field_cref{descriptor_, storage_});
  case KIND_FLOAT:
    return visitor(float_field_cref{descriptor_, storage_});
  case KIND_INT64:
    return visitor(int64_field_cref{descriptor_, storage_});
  case KIND_UINT64:
    return visitor(uint64_field_cref{descriptor_, storage_});
  case KIND_INT32:
    return visitor(int32_field_cref{descriptor_, storage_});
  case KIND_UINT32:
    return visitor(uint32_field_cref{descriptor_, storage_});
  case KIND_BOOL:
    return visitor(bool_field_cref{descriptor_, storage_});
  case KIND_STRING:
    return visitor(string_field_cref{descriptor_, storage_});
  case KIND_BYTES:
    return visitor(bytes_field_cref{descriptor_, storage_});
  case KIND_ENUM:
    return visitor(enum_field_cref{descriptor_, storage_});
  case KIND_MESSAGE:
    return visitor(message_field_cref{descriptor_, storage_});
  case KIND_REPEATED_DOUBLE:
    return visitor(repeated_double_field_cref{descriptor_, storage_});
  case KIND_REPEATED_FLOAT:
    return visitor(repeated_float_field_cref{descriptor_, storage_});
  case KIND_REPEATED_INT64:
    return visitor(repeated_int64_field_cref{descriptor_, storage_});
  case KIND_REPEATED_UINT64:
    return visitor(repeated_uint64_field_cref{descriptor_, storage_});
  case KIND_REPEATED_INT32:
    return visitor(repeated_int32_field_cref{descriptor_, storage_});
  case KIND_REPEATED_UINT32:
    return visitor(repeated_uint32_field_cref{descriptor_, storage_});
  case KIND_REPEATED_BOOL:
    return visitor(repeated_bool_field_cref{descriptor_, storage_});
  case KIND_REPEATED_STRING:
    return visitor(repeated_string_field_cref{descriptor_, storage_});
  case KIND_REPEATED_BYTES:
    return visitor(repeated_bytes_field_cref{descriptor_, storage_});
  case KIND_REPEATED_ENUM:
    return visitor(repeated_enum_field_cref{descriptor_, storage_});
  case KIND_REPEATED_MESSAGE:
    return visitor(repeated_message_field_cref{descriptor_, storage_});
  }
}

inline auto field_mref::visit(auto &&visitor) {
  switch (descriptor_.field_kind) {
  case KIND_DOUBLE:
    return visitor(double_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_FLOAT:
    return visitor(float_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_INT64:
    return visitor(int64_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_UINT64:
    return visitor(uint64_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_INT32:
    return visitor(int32_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_UINT32:
    return visitor(uint32_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_BOOL:
    return visitor(bool_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_STRING:
    return visitor(string_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_BYTES:
    return visitor(bytes_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_ENUM:
    return visitor(enum_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_MESSAGE:
    return visitor(message_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_REPEATED_DOUBLE:
    return visitor(repeated_double_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_REPEATED_FLOAT:
    return visitor(repeated_float_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_REPEATED_INT64:
    return visitor(repeated_int64_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_REPEATED_UINT64:
    return visitor(repeated_uint64_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_REPEATED_INT32:
    return visitor(repeated_int32_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_REPEATED_UINT32:
    return visitor(repeated_uint32_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_REPEATED_BOOL:
    return visitor(repeated_bool_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_REPEATED_STRING:
    return visitor(repeated_string_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_REPEATED_BYTES:
    return visitor(repeated_bytes_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_REPEATED_ENUM:
    return visitor(repeated_enum_field_mref{descriptor_, storage_, memory_resource_});
  case KIND_REPEATED_MESSAGE:
    return visitor(repeated_message_field_mref{descriptor_, storage_, memory_resource_});
  }
}

class dynamic_serializer {
  descriptor_pool_t pool_;

public:
  explicit dynamic_serializer(const google::protobuf::FileDescriptorSet &set) : pool_(set.file) {}

  message_value_mref create_message(std::string_view name, std::pmr::monotonic_buffer_resource &memory_resource);
};

} // namespace hpp::proto::reflection