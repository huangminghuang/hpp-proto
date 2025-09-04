#pragma once
#include <compare>
#include <utility>
#include <variant>

#include <hpp_proto/descriptor_pool.hpp>
#include <hpp_proto/pb_serializer.hpp>
namespace hpp::proto {
enum field_kind_t : uint8_t {
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
    using type = void;
    std::variant<bool, std::string, int32_t, uint32_t, int64_t, uint64_t, double, float, std::vector<std::byte>>
        default_value;
    field_kind_t field_kind = KIND_DOUBLE;
    /// @brief slot represents the index to the field memory storage of a message; all non-oneof fields use different
    /// slot, fields of the same oneof type share the same slot.
    uint32_t storage_slot = 0;
    /// @brief for oneof field, this value is the order among the same oneof field counting from 1; otherwise, it is
    /// always 1 for singular field and 0 for repeated field
    uint16_t oneof_ordinal = 0;
    field_descriptor(const google::protobuf::FieldDescriptorProto &proto, const std::string &) {
      set_kind_and_default_value(proto);
    }

    void set_kind_and_default_value(const google::protobuf::FieldDescriptorProto &proto) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      using namespace std::string_literals;
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

    [[nodiscard]] const uint32_t *value_of(const std::string_view name) const {
      const auto &proto = static_cast<const EnumD *>(this)->proto();
      for (const auto &ev : proto.value) {
        if (ev.name == name) {
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          return reinterpret_cast<const uint32_t *>(&ev.number);
        }
      }
      return nullptr;
    }

    [[nodiscard]] const char *name_of(uint32_t value) const {
      const auto &proto = static_cast<const EnumD *>(this)->proto();
      for (const auto &ev : proto.value) {
        if (static_cast<uint32_t>(ev.number) == value) {
          return ev.name.c_str();
        }
      }
      return nullptr;
    }
  };

  template <typename OneofD, typename FieldD>
  struct oneof_descriptor {
    explicit oneof_descriptor(const google::protobuf::OneofDescriptorProto &) {}
    [[nodiscard]] uint32_t storage_slot() const {
      return static_cast<const OneofD *>(this)->fields().front().storage_slot;
    }
  };

  template <typename MessageD, typename EnumD, typename OneofD, typename FieldD>
  struct message_descriptor {
    uint32_t num_slots = 0;
    explicit message_descriptor(const google::protobuf::DescriptorProto &) {}
  };

  template <typename FileD, typename MessageD, typename EnumD, typename FieldD>
  struct file_descriptor {
    explicit file_descriptor(const google::protobuf::FileDescriptorProto &) {}
  };
};

using reflection_descriptor_pool_base = descriptor_pool<reflection_addons>;

struct reflection_descriptor_pool : descriptor_pool<reflection_addons> {
  explicit reflection_descriptor_pool(google::protobuf::FileDescriptorSet &&proto_files)
      : descriptor_pool<reflection_addons>(std::move(proto_files)) {
    for (auto &message : this->messages()) {
      hpp::proto::optional<std::int32_t> prev_oneof_index;
      uint16_t oneof_ordinal = 1;
      uint32_t cur_slot = UINT32_MAX;
      for (auto &f : message.fields()) {
        if (f.proto().oneof_index.has_value()) {
          if (f.proto().oneof_index != prev_oneof_index) {
            f.storage_slot = ++cur_slot;
          } else {
            f.storage_slot = cur_slot;
          }
          f.oneof_ordinal = ++oneof_ordinal;
        } else {
          f.storage_slot = ++cur_slot;
          f.oneof_ordinal = f.is_repeated() ? 0 : 1;
          oneof_ordinal = 1;
        }
        prev_oneof_index = f.proto().oneof_index;
      }
      message.num_slots = cur_slot + 1;
    }
  }
};

using field_descriptor_t = reflection_descriptor_pool::field_descriptor_t;
using enum_descriptor_t = reflection_descriptor_pool::enum_descriptor_t;
using oneof_descriptor_t = reflection_descriptor_pool::oneof_descriptor_t;
using message_descriptor_t = reflection_descriptor_pool::message_descriptor_t;

template <typename T>
struct scalar_storage_base {
  T content;
  alignas(8) uint32_t size; // only used for string and bytes
  uint32_t selection; // 0 means no value; otherwise it means the selection index in oneof or 1 for non-oneof fields
};

template <typename T>
struct repeated_storage_base {
  T *content;
  alignas(8) uint32_t capacity;
  uint32_t size;
};

using bytes_storage_t = scalar_storage_base<const std::byte *>;
using string_storage_t = scalar_storage_base<const char *>;

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

  value_storage() : of_int64{0ULL, 0U, 0U} {}

  [[nodiscard]] bool has_value() const noexcept { return of_repeated_int64.size != 0; }
  void reset() noexcept { of_repeated_int64.size = 0; }
};

class field_cref {
  const field_descriptor_t *descriptor_;
  const value_storage *storage_;

public:
  field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

  field_cref(const field_cref &) noexcept = default;
  field_cref(field_cref &&) noexcept = default;
  field_cref &operator=(const field_cref &) noexcept = default;
  field_cref &operator=(field_cref &&) noexcept = default;
  ~field_cref() noexcept = default;

  [[nodiscard]] field_kind_t field_kind() const noexcept { return descriptor_->field_kind; }
  [[nodiscard]] bool is_repeated() const noexcept { return field_kind() >= KIND_REPEATED_DOUBLE; }
  [[nodiscard]] bool explicit_presence() const noexcept { return descriptor_->explicit_presence(); }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

  [[nodiscard]] bool has_value() const noexcept {
    return storage_->has_value() && (is_repeated() || storage_->of_int64.selection == descriptor().oneof_ordinal);
  }

  template <typename T>
  std::optional<T> to() const noexcept {
    if (T::field_kind == field_kind()) {
      return T(*descriptor_, *storage_);
    }
    return std::nullopt;
  }

  auto visit(auto &&v);
}; // class field_cref

class field_mref {
  const field_descriptor_t *descriptor_;
  value_storage *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

public:
  field_mref(const field_descriptor_t &descriptor, value_storage &storage,
             std::pmr::monotonic_buffer_resource &mr) noexcept
      : descriptor_(&descriptor), storage_(&storage), memory_resource_(&mr) {}

  field_mref(const field_mref &) noexcept = default;
  field_mref(field_mref &&) noexcept = default;
  field_mref &operator=(const field_mref &) noexcept = default;
  field_mref &operator=(field_mref &&) noexcept = default;
  ~field_mref() noexcept = default;

  void reset() noexcept { storage_->reset(); }
  [[nodiscard]] field_kind_t field_kind() const noexcept { return descriptor_->field_kind; }
  [[nodiscard]] bool is_repeated() const noexcept { return field_kind() >= KIND_REPEATED_DOUBLE; }
  [[nodiscard]] bool explicit_presence() const noexcept { return descriptor_->explicit_presence(); }
  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }

  template <typename T>
  [[nodiscard]] std::optional<T> to() const noexcept {
    if (T::field_kind == field_kind()) {
      return T(*descriptor_, *storage_, *memory_resource_);
    }
    return std::nullopt;
  }

  [[nodiscard]] field_cref cref() const noexcept { return {*descriptor_, *storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversion)
  [[nodiscard]] operator field_cref() const noexcept { return cref(); }
  auto visit(auto &&v);
}; // class field_mref

template <typename T, field_kind_t Kind>
class scalar_field_cref {
  const field_descriptor_t *descriptor_;
  const scalar_storage_base<T> *storage_;

public:
  static constexpr field_kind_t field_kind = Kind;

  scalar_field_cref(const field_descriptor_t &descriptor, const scalar_storage_base<T> &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {
    assert(descriptor.field_kind == field_kind);
  }

  scalar_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      : scalar_field_cref(descriptor, reinterpret_cast<const scalar_storage_base<T> &>(storage)) {}

  scalar_field_cref(const scalar_field_cref &) noexcept = default;
  scalar_field_cref(scalar_field_cref &&) noexcept = default;
  scalar_field_cref &operator=(const scalar_field_cref &) noexcept = default;
  scalar_field_cref &operator=(scalar_field_cref &&) noexcept = default;
  ~scalar_field_cref() noexcept = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->selection; }
  [[nodiscard]] T value() const noexcept {
    if (!descriptor().explicit_presence() && !has_value()) {
      return std::get<T>(descriptor_->default_value);
    }
    return storage_->content;
  }

  [[nodiscard]] T operator*() const noexcept { return value(); }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
};

template <typename T, field_kind_t Kind>
class scalar_field_mref {
  const field_descriptor_t *descriptor_;
  scalar_storage_base<T> *storage_;

public:
  static constexpr field_kind_t field_kind = Kind;
  scalar_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                    std::pmr::monotonic_buffer_resource &) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      : descriptor_(&descriptor), storage_(reinterpret_cast<scalar_storage_base<T> *>(&storage)) {
    assert(descriptor.field_kind == field_kind);
  }

  scalar_field_mref(const scalar_field_mref &) noexcept = default;
  scalar_field_mref(scalar_field_mref &&) noexcept = default;
  scalar_field_mref &operator=(const scalar_field_mref &) noexcept = default;
  scalar_field_mref &operator=(scalar_field_mref &&) noexcept = default;
  ~scalar_field_mref() noexcept = default;
  scalar_field_mref &operator=(T v) noexcept {
    storage_->content = v;
    storage_->selection = descriptor_->oneof_ordinal;
    return *this;
  }

  [[nodiscard]] scalar_field_cref<T, Kind> cref() const noexcept { return {*descriptor_, *storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversion)
  [[nodiscard]] operator scalar_field_cref<T, Kind>() const noexcept { return cref(); }

  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }
  [[nodiscard]] T operator*() const noexcept { return cref().operator*(); }
  [[nodiscard]] T value() const noexcept { return cref().value(); }
  void reset() noexcept { storage_->selection = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
};

class string_field_cref {
  const field_descriptor_t *descriptor_;
  const string_storage_t *storage_;

public:
  constexpr static field_kind_t field_kind = field_kind_t::KIND_STRING;
  string_field_cref(const field_descriptor_t &descriptor, const string_storage_t &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {
    assert(descriptor.field_kind == field_kind);
  }
  string_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : string_field_cref(descriptor, storage.of_string) {}

  string_field_cref(const string_field_cref &) noexcept = default;
  string_field_cref(string_field_cref &&) noexcept = default;
  string_field_cref &operator=(const string_field_cref &) noexcept = default;
  string_field_cref &operator=(string_field_cref &&) noexcept = default;
  ~string_field_cref() noexcept = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->selection != 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }

  [[nodiscard]] std::string_view value() const noexcept {
    if (!descriptor_->explicit_presence() && !has_value()) {
      auto &default_value = std::get<std::string>(descriptor_->default_value);
      return default_value;
    }
    return {storage_->content, storage_->size};
  }

  [[nodiscard]] std::string_view operator*() const noexcept { return value(); }
  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
};

class string_field_mref {
  const field_descriptor_t *descriptor_;
  string_storage_t *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

  [[nodiscard]] const std::string &default_value() const noexcept {
    return std::get<std::string>(descriptor_->default_value);
  }

  [[nodiscard]] bool is_default_value(std::string_view v) const noexcept {
    return std::ranges::equal(v, default_value());
  }

public:
  constexpr static field_kind_t field_kind = field_kind_t::KIND_STRING;
  string_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                    std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : descriptor_(&descriptor), storage_(&storage.of_string), memory_resource_(&mr) {
    assert(descriptor.field_kind == field_kind);
  }

  string_field_mref(const string_field_mref &) noexcept = default;
  string_field_mref(string_field_mref &&) noexcept = default;
  string_field_mref &operator=(const string_field_mref &) noexcept = default;
  string_field_mref &operator=(string_field_mref &&) noexcept = default;
  ~string_field_mref() noexcept = default;

  string_field_mref &operator=(std::string_view v) noexcept {
    storage_->content = v.data();
    storage_->size = v.size();
    storage_->selection = descriptor_->oneof_ordinal;
    return *this;
  }

  [[nodiscard]] string_field_cref cref() const noexcept { return string_field_cref{*descriptor_, *storage_}; }
  [[nodiscard]] operator string_field_cref() const noexcept { return cref(); }

  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }
  [[nodiscard]] std::string_view value() const noexcept { return cref().value(); }
  [[nodiscard]] std::string_view operator*() const noexcept { return cref().operator*(); }

  void reset() noexcept {
    storage_->size = 0;
    storage_->selection = 0;
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
};

class bytes_field_cref {
  const field_descriptor_t *descriptor_;
  const bytes_storage_t *storage_;

public:
  constexpr static field_kind_t field_kind = field_kind_t::KIND_BYTES;
  bytes_field_cref(const field_descriptor_t &descriptor, const bytes_storage_t &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {
    assert(descriptor.field_kind == field_kind);
  }
  bytes_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : bytes_field_cref(descriptor, storage.of_bytes) {}

  bytes_field_cref(const bytes_field_cref &) noexcept = default;
  bytes_field_cref(bytes_field_cref &&) noexcept = default;
  bytes_field_cref &operator=(const bytes_field_cref &) noexcept = default;
  bytes_field_cref &operator=(bytes_field_cref &&) noexcept = default;
  ~bytes_field_cref() noexcept = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->selection; }
  [[nodiscard]] bytes_view value() const noexcept {
    if (!descriptor_->explicit_presence() && !has_value()) {
      auto &default_value = std::get<std::vector<std::byte>>(descriptor_->default_value);
      return {default_value.data(), default_value.size()};
    }
    return {storage_->content, storage_->size};
  }
  [[nodiscard]] bytes_view operator*() const noexcept { return value(); }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
};

class bytes_field_mref {
  const field_descriptor_t *descriptor_;
  bytes_storage_t *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

  [[nodiscard]] const std::vector<std::byte> &default_value() const noexcept {
    return std::get<std::vector<std::byte>>(descriptor_->default_value);
  }

  [[nodiscard]] bool is_default_value(bytes_view v) const noexcept { return std::ranges::equal(v, default_value()); }

public:
  constexpr static field_kind_t field_kind = field_kind_t::KIND_BYTES;
  bytes_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                   std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : descriptor_(&descriptor), storage_(&storage.of_bytes), memory_resource_(&mr) {
    assert(descriptor.field_kind == field_kind);
  }

  bytes_field_mref(const bytes_field_mref &) noexcept = default;
  bytes_field_mref(bytes_field_mref &&) noexcept = default;
  bytes_field_mref &operator=(const bytes_field_mref &) noexcept = default;
  bytes_field_mref &operator=(bytes_field_mref &&) noexcept = default;
  ~bytes_field_mref() = default;
  bytes_field_mref &operator=(std::span<const std::byte> v) noexcept {
    storage_->content = v.data();
    storage_->size = v.size();
    storage_->selection = descriptor_->oneof_ordinal;
    return *this;
  }
  [[nodiscard]] bytes_field_cref cref() const noexcept { return {*descriptor_, *storage_}; }
  [[nodiscard]] operator bytes_field_cref() const noexcept { return cref(); }

  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }
  [[nodiscard]] bytes_view value() const noexcept { return cref().value(); }
  [[nodiscard]] bytes_view operator*() const noexcept { return cref().operator*(); }

  void reset() noexcept {
    storage_->size = 0;
    storage_->selection = 0;
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
};

class enum_value_cref {
  const enum_descriptor_t *descriptor_;
  uint32_t number_;

public:
  using is_enum_value_ref = void;
  enum_value_cref(const enum_descriptor_t &descriptor, uint32_t number) noexcept
      : descriptor_(&descriptor), number_(number) {}
  enum_value_cref(const enum_value_cref &) noexcept = default;
  enum_value_cref(enum_value_cref &&) noexcept = default;
  enum_value_cref &operator=(const enum_value_cref &) noexcept = default;
  enum_value_cref &operator=(enum_value_cref &&) noexcept = default;
  ~enum_value_cref() noexcept = default;

  [[nodiscard]] explicit operator uint32_t() const noexcept { return number_; }

  [[nodiscard]] uint32_t number() const noexcept { return number_; }
  [[nodiscard]] const char *name() const noexcept { return descriptor_->name_of(number_); }
  [[nodiscard]] const enum_descriptor_t &descriptor() const noexcept { return *descriptor_; }
};

class enum_value_mref {
  const enum_descriptor_t *descriptor_;
  uint32_t *number_;

public:
  using is_enum_value_ref = void;
  enum_value_mref(const enum_descriptor_t &descriptor, uint32_t &number) noexcept
      : descriptor_(&descriptor), number_(&number) {}
  enum_value_mref(const enum_value_mref &) noexcept = default;
  enum_value_mref(enum_value_mref &&) noexcept = default;
  enum_value_mref &operator=(const enum_value_mref &) noexcept = default;
  enum_value_mref &operator=(enum_value_mref &&) noexcept = default;
  ~enum_value_mref() noexcept = default;

  enum_value_mref &operator=(uint32_t number) noexcept {
    *number_ = number;
    return *this;
  };

  [[nodiscard]] const uint32_t *number_by_name(const char *name) const noexcept { return descriptor_->value_of(name); }

  explicit operator uint32_t() const noexcept { return *number_; }
  [[nodiscard]] uint32_t number() const noexcept { return *number_; }
  [[nodiscard]] const char *name() const noexcept { return descriptor_->name_of(*number_); }

  [[nodiscard]] const enum_descriptor_t &descriptor() const noexcept { return *descriptor_; }
};

class enum_field_cref {
  const field_descriptor_t *descriptor_;
  const scalar_storage_base<uint32_t> *storage_;

public:
  constexpr static field_kind_t field_kind = field_kind_t::KIND_ENUM;
  using type = vuint32_t;
  enum_field_cref(const field_descriptor_t &descriptor, const scalar_storage_base<uint32_t> &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {
    assert(descriptor.field_kind == field_kind);
  }
  enum_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : enum_field_cref(descriptor, storage.of_uint32) {}

  enum_field_cref(const enum_field_cref &) noexcept = default;
  enum_field_cref(enum_field_cref &&) noexcept = default;
  enum_field_cref &operator=(const enum_field_cref &) noexcept = default;
  enum_field_cref &operator=(enum_field_cref &&) noexcept = default;

  ~enum_field_cref() = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->selection; }
  [[nodiscard]] enum_value_cref value() const noexcept { return {enum_descriptor(), storage_->content}; }
  [[nodiscard]] enum_value_cref operator*() const noexcept { return value(); }
  [[nodiscard]] enum_value_cref operator->() const noexcept { return value(); }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const enum_descriptor_t &enum_descriptor() const noexcept {
    return *descriptor_->enum_field_type_descriptor();
  }
};

class enum_field_mref {
  const field_descriptor_t *descriptor_;
  scalar_storage_base<uint32_t> *storage_;

public:
  constexpr static field_kind_t field_kind = field_kind_t::KIND_ENUM;
  using type = vuint32_t;
  enum_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                  std::pmr::monotonic_buffer_resource &) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : descriptor_(&descriptor), storage_(&storage.of_uint32) {
    assert(descriptor.field_kind == field_kind);
  }

  enum_field_mref(const enum_field_mref &) noexcept = default;
  enum_field_mref(enum_field_mref &&) noexcept = default;
  enum_field_mref &operator=(const enum_field_mref &) noexcept = default;
  enum_field_mref &operator=(enum_field_mref &&) noexcept = default;
  ~enum_field_mref() noexcept = default;
  enum_field_mref &operator=(uint32_t value) noexcept {
    storage_->content = value;
    storage_->selection = descriptor_->oneof_ordinal;
    return *this;
  }

  [[nodiscard]] enum_field_cref cref() const noexcept { return enum_field_cref{*descriptor_, *storage_}; }
  [[nodiscard]] operator enum_field_cref() const noexcept { return cref(); }

  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }
  [[nodiscard]] enum_value_mref value() const noexcept {
    return {*descriptor_->enum_field_type_descriptor(), storage_->content};
  }

  [[nodiscard]] enum_value_mref operator*() const noexcept { return value(); }
  [[nodiscard]] enum_value_mref operator->() const noexcept { return value(); }

  [[nodiscard]] enum_value_mref emplace() noexcept {
    storage_->selection = descriptor_->oneof_ordinal;
    return {*descriptor_->enum_field_type_descriptor(), storage_->content};
  }

  void reset() noexcept { storage_->selection = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const enum_descriptor_t &enum_descriptor() const noexcept {
    return *descriptor_->enum_field_type_descriptor();
  }
};

template <typename T, field_kind_t Kind>
class repeated_scalar_field_cref : public std::ranges::view_interface<repeated_scalar_field_cref<T, Kind>> {
  const field_descriptor_t *descriptor_;
  const repeated_storage_base<T> *storage_;

public:
  static constexpr field_kind_t field_kind = Kind;
  using value_type = T;
  repeated_scalar_field_cref(const field_descriptor_t &descriptor, const repeated_storage_base<T> &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {
    assert(descriptor.field_kind == field_kind);
  }
  repeated_scalar_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      : repeated_scalar_field_cref(descriptor, reinterpret_cast<const repeated_storage_base<T> &>(storage)) {}

  repeated_scalar_field_cref(const repeated_scalar_field_cref &) noexcept = default;
  repeated_scalar_field_cref(repeated_scalar_field_cref &&) noexcept = default;
  repeated_scalar_field_cref &operator=(const repeated_scalar_field_cref &) noexcept = default;
  repeated_scalar_field_cref &operator=(repeated_scalar_field_cref &&) noexcept = default;
  ~repeated_scalar_field_cref() noexcept = default;

  T operator[](std::size_t index) const noexcept {
    assert(index < storage_->size);
    return storage_->content[index];
  }

  T at(std::size_t index) const {
    if (index < storage_->size) {
      return storage_->content[index];
    }
    throw std::out_of_range("");
  }

  [[nodiscard]] bool empty() const noexcept { return storage_->size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] const T *data() const noexcept { return storage_->content; }
  [[nodiscard]] const T *begin() const noexcept { return storage_->content; }
  [[nodiscard]] const T *end() const noexcept { return storage_->content + storage_->size; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
};

template <typename T, field_kind_t Kind>
class repeated_scalar_field_mref : public std::ranges::view_interface<repeated_scalar_field_mref<T, Kind>> {
  const field_descriptor_t *descriptor_;
  repeated_storage_base<T> *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

public:
  static constexpr field_kind_t field_kind = Kind;
  using value_type = T;
  repeated_scalar_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                             std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      : descriptor_(&descriptor), storage_(reinterpret_cast<repeated_storage_base<T> *>(&storage)),
        memory_resource_(&mr) {
    assert(descriptor.field_kind == field_kind);
  }

  repeated_scalar_field_mref(const repeated_scalar_field_mref &) noexcept = default;
  repeated_scalar_field_mref(repeated_scalar_field_mref &&) noexcept = default;
  repeated_scalar_field_mref &operator=(const repeated_scalar_field_mref &) noexcept = default;
  repeated_scalar_field_mref &operator=(repeated_scalar_field_mref &&) noexcept = default;
  ~repeated_scalar_field_mref() noexcept = default;

  [[nodiscard]] repeated_scalar_field_cref<T, Kind> cref() const noexcept {
    return repeated_scalar_field_cref<T, Kind>{*descriptor_, *storage_};
  }
  [[nodiscard]] operator repeated_scalar_field_cref<T, Kind>() const noexcept { return cref(); }

  T &operator[](std::size_t index) const noexcept {
    assert(index < storage_->size);
    return storage_->content[index];
  }

  T &at(std::size_t index) const {
    if (index < storage_->size) {
      return storage_->content[index];
    }
    throw std::out_of_range("");
  }

  void reserve(std::size_t n) noexcept {
    if (capacity() < n) {
      auto new_data = static_cast<T *>(memory_resource_->allocate(n * sizeof(T), alignof(T)));
      storage_->capacity = n;
      if (storage_->content) {
        std::uninitialized_copy(storage_->content, storage_->content + storage_->size, new_data);
      }
      storage_->content = new_data;
    }
  }

  void resize(std::size_t n) {
    if (capacity() < n) {
      auto new_data = static_cast<T *>(memory_resource_->allocate(n * sizeof(T), alignof(T)));
      storage_->capacity = n;
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      std::uninitialized_default_construct(new_data, new_data + n);
      storage_->content = new_data;
    } else if (size() < n) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      std::uninitialized_default_construct(storage_->content + storage_->size, storage_->content + n);
    }
    storage_->size = n;
  }

  [[nodiscard]] bool empty() const noexcept { return storage_->size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] std::size_t capacity() const noexcept { return storage_->capacity; }
  [[nodiscard]] T *begin() const noexcept { return storage_->content; }
  [[nodiscard]] T *end() const noexcept { return storage_->content + storage_->size; }
  [[nodiscard]] T *data() const noexcept { return storage_->content; }

  void reset() noexcept {
    storage_->content = nullptr;
    storage_->size = 0;
  }
  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
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
  repeated_field_iterator(const Field *field, std::size_t index) noexcept : field_(field), index_(index) {}
  repeated_field_iterator(const repeated_field_iterator &) noexcept = default;
  repeated_field_iterator(repeated_field_iterator &&) noexcept = default;
  repeated_field_iterator &operator=(const repeated_field_iterator &) noexcept = default;
  repeated_field_iterator &operator=(repeated_field_iterator &&) noexcept = default;
  ~repeated_field_iterator() noexcept = default;
  repeated_field_iterator &operator++() noexcept {
    ++index_;
    return *this;
  }
  repeated_field_iterator operator++(int) noexcept {
    repeated_field_iterator tmp = *this;
    ++(*this);
    return tmp;
  }
  repeated_field_iterator &operator--() noexcept {
    --index_;
    return *this;
  }
  repeated_field_iterator operator--(int) noexcept {
    repeated_field_iterator tmp = *this;
    --(*this);
    return tmp;
  }
  repeated_field_iterator &operator+=(std::ptrdiff_t n) noexcept {
    index_ += n;
    return *this;
  }
  repeated_field_iterator &operator-=(std::ptrdiff_t n) noexcept {
    index_ -= n;
    return *this;
  }
  repeated_field_iterator operator+(std::ptrdiff_t n) const noexcept {
    repeated_field_iterator tmp = *this;
    tmp += n;
    return tmp;
  }
  repeated_field_iterator operator-(std::ptrdiff_t n) const noexcept {
    repeated_field_iterator tmp = *this;
    tmp -= n;
    return tmp;
  }
  std::ptrdiff_t operator-(const repeated_field_iterator &other) const noexcept { return index_ - other.index_; }

  std::strong_ordering operator<=>(const repeated_field_iterator &other) const noexcept {
    assert(field_ == other.field_);
    return index_ <=> other.index_;
  }

  bool operator==(const repeated_field_iterator &other) const noexcept {
    assert(field_ == other.field_);
    return index_ == other.index_;
  }

  reference operator*() const noexcept { return (*field_)[index_]; }
};

class repeated_enum_field_cref : public std::ranges::view_interface<repeated_enum_field_cref> {
  const field_descriptor_t *descriptor_;
  const repeated_storage_base<uint32_t> *storage_;

public:
  using reference = enum_value_cref;
  using iterator = repeated_field_iterator<repeated_enum_field_cref>;
  static constexpr field_kind_t field_kind = field_kind_t::KIND_REPEATED_ENUM;
  repeated_enum_field_cref(const field_descriptor_t &descriptor,
                           const repeated_storage_base<uint32_t> &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {
    assert(descriptor.field_kind == field_kind);
  }

  repeated_enum_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : repeated_enum_field_cref(descriptor, storage.of_repeated_uint32) {}

  repeated_enum_field_cref(const repeated_enum_field_cref &) noexcept = default;
  repeated_enum_field_cref(repeated_enum_field_cref &&) noexcept = default;
  repeated_enum_field_cref &operator=(const repeated_enum_field_cref &) noexcept = default;
  repeated_enum_field_cref &operator=(repeated_enum_field_cref &&) noexcept = default;
  ~repeated_enum_field_cref() = default;

  [[nodiscard]] bool empty() const noexcept { return storage_->size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] iterator begin() const noexcept { return {this, 0}; }
  [[nodiscard]] iterator end() const noexcept { return {this, storage_->size}; }
  [[nodiscard]] reference operator[](std::size_t index) const noexcept {
    assert(index < size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return {*descriptor_->enum_field_type_descriptor(), storage_->content[index]};
  }

  [[nodiscard]] reference at(std::size_t index) const {
    if (index < size()) {
      return {*descriptor_->enum_field_type_descriptor(), storage_->content[index]};
    }
    throw std::out_of_range("");
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
};

class repeated_enum_field_mref : public std::ranges::view_interface<repeated_enum_field_mref> {
  const field_descriptor_t *descriptor_;
  repeated_storage_base<uint32_t> *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

public:
  static constexpr field_kind_t field_kind = field_kind_t::KIND_REPEATED_ENUM;
  using reference = enum_value_mref;
  using iterator = repeated_field_iterator<repeated_enum_field_mref>;

  repeated_enum_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                           std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      : descriptor_(&descriptor), storage_(reinterpret_cast<repeated_storage_base<uint32_t> *>(&storage)),
        memory_resource_(&mr) {
    assert(descriptor.field_kind == field_kind);
    assert(descriptor.enum_field_type_descriptor() != nullptr);
  }

  repeated_enum_field_mref(const repeated_enum_field_mref &) noexcept = default;
  repeated_enum_field_mref(repeated_enum_field_mref &&) noexcept = default;
  repeated_enum_field_mref &operator=(const repeated_enum_field_mref &) noexcept = default;
  repeated_enum_field_mref &operator=(repeated_enum_field_mref &&) noexcept = default;
  ~repeated_enum_field_mref() noexcept = default;

  [[nodiscard]] repeated_enum_field_cref cref() const noexcept {
    return repeated_enum_field_cref{*descriptor_, *storage_};
  }
  [[nodiscard]] operator repeated_enum_field_cref() const noexcept { return cref(); }

  void resize(std::size_t n) {
    if (capacity() < n) {
      auto new_data = static_cast<uint32_t *>(memory_resource_->allocate(n * sizeof(uint32_t), alignof(uint32_t)));
      std::copy(storage_->content, storage_->content + size(), new_data);
      std::uninitialized_default_construct(new_data, new_data + n);
      storage_->content = new_data;
      storage_->capacity = n;
    } else if (size() < n) {
      std::uninitialized_default_construct(storage_->content + size(), storage_->content + n);
    }
    storage_->size = n;
  }

  [[nodiscard]] bool empty() const noexcept { return storage_->size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] std::size_t capacity() const noexcept { return storage_->capacity; }
  [[nodiscard]] iterator begin() const noexcept { return {this, 0}; }
  [[nodiscard]] iterator end() const noexcept { return {this, storage_->size}; }
  [[nodiscard]] uint32_t *data() const noexcept { return storage_->content; }

  [[nodiscard]] reference operator[](std::size_t index) const noexcept {
    assert(index < size());
    return { *descriptor_->enum_field_type_descriptor(), storage_->content[index]};
  }

  [[nodiscard]] reference at(std::size_t index) const {
    if (index < size()) {
      return {*descriptor_->enum_field_type_descriptor(), storage_->content[index]};
    }
    throw std::out_of_range("");
  }

  void reset() noexcept {
    storage_->content = nullptr;
    storage_->size = 0;
  }
  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const enum_descriptor_t &enum_descriptor() const noexcept {
    return *descriptor_->enum_field_type_descriptor();
  }
};

class message_value_cref {
  const message_descriptor_t *descriptor_;
  const value_storage *storage_;
  std::size_t num_slots() const noexcept { return descriptor_->num_slots; }

  const value_storage &storage_for(const field_descriptor_t &desc) const noexcept {
    return storage_[desc.storage_slot];
  }

  static const value_storage &empty_storage() noexcept {
    const static value_storage empty;
    return empty;
  }

  field_cref operator[](std::int32_t n) const {
    auto &desc = descriptor_->fields()[n];
    return field_cref{desc, storage_for(desc)};
  }
  friend class repeated_field_iterator<message_value_cref>;
  using reference = field_cref;

public:
  message_value_cref(const message_descriptor_t &descriptor, const value_storage *storage) noexcept
      : descriptor_(&descriptor), storage_(storage) {}
  message_value_cref(const message_value_cref &) noexcept = default;
  message_value_cref(message_value_cref &&) noexcept = default;
  message_value_cref &operator=(const message_value_cref &) noexcept = default;
  message_value_cref &operator=(message_value_cref &&) noexcept = default;
  ~message_value_cref() noexcept = default;
  [[nodiscard]] const message_descriptor_t &descriptor() const noexcept { return *descriptor_; }

  [[nodiscard]] const field_descriptor_t *field_descriptor_by_name(std::string_view name) const noexcept {
    auto field_descriptors = descriptor_->fields();
    auto it = std::ranges::find_if(field_descriptors, [name](const auto &desc) { return desc.proto().name == name; });
    if (it != field_descriptors.end()) {
      return std::addressof(*it);
    }
    return nullptr;
  }

  [[nodiscard]] const field_descriptor_t *field_descriptor_by_number(int32_t number) const noexcept {
    auto field_descriptors = descriptor_->fields();
    auto it =
        std::ranges::find_if(field_descriptors, [number](const auto &desc) { return desc.proto().number == number; });
    if (it != field_descriptors.end()) {
      return std::addressof(*it);
    }
    return nullptr;
  }

  [[nodiscard]] const oneof_descriptor_t *oneof_descriptor(std::string_view name) const noexcept {
    auto oneofs = descriptor_->oneofs();
    auto it = std::ranges::find_if(oneofs, [name](const auto &oneof) { return oneof.proto().name == name; });
    if (it != oneofs.end()) {
      return std::addressof(*it);
    }
    return nullptr;
  }

  [[nodiscard]] field_cref const_field(const field_descriptor_t &desc) const noexcept {
    auto &storage = storage_for(desc);
    if (!desc.is_repeated() && storage.of_int64.selection != desc.oneof_ordinal) {
      return field_cref(desc, empty_storage());
    } else {
      return field_cref(desc, storage);
    }
  }

  [[nodiscard]] field_cref operator[](std::string_view name) const noexcept {
    auto *desc = field_descriptor_by_name(name);
    assert(desc != nullptr);
    return const_field(*desc);
  }

  [[nodiscard]] field_cref at(std::string_view name) const {
    if (auto *desc = field_descriptor_by_name(name); desc != nullptr) {
      return const_field(*desc);
    }
    throw std::out_of_range{""};
  }

  [[nodiscard]] bool has_oneof(const oneof_descriptor_t &desc) const noexcept {
    auto &storage = storage_[desc.storage_slot()];
    return storage.of_int64.selection;
  }
  class fields_view : public std::ranges::view_interface<fields_view> {
    const message_value_cref *base_;

  public:
    using value_type = field_cref;
    using reference = field_cref;
    using iterator = repeated_field_iterator<message_value_cref>;
    explicit fields_view(const message_value_cref &base) : base_(&base) {}
    [[nodiscard]] iterator begin() const { return {base_, 0}; }
    [[nodiscard]] iterator end() const { return {base_, base_->descriptor().fields().size()}; }
  };

  fields_view fields() const { return fields_view{*this}; }
};

class message_field_mref;
class message_value_mref {
  friend class message_field_mref;
  const message_descriptor_t *descriptor_;
  value_storage *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

  std::size_t num_slots() const noexcept { return descriptor_->num_slots; }

  value_storage &storage_for(const field_descriptor_t &desc) const noexcept { return storage_[desc.storage_slot]; }

  field_mref operator[](std::int32_t n) const {
    auto &desc = descriptor_->fields()[n];
    return field_mref{desc, storage_for(desc), *memory_resource_};
  }
  friend class repeated_field_iterator<message_value_mref>;
  using reference = field_mref;

public:
  message_value_mref(const message_descriptor_t &descriptor, value_storage *storage,
                     std::pmr::monotonic_buffer_resource &memory_resource) noexcept
      : descriptor_(&descriptor), storage_(storage), memory_resource_(&memory_resource) {}

  message_value_mref(const message_descriptor_t &descriptor,
                     std::pmr::monotonic_buffer_resource &memory_resource) noexcept
      : message_value_mref(descriptor,
                           static_cast<value_storage *>(memory_resource.allocate(
                               sizeof(value_storage) * descriptor.num_slots, alignof(value_storage))),
                           memory_resource) {
    reset();
  }

  message_value_mref(const message_value_mref &) noexcept = default;
  message_value_mref(message_value_mref &&) noexcept = default;
  message_value_mref &operator=(const message_value_mref &) noexcept = default;
  message_value_mref &operator=(message_value_mref &&) noexcept = default;
  ~message_value_mref() noexcept = default;
  const message_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  [[nodiscard]] message_value_cref cref() const noexcept { return {*descriptor_, storage_}; }
  [[nodiscard]] operator message_value_cref() const noexcept { return cref(); }

  [[nodiscard]] const field_descriptor_t *field_descriptor_by_name(std::string_view name) const noexcept {
    return cref().field_descriptor_by_name(name);
  }

  [[nodiscard]] const field_descriptor_t *field_descriptor_by_number(int32_t number) const noexcept {
    return cref().field_descriptor_by_number(number);
  }

  [[nodiscard]] const oneof_descriptor_t *oneof_descriptor(std::string_view name) const noexcept {
    return cref().oneof_descriptor(name);
  }

  void reset() const noexcept { std::memset(storage_, 0, sizeof(value_storage) * num_slots()); }

  [[nodiscard]] field_mref mutable_field(const field_descriptor_t &desc) const noexcept {
    auto &storage = storage_for(desc);
    if (!desc.is_repeated() && storage.of_int64.selection != desc.oneof_ordinal) {
      storage.of_int64.size = 0;
      storage.of_int64.selection = desc.oneof_ordinal;
    }
    return {desc, storage, *memory_resource_};
  }

  [[nodiscard]] field_mref operator[](std::string_view name) const noexcept {
    auto *desc = field_descriptor_by_name(name);
    assert(desc != nullptr);
    return mutable_field(*desc);
  }

  [[nodiscard]] field_mref at(std::string_view name) const {
    if (auto *desc = field_descriptor_by_name(name); desc != nullptr) {
      return mutable_field(*desc);
    }
    throw std::out_of_range{""};
  }

  void clear_field(const field_descriptor_t &desc) const noexcept { storage_for(desc).reset(); }

  void clear_field(const oneof_descriptor_t &desc) const noexcept { storage_[desc.storage_slot()].reset(); }

  [[nodiscard]] bool has_oneof(const oneof_descriptor_t &descriptor) const noexcept {
    return cref().has_oneof(descriptor);
  }

  class fields_view : public std::ranges::view_interface<fields_view> {
    const message_value_mref *base_;

  public:
    using value_type = field_mref;
    using reference = field_mref;
    using iterator = repeated_field_iterator<message_value_mref>;
    explicit fields_view(const message_value_mref &base) : base_(&base) {}
    iterator begin() const { return {base_, 0}; }
    iterator end() const { return {base_, base_->descriptor().fields().size()}; }
  };

  [[nodiscard]] fields_view fields() const { return fields_view{*this}; }
};

class message_field_cref {
  const field_descriptor_t *descriptor_;
  const scalar_storage_base<value_storage *> *storage_;
  std::size_t num_slots() const { return descriptor_->message_field_type_descriptor()->num_slots; }

public:
  static constexpr field_kind_t field_kind = field_kind_t::KIND_MESSAGE;
  message_field_cref(const field_descriptor_t &descriptor, const scalar_storage_base<value_storage *> &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {
    assert(descriptor.field_kind == field_kind);
  }

  message_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : message_field_cref(descriptor, storage.of_message) {}

  message_field_cref(const message_field_cref &) noexcept = default;
  message_field_cref(message_field_cref &&) noexcept = default;
  message_field_cref &operator=(const message_field_cref &) noexcept = default;
  message_field_cref &operator=(message_field_cref &&) noexcept = default;
  ~message_field_cref() noexcept = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->selection != 0; }
  [[nodiscard]] message_value_cref value() const {
    if (!has_value())
      throw std::bad_optional_access{};
    return {message_descriptor(), storage_->content};
  }
  [[nodiscard]] message_value_cref operator*() const noexcept { return {message_descriptor(), storage_->content}; }
  [[nodiscard]] message_value_cref operator->() const noexcept { return operator*(); }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const message_descriptor_t &message_descriptor() const noexcept {
    return *descriptor_->message_field_type_descriptor();
  }
};

class message_field_mref {
  const field_descriptor_t *descriptor_;
  scalar_storage_base<value_storage *> *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
  std::size_t num_slots() const noexcept { return message_descriptor().num_slots; }

public:
  static constexpr field_kind_t field_kind = field_kind_t::KIND_MESSAGE;
  message_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                     std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : descriptor_(&descriptor), storage_(&storage.of_message), memory_resource_(&mr) {
    assert(descriptor.field_kind == field_kind);
    assert(descriptor.message_field_type_descriptor() != nullptr);
  }

  message_field_mref(const message_field_mref &) noexcept = default;
  message_field_mref(message_field_mref &&) noexcept = default;
  message_field_mref &operator=(const message_field_mref &) noexcept = default;
  message_field_mref &operator=(message_field_mref &&) noexcept = default;
  ~message_field_mref() noexcept = default;

  message_value_mref emplace() noexcept {
    storage_->selection = descriptor_->oneof_ordinal;
    if (storage_->content == nullptr) {
      storage_->content = static_cast<value_storage *>(
          memory_resource_->allocate(sizeof(value_storage) * num_slots(), alignof(value_storage)));
    }
    auto result = message_value_mref{message_descriptor(), storage_->content, *memory_resource_};
    result.reset();
    return result;
  }
  [[nodiscard]] bool has_value() const noexcept { return storage_->selection != 0; }
  [[nodiscard]] message_value_mref value() const {
    if (!has_value())
      throw std::bad_optional_access{};
    return message_value_mref{message_descriptor(), storage_->content, *memory_resource_};
  }
  [[nodiscard]] message_value_mref operator*() const noexcept {
    return message_value_mref{message_descriptor(), storage_->content, *memory_resource_};
  }
  [[nodiscard]] message_value_mref operator->() const noexcept { return operator*(); }

  void reset() noexcept { storage_->selection = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const message_descriptor_t &message_descriptor() const noexcept {
    return *descriptor_->message_field_type_descriptor();
  }
};

class repeated_message_field_cref : std::ranges::view_interface<repeated_message_field_cref> {
  const field_descriptor_t *descriptor_;
  const repeated_storage_base<value_storage> *storage_;
  std::size_t num_slots() const { return message_descriptor().num_slots; }

public:
  static constexpr field_kind_t field_kind = field_kind_t::KIND_REPEATED_MESSAGE;
  using reference = message_value_cref;
  using iterator = repeated_field_iterator<repeated_message_field_cref>;
  repeated_message_field_cref(const field_descriptor_t &descriptor,
                              const repeated_storage_base<value_storage> &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {
    assert(descriptor.field_kind == field_kind);
  }

  repeated_message_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : repeated_message_field_cref(descriptor, storage.of_repeated_message) {}

  repeated_message_field_cref(const repeated_message_field_cref &) noexcept = default;
  repeated_message_field_cref(repeated_message_field_cref &&) noexcept = default;
  repeated_message_field_cref &operator=(const repeated_message_field_cref &) noexcept = default;
  repeated_message_field_cref &operator=(repeated_message_field_cref &&) noexcept = default;
  ~repeated_message_field_cref() noexcept = default;

  [[nodiscard]] bool empty() const noexcept { return storage_->size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] message_value_cref operator[](std::size_t index) const noexcept {
    assert(index < size());
    return message_value_cref(message_descriptor(), &storage_->content[index * num_slots()]);
  }

  [[nodiscard]] message_value_cref at(std::size_t index) const {
    if (index < size()) {
      return message_value_cref(message_descriptor(), &storage_->content[index * num_slots()]);
    }
    throw std::out_of_range("");
  }

  [[nodiscard]] iterator begin() const noexcept { return {this, 0}; }
  [[nodiscard]] iterator end() const noexcept { return {this, size()}; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const message_descriptor_t &message_descriptor() const noexcept {
    return *descriptor_->message_field_type_descriptor();
  }
};

class repeated_message_field_mref : std::ranges::view_interface<repeated_message_field_mref> {
  const field_descriptor_t *descriptor_;
  repeated_storage_base<value_storage> *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

  std::size_t num_slots() const noexcept { return message_descriptor().num_slots; }

public:
  static constexpr field_kind_t field_kind = field_kind_t::KIND_REPEATED_MESSAGE;
  using value_type = message_value_mref;
  using reference = message_value_mref;
  using iterator = repeated_field_iterator<repeated_message_field_mref>;
  repeated_message_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                              std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : descriptor_(&descriptor), storage_(&storage.of_repeated_message), memory_resource_(&mr) {
    assert(descriptor.field_kind == field_kind);
  }

  repeated_message_field_mref(const repeated_message_field_mref &) noexcept = default;
  repeated_message_field_mref(repeated_message_field_mref &&) noexcept = default;
  repeated_message_field_mref &operator=(const repeated_message_field_mref &) noexcept = default;
  repeated_message_field_mref &operator=(repeated_message_field_mref &&) noexcept = default;
  ~repeated_message_field_mref() noexcept = default;

  [[nodiscard]] repeated_message_field_cref cref() const noexcept { return {*descriptor_, *storage_}; }
  operator repeated_message_field_cref() const noexcept { return cref(); }

  void resize(std::size_t n) noexcept {
    auto old_size = size();
    if (capacity() < n) {
      auto new_data = static_cast<value_storage *>(
          memory_resource_->allocate(n * num_slots() * sizeof(value_storage), alignof(value_storage)));
      std::ranges::copy(std::span{storage_->content, storage_->size * num_slots()}, new_data);
      storage_->content = new_data;
      storage_->size = n;
      storage_->capacity = n;
      for (std::size_t i = old_size; i < size(); ++i) {
        (*this)[i].reset();
      }
    } else if (size() < n) {
      storage_->size = n;
      for (std::size_t i = old_size; i < size(); ++i) {
        (*this)[i].reset();
      }
    } else {
      storage_->size = n;
    }
  }

  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] std::size_t capacity() const noexcept { return storage_->capacity; }
  [[nodiscard]] message_value_mref operator[](std::size_t index) const noexcept {
    assert(index < size());
    return message_value_mref(message_descriptor(), &storage_->content[index * num_slots()], *memory_resource_);
  }

  [[nodiscard]] message_value_mref at(std::size_t index) const {
    if (index < size()) {
      return message_value_mref(message_descriptor(), &storage_->content[index * num_slots()], *memory_resource_);
    }
    throw std::out_of_range("");
  }

  [[nodiscard]] iterator begin() const noexcept { return {this, 0}; }
  [[nodiscard]] iterator end() const noexcept { return {this, size()}; }

  void reset() noexcept { storage_->size = 0; }
  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const message_descriptor_t &message_descriptor() const noexcept {
    return *descriptor_->message_field_type_descriptor();
  }
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
using repeated_bytes_field_cref = repeated_scalar_field_cref<bytes_view, KIND_REPEATED_BYTES>;

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
using repeated_bytes_field_mref = repeated_scalar_field_mref<bytes_view, KIND_REPEATED_BYTES>;

inline auto field_cref::visit(auto &&visitor) {
  switch (descriptor_->field_kind) {
  case KIND_DOUBLE:
    return visitor(double_field_cref{*descriptor_, *storage_});
  case KIND_FLOAT:
    return visitor(float_field_cref{*descriptor_, *storage_});
  case KIND_INT64:
    return visitor(int64_field_cref{*descriptor_, *storage_});
  case KIND_UINT64:
    return visitor(uint64_field_cref{*descriptor_, *storage_});
  case KIND_INT32:
    return visitor(int32_field_cref{*descriptor_, *storage_});
  case KIND_UINT32:
    return visitor(uint32_field_cref{*descriptor_, *storage_});
  case KIND_BOOL:
    return visitor(bool_field_cref{*descriptor_, *storage_});
  case KIND_STRING:
    return visitor(string_field_cref{*descriptor_, *storage_});
  case KIND_BYTES:
    return visitor(bytes_field_cref{*descriptor_, *storage_});
  case KIND_ENUM:
    return visitor(enum_field_cref{*descriptor_, *storage_});
  case KIND_MESSAGE:
    return visitor(message_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_DOUBLE:
    return visitor(repeated_double_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_FLOAT:
    return visitor(repeated_float_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_INT64:
    return visitor(repeated_int64_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_UINT64:
    return visitor(repeated_uint64_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_INT32:
    return visitor(repeated_int32_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_UINT32:
    return visitor(repeated_uint32_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_BOOL:
    return visitor(repeated_bool_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_STRING:
    return visitor(repeated_string_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_BYTES:
    return visitor(repeated_bytes_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_ENUM:
    return visitor(repeated_enum_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_MESSAGE:
    return visitor(repeated_message_field_cref{*descriptor_, *storage_});
  }
}

inline auto field_mref::visit(auto &&visitor) {
  switch (descriptor_->field_kind) {
  case KIND_DOUBLE:
    return visitor(double_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_FLOAT:
    return visitor(float_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_INT64:
    return visitor(int64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_UINT64:
    return visitor(uint64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_INT32:
    return visitor(int32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_UINT32:
    return visitor(uint32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_BOOL:
    return visitor(bool_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_STRING:
    return visitor(string_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_BYTES:
    return visitor(bytes_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_ENUM:
    return visitor(enum_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_MESSAGE:
    return visitor(message_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_DOUBLE:
    return visitor(repeated_double_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_FLOAT:
    return visitor(repeated_float_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_INT64:
    return visitor(repeated_int64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_UINT64:
    return visitor(repeated_uint64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_INT32:
    return visitor(repeated_int32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_UINT32:
    return visitor(repeated_uint32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_BOOL:
    return visitor(repeated_bool_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_STRING:
    return visitor(repeated_string_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_BYTES:
    return visitor(repeated_bytes_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_ENUM:
    return visitor(repeated_enum_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_MESSAGE:
    return visitor(repeated_message_field_mref{*descriptor_, *storage_, *memory_resource_});
  }
}

template <typename T>
struct adapt_descriptor : field_descriptor_t {
  using type = T;
};

// NOLINTEND(cppcoreguidelines-pro-type-union-access)

namespace concepts {
template <typename T>
concept non_owning_string_or_bytes = std::is_same<T, std::string_view>::value || std::is_same<T, bytes_view>::value;
} // namespace concepts

namespace pb_serializer {

template <concepts::arithmetic T>
status deserialize_scalar(auto &&v, const auto &, uint32_t, auto &archive) {
  T value;
  if (auto ec = archive(value); !ec.ok()) [[unlikely]] {
    return ec;
  }
  v = value;
  return std::errc{};
}

status deserialize_scalar(enum_value_mref &&mref, const auto &, uint32_t, auto &archive) {
  vuint32_t value;
  if (auto ec = archive(value); !ec.ok()) [[unlikely]] {
    return ec;
  }
  if (!mref.descriptor().valid_enum_value(value)) [[likely]] {
    return std::errc::result_out_of_range;
  }
  mref = value;
  return std::errc{};
}

status deserialize_scalar(enum_field_mref &&mref, const auto &, uint32_t tag, auto &archive) {
  auto ec = deserialize_scalar(mref.emplace(), tag, archive);
  if (ec == std::errc::result_out_of_range) [[unlikely]] {
    mref.reset();
    return std::errc{};
  }
  return ec;
}

template <concepts::non_owning_string_or_bytes T>
status deserialize_scalar(auto &&mref, const auto &desc, uint32_t, auto &archive) {
  vuint32_t byte_count;
  if (auto result = archive(byte_count); !result.ok()) [[unlikely]] {
    return result;
  }
  if (byte_count == 0) {
    return {};
  }
  T item;
  decltype(auto) v = detail::as_modifiable(archive.context, item);
  if (auto result = deserialize_packed_repeated_with_byte_count<typename T::value_type>(v, byte_count, archive);
      !result.ok()) [[unlikely]] {
    return result;
  }
  mref = item;
  if constexpr (std::is_same_v<T, std::string_view>) {
    // ensure that the string is valid UTF-8 if required
    if (desc.requires_utf8_validation()) {
      if (!::is_utf8(item.data(), item.size())) {
        mref = {};
        return std::errc::illegal_byte_sequence;
      }
    }
  }
  return {};
}

status deserialize_field(message_value_mref mref, const field_descriptor_t &desc, uint32_t tag, auto &archive) {
  if (desc.is_delimited()) {
    return deserialize_group(tag_number(tag), mref, archive);
  } else {
    return deserialize_sized(mref, archive);
  }
}

status deserialize_non_repeated(field_mref f, const field_descriptor_t &desc, uint32_t tag, auto &archive) {
  using enum google::protobuf::FieldDescriptorProto::Type;
  switch (desc.proto().type) {
  case TYPE_DOUBLE:
    return deserialize_scalar<double>(*f.to<double_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_FLOAT:
    return deserialize_scalar<float>(*f.to<float_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_INT64:
    return deserialize_scalar<vint64_t>(*f.to<int64_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_UINT64:
    return deserialize_scalar<vuint64_t>(*f.to<uint64_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_INT32:
    return deserialize_scalar<vint32_t>(*f.to<int32_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_UINT32:
    return deserialize_scalar<vuint32_t>(*f.to<uint32_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_BOOL:
    return deserialize_scalar<bool>(*f.to<bool_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_STRING:
    return deserialize_scalar<std::string_view>(*f.to<string_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_BYTES:
    return deserialize_scalar<bytes_view>(*f.to<bytes_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_ENUM:
    return deserialize_scalar<vuint32_t>(*f.to<enum_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_MESSAGE:
  case TYPE_GROUP:
    return deserialize_field(f.to<message_field_mref>()->emplace(), desc, tag, archive);
  case TYPE_FIXED64:
    return deserialize_scalar<uint64_t>(*f.to<uint64_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_FIXED32:
    return deserialize_scalar<uint32_t>(*f.to<uint32_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_SFIXED32:
    return deserialize_scalar<int32_t>(*f.to<int32_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_SFIXED64:
    return deserialize_scalar<int64_t>(*f.to<int64_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_SINT32:
    return deserialize_scalar<vsint32_t>(*f.to<int32_field_mref>(), f.descriptor(), tag, archive);
  case TYPE_SINT64:
    return deserialize_scalar<vsint64_t>(*f.to<int64_field_mref>(), f.descriptor(), tag, archive);
  default:
    return std::errc::bad_message;
  }
}

template <typename ElementType>
status deserialize_singular(auto &&element, const auto &descriptor, uint32_t tag, auto &archive) {
  if constexpr (std::is_same_v<ElementType, message_value_mref>) {
    return deserialize_field(element, descriptor, tag, archive);
  } else {
    return deserialize_scalar<ElementType>(element, descriptor, tag, archive);
  }
}

template <typename ElementType, concepts::resizable MRef>
status deserialize_unpacked_repeated(MRef mref, std::size_t count, uint32_t tag, auto &archive) {
  auto old_size = mref.size();
  const std::size_t new_size = mref.size() + count;
  mref.resize(new_size);

  if constexpr (std::is_same_v<MRef, repeated_enum_field_mref>) {
    auto i = old_size;
    for (; count > 0; --count) {
      auto ec = deserialize_scalar(mref[i++], mref.enum_descriptor(), tag, archive);
      if (ec == std::errc::result_out_of_range) [[unlikely]] {
        // ec would only be std::errc::result_out_of_range when the element is an invalid closed enum value,
        // in which case we just skip it
        --i;
      } else if (!ec.ok()) {
        return ec;
      }

      if (count > 1) {
        // no error handling here, because  `count_unpacked_elements()` already checked the tag
        archive.maybe_advance_region();
        (void)archive.read_tag();
      }
    }

    if (i != new_size) [[unlikely]] {
      // if we didn't write all elements, we need to resize the container
      mref.resize(i);
    }
  } else {
    for (std::size_t i = old_size; i < new_size; ++i, --count) {
      if (auto ec = deserialize_singular<ElementType>(mref[i], mref.descriptor(), tag, archive); !ec.ok())
          [[unlikely]] {
        return ec;
      }
      if (count > 1) {
        // no error handling here, because  `count_unpacked_elements()` already checked the tag
        archive.maybe_advance_region();
        (void)archive.read_tag();
      }
    }
  }
  return {};
}

status deserialize_unpacked_repeated(field_mref v, uint32_t tag, concepts::is_basic_in auto &archive) {
  std::size_t count = 0;
  auto &desc = v.descriptor();
  if (desc.is_delimited()) [[unlikely]] {
    if (auto result = count_groups(tag, count, archive); !result.ok()) [[unlikely]] {
      return result;
    }
  } else {
    if (auto result = count_unpacked_elements(tag, count, archive); !result.ok()) [[unlikely]] {
      return result;
    }
  }

  using enum google::protobuf::FieldDescriptorProto::Type;
  switch (desc.proto().type) {
  case TYPE_DOUBLE:
    return deserialize_unpacked_repeated<double>(*(v.to<repeated_double_field_mref>()), count, tag, archive);
  case TYPE_FLOAT:
    return deserialize_unpacked_repeated<float>(*(v.to<repeated_float_field_mref>()), count, tag, archive);
  case TYPE_INT64:
    return deserialize_unpacked_repeated<vint64_t>(*(v.to<repeated_int64_field_mref>()), count, tag, archive);
  case TYPE_UINT64:
    return deserialize_unpacked_repeated<vuint64_t>(*(v.to<repeated_uint64_field_mref>()), count, tag, archive);
  case TYPE_INT32:
    return deserialize_unpacked_repeated<vint32_t>(*(v.to<repeated_int32_field_mref>()), count, tag, archive);
  case TYPE_UINT32:
    return deserialize_unpacked_repeated<vuint32_t>(*(v.to<repeated_uint32_field_mref>()), count, tag, archive);
  case TYPE_BOOL:
    return deserialize_unpacked_repeated<bool>(*(v.to<repeated_bool_field_mref>()), count, tag, archive);
  case TYPE_ENUM:
    return deserialize_unpacked_repeated<vint64_t>(*(v.to<repeated_enum_field_mref>()), count, tag, archive);
  case TYPE_STRING:
    return deserialize_unpacked_repeated<std::string_view>(*(v.to<repeated_string_field_mref>()), count, tag, archive);
  case TYPE_BYTES:
    return deserialize_unpacked_repeated<bytes_view>(*(v.to<repeated_bytes_field_mref>()), count, tag, archive);
  case TYPE_MESSAGE:
  case TYPE_GROUP:
    return deserialize_unpacked_repeated<message_value_mref>(*(v.to<repeated_message_field_mref>()), count, tag,
                                                             archive);
  case TYPE_FIXED64:
    return deserialize_unpacked_repeated<uint64_t>(*(v.to<repeated_uint64_field_mref>()), count, tag, archive);
  case TYPE_FIXED32:
    return deserialize_unpacked_repeated<uint32_t>(*(v.to<repeated_uint32_field_mref>()), count, tag, archive);
  case TYPE_SFIXED32:
    return deserialize_unpacked_repeated<int32_t>(*(v.to<repeated_int32_field_mref>()), count, tag, archive);
  case TYPE_SFIXED64:
    return deserialize_unpacked_repeated<int64_t>(*(v.to<repeated_int64_field_mref>()), count, tag, archive);
  case TYPE_SINT32:
    return deserialize_unpacked_repeated<vsint32_t>(*(v.to<repeated_int32_field_mref>()), count, tag, archive);
  case TYPE_SINT64:
    return deserialize_unpacked_repeated<vsint64_t>(*(v.to<repeated_int64_field_mref>()), count, tag, archive);
  default:
    return std::errc::bad_message;
  }
}

status deserialize_packed_repeated(const field_descriptor_t &desc, uint32_t, field_mref &item,
                                   concepts::is_basic_in auto &archive) {

  vuint32_t byte_count;
  if (auto result = archive(byte_count); !result.ok()) [[unlikely]] {
    return result;
  }
  if (byte_count == 0) {
    return {};
  }

  using enum google::protobuf::FieldDescriptorProto::Type;
  switch (desc.proto().type) {
  case TYPE_DOUBLE:
    return deserialize_packed_repeated_with_byte_count<double>(*item.to<repeated_double_field_mref>(), byte_count,
                                                               archive);
  case TYPE_FLOAT:
    return deserialize_packed_repeated_with_byte_count<float>(*item.to<repeated_float_field_mref>(), byte_count,
                                                              archive);
  case TYPE_INT64:
    return deserialize_packed_repeated_with_byte_count<vint64_t>(*item.to<repeated_int64_field_mref>(), byte_count,
                                                                 archive);
  case TYPE_UINT64:
    return deserialize_packed_repeated_with_byte_count<vuint64_t>(*item.to<repeated_uint64_field_mref>(), byte_count,
                                                                  archive);
  case TYPE_INT32:
    return deserialize_packed_repeated_with_byte_count<vint32_t>(*item.to<repeated_int32_field_mref>(), byte_count,
                                                                 archive);
  case TYPE_UINT32:
    return deserialize_packed_repeated_with_byte_count<vuint32_t>(*item.to<repeated_uint32_field_mref>(), byte_count,
                                                                  archive);
  case TYPE_BOOL:
    return deserialize_packed_repeated_with_byte_count<bool>(*item.to<repeated_bool_field_mref>(), byte_count, archive);
  case TYPE_ENUM:
    return deserialize_packed_repeated_with_byte_count<vuint32_t>(*item.to<repeated_enum_field_mref>(), byte_count,
                                                                  archive);
  case TYPE_FIXED64:
    return deserialize_packed_repeated_with_byte_count<uint64_t>(*item.to<repeated_uint64_field_mref>(), byte_count,
                                                                 archive);
  case TYPE_FIXED32:
    return deserialize_packed_repeated_with_byte_count<uint32_t>(*item.to<repeated_uint32_field_mref>(), byte_count,
                                                                 archive);
  case TYPE_SFIXED32:
    return deserialize_packed_repeated_with_byte_count<int32_t>(*item.to<repeated_int32_field_mref>(), byte_count,
                                                                archive);
  case TYPE_SFIXED64:
    return deserialize_packed_repeated_with_byte_count<int64_t>(*item.to<repeated_int64_field_mref>(), byte_count,
                                                                archive);
  case TYPE_SINT32:
    return deserialize_packed_repeated_with_byte_count<vsint32_t>(*item.to<repeated_int32_field_mref>(), byte_count,
                                                                  archive);
  case TYPE_SINT64:
    return deserialize_packed_repeated_with_byte_count<vsint64_t>(*item.to<repeated_int64_field_mref>(), byte_count,
                                                                  archive);
  default:
    return std::errc::bad_message;
  }
}

status deserialize_repeated(field_mref mref, const field_descriptor_t &desc, uint32_t tag, auto &archive) {
  if (desc.is_packed()) {
    if (tag_type(tag) != wire_type::length_delimited) {
      return deserialize_unpacked_repeated(mref, tag, archive);
    }
    return deserialize_packed_repeated(desc, tag, mref, archive);
  } else {
    return deserialize_unpacked_repeated(mref, tag, archive);
  }
}

status deserialize_field(field_mref f, const field_descriptor_t &desc, uint32_t tag, auto &archive) {
  if (f.is_repeated()) {
    return deserialize_repeated(f, desc, tag, archive);
  } else {
    return deserialize_non_repeated(f, desc, tag, archive);
  }
}

status deserialize_field_by_tag(uint32_t tag, message_value_mref item, concepts::is_basic_in auto &archive) {
  if (tag == 0) {
    return std::errc::bad_message;
  }
  const auto *field_desc = item.field_descriptor_by_number(static_cast<int32_t>(tag_number(tag)));
  if (field_desc == nullptr) [[unlikely]] {
    return std::errc::bad_message;
  }
  return deserialize_field(item.mutable_field(*field_desc), *field_desc, tag, archive);
}
} // namespace pb_serializer

status read_proto(message_value_mref msg, auto &&buffer) {
  msg.reset();
  auto context = pb_context{alloc_from(msg.memory_resource())};
  return pb_serializer::deserialize(msg, buffer, context);
}
} // namespace hpp::proto
