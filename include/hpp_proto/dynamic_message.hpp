/**
 * @file dynamic_message.hpp
 * @brief Runtime facilities for parsing, building, and serializing protobuf messages using descriptors only.
 *
 * The dynamic message layer exposes:
 * - descriptor-driven factories (`dynamic_message_factory`) to load FileDescriptorSets and produce mutable/const views.
 * - field and message reference types (`*_field_mref` / `*_field_cref`, `*_value_mref` / `*_value_cref`)
 *   that provide typed accessors, mutation helpers, and serialization hooks without generated code.
 *   * field_refs point at a specific field slot within a message (with presence/descriptor info); value_refs wrap the
 *     underlying value itself (e.g., messages, enums, strings) and can be used by field_refs to expose typed access.
 * - utilities and traits to support JSON/proto encoding, well-known types, and enum access patterns.
 *
 * This header is the main entry point when working with dynamic messages in hpp_proto.
 */
#pragma once
#include <cerrno>
#include <charconv>
#include <compare>
#include <cstdlib>
#include <functional>
#include <iterator>
#include <memory>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

#include <google/protobuf/any.desc.hpp>
#include <google/protobuf/duration.desc.hpp>
#include <google/protobuf/field_mask.desc.hpp>
#include <google/protobuf/struct.desc.hpp>
#include <google/protobuf/timestamp.desc.hpp>
#include <google/protobuf/wrappers.desc.hpp>
#include <hpp_proto/descriptor_pool.hpp>
#include <hpp_proto/pb_serializer.hpp>
namespace hpp::proto {
enum class field_kind_t : uint8_t {
  KIND_DOUBLE = 1,
  KIND_FLOAT = 2,
  KIND_INT64 = 3,
  KIND_UINT64 = 4,
  KIND_INT32 = 5,
  KIND_FIXED64 = 6,
  KIND_FIXED32 = 7,
  KIND_BOOL = 8,
  KIND_STRING = 9,
  KIND_MESSAGE = 11,
  KIND_BYTES = 12,
  KIND_UINT32 = 13,
  KIND_ENUM = 14,
  KIND_SFIXED32 = 15,
  KIND_SFIXED64 = 16,
  KIND_SINT32 = 17,
  KIND_SINT64 = 18,
  KIND_REPEATED_DOUBLE = 19,
  KIND_REPEATED_FLOAT = 20,
  KIND_REPEATED_INT64 = 21,
  KIND_REPEATED_UINT64 = 22,
  KIND_REPEATED_INT32 = 23,
  KIND_REPEATED_FIXED64 = 24,
  KIND_REPEATED_FIXED32 = 25,
  KIND_REPEATED_BOOL = 26,
  KIND_REPEATED_STRING = 27,
  KIND_REPEATED_MESSAGE = 29,
  KIND_REPEATED_BYTES = 30,
  KIND_REPEATED_UINT32 = 31,
  KIND_REPEATED_ENUM = 32,
  KIND_REPEATED_SFIXED32 = 33,
  KIND_REPEATED_SFIXED64 = 34,
  KIND_REPEATED_SINT32 = 35,
  KIND_REPEATED_SINT64 = 36
};

using enum field_kind_t;

enum class wellknown_types_t : uint8_t {
  NONE = 0,
  ANY = 1,
  TIMESTAMP = 2,
  DURATION = 3,
  FIELDMASK = 4,
  VALUE = 5,
  LISTVALUE = 6,
  STRUCT = 7,
  WRAPPER = 8
};

/**
 * @brief Factory that builds dynamic message instances from descriptor sets.
 *
 * The factory owns a descriptor pool created from provided FileDescriptorSets and can
 * spawn mutable message views (`message_value_mref`) backed by a user-supplied
 * monotonic_buffer_resource. It also exposes access to the loaded file descriptors.
 */
class dynamic_message_factory;

template <std::ranges::input_range Range>
struct sized_input_range { // NOLINT(hicpp-member-init)
  Range &range_;           // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
  std::size_t size_;

  [[nodiscard]] auto begin() const { return std::ranges::begin(range_); }
  [[nodiscard]] auto end() const { return std::ranges::end(range_); }
  [[nodiscard]] std::size_t size() const { return size_; }
};

template <typename R>
sized_input_range(R &&range, std::size_t size) -> sized_input_range<std::remove_cvref_t<R>>;

template <typename U, typename = void>
struct range_value_or_void {
  using type = void;
};
template <typename U>
struct range_value_or_void<U, std::void_t<std::ranges::range_value_t<U>>> {
  using type = std::ranges::range_value_t<U>;
};
template <typename U>
using range_value_or_void_t = typename range_value_or_void<U>::type;

struct enum_number {
  std::int32_t value = 0;
  operator std::int32_t() const { return value; } // NOLINT(hicpp-explicit-conversions)
};

struct enum_name {
  std::string_view value;
  operator std::string_view() const { return value; } // NOLINT(hicpp-explicit-conversions)
};

struct enum_numbers_span {
  std::span<std::int32_t> value;
};

template <typename T>
struct get_traits {
  using type = T;
};

template <>
struct get_traits<enum_number> {
  using type = std::int32_t;
};

template <>
struct get_traits<enum_name> {
  using type = std::string_view;
};

template <>
struct get_traits<enum_numbers_span> {
  using type = std::span<const std::int32_t>;
};

enum class dynamic_message_errc : uint8_t {
  no_error,
  no_such_field,
  no_such_value,
  invalid_field_type,
  invalid_enum_name,
  unknown_enum_value,
  wrong_message_type
};

struct dynamic_message_factory_addons {
  using traits_type = non_owning_traits;
  using string_t = std::pmr::string;
  template <typename T>
  using vector_t = std::pmr::vector<T>;

  template <typename T, typename U>
  using map_t = std::pmr::unordered_map<T, U>;

// macOS historically lacks floating-point from_chars; fall back to strto* when not available.
#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L && !defined(__APPLE__)
  static constexpr bool has_std_from_chars_float = true;
#else
  static constexpr bool has_std_from_chars_float = false;
#endif

  template <typename T>
  static T parse_default_value(std::string_view value) {
    T parsed{};
    if (value.empty()) {
      return parsed;
    }
    const char *const begin = value.data();
    const char *const end = std::to_address(value.cend());
    bool consumed_entire_input = true;
    std::errc ec{};

    if constexpr (std::is_floating_point_v<T>) {
      if constexpr (has_std_from_chars_float) {
        const auto result = std::from_chars(begin, end, parsed);
        ec = result.ec;
        consumed_entire_input = result.ptr == end;
      } else {
        std::string buffer(value);
        char *conv_end = nullptr;
        errno = 0;
        if constexpr (std::is_same_v<T, float>) {
          parsed = std::strtof(buffer.c_str(), &conv_end);
        } else {
          parsed = std::strtod(buffer.c_str(), &conv_end);
        }
        if (errno == ERANGE) {
          ec = std::errc::result_out_of_range;
          consumed_entire_input = false;
        } else if (conv_end == buffer.c_str()) {
          ec = std::errc::invalid_argument;
          consumed_entire_input = false;
        } else {
          const char *const buffer_end = std::to_address(buffer.cend());
          consumed_entire_input = (conv_end == buffer_end);
          if (!consumed_entire_input) {
            ec = std::errc::invalid_argument;
          }
        }
      }
    } else {
      const auto result = std::from_chars(begin, end, parsed);
      ec = result.ec;
      consumed_entire_input = result.ptr == end;
    }

    if (ec == std::errc::result_out_of_range) {
      throw std::out_of_range("default value out of range");
    }
    if (ec != std::errc{} || !consumed_entire_input) {
      throw std::invalid_argument("invalid default value");
    }
    return parsed;
  }

  template <typename Derived>
  struct field_descriptor {
    using type = void;
    std::variant<bool, int32_t, uint32_t, int64_t, uint64_t, double, float> default_value;
    /// @brief slot represents the index to the field memory storage of a message; all non-oneof fields use different
    /// slot, fields of the same oneof type share the same slot.
    uint32_t storage_slot = 0;
    /// @brief for oneof field, this value is the order among the same oneof field counting from 1; otherwise, it is
    /// always 1 for singular field and 0 for repeated field
    uint16_t oneof_ordinal = 0;
    field_descriptor(Derived &self, [[maybe_unused]] const auto &inherited_options) { set_default_value(self.proto()); }

    void set_default_value(const google::protobuf::FieldDescriptorProto<traits_type> &proto) {
      using enum google::protobuf::FieldDescriptorProto_::Type;
      switch (proto.type) {
      case TYPE_ENUM:
        break;
      case TYPE_DOUBLE:
        default_value = parse_default_value<double>(proto.default_value);
        break;
      case TYPE_FLOAT:
        default_value = parse_default_value<float>(proto.default_value);
        break;
      case TYPE_INT64:
      case TYPE_SFIXED64:
      case TYPE_SINT64:
        default_value = parse_default_value<int64_t>(proto.default_value);
        break;
      case TYPE_UINT64:
      case TYPE_FIXED64:
        default_value = parse_default_value<uint64_t>(proto.default_value);
        break;
      case TYPE_INT32:
      case TYPE_SFIXED32:
      case TYPE_SINT32:
        default_value = parse_default_value<int32_t>(proto.default_value);
        break;
      case TYPE_UINT32:
      case TYPE_FIXED32:
        default_value = parse_default_value<uint32_t>(proto.default_value);
        break;
      case TYPE_BOOL:
        default_value = proto.default_value == "true";
        break;
      default:
        break;
      }
    }
  };

  template <typename Derived>
  struct enum_descriptor {
    bool is_null_value = false;
    explicit enum_descriptor(Derived &derived, [[maybe_unused]] const auto &inherited_options)
        : is_null_value(derived.full_name() == "google.protobuf.NullValue") {}

    [[nodiscard]] const int32_t *value_of(const std::string_view name) const {
      const auto &proto = static_cast<const Derived *>(this)->proto();
      for (const auto &ev : proto.value) {
        if (ev.name == name) {
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          return &ev.number;
        }
      }
      return nullptr;
    }

    [[nodiscard]] std::string_view name_of(int32_t value) const {
      const auto &proto = static_cast<const Derived *>(this)->proto();
      for (const auto &ev : proto.value) {
        if (ev.number == value) {
          return ev.name;
        }
      }
      return {};
    }
  };

  template <typename Derived>
  struct oneof_descriptor {
    explicit oneof_descriptor(Derived &, [[maybe_unused]] const auto &inherited_options) {}
    [[nodiscard]] uint32_t storage_slot() const {
      return static_cast<const Derived *>(this)->fields().front().storage_slot;
    }
  };

  template <typename Derived>
  struct message_descriptor {
    uint32_t num_slots = 0;
    wellknown_types_t wellknown = wellknown_types_t::NONE;
    explicit message_descriptor(const Derived &, [[maybe_unused]] const auto &inherited_options) {}
  };

  template <typename Derived>
  struct file_descriptor {
    bool wellknown_validated_ = false;
    explicit file_descriptor([[maybe_unused]] const Derived &derived) {
      using namespace hpp::proto::file_descriptors;
      static flat_map<std::string_view, file_descriptor_pb> wellknown_type_pbs{
          {"google/protobuf/any.proto", _desc_google_protobuf_any_proto},
          {"google/protobuf/duration.proto", _desc_google_protobuf_duration_proto},
          {"google/protobuf/field_mask.proto", _desc_google_protobuf_field_mask_proto},
          {"google/protobuf/struct.proto", _desc_google_protobuf_struct_proto},
          {"google/protobuf/timestamp.proto", _desc_google_protobuf_timestamp_proto},
          {"google/protobuf/wrappers.proto", _desc_google_protobuf_wrappers_proto}};

      if (auto itr = wellknown_type_pbs.find(derived.proto().name); itr != wellknown_type_pbs.end()) {
        std::string pb;
        [[maybe_unused]] auto status = write_proto(derived.proto(), pb);
        assert(status.ok());
        wellknown_validated_ = (pb == itr->second.value);
      }
    }
  };
};

class message_value_mref;
class dynamic_message_factory {
  using descriptor_pool_t = descriptor_pool<dynamic_message_factory_addons>;
  std::pmr::monotonic_buffer_resource memory_resource_;
  descriptor_pool_t pool_;

  void setup_storage_slots() {
    for (auto &message : pool_.messages()) {
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

  void setup_wellknown_types() {
    const static std::pair<const char *, wellknown_types_t> wellknown_mappings[] = {
        {"google.protobuf.Any", wellknown_types_t::ANY},
        {"google.protobuf.Timestamp", wellknown_types_t::TIMESTAMP},
        {"google.protobuf.Duration", wellknown_types_t::DURATION},
        {"google.protobuf.FieldMask", wellknown_types_t::FIELDMASK},
        {"google.protobuf.Value", wellknown_types_t::VALUE},
        {"google.protobuf.ListValue", wellknown_types_t::LISTVALUE},
        {"google.protobuf.Struct", wellknown_types_t::STRUCT},
        {"google.protobuf.DoubleValue", wellknown_types_t::WRAPPER},
        {"google.protobuf.FloatValue", wellknown_types_t::WRAPPER},
        {"google.protobuf.Int64Value", wellknown_types_t::WRAPPER},
        {"google.protobuf.UInt64Value", wellknown_types_t::WRAPPER},
        {"google.protobuf.Int32Value", wellknown_types_t::WRAPPER},
        {"google.protobuf.UInt32Value", wellknown_types_t::WRAPPER},
        {"google.protobuf.BoolValue", wellknown_types_t::WRAPPER},
        {"google.protobuf.StringValue", wellknown_types_t::WRAPPER},
        {"google.protobuf.BytesValue", wellknown_types_t::WRAPPER},
    };

    for (auto [name, id] : wellknown_mappings) {
      if (auto *desc = pool_.get_message_descriptor(name); desc != nullptr) {
        if (desc->parent_file()->wellknown_validated_) {
          desc->wellknown = id;
        }
      }
    }
  }

  void setup_enum_field_default_value() {
    using enum google::protobuf::FieldDescriptorProto_::Type;
    for (auto &field : pool_.fields()) {
      const auto &proto = field.proto();
      if (proto.type == TYPE_ENUM && !proto.default_value.empty()) {
        field.default_value = *field.enum_field_type_descriptor()->value_of(proto.default_value);
      }
    }
  }

  void init() {
    setup_storage_slots();
    setup_wellknown_types();
    setup_enum_field_default_value();
  }

public:
  using FileDescriptorSet = google::protobuf::FileDescriptorSet<dynamic_message_factory_addons::traits_type>;
  using field_descriptor_t = typename descriptor_pool_t::field_descriptor_t;
  using enum_descriptor_t = typename descriptor_pool_t::enum_descriptor_t;
  using oneof_descriptor_t = typename descriptor_pool_t::oneof_descriptor_t;
  using message_descriptor_t = typename descriptor_pool_t::message_descriptor_t;
  using file_descriptor_t = typename descriptor_pool_t::file_descriptor_t;

  /// enable to pass dynamic_message_factory as an option to read_json()/write_json()
  using option_type = std::reference_wrapper<dynamic_message_factory>;

  explicit dynamic_message_factory(FileDescriptorSet &&proto_files, std::pmr::monotonic_buffer_resource &mr)
      : pool_(std::move(proto_files), mr) {
    init();
  }

  template <std::ranges::forward_range Range>
    requires std::same_as<std::ranges::range_value_t<Range>, file_descriptor_pb>
  explicit dynamic_message_factory(Range &&descs, auto &&...memory_resource_init_args)
      : memory_resource_(std::forward<decltype(memory_resource_init_args)>(memory_resource_init_args)...),
        pool_(descriptor_pool_t::make_file_descriptor_set(std::forward<Range>(descs), alloc_from(memory_resource_))
                  .value(),
              memory_resource_) {
    init();
  }

  template <std::size_t N>
  explicit dynamic_message_factory(const distinct_file_descriptor_pb_array<N> &descs,
                                   auto &&...memory_resource_init_args)
      : dynamic_message_factory(std::span<file_descriptor_pb>(std::data(descs), std::size(descs)),
                                distinct_file_tag_t{},
                                std::forward<decltype(memory_resource_init_args)>(memory_resource_init_args)...) {}

  explicit dynamic_message_factory(std::span<file_descriptor_pb> unique_descs, distinct_file_tag_t tag,
                                   auto &&...memory_resource_init_args)
      : memory_resource_(std::forward<decltype(memory_resource_init_args)>(memory_resource_init_args)...),
        pool_(descriptor_pool_t::make_file_descriptor_set(unique_descs, tag, alloc_from(memory_resource_)).value(),
              memory_resource_) {
    init();
  }

  std::optional<message_value_mref> get_message(std::string_view name, std::pmr::monotonic_buffer_resource &mr) const;
  [[nodiscard]] std::span<const file_descriptor_t> files() const { return pool_.files(); }
};

using field_descriptor_t = dynamic_message_factory::field_descriptor_t;
using enum_descriptor_t = dynamic_message_factory::enum_descriptor_t;
using oneof_descriptor_t = dynamic_message_factory::oneof_descriptor_t;
using message_descriptor_t = dynamic_message_factory::message_descriptor_t;

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

namespace concepts {
template <typename T>
concept const_field_ref = !T::is_mutable && requires { T::field_kind; };

template <typename T>
concept mutable_field_ref = T::is_mutable && requires { T::field_kind; };

template <typename T>
concept contiguous_std_byte_range =
    std::ranges::contiguous_range<T> && std::same_as<std::ranges::range_value_t<T>, std::byte>;
}; // namespace concepts

inline auto enum_numbers_to_names(const enum_descriptor_t &descriptor, std::span<const std::int32_t> numbers) {
  return std::views::transform(numbers, [&descriptor](std::int32_t v) { return descriptor.name_of(v); });
}

using enum_names_view = decltype(enum_numbers_to_names(std::declval<const enum_descriptor_t &>(),
                                                       std::declval<std::span<const std::int32_t>>()));

template <typename Range>
struct enum_numbers_range {
  using is_enum_numbers_range = void;
  const Range &value; // NOLINT
};

template <typename T>
  requires(std::ranges::sized_range<T> && std::is_convertible_v<range_value_or_void_t<T>, std::int32_t>)
enum_numbers_range(const T &v) -> enum_numbers_range<T>;

template <typename Range>
struct enum_names_range {
  using is_enum_names_range = void;
  const Range &value; // NOLINT
};

template <typename T>
  requires(std::ranges::sized_range<T> && std::is_convertible_v<range_value_or_void_t<T>, std::string_view>)
enum_names_range(const T &v) -> enum_names_range<T>;

/**
 * @brief Untyped, read-only reference to a single field in a dynamic message.
 *
 * This wrapper provides presence checks and type-erased access via `get<T>()`, which
 * dispatches to the underlying typed field view if the requested type matches.
 */
class field_cref {
  const field_descriptor_t *descriptor_;
  const value_storage *storage_;
  friend class field_mref;

public:
  field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

  field_cref(const field_cref &) noexcept = default;
  field_cref(field_cref &&) noexcept = default;
  field_cref &operator=(const field_cref &) noexcept = default;
  field_cref &operator=(field_cref &&) noexcept = default;
  ~field_cref() noexcept = default;

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] field_kind_t field_kind() const noexcept {
    // map TYPE_GROUP to TYPE_MESSAGE
    using enum google::protobuf::FieldDescriptorProto_::Type;
    auto base_type = descriptor().proto().type == TYPE_GROUP ? TYPE_MESSAGE : descriptor().proto().type;
    return static_cast<field_kind_t>(std::to_underlying(base_type) +
                                     (18 * static_cast<int>(descriptor().is_repeated())));
  }

  [[nodiscard]] bool explicit_presence() const noexcept { return descriptor_->explicit_presence(); }

  [[nodiscard]] bool has_value() const noexcept {
    return descriptor().is_repeated() ? (storage_->of_repeated_uint64.size > 0)
                                      : (storage_->of_int64.selection == descriptor().oneof_ordinal);
  }

  /// if the field is part of an oneof fields, return the active field index of the oneof. If the returned
  /// value is smaller than 0, it means the oneof does not contains any value.
  [[nodiscard]] std::int32_t active_oneof_index() const {
    return static_cast<std::int32_t>(storage_->of_int64.selection + descriptor().storage_slot) -
           descriptor().oneof_ordinal;
  }

  template <typename T>
  [[nodiscard]] std::optional<T> to() const noexcept {
    if (T::field_kind == field_kind()) {
      return T(*descriptor_, *storage_);
    }
    return std::nullopt;
  }

  auto visit(auto &&v) const;
  template <typename T>
  [[nodiscard]] auto get() const noexcept -> std::expected<typename get_traits<T>::type, dynamic_message_errc> {
    return visit([](auto cref) -> std::expected<typename get_traits<T>::type, dynamic_message_errc> {
      if constexpr (requires { cref.template get<T>(); }) {
        return cref.template get<T>();
      } else {
        return std::unexpected(dynamic_message_errc::invalid_field_type);
      }
    });
  }
}; // class field_cref

class field_mref {
  const field_descriptor_t *descriptor_;
  value_storage *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

public:
  /**
   * @brief Mutable, untyped reference to a single field in a dynamic message.
   *
   * Offers type-erased mutation via `set<T>()` (copying into message-owned storage)
   * or `adopt<T>()` (aliasing caller-provided storage where supported), presence checks,
   * and conversion to a read-only `field_cref`.
   */
  field_mref(const field_descriptor_t &descriptor, value_storage &storage,
             std::pmr::monotonic_buffer_resource &mr) noexcept
      : descriptor_(&descriptor), storage_(&storage), memory_resource_(&mr) {}

  field_mref(const field_mref &) noexcept = default;
  field_mref(field_mref &&) noexcept = default;
  field_mref &operator=(const field_mref &) noexcept = default;
  field_mref &operator=(field_mref &&) noexcept = default;
  ~field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  void reset() noexcept { storage_->reset(); }
  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] field_kind_t field_kind() const noexcept { return cref().field_kind(); }

  [[nodiscard]] bool explicit_presence() const noexcept { return descriptor_->explicit_presence(); }
  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }

  template <typename T>
  [[nodiscard]] std::optional<T> to() const noexcept {
    if (T::field_kind == field_kind()) {
      return T(*descriptor_, *storage_, *memory_resource_);
    }
    return std::nullopt;
  }

  [[nodiscard]] field_cref cref() const noexcept { return {*descriptor_, *storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator field_cref() const noexcept { return cref(); }
  auto visit(auto &&v) const;
  void alias_from(const field_mref &other) const noexcept {
    assert(this->descriptor_ == other.descriptor_);
    *storage_ = *other.storage_;
  }
  void clone_from(const field_cref &other) const noexcept;

  template <typename T>
  [[nodiscard]] auto get() const noexcept {
    return cref().get<T>();
  }

  template <typename T>
  [[nodiscard]] auto set(T v) const noexcept -> std::expected<void, dynamic_message_errc> {
    return visit([&v](auto mref) -> std::expected<void, dynamic_message_errc> {
      using mref_type = decltype(mref);
      if constexpr (mref_type::template settable_from_v<T>) {
        if constexpr (requires {
                        { mref.set(v) } -> std::same_as<void>;
                      }) {
          mref.set(v);
          return {};
        } else {
          return mref.set(v);
        }
      } else {
        return std::unexpected(dynamic_message_errc::invalid_field_type);
      }
    });
  }

  template <typename T>
  [[nodiscard]] auto adopt(T v) const noexcept -> std::expected<void, dynamic_message_errc> {
    return visit([&v](auto mref) -> std::expected<void, dynamic_message_errc> {
      if constexpr (requires { mref.adopt(v); }) {
        mref.adopt(v);
        return {};
      } else {
        return std::unexpected(dynamic_message_errc::invalid_field_type);
      }
    });
  }

  void set_null() noexcept;
}; // class field_mref

template <typename T>
struct value_type_identity {
  using value_type = T;
};
/**
 * @brief Typed, read-only view of a scalar (non-enum) field.
 *
 * Provides presence checks and `value()` access returning the decoded native type.
 */
template <typename T, field_kind_t Kind>
class scalar_field_cref {
public:
  using encode_type = T;
  using value_type = typename std::conditional_t<concepts::varint<T>, T, value_type_identity<T>>::value_type;
  using storage_type = scalar_storage_base<value_type>;
  constexpr static field_kind_t field_kind = Kind;
  constexpr static bool is_mutable = false;
  constexpr static bool is_repeated = false;

  template <typename U>
  static constexpr bool gettable_to_v = std::same_as<U, value_type>;

  scalar_field_cref(const field_descriptor_t &descriptor, const storage_type &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

  scalar_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      : scalar_field_cref(descriptor, reinterpret_cast<const storage_type &>(storage)) {}

  scalar_field_cref(const scalar_field_cref &) noexcept = default;
  scalar_field_cref(scalar_field_cref &&) noexcept = default;
  scalar_field_cref &operator=(const scalar_field_cref &) noexcept = default;
  scalar_field_cref &operator=(scalar_field_cref &&) noexcept = default;
  ~scalar_field_cref() noexcept = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->selection == descriptor().oneof_ordinal; }
  [[nodiscard]] value_type value() const noexcept {
    if (descriptor().explicit_presence() && !has_value()) {
      return std::get<value_type>(descriptor_->default_value);
    }
    return storage_->content;
  }

  template <typename U>
  [[nodiscard]] std::expected<typename get_traits<U>::type, dynamic_message_errc> get() const noexcept {
    if constexpr (std::same_as<U, value_type>) {
      return value();
    } else {
      return std::unexpected(dynamic_message_errc::invalid_field_type);
    }
  }

  // [[nodiscard]] value_type operator*() const noexcept { return value(); }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

private:
  template <typename, field_kind_t>
  friend class scalar_field_mref;

  const field_descriptor_t *descriptor_;
  const storage_type *storage_;
};

/**
 * @brief Typed, mutable view of a scalar (non-enum) field.
 *
 * Supports `set()`/`reset()` along with read-only access via `cref()`.
 */
template <typename T, field_kind_t Kind>
class scalar_field_mref {
public:
  using encode_type = T;
  using value_type = typename std::conditional_t<concepts::varint<T>, T, value_type_identity<T>>::value_type;
  using storage_type = scalar_storage_base<value_type>;
  using cref_type = scalar_field_cref<T, Kind>;

  constexpr static field_kind_t field_kind = Kind;
  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = false;

  template <typename U>
  static constexpr bool settable_from_v = std::same_as<U, value_type>;

  scalar_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                    std::pmr::monotonic_buffer_resource &) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      : descriptor_(&descriptor), storage_(reinterpret_cast<storage_type *>(&storage)) {}

  scalar_field_mref(const scalar_field_mref &) noexcept = default;
  scalar_field_mref(scalar_field_mref &&) noexcept = default;
  scalar_field_mref &operator=(const scalar_field_mref &) noexcept = default;
  scalar_field_mref &operator=(scalar_field_mref &&) noexcept = default;
  ~scalar_field_mref() noexcept = default;
  void set(T v) const noexcept {
    storage_->content = v;
    storage_->selection = descriptor_->oneof_ordinal;
  }

  void alias_from(const scalar_field_cref<T, Kind> &other) const noexcept { set(other.value()); }
  void clone_from(scalar_field_cref<T, Kind> other) const noexcept { set(other.value()); }

  [[nodiscard]] scalar_field_cref<T, Kind> cref() const noexcept { return {*descriptor_, *storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator scalar_field_cref<T, Kind>() const noexcept { return cref(); }

  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }
  // [[nodiscard]] value_type operator*() const noexcept { return cref().operator*(); }
  [[nodiscard]] value_type value() const noexcept { return cref().value(); }
  void reset() noexcept { storage_->selection = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

private:
  const field_descriptor_t *descriptor_;
  storage_type *storage_;
};

class string_field_cref {
public:
  using encode_type = std::string_view;
  using value_type = std::string_view;
  using storage_type = string_storage_t;
  constexpr static field_kind_t field_kind = KIND_STRING;
  constexpr static bool is_mutable = false;
  constexpr static bool is_repeated = false;

  template <typename U>
  static constexpr bool gettable_to_v = std::same_as<U, std::string_view>;

  string_field_cref(const field_descriptor_t &descriptor, const string_storage_t &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}
  string_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : string_field_cref(descriptor, storage.of_string) {}

  string_field_cref(const string_field_cref &) noexcept = default;
  string_field_cref(string_field_cref &&) noexcept = default;
  string_field_cref &operator=(const string_field_cref &) noexcept = default;
  string_field_cref &operator=(string_field_cref &&) noexcept = default;
  ~string_field_cref() noexcept = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->selection == descriptor().oneof_ordinal; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }

  [[nodiscard]] std::string_view value() const noexcept {
    if (descriptor().explicit_presence() && !has_value()) {
      return descriptor_->proto().default_value;
    }
    return {storage_->content, storage_->size};
  }

  template <typename U>
  [[nodiscard]] std::expected<typename get_traits<U>::type, dynamic_message_errc> get() const noexcept {
    if constexpr (std::same_as<U, std::string_view>) {
      return value();
    } else {
      return std::unexpected(dynamic_message_errc::invalid_field_type);
    }
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

private:
  friend class string_field_mref;
  const field_descriptor_t *descriptor_;
  const string_storage_t *storage_;
};

/**
 * @brief Mutable view of a singular string field.
 *
 * - `set` copies the provided data into message-owned storage allocated from the associated
 *   monotonic_buffer_resource.
 * - `adopt` aliases external storage; the caller must ensure the lifetime of the referenced
 *   characters outlives the message.
 */
class string_field_mref {
public:
  using encode_type = std::string_view;
  using value_type = std::string_view;
  using storage_type = string_storage_t;
  using cref_type = string_field_cref;
  constexpr static field_kind_t field_kind = KIND_STRING;
  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = false;

  template <typename U>
  static constexpr bool settable_from_v = std::convertible_to<U, std::string_view>;

  string_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                    std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : descriptor_(&descriptor), storage_(&storage.of_string), memory_resource_(&mr) {}

  string_field_mref(const string_field_mref &) noexcept = default;
  string_field_mref(string_field_mref &&) noexcept = default;
  string_field_mref &operator=(const string_field_mref &) noexcept = default;
  string_field_mref &operator=(string_field_mref &&) noexcept = default;
  ~string_field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  void adopt(std::string_view v) const noexcept {
    storage_->content = v.data();
    storage_->size = static_cast<uint32_t>(v.size());
    storage_->selection = descriptor_->oneof_ordinal;
  }

  void set(std::string_view v) const noexcept {
    auto *dest = static_cast<char *>(memory_resource_->allocate(v.size(), 1));
    std::ranges::copy(v, dest);
    storage_->content = dest;
    storage_->size = static_cast<uint32_t>(v.size());
    storage_->selection = descriptor_->oneof_ordinal;
  }

  void alias_from(const cref_type &other) const noexcept { *storage_ = *other.storage_; }

  void clone_from(const cref_type &other) const noexcept {
    if (other.has_value()) {
      set(other.value());
    } else {
      reset();
    }
  }

  [[nodiscard]] string_field_cref cref() const noexcept { return string_field_cref{*descriptor_, *storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator string_field_cref() const noexcept { return cref(); }

  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }
  [[nodiscard]] std::string_view value() const noexcept { return cref().value(); }

  void reset() const noexcept {
    storage_->size = 0;
    storage_->selection = 0;
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

private:
  const field_descriptor_t *descriptor_;
  string_storage_t *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

  [[nodiscard]] bool is_default_value(std::string_view v) const noexcept {
    return std::ranges::equal(v, descriptor_->proto().default_value);
  }
};

class bytes_field_cref {
public:
  using encode_type = bytes_view;
  using value_type = bytes_view;
  using storage_type = bytes_storage_t;
  constexpr static field_kind_t field_kind = KIND_BYTES;
  constexpr static bool is_mutable = false;
  constexpr static bool is_repeated = false;

  template <typename U>
  static constexpr bool gettable_to_v = std::same_as<U, bytes_view>;

  bytes_field_cref(const field_descriptor_t &descriptor, const bytes_storage_t &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}
  bytes_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : bytes_field_cref(descriptor, storage.of_bytes) {}

  bytes_field_cref(const bytes_field_cref &) noexcept = default;
  bytes_field_cref(bytes_field_cref &&) noexcept = default;
  bytes_field_cref &operator=(const bytes_field_cref &) noexcept = default;
  bytes_field_cref &operator=(bytes_field_cref &&) noexcept = default;
  ~bytes_field_cref() noexcept = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->selection == descriptor().oneof_ordinal; }
  [[nodiscard]] bytes_view value() const noexcept {
    if (descriptor().explicit_presence() && !has_value()) {
      const auto &default_value = descriptor_->proto().default_value;
      // Avoid reinterpret_cast by using std::as_bytes to obtain a span of bytes
      auto sval = std::span<const char>(default_value.data(), default_value.size());
      auto bspan = std::as_bytes(sval);
      return {bspan.data(), bspan.size()};
    }
    return {storage_->content, storage_->size};
  }

  template <typename U>
  [[nodiscard]] std::expected<typename get_traits<U>::type, dynamic_message_errc> get() const noexcept {
    if constexpr (std::same_as<U, bytes_view>) {
      return value();
    } else {
      return std::unexpected(dynamic_message_errc::invalid_field_type);
    }
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

private:
  friend class bytes_field_mref;
  const field_descriptor_t *descriptor_;
  const bytes_storage_t *storage_;
};

/**
 * @brief Mutable view of a singular bytes field.
 *
 * - `set` copies the bytes into message-owned memory allocated from the associated
 *   monotonic_buffer_resource.
 * - `adopt` aliases an external buffer; the caller must keep the source buffer alive
 *   for as long as the message references it.
 */
class bytes_field_mref {
public:
  using encode_type = bytes_view;
  using value_type = bytes_view;
  using storage_type = bytes_storage_t;
  using cref_type = bytes_field_cref;
  constexpr static field_kind_t field_kind = KIND_BYTES;
  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = false;

  template <typename U>
  static constexpr bool settable_from_v = concepts::contiguous_std_byte_range<U>;

  bytes_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                   std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : descriptor_(&descriptor), storage_(&storage.of_bytes), memory_resource_(&mr) {}

  bytes_field_mref(const bytes_field_mref &) noexcept = default;
  bytes_field_mref(bytes_field_mref &&) noexcept = default;
  bytes_field_mref &operator=(const bytes_field_mref &) noexcept = default;
  bytes_field_mref &operator=(bytes_field_mref &&) noexcept = default;
  ~bytes_field_mref() = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  void adopt(std::span<const std::byte> v) const noexcept {
    storage_->content = v.data();
    storage_->size = static_cast<uint32_t>(v.size());
    storage_->selection = descriptor_->oneof_ordinal;
  }

  void set(concepts::contiguous_std_byte_range auto const &v) const noexcept {
    auto *dest = static_cast<std::byte *>(memory_resource_->allocate(v.size(), 1));
    std::copy(v.begin(), v.end(), dest);
    storage_->content = dest;
    storage_->size = static_cast<uint32_t>(v.size());
    storage_->selection = descriptor_->oneof_ordinal;
  }

  void alias_from(const cref_type &other) const noexcept { *storage_ = *other.storage_; }

  void clone_from(const cref_type &other) const noexcept {
    if (other.has_value()) {
      set(other.value());
    } else {
      reset();
    }
  }

  [[nodiscard]] cref_type cref() const noexcept { return {*descriptor_, *storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator bytes_field_cref() const noexcept { return cref(); }

  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }
  [[nodiscard]] bytes_view value() const noexcept { return cref().value(); }

  void reset() const noexcept {
    storage_->size = 0;
    storage_->selection = 0;
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

private:
  const field_descriptor_t *descriptor_;
  bytes_storage_t *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

  // NOLINTNEXTLINE(performance-unnecessary-value-param)
  [[nodiscard]] bool is_default_value(const bytes_view v) const noexcept {
    auto default_value = descriptor_->proto().default_value;
    return v.size() == default_value.size() && std::memcmp(v.data(), default_value.data(), v.size()) != 0;
  }
};

class string_value_mref {
public:
  using traits_type = std::string_view::traits_type;
  using value_type = std::string_view::value_type;
  using pointer = std::string_view::pointer;
  using const_pointer = std::string_view::const_pointer;
  using reference = std::string_view::reference;
  using const_reference = std::string_view::const_reference;
  using const_iterator = std::string_view::const_iterator;
  using iterator = std::string_view::iterator;
  using const_reverse_iterator = std::string_view::const_reverse_iterator;
  using reverse_iterator = std::string_view::reverse_iterator;
  using size_type = std::string_view::size_type;
  using difference_type = std::string_view::difference_type;
  using char_type = value_type;

  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = false;

  static constexpr size_type npos = std::string_view::npos;
  string_value_mref(std::string_view &data, std::pmr::monotonic_buffer_resource &mr) noexcept
      : data_(&data), memory_resource_(&mr) {}
  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  void adopt(std::string_view v) const noexcept { *data_ = v; }

  void set(std::string_view v) const noexcept {
    auto *dest = static_cast<char *>(memory_resource_->allocate(v.size(), 1));
    std::ranges::copy(v, dest);
    adopt(std::string_view{dest, v.size()});
  }

  void clone_from(std::string_view v) const noexcept { set(v); }

  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  operator std::string_view() const noexcept { return *data_; }

private:
  std::string_view *data_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
};

class bytes_value_mref {
public:
  constexpr static bool is_mutable = true;
  using view_type = hpp::proto::bytes_view;
  using element_type = view_type::element_type;
  using value_type = view_type::value_type;
  using size_type = view_type::size_type;
  using difference_type = view_type::difference_type;
  using pointer = view_type::pointer;
  using const_pointer = view_type::const_pointer;
  using reference = view_type::reference;
  using const_reference = view_type::const_reference;
  using iterator = view_type::iterator;
  using const_iterator = view_type::const_iterator;
  using reverse_iterator = view_type::reverse_iterator;
  using const_reverse_iterator = view_type::const_reverse_iterator;

  bytes_value_mref(hpp::proto::bytes_view &data, std::pmr::monotonic_buffer_resource &mr) noexcept
      : data_(&data), memory_resource_(&mr) {}
  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  void adopt(const hpp::proto::bytes_view &v) const noexcept { *data_ = v; }

  void set(concepts::contiguous_std_byte_range auto const &v) const noexcept {
    auto *dest = static_cast<std::byte *>(memory_resource_->allocate(v.size(), 1));
    std::copy(v.begin(), v.end(), dest);
    adopt(hpp::proto::bytes_view{dest, v.size()});
  }

  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  operator hpp::proto::bytes_view() const noexcept { return *data_; }

private:
  hpp::proto::bytes_view *data_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
};

class enum_value_cref {
public:
  using is_enum_value_ref = void;
  constexpr static bool is_mutable = false;

  enum_value_cref(const enum_descriptor_t &descriptor, int32_t number) noexcept
      : descriptor_(&descriptor), number_(number) {}
  enum_value_cref(const enum_value_cref &) noexcept = default;
  enum_value_cref(enum_value_cref &&) noexcept = default;
  enum_value_cref &operator=(const enum_value_cref &) noexcept = default;
  enum_value_cref &operator=(enum_value_cref &&) noexcept = default;
  ~enum_value_cref() noexcept = default;

  [[nodiscard]] explicit operator int32_t() const noexcept { return number_; }

  [[nodiscard]] int32_t number() const noexcept { return number_; }
  /**
   * @brief Returns the enum value's symbolic name (empty if schema lacks this number).
   */
  [[nodiscard]] std::string_view name() const noexcept { return descriptor_->name_of(number_); }
  [[nodiscard]] const enum_descriptor_t &descriptor() const noexcept { return *descriptor_; }

private:
  const enum_descriptor_t *descriptor_;
  int32_t number_;
};

class enum_value_mref {
  const enum_descriptor_t *descriptor_;
  int32_t *number_;

public:
  /**
   * @brief Mutable view of a single enum value, allowing numeric assignment and name lookup.
   */
  using is_enum_value_ref = void;
  using cref_type = enum_value_cref;
  constexpr static bool is_mutable = true;

  enum_value_mref(const enum_descriptor_t &descriptor, int32_t &number) noexcept
      : descriptor_(&descriptor), number_(&number) {}
  enum_value_mref(const enum_value_mref &) noexcept = default;
  enum_value_mref(enum_value_mref &&) noexcept = default;
  enum_value_mref &operator=(const enum_value_mref &) noexcept = default;
  enum_value_mref &operator=(enum_value_mref &&) noexcept = default;
  ~enum_value_mref() noexcept = default;

  [[nodiscard]] enum_value_cref cref() const noexcept {
    return enum_value_cref{*descriptor_, *number_};
  }

  void set(int32_t number) const noexcept { *number_ = number; }

  [[nodiscard]] const int32_t *number_by_name(const char *name) const noexcept { return descriptor_->value_of(name); }
  [[nodiscard]] const int32_t *number_by_name(std::string_view name) const noexcept {
    return descriptor_->value_of(name);
  }

  explicit operator int32_t() const noexcept { return *number_; }
  [[nodiscard]] int32_t number() const noexcept { return *number_; }
  /**
   * @brief Returns the enum value's symbolic name (empty if schema lacks this number).
   */
  [[nodiscard]] std::string_view name() const noexcept { return cref().name(); }

  [[nodiscard]] const enum_descriptor_t &descriptor() const noexcept { return *descriptor_; }
};

class enum_field_cref {
public:
  using encode_type = vint64_t;
  using value_type = enum_value_cref;
  using storage_type = scalar_storage_base<int32_t>;
  constexpr static field_kind_t field_kind = KIND_ENUM;
  constexpr static bool is_mutable = false;
  constexpr static bool is_repeated = false;

  template <typename U>
  static constexpr bool gettable_to_v =
      std::same_as<U, enum_number> || std::same_as<U, enum_name> || std::same_as<U, enum_value_cref>;

  enum_field_cref(const field_descriptor_t &descriptor, const storage_type &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}
  enum_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : enum_field_cref(descriptor, storage.of_int32) {}

  enum_field_cref(const enum_field_cref &) noexcept = default;
  enum_field_cref(enum_field_cref &&) noexcept = default;
  enum_field_cref &operator=(const enum_field_cref &) noexcept = default;
  enum_field_cref &operator=(enum_field_cref &&) noexcept = default;

  ~enum_field_cref() = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->selection == descriptor().oneof_ordinal; }
  [[nodiscard]] enum_value_cref value() const noexcept {
    if (descriptor().explicit_presence() && !has_value()) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
      const_cast<scalar_storage_base<int32_t> *>(storage_)->content = std::get<int32_t>(descriptor_->default_value);
    }
    return {enum_descriptor(), storage_->content};
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

  template <typename U>
  [[nodiscard]] std::expected<typename get_traits<U>::type, dynamic_message_errc> get() const noexcept {
    if constexpr (std::same_as<U, enum_number>) {
      return number();
    } else if constexpr (std::same_as<U, enum_name>) {
      if (name().empty()){
        return std::unexpected(dynamic_message_errc::unknown_enum_value);
      }
      return name();
    } else if constexpr (std::same_as<U, enum_value_cref>) {
      return value();
    } else {
      return std::unexpected(dynamic_message_errc::invalid_field_type);
    }
  }
  [[nodiscard]] const enum_descriptor_t &enum_descriptor() const noexcept {
    return *descriptor_->enum_field_type_descriptor();
  }

  [[nodiscard]] std::int32_t number() const {
    bool is_default = descriptor().explicit_presence() && !has_value();
    return is_default ? std::get<int32_t>(descriptor_->default_value) : storage_->content;
  }

  /**
   * @brief Returns the enum value's symbolic name (empty if schema lacks this number).
   */
  [[nodiscard]] std::string_view name() const { return enum_descriptor().name_of(number()); }

private:
  friend class enum_field_mref;
  const field_descriptor_t *descriptor_;
  const scalar_storage_base<int32_t> *storage_;
};

class enum_field_mref {
public:
  using encode_type = vint64_t;
  using value_type = enum_value_cref;
  using storage_type = scalar_storage_base<int32_t>;
  using cref_type = enum_field_cref;
  constexpr static field_kind_t field_kind = KIND_ENUM;
  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = false;

  template <typename U>
  static constexpr bool settable_from_v = std::same_as<U, enum_number> || std::same_as<U, enum_name>;

  enum_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                  std::pmr::monotonic_buffer_resource &) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : descriptor_(&descriptor), storage_(&storage.of_int32) {}

  enum_field_mref(const enum_field_mref &) noexcept = default;
  enum_field_mref(enum_field_mref &&) noexcept = default;
  enum_field_mref &operator=(const enum_field_mref &) noexcept = default;
  enum_field_mref &operator=(enum_field_mref &&) noexcept = default;
  ~enum_field_mref() noexcept = default;

  void alias_from(const cref_type &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    *storage_ = *other.storage_;
  }

  void clone_from(const cref_type &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    alias_from(other);
  }

  [[nodiscard]] enum_field_cref cref() const noexcept { return enum_field_cref{*descriptor_, *storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator enum_field_cref() const noexcept { return cref(); }

  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }
  [[nodiscard]] enum_value_mref value() const noexcept {
    if (descriptor().explicit_presence() && !has_value()) {
      storage_->content = std::get<int32_t>(descriptor_->default_value);
    }
    return {*descriptor_->enum_field_type_descriptor(), storage_->content};
  }

  [[nodiscard]] enum_value_mref emplace() noexcept {
    storage_->selection = descriptor_->oneof_ordinal;
    return {*descriptor_->enum_field_type_descriptor(), storage_->content};
  }

  void reset() noexcept { storage_->selection = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const enum_descriptor_t &enum_descriptor() const noexcept {
    return *descriptor_->enum_field_type_descriptor();
  }

  [[nodiscard]] std::int32_t number() const {
    return descriptor().explicit_presence() && !has_value() ? std::get<int32_t>(descriptor_->default_value)
                                                            : storage_->content;
  }
  /**
   * @brief Returns the enum value's symbolic name (empty if schema lacks this number).
   */
  [[nodiscard]] std::string_view name() const { return cref().name(); }

  void set(enum_number number) const {
    storage_->content = number.value;
    storage_->selection = descriptor_->oneof_ordinal;
  }

  [[nodiscard]] std::expected<void, dynamic_message_errc> set(enum_name name) const {
    const auto *pval = enum_descriptor().value_of(name.value);
    if (pval == nullptr) [[unlikely]] {
      return std::unexpected(dynamic_message_errc::invalid_enum_name);
    }

    set(enum_number{*pval});
    return {};
  }

private:
  const field_descriptor_t *descriptor_;
  scalar_storage_base<int32_t> *storage_;
};

template <typename T, field_kind_t Kind>
class repeated_scalar_field_cref : public std::ranges::view_interface<repeated_scalar_field_cref<T, Kind>> {

public:
  using encode_type = T;
  using value_type = typename std::conditional_t<concepts::varint<T>, T, value_type_identity<T>>::value_type;
  using storage_type = repeated_storage_base<value_type>;
  using difference_type = std::ptrdiff_t;
  using size_type = std::size_t;
  constexpr static field_kind_t field_kind = Kind;
  constexpr static bool is_mutable = false;
  constexpr static bool is_repeated = true;

  template <typename U>
  static constexpr bool gettable_to_v = std::same_as<U, std::span<const value_type>>;

  repeated_scalar_field_cref(const field_descriptor_t &descriptor, const storage_type &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}
  repeated_scalar_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      : repeated_scalar_field_cref(descriptor, reinterpret_cast<const storage_type &>(storage)) {}

  repeated_scalar_field_cref(const repeated_scalar_field_cref &) noexcept = default;
  repeated_scalar_field_cref(repeated_scalar_field_cref &&) noexcept = default;
  repeated_scalar_field_cref &operator=(const repeated_scalar_field_cref &) noexcept = default;
  repeated_scalar_field_cref &operator=(repeated_scalar_field_cref &&) noexcept = default;
  ~repeated_scalar_field_cref() noexcept = default;

  value_type operator[](std::size_t index) const noexcept {
    assert(index < storage_->size);
    return *std::next(storage_->content, static_cast<std::ptrdiff_t>(index));
  }

  [[nodiscard]] value_type at(std::size_t index) const {
    if (index < storage_->size) {
      return *std::next(storage_->content, static_cast<std::ptrdiff_t>(index));
    }
    throw std::out_of_range("");
  }

  [[nodiscard]] bool empty() const noexcept { return storage_->size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] const value_type *data() const noexcept { return storage_->content; }
  [[nodiscard]] const value_type *begin() const noexcept { return storage_->content; }
  [[nodiscard]] const value_type *end() const noexcept {
    return std::next(storage_->content, static_cast<std::ptrdiff_t>(storage_->size));
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

  template <typename U>
  [[nodiscard]] std::expected<typename get_traits<U>::type, dynamic_message_errc> get() const noexcept {
    if constexpr (std::same_as<U, std::span<const value_type>>) {
      return std::span<const value_type>{storage_->content, storage_->size};
    } else {
      return std::unexpected(dynamic_message_errc::invalid_field_type);
    }
  }

private:
  template <typename, field_kind_t>
  friend class repeated_scalar_field_mref;
  const field_descriptor_t *descriptor_;
  const storage_type *storage_;
};

/**
 * @brief Mutable view over a repeated scalar field.
 *
 * `set` copies a range of values into message-owned storage (resizing as needed), while
 * `adopt` (where provided) points the field at caller-managed storage. Supports resize
 * and random-access iteration over elements.
 */
template <typename T, field_kind_t Kind>
class repeated_scalar_field_mref : public std::ranges::view_interface<repeated_scalar_field_mref<T, Kind>> {

public:
  using encode_type = T;
  using value_type = typename std::conditional_t<concepts::varint<T>, T, value_type_identity<T>>::value_type;
  using storage_type = repeated_storage_base<value_type>;
  using difference_type = std::ptrdiff_t;
  using reference = value_type &;
  using size_type = std::size_t;
  using cref_type = repeated_scalar_field_cref<T, Kind>;
  constexpr static field_kind_t field_kind = Kind;
  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = true;

  template <typename U>
  static constexpr bool settable_from_v =
      std::ranges::sized_range<U> && std::is_same_v<range_value_or_void_t<U>, value_type>;

  repeated_scalar_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                             std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      : descriptor_(&descriptor), storage_(reinterpret_cast<storage_type *>(&storage)), memory_resource_(&mr) {}

  repeated_scalar_field_mref(const repeated_scalar_field_mref &) noexcept = default;
  repeated_scalar_field_mref(repeated_scalar_field_mref &&) noexcept = default;
  repeated_scalar_field_mref &operator=(const repeated_scalar_field_mref &) noexcept = default;
  repeated_scalar_field_mref &operator=(repeated_scalar_field_mref &&) noexcept = default;
  ~repeated_scalar_field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  [[nodiscard]] repeated_scalar_field_cref<T, Kind> cref() const noexcept {
    return repeated_scalar_field_cref<T, Kind>{*descriptor_, *storage_};
  }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator repeated_scalar_field_cref<T, Kind>() const noexcept { return cref(); }

  value_type &operator[](std::size_t index) const noexcept {
    assert(index < storage_->size);
    return *std::next(storage_->content, static_cast<std::ptrdiff_t>(index));
  }

  [[nodiscard]] value_type &at(std::size_t index) const {
    if (index < storage_->size) {
      return *std::next(storage_->content, static_cast<std::ptrdiff_t>(index));
    }
    throw std::out_of_range("");
  }

  void reserve(std::size_t n) noexcept {
    if (capacity() < n) {
      auto new_data = static_cast<T *>(memory_resource_->allocate(n * sizeof(value_type), alignof(value_type)));
      storage_->capacity = static_cast<uint32_t>(n);
      if (storage_->content) {
        std::uninitialized_copy(storage_->content,
                                std::next(storage_->content, static_cast<std::ptrdiff_t>(storage_->size)), new_data);
      }
      storage_->content = new_data;
    }
  }

  void resize(std::size_t n) const noexcept {
    if (capacity() < n) {
      auto new_data =
          static_cast<value_type *>(memory_resource_->allocate(n * sizeof(value_type), alignof(value_type)));
      storage_->capacity = static_cast<uint32_t>(n);
      std::uninitialized_default_construct(new_data, std::next(new_data, static_cast<std::ptrdiff_t>(n)));
      storage_->content = new_data;
    } else if (size() < n) {
      std::uninitialized_default_construct(std::next(storage_->content, static_cast<std::ptrdiff_t>(storage_->size)),
                                           std::next(storage_->content, static_cast<std::ptrdiff_t>(n)));
    }
    storage_->size = static_cast<uint32_t>(n);
  }

  [[nodiscard]] bool empty() const noexcept { return storage_->size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] std::size_t capacity() const noexcept { return storage_->capacity; }
  [[nodiscard]] value_type *begin() const noexcept { return storage_->content; }
  [[nodiscard]] value_type *end() const noexcept {
    return std::next(storage_->content, static_cast<std::ptrdiff_t>(storage_->size));
  }
  [[nodiscard]] value_type *data() const noexcept { return storage_->content; }

  void reset() const noexcept {
    storage_->content = nullptr;
    storage_->size = 0;
  }
  void clear() const noexcept { storage_->size = 0; }
  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

  void adopt(std::span<value_type> s) const noexcept {
    storage_->content = s.data();
    storage_->size = static_cast<uint32_t>(s.size());
  }

  template <std::ranges::sized_range Range>
    requires std::same_as<std::ranges::range_value_t<Range>, value_type>
  void set(const Range &s) const noexcept {
    resize(static_cast<std::size_t>(std::ranges::distance(s)));
    std::copy(s.begin(), s.end(), data());
  }

  void alias_from(const repeated_scalar_field_mref &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    *storage_ = *other.storage_;
  }

  void clone_from(const cref_type &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    if (other.empty()) {
      clear();
    } else {
      set(std::span{other.data(), other.size()});
    }
  }

private:
  const field_descriptor_t *descriptor_;
  storage_type *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
};

template <typename Field>
class repeated_field_iterator {
  const Field *field_ = nullptr;
  std::size_t index_ = 0;

public:
  using iterator_category = std::random_access_iterator_tag;
  using value_type = typename Field::reference;
  using difference_type = std::ptrdiff_t;
  using reference = typename Field::reference;
  using pointer = void;
  repeated_field_iterator() = default;
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
    index_ = static_cast<std::size_t>(static_cast<std::ptrdiff_t>(index_) + n);
    return *this;
  }
  repeated_field_iterator &operator-=(std::ptrdiff_t n) noexcept {
    index_ = static_cast<std::size_t>(static_cast<std::ptrdiff_t>(index_) - n);
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

  std::ptrdiff_t operator-(const repeated_field_iterator &other) const noexcept {
    return static_cast<std::ptrdiff_t>(index_) - static_cast<std::ptrdiff_t>(other.index_);
  }

  friend repeated_field_iterator operator+(std::ptrdiff_t n, const repeated_field_iterator &rhs) noexcept {
    return rhs + n;
  }

  std::strong_ordering operator<=>(const repeated_field_iterator &other) const noexcept {
    assert(field_ == other.field_);
    return index_ <=> other.index_;
  }

  bool operator==(const repeated_field_iterator &other) const noexcept {
    assert(field_ == other.field_);
    return index_ == other.index_;
  }

  reference operator*() const noexcept { return (*field_)[index_]; }
  reference operator[](std::ptrdiff_t n) const noexcept { return *(*this + n); }
};

class repeated_enum_field_cref : public std::ranges::view_interface<repeated_enum_field_cref> {
public:
  using storage_type = repeated_storage_base<int32_t>;
  using encode_type = vint64_t;
  using reference = enum_value_cref;
  using iterator = repeated_field_iterator<repeated_enum_field_cref>;
  using difference_type = std::ptrdiff_t;
  using size_type = std::size_t;
  static_assert(std::input_or_output_iterator<iterator>);
  static_assert(std::semiregular<iterator>);
  constexpr static field_kind_t field_kind = KIND_REPEATED_ENUM;
  constexpr static bool is_mutable = false;
  constexpr static bool is_repeated = true;

  template <typename U>
  static constexpr bool gettable_to_v = std::same_as<U, enum_numbers_span> || std::same_as<U, enum_names_view>;

  repeated_enum_field_cref(const field_descriptor_t &descriptor, const storage_type &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

  repeated_enum_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : repeated_enum_field_cref(descriptor, storage.of_repeated_int32) {}

  repeated_enum_field_cref(const repeated_enum_field_cref &) noexcept = default;
  repeated_enum_field_cref(repeated_enum_field_cref &&) noexcept = default;
  repeated_enum_field_cref &operator=(const repeated_enum_field_cref &) noexcept = default;
  repeated_enum_field_cref &operator=(repeated_enum_field_cref &&) noexcept = default;
  ~repeated_enum_field_cref() = default;

  [[nodiscard]] bool empty() const noexcept { return storage_->size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] iterator begin() const noexcept { return {this, 0}; }
  [[nodiscard]] iterator end() const noexcept { return {this, storage_->size}; }
  [[nodiscard]] const int32_t *data() const noexcept { return storage_->content; }

  [[nodiscard]] reference operator[](std::size_t index) const noexcept {
    assert(index < size());
    return {*descriptor_->enum_field_type_descriptor(),
            *std::next(storage_->content, static_cast<std::ptrdiff_t>(index))};
  }

  [[nodiscard]] reference at(std::size_t index) const {
    if (index < size()) {
      return {*descriptor_->enum_field_type_descriptor(),
              *std::next(storage_->content, static_cast<std::ptrdiff_t>(index))};
    }
    throw std::out_of_range("");
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

  [[nodiscard]] std::span<const std::int32_t> numbers() const { return std::span{storage_->content, storage_->size}; }

  /**
   * @brief Lazily maps stored enum numbers to their corresponding names.
   */
  [[nodiscard]] auto names() const {
    return enum_numbers_to_names(*descriptor_->enum_field_type_descriptor(), numbers());
  }

  template <typename U>
  [[nodiscard]] std::expected<typename get_traits<U>::type, dynamic_message_errc> get() const noexcept {
    if constexpr (std::same_as<U, enum_numbers_span>) {
      return numbers();
    } else if constexpr (std::same_as<U, enum_names_view>) {
      return names();
    } else {
      return std::unexpected(dynamic_message_errc::invalid_field_type);
    }
  }

private:
  const field_descriptor_t *descriptor_;
  const storage_type *storage_;
};

class repeated_enum_field_mref : public std::ranges::view_interface<repeated_enum_field_mref> {
public:
  using storage_type = repeated_storage_base<int32_t>;
  using encode_type = vint64_t;
  using reference = enum_value_mref;
  using value_type = int32_t;
  using iterator = repeated_field_iterator<repeated_enum_field_mref>;
  using difference_type = std::ptrdiff_t;
  using size_type = std::size_t;
  using cref_type = repeated_enum_field_cref;
  constexpr static field_kind_t field_kind = KIND_REPEATED_ENUM;
  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = true;

  template <typename U>
  static constexpr bool settable_from_v =
      requires { typename U::is_enum_numbers_range; } || requires { typename U::is_enum_names_range; };

  repeated_enum_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                           std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      : descriptor_(&descriptor), storage_(reinterpret_cast<storage_type *>(&storage)), memory_resource_(&mr) {
    assert(descriptor.enum_field_type_descriptor() != nullptr);
  }

  repeated_enum_field_mref(const repeated_enum_field_mref &) noexcept = default;
  repeated_enum_field_mref(repeated_enum_field_mref &&) noexcept = default;
  repeated_enum_field_mref &operator=(const repeated_enum_field_mref &) noexcept = default;
  repeated_enum_field_mref &operator=(repeated_enum_field_mref &&) noexcept = default;
  ~repeated_enum_field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  [[nodiscard]] repeated_enum_field_cref cref() const noexcept {
    return repeated_enum_field_cref{*descriptor_, *storage_};
  }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator repeated_enum_field_cref() const noexcept { return cref(); }

  void resize(std::size_t n) const noexcept {
    if (capacity() < n) {
      auto *new_data = static_cast<int32_t *>(memory_resource_->allocate(n * sizeof(int32_t), alignof(int32_t)));
      std::copy(storage_->content, std::next(storage_->content, static_cast<std::ptrdiff_t>(size())), new_data);
      std::uninitialized_default_construct(new_data, std::next(new_data, static_cast<std::ptrdiff_t>(n)));
      storage_->content = new_data;
      storage_->capacity = static_cast<uint32_t>(n);
    } else if (size() < n) {
      std::uninitialized_default_construct(std::next(storage_->content, static_cast<std::ptrdiff_t>(size())),
                                           std::next(storage_->content, static_cast<std::ptrdiff_t>(n)));
    }
    storage_->size = static_cast<uint32_t>(n);
  }

  [[nodiscard]] bool empty() const noexcept { return storage_->size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] std::size_t capacity() const noexcept { return storage_->capacity; }
  [[nodiscard]] iterator begin() const noexcept { return {this, 0}; }
  [[nodiscard]] iterator end() const noexcept { return {this, storage_->size}; }
  [[nodiscard]] int32_t *data() const noexcept { return storage_->content; }

  [[nodiscard]] reference operator[](std::size_t index) const noexcept {
    assert(index < size());
    return {*descriptor_->enum_field_type_descriptor(),
            *std::next(storage_->content, static_cast<std::ptrdiff_t>(index))};
  }

  [[nodiscard]] reference at(std::size_t index) const {
    if (index < size()) {
      return {*descriptor_->enum_field_type_descriptor(),
              *std::next(storage_->content, static_cast<std::ptrdiff_t>(index))};
    }
    throw std::out_of_range("");
  }

  void reset() noexcept {
    storage_->content = nullptr;
    storage_->size = 0;
  }

  void clear() noexcept { storage_->size = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const enum_descriptor_t &enum_descriptor() const noexcept {
    return *descriptor_->enum_field_type_descriptor();
  }

  void adopt(std::span<int32_t> s) const noexcept {
    storage_->content = s.data();
    storage_->capacity = static_cast<uint32_t>(s.size());
    storage_->size = static_cast<uint32_t>(s.size());
  }

  template <std::ranges::sized_range Range>
    requires std::same_as<std::ranges::range_value_t<Range>, std::int32_t>
  void set(Range const &r) const {
    resize(std::ranges::size(r));
    std::copy(r.begin(), r.end(), data());
  }

  template <std::ranges::sized_range Range>
    requires std::same_as<std::ranges::range_value_t<Range>, std::string_view>
  [[nodiscard]] std::expected<void, dynamic_message_errc> set(Range const &r) const {
    resize(std::ranges::size(r));
    std::size_t i = 0;
    auto values = std::span{storage_->content, storage_->size};
    for (std::string_view name : r) {
      const auto *pval = enum_descriptor().value_of(name);
      if (pval) [[likely]] {
        values[i++] = *pval;
      } else {
        resize(i);
        return std::unexpected(dynamic_message_errc::invalid_enum_name);
      }
    }
    return {};
  }

  template <typename U>
    requires requires { typename U::is_enum_numbers_range; }
  void set(const U &u) const {
    set(u.value);
  }

  template <typename U>
    requires requires { typename U::is_enum_names_range; }
  [[nodiscard]] std::expected<void, dynamic_message_errc> set(const U &u) const {
    return set(u.value);
  }

  void alias_from(const repeated_enum_field_mref &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    adopt(std::span{other.data(), other.size()});
  }

  void clone_from(const cref_type &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    set(std::span{other.data(), other.size()});
  }

private:
  const field_descriptor_t *descriptor_;
  storage_type *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
};

using repeated_string_field_cref = repeated_scalar_field_cref<std::string_view, KIND_REPEATED_STRING>;
/**
 * @brief Mutable view over a repeated string field.
 *
 * - `set` copies a range of strings into message-owned storage (resizing as needed).
 * - `adopt` aliases an external span of string_views; the caller must keep the backing
 *   character data alive while referenced by the message.
 */
class repeated_string_field_mref : public std::ranges::view_interface<repeated_string_field_mref> {
public:
  using storage_type = repeated_storage_base<std::string_view>;
  using encode_type = std::string_view;
  using reference = string_value_mref;
  using value_type = std::string_view;
  using iterator = repeated_field_iterator<repeated_string_field_mref>;
  using difference_type = std::ptrdiff_t;
  using size_type = std::size_t;
  using cref_type = repeated_string_field_cref;
  constexpr static field_kind_t field_kind = KIND_REPEATED_STRING;
  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = true;

  template <typename U>
  static constexpr bool settable_from_v =
      std::ranges::sized_range<U> && std::is_convertible_v<range_value_or_void_t<U>, value_type>;

  repeated_string_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                             std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      : descriptor_(&descriptor), storage_(reinterpret_cast<storage_type *>(&storage)), memory_resource_(&mr) {}

  repeated_string_field_mref(const repeated_string_field_mref &) noexcept = default;
  repeated_string_field_mref(repeated_string_field_mref &&) noexcept = default;
  repeated_string_field_mref &operator=(const repeated_string_field_mref &) noexcept = default;
  repeated_string_field_mref &operator=(repeated_string_field_mref &&) noexcept = default;
  ~repeated_string_field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  [[nodiscard]] repeated_string_field_cref cref() const noexcept {
    return repeated_string_field_cref{*descriptor_, *storage_};
  }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator repeated_string_field_cref() const noexcept { return cref(); }

  void resize(std::size_t n) const noexcept {
    if (capacity() < n) {
      auto *new_data = static_cast<std::string_view *>(
          memory_resource_->allocate(n * sizeof(std::string_view), alignof(value_type)));
      std::copy(storage_->content, std::next(storage_->content, static_cast<std::ptrdiff_t>(size())), new_data);
      std::uninitialized_default_construct(new_data, std::next(new_data, static_cast<std::ptrdiff_t>(n)));
      storage_->content = new_data;
      storage_->capacity = static_cast<uint32_t>(n);
    } else if (size() < n) {
      std::uninitialized_default_construct(std::next(storage_->content, static_cast<std::ptrdiff_t>(size())),
                                           std::next(storage_->content, static_cast<std::ptrdiff_t>(n)));
    }
    storage_->size = static_cast<uint32_t>(n);
  }

  [[nodiscard]] bool empty() const noexcept { return storage_->size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] std::size_t capacity() const noexcept { return storage_->capacity; }
  [[nodiscard]] iterator begin() const noexcept { return {this, 0}; }
  [[nodiscard]] iterator end() const noexcept { return {this, storage_->size}; }
  [[nodiscard]] std::string_view *data() const noexcept { return storage_->content; }

  [[nodiscard]] reference operator[](std::size_t index) const noexcept {
    auto values = content_span();
    assert(index < values.size());
    return reference{values[index], *memory_resource_};
  }

  [[nodiscard]] reference at(std::size_t index) const {
    auto values = content_span();
    if (index < values.size()) {
      return reference{values[index], *memory_resource_};
    }
    throw std::out_of_range("");
  }

  void reset() const noexcept {
    storage_->content = nullptr;
    storage_->size = 0;
  }

  void clear() const noexcept { storage_->size = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

  void adopt(std::span<std::string_view> s) const noexcept {
    storage_->content = s.data();
    storage_->capacity = static_cast<uint32_t>(s.size());
    storage_->size = static_cast<uint32_t>(s.size());
  }

  template <std::ranges::sized_range Range>
    requires std::convertible_to<std::ranges::range_value_t<Range>, std::string_view>
  void set(const Range &r) const noexcept {
    resize(std::ranges::size(r));
    std::size_t i = 0;
    for (auto &&e : r) {
      (*this)[i++].set(e);
    }
  }

  void alias_from(const repeated_string_field_mref &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    adopt(std::span{other.data(), other.size()});
  }

  void clone_from(const cref_type &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    if (other.empty()) {
      clear();
      return;
    }
    resize(other.size());
    for (std::size_t i = 0; i < other.size(); ++i) {
      (*this)[i].clone_from(other[i]);
    }
  }

private:
  [[nodiscard]] std::span<std::string_view> content_span() const noexcept {
    return {storage_->content, static_cast<std::size_t>(storage_->size)};
  }
  const field_descriptor_t *descriptor_;
  storage_type *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
};

using repeated_bytes_field_cref = repeated_scalar_field_cref<bytes_view, KIND_REPEATED_BYTES>;

/**
 * @brief Mutable view over a repeated bytes field.
 *
 * - `set` copies a range of bytes_view elements into message-owned storage.
 * - `adopt` aliases an external span of bytes_view elements; the caller must keep the
 *   referenced buffers alive.
 * Elements are accessible via random-access iterators.
 */
class repeated_bytes_field_mref : public std::ranges::view_interface<repeated_bytes_field_mref> {
public:
  using storage_type = repeated_storage_base<bytes_view>;
  using encode_type = bytes_view;
  using reference = bytes_value_mref;
  using value_type = bytes_view;
  using iterator = repeated_field_iterator<repeated_bytes_field_mref>;
  using difference_type = std::ptrdiff_t;
  using size_type = std::size_t;
  using cref_type = repeated_bytes_field_cref;
  constexpr static field_kind_t field_kind = KIND_REPEATED_BYTES;
  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = true;

  template <typename U>
  static constexpr bool settable_from_v =
      std::ranges::sized_range<U> && concepts::contiguous_std_byte_range<range_value_or_void_t<U>>;

  repeated_bytes_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                            std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      : descriptor_(&descriptor), storage_(reinterpret_cast<storage_type *>(&storage)), memory_resource_(&mr) {}

  repeated_bytes_field_mref(const repeated_bytes_field_mref &) noexcept = default;
  repeated_bytes_field_mref(repeated_bytes_field_mref &&) noexcept = default;
  repeated_bytes_field_mref &operator=(const repeated_bytes_field_mref &) noexcept = default;
  repeated_bytes_field_mref &operator=(repeated_bytes_field_mref &&) noexcept = default;
  ~repeated_bytes_field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  [[nodiscard]] repeated_bytes_field_cref cref() const noexcept {
    return repeated_bytes_field_cref{*descriptor_, *storage_};
  }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator repeated_bytes_field_cref() const noexcept { return cref(); }

  void resize(std::size_t n) const noexcept {
    if (capacity() < n) {
      auto *new_data =
          static_cast<bytes_view *>(memory_resource_->allocate(n * sizeof(bytes_view), alignof(value_type)));
      std::copy(storage_->content, std::next(storage_->content, static_cast<std::ptrdiff_t>(size())), new_data);
      std::uninitialized_default_construct(new_data, std::next(new_data, static_cast<std::ptrdiff_t>(n)));
      storage_->content = new_data;
      storage_->capacity = static_cast<uint32_t>(n);
    } else if (size() < n) {
      std::uninitialized_default_construct(std::next(storage_->content, static_cast<std::ptrdiff_t>(size())),
                                           std::next(storage_->content, static_cast<std::ptrdiff_t>(n)));
    }
    storage_->size = static_cast<uint32_t>(n);
  }

  [[nodiscard]] bool empty() const noexcept { return storage_->size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] std::size_t capacity() const noexcept { return storage_->capacity; }
  [[nodiscard]] iterator begin() const noexcept { return {this, 0}; }
  [[nodiscard]] iterator end() const noexcept { return {this, storage_->size}; }
  [[nodiscard]] bytes_view *data() const noexcept { return storage_->content; }

  [[nodiscard]] reference operator[](std::size_t index) const noexcept {
    auto values = content_span();
    assert(index < values.size());
    return reference{values[index], *memory_resource_};
  }

  [[nodiscard]] reference at(std::size_t index) const {
    auto values = content_span();
    if (index < values.size()) {
      return reference{values[index], *memory_resource_};
    }
    throw std::out_of_range("");
  }

  void reset() const noexcept {
    storage_->content = nullptr;
    storage_->size = 0;
  }

  void clear() const noexcept { storage_->size = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

  void adopt(std::span<bytes_view> s) const noexcept {
    storage_->content = s.data();
    storage_->capacity = static_cast<uint32_t>(s.size());
    storage_->size = static_cast<uint32_t>(s.size());
  }

  template <std::ranges::sized_range Range>
    requires concepts::contiguous_std_byte_range<std::ranges::range_value_t<Range>>
  void set(const Range &r) const noexcept {
    resize(std::ranges::size(r));
    std::size_t i = 0;
    for (auto &&e : r) {
      (*this)[i++].set(e);
    }
  }

  void alias_from(const repeated_bytes_field_mref &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    adopt(std::span{other.data(), other.size()});
  }

  void clone_from(const cref_type &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    if (other.empty()) {
      clear();
      return;
    }
    resize(other.size());
    for (std::size_t i = 0; i < other.size(); ++i) {
      (*this)[i].set(other[i]);
    }
  }

private:
  [[nodiscard]] std::span<bytes_view> content_span() const noexcept {
    return {storage_->content, static_cast<std::size_t>(storage_->size)};
  }
  const field_descriptor_t *descriptor_;
  storage_type *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
};

class message_value_cref {
  const message_descriptor_t *descriptor_;
  const value_storage *storage_;
  [[nodiscard]] std::size_t num_slots() const noexcept { return descriptor_->num_slots; }

  [[nodiscard]] const value_storage &storage_for(const field_descriptor_t &desc) const noexcept {
    return *std::next(storage_, static_cast<std::ptrdiff_t>(desc.storage_slot));
  }

  static const value_storage &empty_storage() noexcept {
    const static value_storage empty;
    return empty;
  }

  field_cref operator[](std::size_t n) const {
    auto &desc = descriptor_->fields()[static_cast<std::ptrdiff_t>(n)];
    return field_cref{desc, storage_for(desc)};
  }
  friend class repeated_field_iterator<message_value_cref>;
  using reference = field_cref;

public:
  constexpr static bool is_mutable = false;
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

  [[nodiscard]] const field_descriptor_t *field_descriptor_by_json_name(std::string_view name) const noexcept {
    auto field_descriptors = descriptor_->fields();
    auto it =
        std::ranges::find_if(field_descriptors, [name](const auto &desc) { return desc.proto().json_name == name; });
    if (it != field_descriptors.end()) {
      return std::addressof(*it);
    }
    return nullptr;
  }

  [[nodiscard]] const field_descriptor_t *field_descriptor_by_number(uint32_t number) const noexcept {
    auto field_descriptors = descriptor_->fields();
    auto it = std::ranges::find_if(field_descriptors,
                                   [number](const auto &desc) { return std::cmp_equal(desc.proto().number, number); });
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

  [[nodiscard]] field_cref field(const field_descriptor_t &desc) const noexcept {
    const auto &storage = storage_for(desc);

    return {desc, storage};
  }

  [[nodiscard]] std::expected<field_cref, dynamic_message_errc> field_by_name(std::string_view name) const noexcept {
    const auto *desc = field_descriptor_by_name(name);
    if (desc != nullptr) {
      return field(*desc);
    } else {
      return std::unexpected(dynamic_message_errc::no_such_field);
    }
  }

  [[nodiscard]] std::expected<field_cref, dynamic_message_errc> field_by_number(uint32_t number) const noexcept {
    const auto *desc = field_descriptor_by_number(number);
    if (desc != nullptr) {
      return field(*desc);
    } else {
      return std::unexpected(dynamic_message_errc::no_such_field);
    }
  }

  template <typename T>
  [[nodiscard]] std::expected<T, dynamic_message_errc> field_value_by_name(std::string_view name) const noexcept {
    return field_by_name(name).transform([](auto ref) { return ref.template get<T>(); });
  }

  template <typename T>
  [[nodiscard]] std::expected<T, dynamic_message_errc> field_value_by_number(std::uint32_t number) const noexcept {
    return field_by_number(number).transform([](auto ref) { return ref.template get<T>(); });
  }

  [[nodiscard]] bool has_oneof(const oneof_descriptor_t &desc) const noexcept {
    const auto &storage = *std::next(storage_, static_cast<std::ptrdiff_t>(desc.storage_slot()));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    return storage.of_int64.selection != 0U;
  }
  class fields_view : public std::ranges::view_interface<fields_view> {
    const message_value_cref *base_;

  public:
    using value_type = field_cref;
    using reference = field_cref;
    using iterator = repeated_field_iterator<message_value_cref>;
    explicit fields_view(const message_value_cref &base) : base_(&base) {}
    [[nodiscard]] iterator begin() const noexcept { return {base_, 0}; }
    [[nodiscard]] iterator end() const noexcept { return {base_, base_->descriptor().fields().size()}; }

    reference operator[](std::size_t n) const { return (*base_)[n]; }
  };

  [[nodiscard]] fields_view fields() const { return fields_view{*this}; }

  template <concepts::const_field_ref T>
  [[nodiscard]] std::expected<T, dynamic_message_errc> typed_ref_by_number(uint32_t number) const noexcept {
    return field_by_number(number).and_then([](auto ref) -> std::expected<T, dynamic_message_errc> {
      auto r = ref.template to<T>();
      if (r.has_value()) {
        return r.value();
      } else {
        return std::unexpected(dynamic_message_errc::invalid_field_type);
      }
    });
  }

  template <concepts::const_field_ref T>
  [[nodiscard]] std::expected<T, dynamic_message_errc> typed_ref_by_name(std::string_view name) const noexcept {
    return field_by_name(name).and_then([](auto ref) -> std::expected<T, dynamic_message_errc> {
      auto r = ref.template to<T>();
      if (r.has_value()) {
        return r.value();
      } else {
        return std::unexpected(dynamic_message_errc::invalid_field_type);
      }
    });
  }
};

/**
 * @brief Mutable dynamic message instance backed by descriptor metadata.
 *
 * Owns storage allocated from a monotonic_buffer_resource and provides typed access
 * to fields via `field_by_name/number` returning `field_mref` views.
 */
class message_value_mref {
public:
  using cref_type = message_value_cref;
  constexpr static bool is_mutable = true;
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
  [[nodiscard]] const message_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  [[nodiscard]] message_value_cref cref() const noexcept { return {*descriptor_, storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator message_value_cref() const noexcept { return cref(); }

  [[nodiscard]] const field_descriptor_t *field_descriptor_by_name(std::string_view name) const noexcept {
    return cref().field_descriptor_by_name(name);
  }

  [[nodiscard]] const field_descriptor_t *field_descriptor_by_json_name(std::string_view name) const noexcept {
    return cref().field_descriptor_by_json_name(name);
  }

  [[nodiscard]] const field_descriptor_t *field_descriptor_by_number(uint32_t number) const noexcept {
    return cref().field_descriptor_by_number(number);
  }

  [[nodiscard]] const oneof_descriptor_t *oneof_descriptor(std::string_view name) const noexcept {
    return cref().oneof_descriptor(name);
  }

  void reset() const noexcept {
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif
    std::memset(storage_, 0, sizeof(value_storage) * num_slots());
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
  }

  [[nodiscard]] field_mref field(const field_descriptor_t &desc) const noexcept {
    auto &storage = storage_for(desc);
    return {desc, storage, *memory_resource_};
  }

  [[nodiscard]] std::expected<field_mref, dynamic_message_errc> field_by_name(std::string_view name) const noexcept {
    const auto *desc = field_descriptor_by_name(name);
    if (desc != nullptr) {
      return field(*desc);
    } else {
      return std::unexpected(dynamic_message_errc::no_such_field);
    }
  }

  [[nodiscard]] std::expected<field_mref, dynamic_message_errc> field_by_number(uint32_t number) const noexcept {
    const auto *desc = field_descriptor_by_number(number);
    if (desc != nullptr) {
      return field(*desc);
    } else {
      return std::unexpected(dynamic_message_errc::no_such_field);
    }
  }

  template <typename T>
  [[nodiscard]] std::expected<typename get_traits<T>::type, dynamic_message_errc>
  field_value_by_name(std::string_view name) const noexcept {
    return field_by_name(name).and_then([](auto ref) { return ref.template get<T>(); });
  }

  template <typename T>
  [[nodiscard]] std::expected<typename get_traits<T>::type, dynamic_message_errc>
  field_value_by_number(uint32_t number) const noexcept {
    return field_by_number(number).and_then([](auto ref) { return ref.template get<T>(); });
  }

  template <concepts::const_field_ref T>
  [[nodiscard]] std::expected<T, dynamic_message_errc> typed_ref_by_number(uint32_t number) const noexcept {
    return cref().field_by_number(number).and_then([](auto ref) -> std::expected<T, dynamic_message_errc> {
      auto r = ref.template to<T>();
      if (r.has_value()) {
        return r.value();
      } else {
        return std::unexpected(dynamic_message_errc::invalid_field_type);
      }
    });
  }

  template <concepts::const_field_ref T>
  [[nodiscard]] std::expected<T, dynamic_message_errc> typed_ref_by_name(std::string_view name) const noexcept {
    return cref().field_by_name(name).and_then([](auto ref) -> std::expected<T, dynamic_message_errc> {
      auto r = ref.template to<T>();
      if (r.has_value()) {
        return r.value();
      } else {
        return std::unexpected(dynamic_message_errc::invalid_field_type);
      }
    });
  }

  template <concepts::mutable_field_ref T>
  [[nodiscard]] std::expected<T, dynamic_message_errc> typed_ref_by_number(uint32_t number) const noexcept {
    return field_by_number(number).and_then([](auto ref) -> std::expected<T, dynamic_message_errc> {
      auto r = ref.template to<T>();
      if (r.has_value()) {
        return r.value();
      } else {
        return std::unexpected(dynamic_message_errc::invalid_field_type);
      }
    });
  }

  template <concepts::mutable_field_ref T>
  [[nodiscard]] std::expected<T, dynamic_message_errc> typed_ref_by_name(std::string_view name) const noexcept {
    return field_by_name(name).and_then([](auto ref) -> std::expected<T, dynamic_message_errc> {
      auto r = ref.template to<T>();
      if (r.has_value()) {
        return r.value();
      } else {
        return std::unexpected(dynamic_message_errc::invalid_field_type);
      }
    });
  }

  void clear_field(const field_descriptor_t &desc) const noexcept {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    storage_for(desc).reset();
  }

  void clear_field(const oneof_descriptor_t &desc) const noexcept {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    std::next(storage_, static_cast<std::ptrdiff_t>(desc.storage_slot()))->reset();
  }

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
    [[nodiscard]] iterator begin() const { return {base_, 0}; }
    [[nodiscard]] iterator end() const { return {base_, base_->descriptor().fields().size()}; }
    reference operator[](std::size_t n) const { return (*base_)[n]; }
  };

  [[nodiscard]] fields_view fields() const { return fields_view{*this}; }

  void alias_from(const message_value_mref &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    std::copy(other.storage_, std::next(other.storage_, static_cast<std::ptrdiff_t>(num_slots())), storage_);
  }

  void clone_from(const cref_type &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    for (std::size_t i = 0; i < num_slots(); ++i) {
      fields()[i].clone_from(other.fields()[i]);
    }
  }

private:
  friend class message_field_mref;
  friend class repeated_field_iterator<message_value_mref>;

  const message_descriptor_t *descriptor_;
  value_storage *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

  [[nodiscard]] std::size_t num_slots() const noexcept { return descriptor_->num_slots; }

  [[nodiscard]] value_storage &storage_for(const field_descriptor_t &desc) const noexcept {
    return *std::next(storage_, static_cast<std::ptrdiff_t>(desc.storage_slot));
  }

  field_mref operator[](std::size_t n) const {
    auto &desc = descriptor_->fields()[static_cast<std::ptrdiff_t>(n)];
    return field_mref{desc, storage_for(desc), *memory_resource_};
  }
  using reference = field_mref;
};

class message_field_cref {
public:
  using encode_type = message_value_cref;
  using storage_type = scalar_storage_base<value_storage *>;
  using value_type = message_value_cref;
  constexpr static bool is_repeated = false;

  template <typename U>
  static constexpr bool gettable_to_v = std::same_as<U, message_value_cref>;

  constexpr static field_kind_t field_kind = KIND_MESSAGE;
  constexpr static bool is_mutable = false;

  message_field_cref(const field_descriptor_t &descriptor, const storage_type &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

  message_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : message_field_cref(descriptor, storage.of_message) {}

  message_field_cref(const message_field_cref &) noexcept = default;
  message_field_cref(message_field_cref &&) noexcept = default;
  message_field_cref &operator=(const message_field_cref &) noexcept = default;
  message_field_cref &operator=(message_field_cref &&) noexcept = default;
  ~message_field_cref() noexcept = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->selection == descriptor().oneof_ordinal; }
  [[nodiscard]] value_type value() const {
    if (!has_value()) {
      throw std::bad_optional_access{};
    }
    return {message_descriptor(), storage_->content};
  }
  [[nodiscard]] value_type operator*() const noexcept { return {message_descriptor(), storage_->content}; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const message_descriptor_t &message_descriptor() const noexcept {
    return *descriptor_->message_field_type_descriptor();
  }

  template <typename U>
  [[nodiscard]] std::expected<typename get_traits<U>::type, dynamic_message_errc> get() const {
    if constexpr (std::same_as<U, message_value_cref>) {
      if (has_value()) {
        return *(*this);
      } else {
        return std::unexpected(dynamic_message_errc::no_such_value);
      }
    } else {
      return std::unexpected(dynamic_message_errc::invalid_field_type);
    }
  }

private:
  const field_descriptor_t *descriptor_;
  const storage_type *storage_;
  [[nodiscard]] std::size_t num_slots() const { return descriptor_->message_field_type_descriptor()->num_slots; }
};

/**
 * @brief Mutable view of a singular embedded message field.
 *
 * Use `emplace()` to materialize a child message (allocating storage from the parent’s
 * monotonic_buffer_resource), then mutate its fields via the returned message_value_mref.
 */
class message_field_mref {
public:
  using encode_type = message_value_mref;
  using storage_type = scalar_storage_base<value_storage *>;
  using value_type = message_value_mref;
  using cref_type = message_field_cref;
  constexpr static field_kind_t field_kind = KIND_MESSAGE;
  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = false;

  template <typename U>
  static constexpr bool settable_from_v = std::convertible_to<U, message_value_cref>;

  message_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                     std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : descriptor_(&descriptor), storage_(&storage.of_message), memory_resource_(&mr) {
    assert(descriptor.message_field_type_descriptor() != nullptr);
  }

  message_field_mref(const message_field_mref &) noexcept = default;
  message_field_mref(message_field_mref &&) noexcept = default;
  message_field_mref &operator=(const message_field_mref &) noexcept = default;
  message_field_mref &operator=(message_field_mref &&) noexcept = default;
  ~message_field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  [[nodiscard]] cref_type cref() const noexcept { return cref_type{*descriptor_, *storage_}; }

  [[nodiscard]] message_value_mref emplace() const noexcept {
    if (!has_value()) {
      storage_->selection = descriptor_->oneof_ordinal;
      storage_->content = static_cast<value_storage *>(
          memory_resource_->allocate(sizeof(value_storage) * num_slots(), alignof(value_storage)));
    }
    auto result = message_value_mref{message_descriptor(), storage_->content, *memory_resource_};
    result.reset();
    return result;
  }
  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }
  [[nodiscard]] value_type value() const {
    if (!has_value()) {
      throw std::bad_optional_access{};
    }
    return {message_descriptor(), storage_->content, *memory_resource_};
  }
  [[nodiscard]] value_type operator*() const noexcept {
    return {message_descriptor(), storage_->content, *memory_resource_};
  }

  template <typename U>
  [[nodiscard]] auto get() const {
    return cref().get<U>();
  }

  void reset() const noexcept { storage_->selection = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const message_descriptor_t &message_descriptor() const noexcept {
    return *descriptor_->message_field_type_descriptor();
  }

  void alias_from(const message_field_mref &other) const noexcept {
    assert(&message_descriptor() == &other.message_descriptor());
    *storage_ = *other.storage_;
  }

  void clone_from(const cref_type &other) const noexcept {
    assert(&this->message_descriptor() == &other.message_descriptor());
    if (other.has_value()) {
      emplace().clone_from(*other);
    } else {
      this->reset();
    }
  }

  [[nodiscard]] std::expected<void, dynamic_message_errc> set(const message_value_cref &v) const {
    if (&this->message_descriptor() == &v.descriptor()) {
      if (!has_value()) {
        emplace().clone_from(v);
      } else {
        message_value_mref val = *(*this);
        val.clone_from(v);
      }
      return {};
    } else {
      return std::unexpected(dynamic_message_errc::wrong_message_type);
    }
  }

private:
  const field_descriptor_t *descriptor_;
  storage_type *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
  [[nodiscard]] std::size_t num_slots() const noexcept { return message_descriptor().num_slots; }
};

class repeated_message_field_cref : std::ranges::view_interface<repeated_message_field_cref> {
  const field_descriptor_t *descriptor_;
  const repeated_storage_base<value_storage> *storage_;
  [[nodiscard]] std::size_t num_slots() const { return message_descriptor().num_slots; }
  friend class repeated_message_field_mref;

public:
  using value_type = message_value_cref;
  using encode_type = message_value_cref;
  using reference = message_value_cref;
  using iterator = repeated_field_iterator<repeated_message_field_cref>;
  using difference_type = std::ptrdiff_t;
  using size_type = std::size_t;

  constexpr static field_kind_t field_kind = KIND_REPEATED_MESSAGE;
  constexpr static bool is_mutable = false;
  constexpr static bool is_repeated = true;

  template <typename U>
  static constexpr bool gettable_to_v = false;

  repeated_message_field_cref(const field_descriptor_t &descriptor,
                              const repeated_storage_base<value_storage> &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

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
    const auto offset = static_cast<std::ptrdiff_t>(index * num_slots());
    return {message_descriptor(), std::next(storage_->content, offset)};
  }

  [[nodiscard]] message_value_cref at(std::size_t index) const {
    if (index < size()) {
      const auto offset = static_cast<std::ptrdiff_t>(index * num_slots());
      return {message_descriptor(), std::next(storage_->content, offset)};
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

static_assert(std::ranges::range<repeated_message_field_cref>);

/**
 * @brief Mutable view over a repeated embedded message field.
 *
 * Supports resize and random access to child message_value_mref elements.
 */
class repeated_message_field_mref : std::ranges::view_interface<repeated_message_field_mref> {
  const field_descriptor_t *descriptor_;
  repeated_storage_base<value_storage> *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

  [[nodiscard]] std::size_t num_slots() const noexcept { return message_descriptor().num_slots; }

public:
  using value_type = message_value_mref;
  using encode_type = message_value_mref;
  using reference = message_value_mref;
  using iterator = repeated_field_iterator<repeated_message_field_mref>;
  using difference_type = std::ptrdiff_t;
  using size_type = std::size_t;
  using cref_type = repeated_message_field_cref;
  constexpr static field_kind_t field_kind = KIND_REPEATED_MESSAGE;
  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = true;

  template <typename U>
  static constexpr bool settable_from_v =
      std::ranges::sized_range<U> && std::is_convertible_v<range_value_or_void_t<U>, message_value_cref>;

  repeated_message_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                              std::pmr::monotonic_buffer_resource &mr) noexcept
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      : descriptor_(&descriptor), storage_(&storage.of_repeated_message), memory_resource_(&mr) {}

  repeated_message_field_mref(const repeated_message_field_mref &) noexcept = default;
  repeated_message_field_mref(repeated_message_field_mref &&) noexcept = default;
  repeated_message_field_mref &operator=(const repeated_message_field_mref &) noexcept = default;
  repeated_message_field_mref &operator=(repeated_message_field_mref &&) noexcept = default;
  ~repeated_message_field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  [[nodiscard]] repeated_message_field_cref cref() const noexcept { return {*descriptor_, *storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  operator repeated_message_field_cref() const noexcept { return cref(); }

  void resize(std::size_t n) const noexcept {
    auto old_size = size();
    if (capacity() < n) {
      auto *new_data = static_cast<value_storage *>(
          memory_resource_->allocate(n * num_slots() * sizeof(value_storage), alignof(value_storage)));
      std::ranges::copy(std::span{storage_->content, storage_->size * num_slots()}, new_data);
      storage_->content = new_data;
      storage_->size = static_cast<uint32_t>(n);
      storage_->capacity = static_cast<uint32_t>(n);
      for (std::size_t i = old_size; i < size(); ++i) {
        (*this)[i].reset();
      }
    } else if (size() < n) {
      storage_->size = static_cast<uint32_t>(n);
      for (std::size_t i = old_size; i < size(); ++i) {
        (*this)[i].reset();
      }
    } else {
      storage_->size = static_cast<uint32_t>(n);
    }
  }

  [[nodiscard]] std::size_t size() const noexcept { return storage_->size; }
  [[nodiscard]] std::size_t capacity() const noexcept { return storage_->capacity; }
  [[nodiscard]] message_value_mref operator[](std::size_t index) const noexcept {
    assert(index < size());
    const auto offset = static_cast<std::ptrdiff_t>(index * num_slots());
    return {message_descriptor(), std::next(storage_->content, offset), *memory_resource_};
  }

  [[nodiscard]] message_value_mref at(std::size_t index) const {
    if (index < size()) {
      const auto offset = static_cast<std::ptrdiff_t>(index * num_slots());
      return {message_descriptor(), std::next(storage_->content, offset), *memory_resource_};
    }
    throw std::out_of_range("");
  }

  [[nodiscard]] iterator begin() const noexcept { return {this, 0}; }
  [[nodiscard]] iterator end() const noexcept { return {this, size()}; }

  void reset() const noexcept { storage_->size = 0; }
  void clear() const noexcept { storage_->size = 0; }
  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const message_descriptor_t &message_descriptor() const noexcept {
    return *descriptor_->message_field_type_descriptor();
  }

  void alias_from(const repeated_message_field_mref &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    *storage_ = *other.storage_;
  }

  void clone_from(const cref_type &other) const {
    assert(this->descriptor_ == other.descriptor_);
    resize(other.size());
    for (std::size_t i = 0; i < size(); ++i) {
      (*this)[i].clone_from(other[i]);
    }
  }

  template <typename T>
    requires settable_from_v<T>
  std::expected<void, dynamic_message_errc> set(const T &v) const {
    resize(v.size());

    for (std::size_t i = 0; i < size(); ++i) {
      if (&message_descriptor() != &(v[i].descriptor())) {
        return std::unexpected(dynamic_message_errc::wrong_message_type);
      }
      (*this)[i].clone_from(v[i]);
    }
    return {};
  }
};

using double_field_cref = scalar_field_cref<double, KIND_DOUBLE>;
using float_field_cref = scalar_field_cref<float, KIND_FLOAT>;

using int64_field_cref = scalar_field_cref<vint64_t, KIND_INT64>;
using sint64_field_cref = scalar_field_cref<vsint64_t, KIND_SINT64>;
using sfixed64_field_cref = scalar_field_cref<int64_t, KIND_SFIXED64>;
using uint64_field_cref = scalar_field_cref<vuint64_t, KIND_UINT64>;
using fixed64_field_cref = scalar_field_cref<uint64_t, KIND_FIXED64>;

using int32_field_cref = scalar_field_cref<vint32_t, KIND_INT32>;
using sint32_field_cref = scalar_field_cref<vsint32_t, KIND_SINT32>;
using sfixed32_field_cref = scalar_field_cref<int32_t, KIND_SFIXED32>;
using uint32_field_cref = scalar_field_cref<vuint32_t, KIND_UINT32>;
using fixed32_field_cref = scalar_field_cref<uint32_t, KIND_FIXED32>;

using bool_field_cref = scalar_field_cref<bool, KIND_BOOL>;

using repeated_double_field_cref = repeated_scalar_field_cref<double, KIND_REPEATED_DOUBLE>;
using repeated_float_field_cref = repeated_scalar_field_cref<float, KIND_REPEATED_FLOAT>;

using repeated_int64_field_cref = repeated_scalar_field_cref<vint64_t, KIND_REPEATED_INT64>;
using repeated_sint64_field_cref = repeated_scalar_field_cref<vsint64_t, KIND_REPEATED_SINT64>;
using repeated_sfixed64_field_cref = repeated_scalar_field_cref<int64_t, KIND_REPEATED_SFIXED64>;
using repeated_uint64_field_cref = repeated_scalar_field_cref<vuint64_t, KIND_REPEATED_UINT64>;
using repeated_fixed64_field_cref = repeated_scalar_field_cref<uint64_t, KIND_REPEATED_FIXED64>;

using repeated_int32_field_cref = repeated_scalar_field_cref<vint32_t, KIND_REPEATED_INT32>;
using repeated_sint32_field_cref = repeated_scalar_field_cref<vsint32_t, KIND_REPEATED_SINT32>;
using repeated_sfixed32_field_cref = repeated_scalar_field_cref<int32_t, KIND_REPEATED_SFIXED32>;
using repeated_uint32_field_cref = repeated_scalar_field_cref<vuint32_t, KIND_REPEATED_UINT32>;
using repeated_fixed32_field_cref = repeated_scalar_field_cref<uint32_t, KIND_REPEATED_FIXED32>;

using repeated_bool_field_cref = repeated_scalar_field_cref<bool, KIND_REPEATED_BOOL>;

////

using double_field_mref = scalar_field_mref<double, KIND_DOUBLE>;
using float_field_mref = scalar_field_mref<float, KIND_FLOAT>;

using int64_field_mref = scalar_field_mref<vint64_t, KIND_INT64>;
using sint64_field_mref = scalar_field_mref<vsint64_t, KIND_SINT64>;
using sfixed64_field_mref = scalar_field_mref<int64_t, KIND_SFIXED64>;
using uint64_field_mref = scalar_field_mref<vuint64_t, KIND_UINT64>;
using fixed64_field_mref = scalar_field_mref<uint64_t, KIND_FIXED64>;

using int32_field_mref = scalar_field_mref<vint32_t, KIND_INT32>;
using sint32_field_mref = scalar_field_mref<vsint32_t, KIND_SINT32>;
using sfixed32_field_mref = scalar_field_mref<int32_t, KIND_SFIXED32>;
using uint32_field_mref = scalar_field_mref<vuint32_t, KIND_UINT32>;
using fixed32_field_mref = scalar_field_mref<uint32_t, KIND_FIXED32>;

using bool_field_mref = scalar_field_mref<bool, KIND_BOOL>;

using repeated_double_field_mref = repeated_scalar_field_mref<double, KIND_REPEATED_DOUBLE>;
using repeated_float_field_mref = repeated_scalar_field_mref<float, KIND_REPEATED_FLOAT>;

using repeated_int64_field_mref = repeated_scalar_field_mref<vint64_t, KIND_REPEATED_INT64>;
using repeated_sint64_field_mref = repeated_scalar_field_mref<vsint64_t, KIND_REPEATED_SINT64>;
using repeated_sfixed64_field_mref = repeated_scalar_field_mref<int64_t, KIND_REPEATED_SFIXED64>;
using repeated_uint64_field_mref = repeated_scalar_field_mref<vuint64_t, KIND_REPEATED_UINT64>;
using repeated_fixed64_field_mref = repeated_scalar_field_mref<uint64_t, KIND_REPEATED_FIXED64>;

using repeated_int32_field_mref = repeated_scalar_field_mref<vint32_t, KIND_REPEATED_INT32>;
using repeated_sint32_field_mref = repeated_scalar_field_mref<vsint32_t, KIND_REPEATED_SINT32>;
using repeated_sfixed32_field_mref = repeated_scalar_field_mref<int32_t, KIND_REPEATED_SFIXED32>;
using repeated_uint32_field_mref = repeated_scalar_field_mref<vuint32_t, KIND_REPEATED_UINT32>;
using repeated_fixed32_field_mref = repeated_scalar_field_mref<uint32_t, KIND_REPEATED_FIXED32>;

using repeated_bool_field_mref = repeated_scalar_field_mref<bool, KIND_REPEATED_BOOL>;

inline auto field_cref::visit(auto &&visitor) const {
  switch (field_kind()) {
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
  case KIND_FIXED64:
    return visitor(fixed64_field_cref{*descriptor_, *storage_});
  case KIND_FIXED32:
    return visitor(fixed32_field_cref{*descriptor_, *storage_});
  case KIND_BOOL:
    return visitor(bool_field_cref{*descriptor_, *storage_});
  case KIND_STRING:
    return visitor(string_field_cref{*descriptor_, *storage_});
  case KIND_MESSAGE:
    return visitor(message_field_cref{*descriptor_, *storage_});
  case KIND_BYTES:
    return visitor(bytes_field_cref{*descriptor_, *storage_});
  case KIND_UINT32:
    return visitor(uint32_field_cref{*descriptor_, *storage_});
  case KIND_ENUM:
    return visitor(enum_field_cref{*descriptor_, *storage_});
  case KIND_SFIXED32:
    return visitor(sfixed32_field_cref{*descriptor_, *storage_});
  case KIND_SFIXED64:
    return visitor(sfixed64_field_cref{*descriptor_, *storage_});
  case KIND_SINT32:
    return visitor(sint32_field_cref{*descriptor_, *storage_});
  case KIND_SINT64:
    return visitor(sint64_field_cref{*descriptor_, *storage_});
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
  case KIND_REPEATED_FIXED64:
    return visitor(repeated_fixed64_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_FIXED32:
    return visitor(repeated_fixed32_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_BOOL:
    return visitor(repeated_bool_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_STRING:
    return visitor(repeated_string_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_MESSAGE:
    return visitor(repeated_message_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_BYTES:
    return visitor(repeated_bytes_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_UINT32:
    return visitor(repeated_uint32_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_ENUM:
    return visitor(repeated_enum_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_SFIXED32:
    return visitor(repeated_sfixed32_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_SFIXED64:
    return visitor(repeated_sfixed64_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_SINT32:
    return visitor(repeated_sint32_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_SINT64:
    return visitor(repeated_sint64_field_cref{*descriptor_, *storage_});
  }
  unreachable();
}

inline auto field_mref::visit(auto &&visitor) const {
  switch (field_kind()) {
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
  case KIND_FIXED64:
    return visitor(fixed64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_FIXED32:
    return visitor(fixed32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_BOOL:
    return visitor(bool_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_STRING:
    return visitor(string_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_MESSAGE:
    return visitor(message_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_BYTES:
    return visitor(bytes_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_UINT32:
    return visitor(uint32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_ENUM:
    return visitor(enum_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_SFIXED32:
    return visitor(sfixed32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_SFIXED64:
    return visitor(sfixed64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_SINT32:
    return visitor(sint32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_SINT64:
    return visitor(sint64_field_mref{*descriptor_, *storage_, *memory_resource_});
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
  case KIND_REPEATED_FIXED64:
    return visitor(repeated_fixed64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_FIXED32:
    return visitor(repeated_fixed32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_BOOL:
    return visitor(repeated_bool_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_STRING:
    return visitor(repeated_string_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_BYTES:
    return visitor(repeated_bytes_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_UINT32:
    return visitor(repeated_uint32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_ENUM:
    return visitor(repeated_enum_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_MESSAGE:
    return visitor(repeated_message_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_SFIXED32:
    return visitor(repeated_sfixed32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_SFIXED64:
    return visitor(repeated_sfixed64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_SINT32:
    return visitor(repeated_sint32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_SINT64:
    return visitor(repeated_sint64_field_mref{*descriptor_, *storage_, *memory_resource_});
  }
  unreachable();
}

inline void field_mref::clone_from(const field_cref &other) const noexcept {
  assert(this->descriptor_ == &other.descriptor());
  this->visit([&](const auto &specific_mref) {
    using cref_type = typename std::decay_t<decltype(specific_mref)>::cref_type;
    specific_mref.clone_from(cref_type{*descriptor_, *other.storage_});
  });
}

inline void field_mref::set_null() noexcept {
  const auto* msg_descriptor = descriptor().message_field_type_descriptor();
  if (msg_descriptor != nullptr && msg_descriptor->wellknown == wellknown_types_t::VALUE) {
    auto msg = message_field_mref{*descriptor_, *storage_, *memory_resource_}.emplace();
    (void) msg.fields()[0].set(enum_number(0)).has_value();
  } else {
    reset();
  } 
}

inline std::optional<message_value_mref>
dynamic_message_factory::get_message(std::string_view name, std::pmr::monotonic_buffer_resource &mr) const {
  const auto *desc = pool_.get_message_descriptor(name);
  if (desc != nullptr) {
    return message_value_mref{*desc, mr};
  }
  return {};
}

namespace concepts {
template <typename T>
concept non_owning_string_or_bytes = std::same_as<T, std::string_view> || std::same_as<T, bytes_view>;
} // namespace concepts

namespace pb_serializer {

template <concepts::is_basic_in Archive>
struct field_deserializer {
  uint32_t tag;
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  Archive &archive;

  status deserialize(concepts::arithmetic auto &value, const field_descriptor_t &) {
    if (auto ec = archive(value); !ec.ok()) [[unlikely]] {
      return ec;
    }
    return std::errc{};
  }

  template <typename T, field_kind_t Kind>
  status operator()(scalar_field_mref<T, Kind> mref) {
    T value;
    if (auto ec = deserialize(value, mref.descriptor()); !ec.ok()) [[likely]] {
      return ec;
    }
    mref.set(value);
    return {};
  }

  status deserialize(enum_value_mref mref, const field_descriptor_t &) {
    vint64_t value;
    if (auto ec = archive(value); !ec.ok()) [[unlikely]] {
      return ec;
    }
    if (!mref.descriptor().valid_enum_value(static_cast<int32_t>(value))) [[likely]] {
      return std::errc::result_out_of_range;
    }
    mref.set(static_cast<int32_t>(value.value));
    return std::errc{};
  }

  status operator()(enum_field_mref mref) {
    auto ec = deserialize(mref.emplace(), mref.descriptor());
    if (ec == std::errc::result_out_of_range) [[unlikely]] {
      mref.reset();
      return std::errc{};
    }
    return ec;
  }

  template <concepts::non_owning_string_or_bytes T>
  status deserialize(T &item, const field_descriptor_t &desc) {
    vuint32_t byte_count;
    if (auto result = archive(byte_count); !result.ok()) [[unlikely]] {
      return result;
    }
    if (byte_count == 0) {
      return {};
    }

    decltype(auto) v = detail::as_modifiable(archive.context, item);
    if (auto result = deserialize_packed_repeated_with_byte_count<typename T::value_type>(v, byte_count, archive);
        !result.ok()) [[unlikely]] {
      return result;
    }

    if constexpr (std::same_as<T, std::string_view>) {
      // ensure that the string is valid UTF-8 if required
      if (desc.requires_utf8_validation()) {
        if (!::is_utf8(item.data(), item.size())) {
          item = {};
          return std::errc::illegal_byte_sequence;
        }
      }
    }
    return {};
  }

  status operator()(string_field_mref mref) {
    std::string_view item;
    if (status result = this->deserialize(item, mref.descriptor()); !result.ok()) {
      return result;
    }
    mref.adopt(item);
    return {};
  }

  status deserialize(string_value_mref mref, const field_descriptor_t &desc) {
    std::string_view item;
    if (status result = this->deserialize(item, desc); !result.ok()) {
      return result;
    }
    mref.adopt(item);
    return {};
  }

  status operator()(bytes_field_mref mref) {
    bytes_view item;
    if (status result = this->deserialize(item, mref.descriptor()); !result.ok()) {
      return result;
    }
    mref.adopt(item);
    return {};
  }

  status deserialize(bytes_value_mref mref, const field_descriptor_t &desc) {
    bytes_view item;
    if (status result = this->deserialize(item, desc); !result.ok()) {
      return result;
    }
    mref.adopt(item);
    return {};
  }

  status deserialize(message_value_mref v, const field_descriptor_t &desc) {
    if (desc.is_delimited()) {
      return deserialize_group(tag_number(tag), v, archive);
    } else {
      return deserialize_sized(v, archive);
    }
  }

  status operator()(message_field_mref mref) { return deserialize(mref.emplace(), mref.descriptor()); }

  status deserialize_unpacked_repeated(repeated_enum_field_mref mref) {
    size_t count = 0;
    if (auto result = count_unpacked_elements(tag, count, archive); !result.ok()) [[unlikely]] {
      return result;
    }

    auto i = mref.size();
    mref.resize(i + count);

    for (; count > 0; --count) {
      auto ec = this->deserialize(mref[i++], mref.descriptor());
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
    return {};
  }

  template <concepts::resizable MRef>
  status deserialize_unpacked_repeated(MRef mref) {
    std::size_t count = 0;

    if (mref.descriptor().is_delimited()) [[unlikely]] {
      if (auto result = count_groups(tag, count, archive); !result.ok()) [[unlikely]] {
        return result;
      }
    } else {
      if (auto result = count_unpacked_elements(tag, count, archive); !result.ok()) [[unlikely]] {
        return result;
      }
    }

    auto old_size = mref.size();
    const std::size_t new_size = mref.size() + count;
    mref.resize(new_size);

    for (std::size_t i = old_size; i < new_size; ++i, --count) {
      if constexpr (std::same_as<typename MRef::encode_type, typename MRef::value_type>) {
        if (auto ec = this->deserialize(mref[i], mref.descriptor()); !ec.ok()) [[unlikely]] {
          return ec;
        }
      } else {
        typename MRef::encode_type v;
        if (auto ec = this->deserialize(v, mref.descriptor()); !ec.ok()) [[unlikely]] {
          return ec;
        }
        mref[i] = v;
      }
      if (count > 1) {
        // no error handling here, because  `count_unpacked_elements()` already checked the tag
        archive.maybe_advance_region();
        (void)archive.read_tag();
      }
    }

    return {};
  }

  template <concepts::resizable MRef>
  status deserialize_packed_repeated(MRef mref) {
    vuint32_t byte_count;
    if (auto result = archive(byte_count); !result.ok()) [[unlikely]] {
      return result;
    }
    if (byte_count == 0) {
      return {};
    }

    return deserialize_packed_repeated_with_byte_count<typename MRef::encode_type>(mref, byte_count, archive);
  }

  template <typename T, field_kind_t Kind>
  status operator()(repeated_scalar_field_mref<T, Kind> mref) {
    if (mref.descriptor().is_packed()) {
      if (tag_type(tag) != wire_type::length_delimited) {
        return deserialize_unpacked_repeated(mref);
      }
      return deserialize_packed_repeated(mref);
    } else {
      return deserialize_unpacked_repeated(mref);
    }
  }

  status operator()(repeated_enum_field_mref mref) {
    if (mref.descriptor().is_packed()) {
      if (tag_type(tag) != wire_type::length_delimited) {
        return deserialize_unpacked_repeated(mref);
      }
      return deserialize_packed_repeated(mref);
    } else {
      return deserialize_unpacked_repeated(mref);
    }
  }

  status operator()(repeated_string_field_mref mref) { return deserialize_unpacked_repeated(mref); }
  status operator()(repeated_bytes_field_mref mref) { return deserialize_unpacked_repeated(mref); }
  status operator()(repeated_message_field_mref mref) { return deserialize_unpacked_repeated(mref); }
}; // field_deserializer

status deserialize_field_by_tag(uint32_t tag, message_value_mref item, concepts::is_basic_in auto &archive,
                                auto & /* unknown_fields*/) {
  if (tag == 0) {
    return std::errc::bad_message;
  }
  const auto *field_desc = item.field_descriptor_by_number(tag_number(tag));
  if (field_desc == nullptr) [[unlikely]] {
    return do_skip_field(tag, archive);
  }

  auto f = item.field(*field_desc);
  return f.visit(field_deserializer{tag, archive});
}

template <>
struct size_cache_counter<message_value_cref> {
  constexpr std::size_t operator()(auto) const { return 0; }

  template <concepts::varint T, field_kind_t Kind>
  std::size_t operator()(repeated_scalar_field_cref<T, Kind> f) const {
    return static_cast<std::size_t>(f.descriptor().is_packed());
  }

  template <typename T, field_kind_t Kind>
  std::size_t operator()(repeated_scalar_field_cref<T, Kind>) const {
    return 0;
  }

  std::size_t operator()(repeated_enum_field_cref f) const { return f.descriptor().is_packed() ? 1 : 0; }

  static std::size_t count(message_value_cref f) {
    auto fields = f.fields();
    return util::transform_accumulate(fields, [](field_cref nested_field) {
      return nested_field.has_value() ? nested_field.visit(size_cache_counter<message_value_cref>{}) : 0;
    });
  }

  std::size_t operator()(message_field_cref f) const { return count(*f) + (f.descriptor().is_delimited() ? 0 : 1); }

  std::size_t operator()(repeated_message_field_cref f) const {
    return util::transform_accumulate(f, [](message_value_cref element) { return count(element); }) +
           (f.descriptor().is_delimited() ? 0 : f.size());
  }
};

template <>
struct message_size_calculator<message_value_cref> {
  using size_cache = std::span<uint32_t>;
  struct field_visitor {
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    size_cache::iterator &cache_itr;
    uint32_t result = 0;

    explicit field_visitor(size_cache::iterator &itr) : cache_itr{itr} {}

    static constexpr uint32_t narrow_size(std::size_t value) { return static_cast<uint32_t>(value); }

    static uint32_t tag_size(const auto &v) {
      return narrow_size(varint_size(static_cast<uint32_t>(v.descriptor().proto().number) << 3U));
    }

    void cache_size(uint32_t s) {
      decltype(auto) msg_size = *cache_itr++;
      msg_size = s;
    }

    template <concepts::varint T, field_kind_t Kind>
    uint32_t operator()(scalar_field_cref<T, Kind> v) {
      return narrow_size(tag_size(v) + T{v.value()}.encode_size());
    }

    template <typename T, field_kind_t Kind>
      requires std::is_arithmetic_v<T>
    uint32_t operator()(scalar_field_cref<T, Kind> v) {
      return narrow_size(tag_size(v) + sizeof(T));
    }

    uint32_t operator()(enum_field_cref v) { return narrow_size(tag_size(v) + varint_size(v.value().number())); }
    uint32_t operator()(string_field_cref v) { return narrow_size(tag_size(v) + len_size(v.value().size())); }
    uint32_t operator()(bytes_field_cref v) { return narrow_size(tag_size(v) + len_size(v.value().size())); }

    template <concepts::varint T, field_kind_t Kind>
    uint32_t operator()(repeated_scalar_field_cref<T, Kind> v) {
      auto ts = tag_size(v);
      if (v.descriptor().is_packed()) {
        auto s = util::transform_accumulate(v, [](auto e) { return T{e}.encode_size(); });
        cache_size(narrow_size(s));
        return narrow_size(ts + len_size(s));
      } else {
        return narrow_size(util::transform_accumulate(v, [ts](auto e) { return ts + T{e}.encode_size(); }));
      }
    }

    template <typename T, field_kind_t Kind>
      requires std::is_arithmetic_v<T>
    uint32_t operator()(repeated_scalar_field_cref<T, Kind> v) {
      auto ts = tag_size(v);
      if (v.descriptor().is_packed()) {
        return narrow_size(ts + len_size(v.size() * sizeof(T)));
      } else {
        return narrow_size(v.size() * (ts + sizeof(T)));
      }
    }

    uint32_t operator()(repeated_enum_field_cref v) {
      auto ts = tag_size(v);
      if (v.descriptor().is_packed()) {
        auto s = util::transform_accumulate(v, [](enum_value_cref e) { return varint_size(e.number()); });
        cache_size(narrow_size(s));
        return narrow_size(ts + len_size(s));
      } else {
        return narrow_size(
            util::transform_accumulate(v, [ts](enum_value_cref e) { return ts + varint_size(e.number()); }));
      }
    }

    uint32_t operator()(repeated_string_field_cref v) {
      auto ts = tag_size(v);
      return narrow_size(
          util::transform_accumulate(v, [ts](const std::string_view e) { return ts + len_size(e.size()); }));
    }

    uint32_t operator()(repeated_bytes_field_cref v) {
      auto ts = tag_size(v);
      // NOLINTNEXTLINE(performance-unnecessary-value-param)
      return narrow_size(util::transform_accumulate(v, [ts](const bytes_view e) { return ts + len_size(e.size()); }));
    }

    uint32_t operator()(message_value_cref msg) {
      return narrow_size(util::transform_accumulate(
          msg.fields(), [this](field_cref f) { return f.has_value() ? f.visit(*this) : 0; }));
    }

    uint32_t operator()(message_field_cref v) {
      if (v.descriptor().is_delimited()) {
        return narrow_size((2 * tag_size(v)) + (*this)(*v));
      } else {
        decltype(auto) msg_size = *cache_itr++;
        auto s = (*this)(*v);
        msg_size = s;
        return narrow_size(tag_size(v) + len_size(s));
      }
    }

    uint32_t operator()(repeated_message_field_cref v) {
      auto ts = tag_size(v);
      if (v.descriptor().is_delimited()) {
        return narrow_size(
            util::transform_accumulate(v, [this, ts](message_value_cref msg) { return (2 * ts) + (*this)(msg); }));
      } else {
        return narrow_size(util::transform_accumulate(v, [this, ts](message_value_cref msg) {
          decltype(auto) msg_size = *cache_itr++;
          auto s = (*this)(msg);
          msg_size = s;
          return ts + len_size(s);
        }));
      }
    }
  };

  [[nodiscard]] static std::size_t message_size(const message_value_cref &item, size_cache cache) {
    auto itr = cache.begin();
    field_visitor calc{itr};
    return calc(item);
  }
};

bool utf8_validation_failed(const field_descriptor_t &desc, const auto &str) {
#if HPP_PROTO_NO_UTF8_VALIDATION
  [[maybe_unused]] desc;
  [[maybe_unused]] str;
#else
  if (desc.requires_utf8_validation()) {
    return !::is_utf8(str.data(), str.size());
  }
#endif
  return false;
}

template <typename Archive>
struct field_serializer {
  // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
  std::span<uint32_t>::iterator &cache_itr;
  Archive &archive;
  // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)

  constexpr static wire_type wire_type_map[] = {
      wire_type::varint,           // 0
      wire_type::fixed_64,         // TYPE_DOUBLE = 1,
      wire_type::fixed_32,         // TYPE_FLOAT = 2,
      wire_type::varint,           // TYPE_INT64 = 3,
      wire_type::varint,           // TYPE_UINT64 = 4,
      wire_type::varint,           // TYPE_INT32 = 5,
      wire_type::fixed_64,         // TYPE_FIXED64 = 6,
      wire_type::fixed_32,         // TYPE_FIXED32 = 7,
      wire_type::varint,           // TYPE_BOOL = 8,
      wire_type::length_delimited, // TYPE_STRING = 9,
      wire_type::sgroup,           // TYPE_GROUP = 10,
      wire_type::length_delimited, // TYPE_MESSAGE = 11,
      wire_type::length_delimited, // TYPE_BYTES = 12,
      wire_type::varint,           // TYPE_UINT32 = 13,
      wire_type::varint,           // TYPE_ENUM = 14,
      wire_type::fixed_32,         // TYPE_SFIXED32 = 15,
      wire_type::fixed_64,         // TYPE_SFIXED64 = 16,
      wire_type::varint,           // TYPE_SINT32 = 17,
      wire_type::varint,           // TYPE_SINT64 = 18
  };

  static vint32_t make_tag(int32_t number, wire_type type) {
    return static_cast<vint32_t>(static_cast<int32_t>(static_cast<uint32_t>(number) << 3U | std::to_underlying(type)));
  }

  static vint32_t make_tag(const field_descriptor_t &desc) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    return make_tag(desc.proto().number, wire_type_map[std::to_underlying(desc.proto().type)]);
  }

  template <typename T, field_kind_t Kind>
  bool operator()(scalar_field_cref<T, Kind> v) {
    const field_descriptor_t &desc = v.descriptor();
    return archive(make_tag(desc), T{v.value()});
  }

  bool operator()(enum_field_cref v) { return archive(make_tag(v.descriptor()), varint{v.value().number()}); }

  bool operator()(string_field_cref v) {
    auto str = v.value();
    return !utf8_validation_failed(v.descriptor(), str) && archive(make_tag(v.descriptor()), varint{str.size()}, str);
  }

  bool operator()(bytes_field_cref v) { return archive(make_tag(v.descriptor()), varint{v.value().size()}, v.value()); }

  template <typename T, field_kind_t Kind>
  bool operator()(repeated_scalar_field_cref<T, Kind> v) {
    const field_descriptor_t &desc = v.descriptor();
    if (desc.is_packed()) {
      const uint32_t byte_count = concepts::varint<T> ? *cache_itr++ : static_cast<uint32_t>(sizeof(T) * v.size());
      return archive(make_tag(desc.proto().number, wire_type::length_delimited), varint{byte_count}) &&
             std::ranges::all_of(v, [this](auto e) { return archive(T{e}); });
    } else {
      const auto tag = make_tag(desc);
      return std::ranges::all_of(v, [this, tag](auto e) { return archive(tag, T{e}); });
    }
  }

  bool operator()(repeated_enum_field_cref v) {
    const field_descriptor_t &desc = v.descriptor();
    if (desc.is_packed()) {
      return archive(make_tag(desc.proto().number, wire_type::length_delimited), varint{*cache_itr++}) &&
             std::ranges::all_of(v, [this](auto e) { return archive(varint{e.number()}); });
    } else {
      const auto tag = make_tag(desc);
      return std::ranges::all_of(v, [this, tag](auto e) { return archive(tag, varint{e.number()}); });
    }
  }

  bool operator()(repeated_string_field_cref v) {
    const field_descriptor_t &desc = v.descriptor();
    const auto tag = make_tag(desc);

    return std::ranges::all_of(
        v, [&](std::string_view e) { return !utf8_validation_failed(desc, e) && archive(tag, varint{e.size()}, e); });
  }

  bool operator()(repeated_bytes_field_cref v) {
    const field_descriptor_t &desc = v.descriptor();
    const auto tag = make_tag(desc);
    return std::ranges::all_of(v, [this, &tag](const auto &e) { return archive(tag, varint{e.size()}, e); });
  }

  bool operator()(message_value_cref item) {
    return std::ranges::all_of(item.fields(), [&](field_cref f) { return !f.has_value() || f.visit(*this); });
  }

  struct message_tag_writer {
    field_serializer *serializer;
    int32_t number;
    bool is_delimited;
    message_tag_writer(const message_tag_writer &) = delete;
    message_tag_writer(message_tag_writer &&) = delete;
    message_tag_writer(field_serializer *ser, const field_descriptor_t &desc)
        : serializer(ser), number(desc.proto().number), is_delimited(desc.is_delimited()) {
      if (is_delimited) {
        serializer->archive(make_tag(number, wire_type::sgroup));
      } else {
        serializer->archive(make_tag(number, wire_type::length_delimited), varint{*serializer->cache_itr++});
      }
    };

    message_tag_writer &operator=(const message_tag_writer &) = delete;
    message_tag_writer &operator=(message_tag_writer &&) = delete;
    ~message_tag_writer() {
      if (is_delimited) {
        serializer->archive(make_tag(number, wire_type::egroup));
      }
    }
  };

  bool operator()(message_field_cref item) {
    const field_descriptor_t &desc = item.descriptor();
    message_tag_writer tag_writer{this, desc};
    return (*this)(item.value());
  }

  bool operator()(repeated_message_field_cref item) {
    const field_descriptor_t &desc = item.descriptor();
    return std::ranges::all_of(item, [&](auto e) {
      message_tag_writer tag_writer{this, desc};
      return (*this)(e);
    });
  }
};

[[nodiscard]] bool serialize(const message_value_cref &item, std::span<uint32_t>::iterator &cache_itr, auto &archive) {
  field_serializer ser{cache_itr, archive};
  return ser(item);
}
} // namespace pb_serializer

[[nodiscard]] status read_proto(message_value_mref msg, auto &&buffer) {
  msg.reset();
  auto context = pb_context{alloc_from(msg.memory_resource())};
  return pb_serializer::deserialize(msg, std::forward<decltype(buffer)>(buffer), context);
}

[[nodiscard]] status write_proto(const message_value_cref &msg, concepts::contiguous_byte_range auto &buffer,
                                 concepts::is_option_type auto &&...option) {
  pb_context ctx{std::forward<decltype(option)>(option)...};
  decltype(auto) v = detail::as_modifiable(ctx, buffer);
  return pb_serializer::serialize(msg, v, ctx);
}
} // namespace hpp::proto
