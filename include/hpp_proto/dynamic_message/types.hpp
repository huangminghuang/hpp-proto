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

#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>
#include <string_view>
#include <type_traits>

#include <hpp_proto/dynamic_message/repeated_field_iterator.hpp>

namespace hpp_proto {

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
using range_value_or_void_t = range_value_or_void<U>::type;

template <typename T>
struct get_traits {
  using type = T;
};

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

enum class field_cardinality_t : uint8_t {
  SINGULAR,
  REPEATED,
};

enum class field_storage_kind_t : uint8_t {
  INT64,
  UINT64,
  INT32,
  UINT32,
  DOUBLE,
  FLOAT,
  BOOL,
  STRING,
  BYTES,
  MESSAGE,
  REPEATED_INT64,
  REPEATED_UINT64,
  REPEATED_INT32,
  REPEATED_UINT32,
  REPEATED_DOUBLE,
  REPEATED_FLOAT,
  REPEATED_BOOL,
  REPEATED_STRING,
  REPEATED_BYTES,
  REPEATED_MESSAGE,
};

enum class field_presence_t : uint8_t {
  IMPLICIT,
  EXPLICIT,
  REQUIRED,
  ONEOF,
  REPEATED,
};

enum class runtime_field_policy : uint8_t {
  NONE = 0,
  PACKED = 1,
  DELIMITED = 2,
  UTF8_VALIDATION = 4,
};

[[nodiscard]] constexpr uint8_t runtime_field_policy_mask(runtime_field_policy policy) noexcept {
  return static_cast<uint8_t>(policy);
}

[[nodiscard]] constexpr runtime_field_policy operator|(runtime_field_policy lhs, runtime_field_policy rhs) noexcept {
  // A fixed-underlying enum intentionally carries combined flag values.
  // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
  return static_cast<runtime_field_policy>(runtime_field_policy_mask(lhs) | runtime_field_policy_mask(rhs));
}

/** @brief Named construction input for resolved dynamic-message field information. */
struct resolved_field_info_init {
  field_kind_t kind;
  field_storage_kind_t storage_kind;
  field_cardinality_t cardinality;
  field_presence_t presence;
  runtime_field_policy policy;
  uint32_t serialized_tag;
  uint32_t storage_slot;
  uint16_t selection_ordinal;
  uint32_t active_oneof_selection_mask;
  int32_t active_oneof_index_bias;
};

/**
 * @brief Immutable resolved execution facts for one dynamic-message field.
 *
 * Raw descriptor enums are interpreted once while the dynamic-message factory is
 * initialized. Runtime storage, visitation, presence, and serialization consume
 * this normalized information instead of deriving behavior from FieldDescriptorProto.
 */
class resolved_field_info {
public:
  constexpr resolved_field_info() noexcept = default;

  explicit constexpr resolved_field_info(resolved_field_info_init init) noexcept
      : serialized_tag_(init.serialized_tag), storage_slot_(init.storage_slot),
        active_oneof_selection_mask_(init.active_oneof_selection_mask),
        active_oneof_index_bias_(init.active_oneof_index_bias), selection_ordinal_(init.selection_ordinal),
        kind_(init.kind), storage_kind_(init.storage_kind), cardinality_(init.cardinality), presence_(init.presence),
        policy_(init.policy) {}

  [[nodiscard]] constexpr bool finalized() const noexcept { return static_cast<uint8_t>(kind_) != 0; }
  [[nodiscard]] constexpr field_kind_t kind() const noexcept { return kind_; }
  [[nodiscard]] constexpr field_storage_kind_t storage_kind() const noexcept { return storage_kind_; }
  [[nodiscard]] constexpr field_cardinality_t cardinality() const noexcept { return cardinality_; }
  [[nodiscard]] constexpr field_presence_t presence() const noexcept { return presence_; }
  [[nodiscard]] constexpr uint32_t serialized_tag() const noexcept { return serialized_tag_; }
  [[nodiscard]] constexpr uint32_t storage_slot() const noexcept { return storage_slot_; }
  [[nodiscard]] constexpr uint16_t selection_ordinal() const noexcept { return selection_ordinal_; }
  [[nodiscard]] constexpr uint32_t active_oneof_selection_mask() const noexcept { return active_oneof_selection_mask_; }
  [[nodiscard]] constexpr int32_t active_oneof_index_bias() const noexcept { return active_oneof_index_bias_; }

  [[nodiscard]] constexpr bool is_repeated() const noexcept { return cardinality_ == field_cardinality_t::REPEATED; }
  [[nodiscard]] constexpr bool explicit_presence() const noexcept {
    return presence_ == field_presence_t::EXPLICIT || presence_ == field_presence_t::REQUIRED ||
           presence_ == field_presence_t::ONEOF;
  }
  [[nodiscard]] constexpr bool is_packed() const noexcept { return has_policy(runtime_field_policy::PACKED); }
  [[nodiscard]] constexpr bool is_delimited() const noexcept { return has_policy(runtime_field_policy::DELIMITED); }
  [[nodiscard]] constexpr bool requires_utf8_validation() const noexcept {
    return has_policy(runtime_field_policy::UTF8_VALIDATION);
  }

  [[nodiscard]] constexpr bool has_value(uint32_t selection_word) const noexcept {
    return is_repeated() ? selection_word > 0 : selection_word == selection_ordinal_;
  }

private:
  [[nodiscard]] constexpr bool has_policy(runtime_field_policy policy) const noexcept {
    return (runtime_field_policy_mask(policy_) & runtime_field_policy_mask(policy)) != 0;
  }

  uint32_t serialized_tag_ = 0;
  uint32_t storage_slot_ = 0;
  uint32_t active_oneof_selection_mask_ = 0;
  int32_t active_oneof_index_bias_ = 0;
  uint16_t selection_ordinal_ = 0;
  field_kind_t kind_ = static_cast<field_kind_t>(0);
  field_storage_kind_t storage_kind_ = field_storage_kind_t::INT64;
  field_cardinality_t cardinality_ = field_cardinality_t::SINGULAR;
  field_presence_t presence_ = field_presence_t::IMPLICIT;
  runtime_field_policy policy_ = runtime_field_policy::NONE;
};

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

enum class dynamic_message_errc : uint8_t {
  no_error,
  no_such_field,
  no_such_value,
  invalid_field_type,
  invalid_enum_name,
  unknown_enum_value,
  wrong_message_type,
  unknown_message_name,
  descriptor_deserialization_error,
  schema_validation_error
};

namespace concepts {
template <typename T>
concept contiguous_std_byte_range =
    std::ranges::contiguous_range<T> && std::same_as<std::ranges::range_value_t<T>, std::byte>;

template <typename T>
concept const_field_ref = !T::is_mutable && requires { T::field_kind; };

template <typename T>
concept mutable_field_ref = T::is_mutable && requires { T::field_kind; };
} // namespace concepts

template <typename T>
struct value_type_identity {
  using value_type = T;
};

template <typename T>
struct value_proxy {
  T value;
  [[nodiscard]] T *operator->() noexcept { return std::addressof(value); }
  [[nodiscard]] const T *operator->() const noexcept { return std::addressof(value); }
};

} // namespace hpp_proto
