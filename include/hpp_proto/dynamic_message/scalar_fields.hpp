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

#include <expected>
#include <memory_resource>
#include <type_traits>

#include <hpp_proto/binpb.hpp>
#include <hpp_proto/dynamic_message/factory_addons.hpp>
#include <hpp_proto/dynamic_message/storage.hpp>
#include <hpp_proto/dynamic_message/types.hpp>

namespace hpp::proto {
using enum field_kind_t;

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

  scalar_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

  scalar_field_cref(const scalar_field_cref &) noexcept = default;
  scalar_field_cref(scalar_field_cref &&) noexcept = default;
  scalar_field_cref &operator=(const scalar_field_cref &) noexcept = default;
  scalar_field_cref &operator=(scalar_field_cref &&) noexcept = default;
  ~scalar_field_cref() noexcept = default;

  [[nodiscard]] bool has_value() const noexcept { return access_storage().selection == descriptor().oneof_ordinal; }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] value_type value() const noexcept {
    if (descriptor().explicit_presence() && !has_value()) {
      return std::get<value_type>(descriptor_->default_value);
    }
    return access_storage().content;
  }

  template <typename U>
  [[nodiscard]] std::expected<typename get_traits<U>::type, dynamic_message_errc> get() const noexcept {
    if constexpr (std::same_as<U, value_type>) {
      return value();
    } else {
      return std::unexpected(dynamic_message_errc::invalid_field_type);
    }
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

private:
  template <typename, field_kind_t>
  friend class scalar_field_mref;

  [[nodiscard]] const storage_type &access_storage() const noexcept {
    if constexpr (std::same_as<value_type, int64_t>) {
      return storage_->of_int64;
    } else if constexpr (std::same_as<value_type, uint64_t>) {
      return storage_->of_uint64;
    } else if constexpr (std::same_as<value_type, int32_t>) {
      return storage_->of_int32;
    } else if constexpr (std::same_as<value_type, uint32_t>) {
      return storage_->of_uint32;
    } else if constexpr (std::same_as<value_type, double>) {
      return storage_->of_double;
    } else if constexpr (std::same_as<value_type, float>) {
      return storage_->of_float;
    } else if constexpr (std::same_as<value_type, bool>) {
      return storage_->of_bool;
    }
  }
  const field_descriptor_t *descriptor_;
  const value_storage *storage_;
};

/**
 * @brief Typed, mutable view of a scalar (non-enum) field.
 *
 * Supports `set()`/`reset()` along with read-only access via `cref()`.
 */
template <typename T, field_kind_t Kind>
class scalar_field_mref {
  using self_type = scalar_field_mref<T, Kind>;

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
      : descriptor_(&descriptor), storage_(&storage) {}

  scalar_field_mref(const self_type &) noexcept = default;
  scalar_field_mref(self_type &&) noexcept = default;
  self_type &operator=(const self_type &) noexcept = default;
  self_type &operator=(self_type &&) noexcept = default;
  ~scalar_field_mref() noexcept = default;

  void set(T v) const noexcept {
    auto &storage = access_storage();
    storage.content = v;
    storage.selection = descriptor_->oneof_ordinal;
  }

  void alias_from(const scalar_field_cref<T, Kind> &other) const noexcept { set(other.value()); }
  void clone_from(scalar_field_cref<T, Kind> other) const noexcept { set(other.value()); }

  [[nodiscard]] cref_type cref() const noexcept { return {*descriptor_, *storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator cref_type() const noexcept { return cref(); }

  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] value_type value() const noexcept { return cref().value(); }
  void reset() noexcept { access_storage().selection = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

private:
  [[nodiscard]] storage_type &access_storage() const noexcept {
    if constexpr (std::same_as<value_type, int64_t>) {
      return storage_->of_int64;
    } else if constexpr (std::same_as<value_type, uint64_t>) {
      return storage_->of_uint64;
    } else if constexpr (std::same_as<value_type, int32_t>) {
      return storage_->of_int32;
    } else if constexpr (std::same_as<value_type, uint32_t>) {
      return storage_->of_uint32;
    } else if constexpr (std::same_as<value_type, double>) {
      return storage_->of_double;
    } else if constexpr (std::same_as<value_type, float>) {
      return storage_->of_float;
    } else if constexpr (std::same_as<value_type, bool>) {
      return storage_->of_bool;
    }
  }
  const field_descriptor_t *descriptor_;
  value_storage *storage_;
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
} // namespace hpp::proto
