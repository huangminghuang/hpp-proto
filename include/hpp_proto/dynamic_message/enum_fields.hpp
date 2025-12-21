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

#include <memory_resource>
#include <string_view>

#include <hpp_proto/dynamic_message/factory_addons.hpp>
#include <hpp_proto/dynamic_message/scalar_fields.hpp>
#include <hpp_proto/dynamic_message/storage.hpp>
#include <hpp_proto/dynamic_message/types.hpp>

namespace hpp::proto {
using enum field_kind_t;

/**
 * @brief Enum number wrapper for single-value enum setters.
 *
 * Example (set): `enum_field.set(enum_number{1});`
 * Example (get):  `auto n = enum_field.get<enum_number>();`
 */
struct enum_number {
  std::int32_t value = 0;
  operator std::int32_t() const { return value; } // NOLINT(hicpp-explicit-conversions)
};

/**
 * @brief Enum name wrapper for single-value enum setters.
 *
 * Example (set): `enum_field.set(enum_name{"OPEN"});`
 * Example (get):  `auto name = enum_field.get<enum_name>();`
 */
struct enum_name {
  std::string_view value;
  operator std::string_view() const { return value; } // NOLINT(hicpp-explicit-conversions)
};

template <>
struct get_traits<enum_number> {
  using type = std::int32_t;
};

template <>
struct get_traits<enum_name> {
  using type = std::string_view;
};

/**
 * @brief Immutable enum value view (stores the value, not a reference).
 *
 * The `_cref` suffix is intentionally omitted: this type holds the numeric enum
 * value by copy and exposes its descriptor for name lookups.
 */
class enum_value {
public:
  using is_enum_value_ref = void;
  constexpr static bool is_mutable = false;

  enum_value(const enum_descriptor_t &descriptor, int32_t number) noexcept
      : descriptor_(&descriptor), number_(number) {}
  enum_value(const enum_value &) noexcept = default;
  enum_value(enum_value &&) noexcept = default;
  enum_value &operator=(const enum_value &) noexcept = default;
  enum_value &operator=(enum_value &&) noexcept = default;
  ~enum_value() noexcept = default;

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

/**
 * @brief Mutable view of a single enum value, allowing numeric assignment and name lookup.
 */
class enum_value_mref {
  const enum_descriptor_t *descriptor_;
  int32_t *number_;

public:
  using is_enum_value_ref = void;
  using cref_type = enum_value;
  constexpr static bool is_mutable = true;

  enum_value_mref(const enum_descriptor_t &descriptor, int32_t &number) noexcept
      : descriptor_(&descriptor), number_(&number) {}
  enum_value_mref(const enum_value_mref &) noexcept = default;
  enum_value_mref(enum_value_mref &&) noexcept = default;
  enum_value_mref &operator=(const enum_value_mref &) noexcept = default;
  enum_value_mref &operator=(enum_value_mref &&) noexcept = default;
  ~enum_value_mref() noexcept = default;

  [[nodiscard]] operator enum_value() const noexcept { return {*descriptor_, *number_}; } // NOLINT

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
  [[nodiscard]] std::string_view name() const noexcept { return descriptor_->name_of(*number_); }

  [[nodiscard]] const enum_descriptor_t &descriptor() const noexcept { return *descriptor_; }
};

class enum_field_cref {
public:
  using encode_type = vint64_t;
  using value_type = enum_value;
  using storage_type = scalar_storage_base<int32_t>;
  constexpr static field_kind_t field_kind = KIND_ENUM;
  constexpr static bool is_mutable = false;
  constexpr static bool is_repeated = false;

  template <typename U>
  static constexpr bool gettable_to_v =
      std::same_as<U, enum_number> || std::same_as<U, enum_name> || std::same_as<U, enum_value>;

  enum_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

  enum_field_cref(const enum_field_cref &) noexcept = default;
  enum_field_cref(enum_field_cref &&) noexcept = default;
  enum_field_cref &operator=(const enum_field_cref &) noexcept = default;
  enum_field_cref &operator=(enum_field_cref &&) noexcept = default;

  ~enum_field_cref() = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->of_int32.selection == descriptor().oneof_ordinal; }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] enum_value value() const noexcept {
    int32_t effective_value = storage_->of_int32.content;
    if (descriptor().explicit_presence() && !has_value()) {
      effective_value = std::get<int32_t>(descriptor_->default_value);
    }
    return {enum_descriptor(), effective_value};
  }
  [[nodiscard]] ::hpp::proto::value_proxy<value_type> operator->() const noexcept { return {value()}; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

  template <typename U>
  [[nodiscard]] std::expected<typename get_traits<U>::type, dynamic_message_errc> get() const noexcept {
    if constexpr (std::same_as<U, enum_number>) {
      return number();
    } else if constexpr (std::same_as<U, enum_name>) {
      if (name().empty()) {
        return std::unexpected(dynamic_message_errc::unknown_enum_value);
      }
      return name();
    } else if constexpr (std::same_as<U, enum_value>) {
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
    return is_default ? std::get<int32_t>(descriptor_->default_value) : storage_->of_int32.content;
  }

  /**
   * @brief Returns the enum value's symbolic name (empty if schema lacks this number).
   */
  [[nodiscard]] std::string_view name() const { return enum_descriptor().name_of(number()); }

private:
  friend class enum_field_mref;
  const field_descriptor_t *descriptor_;
  const value_storage *storage_;
};

class enum_field_mref {
public:
  using encode_type = vint64_t;
  using value_type = enum_value;
  using storage_type = scalar_storage_base<int32_t>;
  using cref_type = enum_field_cref;
  constexpr static field_kind_t field_kind = KIND_ENUM;
  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = false;

  template <typename U>
  static constexpr bool settable_from_v = std::same_as<U, enum_number> || std::same_as<U, enum_name>;

  enum_field_mref(const field_descriptor_t &descriptor, value_storage &storage,
                  std::pmr::monotonic_buffer_resource &) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

  enum_field_mref(const enum_field_mref &) noexcept = default;
  enum_field_mref(enum_field_mref &&) noexcept = default;
  enum_field_mref &operator=(const enum_field_mref &) noexcept = default;
  enum_field_mref &operator=(enum_field_mref &&) noexcept = default;
  ~enum_field_mref() noexcept = default;

  void alias_from(const cref_type &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    storage_->of_int32 = other.storage_->of_int32;
  }

  void clone_from(const cref_type &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    alias_from(other);
  }

  [[nodiscard]] enum_field_cref cref() const noexcept { return enum_field_cref{*descriptor_, *storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator enum_field_cref() const noexcept { return cref(); }

  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] enum_value_mref value() const noexcept {
    if (descriptor().explicit_presence() && !has_value()) {
      storage_->of_int32.content = std::get<int32_t>(descriptor_->default_value);
    }
    return {*descriptor_->enum_field_type_descriptor(), storage_->of_int32.content};
  }
  [[nodiscard]] ::hpp::proto::value_proxy<value_type> operator->() const noexcept { return {value()}; }

  [[nodiscard]] enum_value_mref emplace() const noexcept {
    storage_->of_int32.selection = descriptor_->oneof_ordinal;
    return {*descriptor_->enum_field_type_descriptor(), storage_->of_int32.content};
  }

  void reset() const noexcept { storage_->of_int32.selection = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const enum_descriptor_t &enum_descriptor() const noexcept {
    return *descriptor_->enum_field_type_descriptor();
  }

  [[nodiscard]] std::int32_t number() const {
    return descriptor().explicit_presence() && !has_value() ? std::get<int32_t>(descriptor_->default_value)
                                                            : storage_->of_int32.content;
  }
  /**
   * @brief Returns the enum value's symbolic name (empty if schema lacks this number).
   */
  [[nodiscard]] std::string_view name() const { return cref().name(); }

  void set(enum_number number) const {
    storage_->of_int32.content = number.value;
    storage_->of_int32.selection = descriptor_->oneof_ordinal;
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
  value_storage *storage_;
};

} // namespace hpp::proto
