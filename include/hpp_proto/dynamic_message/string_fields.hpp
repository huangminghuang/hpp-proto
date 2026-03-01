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

#include <algorithm>
#include <cassert>
#include <limits>
#include <memory_resource>
#include <span>
#include <string_view>

#include <hpp_proto/dynamic_message/factory_addons.hpp>
#include <hpp_proto/dynamic_message/storage.hpp>
#include <hpp_proto/dynamic_message/types.hpp>

namespace hpp_proto {
using enum field_kind_t;

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

  string_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

  string_field_cref(const string_field_cref &) noexcept = default;
  string_field_cref(string_field_cref &&) noexcept = default;
  string_field_cref &operator=(const string_field_cref &) noexcept = default;
  string_field_cref &operator=(string_field_cref &&) noexcept = default;
  ~string_field_cref() noexcept = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->selection_matches(descriptor().oneof_ordinal); }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->of_string.size; }
  [[nodiscard]] std::string_view default_value() const noexcept { return descriptor_->proto().default_value; }

  [[nodiscard]] std::string_view value() const noexcept {
    if (descriptor().explicit_presence() && !has_value()) {
      return descriptor_->proto().default_value;
    }
    return {storage_->of_string.content, storage_->of_string.size};
  }

  [[nodiscard]] bool is_present_or_explicit_default() const noexcept {
    if (has_value()) {
      auto val = std::string_view{storage_->of_string.content, storage_->of_string.size};
      return descriptor().explicit_presence() || !std::ranges::equal(val, descriptor_->proto().default_value);
    } else {
      return false;
    }
  }

  [[nodiscard]] ::hpp_proto::value_proxy<value_type> operator->() const noexcept { return {value()}; }

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
  const value_storage *storage_;
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
      : descriptor_(&descriptor), storage_(&storage), memory_resource_(&mr) {}

  string_field_mref(const string_field_mref &) noexcept = default;
  string_field_mref(string_field_mref &&) noexcept = default;
  string_field_mref &operator=(const string_field_mref &) noexcept = default;
  string_field_mref &operator=(string_field_mref &&) noexcept = default;
  ~string_field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  void adopt(std::string_view v) const noexcept {
    assert(v.size() <= static_cast<std::size_t>(std::numeric_limits<int32_t>::max()));
    storage_->of_string.content = v.data();
    storage_->of_string.size = static_cast<uint32_t>(v.size());
    storage_->of_string.selection = descriptor_->oneof_ordinal;
  }

  void set(std::string_view v) const {
    assert(v.size() <= static_cast<std::size_t>(std::numeric_limits<int32_t>::max()));
    auto *dest = static_cast<char *>(memory_resource_->allocate(v.size(), 1));
    std::ranges::copy(v, dest);
    storage_->of_string.content = dest;
    storage_->of_string.size = static_cast<uint32_t>(v.size());
    storage_->of_string.selection = descriptor_->oneof_ordinal;
  }

  void alias_from(const cref_type &other) const noexcept { adopt(other.value()); }

  void clone_from(const cref_type &other) const {
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
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] std::string_view default_value() const noexcept { return cref().default_value(); }
  [[nodiscard]] std::string_view value() const noexcept { return cref().value(); }
  [[nodiscard]] ::hpp_proto::value_proxy<value_type> operator->() const noexcept { return {value()}; }

  void set_as_default() const noexcept { adopt(default_value()); }

  void reset() const noexcept {
    storage_->of_string.size = 0;
    storage_->of_string.selection = 0;
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

private:
  const field_descriptor_t *descriptor_;
  value_storage *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
};

class string_value_mref {
public:
  constexpr static bool is_mutable = true;
  constexpr static bool is_repeated = false;

  string_value_mref(std::string_view &data, std::pmr::monotonic_buffer_resource &mr) noexcept
      : data_(&data), memory_resource_(&mr) {}
  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  void adopt(std::string_view v) const noexcept { *data_ = v; }

  void set(std::string_view v) const noexcept {
    assert(v.size() <= static_cast<std::size_t>(std::numeric_limits<int32_t>::max()));
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

} // namespace hpp_proto
