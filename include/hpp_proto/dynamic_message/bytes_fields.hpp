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
#include <memory_resource>
#include <span>

#include <hpp_proto/dynamic_message/factory_addons.hpp>
#include <hpp_proto/dynamic_message/storage.hpp>
#include <hpp_proto/dynamic_message/types.hpp>

namespace hpp::proto {
using enum field_kind_t;

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

  bytes_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

  bytes_field_cref(const bytes_field_cref &) noexcept = default;
  bytes_field_cref(bytes_field_cref &&) noexcept = default;
  bytes_field_cref &operator=(const bytes_field_cref &) noexcept = default;
  bytes_field_cref &operator=(bytes_field_cref &&) noexcept = default;
  ~bytes_field_cref() noexcept = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->of_bytes.selection == descriptor().oneof_ordinal; }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] bytes_view value() const noexcept {
    if (descriptor().explicit_presence() && !has_value()) {
      const auto &default_value = descriptor_->proto().default_value;
      auto sval = std::span<const char>(default_value.data(), default_value.size());
      auto bspan = std::as_bytes(sval);
      return {bspan.data(), bspan.size()};
    }
    return {storage_->of_bytes.content, storage_->of_bytes.size};
  }

  [[nodiscard]] bool is_present_or_explicit_default() const noexcept {
    if (has_value()) {
      auto val = std::span{storage_->of_bytes.content, storage_->of_bytes.size};
      auto default_val = std::as_bytes(std::span{descriptor_->proto().default_value});
      return descriptor().explicit_presence() || !std::ranges::equal(val, default_val);
    } else {
      return false;
    }
  }

  [[nodiscard]] ::hpp::proto::value_proxy<value_type> operator->() const noexcept { return {value()}; }

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
  const value_storage *storage_;
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
      : descriptor_(&descriptor), storage_(&storage), memory_resource_(&mr) {}

  bytes_field_mref(const bytes_field_mref &) noexcept = default;
  bytes_field_mref(bytes_field_mref &&) noexcept = default;
  bytes_field_mref &operator=(const bytes_field_mref &) noexcept = default;
  bytes_field_mref &operator=(bytes_field_mref &&) noexcept = default;
  ~bytes_field_mref() = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  void adopt(std::span<const std::byte> v) const noexcept {
    storage_->of_bytes.content = v.data();
    storage_->of_bytes.size = static_cast<uint32_t>(v.size());
    storage_->of_bytes.selection = descriptor_->oneof_ordinal;
  }

  void set(concepts::contiguous_std_byte_range auto const &v) const {
    auto *dest = static_cast<std::byte *>(memory_resource_->allocate(v.size(), 1));
    std::copy(v.begin(), v.end(), dest);
    storage_->of_bytes.content = dest;
    storage_->of_bytes.size = static_cast<uint32_t>(v.size());
    storage_->of_bytes.selection = descriptor_->oneof_ordinal;
  }

  void alias_from(const cref_type &other) const noexcept { adopt(other.value()); }

  void clone_from(const cref_type &other) const {
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
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] bytes_view value() const noexcept { return cref().value(); }
  [[nodiscard]] ::hpp::proto::value_proxy<value_type> operator->() const noexcept { return {value()}; }

  void reset() const noexcept {
    storage_->of_bytes.size = 0;
    storage_->of_bytes.selection = 0;
  }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

private:
  const field_descriptor_t *descriptor_;
  value_storage *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
};

class bytes_value_mref {
public:
  constexpr static bool is_mutable = true;

  bytes_value_mref(hpp::proto::bytes_view &data, std::pmr::monotonic_buffer_resource &mr) noexcept
      : data_(&data), memory_resource_(&mr) {}
  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  void adopt(const hpp::proto::bytes_view &v) const noexcept { *data_ = v; }

  void set(concepts::contiguous_std_byte_range auto const &v) const {
    auto *dest = static_cast<std::byte *>(memory_resource_->allocate(v.size(), 1));
    std::copy(v.begin(), v.end(), dest);
    adopt(hpp::proto::bytes_view{dest, v.size()});
  }

  void clone_from(const hpp::proto::bytes_view &v) const { set(v); }

  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  operator hpp::proto::bytes_view() const noexcept { return *data_; }

private:
  hpp::proto::bytes_view *data_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
};

} // namespace hpp::proto
