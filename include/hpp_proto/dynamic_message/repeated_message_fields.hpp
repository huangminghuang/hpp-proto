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
#include <memory>
#include <memory_resource>
#include <ranges>
#include <span>
#include <stdexcept>
#include <type_traits>

#include <hpp_proto/dynamic_message/message_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_field_iterator.hpp>
#include <hpp_proto/dynamic_message/storage.hpp>
#include <hpp_proto/dynamic_message/types.hpp>

namespace hpp::proto {
using enum field_kind_t;

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

  void reserve(std::size_t n) const {
    if (capacity() < n) {
      auto *new_data = static_cast<value_storage *>(
          memory_resource_->allocate(n * num_slots() * sizeof(value_storage), alignof(value_storage)));
      auto old_size = size();
      const auto total_slots = n * num_slots();
      const auto initialized_slots = old_size * num_slots();
      if (initialized_slots > 0) {
        auto *old_begin = storage_->content;
        auto *old_end = std::next(old_begin, static_cast<std::ptrdiff_t>(initialized_slots));
        std::uninitialized_copy(old_begin, old_end, new_data);
      }
      auto *construct_begin = std::next(new_data, static_cast<std::ptrdiff_t>(initialized_slots));
      const auto remaining_slots = total_slots - initialized_slots;
      if (remaining_slots > 0) {
        std::uninitialized_value_construct_n(construct_begin, remaining_slots);
      }
      storage_->content = new_data;
      storage_->capacity = static_cast<uint32_t>(n);
    }
  }

  void resize(std::size_t n) const {
    auto old_size = size();
    if (capacity() < n) {
      reserve(n);
    }
    storage_->size = static_cast<uint32_t>(n);
    if (n > old_size) {
      auto *start = std::next(storage_->content, static_cast<std::ptrdiff_t>(old_size * num_slots()));
      const auto count = (n - old_size) * num_slots();
      auto new_span = std::span{start, count};
      std::ranges::fill(new_span, value_storage{});
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

  [[nodiscard]] message_value_mref emplace_back() const {
    auto idx = size();
    resize(idx + 1);
    return (*this)[idx];
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

} // namespace hpp::proto
