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

#include <memory>
#include <memory_resource>
#include <ranges>
#include <span>
#include <string_view>

#include <hpp_proto/dynamic_message/factory_addons.hpp>
#include <hpp_proto/dynamic_message/repeated_field_iterator.hpp>
#include <hpp_proto/dynamic_message/repeated_scalar_fields.hpp>
#include <hpp_proto/dynamic_message/string_fields.hpp>
#include <hpp_proto/dynamic_message/types.hpp>

namespace hpp::proto {
using enum field_kind_t;

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
      : descriptor_(&descriptor), storage_(&storage), memory_resource_(&mr) {}

  repeated_string_field_mref(const repeated_string_field_mref &) noexcept = default;
  repeated_string_field_mref(repeated_string_field_mref &&) noexcept = default;
  repeated_string_field_mref &operator=(const repeated_string_field_mref &) noexcept = default;
  repeated_string_field_mref &operator=(repeated_string_field_mref &&) noexcept = default;
  ~repeated_string_field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  [[nodiscard]] repeated_string_field_cref cref() const noexcept {
    return repeated_string_field_cref{*descriptor_, storage_->of_repeated_string};
  }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator repeated_string_field_cref() const noexcept { return cref(); }

  void reserve(std::size_t n) const {
    auto &s = storage_->of_repeated_string;
    if (s.capacity < n) {
      auto *new_data = static_cast<std::string_view *>(
          memory_resource_->allocate(n * sizeof(std::string_view), alignof(value_type)));
      std::uninitialized_copy(s.content, std::next(s.content, static_cast<std::ptrdiff_t>(s.size)), new_data);
      s.content = new_data;
      s.capacity = static_cast<uint32_t>(n);
    }
  }

  void resize(std::size_t n) const {
    auto &s = storage_->of_repeated_string;
    const auto old_size = s.size;
    if (s.capacity < n) {
      reserve(n);
    }
    if (old_size < n) {
      std::uninitialized_default_construct(std::next(s.content, static_cast<std::ptrdiff_t>(old_size)),
                                           std::next(s.content, static_cast<std::ptrdiff_t>(n)));
    }
    s.size = static_cast<uint32_t>(n);
  }

  [[nodiscard]] bool empty() const noexcept { return storage_->of_repeated_string.size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return storage_->of_repeated_string.size; }
  [[nodiscard]] std::size_t capacity() const noexcept { return storage_->of_repeated_string.capacity; }
  [[nodiscard]] iterator begin() const noexcept { return {this, 0}; }
  [[nodiscard]] iterator end() const noexcept { return {this, storage_->of_repeated_string.size}; }
  [[nodiscard]] std::string_view *data() const noexcept { return storage_->of_repeated_string.content; }

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

  void push_back(std::string_view v) const {
    auto idx = size();
    resize(idx + 1);
    (*this)[idx].set(v);
  }

  void reset() const noexcept {
    storage_->of_repeated_string.content = nullptr;
    storage_->of_repeated_string.size = 0;
  }

  void clear() const noexcept { storage_->of_repeated_string.size = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

  void adopt(std::span<std::string_view> s) const noexcept {
    auto &storage = storage_->of_repeated_string;
    storage.content = s.data();
    storage.capacity = static_cast<uint32_t>(s.size());
    storage.size = static_cast<uint32_t>(s.size());
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
    return {storage_->of_repeated_string.content, static_cast<std::size_t>(storage_->of_repeated_string.size)};
  }
  const field_descriptor_t *descriptor_;
  value_storage *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
};

} // namespace hpp::proto
