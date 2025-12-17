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

#include <ranges>
#include <span>
#include <type_traits>

#include <hpp_proto/dynamic_message/factory.hpp>
#include <hpp_proto/dynamic_message/scalar_fields.hpp>
#include <hpp_proto/dynamic_message/storage.hpp>
#include <hpp_proto/dynamic_message/types.hpp>
#include <hpp_proto/pb_serializer.hpp>

namespace hpp::proto {
using enum field_kind_t;
/**
 * @brief Immutable enum value view (stores the value, not a reference).
 *
 * The `_cref` suffix is intentionally omitted: this type holds the numeric enum
 * value by copy and exposes its descriptor for name lookups.
 */
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
      : descriptor_(&descriptor), storage_(&storage), memory_resource_(&mr) {}

  repeated_scalar_field_mref(const repeated_scalar_field_mref &) noexcept = default;
  repeated_scalar_field_mref(repeated_scalar_field_mref &&) noexcept = default;
  repeated_scalar_field_mref &operator=(const repeated_scalar_field_mref &) noexcept = default;
  repeated_scalar_field_mref &operator=(repeated_scalar_field_mref &&) noexcept = default;
  ~repeated_scalar_field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  [[nodiscard]] repeated_scalar_field_cref<T, Kind> cref() const noexcept {
    return repeated_scalar_field_cref<T, Kind>{*descriptor_, access_storage()};
  }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator repeated_scalar_field_cref<T, Kind>() const noexcept { return cref(); }

  value_type &operator[](std::size_t index) const noexcept {
    auto &s = access_storage();
    assert(index < s.size);
    return *std::next(s.content, static_cast<std::ptrdiff_t>(index));
  }

  [[nodiscard]] value_type &at(std::size_t index) const {
    auto &s = access_storage();
    if (index < s.size) {
      return *std::next(s.content, static_cast<std::ptrdiff_t>(index));
    }
    throw std::out_of_range("");
  }

  void push_back(const value_type &v) const {
    auto idx = size();
    resize(idx + 1);
    (*this)[idx] = v;
  }

  void reserve(std::size_t n) const {
    auto &s = access_storage();
    if (s.capacity < n) {
      auto new_data =
          static_cast<value_type *>(memory_resource_->allocate(n * sizeof(value_type), alignof(value_type)));
      s.capacity = static_cast<uint32_t>(n);
      if (s.content) {
        std::uninitialized_copy(s.content, std::next(s.content, static_cast<std::ptrdiff_t>(s.size)), new_data);
      }
      s.content = new_data;
    }
  }

  void resize(std::size_t n) const {
    auto &s = access_storage();
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

  [[nodiscard]] bool empty() const noexcept { return access_storage().size == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return access_storage().size; }
  [[nodiscard]] std::size_t capacity() const noexcept { return access_storage().capacity; }
  [[nodiscard]] value_type *begin() const noexcept { return access_storage().content; }
  [[nodiscard]] value_type *end() const noexcept {
    auto &s = access_storage();
    return std::next(s.content, static_cast<std::ptrdiff_t>(s.size));
  }
  [[nodiscard]] value_type *data() const noexcept { return access_storage().content; }

  void reset() const noexcept {
    auto &s = access_storage();
    s.content = nullptr;
    s.size = 0;
  }
  void clear() const noexcept { access_storage().size = 0; }
  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }

  void adopt(std::span<value_type> s) const noexcept {
    auto &storage = access_storage();
    storage.content = s.data();
    storage.size = static_cast<uint32_t>(s.size());
  }

  template <std::ranges::sized_range Range>
    requires std::same_as<std::ranges::range_value_t<Range>, value_type>
  void set(const Range &s) const noexcept {
    resize(static_cast<std::size_t>(std::ranges::distance(s)));
    std::copy(s.begin(), s.end(), data());
  }

  void alias_from(const repeated_scalar_field_mref &other) const noexcept {
    assert(this->descriptor_ == &other.descriptor());
    access_storage() = other.access_storage();
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
  [[nodiscard]] storage_type &access_storage() const noexcept {
    if constexpr (std::is_same_v<value_type, int64_t>) {
      return storage_->of_repeated_int64;
    } else if constexpr (std::is_same_v<value_type, uint64_t>) {
      return storage_->of_repeated_uint64;
    } else if constexpr (std::is_same_v<value_type, int32_t>) {
      return storage_->of_repeated_int32;
    } else if constexpr (std::is_same_v<value_type, uint32_t>) {
      return storage_->of_repeated_uint32;
    } else if constexpr (std::is_same_v<value_type, double>) {
      return storage_->of_repeated_double;
    } else if constexpr (std::is_same_v<value_type, float>) {
      return storage_->of_repeated_float;
    } else if constexpr (std::is_same_v<value_type, bool>) {
      return storage_->of_repeated_bool;
    }
  }
  const field_descriptor_t *descriptor_;
  value_storage *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
};

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

} // namespace hpp::proto
