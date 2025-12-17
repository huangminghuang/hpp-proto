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
#include <variant>

#include <hpp_proto/dynamic_message/enum_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_field_iterator.hpp>
#include <hpp_proto/dynamic_message/scalar_fields.hpp>
#include <hpp_proto/dynamic_message/storage.hpp>
#include <hpp_proto/dynamic_message/types.hpp>

namespace hpp::proto {
using enum field_kind_t;


/**
 * @brief Bulk helper to pass a span of enum numbers to repeated enum setters.
 *
 * Example (set): `rep_enum.set(enum_numbers_span{nums_span});`
 * Example (get):  `auto nums = rep_enum.get<enum_numbers_span>();`
 */
struct enum_numbers_span {
  std::span<std::int32_t> value;
};

/**
 * @brief Sized range of enum numbers for bulk set on repeated enums.
 *
 * Example:
 * ```
 * std::array<int32_t, 2> nums{1, 2};
 * rep_enum.set(enum_numbers_range{nums});
 * ```
 */
template <typename Range>
struct enum_numbers_range {
  using is_enum_numbers_range = void;
  const Range &value; // NOLINT
};

template <typename T>
  requires(std::ranges::sized_range<T> && std::is_convertible_v<range_value_or_void_t<T>, std::int32_t>)
enum_numbers_range(const T &v) -> enum_numbers_range<T>;

/**
 * @brief Sized range of enum names for bulk set on repeated enums.
 *
 * Example:
 * ```
 * std::array<std::string_view, 2> names{"OPEN", "CLOSED"};
 * rep_enum.set(enum_names_range{names});
 * ```
 */
template <typename Range>
struct enum_names_range {
  using is_enum_names_range = void;
  const Range &value; // NOLINT
};

template <typename T>
  requires(std::ranges::sized_range<T> && std::is_convertible_v<range_value_or_void_t<T>, std::string_view>)
enum_names_range(const T &v) -> enum_names_range<T>;

template <>
struct get_traits<enum_numbers_span> {
  using type = std::span<const std::int32_t>;
};

inline auto enum_numbers_to_names(const enum_descriptor_t &descriptor, std::span<const std::int32_t> numbers) {
  return std::views::transform(numbers, [&descriptor](std::int32_t v) { return descriptor.name_of(v); });
}

using enum_names_view = decltype(enum_numbers_to_names(std::declval<const enum_descriptor_t &>(),
                                                       std::declval<std::span<const std::int32_t>>()));

/**
 * @brief Sized range of enum numbers for bulk set on repeated enums.
 *
 * Example:
 * ```
 * std::array<int32_t, 2> nums{1, 2};
 * rep_enum.set(enum_numbers_range{nums});
 * ```
 */
class repeated_enum_field_cref : public std::ranges::view_interface<repeated_enum_field_cref> {
public:
  using storage_type = repeated_storage_base<int32_t>;
  using encode_type = vint64_t;
  using value_type = enum_value;
  using reference = enum_value;
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
  using value_type = enum_value_mref;
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

  void reserve(std::size_t n) const {
    if (capacity() < n) {
      auto *new_data = static_cast<int32_t *>(memory_resource_->allocate(n * sizeof(int32_t), alignof(int32_t)));
      std::uninitialized_copy(storage_->content, std::next(storage_->content, static_cast<std::ptrdiff_t>(size())),
                              new_data);
      storage_->content = new_data;
      storage_->capacity = static_cast<uint32_t>(n);
    }
  }

  void resize(std::size_t n) const {
    const auto old_size = size();
    if (capacity() < n) {
      reserve(n);
    }
    if (old_size < n) {
      std::uninitialized_default_construct(std::next(storage_->content, static_cast<std::ptrdiff_t>(old_size)),
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

  void push_back(enum_number number) const {
    auto idx = size();
    resize(idx + 1);
    auto values = std::span{storage_->content, storage_->size};
    values[idx] = number.value;
  }

  [[nodiscard]] std::expected<void, dynamic_message_errc> push_back(enum_name name) const {
    const auto *pval = enum_descriptor().value_of(name.value);
    if (pval == nullptr) {
      return std::unexpected(dynamic_message_errc::invalid_enum_name);
    }
    push_back(enum_number{*pval});
    return {};
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

} // namespace hpp::proto
