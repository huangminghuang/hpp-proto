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
#include <cstring>
#include <expected>
#include <memory_resource>
#include <optional>
#include <span>
#include <string_view>

#include <hpp_proto/dynamic_message/factory_addons.hpp>
#include <hpp_proto/dynamic_message/field_refs.hpp>
#include <hpp_proto/dynamic_message/storage.hpp>
#include <hpp_proto/dynamic_message/types.hpp>

namespace hpp_proto {
class message_value_cref {
  const message_descriptor_t *descriptor_;
  const value_storage *storage_;
  [[nodiscard]] std::size_t num_slots() const noexcept { return descriptor_->num_slots; }

  [[nodiscard]] const value_storage &storage_for(const field_descriptor_t &desc) const noexcept {
    return *std::next(storage_, static_cast<std::ptrdiff_t>(desc.storage_slot));
  }

  static const value_storage &empty_storage() noexcept {
    const static value_storage empty{};
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
  message_value_cref(const message_descriptor_t &descriptor, const value_storage &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}
  message_value_cref(const message_value_cref &) noexcept = default;
  message_value_cref(message_value_cref &&) noexcept = default;
  message_value_cref &operator=(const message_value_cref &) noexcept = default;
  message_value_cref &operator=(message_value_cref &&) noexcept = default;
  ~message_value_cref() noexcept = default;
  [[nodiscard]] const message_descriptor_t &descriptor() const noexcept { return *descriptor_; }

  [[nodiscard]] bool is_map_entry() const noexcept { return descriptor().is_map_entry(); }

  /**
   * Look up a field descriptor by proto name.
   *
   * Returns a pointer to the descriptor, or `nullptr` if no such field exists.
   */
  [[nodiscard]] const field_descriptor_t *field_descriptor_by_name(std::string_view name) const noexcept {
    auto field_descriptors = descriptor_->fields();
    auto it = std::ranges::find_if(field_descriptors, [name](const auto &desc) { return desc.proto().name == name; });
    if (it != field_descriptors.end()) {
      return std::addressof(*it);
    }
    return nullptr;
  }

  /**
   * Look up a field descriptor by JSON name.
   *
   * Returns a pointer to the descriptor, or `nullptr` if no such field exists.
   */
  [[nodiscard]] const field_descriptor_t *field_descriptor_by_json_name(std::string_view name) const noexcept {
    auto field_descriptors = descriptor_->fields();
    auto it =
        std::ranges::find_if(field_descriptors, [name](const auto &desc) { return desc.proto().json_name == name; });
    if (it != field_descriptors.end()) {
      return std::addressof(*it);
    }
    return nullptr;
  }

  /**
   * Look up a field descriptor by tag number.
   *
   * Returns a pointer to the descriptor, or `nullptr` if no such field exists.
   */
  [[nodiscard]] const field_descriptor_t *field_descriptor_by_number(uint32_t number) const noexcept {
    auto field_descriptors = descriptor_->fields();
    auto it = std::ranges::find_if(field_descriptors,
                                   [number](const auto &desc) { return std::cmp_equal(desc.proto().number, number); });
    if (it != field_descriptors.end()) {
      return std::addressof(*it);
    }
    return nullptr;
  }

  /**
   * Look up a oneof descriptor by proto name.
   *
   * Returns a pointer to the descriptor, or `nullptr` if no such field exists.
   */
  [[nodiscard]] const oneof_descriptor_t *oneof_descriptor(std::string_view name) const noexcept {
    auto oneofs = descriptor_->oneofs();
    auto it = std::ranges::find_if(oneofs, [name](const auto &oneof) { return oneof.proto().name == name; });
    if (it != oneofs.end()) {
      return std::addressof(*it);
    }
    return nullptr;
  }

  [[nodiscard]] field_cref field(const field_descriptor_t &desc) const noexcept {
    assert(desc.parent_message() == descriptor_);
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
    return field_by_name(name).and_then([](auto ref) { return ref.template get<T>(); });
  }

  template <typename T>
  [[nodiscard]] std::expected<T, dynamic_message_errc> field_value_by_number(std::uint32_t number) const noexcept {
    return field_by_number(number).and_then([](auto ref) { return ref.template get<T>(); });
  }

  [[nodiscard]] bool has_oneof(const oneof_descriptor_t &desc) const noexcept {
    if (!std::ranges::any_of(descriptor_->oneofs(), [&](const auto &oneof) { return &oneof == &desc; })) [[unlikely]] {
      return false;
    }
    if (desc.fields().empty()) [[unlikely]] {
      return false;
    }
    const auto &storage = *std::next(storage_, static_cast<std::ptrdiff_t>(desc.storage_slot()));
    return value_storage::read_selection_word(storage) != 0U;
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
 * @brief Mutable reference to a dynamic message.
 *
 * Lifetime: This reference is valid as long as the underlying message
 * storage (held by the monotonic_buffer_resource) remains valid.
 *
 * Memory Ownership:
 * - Scalar/string/bytes fields: owned by the message's memory resource
 * - Field values from adopt(): caller-managed; must outlive message
 */
class message_value_mref {
public:
  using cref_type = message_value_cref;
  constexpr static bool is_mutable = true;
  message_value_mref(const message_descriptor_t &descriptor, value_storage *storage,
                     std::pmr::monotonic_buffer_resource &memory_resource)
      : descriptor_(&descriptor), storage_(storage), memory_resource_(&memory_resource) {}

  message_value_mref(const message_descriptor_t &descriptor, std::pmr::monotonic_buffer_resource &memory_resource)
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

  [[nodiscard]] message_value_cref cref() const noexcept { return {*descriptor_, *storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator message_value_cref() const noexcept { return cref(); }

  [[nodiscard]] bool is_map_entry() const noexcept { return cref().is_map_entry(); }

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
    using diff_t = std::iter_difference_t<value_storage *>;
    std::ranges::fill_n(storage_, static_cast<diff_t>(num_slots()), value_storage{});
  }

  [[nodiscard]] field_mref field(const field_descriptor_t &desc) const noexcept {
    assert(desc.parent_message() == descriptor_);
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

  template <typename T>
  [[nodiscard]] std::expected<message_value_mref, dynamic_message_errc> set_field_by_name(std::string_view field_name,
                                                                                          T &&value) const {
    return field_by_name(field_name)
        .and_then([&value](auto field) { return field.set(std::forward<T>(value)); })
        .transform([this]() { return *this; });
  }

  template <typename CharT, std::size_t N>
    requires(std::same_as<std::remove_cv_t<CharT>, char>)
  [[nodiscard]] std::expected<message_value_mref, dynamic_message_errc> set_field_by_name(std::string_view field_name,
                                                                                          CharT (&value)[N]) const {
    auto chars = std::span<CharT, N>{value};
    const auto has_trailing_null = value[N - 1] == CharT{};
    const auto view_size = has_trailing_null ? N - 1 : N;
    return set_field_by_name(field_name, std::string_view{chars.data(), view_size});
  }

  template <typename T, std::size_t N>
    requires(!std::same_as<std::remove_cv_t<T>, char>)
  [[nodiscard]] std::expected<message_value_mref, dynamic_message_errc> set_field_by_name(std::string_view field_name,
                                                                                          T (&value)[N]) const {
    return set_field_by_name(field_name, std::span<T, N>{value});
  }

  template <typename T>
  std::expected<message_value_mref, dynamic_message_errc> set_field_by_number(std::uint32_t field_number,
                                                                              T &&value) const {
    return field_by_number(field_number)
        .and_then([&value](auto field) { return field.set(std::forward<T>(value)); })
        .transform([this]() { return *this; });
  }

  template <typename CharT, std::size_t N>
    requires(std::same_as<std::remove_cv_t<CharT>, char>)
  [[nodiscard]] std::expected<message_value_mref, dynamic_message_errc> set_field_by_number(std::uint32_t field_number,
                                                                                            CharT (&value)[N]) const {
    auto chars = std::span<CharT, N>{value};
    const auto has_trailing_null = value[N - 1] == CharT{};
    const auto view_size = has_trailing_null ? N - 1 : N;
    return set_field_by_number(field_number, std::string_view{chars.data(), view_size});
  }

  template <typename T, std::size_t N>
    requires(!std::same_as<std::remove_cv_t<T>, char>)
  [[nodiscard]] std::expected<message_value_mref, dynamic_message_errc> set_field_by_number(std::uint32_t field_number,
                                                                                            T (&value)[N]) const {
    return set_field_by_number(field_number, std::span<T, N>{value});
  }

  template <typename Mutator>
  std::expected<message_value_mref, dynamic_message_errc> modify_field_by_name(std::string_view field_name,
                                                                               Mutator &&mutator) const {
    return field_by_name(field_name)
        .and_then([mutator = std::forward<Mutator>(mutator)](auto field) mutable {
          return field.modify(std::forward<Mutator>(mutator));
        })
        .transform([this]() { return *this; });
  }

  template <typename Mutator>
  std::expected<message_value_mref, dynamic_message_errc> modify_field_by_number(std::uint32_t field_number,
                                                                                 Mutator &&mutator) const {
    return field_by_number(field_number)
        .and_then([mutator = std::forward<Mutator>(mutator)](auto field) mutable {
          return field.modify(std::forward<Mutator>(mutator));
        })
        .transform([this]() { return *this; });
  }

  void clear_field(const field_descriptor_t &desc) const noexcept {
    assert(desc.parent_message() == descriptor_);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    storage_for(desc).reset();
  }

  void clear_field(const oneof_descriptor_t &desc) const noexcept {
    if (!std::ranges::any_of(descriptor_->oneofs(), [&](const auto &oneof) { return &oneof == &desc; })) [[unlikely]] {
      return;
    }
    if (desc.fields().empty()) [[unlikely]] {
      return;
    }
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

  message_field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

  message_field_cref(const message_field_cref &) noexcept = default;
  message_field_cref(message_field_cref &&) noexcept = default;
  message_field_cref &operator=(const message_field_cref &) noexcept = default;
  message_field_cref &operator=(message_field_cref &&) noexcept = default;
  ~message_field_cref() noexcept = default;

  [[nodiscard]] bool has_value() const noexcept { return storage_->selection_matches(descriptor().oneof_ordinal); }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] value_type value() const {
    if (!has_value()) {
      throw std::bad_optional_access{};
    }
    return {message_descriptor(), *(storage_->of_message.content)};
  }

  [[nodiscard]] bool is_present_or_explicit_default() const noexcept { return has_value(); }

  [[nodiscard]] ::hpp_proto::value_proxy<value_type> operator->() const noexcept { return {operator*()}; }
  [[nodiscard]] value_type operator*() const noexcept {
    return {message_descriptor(), *(storage_->of_message.content)};
  }

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
  const value_storage *storage_;
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
      : descriptor_(&descriptor), storage_(&storage), memory_resource_(&mr) {
    assert(descriptor.message_field_type_descriptor() != nullptr);
  }

  message_field_mref(const message_field_mref &) noexcept = default;
  message_field_mref(message_field_mref &&) noexcept = default;
  message_field_mref &operator=(const message_field_mref &) noexcept = default;
  message_field_mref &operator=(message_field_mref &&) noexcept = default;
  ~message_field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  [[nodiscard]] cref_type cref() const noexcept { return cref_type{*descriptor_, *storage_}; }

  message_value_mref emplace() const { // NOLINT(modernize-use-nodiscard)
    if (!has_value()) {
      storage_->of_message.selection = descriptor_->oneof_ordinal;
      storage_->of_message.content = static_cast<value_storage *>(
          memory_resource_->allocate(sizeof(value_storage) * num_slots(), alignof(value_storage)));
    }
    auto result = message_value_mref{message_descriptor(), storage_->of_message.content, *memory_resource_};
    result.reset();
    return result;
  }

  void set_as_default() const { (void)emplace(); }

  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] value_type value() const {
    if (!has_value()) {
      throw std::bad_optional_access{};
    }
    return {message_descriptor(), storage_->of_message.content, *memory_resource_};
  }
  [[nodiscard]] ::hpp_proto::value_proxy<value_type> operator->() const noexcept { return {operator*()}; }
  [[nodiscard]] value_type operator*() const noexcept {
    return {message_descriptor(), storage_->of_message.content, *memory_resource_};
  }

  template <typename U>
  [[nodiscard]] auto get() const {
    return cref().get<U>();
  }

  void reset() const noexcept { storage_->of_message.selection = 0; }

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] const message_descriptor_t &message_descriptor() const noexcept {
    return *descriptor_->message_field_type_descriptor();
  }

  void alias_from(const message_field_mref &other) const noexcept {
    assert(&message_descriptor() == &other.message_descriptor());
    storage_->of_message = other.storage_->of_message;
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
  value_storage *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;
  [[nodiscard]] std::size_t num_slots() const noexcept { return message_descriptor().num_slots; }
};
} // namespace hpp_proto
