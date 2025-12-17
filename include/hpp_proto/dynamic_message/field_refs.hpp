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
#include <compare>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <string_view>

#include <hpp_proto/dynamic_message/factory.hpp>
#include <hpp_proto/dynamic_message/repeated_bytes_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_enum_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_scalar_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_string_fields.hpp>
#include <hpp_proto/dynamic_message/scalar_fields.hpp>
#include <hpp_proto/dynamic_message/storage.hpp>
#include <hpp_proto/dynamic_message/types.hpp>

namespace hpp::proto {

/**
 * @brief Untyped, read-only reference to a single field in a dynamic message.
 *
 * This wrapper provides presence checks and type-erased access via `get<T>()`, which
 * dispatches to the underlying typed field view if the requested type matches.
 */
class field_cref {
  const field_descriptor_t *descriptor_;
  const value_storage *storage_;
  friend class field_mref;

public:
  field_cref(const field_descriptor_t &descriptor, const value_storage &storage) noexcept
      : descriptor_(&descriptor), storage_(&storage) {}

  field_cref(const field_cref &) noexcept = default;
  field_cref(field_cref &&) noexcept = default;
  field_cref &operator=(const field_cref &) noexcept = default;
  field_cref &operator=(field_cref &&) noexcept = default;
  ~field_cref() noexcept = default;

  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] field_kind_t field_kind() const noexcept {
    // map TYPE_GROUP to TYPE_MESSAGE
    using enum google::protobuf::FieldDescriptorProto_::Type;
    auto base_type = descriptor().proto().type == TYPE_GROUP ? TYPE_MESSAGE : descriptor().proto().type;
    return static_cast<field_kind_t>(std::to_underlying(base_type) +
                                     (18 * static_cast<int>(descriptor().is_repeated())));
  }

  [[nodiscard]] bool explicit_presence() const noexcept { return descriptor_->explicit_presence(); }

  [[nodiscard]] bool has_value() const noexcept {
    return descriptor().is_repeated() ? (storage_->of_repeated_uint64.size > 0)
                                      : (storage_->of_int64.selection == descriptor().oneof_ordinal);
  }

  /// if the field is part of an oneof fields, return the active field index of the oneof. If the returned
  /// value is smaller than 0, it means the oneof does not contains any value.
  [[nodiscard]] std::int32_t active_oneof_index() const {
    return static_cast<std::int32_t>(storage_->of_int64.selection + descriptor().storage_slot) -
           descriptor().oneof_ordinal;
  }

  template <typename T>
  [[nodiscard]] std::optional<T> to() const noexcept {
    if (T::field_kind == field_kind()) {
      return T(*descriptor_, *storage_);
    }
    return std::nullopt;
  }

  auto visit(auto &&v) const;
  template <typename T>
  [[nodiscard]] auto get() const noexcept -> std::expected<typename get_traits<T>::type, dynamic_message_errc> {
    return visit([](auto cref) -> std::expected<typename get_traits<T>::type, dynamic_message_errc> {
      if constexpr (requires { cref.template get<T>(); }) {
        return cref.template get<T>();
      } else {
        return std::unexpected(dynamic_message_errc::invalid_field_type);
      }
    });
  }
}; // class field_cref

/**
 * @brief Mutable, untyped reference to a single field in a dynamic message.
 *
 * Offers type-erased mutation via `set<T>()` (copying into message-owned storage)
 * or `adopt<T>()` (aliasing caller-provided storage where supported), presence checks,
 * and conversion to a read-only `field_cref`.
 */
class field_mref {
  const field_descriptor_t *descriptor_;
  value_storage *storage_;
  std::pmr::monotonic_buffer_resource *memory_resource_;

public:
  field_mref(const field_descriptor_t &descriptor, value_storage &storage,
             std::pmr::monotonic_buffer_resource &mr) noexcept
      : descriptor_(&descriptor), storage_(&storage), memory_resource_(&mr) {}

  field_mref(const field_mref &) noexcept = default;
  field_mref(field_mref &&) noexcept = default;
  field_mref &operator=(const field_mref &) noexcept = default;
  field_mref &operator=(field_mref &&) noexcept = default;
  ~field_mref() noexcept = default;

  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() const noexcept { return *memory_resource_; }

  void reset() noexcept { storage_->reset(); }
  [[nodiscard]] const field_descriptor_t &descriptor() const noexcept { return *descriptor_; }
  [[nodiscard]] field_kind_t field_kind() const noexcept { return cref().field_kind(); }

  [[nodiscard]] bool explicit_presence() const noexcept { return descriptor_->explicit_presence(); }
  [[nodiscard]] bool has_value() const noexcept { return cref().has_value(); }

  template <typename T>
  [[nodiscard]] std::optional<T> to() const noexcept {
    if (T::field_kind == field_kind()) {
      return T(*descriptor_, *storage_, *memory_resource_);
    }
    return std::nullopt;
  }

  [[nodiscard]] field_cref cref() const noexcept { return {*descriptor_, *storage_}; }
  // NOLINTNEXTLINE(hicpp-explicit-conversions)
  [[nodiscard]] operator field_cref() const noexcept { return cref(); }
  auto visit(auto &&v) const;
  void alias_from(const field_mref &other) const noexcept {
    assert(this->descriptor_ == other.descriptor_);
    *storage_ = *other.storage_;
  }
  void clone_from(const field_cref &other) const noexcept;

  template <typename T>
  [[nodiscard]] auto get() const noexcept {
    return cref().get<T>();
  }

  template <typename T>
  [[nodiscard]] auto set(T v) const noexcept -> std::expected<void, dynamic_message_errc> {
    return visit([&v](auto mref) -> std::expected<void, dynamic_message_errc> {
      using mref_type = decltype(mref);
      if constexpr (mref_type::template settable_from_v<T>) {
        if constexpr (requires {
                        { mref.set(v) } -> std::same_as<void>;
                      }) {
          mref.set(v);
          return {};
        } else {
          return mref.set(v);
        }
      } else {
        return std::unexpected(dynamic_message_errc::invalid_field_type);
      }
    });
  }

  template <typename T>
  [[nodiscard]] auto adopt(T v) const noexcept -> std::expected<void, dynamic_message_errc> {
    return visit([&v](auto mref) -> std::expected<void, dynamic_message_errc> {
      if constexpr (requires { mref.adopt(v); }) {
        mref.adopt(v);
        return {};
      } else {
        return std::unexpected(dynamic_message_errc::invalid_field_type);
      }
    });
  }

  template <typename Mutator>
  [[nodiscard]] std::expected<void, dynamic_message_errc> modify(Mutator &&mutator) const {
    return visit(
        [mutator = std::forward<Mutator>(mutator)](auto mref) mutable -> std::expected<void, dynamic_message_errc> {
          if constexpr (requires { mutator(mref); }) {
            return mutator(mref);
          } else {
            return std::unexpected(dynamic_message_errc::invalid_field_type);
          }
        });
  }

  void set_null() noexcept;
}; // class field_mref

} // namespace hpp::proto
