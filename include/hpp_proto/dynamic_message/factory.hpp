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

#include <cstddef>
#include <expected>
#include <functional>
#include <memory>
#include <memory_resource>
#include <ranges>
#include <span>
#include <string_view>
#include <utility>

#include <google/protobuf/descriptor.pb.hpp>
#include <hpp_proto/binpb/concepts.hpp>
#include <hpp_proto/dynamic_message/expected_message_mref.hpp>
#include <hpp_proto/file_descriptor_pb.hpp>

namespace hpp_proto {

namespace detail {
class dynamic_message_factory_impl;
} // namespace detail

/**
 * @brief Factory that builds dynamic message instances from descriptor sets.
 *
 * Instances are created via `create(...)` and own an internal implementation
 * object that stores descriptor state and PMR resources.
 */
class dynamic_message_factory {
private:
  using file_descriptor_set_type = ::google::protobuf::FileDescriptorSet<non_owning_traits>;

public:
  using impl_allocator_type = std::pmr::polymorphic_allocator<detail::dynamic_message_factory_impl>;

  /// enable to pass dynamic_message_factory as an option to read_json()/write_json()
  using option_type = std::reference_wrapper<dynamic_message_factory>;

private:
  struct impl_deleter {
    void operator()(detail::dynamic_message_factory_impl *p) noexcept;
  };
  using impl_ptr = std::unique_ptr<detail::dynamic_message_factory_impl, impl_deleter>;

  impl_ptr impl_;

  explicit dynamic_message_factory(impl_ptr impl) noexcept;

  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create_from_fileset(file_descriptor_set_type &&fileset, impl_allocator_type allocator);

  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create_from_descs(std::span<const file_descriptor_pb> descs, impl_allocator_type allocator);

  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create_from_binpb(std::span<const std::byte> file_descriptor_set_binpb, impl_allocator_type allocator);

public:
  dynamic_message_factory(const dynamic_message_factory &) = delete;
  dynamic_message_factory(dynamic_message_factory &&) noexcept;
  dynamic_message_factory &operator=(const dynamic_message_factory &) = delete;
  dynamic_message_factory &operator=(dynamic_message_factory &&) noexcept;
  ~dynamic_message_factory();

  /**
   * @brief Construct and initialize from FileDescriptorSet.
   * @details This API does not catch std::bad_alloc thrown by standard containers.
   */
  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create(file_descriptor_set_type &&fileset, impl_allocator_type allocator = {}) {
    return create_from_fileset(std::move(fileset), allocator);
  }

  /**
   * @brief Construct and initialize from distinct serialized file descriptors.
   * @details This API does not catch std::bad_alloc thrown by standard containers.
   */
  template <std::size_t N>
  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create(const distinct_file_descriptor_pb_array<N> &descs, impl_allocator_type allocator = {}) {
    return create_from_descs(std::span<const file_descriptor_pb>(std::data(descs), std::size(descs)), allocator);
  }

  /**
   * @brief Construct and initialize from serialized FileDescriptorSet bytes.
   * @details This API does not catch std::bad_alloc thrown by standard containers.
   */
  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create(concepts::contiguous_byte_range auto &&file_descriptor_set_binpb, impl_allocator_type allocator = {}) {
    return create_from_binpb(
        std::as_bytes(std::span{std::ranges::data(file_descriptor_set_binpb), std::ranges::size(file_descriptor_set_binpb)}),
        allocator);
  }

  /**
   * @brief Construct a mutable dynamic message for the given type name.
   *
   * @param name Fully-qualified protobuf message name.
   * @param mr   Monotonic buffer resource used for allocating message storage.
   */
  [[nodiscard]] expected_message_mref get_message(std::string_view name, std::pmr::monotonic_buffer_resource &mr) const;
};

class use_factory {
  dynamic_message_factory *factory_;

public:
  using option_type = use_factory;
  explicit use_factory(dynamic_message_factory &f) : factory_(&f) {}
  [[nodiscard]] dynamic_message_factory &get_dynamic_message_factory() const { return *factory_; }
};

} // namespace hpp_proto
