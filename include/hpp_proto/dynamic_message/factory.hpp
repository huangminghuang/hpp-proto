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
#include <hpp_proto/dynamic_message/export.hpp>
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
class HPP_PROTO_DYNAMIC_MESSAGE_EXPORT dynamic_message_factory {
private:
  using file_descriptor_set_type = ::google::protobuf::FileDescriptorSet<non_owning_traits>;

public:
  using allocator_type = std::pmr::polymorphic_allocator<detail::dynamic_message_factory_impl>;

  /**
   * @brief Default wire-size limit for serialized descriptor inputs: 16 MiB.
   *
   * This limit applies before decoding to the complete serialized `FileDescriptorSet`, or to the sum of all encoded
   * `FileDescriptorProto` values passed through the distinct-descriptor overload. It bounds input retention and the
   * parser work directly attributable to encoded bytes, but it does not bound decoded memory: very small protobuf
   * submessages can expand into much larger C++ objects. The in-memory `FileDescriptorSet` overload has no encoded
   * representation and therefore does not use this limit.
   */
  static constexpr std::size_t max_serialized_descriptor_bytes = std::size_t{16} * 1024U * 1024U;

  /**
   * @brief Default live-memory limit for factory-owned descriptor state: 64 MiB.
   *
   * This limit applies to every factory entry point. It covers allocations made by binary decoding, persistent
   * descriptor-pool containers and descriptor internals, plus temporary validation structures. Persistent state uses
   * a monotonic arena, so its allocation remains live until the factory is destroyed; temporary scratch allocations
   * restore budget when released. The budget counts bytes requested from the caller's upstream memory resource and
   * can include allocator or arena growth overhead. It does not include the factory implementation object itself,
   * caller-owned input buffers, or unrelated allocations outside descriptor construction.
   */
  static constexpr std::size_t max_descriptor_memory_bytes = std::size_t{64} * 1024U * 1024U;

  /**
   * @brief Per-factory resource limits.
   *
   * Raising either limit permits larger schemas but increases the CPU or memory available to untrusted descriptors.
   * `std::numeric_limits<std::size_t>::max()` can be used as an effectively unlimited value when input is trusted.
   * Defaults preserve the 16 MiB encoded-input and 64 MiB live-memory limits above.
   */
  struct limits {
    /// Maximum encoded bytes accepted by serialized factory overloads; ignored by the in-memory overload.
    std::size_t max_serialized_bytes = max_serialized_descriptor_bytes;
    /// Maximum live bytes allocated for decoding, descriptor storage, indexing, and validation scratch space.
    std::size_t max_memory_bytes = max_descriptor_memory_bytes;
  };

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
  create_from_fileset(file_descriptor_set_type &&fileset, limits resource_limits, allocator_type allocator);

  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create_from_descs(std::span<const file_descriptor_pb> descs, limits resource_limits, allocator_type allocator);

  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create_from_binpb(std::span<const std::byte> file_descriptor_set_binpb, limits resource_limits,
                    allocator_type allocator);

public:
  dynamic_message_factory(const dynamic_message_factory &) = delete;
  dynamic_message_factory(dynamic_message_factory &&) noexcept;
  dynamic_message_factory &operator=(const dynamic_message_factory &) = delete;
  dynamic_message_factory &operator=(dynamic_message_factory &&) noexcept;
  ~dynamic_message_factory();

  /**
   * @brief Construct and initialize from FileDescriptorSet.
   * @details This is a trusted-input API and does not enforce a serialized-size or parser-recursion limit. Descriptor
   *          storage is limited to max_descriptor_memory_bytes. Exhausting that budget returns
   *          descriptor_memory_limit_exceeded; unrelated std::bad_alloc exceptions remain uncaught. Prefer a
   *          serialized overload for untrusted input.
   * @param allocator Allocator used to create the internal impl object. Its memory_resource()
   *                  must outlive the returned factory instance.
   */
  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create(file_descriptor_set_type &&fileset, allocator_type allocator = {}) {
    return create_from_fileset(std::move(fileset), limits{}, allocator);
  }

  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create(file_descriptor_set_type &&fileset, limits resource_limits, allocator_type allocator = {}) {
    return create_from_fileset(std::move(fileset), resource_limits, allocator);
  }

  /**
   * @brief Construct and initialize from distinct serialized file descriptors.
   * @details Returns descriptor_size_limit_exceeded when the aggregate encoded descriptors exceed
   *          max_serialized_descriptor_bytes, or descriptor_memory_limit_exceeded when decoded descriptors and pool
   *          storage exceed max_descriptor_memory_bytes. Unrelated std::bad_alloc exceptions remain uncaught.
   * @param allocator Allocator used to create the internal impl object. Its memory_resource()
   *                  must outlive the returned factory instance.
   */
  template <std::size_t N>
  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create(const distinct_file_descriptor_pb_array<N> &descs, allocator_type allocator = {}) {
    return create_from_descs(std::span<const file_descriptor_pb>(std::data(descs), std::size(descs)), limits{},
                             allocator);
  }

  template <std::size_t N>
  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create(const distinct_file_descriptor_pb_array<N> &descs, limits resource_limits, allocator_type allocator = {}) {
    return create_from_descs(std::span<const file_descriptor_pb>(std::data(descs), std::size(descs)), resource_limits,
                             allocator);
  }

  /**
   * @brief Construct and initialize from serialized FileDescriptorSet bytes.
   * @details Returns descriptor_size_limit_exceeded when the input exceeds max_serialized_descriptor_bytes. Binary
   *          parsing also enforces its default recursion limit. Decoded descriptors and pool storage are limited to
   *          max_descriptor_memory_bytes; exhausting that budget returns descriptor_memory_limit_exceeded. Unrelated
   *          std::bad_alloc exceptions remain uncaught.
   * @param allocator Allocator used to create the internal impl object. Its memory_resource()
   *                  must outlive the returned factory instance.
   */
  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create(concepts::contiguous_byte_range auto &&file_descriptor_set_binpb, allocator_type allocator = {}) {
    return create_from_binpb(std::as_bytes(std::span{std::ranges::data(file_descriptor_set_binpb),
                                                     std::ranges::size(file_descriptor_set_binpb)}),
                             limits{}, allocator);
  }

  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create(concepts::contiguous_byte_range auto &&file_descriptor_set_binpb, limits resource_limits,
         allocator_type allocator = {}) {
    return create_from_binpb(std::as_bytes(std::span{std::ranges::data(file_descriptor_set_binpb),
                                                     std::ranges::size(file_descriptor_set_binpb)}),
                             resource_limits, allocator);
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
