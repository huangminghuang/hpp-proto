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

inline constexpr std::size_t max_descriptor_memory_bytes = std::size_t{64} * 1024U * 1024U;

/**
 * @brief Per-factory descriptor-memory configuration.
 *
 * Raising the limit permits larger schemas but increases the memory available to descriptor construction.
 * `std::numeric_limits<std::size_t>::max()` can be used as an effectively unlimited value. Serialized input size is
 * deliberately not limited here: callers must bound untrusted input before invoking the factory. The factory owns
 * the limited resource and descriptor arena constructed from this configuration, but it does not own `upstream`.
 */
struct descriptor_memory_options {
  /// Maximum live bytes allocated for decoding, descriptor storage, indexing, and validation scratch space.
  std::size_t limit = max_descriptor_memory_bytes;
  /// Non-owning upstream resource used for the factory implementation and its owned limited descriptor resource.
  /// Passing nullptr makes dynamic_message_factory::create() return invalid_descriptor_memory_options.
  std::pmr::memory_resource *upstream = std::pmr::get_default_resource();
};

/**
 * @brief Factory that builds dynamic message instances from descriptor sets.
 *
 * Instances are created via `create(...)` and own an internal implementation
 * object that stores descriptor state and PMR resources. Descriptor inputs are
 * trusted and prevalidated. Callers receiving serialized descriptors from an
 * untrusted source must bound and validate the input before calling `create()`,
 * consistent with the `read_binpb()` contract.
 */
class HPP_PROTO_DYNAMIC_MESSAGE_EXPORT dynamic_message_factory {
private:
  using file_descriptor_set_type = ::google::protobuf::FileDescriptorSet<non_owning_traits>;

public:
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
  static constexpr std::size_t max_descriptor_memory_bytes = hpp_proto::max_descriptor_memory_bytes;

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
  create_from_fileset(file_descriptor_set_type &&fileset, descriptor_memory_options memory_options);

  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create_from_descs(std::span<const file_descriptor_pb> descs, descriptor_memory_options memory_options);

  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create_from_binpb(std::span<const std::byte> file_descriptor_set_binpb, descriptor_memory_options memory_options);

public:
  dynamic_message_factory(const dynamic_message_factory &) = delete;
  dynamic_message_factory(dynamic_message_factory &&) noexcept;
  dynamic_message_factory &operator=(const dynamic_message_factory &) = delete;
  dynamic_message_factory &operator=(dynamic_message_factory &&) noexcept;
  ~dynamic_message_factory();

  /**
   * @brief Construct and initialize from FileDescriptorSet.
   * @details This is a trusted-input API. Descriptor storage is limited to max_descriptor_memory_bytes. Exhausting
   *          that budget returns descriptor_memory_limit_exceeded; unrelated std::bad_alloc exceptions remain
   *          uncaught.
   * @param memory_options Descriptor-memory limit and upstream resource. A null upstream returns
   *                       invalid_descriptor_memory_options; otherwise the resource must outlive the returned factory.
   */
  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create(file_descriptor_set_type &&fileset, descriptor_memory_options memory_options = {}) {
    return create_from_fileset(std::move(fileset), memory_options);
  }

  /**
   * @brief Construct and initialize from distinct serialized file descriptors.
   * @details The encoded descriptors are trusted, prevalidated input and are not size-limited by the factory. Callers
   *          accepting them from an untrusted source must enforce an aggregate input bound before calling `create()`.
   *          Decoded descriptors and pool storage are limited to max_descriptor_memory_bytes; exhausting that budget
   *          returns descriptor_memory_limit_exceeded. Unrelated std::bad_alloc exceptions remain uncaught.
   * @param memory_options Descriptor-memory limit and upstream resource. A null upstream returns
   *                       invalid_descriptor_memory_options; otherwise the resource must outlive the returned factory.
   */
  template <std::size_t N>
  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create(const distinct_file_descriptor_pb_array<N> &descs, descriptor_memory_options memory_options = {}) {
    return create_from_descs(std::span<const file_descriptor_pb>(std::data(descs), std::size(descs)), memory_options);
  }

  /**
   * @brief Construct and initialize from serialized FileDescriptorSet bytes.
   * @details The byte range is trusted, prevalidated input and is not size-limited by the factory. Callers accepting
   *          it from an untrusted source must enforce a transport or buffer-size bound before calling `create()`.
   *          Binary parsing still enforces its default recursion limit. Decoded descriptors and pool storage are
   *          limited to max_descriptor_memory_bytes; exhausting that budget returns descriptor_memory_limit_exceeded.
   *          Unrelated std::bad_alloc exceptions remain uncaught.
   * @param memory_options Descriptor-memory limit and upstream resource. A null upstream returns
   *                       invalid_descriptor_memory_options; otherwise the resource must outlive the returned factory.
   */
  [[nodiscard]] static std::expected<dynamic_message_factory, dynamic_message_errc>
  create(concepts::contiguous_byte_range auto &&file_descriptor_set_binpb,
         descriptor_memory_options memory_options = {}) {
    return create_from_binpb(std::as_bytes(std::span{std::ranges::data(file_descriptor_set_binpb),
                                                     std::ranges::size(file_descriptor_set_binpb)}),
                             memory_options);
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
