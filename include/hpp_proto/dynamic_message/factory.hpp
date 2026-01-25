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

#include <memory>
#include <memory_resource>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <hpp_proto/binpb.hpp>
#include <hpp_proto/dynamic_message/expected_message_mref.hpp>
#include <hpp_proto/dynamic_message/factory_addons.hpp>

namespace hpp::proto {

/**
 * @brief Factory that builds dynamic message instances from descriptor sets.
 *
 * The factory owns a descriptor pool created from provided FileDescriptorSets and can
 * spawn mutable message views (`message_value_mref`) backed by a user-supplied
 * monotonic_buffer_resource. It also exposes access to the loaded file descriptors.
 */
class dynamic_message_factory {
  std::pmr::monotonic_buffer_resource memory_resource_;
  descriptor_pool_t pool_;
  bool initialized_ = false;

  void setup_storage_slots();
  void setup_wellknown_types();
  void setup_enum_field_default_value();
  void init();

public:
  using FileDescriptorSet = ::google::protobuf::FileDescriptorSet<dynamic_message_factory_addons::traits_type>;

  /// enable to pass dynamic_message_factory as an option to read_json()/write_json()
  using option_type = std::reference_wrapper<dynamic_message_factory>;

  dynamic_message_factory() = default;

  /**
   * @brief Construct a factory with an in-place monotonic buffer resource.
   *
   * The constructor forwards `memory_resource_init_args...` to
   * `std::pmr::monotonic_buffer_resource`, letting callers optionally provide a
   * backing buffer and upstream resource. Use `init(...)` afterward to populate
   * the descriptor pool before calling `get_message()`.
   */
  explicit dynamic_message_factory(auto &&...memory_resource_init_args)
      : memory_resource_(std::forward<decltype(memory_resource_init_args)>(memory_resource_init_args)...) {}

  /**
   * @brief Initialize the object from a FileDescriptorSet
   *
   * On failure, the factory remains uninitialized and `get_message()` returns
   * `dynamic_message_errc::unknown_message_name`.
   */
  void init(FileDescriptorSet &&fileset) {
    if (auto result = pool_.init(std::move(fileset), memory_resource_); !result.ok()) {
      initialized_ = false;
      return;
    }
    initialized_ = true;
    init();
  }

  /**
   * @brief Initialize the object from a fixed array of serialized file descriptors.
   *
   * @pre: Every element in `descs` must describe a different file. Passing
   * duplicates is undefined and will violate the distinct-file contract enforced by
   * `distinct_file_descriptor_pb_array`.
   *
   * @return false if any of the element in the array cannot be deserialized into
   *          ::google::protobuf::FileDescriptorProto.
   */
  template <std::size_t N>
  bool init(const distinct_file_descriptor_pb_array<N> &descs) {
    return descriptor_pool_t::make_file_descriptor_set(
               std::span<const file_descriptor_pb>(std::data(descs), std::size(descs)), distinct_file_tag_t{},
               alloc_from(memory_resource_))
        .and_then([this](auto &&fileset) -> std::expected<void, status> {
          this->init(std::forward<decltype(fileset)>(fileset));
          if (!initialized_) {
            return std::unexpected(status{std::errc::bad_message});
          }
          return {};
        })
        .has_value();
  }

  /**
   * @brief Initialize the object from a serialized FileDescriptorSet.
   *
   * @return false if the input cannot be deserialized into
   *          ::google::protobuf::FileDescriptorSet.
   */
  bool init(concepts::contiguous_byte_range auto &&file_descriptor_set_binpb) {
    return ::hpp::proto::read_binpb<FileDescriptorSet>(
               std::as_bytes(std::span{std::ranges::data(file_descriptor_set_binpb),
                                       std::ranges::size(file_descriptor_set_binpb)}),
               alloc_from(memory_resource_))
        .and_then([this](auto &&fileset) -> std::expected<void, std::errc> {
          this->init(std::forward<decltype(fileset)>(fileset));
          if (!initialized_) {
            return std::unexpected(std::errc::bad_message);
          }
          return {};
        })
        .has_value();
  }

  /**
   * @brief Construct a mutable dynamic message for the given type name.
   *
   * @pre `init()` has been called on this factory and returned true so that the descriptor
   *      pool is populated.
   * @param name Fully-qualified protobuf message name.
   * @param mr   Monotonic buffer resource used for allocating message storage.
   * @return `expected_message_mref` containing a message view on success, or an error
   *         (e.g., `dynamic_message_errc::unknown_message_name`) if the name is not found.
   */
  expected_message_mref get_message(std::string_view name, std::pmr::monotonic_buffer_resource &mr) const;
  [[nodiscard]] std::span<const file_descriptor_t> files() const { return pool_.files(); }
};

class use_factory {
  dynamic_message_factory *factory_;

public:
  using option_type = use_factory;
  explicit use_factory(dynamic_message_factory &f) : factory_(&f) {}
  [[nodiscard]] dynamic_message_factory &get_dynamic_message_factory() const { return *factory_; }
};

inline void dynamic_message_factory::setup_storage_slots() {
  for (auto &message : pool_.messages()) {
    hpp::proto::optional<std::int32_t> prev_oneof_index;
    uint16_t oneof_ordinal = 1;
    uint32_t cur_slot = 0;
    for (auto &f : message.fields()) {
      if (f.proto().oneof_index.has_value()) {
        if (f.proto().oneof_index != prev_oneof_index) {
          f.storage_slot = cur_slot++;
        } else {
          f.storage_slot = cur_slot - 1;
        }
        f.oneof_ordinal = ++oneof_ordinal;
      } else {
        f.storage_slot = cur_slot++;
        f.oneof_ordinal = f.is_repeated() ? 0 : 1;
        oneof_ordinal = 1;
      }
      prev_oneof_index = f.proto().oneof_index;
    }
    message.num_slots = cur_slot;
  }
}

inline void dynamic_message_factory::setup_wellknown_types() {
  const static std::pair<const char *, wellknown_types_t> wellknown_mappings[] = {
      {"google.protobuf.Any", wellknown_types_t::ANY},
      {"google.protobuf.Timestamp", wellknown_types_t::TIMESTAMP},
      {"google.protobuf.Duration", wellknown_types_t::DURATION},
      {"google.protobuf.FieldMask", wellknown_types_t::FIELDMASK},
      {"google.protobuf.Value", wellknown_types_t::VALUE},
      {"google.protobuf.ListValue", wellknown_types_t::LISTVALUE},
      {"google.protobuf.Struct", wellknown_types_t::STRUCT},
      {"google.protobuf.DoubleValue", wellknown_types_t::WRAPPER},
      {"google.protobuf.FloatValue", wellknown_types_t::WRAPPER},
      {"google.protobuf.Int64Value", wellknown_types_t::WRAPPER},
      {"google.protobuf.UInt64Value", wellknown_types_t::WRAPPER},
      {"google.protobuf.Int32Value", wellknown_types_t::WRAPPER},
      {"google.protobuf.UInt32Value", wellknown_types_t::WRAPPER},
      {"google.protobuf.BoolValue", wellknown_types_t::WRAPPER},
      {"google.protobuf.StringValue", wellknown_types_t::WRAPPER},
      {"google.protobuf.BytesValue", wellknown_types_t::WRAPPER},
  };

  for (auto [name, id] : wellknown_mappings) {
    if (auto *desc = pool_.get_message_descriptor(name); desc != nullptr) {
      if (desc->parent_file()->wellknown_validated_) {
        desc->wellknown = id;
      }
    }
  }
}

inline void dynamic_message_factory::setup_enum_field_default_value() {
  using enum google::protobuf::FieldDescriptorProto_::Type;
  for (auto &field : pool_.fields()) {
    const auto &proto = field.proto();
    if (proto.type == TYPE_ENUM) {
      if (!proto.default_value.empty()) {
        field.default_value = *field.enum_field_type_descriptor()->value_of(proto.default_value);
      } else if (field.explicit_presence()) {
        // In proto2, if you do not explicitly specify a [default = ...] option for an optional enum field, the
        // default value is the first value defined in that enum's definition.
        field.default_value = field.enum_field_type_descriptor()->proto().value[0].number;
      } else {
        field.default_value = 0;
      }
    }
  }
}

inline void dynamic_message_factory::init() {
  setup_storage_slots();
  setup_wellknown_types();
  setup_enum_field_default_value();
}

inline expected_message_mref dynamic_message_factory::get_message(std::string_view name,
                                                                  std::pmr::monotonic_buffer_resource &mr) const {
  if (!initialized_) {
    return expected_message_mref{std::unexpected(dynamic_message_errc::unknown_message_name)};
  }
  const auto *desc = pool_.get_message_descriptor(name);
  if (desc != nullptr) {
    return expected_message_mref{message_value_mref{*desc, mr}};
  }
  return expected_message_mref{std::unexpected(dynamic_message_errc::unknown_message_name)};
}

} // namespace hpp::proto
