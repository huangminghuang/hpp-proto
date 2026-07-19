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

#include <hpp_proto/binpb.hpp>
#include <hpp_proto/dynamic_message/factory.hpp>
#include <hpp_proto/dynamic_message/factory_addons.hpp>

#include <array>
#include <cassert>
#include <cstdint>
#include <limits>
#include <memory>
#include <memory_resource>
#include <ranges>
#include <utility>
#include <vector>

namespace hpp_proto {
namespace detail {

[[nodiscard]] constexpr dynamic_message_errc to_dynamic_message_errc(descriptor_pool_errc ec) noexcept {
  return (ec == descriptor_pool_errc::descriptor_deserialization_error)
             ? dynamic_message_errc::descriptor_deserialization_error
             : dynamic_message_errc::schema_validation_error;
}

struct storage_slot_state {
  uint32_t cur_slot = 0;
  std::size_t oneof_count = 0;
  std::pmr::vector<bool> oneof_started;
  std::size_t prev_oneof = 0;
  uint16_t oneof_next_ordinal = 1;

  storage_slot_state(std::size_t count, std::pmr::memory_resource *resource)
      : oneof_count(count), oneof_started(count, false, resource), prev_oneof(count) {}
};

/**
 * @brief Storage and selection metadata assigned to one field during factory finalization.
 *
 * This is the transient output of message slot allocation. It is combined with the
 * field's resolved type, presence, policy, and wire information to construct
 * resolved_field_info.
 */
struct field_slot_layout {
  /**
   * @brief Index of the field's value_storage entry in its containing dynamic message.
   *
   * Every non-oneof field owns a distinct slot. All alternatives in one oneof share
   * the slot allocated to that oneof, because at most one alternative can be active.
   */
  uint32_t storage_slot = 0;

  /**
   * @brief Selection word written when a singular field becomes present.
   *
   * Zero is used for repeated fields because their size, stored at the same union
   * offset, determines presence. Ordinary singular fields use 1. Oneof alternatives
   * use distinct oneof-local ordinals beginning at 2; zero remains the absent value
   * and 1 remains the ordinary-singular marker.
   */
  uint16_t selection_ordinal = 0;

  /**
   * @brief Mask selecting the oneof ordinal from a slot's selection word.
   *
   * Oneof fields use UINT32_MAX so the active alternative's ordinal participates in
   * active-field-index calculation. Non-oneof fields use 0 so their selection word
   * is ignored and the bias alone identifies the field.
   */
  uint32_t active_oneof_selection_mask = 0;

  /**
   * @brief Signed offset that converts the masked selection word to a message field index.
   *
   * For a oneof member this is `field_index - selection_ordinal`; because oneof fields
   * and their ordinals are contiguous, every member of that oneof gets the same offset.
   * For a non-oneof field this is its field index, paired with a zero mask.
   */
  int32_t active_oneof_index_bias = 0;
};

template <typename FieldT>
[[nodiscard]] std::expected<field_slot_layout, dynamic_message_errc>
setup_oneof_field(const FieldT &field, storage_slot_state &state, std::size_t field_index) {
  const auto index = static_cast<std::size_t>(*field.proto().oneof_index);
  assert(index < state.oneof_count);
  field_slot_layout layout;
  if (state.prev_oneof != index) {
    if (state.oneof_started[index]) [[unlikely]] {
      return std::unexpected(dynamic_message_errc::schema_validation_error);
    }
    state.oneof_started[index] = true;
    assert(state.cur_slot != std::numeric_limits<uint32_t>::max());
    layout.storage_slot = state.cur_slot++;
    state.oneof_next_ordinal = 1;
  } else {
    layout.storage_slot = state.cur_slot - 1;
  }
  if (state.oneof_next_ordinal == std::numeric_limits<uint16_t>::max()) [[unlikely]] {
    return std::unexpected(dynamic_message_errc::schema_validation_error);
  }
  layout.selection_ordinal = ++state.oneof_next_ordinal;
  assert(field_index <= static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()));
  const auto bias = static_cast<std::int64_t>(field_index) - static_cast<std::int64_t>(layout.selection_ordinal);
  assert(bias >= std::numeric_limits<std::int32_t>::min() && bias <= std::numeric_limits<std::int32_t>::max());
  layout.active_oneof_index_bias = static_cast<std::int32_t>(bias);
  layout.active_oneof_selection_mask = std::numeric_limits<uint32_t>::max();
  state.prev_oneof = index;
  return layout;
}

template <typename FieldT>
[[nodiscard]] std::expected<field_slot_layout, dynamic_message_errc>
setup_non_oneof_field(const FieldT &field, storage_slot_state &state, std::size_t field_index) {
  state.prev_oneof = state.oneof_count;
  assert(state.cur_slot != std::numeric_limits<uint32_t>::max());
  field_slot_layout layout{.storage_slot = state.cur_slot++,
                           .selection_ordinal = static_cast<uint16_t>(field.is_repeated() ? 0 : 1)};
  assert(field_index <= static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()));
  layout.active_oneof_index_bias = static_cast<std::int32_t>(field_index);
  return layout;
}

struct runtime_type_traits {
  field_kind_t singular_kind;
  field_kind_t repeated_kind;
  field_storage_kind_t singular_storage;
  field_storage_kind_t repeated_storage;
  wire_type base_wire_type;
};

// Indexed by the contiguous, descriptor_pool-validated FieldDescriptorProto type values.
constexpr std::array runtime_type_traits_by_proto_type{
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_DOUBLE,
        .repeated_kind = field_kind_t::KIND_REPEATED_DOUBLE,
        .singular_storage = field_storage_kind_t::DOUBLE,
        .repeated_storage = field_storage_kind_t::REPEATED_DOUBLE,
        .base_wire_type = wire_type::fixed_64,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_FLOAT,
        .repeated_kind = field_kind_t::KIND_REPEATED_FLOAT,
        .singular_storage = field_storage_kind_t::FLOAT,
        .repeated_storage = field_storage_kind_t::REPEATED_FLOAT,
        .base_wire_type = wire_type::fixed_32,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_INT64,
        .repeated_kind = field_kind_t::KIND_REPEATED_INT64,
        .singular_storage = field_storage_kind_t::INT64,
        .repeated_storage = field_storage_kind_t::REPEATED_INT64,
        .base_wire_type = wire_type::varint,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_UINT64,
        .repeated_kind = field_kind_t::KIND_REPEATED_UINT64,
        .singular_storage = field_storage_kind_t::UINT64,
        .repeated_storage = field_storage_kind_t::REPEATED_UINT64,
        .base_wire_type = wire_type::varint,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_INT32,
        .repeated_kind = field_kind_t::KIND_REPEATED_INT32,
        .singular_storage = field_storage_kind_t::INT32,
        .repeated_storage = field_storage_kind_t::REPEATED_INT32,
        .base_wire_type = wire_type::varint,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_FIXED64,
        .repeated_kind = field_kind_t::KIND_REPEATED_FIXED64,
        .singular_storage = field_storage_kind_t::UINT64,
        .repeated_storage = field_storage_kind_t::REPEATED_UINT64,
        .base_wire_type = wire_type::fixed_64,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_FIXED32,
        .repeated_kind = field_kind_t::KIND_REPEATED_FIXED32,
        .singular_storage = field_storage_kind_t::UINT32,
        .repeated_storage = field_storage_kind_t::REPEATED_UINT32,
        .base_wire_type = wire_type::fixed_32,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_BOOL,
        .repeated_kind = field_kind_t::KIND_REPEATED_BOOL,
        .singular_storage = field_storage_kind_t::BOOL,
        .repeated_storage = field_storage_kind_t::REPEATED_BOOL,
        .base_wire_type = wire_type::varint,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_STRING,
        .repeated_kind = field_kind_t::KIND_REPEATED_STRING,
        .singular_storage = field_storage_kind_t::STRING,
        .repeated_storage = field_storage_kind_t::REPEATED_STRING,
        .base_wire_type = wire_type::length_delimited,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_MESSAGE,
        .repeated_kind = field_kind_t::KIND_REPEATED_MESSAGE,
        .singular_storage = field_storage_kind_t::MESSAGE,
        .repeated_storage = field_storage_kind_t::REPEATED_MESSAGE,
        .base_wire_type = wire_type::sgroup,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_MESSAGE,
        .repeated_kind = field_kind_t::KIND_REPEATED_MESSAGE,
        .singular_storage = field_storage_kind_t::MESSAGE,
        .repeated_storage = field_storage_kind_t::REPEATED_MESSAGE,
        .base_wire_type = wire_type::length_delimited,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_BYTES,
        .repeated_kind = field_kind_t::KIND_REPEATED_BYTES,
        .singular_storage = field_storage_kind_t::BYTES,
        .repeated_storage = field_storage_kind_t::REPEATED_BYTES,
        .base_wire_type = wire_type::length_delimited,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_UINT32,
        .repeated_kind = field_kind_t::KIND_REPEATED_UINT32,
        .singular_storage = field_storage_kind_t::UINT32,
        .repeated_storage = field_storage_kind_t::REPEATED_UINT32,
        .base_wire_type = wire_type::varint,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_ENUM,
        .repeated_kind = field_kind_t::KIND_REPEATED_ENUM,
        .singular_storage = field_storage_kind_t::INT32,
        .repeated_storage = field_storage_kind_t::REPEATED_INT32,
        .base_wire_type = wire_type::varint,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_SFIXED32,
        .repeated_kind = field_kind_t::KIND_REPEATED_SFIXED32,
        .singular_storage = field_storage_kind_t::INT32,
        .repeated_storage = field_storage_kind_t::REPEATED_INT32,
        .base_wire_type = wire_type::fixed_32,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_SFIXED64,
        .repeated_kind = field_kind_t::KIND_REPEATED_SFIXED64,
        .singular_storage = field_storage_kind_t::INT64,
        .repeated_storage = field_storage_kind_t::REPEATED_INT64,
        .base_wire_type = wire_type::fixed_64,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_SINT32,
        .repeated_kind = field_kind_t::KIND_REPEATED_SINT32,
        .singular_storage = field_storage_kind_t::INT32,
        .repeated_storage = field_storage_kind_t::REPEATED_INT32,
        .base_wire_type = wire_type::varint,
    },
    runtime_type_traits{
        .singular_kind = field_kind_t::KIND_SINT64,
        .repeated_kind = field_kind_t::KIND_REPEATED_SINT64,
        .singular_storage = field_storage_kind_t::INT64,
        .repeated_storage = field_storage_kind_t::REPEATED_INT64,
        .base_wire_type = wire_type::varint,
    },
};

// Sole adapter from descriptor_pool's schema-derived representation to dynamic_message's
// authoritative resolved field information. Runtime consumers must not re-derive these facts.
[[nodiscard]] constexpr runtime_type_traits runtime_traits_for(google::protobuf::FieldDescriptorProto<>::Type type) {
  using enum google::protobuf::FieldDescriptorProto<>::Type;
  assert(is_valid(type));
  constexpr auto first_type_value = std::to_underlying(TYPE_DOUBLE);
  const auto index = static_cast<std::size_t>(std::to_underlying(type) - first_type_value);
  return runtime_type_traits_by_proto_type.at(index);
}

[[nodiscard]] runtime_field_policy runtime_policy_for(const field_descriptor_t &field) noexcept {
  auto policy = runtime_field_policy::NONE;
  if (field.is_packed()) {
    policy = policy | runtime_field_policy::PACKED;
  }
  if (field.is_delimited()) {
    policy = policy | runtime_field_policy::DELIMITED;
  }
  if (field.requires_utf8_validation()) {
    policy = policy | runtime_field_policy::UTF8_VALIDATION;
  }
  return policy;
}

[[nodiscard]] field_presence_t presence_for(const field_descriptor_t &field) noexcept {
  if (field.is_repeated()) {
    return field_presence_t::REPEATED;
  }
  if (field.proto().oneof_index.has_value()) {
    return field_presence_t::ONEOF;
  }
  if (field.is_required()) {
    return field_presence_t::REQUIRED;
  }
  return field.explicit_presence() ? field_presence_t::EXPLICIT : field_presence_t::IMPLICIT;
}

class dynamic_message_factory_impl {
public:
  using FileDescriptorSet = ::google::protobuf::FileDescriptorSet<dynamic_message_factory_addons::traits_type>;

  explicit dynamic_message_factory_impl(std::pmr::memory_resource *upstream_resource)
      : memory_resource_(upstream_resource), pool_(&memory_resource_, upstream_resource) {}

  [[nodiscard]] std::expected<void, dynamic_message_errc> initialize(FileDescriptorSet &&fileset) {
    return pool_.init(std::move(fileset)).transform_error(to_dynamic_message_errc).and_then([this] {
      return finish_initialize();
    });
  }

  [[nodiscard]] std::expected<void, dynamic_message_errc>
  initialize(std::span<const std::byte> file_descriptor_set_binpb) {
    return ::hpp_proto::read_binpb<FileDescriptorSet>(file_descriptor_set_binpb, alloc_from(memory_resource_))
        .transform_error([](std::errc) { return dynamic_message_errc::descriptor_deserialization_error; })
        .and_then([this](auto &&fileset) { return initialize(std::forward<decltype(fileset)>(fileset)); });
  }

  [[nodiscard]] expected_message_mref get_message(std::string_view name,
                                                  std::pmr::monotonic_buffer_resource &mr) const {
    const auto *desc = pool_.get_message_descriptor(name);
    if (desc != nullptr) {
      return expected_message_mref{message_value_mref{*desc, mr}};
    }
    return expected_message_mref{std::unexpected(dynamic_message_errc::unknown_message_name)};
  }
  [[nodiscard]] std::pmr::memory_resource *upstream_resource() const { return memory_resource_.upstream_resource(); }
  [[nodiscard]] std::pmr::monotonic_buffer_resource &memory_resource() { return memory_resource_; }

private:
  std::pmr::monotonic_buffer_resource memory_resource_;
  descriptor_pool_t pool_;

  [[nodiscard]] std::expected<void, dynamic_message_errc> finalize_resolved_field_infos() {
    for (auto &message : pool_.messages()) {
      const auto oneof_count = message.proto().oneof_decl.size();
      storage_slot_state state{oneof_count, upstream_resource()};
      std::size_t field_index = 0;
      for (auto &f : message.fields()) {
        auto layout = f.proto().oneof_index.has_value() ? setup_oneof_field(f, state, field_index)
                                                        : setup_non_oneof_field(f, state, field_index);
        if (!layout.has_value()) {
          return std::unexpected(layout.error());
        }
        const auto type_traits = runtime_traits_for(f.proto().type);
        const auto repeated = f.is_repeated();
        auto serialized_wire_type = type_traits.base_wire_type;
        if (f.is_packed()) {
          serialized_wire_type = wire_type::length_delimited;
        } else if (f.is_delimited()) {
          serialized_wire_type = wire_type::sgroup;
        }
        const auto serialized_tag =
            (static_cast<uint32_t>(f.proto().number) << 3U) | std::to_underlying(serialized_wire_type);
        f.finalize_resolved_info(resolved_field_info{resolved_field_info_init{
            .kind = repeated ? type_traits.repeated_kind : type_traits.singular_kind,
            .storage_kind = repeated ? type_traits.repeated_storage : type_traits.singular_storage,
            .cardinality = repeated ? field_cardinality_t::REPEATED : field_cardinality_t::SINGULAR,
            .presence = presence_for(f),
            .policy = runtime_policy_for(f),
            .serialized_tag = serialized_tag,
            .storage_slot = layout->storage_slot,
            .selection_ordinal = layout->selection_ordinal,
            .active_oneof_selection_mask = layout->active_oneof_selection_mask,
            .active_oneof_index_bias = layout->active_oneof_index_bias,
        }});
        ++field_index;
      }
      message.num_slots = state.cur_slot;
    }
    return {};
  }

  static void setup_wellknown_types_impl(descriptor_pool_t &pool_) {
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
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
      if (auto *desc = pool_.get_message_descriptor(name);
          desc != nullptr && desc->parent_file()->wellknown_validated_) {
        desc->wellknown = id;
      }
    }
  }

  [[nodiscard]] std::expected<void, dynamic_message_errc> setup_enum_field_default_value() {
    using enum google::protobuf::FieldDescriptorProto<>::Type;
    for (auto &field : pool_.fields()) {
      const auto &proto = field.proto();
      if (proto.type == TYPE_ENUM) {
        auto *enum_desc = field.enum_field_type_descriptor();
        assert(enum_desc != nullptr);
        const auto &enum_values = enum_desc->proto().value;
        if (enum_values.empty()) [[unlikely]] {
          return std::unexpected(dynamic_message_errc::schema_validation_error);
        }
        if (!proto.default_value.empty()) {
          const auto *pdefault = enum_desc->value_of(proto.default_value);
          if (pdefault == nullptr) [[unlikely]] {
            return std::unexpected(dynamic_message_errc::schema_validation_error);
          }
          field.default_value_ = *pdefault;
        } else if (field.explicit_presence() || field.is_required()) {
          // In proto2, if you do not explicitly specify a [default = ...] option for an optional enum field, the
          // default value is the first value defined in that enum's definition.
          field.default_value_ = enum_values[0].number;
        } else {
          field.default_value_ = 0;
        }
      }
    }
    return {};
  }

  [[nodiscard]] std::expected<void, dynamic_message_errc> finish_initialize() {
    if (std::ranges::any_of(pool_.fields(), [](const auto &field) { return !field.default_value_valid_; })) {
      return std::unexpected(dynamic_message_errc::schema_validation_error);
    }
    return finalize_resolved_field_infos().and_then([this] {
      setup_wellknown_types_impl(pool_);
      return setup_enum_field_default_value();
    });
  }
};

} // namespace detail

dynamic_message_factory::dynamic_message_factory(impl_ptr impl) noexcept : impl_(std::move(impl)) {}

dynamic_message_factory::dynamic_message_factory(dynamic_message_factory &&) noexcept = default;

dynamic_message_factory &dynamic_message_factory::operator=(dynamic_message_factory &&) noexcept = default;

dynamic_message_factory::~dynamic_message_factory() = default;

void dynamic_message_factory::impl_deleter::operator()(detail::dynamic_message_factory_impl *p) noexcept {
  if (p != nullptr) {
    std::pmr::polymorphic_allocator<detail::dynamic_message_factory_impl> allocator{p->upstream_resource()};
    allocator.delete_object(p);
  }
}

std::expected<dynamic_message_factory, dynamic_message_errc>
dynamic_message_factory::create_from_descs(std::span<const file_descriptor_pb> descs, allocator_type allocator) {
  impl_ptr impl{allocator.new_object<detail::dynamic_message_factory_impl>(allocator.resource())};
  return descriptor_pool_t::make_file_descriptor_set(descs, distinct_file_tag_t{}, alloc_from(impl->memory_resource()))
      .transform_error(detail::to_dynamic_message_errc)
      .and_then([&](auto &&fileset) { return impl->initialize(std::forward<decltype(fileset)>(fileset)); })
      .transform([&] { return dynamic_message_factory{std::move(impl)}; });
}

std::expected<dynamic_message_factory, dynamic_message_errc>
dynamic_message_factory::create_from_binpb(std::span<const std::byte> file_descriptor_set_binpb,
                                           allocator_type allocator) {
  impl_ptr impl{allocator.new_object<detail::dynamic_message_factory_impl>(allocator.resource())};
  return impl->initialize(file_descriptor_set_binpb).transform([&] {
    return dynamic_message_factory{std::move(impl)};
  });
}

expected_message_mref dynamic_message_factory::get_message(std::string_view name,
                                                           std::pmr::monotonic_buffer_resource &mr) const {
  if (!impl_) {
    return expected_message_mref{std::unexpected(dynamic_message_errc::unknown_message_name)};
  }
  return impl_->get_message(name, mr);
}

} // namespace hpp_proto
