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

#include <cstdint>
#include <limits>
#include <memory>
#include <memory_resource>
#include <utility>
#include <vector>

namespace hpp_proto {
namespace detail {

struct storage_slot_state {
  uint32_t cur_slot = 0;
  std::size_t oneof_count = 0;
  std::vector<bool> oneof_started;
  std::size_t prev_oneof = 0;
  uint16_t oneof_next_ordinal = 1;

  explicit storage_slot_state(std::size_t count) : oneof_count(count), oneof_started(count, false), prev_oneof(count) {}
};

template <typename FieldT>
[[nodiscard]] dynamic_message_errc setup_oneof_field(FieldT &field, storage_slot_state &state,
                                                     std::size_t field_index) {
  const auto index = static_cast<std::size_t>(*field.proto().oneof_index);
  if (index >= state.oneof_count) [[unlikely]] {
    return dynamic_message_errc::bad_message;
  }
  if (state.prev_oneof != index) {
    if (state.oneof_started[index]) [[unlikely]] {
      return dynamic_message_errc::bad_message;
    }
    state.oneof_started[index] = true;
    if (state.cur_slot == std::numeric_limits<uint32_t>::max()) [[unlikely]] {
      return dynamic_message_errc::bad_message;
    }
    field.storage_slot = state.cur_slot++;
    state.oneof_next_ordinal = 1;
  } else {
    field.storage_slot = state.cur_slot - 1;
  }
  if (state.oneof_next_ordinal == std::numeric_limits<uint16_t>::max()) [[unlikely]] {
    return dynamic_message_errc::bad_message;
  }
  field.oneof_ordinal = ++state.oneof_next_ordinal;
  if (field_index > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) [[unlikely]] {
    return dynamic_message_errc::bad_message;
  }
  const auto bias = static_cast<std::int64_t>(field_index) - static_cast<std::int64_t>(field.oneof_ordinal);
  if (bias < std::numeric_limits<std::int32_t>::min() || bias > std::numeric_limits<std::int32_t>::max()) [[unlikely]] {
    return dynamic_message_errc::bad_message;
  }
  field.active_oneof_index_bias = static_cast<std::int32_t>(bias);
  field.active_oneof_selection_mask = std::numeric_limits<uint32_t>::max();
  state.prev_oneof = index;
  return {};
}

template <typename FieldT>
[[nodiscard]] dynamic_message_errc setup_non_oneof_field(FieldT &field, storage_slot_state &state,
                                                         std::size_t field_index) {
  state.prev_oneof = state.oneof_count;
  if (state.cur_slot == std::numeric_limits<uint32_t>::max()) [[unlikely]] {
    return dynamic_message_errc::bad_message;
  }
  field.storage_slot = state.cur_slot++;
  field.oneof_ordinal = field.is_repeated() ? 0 : 1;
  if (field_index > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) [[unlikely]] {
    return dynamic_message_errc::bad_message;
  }
  field.active_oneof_index_bias = static_cast<std::int32_t>(field_index);
  field.active_oneof_selection_mask = 0;
  return {};
}

class dynamic_message_factory_impl {
public:
  using FileDescriptorSet = ::google::protobuf::FileDescriptorSet<dynamic_message_factory_addons::traits_type>;

  explicit dynamic_message_factory_impl(std::pmr::memory_resource *upstream_resource)
      : memory_resource_(upstream_resource) {}

  [[nodiscard]] std::expected<void, dynamic_message_errc> initialize(FileDescriptorSet &&fileset) {
    if (!pool_.init(std::move(fileset), memory_resource_).ok()) {
      return std::unexpected(dynamic_message_errc::bad_message);
    }
    return finish_initialize();
  }

  [[nodiscard]] std::expected<void, dynamic_message_errc>
  initialize(std::span<const std::byte> file_descriptor_set_binpb) {
    return ::hpp_proto::read_binpb<FileDescriptorSet>(file_descriptor_set_binpb, alloc_from(memory_resource_))
        .transform_error([](std::errc) { return dynamic_message_errc::bad_message; })
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

  [[nodiscard]] std::expected<void, dynamic_message_errc> setup_storage_slots() {
    for (auto &message : pool_.messages()) {
      const auto oneof_count = message.proto().oneof_decl.size();
      storage_slot_state state{oneof_count};
      std::size_t field_index = 0;
      for (auto &f : message.fields()) {
        const auto ec = f.proto().oneof_index.has_value() ? setup_oneof_field(f, state, field_index)
                                                          : setup_non_oneof_field(f, state, field_index);
        if (ec != dynamic_message_errc{}) {
          return std::unexpected(ec);
        }
        ++field_index;
      }
      message.num_slots = state.cur_slot;
    }
    return {};
  }

  void setup_wellknown_types() {
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
    using enum google::protobuf::FieldDescriptorProto_::Type;
    for (auto &field : pool_.fields()) {
      const auto &proto = field.proto();
      if (proto.type == TYPE_ENUM) {
        auto *enum_desc = field.enum_field_type_descriptor();
        if (enum_desc == nullptr) [[unlikely]] {
          return std::unexpected(dynamic_message_errc::bad_message);
        }
        const auto &enum_values = enum_desc->proto().value;
        if (enum_values.empty()) [[unlikely]] {
          return std::unexpected(dynamic_message_errc::bad_message);
        }
        if (!proto.default_value.empty()) {
          const auto *pdefault = enum_desc->value_of(proto.default_value);
          if (pdefault == nullptr) [[unlikely]] {
            return std::unexpected(dynamic_message_errc::bad_message);
          }
          field.default_value = *pdefault;
        } else if (field.explicit_presence()) {
          // In proto2, if you do not explicitly specify a [default = ...] option for an optional enum field, the
          // default value is the first value defined in that enum's definition.
          field.default_value = enum_values[0].number;
        } else {
          field.default_value = 0;
        }
      }
    }
    return {};
  }

  [[nodiscard]] std::expected<void, dynamic_message_errc> finish_initialize() {
    return setup_storage_slots().and_then([this] {
      setup_wellknown_types();
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
    impl_allocator_type allocator{p->upstream_resource()};
    allocator.delete_object(p);
  }
}

std::expected<dynamic_message_factory, dynamic_message_errc>
dynamic_message_factory::create_from_fileset(dynamic_message_factory::file_descriptor_set_type &&fileset,
                                             impl_allocator_type allocator) {
  impl_ptr impl{allocator.new_object<detail::dynamic_message_factory_impl>(allocator.resource())};
  return impl->initialize(std::move(fileset)).transform([&] { return dynamic_message_factory{std::move(impl)}; });
}

std::expected<dynamic_message_factory, dynamic_message_errc>
dynamic_message_factory::create_from_descs(std::span<const file_descriptor_pb> descs, impl_allocator_type allocator) {
  impl_ptr impl{allocator.new_object<detail::dynamic_message_factory_impl>(allocator.resource())};
  return descriptor_pool_t::make_file_descriptor_set(descs, distinct_file_tag_t{}, alloc_from(impl->memory_resource()))
      .transform_error([](std::errc) { return dynamic_message_errc::bad_message; })
      .and_then([&](auto &&fileset) { return impl->initialize(std::forward<decltype(fileset)>(fileset)); })
      .transform([&] { return dynamic_message_factory{std::move(impl)}; });
}

std::expected<dynamic_message_factory, dynamic_message_errc>
dynamic_message_factory::create_from_binpb(std::span<const std::byte> file_descriptor_set_binpb,
                                           impl_allocator_type allocator) {
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
