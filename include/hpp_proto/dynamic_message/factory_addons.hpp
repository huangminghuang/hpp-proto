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

#include <cassert>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <memory_resource>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <vector>

#include <google/protobuf/any.desc.hpp>
#include <google/protobuf/descriptor.pb.hpp>
#include <google/protobuf/duration.desc.hpp>
#include <google/protobuf/field_mask.desc.hpp>
#include <google/protobuf/struct.desc.hpp>
#include <google/protobuf/timestamp.desc.hpp>
#include <google/protobuf/wrappers.desc.hpp>
#include <hpp_proto/descriptor_pool.hpp>
#include <hpp_proto/dynamic_message/types.hpp>
#include <hpp_proto/field_types.hpp>
namespace hpp_proto {
struct dynamic_message_factory_addons {
  using traits_type = non_owning_traits;
  using string_t = std::pmr::string;
  template <typename T>
  using vector_t = std::pmr::vector<T>;

  template <typename T, typename U>
  using map_t = std::pmr::unordered_map<T, U>;

// macOS historically lacks floating-point from_chars; fall back to strto* when not available.
#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L && !defined(__APPLE__)
  static constexpr bool has_std_from_chars_float = true;
#else
  static constexpr bool has_std_from_chars_float = false;
#endif

  template <typename T>
  static T parse_default_value(std::string_view value) {
    T parsed{};
    if (value.empty()) {
      return parsed;
    }
    const char *const begin = value.data();
    const char *const end = std::to_address(value.cend());
    bool consumed_entire_input = true;
    std::errc ec{};

    if constexpr (std::is_floating_point_v<T>) {
      if constexpr (has_std_from_chars_float) {
        const auto result = std::from_chars(begin, end, parsed);
        ec = result.ec;
        consumed_entire_input = result.ptr == end;
      } else {
        std::string buffer(value);
        char *conv_end = nullptr;
        errno = 0;
        if constexpr (std::same_as<T, float>) {
          parsed = std::strtof(buffer.c_str(), &conv_end);
        } else {
          parsed = std::strtod(buffer.c_str(), &conv_end);
        }
        if (errno == ERANGE) {
          ec = std::errc::result_out_of_range;
          consumed_entire_input = false;
        } else if (conv_end == buffer.c_str()) {
          ec = std::errc::invalid_argument;
          consumed_entire_input = false;
        } else {
          const char *const buffer_end = std::to_address(buffer.cend());
          consumed_entire_input = (conv_end == buffer_end);
          if (!consumed_entire_input) {
            ec = std::errc::invalid_argument;
          }
        }
      }
    } else {
      const auto result = std::from_chars(begin, end, parsed);
      ec = result.ec;
      consumed_entire_input = result.ptr == end;
    }

    if (ec == std::errc::result_out_of_range) {
      throw std::out_of_range("default value out of range");
    }
    if (ec != std::errc{} || !consumed_entire_input) {
      throw std::invalid_argument("invalid default value");
    }
    return parsed;
  }

  template <typename Derived>
  struct field_descriptor {
    using type = void;
    std::variant<bool, int32_t, uint32_t, int64_t, uint64_t, double, float> default_value;
    /// @brief slot represents the index to the field memory storage of a message; all non-oneof fields use different
    /// slot, fields of the same oneof type share the same slot.
    uint32_t storage_slot = 0;
    /// @brief for oneof field, this value is the order among the same oneof field counting from 1; otherwise, it is
    /// always 1 for singular field and 0 for repeated field
    uint16_t oneof_ordinal = 0;
    field_descriptor(Derived &self, [[maybe_unused]] const auto &inherited_options) { set_default_value(self.proto()); }

    void set_default_value(const google::protobuf::FieldDescriptorProto<traits_type> &proto) {
      using enum google::protobuf::FieldDescriptorProto_::Type;
      switch (proto.type) {
      case TYPE_ENUM:
        break;
      case TYPE_DOUBLE:
        default_value = parse_default_value<double>(proto.default_value);
        break;
      case TYPE_FLOAT:
        default_value = parse_default_value<float>(proto.default_value);
        break;
      case TYPE_INT64:
      case TYPE_SFIXED64:
      case TYPE_SINT64:
        default_value = parse_default_value<int64_t>(proto.default_value);
        break;
      case TYPE_UINT64:
      case TYPE_FIXED64:
        default_value = parse_default_value<uint64_t>(proto.default_value);
        break;
      case TYPE_INT32:
      case TYPE_SFIXED32:
      case TYPE_SINT32:
        default_value = parse_default_value<int32_t>(proto.default_value);
        break;
      case TYPE_UINT32:
      case TYPE_FIXED32:
        default_value = parse_default_value<uint32_t>(proto.default_value);
        break;
      case TYPE_BOOL:
        default_value = proto.default_value == "true";
        break;
      default:
        break;
      }
    }
  };

  template <typename Derived>
  struct enum_descriptor {
    bool is_null_value = false;
    explicit enum_descriptor(Derived &derived, [[maybe_unused]] const auto &inherited_options)
        : is_null_value(derived.full_name() == "google.protobuf.NullValue") {}

    [[nodiscard]] const int32_t *value_of(const std::string_view name) const {
      const auto &proto = static_cast<const Derived *>(this)->proto();
      for (const auto &ev : proto.value) {
        if (ev.name == name) {
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          return &ev.number;
        }
      }
      return nullptr;
    }

    [[nodiscard]] std::string_view name_of(int32_t value) const {
      const auto &proto = static_cast<const Derived *>(this)->proto();
      for (const auto &ev : proto.value) {
        if (ev.number == value) {
          return ev.name;
        }
      }
      return {};
    }
  };

  template <typename Derived>
  struct oneof_descriptor {
    explicit oneof_descriptor(Derived &, [[maybe_unused]] const auto &inherited_options) {}
    [[nodiscard]] uint32_t storage_slot() const {
      return static_cast<const Derived *>(this)->fields().front().storage_slot;
    }
  };

  template <typename Derived>
  struct message_descriptor {
    uint32_t num_slots = 0;
    wellknown_types_t wellknown = wellknown_types_t::NONE;
    explicit message_descriptor(const Derived &, [[maybe_unused]] const auto &inherited_options) {}
  };

  template <typename Derived>
  struct file_descriptor {
    bool wellknown_validated_ = false;
    explicit file_descriptor([[maybe_unused]] const Derived &derived) {
      using namespace hpp_proto::file_descriptors;
      static flat_map<std::string_view, file_descriptor_pb> wellknown_type_pbs{
          {"google/protobuf/any.proto", _desc_google_protobuf_any_proto},
          {"google/protobuf/duration.proto", _desc_google_protobuf_duration_proto},
          {"google/protobuf/field_mask.proto", _desc_google_protobuf_field_mask_proto},
          {"google/protobuf/struct.proto", _desc_google_protobuf_struct_proto},
          {"google/protobuf/timestamp.proto", _desc_google_protobuf_timestamp_proto},
          {"google/protobuf/wrappers.proto", _desc_google_protobuf_wrappers_proto}};

      if (auto itr = wellknown_type_pbs.find(derived.proto().name); itr != wellknown_type_pbs.end()) {
        std::vector<std::byte> pb;
        hpp_proto::status status;
        if (derived.proto().source_code_info.has_value()) {
          auto proto_no_source_info = derived.proto();
          proto_no_source_info.source_code_info.reset();
          status = write_binpb(proto_no_source_info, pb);
        } else {
          status = write_binpb(derived.proto(), pb);
        }
        assert(status.ok());
        auto expected_binpb = std::as_bytes(std::span{itr->second.value.data(), itr->second.value.size()});
        wellknown_validated_ = std::ranges::equal(pb, expected_binpb);
      }
    }
  };
};

using descriptor_pool_t = descriptor_pool<dynamic_message_factory_addons>;
using field_descriptor_t = typename descriptor_pool_t::field_descriptor_t;
using enum_descriptor_t = typename descriptor_pool_t::enum_descriptor_t;
using oneof_descriptor_t = typename descriptor_pool_t::oneof_descriptor_t;
using message_descriptor_t = typename descriptor_pool_t::message_descriptor_t;
using file_descriptor_t = typename descriptor_pool_t::file_descriptor_t;
} // namespace hpp_proto
