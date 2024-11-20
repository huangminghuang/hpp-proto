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
#include <system_error>
#include <unordered_map>

#include <hpp_proto/descriptor_pool.hpp>
#include <hpp_proto/duration_codec.hpp>
#include <hpp_proto/field_mask_codec.hpp>
#include <hpp_proto/json_serializer.hpp>
#include <hpp_proto/pb_serializer.hpp>
#include <hpp_proto/timestamp_codec.hpp>

namespace hpp::proto {

// used to represent a protobuf encoded FileDescriptorProto
struct file_descriptor_pb {
  std::string_view value;

  constexpr bool operator==(const file_descriptor_pb &) const = default;
  constexpr bool operator<(const file_descriptor_pb &other) const { return value < other.value; };
};

template <std::ranges::input_range R, class T>
constexpr bool contains(const R &r, const T &value) {
  return std::find(std::begin(r), std::end(r), value) != std::end(r);
}

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables)
namespace concepts {
template <typename T>
concept input_bytes_range =
    std::ranges::input_range<T> && contiguous_byte_range<typename std::ranges::range_value_t<T>>;

template <typename T>
concept file_descriptor_pb_array =
    std::ranges::input_range<T> && std::same_as<typename std::ranges::range_value_t<T>, file_descriptor_pb>;
} // namespace concepts
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

namespace wellknown {
struct Any {
  std::string type_url;
  std::vector<std::byte> value;
};
auto pb_meta(const Any &) -> std::tuple<hpp::proto::field_meta<1, &Any::type_url, hpp::proto::field_option::none>,
                                        hpp::proto::field_meta<2, &Any::value, hpp::proto::field_option::none>>;

struct Duration {
  constexpr static bool glaze_reflect = false;
  int64_t seconds = {};
  int32_t nanos = {};
};

auto pb_meta(const Duration &)
    -> std::tuple<hpp::proto::field_meta<1, &Duration::seconds, hpp::proto::field_option::none, hpp::proto::vint64_t>,
                  hpp::proto::field_meta<2, &Duration::nanos, hpp::proto::field_option::none, hpp::proto::vint64_t>>;

struct Timestamp {
  constexpr static bool glaze_reflect = false;
  int64_t seconds = {};
  int32_t nanos = {};
};

auto pb_meta(const Timestamp &)
    -> std::tuple<hpp::proto::field_meta<1, &Timestamp::seconds, hpp::proto::field_option::none, hpp::proto::vint64_t>,
                  hpp::proto::field_meta<2, &Timestamp::nanos, hpp::proto::field_option::none, hpp::proto::vint64_t>>;

// NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
struct FieldMask {
  constexpr static bool glaze_reflect = false;
  std::vector<std::string> paths;
};

auto pb_meta(const FieldMask &)
    -> std::tuple<hpp::proto::field_meta<1, &FieldMask::paths, hpp::proto::field_option::none>>;
} // namespace wellknown

template <>
struct json_codec<wellknown::Duration> {
  using type = duration_codec;
};

template <>
struct json_codec<wellknown::Timestamp> {
  using type = timestamp_codec;
};

template <>
struct json_codec<wellknown::FieldMask> {
  using type = field_mask_codec;
};

struct proto_json_addons {
  template <typename Derived>
  struct field_descriptor {
    field_descriptor(const google::protobuf::FieldDescriptorProto &, const std::string &) {}
  };

  template <typename EnumD>
  struct enum_descriptor {
    explicit enum_descriptor(const google::protobuf::EnumDescriptorProto &) {}
  };

  template <typename OneofD, typename FieldD>
  struct oneof_descriptor {
    explicit oneof_descriptor(const google::protobuf::OneofDescriptorProto &) {}
  };

  template <typename MessageD, typename EnumD, typename OneofD, typename FieldD>
  struct message_descriptor {
    std::string syntax;
    bool is_map_entry = false;
    std::vector<FieldD *> fields;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
    explicit message_descriptor(const google::protobuf::DescriptorProto &proto)
        : is_map_entry(proto.options.has_value() && proto.options->map_entry) {
      fields.reserve(proto.field.size() + proto.extension.size());
    }
    void add_field(FieldD &f) { fields.push_back(&f); }
    void add_enum(EnumD &) {}
    void add_message(MessageD &m) { m.syntax = syntax; }
    void add_oneof(OneofD &) {}
    void add_extension(FieldD &f) { fields.push_back(&f); }
  };

  template <typename FileD, typename MessageD, typename EnumD, typename FieldD>
  struct file_descriptor {
    std::string syntax;
    explicit file_descriptor(const google::protobuf::FileDescriptorProto &proto)
        : syntax(proto.syntax.empty() ? std::string{"proto2"} : proto.syntax) {}
    void add_enum(EnumD &) {}
    void add_message(MessageD &m) { m.syntax = syntax; }
    void add_extension(FieldD &) {}
  };
};

class dynamic_serializer {

  enum field_options : uint8_t {
    explicit_presence = 1,
    repeated = 2,
    packed = 4,
    group = 8,
    utf8_validation = 16,
    is_oneof = 32,
    required = 64,
    is_map_entry = 128
  };

  struct enum_value_meta {
    int32_t number;
    std::string name;
  };

  static uint32_t find_index(const std::vector<std::string> &m, std::string_view key) {
    return static_cast<uint32_t>(std::ranges::lower_bound(m, key) - m.begin());
  }

  struct field_meta {
    uint32_t number = 0;
    uint32_t type_index = 0;
    std::string name;
    std::string json_name;
    google::protobuf::FieldDescriptorProto::Type type = {};
    uint8_t options = 0;
    std::string default_value;

    field_meta() = default;

    template <typename FieldDescriptor, typename Pool>
    field_meta(FieldDescriptor *field_descriptor, const Pool &pool)
        : number(field_descriptor->proto.number), name(field_descriptor->proto.name),
          json_name(field_descriptor->proto.json_name), type(field_descriptor->proto.type),
          default_value(field_descriptor->proto.default_value) {
      auto &proto = field_descriptor->proto;
      if (!proto.type_name.empty() && proto.type == google::protobuf::FieldDescriptorProto::Type::TYPE_MESSAGE) {
        if (pool.message_map.find(proto.type_name)->second->is_map_entry) {
          options |= field_options::is_map_entry;
        }
      }

      using enum google::protobuf::FieldDescriptorProto::Type;
      if (proto.type == TYPE_MESSAGE || proto.type == TYPE_GROUP) {
        type_index = find_index(pool.message_map.keys(), proto.type_name);
      } else if (proto.type == TYPE_ENUM) {
        type_index = find_index(pool.enum_map.keys(), proto.type_name);
      }

      using enum google::protobuf::FieldDescriptorProto::Label;
      if (proto.label == LABEL_REPEATED) {
        if (field_descriptor->is_packed()) {
          options |= uint8_t(field_options::repeated | field_options::packed);
        } else {
          options |= (field_options::repeated);
        }
      }

      if (field_descriptor->is_required()) {
        options |= field_options::required;
      }

      if (field_descriptor->requires_utf8_validation()) {
        options |= field_options::utf8_validation;
      }

      if (field_descriptor->is_delimited()) {
        type = TYPE_GROUP;
        options |= field_options::group;
      }

      if (proto.oneof_index.has_value()) {
        options |= field_options::is_oneof;
      }
    }

    [[nodiscard]] constexpr bool is_packed_repeated() const { return (options & field_options::packed) != 0; }
    [[nodiscard]] constexpr bool is_repeated() const { return (options & field_options::repeated) != 0; }
    [[nodiscard]] constexpr bool is_map_entry() const { return (options & field_options::is_map_entry) != 0; }
  };

  [[nodiscard]] std::size_t message_index(std::string_view name) const {
    auto it = std::ranges::lower_bound(message_names, name);
    if (it == message_names.end() || *it != name) {
      return message_names.size();
    }
    return it - message_names.begin();
  }

  [[nodiscard]] std::size_t message_index_from_type_url(std::string_view type_url) const {
    auto slash_pos = type_url.find('/');
    if (slash_pos >= type_url.size() - 1) {
      return message_names.size();
    }
    return message_index(type_url.substr(slash_pos + 1));
  }

  using message_meta = std::vector<field_meta>;
  using enum_meta = std::vector<enum_value_meta>;

  std::vector<message_meta> messages;
  std::vector<enum_meta> enums;
  std::vector<std::string> message_names;

  std::size_t protobuf_any_message_index = std::numeric_limits<std::size_t>::max();
  std::size_t protobuf_timestamp_message_index = std::numeric_limits<std::size_t>::max();
  std::size_t protobuf_duration_message_index = std::numeric_limits<std::size_t>::max();
  std::size_t protobuf_field_mask_message_index = std::numeric_limits<std::size_t>::max();
  std::size_t protobuf_value_message_index = std::numeric_limits<std::size_t>::max();
  std::size_t protobuf_list_value_message_index = std::numeric_limits<std::size_t>::max();
  std::size_t protobuf_struct_message_index = std::numeric_limits<std::size_t>::max();
  std::vector<std::size_t> protobuf_wrapper_type_message_indices;

  [[nodiscard]] bool is_wellknown_message(std::size_t msg_index) const {
    return msg_index == protobuf_duration_message_index || msg_index == protobuf_timestamp_message_index ||
           msg_index == protobuf_field_mask_message_index || msg_index == protobuf_list_value_message_index ||
           contains(protobuf_wrapper_type_message_indices, msg_index);
  }

  // NOLINTBEGIN(readability-function-cognitive-complexity)
  template <typename Buffer>
  struct pb_to_json_state {
    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    const dynamic_serializer &pb_meta;
    Buffer &b;
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
    glz::context context;
    std::size_t ix = 0;

    pb_to_json_state(const dynamic_serializer &meta, Buffer &buffer) : pb_meta(meta), b(buffer) {}

    bool circular_find(uint32_t &field_index, uint32_t number, const dynamic_serializer::message_meta &msg_meta) {
      for (uint32_t i = field_index; i < msg_meta.size() + field_index; ++i) {
        uint32_t const j = i % msg_meta.size();
        if (msg_meta[j].number == number) {
          field_index = j;
          return true;
        }
      }
      return false;
    }

    status skip_field(uint32_t number, wire_type field_wire_type, concepts::is_basic_in auto &archive) {
      vuint64_t length = 0;
      switch (field_wire_type) {
      case wire_type::varint:
        return archive(length);
      case wire_type::length_delimited:
        if (auto ec = archive(length); !ec.ok()) [[unlikely]] {
          return ec;
        }
        return archive.skip(length);
      case wire_type::fixed_64:
        return archive.skip(8);
      case wire_type::sgroup:
        return skip_group(number, archive);
      case wire_type::fixed_32:
        return archive.skip(4);
      default:
        return std::errc::bad_message;
      }
    }

    status skip_group(uint32_t field_num, concepts::is_basic_in auto &archive) {
      while (archive.in_avail() > 0) {
        auto tag = archive.read_tag();
        uint32_t const next_field_num = tag_number(tag);
        wire_type const next_type = proto::tag_type(tag);

        if (next_type == wire_type::egroup && field_num == next_field_num) {
          return {};
        } else if (auto result = skip_field(next_field_num, next_type, archive); !result.ok()) [[unlikely]] {
          return result;
        }
      }

      return std::errc::bad_message;
    }

    template <auto Options, typename T>
    status field_type_to_json(bool quote_required, concepts::is_basic_in auto &archive) {
      T value{};
      if constexpr (concepts::contiguous_byte_range<T>) {
        vint64_t len;
        if (auto ec = archive(len); !ec.ok()) [[unlikely]] {
          return ec;
        }
        if (archive.in_avail() < len) {
          return std::errc::bad_message;
        }
        value.resize(0);
        if (auto ec = archive.deserialize_packed(len, value); !ec.ok()) [[unlikely]] {
          return ec;
        }
      } else {
        if (auto ec = archive(value); !ec.ok()) [[unlikely]] {
          return ec;
        }
      }
      if (quote_required) {
        glz::detail::dump<'"'>(b, ix);
      }
      if constexpr (concepts::varint<T>) {
        glz::detail::write<glz::json>::op<Options>(value.value, context, b, ix);
      } else {
        glz::detail::write<glz::json>::op<Options>(value, context, b, ix);
      }
      if (quote_required) {
        glz::detail::dump<'"'>(b, ix);
      }
      return {};
    }

    template <auto Options>
    status packed_repeated_to_json(const dynamic_serializer::field_meta &meta, concepts::is_basic_in auto &archive) {
      glz::detail::dump<'['>(b, ix);
      if constexpr (Options.prettify) {
        context.indentation_level += Options.indentation_width;
        glz::detail::dump<'\n'>(b, ix);
        glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
      }

      vint64_t length = 0;
      if (auto ec = archive(length); !ec.ok()) [[unlikely]] {
        return ec;
      }

      if (archive.in_avail() < length) {
        [[unlikely]] return std::errc::bad_message;
      }

      auto new_archive = archive.split(length);

      for (int n = 0; new_archive.in_avail() > 0; ++n) {
        if (n > 0) {
          glz::detail::dump<','>(b, ix);
          if constexpr (Options.prettify) {
            glz::detail::dump<'\n'>(b, ix);
            glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
          }
        }
        const bool is_map_key = false;
        if (auto ec = field_to_json<Options>(meta, is_map_key, new_archive); !ec.ok()) [[unlikely]] {
          return ec;
        }
      }

      if (new_archive.in_avail() < 0) [[unlikely]] {
        return std::errc::bad_message;
      }

      if constexpr (Options.prettify) {
        context.indentation_level -= Options.indentation_width;
        glz::detail::dump<'\n'>(b, ix);
        glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
      }

      glz::detail::dump<']'>(b, ix);
      return {};
    }

    template <auto Options>
    status unpacked_repeated_to_json(uint32_t field_index, const dynamic_serializer::field_meta &meta,
                                     std::vector<uint64_t> &unpacked_repeated_positions,
                                     concepts::is_basic_in auto &archive) {
      auto old_pos =
          unpacked_repeated_positions[field_index]; // the end position of previous repeated element being decoded
      auto start_pos = ix;
      if (old_pos == 0) {
        auto c = meta.is_map_entry() ? '{' : '[';
        glz::detail::dump(c, b, ix);
      } else {
        glz::detail::dump<','>(b, ix);
      }
      if constexpr (Options.prettify) {
        context.indentation_level += Options.indentation_width;
        glz::detail::dump<'\n'>(b, ix);
        glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
      }
      const bool is_map_key = false;
      if (auto ec = field_to_json<Options>(meta, is_map_key, archive); !ec.ok()) [[unlikely]] {
        return ec;
      }

      if (old_pos != 0) {
        auto it = b.begin();
        // move the newly decoded element to the end of previous element
        std::rotate(it + old_pos, it + start_pos, it + ix);
        unpacked_repeated_positions[field_index] = old_pos + (ix - start_pos);
      } else {
        unpacked_repeated_positions[field_index] = ix;
      }

      if constexpr (Options.prettify) {
        context.indentation_level -= Options.indentation_width;
      }

      if (old_pos == 0) {
        if constexpr (Options.prettify) {
          glz::detail::dump<'\n'>(b, ix);
          glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
        }
        auto c = meta.is_map_entry() ? '}' : ']';
        glz::detail::dump(c, b, ix);
      }
      return {};
    }

    template <auto Options>
    status field_to_json(const dynamic_serializer::field_meta &meta, bool is_map_key,
                         concepts::is_basic_in auto &archive) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      switch (meta.type) {
      case TYPE_DOUBLE:
        return field_type_to_json<Options, double>(false, archive);
      case TYPE_FLOAT:
        return field_type_to_json<Options, float>(false, archive);
      case TYPE_INT64:
        return field_type_to_json<Options, vint64_t>(true, archive);
      case TYPE_UINT64:
        return field_type_to_json<Options, vuint64_t>(true, archive);
      case TYPE_INT32:
        return field_type_to_json<Options, vint64_t>(is_map_key, archive);
      case TYPE_FIXED64:
        return field_type_to_json<Options, uint64_t>(true, archive);
      case TYPE_FIXED32:
        return field_type_to_json<Options, uint32_t>(is_map_key, archive);
      case TYPE_BOOL:
        return field_type_to_json<Options, bool>(is_map_key, archive);
      case TYPE_STRING:
        return field_type_to_json<Options, std::string>(false, archive);
      case TYPE_GROUP:
        return group_to_json<Options>(meta.type_index, meta.number, archive);
      case TYPE_MESSAGE: {
        vint64_t length = 0;
        if (!archive(length).ok() || archive.in_avail() < length) [[unlikely]] {
          return std::errc::bad_message;
        }

        auto new_archive = archive.split(length);
        return message_to_json<Options>(meta.type_index, meta.is_map_entry(), new_archive);
      }
      case TYPE_BYTES:
        return field_type_to_json<Options, std::vector<std::byte>>(false, archive);
      case TYPE_UINT32:
        return field_type_to_json<Options, vuint32_t>(is_map_key, archive);
      case TYPE_ENUM:
        return enum_to_json<Options>(meta.type_index, archive);
      case TYPE_SFIXED32:
        return field_type_to_json<Options, int32_t>(is_map_key, archive);
      case TYPE_SFIXED64:
        return field_type_to_json<Options, int64_t>(true, archive);
      case TYPE_SINT32:
        return field_type_to_json<Options, vsint32_t>(is_map_key, archive);
      case TYPE_SINT64:
        return field_type_to_json<Options, vsint64_t>(true, archive);
      }
      glz::unreachable();
    }

    template <auto Options>
    status enum_to_json(uint32_t enum_index, concepts::is_basic_in auto &archive) {
      const auto &meta = pb_meta.enums[enum_index];
      vint64_t value;
      if (auto ec = archive(value); !ec.ok()) [[unlikely]] {
        return ec;
      }
      if (meta.empty() && value == 0) {
        // should be google.protobuf.NullValue
        glz::detail::dump<"null">(b, ix);
        return {};
      } else {
        for (const auto &m : meta) {
          if (m.number == value) {
            glz::detail::dump<'"'>(b, ix);
            glz::detail::dump(m.name, b, ix);
            glz::detail::dump<'"'>(b, ix);
            return {};
          }
        }
      }
      glz::detail::write<glz::json>::op<Options>(value.value, context, b, ix);
      return {};
    }

    template <auto Options>
    status field_to_json(const dynamic_serializer::message_meta &msg_meta, uint32_t number, wire_type field_wire_type,
                         std::vector<uint64_t> &unpacked_repeated_positions, uint32_t &field_index, char &separator,
                         bool is_map_entry, concepts::is_basic_in auto &archive) {
      if (circular_find(field_index, number, msg_meta)) {
        const auto &field_m = msg_meta[field_index];
        if (separator && unpacked_repeated_positions[field_index] == 0) {
          // not the first field in a message, output the separator
          glz::detail::dump(separator, b, ix);
          if (Options.prettify && separator == ',') {
            glz::detail::dump<'\n'>(b, ix);
            glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
          }
        }

        using enum google::protobuf::FieldDescriptorProto::Type;
        if (is_map_entry) {
          separator = ':';
        } else if (!field_m.is_repeated() || unpacked_repeated_positions[field_index] == 0) {
          // output the field name only when it's a non-repeated field or the beginning of repeated field
          const auto &field_name = field_m.json_name;
          glz::detail::write<glz::json>::op<Options>(field_name, context, b, ix);
          glz::detail::dump<':'>(b, ix);
          if constexpr (Options.prettify) {
            glz::detail::dump<' '>(b, ix);
          }
          separator = ',';
        }

        if (!field_m.is_repeated()) {
          if (auto ec = field_to_json<Options>(field_m, is_map_entry && field_index == 0, archive); !ec.ok())
              [[unlikely]] {
            return ec;
          }
        } else if (field_m.is_packed_repeated() && field_wire_type == wire_type::length_delimited) {
          if (auto ec = packed_repeated_to_json<Options>(field_m, archive); !ec.ok()) [[unlikely]] {
            return ec;
          }
        } else {
          if (auto ec = unpacked_repeated_to_json<Options>(field_index, field_m, unpacked_repeated_positions, archive);
              !ec.ok()) [[unlikely]] {
            return ec;
          }
        }

      } else [[unlikely]] {
        //  cannot find the field definition from the schema, skip it
        if (auto ec = skip_field(number, field_wire_type, archive); !ec.ok()) [[unlikely]] {
          return ec;
        }
      }
      return {};
    }

    // NOLINTBEGIN(bugprone-easily-swappable-parameters)
    template <auto Options>
    status group_to_json(uint32_t msg_index, uint32_t field_number, concepts::is_basic_in auto &archive) {
      const dynamic_serializer::message_meta &msg_meta = pb_meta.messages[msg_index];
      glz::detail::dump<'{'>(b, ix);
      if constexpr (Options.prettify) {
        context.indentation_level += Options.indentation_width;
        glz::detail::dump<'\n'>(b, ix);
        glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
      }
      std::vector<uint64_t> unpacked_repeated_positions(msg_meta.size());

      uint32_t field_index = 0;
      char separator = '\0';

      while (archive.in_avail() > 0) {
        auto tag = archive.read_tag();
        auto number = tag_number(tag);
        auto field_wire_type = tag_type(tag);

        if (field_wire_type == wire_type::egroup && field_number == number) {
          if constexpr (Options.prettify) {
            context.indentation_level -= Options.indentation_width;
            glz::detail::dump<'\n'>(b, ix);
            glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
          }
          glz::detail::dump<'}'>(b, ix);

          return {};
        }

        const bool is_map_key = false;
        if (auto ec = field_to_json<Options>(msg_meta, number, field_wire_type, unpacked_repeated_positions,
                                             field_index, separator, is_map_key, archive);
            !ec.ok()) [[unlikely]] {
          return ec;
        }
      }

      return std::errc::bad_message;
    }
    // NOLINTEND(bugprone-easily-swappable-parameters)

    template <auto Options>
    status any_to_json(const auto &v) {
      auto msg_index = pb_meta.message_index_from_type_url(v.type_url);
      if (msg_index >= pb_meta.messages.size()) [[unlikely]] {
        return std::errc::no_message_available;
      }

      glz::detail::dump<"\"@type\":">(b, ix);
      if constexpr (Options.prettify) {
        glz::detail::dump<' '>(b, ix);
      }

      glz::detail::write<glz::json>::op<Options>(v.type_url, context, b, ix);
      glz::detail::dump<','>(b, ix);
      if (Options.prettify) {
        glz::detail::dump<'\n'>(b, ix);
        glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
      }

      pb_context pb_ctx;
      pb_serializer::contiguous_input_stream strm(v.value, pb_ctx);
      auto value_archive = strm.archive();
      const bool is_wellknown = pb_meta.is_wellknown_message(msg_index);
      if (is_wellknown) {
        glz::detail::dump<"\"value\":">(b, ix);
        if constexpr (Options.prettify) {
          glz::detail::dump<' '>(b, ix);
        }

        if (auto ec = message_to_json<Options>(msg_index, false, value_archive); !ec.ok()) [[unlikely]] {
          return ec;
        }

        if constexpr (Options.prettify) {
          context.indentation_level -= Options.indentation_width;
          glz::detail::dump<'\n'>(b, ix);
          glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
        }
        glz::detail::dump<'}'>(b, ix);
        return {};
      } else {
        constexpr auto opts = glz::opening_handled<Options>();
        return message_to_json<opts>(msg_index, false, value_archive);
      }
    }

    template <auto Options, typename T>
    status wellknown_with_codec_to_json(concepts::is_basic_in auto &archive) {
      T v;
      pb_context ctx;
      if (auto ec = pb_serializer::deserialize(v, ctx, archive); !ec.ok()) [[unlikely]] {
        return ec;
      }

      glz::detail::write<glz::json>::op<Options>(v, context, b, ix);
      if (static_cast<bool>(context.error)) [[unlikely]] {
        return std::errc::bad_message;
      }
      return {};
    }

    template <auto Options>
    status list_value_to_json(const dynamic_serializer::message_meta &msg_meta, concepts::is_basic_in auto &archive) {
      std::vector<uint64_t> unpacked_repeated_positions(msg_meta.size());
      while (archive.in_avail() > 0) {
        auto tag = archive.read_tag();
        if (tag_number(tag) != 1 || tag_type(tag) != wire_type::length_delimited) [[unlikely]] {
          return std::errc::bad_message;
        }
        if (auto ec = unpacked_repeated_to_json<Options>(0, msg_meta[0], unpacked_repeated_positions, archive);
            !ec.ok()) [[unlikely]] {
          return ec;
        }
      }
      return archive.in_avail() == 0 ? std::errc{} : std::errc::bad_message;
    }

    template <auto Options>
    status struct_field_to_json(const dynamic_serializer::message_meta &msg_meta, uint32_t number,
                                wire_type field_wire_type, char &separator, concepts::is_basic_in auto &archive) {
      if (number != 1 || field_wire_type != wire_type::length_delimited) [[unlikely]] {
        return std::errc::bad_message;
      }

      if (separator) {
        // not the first field in a message, output the separator
        glz::detail::dump<','>(b, ix);
        if (Options.prettify) {
          glz::detail::dump<'\n'>(b, ix);
          glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
        }
      }

      if (auto ec = field_to_json<Options>(msg_meta[0], true, archive); !ec.ok()) [[unlikely]] {
        return ec;
      }

      separator = ',';
      return {};
    }

    template <auto Options>
    status wrapper_type_to_json(const dynamic_serializer::message_meta &msg_meta, concepts::is_basic_in auto &archive) {
      auto tag = archive.read_tag();
      if (tag_number(tag) != 1) [[unlikely]] {
        return std::errc::bad_message;
      }
      return field_to_json<Options>(msg_meta[0], false, archive);
    }

    template <auto Options>
    status message_to_json(std::size_t msg_index, bool is_map_entry, concepts::is_basic_in auto &archive) {
      const dynamic_serializer::message_meta &msg_meta = pb_meta.messages[msg_index];

      if (msg_index == pb_meta.protobuf_duration_message_index) {
        return wellknown_with_codec_to_json<Options, wellknown::Duration>(archive);
      } else if (msg_index == pb_meta.protobuf_timestamp_message_index) {
        return wellknown_with_codec_to_json<Options, wellknown::Timestamp>(archive);
      } else if (msg_index == pb_meta.protobuf_field_mask_message_index) {
        return wellknown_with_codec_to_json<Options, wellknown::FieldMask>(archive);
      } else if (msg_index == pb_meta.protobuf_list_value_message_index) {
        return list_value_to_json<Options>(msg_meta, archive);
      } else if (contains(pb_meta.protobuf_wrapper_type_message_indices, msg_index)) {
        return wrapper_type_to_json<Options>(msg_meta, archive);
      }

      const bool dump_brace =
          !has_opening_handled(Options) && !is_map_entry && msg_index != pb_meta.protobuf_value_message_index;

      if (dump_brace) {
        glz::detail::dump<'{'>(b, ix);
        if constexpr (Options.prettify) {
          context.indentation_level += Options.indentation_width;
          glz::detail::dump<'\n'>(b, ix);
          glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
        }
      }

      constexpr auto opts = glz::opening_handled_off<Options>();

      // used to track the last postion of the latest decoded element of unpacked repeated fields
      std::vector<uint64_t> unpacked_repeated_positions(msg_meta.size());
      uint32_t field_index = 0;
      char separator = '\0';

      if (msg_index == pb_meta.protobuf_any_message_index) {
        wellknown::Any v;
        pb_context ctx;
        if (auto ec = pb_serializer::deserialize(v, ctx, archive); !ec.ok()) [[unlikely]] {
          return ec;
        }
        if (auto ec = any_to_json<opts>(v); !ec.ok()) [[unlikely]] {
          return ec;
        }
      } else {
        while (archive.in_avail() > 0) {
          auto tag = archive.read_tag();
          auto number = tag_number(tag);
          auto field_wire_type = tag_type(tag);
          if (msg_index == pb_meta.protobuf_struct_message_index) {
            if (auto ec = struct_field_to_json<opts>(msg_meta, number, field_wire_type, separator, archive); !ec.ok())
                [[unlikely]] {
              return ec;
            }
          } else if (msg_index != pb_meta.protobuf_value_message_index) {
            if (auto ec = field_to_json<opts>(msg_meta, number, field_wire_type, unpacked_repeated_positions,
                                              field_index, separator, is_map_entry, archive);
                !ec.ok()) [[unlikely]] {
              return ec;
            }
          } else {
            if (circular_find(field_index, number, msg_meta)) {
              const auto &field_m = msg_meta[field_index];
              if (auto ec = field_to_json<opts>(field_m, false, archive); !ec.ok()) [[unlikely]] {
                return ec;
              }
            }
          }
        }
        if (archive.in_avail() < 0) [[unlikely]] {
          return std::errc::bad_message;
        }
      }

      if (dump_brace) {
        if constexpr (Options.prettify) {
          context.indentation_level -= Options.indentation_width;
          glz::detail::dump<'\n'>(b, ix);
          glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
        }
        glz::detail::dump<'}'>(b, ix);
      }
      return {};
    }
  };

  template <typename Buffer>
  friend struct pb_to_json_state;

  template <typename Buffer>
  struct relocatable_out {
    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    Buffer &buffer;
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
    std::size_t position = 0;

    explicit relocatable_out(Buffer &buffer) : buffer(buffer) {}
    relocatable_out(const relocatable_out &) = delete;
    relocatable_out(relocatable_out &&) = delete;

    relocatable_out &operator=(const relocatable_out &) = delete;
    relocatable_out &operator=(relocatable_out &&) = delete;

    ~relocatable_out() { buffer.resize(position); }
    [[nodiscard]] std::size_t remaining_size() const { return buffer.size() - position; }

    [[nodiscard]] std::size_t size_for(const auto &item) const {
      using type = std::remove_cvref_t<decltype(item)>;
      if constexpr (concepts::byte_serializable<type>) {
        return sizeof(item);
      } else if constexpr (std::is_enum_v<type>) {
        return varint_size(static_cast<int64_t>(item));
      } else if constexpr (concepts::varint<type>) {
        return varint_size<type::encoding, typename type::value_type>(item.value);
      } else if constexpr (concepts::contiguous_byte_range<type>) {
        return varint_size(item.size()) + item.size();
      } else {
        static_assert(!sizeof(type));
      }
    }

    template <typename Item>
    void serialize(const Item &item, concepts::is_basic_out auto &archive) {
      using type = std::remove_cvref_t<Item>;
      if constexpr (concepts::contiguous_byte_range<type>) {
        archive(varint{item.size()}, item);
      } else {
        archive(item);
      }
    }

    template <typename... Item>
    void operator()(Item &&...item) {
      std::size_t sz = (size_for(item) + ...);
      if (remaining_size() < sz) {
        buffer.resize(2 * (buffer.size() + sz));
      }
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      auto out_span = std::span{buffer.data() + position, remaining_size()};
      pb_serializer::basic_out archive{out_span};
      (serialize(std::forward<Item>(item), archive), ...);
      position += sz;
    }
  };

  struct json_to_pb_state {
    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    const dynamic_serializer &pb_meta;
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
    glz::context context = {};

    explicit json_to_pb_state(const dynamic_serializer &meta) : pb_meta(meta) {}

    template <typename T>
    static T &get_underlying_value(T &v) {
      return v;
    }

    template <concepts::varint T>
    static typename T::value_type &get_underlying_value(T &v) {
      return v.value;
    }

    template <auto Options, typename T, bool quoted>
    status type_to_pb(const dynamic_serializer::field_meta &meta, auto &it, auto &end, auto &archive) {
      T value;
      if (quoted) {
        glz::detail::match<'"'>(context, it, end);
        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }
      }

      glz::detail::read<glz::json>::op<glz::ws_handled<Options>()>(get_underlying_value(value), context, it, end);
      if (bool(context.error)) {
        [[unlikely]] return std::errc::illegal_byte_sequence;
      }

      if (quoted) {
        glz::detail::match<'"'>(context, it, end);
        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }
      }

      if (meta.is_packed_repeated()) {
        archive(value);
      } else {
        archive(make_tag<T>(meta), value);
      }
      return {};
    }

    template <typename T>
    status map_key_to_pb(std::string_view key, auto &archive) {
      T value;
      glz::detail::read<glz::json>::op<glz::ws_handled<glz::opts{}>()>(get_underlying_value(value), context, key.data(),
                                                                       key.data() + key.size());
      if (bool(context.error)) {
        [[unlikely]] return std::errc::illegal_byte_sequence;
      }

      archive(make_tag(1, tag_type<T>()), value);
      return {};
    }

    status map_key_to_pb(const dynamic_serializer::field_meta &meta, std::string_view key, auto &archive) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      switch (meta.type) {
      case TYPE_DOUBLE:
        return map_key_to_pb<double>(key, archive);
      case TYPE_FLOAT:
        return map_key_to_pb<float>(key, archive);
      case TYPE_INT64:
        return map_key_to_pb<vint64_t>(key, archive);
      case TYPE_UINT64:
        return map_key_to_pb<vuint64_t>(key, archive);
      case TYPE_INT32:
        return map_key_to_pb<vint64_t>(key, archive);
      case TYPE_FIXED64:
        return map_key_to_pb<uint64_t>(key, archive);
      case TYPE_FIXED32:
        return map_key_to_pb<uint32_t>(key, archive);
      case TYPE_BOOL:
        return map_key_to_pb<bool>(key, archive);
      case TYPE_STRING:
        archive(make_tag(1, tag_type<std::string>()), key);
        return {};
      case TYPE_UINT32:
        return map_key_to_pb<vuint32_t>(key, archive);
      case TYPE_SFIXED32:
        return map_key_to_pb<int32_t>(key, archive);
      case TYPE_SFIXED64:
        return map_key_to_pb<int64_t>(key, archive);
      case TYPE_SINT32:
        return map_key_to_pb<vsint32_t>(key, archive);
      case TYPE_SINT64:
        return map_key_to_pb<vsint64_t>(key, archive);
      default:
        glz::unreachable();
      }
    }

    status serialize_sized(auto &archive, auto const &serialize) {
      std::vector<std::byte> buffer;
      {
        relocatable_out new_archive{buffer};
        if (auto result = serialize(new_archive); !result.ok()) [[unlikely]] {
          return result;
        }
      }
      archive(buffer);
      return {};
    }

    template <auto Options>
    status field_to_pb(const dynamic_serializer::field_meta &meta, auto &it, auto &end, auto &archive) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      switch (meta.type) {
      case TYPE_DOUBLE:
        return type_to_pb<Options, double, false>(meta, it, end, archive);
      case TYPE_FLOAT:
        return type_to_pb<Options, float, false>(meta, it, end, archive);
      case TYPE_INT64:
        return type_to_pb<Options, vint64_t, true>(meta, it, end, archive);
      case TYPE_UINT64:
        return type_to_pb<Options, vuint64_t, true>(meta, it, end, archive);
      case TYPE_INT32:
        return type_to_pb<Options, vint64_t, false>(meta, it, end, archive);
      case TYPE_FIXED64:
        return type_to_pb<Options, uint64_t, true>(meta, it, end, archive);
      case TYPE_FIXED32:
        return type_to_pb<Options, uint32_t, false>(meta, it, end, archive);
      case TYPE_BOOL:
        return type_to_pb<Options, bool, false>(meta, it, end, archive);
      case TYPE_STRING:
        return type_to_pb<Options, std::string, false>(meta, it, end, archive);
      case TYPE_GROUP: {
        archive(make_tag(meta.number, wire_type::sgroup));

        if (auto ec = message_to_pb<Options>(meta.type_index, it, end, 0, archive); !ec.ok()) [[unlikely]] {
          return ec;
        }

        archive(make_tag(meta.number, wire_type::egroup));
        return {};
      }
      case TYPE_MESSAGE: {
        archive(make_tag(meta.number, wire_type::length_delimited));
        return serialize_sized(archive, [this, &meta, &it, &end](auto &archive) {
          return this->message_to_pb<Options>(meta.type_index, it, end, meta.is_map_entry(), archive);
        });
      }
      case TYPE_BYTES:
        return type_to_pb<Options, std::vector<std::byte>, false>(meta, it, end, archive);
      case TYPE_UINT32:
        return type_to_pb<Options, vuint32_t, false>(meta, it, end, archive);
      case TYPE_ENUM:
        return enum_to_pb<Options>(meta, it, end, archive);
      case TYPE_SFIXED32:
        return type_to_pb<Options, int32_t, false>(meta, it, end, archive);
      case TYPE_SFIXED64:
        return type_to_pb<Options, int64_t, true>(meta, it, end, archive);
      case TYPE_SINT32:
        return type_to_pb<Options, vsint32_t, false>(meta, it, end, archive);
      case TYPE_SINT64:
        return type_to_pb<Options, vsint64_t, true>(meta, it, end, archive);
      default:
        glz::unreachable();
      }
    }

    template <auto Opts>
    status enum_to_pb(const dynamic_serializer::field_meta &meta, auto &it, auto &end, auto &archive) {
      const auto &enum_meta = pb_meta.enums[meta.type_index];
      if constexpr (!has_ws_handled(Opts)) {
        glz::detail::skip_ws<Opts>(context, it, end);
        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }
      }

      if (enum_meta.empty()) {
        // this is google.protobuf.NullValue
        glz::detail::match<"null", Opts>(context, it, end);
        archive(make_tag(meta.number, wire_type::varint), varint{0});
        return {};
      }

      const auto key = glz::detail::parse_key(context, it, end);
      if (bool(context.error)) {
        [[unlikely]] return std::errc::illegal_byte_sequence;
      }

      for (const auto &m : enum_meta) {
        if (m.name == key) {
          if (meta.is_packed_repeated()) {
            archive(varint{m.number});
          } else {
            archive(make_tag(meta.number, wire_type::varint), varint{m.number});
          }
          return {};
        }
      }

      context.error = glz::error_code::unexpected_enum;
      return std::errc::illegal_byte_sequence;
    }

    template <auto Options>
    status repeated_to_pb(const dynamic_serializer::field_meta &meta, auto &it, auto &end, auto &archive) {
      if constexpr (!has_ws_handled(Options)) {
        glz::detail::skip_ws<Options>(context, it, end);
        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }
      }
      static constexpr auto Opts = glz::ws_handled_off<Options>();

      glz::detail::match<'['>(context, it, end);
      glz::detail::skip_ws<Options>(context, it, end);
      if (bool(context.error)) {
        [[unlikely]] return std::errc::illegal_byte_sequence;
      }
      const auto n = glz::detail::number_of_array_elements<Opts>(context, it, end);
      if (bool(context.error)) {
        [[unlikely]] return std::errc::illegal_byte_sequence;
      }

      auto handle_elements = [n, this, &meta, &it, &end](auto &archive) -> status {
        size_t i = 0;
        for (i = 0; i < n; ++i) {
          if (auto ec = field_to_pb<Opts>(meta, it, end, archive); !ec.ok()) [[unlikely]] {
            return ec;
          }
          glz::detail::skip_ws<Opts>(context, it, end);
          if (i < n - 1) {
            glz::detail::match<','>(context, it, end);
            glz::detail::skip_ws<Opts>(context, it, end);
          }
          if (bool(context.error)) [[unlikely]] {
            return std::errc::illegal_byte_sequence;
          }
        }
        return {};
      };

      if (meta.is_packed_repeated()) {
        archive(make_tag(meta.number, wire_type::length_delimited));
        if (auto ec = serialize_sized(archive, handle_elements); !ec.ok()) [[unlikely]] {
          return ec;
        }
      } else {
        if (auto ec = handle_elements(archive); !ec.ok()) [[unlikely]] {
          return ec;
        }
      }

      glz::detail::match<']'>(context, it, end);
      return {};
    }

    static bool circular_find(uint32_t &field_index, std::string_view name,
                              const dynamic_serializer::message_meta &msg_meta) {
      for (uint32_t i = field_index; i < msg_meta.size() + field_index; ++i) {
        uint32_t const j = i % msg_meta.size();
        if (msg_meta[j].json_name == name) {
          field_index = j;
          return true;
        }
      }
      return false;
    }

    template <auto Options, typename T>
    status wellknown_with_codec_to_pb(auto &it, auto &end, auto &archive) {
      T value;
      glz::detail::read<glz::json>::op<Options>(value, context, it, end);

      if (bool(context.error)) [[unlikely]] {
        return std::errc::illegal_byte_sequence;
      }
      if (auto ec = append_proto(value, archive.buffer); !ec.ok()) [[unlikely]] {
        return ec;
      }
      archive.position = archive.buffer.size();
      return {};
    }

    template <auto Options>
    status value_to_pb(const dynamic_serializer::message_meta &meta, auto &it, auto &end, auto &archive) {
      if constexpr (!has_ws_handled(Options)) {
        glz::detail::skip_ws<Options>(context, it, end);
        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }
      }
      enum value_kind : uint8_t { kind_null, kind_number, kind_string, kind_bool, kind_struct, kind_list };

      static constexpr auto Opts = glz::opening_handled_off<glz::ws_handled_off<Options>()>();

      switch (static_cast<char>(*it)) {
      case 'n':
        return field_to_pb<Opts>(meta[kind_null], it, end, archive);
      case 'f':
      case 't':
        return field_to_pb<Opts>(meta[kind_bool], it, end, archive);
      case '"':
        return field_to_pb<Opts>(meta[kind_string], it, end, archive);
      case '{': {
        archive(make_tag(meta[kind_struct].number, wire_type::length_delimited));
        const dynamic_serializer::message_meta &msg_meta = pb_meta.messages[pb_meta.protobuf_struct_message_index];
        return serialize_sized(archive, [&](auto &archive) {
          auto meta = msg_meta[0];
          return this->message_to_pb<Options>(meta.type_index, it, end, meta.is_map_entry(), archive);
        });
      }
      case '[': {
        archive(make_tag(meta[kind_list].number, wire_type::length_delimited));
        const dynamic_serializer::message_meta &msg_meta = pb_meta.messages[pb_meta.protobuf_list_value_message_index];
        return serialize_sized(archive,
                               [&](auto &archive) { return repeated_to_pb<Opts>(msg_meta[0], it, end, archive); });
      }
      default:
        return field_to_pb<Opts>(meta[kind_number], it, end, archive);
      }
    }

    template <auto Options>
    bool parse_opening(auto &it, auto &end) {
      using namespace glz::detail;
      if constexpr (!has_opening_handled(Options)) {
        if constexpr (!has_ws_handled(Options)) {
          skip_ws<Options>(context, it, end);
          if (bool(context.error)) [[unlikely]] {
            return false;
          }
        }

        match<'{'>(context, it, end);
        if (bool(context.error)) [[unlikely]] {
          return false;
        }
      }

      skip_ws<Options>(context, it, end);
      if (bool(context.error)) [[unlikely]] {
        return false;
      }
      return true;
    }

    template <auto Options>
    bool parse_colon(auto &it, auto &end) {
      using namespace glz::detail;
      skip_ws<Options>(context, it, end);
      if (bool(context.error)) [[unlikely]] {
        return false;
      }
      match<':'>(context, it, end);
      if (bool(context.error)) [[unlikely]] {
        return false;
      }
      skip_ws<Options>(context, it, end);
      if (bool(context.error)) [[unlikely]] {
        return false;
      }
      return true;
    }

    template <auto Options>
    std::string_view parse_key(auto &it, auto &end) {
      const auto key = glz::detail::parse_key(context, it, end);
      if (bool(context.error) || !parse_colon<Options>(it, end)) [[unlikely]] {
        return {};
      }
      return key;
    }

    template <auto Opts, bool sized>
    status any_value_to_pb(std::size_t msg_index, auto &it, auto &end, auto &archive) {
      if constexpr (!sized) {
        return this->message_to_pb<Opts>(msg_index, it, end, false, archive);
      } else {
        return serialize_sized(archive, [this, msg_index, &it, &end](auto &archive) {
          return this->message_to_pb<Opts>(msg_index, it, end, false, archive);
        });
      }
    }

    template <auto Options, bool any_value_only = false>
    status any_to_pb(auto &type_url, auto &it, auto &end, auto &archive) {
      if (!parse_opening<Options>(it, end)) [[unlikely]] {
        return std::errc::illegal_byte_sequence;
      }

      const auto key = parse_key<Options>(it, end);
      if (bool(context.error)) [[unlikely]] {
        return std::errc::illegal_byte_sequence;
      }

      if (key == "@type") {
        constexpr auto Opts = glz::opening_handled_off<glz::ws_handled_off<Options>()>();
        using namespace glz::detail;
        from_json<std::string_view>::op<Opts>(type_url, context, it, end);
        if (bool(context.error)) [[unlikely]] {
          return std::errc::illegal_byte_sequence;
        }
        auto msg_index = pb_meta.message_index_from_type_url(type_url);
        if (msg_index >= pb_meta.messages.size()) [[unlikely]] {
          return std::errc::no_message_available;
        }

        if constexpr (!any_value_only) {
          archive(make_tag(1, wire_type::length_delimited));
          archive(type_url);
          archive(make_tag(2, wire_type::length_delimited));
        }

        if (!pb_meta.is_wellknown_message(msg_index)) {
          return any_value_to_pb<glz::opening_handled<Opts>(), !any_value_only>(msg_index, it, end, archive);
        } else {
          match<','>(context, it, end);
          if (bool(context.error)) [[unlikely]] {
            return std::errc::illegal_byte_sequence;
          }
          skip_ws<Opts>(context, it, end);
          if (bool(context.error)) [[unlikely]] {
            return std::errc::illegal_byte_sequence;
          }
          match<"\"value\"", Opts>(context, it, end);

          if (!parse_colon<Opts>(it, end)) [[unlikely]] {
            return std::errc::illegal_byte_sequence;
          }
          return any_value_to_pb<Opts, !any_value_only>(msg_index, it, end, archive);
        }
      } else [[unlikely]] {
        return std::errc::illegal_byte_sequence;
      }
    }

    template <auto Options>
    status message_to_pb(std::size_t msg_index, auto &it, auto &end, uint32_t map_entry_number, auto &archive) {
      if (msg_index == pb_meta.protobuf_duration_message_index) {
        return wellknown_with_codec_to_pb<Options, wellknown::Duration>(it, end, archive);
      } else if (msg_index == pb_meta.protobuf_timestamp_message_index) {
        return wellknown_with_codec_to_pb<Options, wellknown::Timestamp>(it, end, archive);
      } else if (msg_index == pb_meta.protobuf_field_mask_message_index) {
        return wellknown_with_codec_to_pb<Options, wellknown::FieldMask>(it, end, archive);
      } else if (msg_index == pb_meta.protobuf_value_message_index) {
        return value_to_pb<Options>(pb_meta.messages[msg_index], it, end, archive);
      } else if (msg_index == pb_meta.protobuf_any_message_index) {
        std::string_view type_url;
        return any_to_pb<Options>(type_url, it, end, archive);
      } else if (contains(pb_meta.protobuf_wrapper_type_message_indices, msg_index)) {
        const auto &meta = pb_meta.messages[msg_index][0];
        return this->field_to_pb<Options>(meta, it, end, archive);
      }

      using namespace glz::detail;
      if (!parse_opening<Options>(it, end)) [[unlikely]] {
        return std::errc::illegal_byte_sequence;
      }

      static constexpr auto Opts = glz::opening_handled_off<glz::ws_handled_off<Options>()>();

      uint32_t field_index = 0;

      bool first = !has_opening_handled(Options);
      while (true) {
        if (*it == '}') [[unlikely]] {
          // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
          ++it;
          // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
          return {};
        } else if (first) {
          [[unlikely]] first = false;
        } else [[likely]] {
          match<','>(context, it, end);
          if (bool(context.error)) {
            [[unlikely]] return std::errc::illegal_byte_sequence;
          }
          skip_ws<Opts>(context, it, end);
          if (bool(context.error)) {
            [[unlikely]] return std::errc::illegal_byte_sequence;
          }
        }

        const auto key = parse_key<Options>(it, end);
        if (bool(context.error)) [[unlikely]] {
          return std::errc::illegal_byte_sequence;
        }

        status ec;

        if (map_entry_number) {
          archive(make_tag(map_entry_number, wire_type::length_delimited));
          const dynamic_serializer::message_meta &msg_meta = pb_meta.messages[msg_index];
          ec = serialize_sized(archive, [this, msg_meta, key, &it, &end](auto &archive) {
            if (auto ec = this->map_key_to_pb((msg_meta)[0], key, archive); !ec.ok()) [[unlikely]] {
              return ec;
            }
            return field_to_pb<Opts>(msg_meta[1], it, end, archive);
          });
        } else {
          const dynamic_serializer::message_meta &msg_meta = pb_meta.messages[msg_index];
          if (!circular_find(field_index, key, msg_meta)) [[unlikely]] {
            context.error = glz::error_code::unknown_key;
            return std::errc::illegal_byte_sequence;
          }
          auto field_m = msg_meta[field_index];
          if (!field_m.is_repeated()) {
            ec = field_to_pb<Opts>(field_m, it, end, archive);
          } else if (field_m.is_map_entry()) {
            ec = message_to_pb<Opts>(field_m.type_index, it, end, field_m.number, archive);
          } else {
            ec = repeated_to_pb<Opts>(field_m, it, end, archive);
          }
        }

        if (!ec.ok()) [[unlikely]] {
          return ec;
        }

        skip_ws<Opts>(context, it, end);
        if (bool(context.error)) [[unlikely]] {
          return std::errc::illegal_byte_sequence;
        }
      }
      return {};
    }
  };
  // NOLINTEND(readability-function-cognitive-complexity)
public:
  using option_type = std::reference_wrapper<dynamic_serializer>;
  explicit dynamic_serializer(const google::protobuf::FileDescriptorSet &set) {
    descriptor_pool<proto_json_addons> pool(set.file);

    if (pool.enum_map.size() != 1 || pool.enum_map.begin()->first != ".google.protobuf.NullValue") {
      enums.reserve(pool.enums.size());
      const auto &enum_descriptors = pool.enum_map.values();
      std::ranges::transform(enum_descriptors, std::back_inserter(enums), [](const auto descriptor) {
        dynamic_serializer::enum_meta m;
        const auto values = descriptor->proto.value;
        m.reserve(values.size());
        std::transform(values.begin(), values.end(), std::back_inserter(m),
                       [](auto &v) { return dynamic_serializer::enum_value_meta{v.number, v.name}; });
        return m;
      });
    } else {
      enums.emplace_back();
    }

    messages.reserve(pool.messages.size());
    const auto &message_descriptors = pool.message_map.values();
    std::ranges::transform(message_descriptors, std::back_inserter(messages), [&pool](const auto descriptor) {
      dynamic_serializer::message_meta m;
      m.reserve(descriptor->fields.size());
      std::ranges::transform(descriptor->fields, std::back_inserter(m),
                             [&pool](auto &f) { return dynamic_serializer::field_meta{f, pool}; });
      return m;
    });

    const auto names = pool.message_map.keys();
    message_names.reserve(names.size());
    // remove the leading "." for the message name
    std::ranges::transform(names, std::back_inserter(message_names), [](const auto &name) { return name.substr(1); });

    protobuf_any_message_index = message_index("google.protobuf.Any");
    protobuf_timestamp_message_index = message_index("google.protobuf.Timestamp");
    protobuf_duration_message_index = message_index("google.protobuf.Duration");
    protobuf_field_mask_message_index = message_index("google.protobuf.FieldMask");
    protobuf_value_message_index = message_index("google.protobuf.Value");
    protobuf_list_value_message_index = message_index("google.protobuf.ListValue");
    protobuf_struct_message_index = message_index("google.protobuf.Struct");

    std::array well_known_wrapper_types{
        "google.protobuf.DoubleValue", "google.protobuf.FloatValue",  "google.protobuf.Int64Value",
        "google.protobuf.UInt64Value", "google.protobuf.Int32Value",  "google.protobuf.UInt32Value",
        "google.protobuf.BoolValue",   "google.protobuf.StringValue", "google.protobuf.BytesValue"};

    protobuf_wrapper_type_message_indices.resize(well_known_wrapper_types.size());
    std::ranges::transform(well_known_wrapper_types, protobuf_wrapper_type_message_indices.begin(),
                           [this](const char *n) { return message_index(n); });
    std::ranges::sort(protobuf_wrapper_type_message_indices);

    // erase the invalid indices in protobuf_wrapper_type_message_indices
    auto to_remove = std::ranges::remove_if(protobuf_wrapper_type_message_indices,
                                            [max_index = messages.size()](auto i) { return i >= max_index; });
    protobuf_wrapper_type_message_indices.erase(to_remove.begin(), to_remove.end());
  }

  static auto make(concepts::contiguous_byte_range auto const &stream) {
    // workaround for glz::expected requires its template parameters to be complete types
    using result_t = glz::expected<dynamic_serializer, hpp::proto::status>;
    google::protobuf::FileDescriptorSet fileset;
    if (auto ec = read_proto(fileset, stream); !ec.ok()) [[unlikely]] {
      return result_t{glz::unexpected(ec)};
    }

    return result_t{dynamic_serializer{fileset}};
  }

  static auto make(concepts::input_bytes_range auto const &stream_range) {
    // workaround for glz::expected requires its template parameters to be complete types
    using result_t = glz::expected<dynamic_serializer, hpp::proto::status>;
    google::protobuf::FileDescriptorSet fileset;
    for (const auto &stream : stream_range) {
      if (auto ec = merge_proto(fileset, stream); !ec.ok()) [[unlikely]] {
        return result_t{glz::unexpected(ec)};
      }
    }
    // double check if we have duplicated files
    std::unordered_map<std::string, google::protobuf::FileDescriptorProto *> file_map;
    auto itr = fileset.file.begin();
    auto last = fileset.file.end();
    for (; itr != last; ++itr) {
      auto [map_itr, inserted] = file_map.try_emplace(itr->name, &(*itr));
      if (!inserted) {
        if (*map_itr->second != *itr) [[unlikely]] {
          // in this case, we have two files with identical names but different content
          return glz::unexpected(std::errc::invalid_argument);
        } else {
          std::rotate(itr, itr + 1, last);
          --last;
        }
      }
    }
    fileset.file.erase(last, fileset.file.end());

    return result_t{dynamic_serializer{fileset}};
  }

  static auto make(concepts::file_descriptor_pb_array auto const &...args) {
    // workaround for glz::expected requires its template parameters to be complete types
    using result_t = glz::expected<dynamic_serializer, hpp::proto::status>;
    constexpr auto s = (std::tuple_size_v<std::remove_cvref_t<decltype(args)>> + ...);
    std::array<file_descriptor_pb, s> tmp;
    auto it = tmp.begin();
    ((it = std::copy(args.begin(), args.end(), it)), ...);

    std::sort(tmp.begin(), it);
    auto last = std::unique(tmp.begin(), tmp.end());
    std::size_t size = last - tmp.begin();

    google::protobuf::FileDescriptorSet fileset;
    fileset.file.resize(size);

    for (std::size_t i = 0; i < size; ++i) {
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
      if (auto ec = read_proto(fileset.file[i], tmp[i].value); !ec.ok()) [[unlikely]] {
        return result_t{glz::unexpected(ec)};
      }
      // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    return result_t{dynamic_serializer{fileset}};
  }

  hpp::proto::status proto_to_json(std::string_view message_name,
                                   concepts::contiguous_byte_range auto const &pb_encoded_stream,
                                   concepts::resizable_contiguous_byte_container auto &buffer,
                                   concepts::glz_opts_t auto opts) const {
    using buffer_type = std::decay_t<decltype(buffer)>;
    auto const id = message_index(message_name);
    if (id == messages.size()) [[unlikely]] {
      return std::errc::invalid_argument;
    }
    buffer.resize(pb_encoded_stream.size() * 2);

    pb_context pb_ctx;
    pb_serializer::contiguous_input_stream strm(pb_encoded_stream, pb_ctx);
    auto archive = strm.archive();

    pb_to_json_state<buffer_type> state{*this, buffer};
    state.context.indentation_level = 0;
    const bool is_map_entry = false;
    constexpr auto opts_value = decltype(opts)::glz_opts_value;
    if (auto ec = state.template message_to_json<opts_value>(id, is_map_entry, archive); !ec.ok()) [[unlikely]] {
      return ec;
    }
    buffer.resize(state.ix);
    return {};
  }

  hpp::proto::status proto_to_json(std::string_view message_name,
                                   concepts::contiguous_byte_range auto const &pb_encoded_stream,
                                   concepts::resizable_contiguous_byte_container auto &buffer) const {
    return proto_to_json(message_name, pb_encoded_stream, buffer, glz_opts_t<glz::opts{}>{});
  }

  [[nodiscard]] expected<std::string, std::errc>
  proto_to_json(std::string_view message_name, concepts::contiguous_byte_range auto const &pb_encoded_stream,
                concepts::glz_opts_t auto opts) const {
    std::string result;
    if (auto ec = proto_to_json(message_name, pb_encoded_stream, result, opts); !ec.ok()) [[unlikely]] {
      return unexpected(ec);
    }
    return result;
  }

  [[nodiscard]] expected<std::string, std::errc>
  proto_to_json(std::string_view message_name, concepts::contiguous_byte_range auto const &pb_encoded_stream) const {
    return proto_to_json(message_name, pb_encoded_stream, glz_opts_t<glz::opts{}>{});
  }

  // NOLINTBEGIN(bugprone-easily-swappable-parameters)
  hpp::proto::json_status json_to_proto(std::string_view message_name, std::string_view json_view,
                                        concepts::contiguous_byte_range auto &buffer) const {
    auto const id = message_index(message_name);
    if (id == messages.size()) [[unlikely]] {
      return json_status{.ctx = {.ec = glz::error_code::unknown_key}};
    }
    json_to_pb_state state{*this};
    const char *it = json_view.data();
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const char *end = it + json_view.size();
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    relocatable_out archive{buffer};
    if (auto ec = state.template message_to_pb<glz::opts{}>(id, it, end, 0, archive); !ec.ok()) [[unlikely]] {
      // NOLINTBEGIN(bugprone-suspicious-stringview-data-usage)
      auto location = std::distance<const char *>(json_view.data(), it);
      // NOLINTEND(bugprone-suspicious-stringview-data-usage)
      return json_status{.ctx = {.ec = (state.context.error == glz::error_code::none ? glz::error_code::syntax_error
                                                                                     : state.context.error),
                                 .location = static_cast<size_t>(location)}};
    }
    return {};
  }
  // NOLINTEND(bugprone-easily-swappable-parameters)

  [[nodiscard]] glz::expected<std::vector<std::byte>, hpp::proto::json_status>
  json_to_proto(std::string_view message_name, std::string_view json) const {
    std::vector<std::byte> result;
    if (auto ec = json_to_proto(message_name, json, result); !ec.ok()) [[unlikely]] {
      return glz::unexpected(ec);
    }
    return result;
  }

  template <auto Options, class End>
  void from_json_any(hpp::proto::concepts::is_any auto &value, glz::is_context auto &ctx, auto &it, End &end) const {
    json_to_pb_state state{*this};
    relocatable_out archive{value.value};
    if (!state.template any_to_pb<Options, true>(value.type_url, it, end, archive).ok()) [[unlikely]] {
      ctx.error = glz::error_code::syntax_error;
    } else {
      ctx.error = state.context.error;
    }
  }

  template <auto Options>
  void to_json_any(hpp::proto::concepts::is_any auto const &value, glz::is_context auto &&ctx, auto &b,
                   auto &ix) const {
    pb_to_json_state state(*this, b);
    state.ix = ix;
    if (!state.template any_to_json<Options>(value).ok()) [[unlikely]] {
      ctx.error = glz::error_code::syntax_error;
    } else {
      ctx.error = state.context.error;
    }
    ix = state.ix;
  }
};

} // namespace hpp::proto
