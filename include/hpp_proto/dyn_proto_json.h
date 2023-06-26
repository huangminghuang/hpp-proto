#pragma once
#include <glaze/glaze.hpp>
#include <hpp_proto/descriptor_pool.h>
#include <hpp_proto/hpp_proto.h>
#include <zpp_bits.h>

namespace hpp::proto {

struct proto_json_addons {
  template <typename Derived>
  struct field_descriptor {
    field_descriptor(const google::protobuf::FieldDescriptorProto &proto, const std::string &parent_name) {}
  };

  template <typename EnumD>
  struct enum_descriptor {
    enum_descriptor(const google::protobuf::EnumDescriptorProto &proto) {}
  };

  template <typename OneofD, typename FieldD>
  struct oneof_descriptor {
    oneof_descriptor(const google::protobuf::OneofDescriptorProto &proto) {}
  };

  template <typename MessageD, typename EnumD, typename OneofD, typename FieldD>
  struct message_descriptor {
    int syntax = 2;
    bool is_map_entry = false;
    std::vector<FieldD *> fields;
    message_descriptor(const google::protobuf::DescriptorProto &proto) {
      fields.reserve(proto.field.size() + proto.extension.size());
      is_map_entry = proto.options.has_value() && proto.options->map_entry;
    }
    void add_field(FieldD &f) { fields.push_back(&f); }
    void add_enum(EnumD &e) {}
    void add_message(MessageD &m) {}
    void add_oneof(OneofD &o) {}
    void add_extension(FieldD &f) { fields.push_back(&f); }
  };

  template <typename FileD, typename MessageD, typename EnumD, typename FieldD>
  struct file_descriptor {
    int syntax;
    file_descriptor(const google::protobuf::FileDescriptorProto &proto) {
      if (proto.syntax == "proto3")
        syntax = 3;
      else
        syntax = 2;
    }
    void add_enum(EnumD &e) {}
    void add_message(MessageD &m) { m.syntax = syntax; }
    void add_extension(FieldD &f) {}
  };
};

using proto_json_descriptor_pool = descriptor_pool<proto_json_addons>;

class proto_json_meta {
  enum encoding : uint8_t { none, unpacked_repeated, packed_repeated };

  struct enum_value_meta {
    int32_t number;
    std::string name;
  };

  static size_t find_index(const std::vector<std::string> &m, std::string_view key) {
    return std::lower_bound(m.begin(), m.end(), key) - m.begin();
  }

  // TODO: map is not properly modeled
  struct field_meta {
    uint32_t number;
    uint32_t type_index;
    std::string name;
    std::string json_name;
    google::protobuf::FieldDescriptorProto::Type type;
    encoding rule;
    bool is_map_entry = false;

    field_meta() = default;

    template <typename MesssageDescriptor, typename Pool>
    field_meta(MesssageDescriptor *descriptor, const google::protobuf::FieldDescriptorProto &proto, const Pool &pool)
        : number(proto.number), name(proto.name), json_name(proto.json_name), type(proto.type) {

      if (proto.type_name.size() && proto.type == google::protobuf::FieldDescriptorProto::Type::TYPE_MESSAGE) {
        is_map_entry = pool.message_map.find(proto.type_name)->second->is_map_entry;
      }

      using enum google::protobuf::FieldDescriptorProto::Type;
      if (proto.type == TYPE_MESSAGE) {
        type_index = find_index(pool.message_map.keys(), proto.type_name);
      } else if (proto.type == TYPE_ENUM) {
        type_index = find_index(pool.enum_map.keys(), proto.type_name);
      }

      if (proto.label == google::protobuf::FieldDescriptorProto::Label::LABEL_REPEATED) {
        auto &options = proto.options;
        bool packed = options.has_value() && options->packed;
        if ((!packed) || descriptor->syntax == 2 || (proto.type == TYPE_MESSAGE) ||
            (proto.type == TYPE_STRING) || (proto.type == TYPE_BYTES))
          rule = proto_json_meta::unpacked_repeated;
        else
          rule = proto_json_meta::packed_repeated;
      } else {
        rule = proto_json_meta::none;
      }
    }
  };

  std::size_t message_index(std::string name) const {
    return std::lower_bound(message_names.begin(), message_names.end(), name) - message_names.begin();
  }

  using message_meta = std::vector<field_meta>;
  using enum_meta = std::vector<enum_value_meta>;

  std::vector<message_meta> messages;
  std::vector<enum_meta> enums;
  std::vector<std::string> message_names;

  template <glz::opts Options, typename Archive, typename Buffer>
  struct pb_to_json_state {
    const proto_json_meta &pb_meta;
    Archive &archive;
    Buffer &b;
    glz::context context;
    std::size_t ix = 0;

    pb_to_json_state(const proto_json_meta &meta, Archive &archive, Buffer &buffer)
        : pb_meta(meta), archive(archive), b(buffer) {}

    bool circular_find(uint32_t &field_index, uint32_t number, const proto_json_meta::message_meta &msg_meta) {
      for (uint32_t i = field_index; i < msg_meta.size() + field_index; ++i) {
        uint32_t j = i % msg_meta.size();
        if (msg_meta[j].number == number) {
          field_index = j;
          return true;
        }
      }
      return false;
    }

    std::errc skip_field(wire_type field_wire_type) {
      ::zpp::bits::vsize_t length = 0;
      using enum hpp::proto::wire_type;
      switch (field_wire_type) {
      case wire_type::varint:
        return archive(length);
      case wire_type::length_delimited:
        if (auto result = archive(length); result != hpp::proto::errc{}) [[unlikely]] {
          return result;
        }
        break;
      case wire_type::fixed_64:
        length = 8;
        break;
      case wire_type::fixed_32:
        length = 4;
        break;
      default:
        return std::errc::result_out_of_range;
      }
      if (archive.remaining_data().size() < length) [[unlikely]]
        return std::errc::result_out_of_range;
      archive.position() += length;
      return {};
    }

    template <typename T>
    std::errc decode_field_type() {
      T value;
      if (auto ec = archive(value); ec != std::errc{}) [[unlikely]] {
        return ec;
      }
      glz::detail::write<glz::json>::op<Options>(value, context, b, ix);
      return {};
    }

    std::errc decode_packed_repeated(const proto_json_meta::field_meta &meta) {
      glz::detail::dump<'['>(b, ix);
      if constexpr (Options.prettify) {
        context.indentation_level += Options.indentation_width;
        glz::detail::dump<'\n'>(b, ix);
        glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
      }

      ::zpp::bits::vsize_t length = 0;
      if (auto ec = archive(length); ec != std::errc{}) [[unlikely]] {
        return ec;
      }

      if (archive.remaining_data().size() < length) [[unlikely]]
        return std::errc::result_out_of_range;

      auto end_pos = archive.position() + length;

      for (int n = 0; archive.position() < end_pos; ++n) {
        if (n > 0) {
          glz::detail::dump<','>(b, ix);
          if constexpr (Options.prettify) {
            glz::detail::dump<'\n'>(b, ix);
            glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
          }
        }

        if (auto ec = decode_field(meta); ec != std::errc{}) [[unlikely]] {
          return ec;
        }
      }

      if constexpr (Options.prettify) {
        context.indentation_level -= Options.indentation_width;
        glz::detail::dump<'\n'>(b, ix);
        glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
      }

      glz::detail::dump<']'>(b, ix);
      return {};
    }

    std::errc decode_unpacked_repeated(uint32_t field_index, const proto_json_meta::field_meta &meta,
                                       std::vector<uint64_t> &unpacked_repeated_positions) {
      auto old_pos = unpacked_repeated_positions[field_index];
      auto start_pos = ix;
      bool is_map = meta.is_map_entry;
      if (old_pos == 0) {
        if (meta.is_map_entry)
          glz::detail::dump<'{'>(b, ix);
        else
          glz::detail::dump<'['>(b, ix);

      } else {
        glz::detail::dump<','>(b, ix);
      }
      if constexpr (Options.prettify) {
        context.indentation_level += Options.indentation_width;
        glz::detail::dump<'\n'>(b, ix);
        uint32_t indentation_level = context.indentation_level;
        glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
      }

      if (auto ec = decode_field(meta); ec != std::errc{}) [[unlikely]] {
        return ec;
      }

      if (old_pos != 0) {
        auto it = b.begin();
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
        if (meta.is_map_entry)
          glz::detail::dump<'}'>(b, ix);
        else
          glz::detail::dump<']'>(b, ix);
      }
      return {};
    }

    std::errc decode_field(const proto_json_meta::field_meta &meta) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      switch (meta.type) {
      case TYPE_DOUBLE:
        return decode_field_type<double>();
      case TYPE_FLOAT:
        return decode_field_type<float>();
      case TYPE_INT64:
        return decode_field_type<zpp::bits::vint64_t>();
      case TYPE_UINT64:
        return decode_field_type<zpp::bits::vuint64_t>();
      case TYPE_INT32:
        return decode_field_type<zpp::bits::vint64_t>();
      case TYPE_FIXED64:
        return decode_field_type<uint64_t>();
      case TYPE_FIXED32:
        return decode_field_type<uint32_t>();
      case TYPE_BOOL:
        return decode_field_type<bool>();
      case TYPE_STRING:
        return decode_field_type<std::string>();
      case TYPE_GROUP:
        return decode_group(meta.type_index, meta.number);
      case TYPE_MESSAGE: {
        zpp::bits::vsize_t length = 0;
        if (auto result = archive(length); result != hpp::proto::errc{}) [[unlikely]] {
          return result;
        }
        if (archive.remaining_data().size() < length) [[unlikely]]
          return std::errc::result_out_of_range;

        return decode_message(meta.type_index, archive.position() + length, meta.is_map_entry);
      }
      case TYPE_BYTES:
        return decode_field_type<std::vector<std::byte>>();
      case TYPE_UINT32:
        return decode_field_type<zpp::bits::vuint32_t>();
      case TYPE_ENUM:
        return decode_enum(meta.type_index);
      case TYPE_SFIXED32:
        return decode_field_type<int32_t>();
      case TYPE_SFIXED64:
        return decode_field_type<int64_t>();
      case TYPE_SINT32:
        return decode_field_type<zpp::bits::vsint32_t>();
      case TYPE_SINT64:
        return decode_field_type<zpp::bits::vsint64_t>();
      }
      return {};
    }

    std::errc decode_enum(uint32_t enum_index) {
      auto &meta = pb_meta.enums[enum_index];
      ::zpp::bits::vint64_t value;
      if (auto ec = archive(value); ec != std::errc{}) [[unlikely]] {
        return ec;
      }
      for (int i = 0; i < meta.size(); ++i) {
        if (meta[i].number == value) {
          glz::detail::dump<'"'>(b, ix);
          glz::detail::dump(meta[i].name, b, ix);
          glz::detail::dump<'"'>(b, ix);
          return {};
        }
      }
      glz::detail::write<glz::json>::op<Options>(value.value, context, b, ix);
      return {};
    }

    std::errc decode_field(const proto_json_meta::message_meta &msg_meta, uint32_t number, wire_type field_wire_type,
                           std::vector<uint64_t>& unpacked_repeated_positions, uint32_t &field_index, char &separator,
                           bool is_map_entry = false) {
      if (circular_find(field_index, number, msg_meta)) {
        auto &field_m = msg_meta[field_index];

        if (separator && (!field_m.is_map_entry || unpacked_repeated_positions[field_index] == 0)) {
          glz::detail::dump(separator, b, ix);
          if (Options.prettify && separator == ',') {
            glz::detail::dump<'\n'>(b, ix);
            glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
          }
        }

        using enum google::protobuf::FieldDescriptorProto::Type;
        if (is_map_entry) {
          separator = ':';
        } else if (field_m.rule == proto_json_meta::encoding::none || unpacked_repeated_positions[field_index] == 0) {
          auto &key = field_m.json_name;
          glz::detail::write<glz::json>::op<Options>(key, context, b, ix);
          glz::detail::dump<':'>(b, ix);
          if constexpr (Options.prettify) {
            glz::detail::dump<' '>(b, ix);
          }
          separator = ',';
        } else if (!field_m.is_map_entry) {
          separator = '\0';
        }

        if (field_m.rule == proto_json_meta::encoding::none) {
          bool is_numeric_map_key =
              is_map_entry && field_index == 0 && (field_m.type != TYPE_STRING && field_m.type != TYPE_BYTES);
          if (is_numeric_map_key)
            glz::detail::dump<'"'>(b, ix);

          if (auto ec = decode_field(field_m); hpp::proto::failure(ec)) [[unlikely]] {
            return ec;
          }
          if (is_numeric_map_key)
            glz::detail::dump<'"'>(b, ix);
        } else if (field_m.rule == proto_json_meta::encoding::packed_repeated &&
                   field_wire_type == wire_type::length_delimited) {
          if (auto ec = decode_packed_repeated(field_m); hpp::proto::failure(ec)) [[unlikely]] {
            return ec;
          }
        } else {
          if (auto ec = decode_unpacked_repeated(field_index, field_m, unpacked_repeated_positions);
              hpp::proto::failure(ec)) [[unlikely]] {
            return ec;
          }
        }

      } else [[unlikely]] {
        if (auto ec = skip_field(field_wire_type); hpp::proto::failure(ec)) [[unlikely]] {
          return ec;
        }
      }
      return {};
    }

    std::errc decode_group(uint32_t msg_index, uint32_t field_number) {
      const proto_json_meta::message_meta &msg_meta = pb_meta.messages[msg_index];
      glz::detail::dump<'{'>(b, ix);
      if constexpr (Options.prettify) {
        context.indentation_level += Options.indentation_width;
        glz::detail::dump<'\n'>(b, ix);
        glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
      }
      std::vector<uint64_t> unpacked_repeated_positions(msg_meta.size());

      uint32_t field_index = 0;
      char separator = '\0';

      while (archive.remaining_data().size()) {
        ::zpp::bits::vuint32_t tag;
        if (auto result = archive(tag); failure(result)) [[unlikely]] {
          return result;
        }

        auto number = hpp::proto::tag_number(tag);
        auto field_wire_type = hpp::proto::tag_type(tag);

        if (field_wire_type == wire_type::egroup && field_number == number)
          return {};

        if (auto result =
                decode_field(msg_meta, number, field_wire_type, unpacked_repeated_positions, field_index, separator);
            hpp::proto::failure(result)) [[unlikely]] {
          return result;
        }
      }

      if constexpr (Options.prettify) {
        context.indentation_level -= Options.indentation_width;
        glz::detail::dump<'\n'>(b, ix);
        glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
      }
      glz::detail::dump<'}'>(b, ix);

      return std::errc::result_out_of_range;
    }

    std::errc decode_message(uint32_t msg_index, std::size_t end_position, bool is_map_entry = false) {

      const proto_json_meta::message_meta &msg_meta = pb_meta.messages[msg_index];

      if (!is_map_entry) {
        glz::detail::dump<'{'>(b, ix);
        if constexpr (Options.prettify) {
          context.indentation_level += Options.indentation_width;
          glz::detail::dump<'\n'>(b, ix);
          glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
        }
      }

      std::vector<uint64_t> unpacked_repeated_positions(msg_meta.size());
      uint32_t field_index = 0;
      char separator = '\0';

      while (archive.position() < end_position) {
        zpp::bits::vuint32_t tag;
        if (auto result = archive(tag); hpp::proto::failure(result)) [[unlikely]] {
          return result;
        }
        auto number = hpp::proto::tag_number(tag);
        auto field_wire_type = hpp::proto::tag_type(tag);

        if (auto result = decode_field(msg_meta, number, field_wire_type, unpacked_repeated_positions, field_index,
                                       separator, is_map_entry);
            hpp::proto::failure(result)) [[unlikely]] {
          return result;
        }
      }

      if (!is_map_entry) {
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

  template <glz::opts Options, typename Archive, typename Buffer>
  friend struct pb_to_json_state;

public:
  proto_json_meta(const google::protobuf::FileDescriptorSet &set) {
    hpp::proto::proto_json_descriptor_pool pool(set.file);

    enums.reserve(pool.enums.size());
    const auto &enum_descriptors = pool.enum_map.values();
    std::transform(enum_descriptors.begin(), enum_descriptors.end(), std::back_inserter(enums),
                   [](const auto descriptor) {
                     proto_json_meta::enum_meta m;
                     const auto values = descriptor->proto.value;
                     m.reserve(values.size());
                     std::transform(values.begin(), values.end(), std::back_inserter(m), [](auto &v) {
                       return proto_json_meta::enum_value_meta{v.number, v.name};
                     });
                     return m;
                   });

    messages.reserve(pool.messages.size());
    const auto &message_descriptors = pool.message_map.values();
    std::transform(message_descriptors.begin(), message_descriptors.end(), std::back_inserter(messages),
                   [&pool](const auto descriptor) {
                     proto_json_meta::message_meta m;
                     m.reserve(descriptor->fields.size());
                     std::transform(descriptor->fields.begin(), descriptor->fields.end(), std::back_inserter(m),
                                    [descriptor, &pool](auto &f) {
                                      return proto_json_meta::field_meta{descriptor, f->proto, pool};
                                    });
                     return m;
                   });

    const auto names = pool.message_map.keys();
    message_names.reserve(names.size());
    // remove the leading "." for the message name
    std::transform(names.begin(), names.end(), std::back_inserter(message_names),
                   [](const auto &name) { return name.substr(1); });
  }

  template <glz::opts Options, zpp::bits::concepts::byte_view ByteView, class Buffer>
  std::error_code proto_to_json(std::string message_name, ByteView &&pb_encoded_stream, Buffer &&buffer) const {
    auto archive = make_in_archive(pb_encoded_stream);

    std::size_t id = message_index(message_name);
    if (id == messages.size())
      return std::make_error_code(std::errc::invalid_argument);
    buffer.resize(pb_encoded_stream.size() * 2);
    pb_to_json_state<Options, decltype(archive), Buffer> state{*this, archive, buffer};
    if (auto ec = state.decode_message(id, pb_encoded_stream.size()); hpp::proto::failure(ec)) [[unlikely]]
      return std::make_error_code(ec);
    return {};
  }

  // template <auto Opts = glz::opts{}, class JsonView, class Buffer>
  // std::error_code json_to_proto(std::string message_name, JsonView json_view, Buffer &&buffer) const {
  //   std::size_t id = message_index(message_name);
  //   if (id == messages.size())
  //     return std::make_error_code(std::errc::invalid_argument);

  //   glz::json_t obj{};
  //   auto err = glz::read_json(obj, json_view);

  //   if (!err){

  //   }
  // }
};

} // namespace hpp::proto
