#pragma once
#include <glaze/glaze.hpp>
#include <hpp_proto/descriptor_pool.h>
#include <hpp_proto/json_serializer.h>
#include <hpp_proto/pb_serializer.h>
#include <zpp_bits.h>

namespace hpp::proto {

#if defined(__cpp_lib_expected)
using std::expected;
using std::unexpected;
#else
using tl::expected;
using tl::unexpected;
#endif

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

class dynamic_serializer {
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
      if (proto.type == TYPE_MESSAGE || proto.type == TYPE_GROUP) {
        type_index = find_index(pool.message_map.keys(), proto.type_name);
      } else if (proto.type == TYPE_ENUM) {
        type_index = find_index(pool.enum_map.keys(), proto.type_name);
      }

      if (proto.label == google::protobuf::FieldDescriptorProto::Label::LABEL_REPEATED) {
        std::optional<bool> packed;
        if (proto.options.has_value() && proto.options->packed.has_value())
          packed = proto.options->packed.value();
        bool is_numeric = !(proto.type == TYPE_MESSAGE || proto.type == TYPE_GROUP || proto.type == TYPE_STRING ||
                            proto.type == TYPE_BYTES);
        if (!is_numeric ||
            ((packed.has_value() && !packed.value()) || (descriptor->syntax == 2 && !packed.has_value())))
          rule = dynamic_serializer::unpacked_repeated;
        else
          rule = dynamic_serializer::packed_repeated;
      } else {
        rule = dynamic_serializer::none;
      }
    }
  };

  std::size_t message_index(std::string_view name) const {
    return std::lower_bound(message_names.begin(), message_names.end(), name) - message_names.begin();
  }

  using message_meta = std::vector<field_meta>;
  using enum_meta = std::vector<enum_value_meta>;

  std::vector<message_meta> messages;
  std::vector<enum_meta> enums;
  std::vector<std::string> message_names;

  template <glz::opts Options, typename Archive, typename Buffer>
  struct pb_to_json_state {
    const dynamic_serializer &pb_meta;
    Archive &archive;
    Buffer &b;
    glz::context context;
    std::size_t ix = 0;

    pb_to_json_state(const dynamic_serializer &meta, Archive &archive, Buffer &buffer)
        : pb_meta(meta), archive(archive), b(buffer) {}

    bool circular_find(uint32_t &field_index, uint32_t number, const dynamic_serializer::message_meta &msg_meta) {
      for (uint32_t i = field_index; i < msg_meta.size() + field_index; ++i) {
        uint32_t j = i % msg_meta.size();
        if (msg_meta[j].number == number) {
          field_index = j;
          return true;
        }
      }
      return false;
    }

    std::errc skip_field(uint32_t number, wire_type field_wire_type) {
      ::zpp::bits::vsize_t length = 0;
      using enum hpp::proto::wire_type;
      switch (field_wire_type) {
      case wire_type::varint:
        return archive(length);
      case wire_type::length_delimited:
        if (auto ec = archive(length); ec != std::errc{}) [[unlikely]] {
          return ec;
        }
        break;
      case wire_type::fixed_64:
        length = 8;
        break;
      case wire_type::sgroup:
        skip_group(number);
        return {};
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

    std::errc skip_group(uint32_t field_num) {
      while (archive.remaining_data().size()) {
        ::zpp::bits::vuint32_t tag;
        if (auto result = archive(tag); failure(result)) [[unlikely]] {
          return result;
        }
        uint32_t next_field_num = tag_number(tag);
        wire_type next_type = proto::tag_type(tag);

        if (next_type == wire_type::egroup && field_num == next_field_num)
          return {};
        else if (auto result = skip_field(next_field_num, next_type); failure(result)) [[unlikely]] {
          return result;
        }
      }

      return std::errc::result_out_of_range;
    }

    template <typename T>
    std::errc decode_field_type(bool quote_required = false) {
      T value;
      if (auto ec = archive(value); ec != std::errc{}) [[unlikely]] {
        return ec;
      }
      if (quote_required)
        glz::detail::dump<'"'>(b, ix);
      if constexpr (zpp::bits::concepts::varint<T>)
        glz::detail::write<glz::json>::op<Options>(value.value, context, b, ix);
      else
        glz::detail::write<glz::json>::op<Options>(value, context, b, ix);
      if (quote_required)
        glz::detail::dump<'"'>(b, ix);
      return {};
    }

    std::errc decode_packed_repeated(const dynamic_serializer::field_meta &meta) {
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

    std::errc decode_unpacked_repeated(uint32_t field_index, const dynamic_serializer::field_meta &meta,
                                       std::vector<uint64_t> &unpacked_repeated_positions) {
      auto old_pos =
          unpacked_repeated_positions[field_index]; // the end position of previous repeated element being decoded
      auto start_pos = ix;
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
        if (meta.is_map_entry)
          glz::detail::dump<'}'>(b, ix);
        else
          glz::detail::dump<']'>(b, ix);
      }
      return {};
    }

    std::errc decode_field(const dynamic_serializer::field_meta &meta, bool is_map_key = false) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      switch (meta.type) {
      case TYPE_DOUBLE:
        return decode_field_type<double>(false);
      case TYPE_FLOAT:
        return decode_field_type<float>(false);
      case TYPE_INT64:
        return decode_field_type<zpp::bits::vint64_t>(true);
      case TYPE_UINT64:
        return decode_field_type<zpp::bits::vuint64_t>(true);
      case TYPE_INT32:
        return decode_field_type<zpp::bits::vint64_t>(is_map_key);
      case TYPE_FIXED64:
        return decode_field_type<uint64_t>(true);
      case TYPE_FIXED32:
        return decode_field_type<uint32_t>(is_map_key);
      case TYPE_BOOL:
        return decode_field_type<bool>(is_map_key);
      case TYPE_STRING:
        return decode_field_type<std::string>(false);
      case TYPE_GROUP:
        return decode_group(meta.type_index, meta.number);
      case TYPE_MESSAGE: {
        zpp::bits::vsize_t length = 0;
        if (auto ec = archive(length); ec != std::errc{}) [[unlikely]] {
          return ec;
        }
        if (archive.remaining_data().size() < length) [[unlikely]]
          return std::errc::result_out_of_range;

        return decode_message(meta.type_index, archive.position() + length, meta.is_map_entry);
      }
      case TYPE_BYTES:
        return decode_field_type<std::vector<std::byte>>(false);
      case TYPE_UINT32:
        return decode_field_type<zpp::bits::vuint32_t>(is_map_key);
      case TYPE_ENUM:
        return decode_enum(meta.type_index);
      case TYPE_SFIXED32:
        return decode_field_type<int32_t>(is_map_key);
      case TYPE_SFIXED64:
        return decode_field_type<int64_t>(true);
      case TYPE_SINT32:
        return decode_field_type<zpp::bits::vsint32_t>(is_map_key);
      case TYPE_SINT64:
        return decode_field_type<zpp::bits::vsint64_t>(true);
      }
      glz::unreachable();
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

    std::errc decode_field(const dynamic_serializer::message_meta &msg_meta, uint32_t number, wire_type field_wire_type,
                           std::vector<uint64_t> &unpacked_repeated_positions, uint32_t &field_index, char &separator,
                           bool is_map_entry = false) {
      if (circular_find(field_index, number, msg_meta)) {
        auto &field_m = msg_meta[field_index];

        if (separator && (!field_m.is_map_entry || unpacked_repeated_positions[field_index] == 0)) {
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
        } else if (field_m.rule == dynamic_serializer::encoding::none ||
                   unpacked_repeated_positions[field_index] == 0) {
          // output the field name only when it's a non-repeated field or the beginning of repeated field
          auto &field_name = field_m.json_name;
          glz::detail::write<glz::json>::op<Options>(field_name, context, b, ix);
          glz::detail::dump<':'>(b, ix);
          if constexpr (Options.prettify) {
            glz::detail::dump<' '>(b, ix);
          }
          separator = ',';
        } else if (!field_m.is_map_entry) {
          // non first element of unpacked repeated field; we need to reset the separator
          // to avoid an extra comma is written at the end of the field
          separator = '\0';
        }

        if (field_m.rule == dynamic_serializer::encoding::none) {
          if (auto ec = decode_field(field_m, is_map_entry && field_index == 0); ec != std::errc{}) [[unlikely]] {
            return ec;
          }
        } else if (field_m.rule == dynamic_serializer::encoding::packed_repeated &&
                   field_wire_type == wire_type::length_delimited) {
          if (auto ec = decode_packed_repeated(field_m); ec != std::errc{}) [[unlikely]] {
            return ec;
          }
        } else {
          if (auto ec = decode_unpacked_repeated(field_index, field_m, unpacked_repeated_positions); ec != std::errc{})
              [[unlikely]] {
            return ec;
          }
        }

      } else [[unlikely]] {
        //  cannot find the field definition from the schema, skip it
        if (auto ec = skip_field(number, field_wire_type); ec != std::errc{}) [[unlikely]] {
          return ec;
        }
      }
      return {};
    }

    std::errc decode_group(uint32_t msg_index, uint32_t field_number) {
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

      while (archive.remaining_data().size()) {
        ::zpp::bits::vuint32_t tag;
        if (auto ec = archive(tag); failure(ec)) [[unlikely]] {
          return ec;
        }

        auto number = hpp::proto::tag_number(tag);
        auto field_wire_type = hpp::proto::tag_type(tag);

        if (field_wire_type == wire_type::egroup && field_number == number) {

          if constexpr (Options.prettify) {
            context.indentation_level -= Options.indentation_width;
            glz::detail::dump<'\n'>(b, ix);
            glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
          }
          glz::detail::dump<'}'>(b, ix);

          return {};
        }

        if (auto ec =
                decode_field(msg_meta, number, field_wire_type, unpacked_repeated_positions, field_index, separator);
            ec != std::errc{}) [[unlikely]] {
          return ec;
        }
      }

      return std::errc::result_out_of_range;
    }

    std::errc decode_message(uint32_t msg_index, std::size_t end_position, bool is_map_entry = false) {

      const dynamic_serializer::message_meta &msg_meta = pb_meta.messages[msg_index];

      if (!is_map_entry) {
        glz::detail::dump<'{'>(b, ix);
        if constexpr (Options.prettify) {
          context.indentation_level += Options.indentation_width;
          glz::detail::dump<'\n'>(b, ix);
          glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
        }
      }

      // used to track the last postion of the latest decoded element of unpacked repeated fields
      std::vector<uint64_t> unpacked_repeated_positions(msg_meta.size());
      uint32_t field_index = 0;
      char separator = '\0';

      while (archive.position() < end_position) {
        zpp::bits::vuint32_t tag;
        if (auto ec = archive(tag); ec != std::errc{}) [[unlikely]] {
          return ec;
        }
        auto number = hpp::proto::tag_number(tag);
        auto field_wire_type = hpp::proto::tag_type(tag);

        if (auto ec = decode_field(msg_meta, number, field_wire_type, unpacked_repeated_positions, field_index,
                                   separator, is_map_entry);
            ec != std::errc{}) [[unlikely]] {
          return ec;
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

  template <typename Archive>
  struct json_to_pb_state {
    const dynamic_serializer &pb_meta;
    Archive &archive;
    glz::context context = {};

    template <typename T>
    static T &get_underlying_value(T &v) {
      return v;
    }

    template <zpp::bits::concepts::varint T>
    static typename T::value_type &get_underlying_value(T &v) {
      return v.value;
    }

    template <auto Options, typename T, bool quoted>
    std::errc encode_type(const dynamic_serializer::field_meta &meta, auto &&it, auto &&end) {
      T value;
      if (quoted) {
        glz::detail::match<'"'>(context, it, end);
        if (bool(context.error)) [[unlikely]]
          return std::errc::illegal_byte_sequence;
      }

      glz::detail::read<glz::json>::op<glz::ws_handled<Options>()>(get_underlying_value(value), context, it, end);
      if (bool(context.error)) [[unlikely]]
        return std::errc::illegal_byte_sequence;

      if (quoted) {
        glz::detail::match<'"'>(context, it, end);
        if (bool(context.error)) [[unlikely]]
          return std::errc::illegal_byte_sequence;
      }

      if (meta.rule == dynamic_serializer::encoding::packed_repeated)
        return archive(value);
      else
        return archive(hpp::proto::make_tag<T>(meta), value);
    }

    template <typename T>
    std::errc encode_map_key(std::string_view key) {
      T value;
      const uint8_t *cur = reinterpret_cast<const uint8_t *>(key.data());
      glz::detail::read<glz::json>::op<glz::opts{.ws_handled = true}>(get_underlying_value(value), context, key.begin(),
                                                                      key.end());
      if (bool(context.error)) [[unlikely]]
        return std::errc::illegal_byte_sequence;

      return archive(make_tag(1, tag_type<T>()), value);
    }

    std::errc encode_map_key(const dynamic_serializer::field_meta &meta, std::string_view key) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      switch (meta.type) {
      case TYPE_DOUBLE:
        return encode_map_key<double>(key);
      case TYPE_FLOAT:
        return encode_map_key<float>(key);
      case TYPE_INT64:
        return encode_map_key<zpp::bits::vint64_t>(key);
      case TYPE_UINT64:
        return encode_map_key<zpp::bits::vuint64_t>(key);
      case TYPE_INT32:
        return encode_map_key<zpp::bits::vint64_t>(key);
      case TYPE_FIXED64:
        return encode_map_key<uint64_t>(key);
      case TYPE_FIXED32:
        return encode_map_key<uint32_t>(key);
      case TYPE_BOOL:
        return encode_map_key<bool>(key);
      case TYPE_STRING:
        return archive(make_tag(1, tag_type<std::string>()), key);
      case TYPE_UINT32:
        return encode_map_key<zpp::bits::vuint32_t>(key);
      case TYPE_SFIXED32:
        return encode_map_key<int32_t>(key);
      case TYPE_SFIXED64:
        return encode_map_key<int64_t>(key);
      case TYPE_SINT32:
        return encode_map_key<zpp::bits::vsint32_t>(key);
      case TYPE_SINT64:
        return encode_map_key<zpp::bits::vsint64_t>(key);
      default:
        glz::unreachable();
        return {};
      }
    }

    template <auto Options>
    std::errc encode_field(const dynamic_serializer::field_meta &meta, auto &&it, auto &&end) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      switch (meta.type) {
      case TYPE_DOUBLE:
        return encode_type<Options, double, false>(meta, it, end);
      case TYPE_FLOAT:
        return encode_type<Options, float, false>(meta, it, end);
      case TYPE_INT64:
        return encode_type<Options, zpp::bits::vint64_t, true>(meta, it, end);
      case TYPE_UINT64:
        return encode_type<Options, zpp::bits::vuint64_t, true>(meta, it, end);
      case TYPE_INT32:
        return encode_type<Options, zpp::bits::vint64_t, false>(meta, it, end);
      case TYPE_FIXED64:
        return encode_type<Options, uint64_t, true>(meta, it, end);
      case TYPE_FIXED32:
        return encode_type<Options, uint32_t, false>(meta, it, end);
      case TYPE_BOOL:
        return encode_type<Options, bool, false>(meta, it, end);
      case TYPE_STRING:
        return encode_type<Options, std::string, false>(meta, it, end);
      case TYPE_GROUP: {
        if (auto ec = archive(make_tag(meta.number, wire_type::sgroup)); ec != std::errc{}) [[unlikely]] {
          return ec;
        }

        if (auto ec = encode_message<Options>(meta.type_index, it, end); ec != std::errc{}) [[unlikely]] {
          return ec;
        }

        return archive(make_tag(meta.number, wire_type::egroup));
      }
      case TYPE_MESSAGE: {
        if (auto ec = archive(make_tag(meta.number, wire_type::length_delimited)); ec != std::errc{}) [[unlikely]] {
          return ec;
        }
        return serialize_sized(archive, [this, &meta, &it, &end]() ZPP_BITS_CONSTEXPR_INLINE_LAMBDA {
          return encode_message<Options>(meta.type_index, it, end, meta.is_map_entry);
        });
      }
      case TYPE_BYTES:
        return encode_type<Options, std::vector<std::byte>, false>(meta, it, end);
      case TYPE_UINT32:
        return encode_type<Options, zpp::bits::vuint32_t, false>(meta, it, end);
      case TYPE_ENUM:
        return encode_enum<Options>(meta, it, end);
      case TYPE_SFIXED32:
        return encode_type<Options, int32_t, false>(meta, it, end);
      case TYPE_SFIXED64:
        return encode_type<Options, int64_t, true>(meta, it, end);
      case TYPE_SINT32:
        return encode_type<Options, zpp::bits::vsint32_t, false>(meta, it, end);
      case TYPE_SINT64:
        return encode_type<Options, zpp::bits::vsint64_t, true>(meta, it, end);
      default:
        glz::unreachable();
        return {};
      }
    }

    template <auto Opts>
    std::errc encode_enum(const dynamic_serializer::field_meta &meta, auto &&it, auto &&end) {
      auto &enum_meta = pb_meta.enums[meta.type_index];
      if constexpr (!Opts.ws_handled) {
        glz::detail::skip_ws<Opts>(context, it, end);
        if (bool(context.error)) [[unlikely]]
          return std::errc::illegal_byte_sequence;
      }

      const auto key = glz::detail::parse_key(context, it, end);
      if (bool(context.error)) [[unlikely]]
        return std::errc::illegal_byte_sequence;

      for (int i = 0; i < enum_meta.size(); ++i) {
        if (enum_meta[i].name == key) {
          if (meta.rule == dynamic_serializer::encoding::packed_repeated)
            return archive(::zpp::bits::varint{enum_meta[i].number});
          else
            return archive(make_tag(meta.number, wire_type::varint), ::zpp::bits::varint{enum_meta[i].number});
        }
      }

      context.error = glz::error_code::unexpected_enum;
      return std::errc::illegal_byte_sequence;
    }

    template <auto Options>
    std::errc encode_repeated(const dynamic_serializer::field_meta &meta, auto &&it, auto &&end) {
      if constexpr (!Options.ws_handled) {
        glz::detail::skip_ws<Options>(context, it, end);
        if (bool(context.error)) [[unlikely]]
          return std::errc::illegal_byte_sequence;
      }
      static constexpr auto Opts = glz::ws_handled_off<Options>();

      glz::detail::match<'['>(context, it, end);
      if (bool(context.error)) [[unlikely]]
        return std::errc::illegal_byte_sequence;
      const auto n = glz::detail::number_of_array_elements<Opts>(context, it, end);
      if (bool(context.error)) [[unlikely]]
        return std::errc::illegal_byte_sequence;

      if (meta.rule == dynamic_serializer::encoding::packed_repeated) {
        if (auto ec = archive(make_tag(meta.number, wire_type::length_delimited), ::zpp::bits::varint{n});
            ec != std::errc{}) [[unlikely]] {
          return ec;
        }
      }

      size_t i = 0;
      for (i = 0; i < n; ++i) {
        if (auto ec = encode_field<Opts>(meta, it, end); ec != std::errc{}) [[unlikely]] {
          return ec;
        }
        glz::detail::skip_ws<Opts>(context, it, end);
        if (i < n - 1) {
          glz::detail::match<','>(context, it, end);
        }
      }
      glz::detail::match<']'>(context, it, end);
      return {};
    }

    bool circular_find(uint32_t &field_index, std::string_view name, const dynamic_serializer::message_meta &msg_meta) {
      for (uint32_t i = field_index; i < msg_meta.size() + field_index; ++i) {
        uint32_t j = i % msg_meta.size();
        if (msg_meta[j].json_name == name) {
          field_index = j;
          return true;
        }
      }
      return false;
    }

    template <auto Options>
    std::errc encode_message(uint32_t msg_index, auto &&it, auto &&end, uint32_t map_entry_number = 0) {
      const dynamic_serializer::message_meta &msg_meta = pb_meta.messages[msg_index];
      using namespace glz::detail;

      if constexpr (!Options.opening_handled) {
        if constexpr (!Options.ws_handled) {
          skip_ws<Options>(context, it, end);
          if (bool(context.error)) [[unlikely]]
            return std::errc::illegal_byte_sequence;
        }
        match<'{'>(context, it, end);
        if (bool(context.error)) [[unlikely]]
          return std::errc::illegal_byte_sequence;
      }

      skip_ws<Options>(context, it, end);
      if (bool(context.error)) [[unlikely]]
        return std::errc::illegal_byte_sequence;

      static constexpr auto Opts = glz::opening_handled_off<glz::ws_handled_off<Options>()>();

      uint32_t field_index = 0;

      bool first = true;
      while (true) {
        if (*it == '}') [[unlikely]] {
          ++it;
          return {};
        } else if (first) [[unlikely]]
          first = false;
        else [[likely]] {
          match<','>(context, it, end);
          if (bool(context.error)) [[unlikely]]
            return std::errc::illegal_byte_sequence;
          skip_ws<Opts>(context, it, end);
          if (bool(context.error)) [[unlikely]]
            return std::errc::illegal_byte_sequence;
        }

        const auto key = glz::detail::parse_key(context, it, end);

        if (bool(context.error)) [[unlikely]]
          return std::errc::illegal_byte_sequence;

        skip_ws<Opts>(context, it, end);
        if (bool(context.error)) [[unlikely]]
          return std::errc::illegal_byte_sequence;
        match<':'>(context, it, end);
        if (bool(context.error)) [[unlikely]]
          return std::errc::illegal_byte_sequence;
        skip_ws<Opts>(context, it, end);
        if (bool(context.error)) [[unlikely]]
          return std::errc::illegal_byte_sequence;

        std::errc ec;

        if (map_entry_number) {
          if (auto ec = archive(make_tag(map_entry_number, wire_type::length_delimited)); ec != std::errc{})
              [[unlikely]] {
            return ec;
          }
          ec = serialize_sized(archive, [this, &msg_meta, key, &it, &end]() ZPP_BITS_CONSTEXPR_INLINE_LAMBDA {
            if (auto ec = encode_map_key(msg_meta[0], key); ec != std::errc{}) [[unlikely]] {
              return ec;
            }
            return encode_field<Opts>(msg_meta[1], it, end);
          });
        } else {
          if (!circular_find(field_index, key, msg_meta)) [[unlikely]] {
            context.error = glz::error_code::unknown_key;
            return std::errc::illegal_byte_sequence;
          }
          auto field_m = msg_meta[field_index];
          if (field_m.rule == dynamic_serializer::none)
            ec = encode_field<Opts>(field_m, it, end);
          else if (field_m.is_map_entry)
            ec = encode_message<Opts>(field_m.type_index, it, end, field_m.number);
          else
            ec = encode_repeated<Opts>(field_m, it, end);
        }

        if (ec != std::errc{}) [[unlikely]] {
          return ec;
        }

        skip_ws<Opts>(context, it, end);
        if (bool(context.error)) [[unlikely]]
          return std::errc::illegal_byte_sequence;
      }
      return {};
    }
  };

public:
  dynamic_serializer(const google::protobuf::FileDescriptorSet &set) {
    descriptor_pool<proto_json_addons> pool(set.file);

    enums.reserve(pool.enums.size());
    const auto &enum_descriptors = pool.enum_map.values();
    std::transform(enum_descriptors.begin(), enum_descriptors.end(), std::back_inserter(enums),
                   [](const auto descriptor) {
                     dynamic_serializer::enum_meta m;
                     const auto values = descriptor->proto.value;
                     m.reserve(values.size());
                     std::transform(values.begin(), values.end(), std::back_inserter(m), [](auto &v) {
                       return dynamic_serializer::enum_value_meta{v.number, v.name};
                     });
                     return m;
                   });

    messages.reserve(pool.messages.size());
    const auto &message_descriptors = pool.message_map.values();
    std::transform(message_descriptors.begin(), message_descriptors.end(), std::back_inserter(messages),
                   [&pool](const auto descriptor) {
                     dynamic_serializer::message_meta m;
                     m.reserve(descriptor->fields.size());
                     std::transform(descriptor->fields.begin(), descriptor->fields.end(), std::back_inserter(m),
                                    [descriptor, &pool](auto &f) {
                                      return dynamic_serializer::field_meta{descriptor, f->proto, pool};
                                    });
                     return m;
                   });

    const auto names = pool.message_map.keys();
    message_names.reserve(names.size());
    // remove the leading "." for the message name
    std::transform(names.begin(), names.end(), std::back_inserter(message_names),
                   [](const auto &name) { return name.substr(1); });
  }

  template <zpp::bits::concepts::byte_view ByteView>
  static expected<dynamic_serializer, std::error_code> make(ByteView filedescriptorset_stream) {
    google::protobuf::FileDescriptorSet fileset;
    if (auto ec = hpp::proto::read_proto(fileset, filedescriptorset_stream); ec) {
      return unexpected{ec};
    }
    return dynamic_serializer{fileset};
  }

  template <auto Options = glz::opts{}>
  std::error_code proto_to_json(std::string_view message_name, zpp::bits::concepts::byte_view auto &&pb_encoded_stream,
                                auto &&buffer) const {
    using buffer_type = std::decay_t<decltype(buffer)>;
    std::size_t id = message_index(message_name);
    if (id == messages.size())
      return std::make_error_code(std::errc::invalid_argument);
    buffer.resize(pb_encoded_stream.size() * 2);
    auto archive = make_in_archive(pb_encoded_stream);
    pb_to_json_state<Options, decltype(archive), buffer_type> state{*this, archive, buffer};
    if (auto ec = state.decode_message(id, pb_encoded_stream.size()); ec != std::errc{}) [[unlikely]]
      return std::make_error_code(ec);
    buffer.resize(state.ix);
    return {};
  }

  template <auto Options = glz::opts{}>
  expected<std::string, std::error_code> proto_to_json(std::string_view message_name,
                                                       zpp::bits::concepts::byte_view auto &&pb_encoded_stream) {
    std::string result;
    if (auto ec = proto_to_json(message_name, std::forward<decltype(pb_encoded_stream)>(pb_encoded_stream), result); ec)
      return unexpected(ec);
    return result;
  }

  template <auto Opts = glz::opts{}, class JsonView, class Buffer>
  std::error_code json_to_proto(std::string_view message_name, JsonView json_view, Buffer &&buffer) const {
    uint32_t id = message_index(message_name);
    if (id == messages.size())
      return std::make_error_code(std::errc::invalid_argument);
    auto archive = make_out_archive(buffer);
    json_to_pb_state<decltype(archive)> state{*this, archive};
    const char *it = json_view.data();
    const char *end = it + json_view.size();
    if (auto ec = state.template encode_message<Opts>(id, it, end); ec != std::errc{}) [[unlikely]]
      return std::make_error_code(ec);
    buffer.resize(archive.position());
    return {};
  }

  template <auto Options = glz::opts{}>
  expected<std::vector<std::byte>, std::error_code> json_to_proto(std::string_view message_name,
                                                                  zpp::bits::concepts::byte_view auto &&json) {
    std::vector<std::byte> result;
    if (auto ec = json_to_proto(message_name, std::forward<decltype(json)>(json), result); ec)
      return unexpected(ec);
    return result;
  }
};

} // namespace hpp::proto
