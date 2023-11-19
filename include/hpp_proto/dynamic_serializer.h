#pragma once
#include <glaze/glaze.hpp>
#include <hpp_proto/descriptor_pool.h>
#include <hpp_proto/json_serializer.h>
#include <hpp_proto/pb_serializer.h>
#include <system_error>

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
    field_descriptor(const google::protobuf::FieldDescriptorProto &, const std::string &) {}
  };

  template <typename EnumD>
  struct enum_descriptor {
    enum_descriptor(const google::protobuf::EnumDescriptorProto &) {}
  };

  template <typename OneofD, typename FieldD>
  struct oneof_descriptor {
    oneof_descriptor(const google::protobuf::OneofDescriptorProto &) {}
  };

  template <typename MessageD, typename EnumD, typename OneofD, typename FieldD>
  struct message_descriptor {
    std::string syntax;
    bool is_map_entry = false;
    std::vector<FieldD *> fields;
    message_descriptor(const google::protobuf::DescriptorProto &proto) {
      fields.reserve(proto.field.size() + proto.extension.size());
      is_map_entry = proto.options.has_value() && proto.options->map_entry;
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
    file_descriptor(const google::protobuf::FileDescriptorProto &proto)
        : syntax(proto.syntax.empty() ? std::string{"proto2"} : proto.syntax) {}
    void add_enum(EnumD &) {}
    void add_message(MessageD &m) { m.syntax = syntax; }
    void add_extension(FieldD &) {}
  };
};

class dynamic_serializer {
  enum encoding : uint8_t { none, unpacked_repeated, packed_repeated };

  struct enum_value_meta {
    int32_t number;
    std::string name;
  };

  static uint32_t find_index(const std::vector<std::string> &m, std::string_view key) {
    return static_cast<uint32_t>(std::lower_bound(m.begin(), m.end(), key) - m.begin());
  }

  struct field_meta {
    uint32_t number;
    uint32_t type_index;
    std::string name;
    std::string json_name;
    google::protobuf::FieldDescriptorProto::Type type;
    encoding rule;
    bool is_map_entry = false;

    field_meta() = default;

    template <typename MessageDescriptor, typename Pool>
    field_meta(MessageDescriptor *descriptor, const google::protobuf::FieldDescriptorProto &proto, const Pool &pool)
        : number(proto.number), name(proto.name), json_name(proto.json_name), type(proto.type) {

      if (!proto.type_name.empty() && proto.type == google::protobuf::FieldDescriptorProto::Type::TYPE_MESSAGE) {
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
        if (proto.options.has_value() && proto.options->packed.has_value()) {
          packed = proto.options->packed.value();
        }
        bool const is_numeric = !(proto.type == TYPE_MESSAGE || proto.type == TYPE_GROUP || proto.type == TYPE_STRING ||
                                  proto.type == TYPE_BYTES);
        if (!is_numeric ||
            ((packed.has_value() && !packed.value()) || (descriptor->syntax == "proto2" && !packed.has_value()))) {
          rule = dynamic_serializer::unpacked_repeated;
        } else {
          rule = dynamic_serializer::packed_repeated;
        }
      } else {
        rule = dynamic_serializer::none;
      }
    }
  };

  uint32_t message_index(std::string_view name) const {
    return static_cast<uint32_t>(std::lower_bound(message_names.begin(), message_names.end(), name) -
                                 message_names.begin());
  }

  using message_meta = std::vector<field_meta>;
  using enum_meta = std::vector<enum_value_meta>;

  std::vector<message_meta> messages;
  std::vector<enum_meta> enums;
  std::vector<std::string> message_names;

  template <glz::opts Options, typename Buffer>
  struct pb_to_json_state {
    const dynamic_serializer &pb_meta;
    Buffer &b;
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

    std::errc skip_field(uint32_t number, wire_type field_wire_type, concepts::is_basic_in auto &archive) {
      vuint64_t length = 0;
      switch (field_wire_type) {
      case wire_type::varint:
        return archive(length);
      case wire_type::length_delimited:
        if (auto ec = archive(length); ec != std::errc{}) [[unlikely]] {
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
        return std::errc::result_out_of_range;
      }
    }

    std::errc skip_group(uint32_t field_num, concepts::is_basic_in auto &archive) {
      while (!archive.empty()) {
        vuint32_t tag;
        archive(tag);
        uint32_t const next_field_num = tag_number(tag);
        wire_type const next_type = proto::tag_type(tag);

        if (next_type == wire_type::egroup && field_num == next_field_num) {
          return {};
        } else if (auto result = skip_field(next_field_num, next_type, archive); result != std::errc{}) [[unlikely]] {
          return result;
        }
      }

      return std::errc::result_out_of_range;
    }

    template <typename T>
    std::errc decode_field_type(bool quote_required, concepts::is_basic_in auto &archive) {
      T value;
      if constexpr (concepts::string_or_bytes<T>) {
        vuint64_t len;
        if (auto ec = archive(len); ec != std::errc{}) [[unlikely]] {
          return ec;
        }
        auto bytes = archive.read(len);
        if (len != bytes.size()) {
          return std::errc::result_out_of_range;
        }
        auto data = std::bit_cast<const typename T::value_type *>(bytes.data());
        value.assign(data, data + bytes.size());
      } else {
        if (auto ec = archive(value); ec != std::errc{}) [[unlikely]] {
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

    std::errc decode_packed_repeated(const dynamic_serializer::field_meta &meta, concepts::is_basic_in auto &archive) {
      glz::detail::dump<'['>(b, ix);
      if constexpr (Options.prettify) {
        context.indentation_level += Options.indentation_width;
        glz::detail::dump<'\n'>(b, ix);
        glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
      }

      vuint64_t length = 0;
      if (auto ec = archive(length); ec != std::errc{}) [[unlikely]] {
        return ec;
      }

      auto field_span = archive.read(length);

      if (field_span.size() != length) {
        [[unlikely]] return std::errc::result_out_of_range;
      }

      pb_serializer::basic_in new_archive{field_span};

      for (int n = 0; !new_archive.empty(); ++n) {
        if (n > 0) {
          glz::detail::dump<','>(b, ix);
          if constexpr (Options.prettify) {
            glz::detail::dump<'\n'>(b, ix);
            glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
          }
        }
        const bool is_map_key = false;
        if (auto ec = decode_field(meta, is_map_key, new_archive); ec != std::errc{}) [[unlikely]] {
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
                                       std::vector<uint64_t> &unpacked_repeated_positions,
                                       concepts::is_basic_in auto &archive) {
      auto old_pos =
          unpacked_repeated_positions[field_index]; // the end position of previous repeated element being decoded
      auto start_pos = ix;
      if (old_pos == 0) {
        if (meta.is_map_entry) {
          glz::detail::dump<'{'>(b, ix);
        } else {
          glz::detail::dump<'['>(b, ix);
        }

      } else {
        glz::detail::dump<','>(b, ix);
      }
      if constexpr (Options.prettify) {
        context.indentation_level += Options.indentation_width;
        glz::detail::dump<'\n'>(b, ix);
        glz::detail::dumpn<Options.indentation_char>(context.indentation_level, b, ix);
      }
      const bool is_map_key = false;
      if (auto ec = decode_field(meta, is_map_key, archive); ec != std::errc{}) [[unlikely]] {
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
        if (meta.is_map_entry) {
          glz::detail::dump<'}'>(b, ix);
        } else {
          glz::detail::dump<']'>(b, ix);
        }
      }
      return {};
    }

    std::errc decode_field(const dynamic_serializer::field_meta &meta, bool is_map_key,
                           concepts::is_basic_in auto &archive) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      switch (meta.type) {
      case TYPE_DOUBLE:
        return decode_field_type<double>(false, archive);
      case TYPE_FLOAT:
        return decode_field_type<float>(false, archive);
      case TYPE_INT64:
        return decode_field_type<vint64_t>(true, archive);
      case TYPE_UINT64:
        return decode_field_type<vuint64_t>(true, archive);
      case TYPE_INT32:
        return decode_field_type<vint64_t>(is_map_key, archive);
      case TYPE_FIXED64:
        return decode_field_type<uint64_t>(true, archive);
      case TYPE_FIXED32:
        return decode_field_type<uint32_t>(is_map_key, archive);
      case TYPE_BOOL:
        return decode_field_type<bool>(is_map_key, archive);
      case TYPE_STRING:
        return decode_field_type<std::string>(false, archive);
      case TYPE_GROUP:
        return decode_group(meta.type_index, meta.number, archive);
      case TYPE_MESSAGE: {
        vuint64_t length = 0;
        archive(length);
        if (archive.size() < length) {
          [[unlikely]] return std::errc::result_out_of_range;
        }

        pb_serializer::basic_in new_archive{archive.read(length)};
        return decode_message(meta.type_index, meta.is_map_entry, new_archive);
      }
      case TYPE_BYTES:
        return decode_field_type<std::vector<std::byte>>(false, archive);
      case TYPE_UINT32:
        return decode_field_type<vuint32_t>(is_map_key, archive);
      case TYPE_ENUM:
        return decode_enum(meta.type_index, archive);
      case TYPE_SFIXED32:
        return decode_field_type<int32_t>(is_map_key, archive);
      case TYPE_SFIXED64:
        return decode_field_type<int64_t>(true, archive);
      case TYPE_SINT32:
        return decode_field_type<vsint32_t>(is_map_key, archive);
      case TYPE_SINT64:
        return decode_field_type<vsint64_t>(true, archive);
      }
      glz::unreachable();
    }

    std::errc decode_enum(uint32_t enum_index, concepts::is_basic_in auto &archive) {
      auto &meta = pb_meta.enums[enum_index];
      vint64_t value;
      if (auto ec = archive(value); ec != std::errc{}) [[unlikely]] {
        return ec;
      }
      for (std::size_t i = 0; i < meta.size(); ++i) {
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
                           bool is_map_entry, concepts::is_basic_in auto &archive) {
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
          if (auto ec = decode_field(field_m, is_map_entry && field_index == 0, archive); ec != std::errc{})
              [[unlikely]] {
            return ec;
          }
        } else if (field_m.rule == dynamic_serializer::encoding::packed_repeated &&
                   field_wire_type == wire_type::length_delimited) {
          if (auto ec = decode_packed_repeated(field_m, archive); ec != std::errc{}) [[unlikely]] {
            return ec;
          }
        } else {
          if (auto ec = decode_unpacked_repeated(field_index, field_m, unpacked_repeated_positions, archive);
              ec != std::errc{}) [[unlikely]] {
            return ec;
          }
        }

      } else [[unlikely]] {
        //  cannot find the field definition from the schema, skip it
        if (auto ec = skip_field(number, field_wire_type, archive); ec != std::errc{}) [[unlikely]] {
          return ec;
        }
      }
      return {};
    }

    std::errc decode_group(uint32_t msg_index, uint32_t field_number, concepts::is_basic_in auto &archive) {
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

      while (!archive.empty()) {
        vuint32_t tag;
        archive(tag);

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
        if (auto ec = decode_field(msg_meta, number, field_wire_type, unpacked_repeated_positions, field_index,
                                   separator, is_map_key, archive);
            ec != std::errc{}) [[unlikely]] {
          return ec;
        }
      }

      return std::errc::result_out_of_range;
    }

    std::errc decode_message(uint32_t msg_index, bool is_map_entry, concepts::is_basic_in auto &archive) {

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

      while (!archive.empty()) {
        vuint32_t tag;
        if (auto ec = archive(tag); ec != std::errc{}) [[unlikely]] {
          return ec;
        }
        auto number = tag_number(tag);
        auto field_wire_type = tag_type(tag);

        if (auto ec = decode_field(msg_meta, number, field_wire_type, unpacked_repeated_positions, field_index,
                                   separator, is_map_entry, archive);
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

  template <glz::opts Options, typename Buffer>
  friend struct pb_to_json_state;

  template <typename Buffer>
  struct relocatable_out {
    Buffer &buffer;
    std::size_t position = 0;

    relocatable_out(Buffer &buffer) : buffer(buffer) {}

    ~relocatable_out() { buffer.resize(position); }
    std::size_t remaining_size() const { return buffer.size() - position; }

    std::size_t size_for(auto &&item) const {
      using type = std::remove_cvref_t<decltype(item)>;
      if constexpr (concepts::byte_serializable<type>) {
        return sizeof(item);
      } else if constexpr (std::is_enum_v<type>) {
        return varint_size(static_cast<int64_t>(item));
      } else if constexpr (concepts::varint<type>) {
        return varint_size<type::encoding, typename type::value_type>(item.value);
      } else if constexpr (concepts::string_or_bytes<type>) {
        return varint_size(item.size()) + item.size();
      } else {
        static_assert(!sizeof(type));
      }
    }

    template <typename Item>
    void serialize(Item &&item, concepts::is_basic_out auto &archive) {
      using type = std::remove_cvref_t<Item>;
      if constexpr (concepts::string_or_bytes<type>) {
        archive(varint{item.size()}, item);
      } else {
        archive(item);
      }
    }

    template <typename... Item>
    void operator()(Item &&...item) {
      std::size_t sz = (size_for(std::forward<Item>(item)) + ...);
      if (remaining_size() < sz) {
        buffer.resize(2 * (buffer.size() + sz));
      }

      auto out_span = std::span{buffer.data() + position, remaining_size()};
      pb_serializer::basic_out archive{out_span};
      (serialize(std::forward<Item>(item), archive), ...);
      position += sz;
    }
  };

  struct json_to_pb_state {
    const dynamic_serializer &pb_meta;
    glz::context context = {};

    template <typename T>
    static T &get_underlying_value(T &v) {
      return v;
    }

    template <concepts::varint T>
    static typename T::value_type &get_underlying_value(T &v) {
      return v.value;
    }

    template <auto Options, typename T, bool quoted>
    std::errc encode_type(const dynamic_serializer::field_meta &meta, auto &&it, auto &&end, auto &archive) {
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

      if (meta.rule == dynamic_serializer::encoding::packed_repeated) {
        archive(value);
      } else {
        archive(make_tag<T>(meta), value);
      }
      return {};
    }

    template <typename T>
    std::errc encode_map_key(std::string_view key, auto &archive) {
      T value;
      glz::detail::read<glz::json>::op<glz::opts{.ws_handled = true}>(get_underlying_value(value), context, key.begin(),
                                                                      key.end());
      if (bool(context.error)) {
        [[unlikely]] return std::errc::illegal_byte_sequence;
      }

      archive(make_tag(1, tag_type<T>()), value);
      return {};
    }

    std::errc encode_map_key(const dynamic_serializer::field_meta &meta, std::string_view key, auto &archive) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      switch (meta.type) {
      case TYPE_DOUBLE:
        return encode_map_key<double>(key, archive);
      case TYPE_FLOAT:
        return encode_map_key<float>(key, archive);
      case TYPE_INT64:
        return encode_map_key<vint64_t>(key, archive);
      case TYPE_UINT64:
        return encode_map_key<vuint64_t>(key, archive);
      case TYPE_INT32:
        return encode_map_key<vint64_t>(key, archive);
      case TYPE_FIXED64:
        return encode_map_key<uint64_t>(key, archive);
      case TYPE_FIXED32:
        return encode_map_key<uint32_t>(key, archive);
      case TYPE_BOOL:
        return encode_map_key<bool>(key, archive);
      case TYPE_STRING:
        archive(make_tag(1, tag_type<std::string>()), key);
        return {};
      case TYPE_UINT32:
        return encode_map_key<vuint32_t>(key, archive);
      case TYPE_SFIXED32:
        return encode_map_key<int32_t>(key, archive);
      case TYPE_SFIXED64:
        return encode_map_key<int64_t>(key, archive);
      case TYPE_SINT32:
        return encode_map_key<vsint32_t>(key, archive);
      case TYPE_SINT64:
        return encode_map_key<vsint64_t>(key, archive);
      default:
        glz::unreachable();
      }
    }

    std::errc serialize_sized(auto &archive, auto &&serialize) {
      std::vector<std::byte> buffer;
      {
        relocatable_out new_rchive{buffer};
        if (auto result = serialize(new_rchive); result != std::errc{}) [[unlikely]] {
          return result;
        }
      }
      archive(buffer);
      return {};
    }

    template <auto Options>
    std::errc encode_field(const dynamic_serializer::field_meta &meta, auto &&it, auto &&end, auto &archive) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      switch (meta.type) {
      case TYPE_DOUBLE:
        return encode_type<Options, double, false>(meta, it, end, archive);
      case TYPE_FLOAT:
        return encode_type<Options, float, false>(meta, it, end, archive);
      case TYPE_INT64:
        return encode_type<Options, vint64_t, true>(meta, it, end, archive);
      case TYPE_UINT64:
        return encode_type<Options, vuint64_t, true>(meta, it, end, archive);
      case TYPE_INT32:
        return encode_type<Options, vint64_t, false>(meta, it, end, archive);
      case TYPE_FIXED64:
        return encode_type<Options, uint64_t, true>(meta, it, end, archive);
      case TYPE_FIXED32:
        return encode_type<Options, uint32_t, false>(meta, it, end, archive);
      case TYPE_BOOL:
        return encode_type<Options, bool, false>(meta, it, end, archive);
      case TYPE_STRING:
        return encode_type<Options, std::string, false>(meta, it, end, archive);
      case TYPE_GROUP: {
        archive(make_tag(meta.number, wire_type::sgroup));

        if (auto ec = encode_message<Options>(meta.type_index, it, end, 0, archive); ec != std::errc{}) [[unlikely]] {
          return ec;
        }

        archive(make_tag(meta.number, wire_type::egroup));
        return {};
      }
      case TYPE_MESSAGE: {
        archive(make_tag(meta.number, wire_type::length_delimited));
        return serialize_sized(archive, [this, &meta, &it, &end](auto &archive) {
          return this->encode_message<Options>(meta.type_index, it, end, meta.is_map_entry, archive);
        });
      }
      case TYPE_BYTES:
        return encode_type<Options, std::vector<std::byte>, false>(meta, it, end, archive);
      case TYPE_UINT32:
        return encode_type<Options, vuint32_t, false>(meta, it, end, archive);
      case TYPE_ENUM:
        return encode_enum<Options>(meta, it, end, archive);
      case TYPE_SFIXED32:
        return encode_type<Options, int32_t, false>(meta, it, end, archive);
      case TYPE_SFIXED64:
        return encode_type<Options, int64_t, true>(meta, it, end, archive);
      case TYPE_SINT32:
        return encode_type<Options, vsint32_t, false>(meta, it, end, archive);
      case TYPE_SINT64:
        return encode_type<Options, vsint64_t, true>(meta, it, end, archive);
      default:
        glz::unreachable();
      }
    }

    template <auto Opts>
    std::errc encode_enum(const dynamic_serializer::field_meta &meta, auto &&it, auto &&end, auto &archive) {
      auto &enum_meta = pb_meta.enums[meta.type_index];
      if constexpr (!Opts.ws_handled) {
        glz::detail::skip_ws<Opts>(context, it, end);
        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }
      }

      const auto key = glz::detail::parse_key(context, it, end);
      if (bool(context.error)) {
        [[unlikely]] return std::errc::illegal_byte_sequence;
      }

      for (std::size_t i = 0; i < enum_meta.size(); ++i) {
        if (enum_meta[i].name == key) {
          if (meta.rule == dynamic_serializer::encoding::packed_repeated) {
            archive(varint{enum_meta[i].number});
          } else {
            archive(make_tag(meta.number, wire_type::varint), varint{enum_meta[i].number});
          }
          return {};
        }
      }

      context.error = glz::error_code::unexpected_enum;
      return std::errc::illegal_byte_sequence;
    }

    template <auto Options>
    std::errc encode_repeated(const dynamic_serializer::field_meta &meta, auto &&it, auto &&end, auto &archive) {
      if constexpr (!Options.ws_handled) {
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

      if (meta.rule == dynamic_serializer::encoding::packed_repeated) {
        archive(make_tag(meta.number, wire_type::length_delimited), varint{n});
      }

      size_t i = 0;
      for (i = 0; i < n; ++i) {
        if (auto ec = encode_field<Opts>(meta, it, end, archive); ec != std::errc{}) [[unlikely]] {
          return ec;
        }
        glz::detail::skip_ws<Opts>(context, it, end);
        if (i < n - 1) {
          glz::detail::match<','>(context, it, end);
          glz::detail::skip_ws<Opts>(context, it, end);
        }
        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }
      }
      glz::detail::match<']'>(context, it, end);
      return {};
    }

    bool circular_find(uint32_t &field_index, std::string_view name, const dynamic_serializer::message_meta &msg_meta) {
      for (uint32_t i = field_index; i < msg_meta.size() + field_index; ++i) {
        uint32_t const j = i % msg_meta.size();
        if (msg_meta[j].json_name == name) {
          field_index = j;
          return true;
        }
      }
      return false;
    }

    template <auto Options>
    std::errc encode_message(uint32_t msg_index, auto &&it, auto &&end, uint32_t map_entry_number, auto &archive) {
      const dynamic_serializer::message_meta &msg_meta = pb_meta.messages[msg_index];
      using namespace glz::detail;

      if constexpr (!Options.opening_handled) {
        if constexpr (!Options.ws_handled) {
          skip_ws<Options>(context, it, end);
          if (bool(context.error)) {
            [[unlikely]] return std::errc::illegal_byte_sequence;
          }
        }
        match<'{'>(context, it, end);
        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }
      }

      skip_ws<Options>(context, it, end);
      if (bool(context.error)) {
        [[unlikely]] return std::errc::illegal_byte_sequence;
      }

      static constexpr auto Opts = glz::opening_handled_off<glz::ws_handled_off<Options>()>();

      uint32_t field_index = 0;

      bool first = true;
      while (true) {
        if (*it == '}') [[unlikely]] {
          ++it;
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

        const auto key = glz::detail::parse_key(context, it, end);

        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }

        skip_ws<Opts>(context, it, end);
        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }
        match<':'>(context, it, end);
        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }
        skip_ws<Opts>(context, it, end);
        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }

        std::errc ec;

        if (map_entry_number) {
          archive(make_tag(map_entry_number, wire_type::length_delimited));
          ec = serialize_sized(archive, [this, &msg_meta, key, &it, &end](auto &archive) {
            if (auto ec = this->encode_map_key(msg_meta[0], key, archive); ec != std::errc{}) [[unlikely]] {
              return ec;
            }
            return encode_field<Opts>(msg_meta[1], it, end, archive);
          });
        } else {
          if (!circular_find(field_index, key, msg_meta)) [[unlikely]] {
            context.error = glz::error_code::unknown_key;
            return std::errc::illegal_byte_sequence;
          }
          auto field_m = msg_meta[field_index];
          if (field_m.rule == dynamic_serializer::none) {
            ec = encode_field<Opts>(field_m, it, end, archive);
          } else if (field_m.is_map_entry) {
            ec = encode_message<Opts>(field_m.type_index, it, end, field_m.number, archive);
          } else {
            ec = encode_repeated<Opts>(field_m, it, end, archive);
          }
        }

        if (ec != std::errc{}) [[unlikely]] {
          return ec;
        }

        skip_ws<Opts>(context, it, end);
        if (bool(context.error)) {
          [[unlikely]] return std::errc::illegal_byte_sequence;
        }
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

  template <concepts::contiguous_byte_range ByteView>
  static expected<dynamic_serializer, std::error_code> make(ByteView filedescriptorset_stream) {
    google::protobuf::FileDescriptorSet fileset;
    if (auto ec = read_proto(fileset, filedescriptorset_stream); ec) {
      return unexpected{ec};
    }
    return dynamic_serializer{fileset};
  }

  template <auto Options>
  std::error_code proto_to_json(std::string_view message_name, concepts::contiguous_byte_range auto &&pb_encoded_stream,
                                auto &&buffer) const {
    using buffer_type = std::decay_t<decltype(buffer)>;
    uint32_t const id = message_index(message_name);
    if (id == messages.size()) {
      return std::make_error_code(std::errc::invalid_argument);
    }
    buffer.resize(pb_encoded_stream.size() * 2);
    auto archive = pb_serializer::basic_in(pb_encoded_stream);
    pb_to_json_state<Options, buffer_type> state{*this, buffer};
    const bool is_map_entry = false;
    if (auto ec = state.decode_message(id, is_map_entry, archive); ec != std::errc{}) {
      [[unlikely]] return std::make_error_code(ec);
    }
    buffer.resize(state.ix);
    return {};
  }

  std::error_code proto_to_json(std::string_view message_name, concepts::contiguous_byte_range auto &&pb_encoded_stream,
                                auto &&buffer) const {
    return proto_to_json<glz::opts{}>(message_name, pb_encoded_stream, buffer);
  }

  template <auto Options>
  expected<std::string, std::error_code> proto_to_json(std::string_view message_name,
                                                       concepts::contiguous_byte_range auto &&pb_encoded_stream) {
    std::string result;
    if (auto ec =
            proto_to_json<Options>(message_name, std::forward<decltype(pb_encoded_stream)>(pb_encoded_stream), result);
        ec) {
      return unexpected(ec);
    }
    return result;
  }

  expected<std::string, std::error_code> proto_to_json(std::string_view message_name,
                                                       concepts::contiguous_byte_range auto &&pb_encoded_stream) {
    return proto_to_json<glz::opts{}>(message_name, pb_encoded_stream);
  }

  template <auto Opts>
  std::error_code json_to_proto(std::string_view message_name, concepts::contiguous_byte_range auto &&json_view,
                                concepts::contiguous_byte_range auto &&buffer) const {
    uint32_t const id = message_index(message_name);
    if (id == messages.size()) {
      return std::make_error_code(std::errc::invalid_argument);
    }
    json_to_pb_state state{*this};
    const char *it = json_view.data();
    const char *end = it + json_view.size();
    relocatable_out archive{buffer};
    if (auto ec = state.template encode_message<Opts>(id, it, end, 0, archive); ec != std::errc{}) {
      [[unlikely]] return std::make_error_code(ec);
    }
    return {};
  }

  std::error_code json_to_proto(std::string_view message_name, concepts::contiguous_byte_range auto &&json_view,
                                concepts::contiguous_byte_range auto &&buffer) const {
    return json_to_proto<glz::opts{}>(message_name, json_view, buffer);
  }

  template <auto Opts>
  expected<std::vector<std::byte>, std::error_code> json_to_proto(std::string_view message_name,
                                                                  concepts::contiguous_byte_range auto &&json) {
    std::vector<std::byte> result;
    if (auto ec = json_to_proto<Opts>(message_name, std::forward<decltype(json)>(json), result); ec) {
      return unexpected(ec);
    }
    return result;
  }

  expected<std::vector<std::byte>, std::error_code> json_to_proto(std::string_view message_name,
                                                                  concepts::contiguous_byte_range auto &&json) {
    return json_to_proto<glz::opts{}>(message_name, json);
  }
};

} // namespace hpp::proto
