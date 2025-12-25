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

#include <span>
#include <string_view>
#include <utility>

#include <hpp_proto/binpb.hpp>
#include <hpp_proto/dynamic_message/bytes_fields.hpp>
#include <hpp_proto/dynamic_message/message_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_bytes_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_enum_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_message_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_scalar_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_string_fields.hpp>
#include <hpp_proto/dynamic_message/scalar_fields.hpp>
#include <hpp_proto/dynamic_message/string_fields.hpp>
#include <hpp_proto/dynamic_message/types.hpp>

namespace hpp::proto {

namespace concepts {
template <typename T>
concept non_owning_string_or_bytes = std::same_as<T, std::string_view> || std::same_as<T, bytes_view>;
} // namespace concepts

namespace pb_serializer {

template <concepts::is_basic_in Archive>
struct field_deserializer {
  uint32_t tag;
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  Archive &archive;

  status deserialize(concepts::arithmetic auto &value, const field_descriptor_t &) {
    if (auto ec = archive(value); !ec.ok()) [[unlikely]] {
      return ec;
    }
    return std::errc{};
  }

  template <typename T, field_kind_t Kind>
  status operator()(scalar_field_mref<T, Kind> mref) {
    if (tag_type<T>() != tag_type(tag)) {
      return std::errc::bad_message;
    }
    T value;
    if (auto ec = deserialize(value, mref.descriptor()); !ec.ok()) [[likely]] {
      return ec;
    }
    mref.set(value);
    return {};
  }

  status deserialize(enum_value_mref mref, const field_descriptor_t &) {
    if (tag_type(tag) != wire_type::varint) {
      return std::errc::bad_message;
    }
    vint64_t value;
    if (auto ec = archive(value); !ec.ok()) [[unlikely]] {
      return ec;
    }
    if (!mref.descriptor().valid_enum_value(static_cast<int32_t>(value))) [[unlikely]] {
      return std::errc::result_out_of_range;
    }
    mref.set(static_cast<int32_t>(value.value));
    return std::errc{};
  }

  status operator()(enum_field_mref mref) {
    auto ec = deserialize(mref.emplace(), mref.descriptor());
    if (ec == std::errc::result_out_of_range) [[unlikely]] {
      mref.reset();
      return std::errc{};
    }
    return ec;
  }

  template <concepts::non_owning_string_or_bytes T>
  status deserialize(T &item, const field_descriptor_t &desc) {
    if (tag_type(tag) != wire_type::length_delimited) {
      return std::errc::bad_message;
    }
    vuint32_t byte_count;
    if (auto result = archive(byte_count); !result.ok()) [[unlikely]] {
      return result;
    }
    if (byte_count == 0) {
      return {};
    }

    decltype(auto) v = detail::as_modifiable(archive.context, item);
    if (auto result = deserialize_packed_repeated_with_byte_count<typename T::value_type>(v, byte_count, archive);
        !result.ok()) [[unlikely]] {
      return result;
    }

    if constexpr (std::same_as<T, std::string_view>) {
      // ensure that the string is valid UTF-8 if required
      if (desc.requires_utf8_validation()) {
        if (!::is_utf8(item.data(), item.size())) {
          item = {};
          return std::errc::illegal_byte_sequence;
        }
      }
    }
    return {};
  }

  status operator()(string_field_mref mref) {
    std::string_view item;
    if (status result = this->deserialize(item, mref.descriptor()); !result.ok()) {
      return result;
    }
    mref.adopt(item);
    return {};
  }

  status deserialize(string_value_mref mref, const field_descriptor_t &desc) {
    std::string_view item;
    if (status result = this->deserialize(item, desc); !result.ok()) {
      return result;
    }
    mref.adopt(item);
    return {};
  }

  status operator()(bytes_field_mref mref) {
    bytes_view item;
    if (status result = this->deserialize(item, mref.descriptor()); !result.ok()) {
      return result;
    }
    mref.adopt(item);
    return {};
  }

  status deserialize(bytes_value_mref mref, const field_descriptor_t &desc) {
    bytes_view item;
    if (status result = this->deserialize(item, desc); !result.ok()) {
      return result;
    }
    mref.adopt(item);
    return {};
  }

  status deserialize(message_value_mref v, const field_descriptor_t &desc) {
    if (!desc.is_delimited() && tag_type(tag) == wire_type::length_delimited) [[likely]] {
      return deserialize_sized(v, archive);
    } else if (desc.is_delimited() && tag_type(tag) == wire_type::sgroup) {
      return deserialize_group(tag_number(tag), v, archive);
    } else {
      return std::errc::bad_message;
    }
  }

  status operator()(message_field_mref mref) { return deserialize(mref.emplace(), mref.descriptor()); }

  status deserialize_unpacked_repeated(repeated_enum_field_mref mref) {
    size_t count = 0;
    if (auto result = count_unpacked_elements(tag, count, archive); !result.ok()) [[unlikely]] {
      return result;
    }

    auto i = mref.size();
    mref.resize(i + count);

    for (; count > 0; --count) {
      auto ec = this->deserialize(mref[i++], mref.descriptor());
      if (ec == std::errc::result_out_of_range) [[unlikely]] {
        --i;
      } else if (!ec.ok()) {
        return ec;
      }

      if (count > 1) {
        archive.maybe_advance_region();
        (void)archive.read_tag();
      }
    }
    mref.resize(i);
    return {};
  }

  template <concepts::resizable MRef>
  status deserialize_unpacked_repeated(MRef mref) {
    std::size_t count = 0;

    if (mref.descriptor().is_delimited()) [[unlikely]] {
      if (auto result = count_groups(tag, count, archive); !result.ok()) [[unlikely]] {
        return result;
      }
    } else {
      if (auto result = count_unpacked_elements(tag, count, archive); !result.ok()) [[unlikely]] {
        return result;
      }
    }

    auto old_size = mref.size();
    const std::size_t new_size = mref.size() + count;
    mref.resize(new_size);

    for (std::size_t i = old_size; i < new_size; ++i, --count) {
      if constexpr (std::same_as<typename MRef::encode_type, typename MRef::value_type>) {
        if (auto ec = this->deserialize(mref[i], mref.descriptor()); !ec.ok()) [[unlikely]] {
          return ec;
        }
      } else {
        typename MRef::encode_type v;
        if (auto ec = this->deserialize(v, mref.descriptor()); !ec.ok()) [[unlikely]] {
          return ec;
        }
        mref[i] = v;
      }
      if (count > 1) {
        archive.maybe_advance_region();
        (void)archive.read_tag();
      }
    }

    return {};
  }

  template <typename EncodeType>
  status deserialize_packed_repeated(concepts::resizable auto &&mref) {
    vuint32_t byte_count;
    if (auto result = archive(byte_count); !result.ok()) [[unlikely]] {
      return result;
    }
    if (byte_count == 0) {
      return {};
    }

    return deserialize_packed_repeated_with_byte_count<EncodeType>(mref, byte_count, archive);
  }

  template <typename T, field_kind_t Kind>
  status operator()(repeated_scalar_field_mref<T, Kind> mref) {
    if (tag_type(tag) == tag_type<T>()) {
      return deserialize_unpacked_repeated(mref);
    } else if (mref.descriptor().is_packed() && tag_type(tag) == wire_type::length_delimited) {
      return deserialize_packed_repeated<T>(mref);
    } else {
      return std::errc::bad_message;
    }
  }

  status operator()(repeated_enum_field_mref mref) {
    if (tag_type(tag) == wire_type::varint) {
      return deserialize_unpacked_repeated(mref);
    } else if (mref.descriptor().is_packed() && tag_type(tag) == wire_type::length_delimited) {
      std::span<int32_t> content;
      pb_context ctx{alloc_from{mref.memory_resource()}};
      if (auto r = deserialize_packed_repeated<vint64_t>(detail::as_modifiable(ctx, content)); !r.ok()) {
        return r;
      }
      mref.adopt(content);
      return {};
    } else {
      return std::errc::bad_message;
    }
  }

  status operator()(repeated_string_field_mref mref) { return deserialize_unpacked_repeated(mref); }
  status operator()(repeated_bytes_field_mref mref) { return deserialize_unpacked_repeated(mref); }
  status operator()(repeated_message_field_mref mref) { return deserialize_unpacked_repeated(mref); }
}; // field_deserializer

status deserialize_field_by_tag(uint32_t tag, message_value_mref item, concepts::is_basic_in auto &archive,
                                auto & /* unknown_fields*/) {
  if (tag_number(tag) == 0) {
    return std::errc::bad_message;
  }
  const auto *field_desc = item.field_descriptor_by_number(tag_number(tag));
  if (field_desc == nullptr) [[unlikely]] {
    return do_skip_field(tag, archive);
  }

  auto f = item.field(*field_desc);
  return f.visit(field_deserializer{tag, archive});
}

template <>
struct size_cache_counter<message_value_cref> {
  constexpr std::size_t operator()(auto) const { return 0; }

  template <concepts::varint T, field_kind_t Kind>
  std::size_t operator()(repeated_scalar_field_cref<T, Kind> f) const {
    return static_cast<std::size_t>(f.descriptor().is_packed());
  }

  template <typename T, field_kind_t Kind>
  std::size_t operator()(repeated_scalar_field_cref<T, Kind>) const {
    return 0;
  }

  std::size_t operator()(repeated_enum_field_cref f) const { return f.descriptor().is_packed() ? 1 : 0; }

  static std::size_t count(message_value_cref f) {
    auto fields = f.fields();
    return util::transform_accumulate(fields, [](field_cref nested_field) {
      return nested_field.has_value() ? nested_field.visit(size_cache_counter<message_value_cref>{}) : 0;
    });
  }

  std::size_t operator()(message_field_cref f) const { return count(*f) + (f.descriptor().is_delimited() ? 0 : 1); }

  std::size_t operator()(repeated_message_field_cref f) const {
    return util::transform_accumulate(f, [](message_value_cref element) { return count(element); }) +
           (f.descriptor().is_delimited() ? 0 : f.size());
  }
};

template <>
struct message_size_calculator<message_value_cref> {
  using size_cache = std::span<uint32_t>;
  struct field_visitor {
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    size_cache::iterator &cache_itr;
    uint32_t result = 0;

    explicit field_visitor(size_cache::iterator &itr) : cache_itr{itr} {}

    static constexpr uint32_t narrow_size(std::size_t value) { return static_cast<uint32_t>(value); }

    static uint32_t tag_size(const auto &v) {
      return narrow_size(varint_size(static_cast<uint32_t>(v.descriptor().proto().number) << 3U));
    }

    void cache_size(uint32_t s) {
      decltype(auto) msg_size = *cache_itr++;
      msg_size = s;
    }

    template <concepts::varint T, field_kind_t Kind>
    uint32_t operator()(scalar_field_cref<T, Kind> v) {
      return narrow_size(tag_size(v) + T{v.value()}.encode_size());
    }

    template <typename T, field_kind_t Kind>
      requires std::is_arithmetic_v<T>
    uint32_t operator()(scalar_field_cref<T, Kind> v) {
      return narrow_size(tag_size(v) + sizeof(T));
    }

    uint32_t operator()(enum_field_cref v) {
      return narrow_size(tag_size(v) + varint_size(int64_t{v.value().number()}));
    }
    uint32_t operator()(string_field_cref v) { return narrow_size(tag_size(v) + len_size(v.value().size())); }
    uint32_t operator()(bytes_field_cref v) { return narrow_size(tag_size(v) + len_size(v.value().size())); }

    template <concepts::varint T, field_kind_t Kind>
    uint32_t operator()(repeated_scalar_field_cref<T, Kind> v) {
      auto ts = tag_size(v);
      if (v.descriptor().is_packed()) {
        auto s = util::transform_accumulate(v, [](auto e) { return T{e}.encode_size(); });
        cache_size(narrow_size(s));
        return narrow_size(ts + len_size(s));
      } else {
        return narrow_size(util::transform_accumulate(v, [ts](auto e) { return ts + T{e}.encode_size(); }));
      }
    }

    template <typename T, field_kind_t Kind>
      requires std::is_arithmetic_v<T>
    uint32_t operator()(repeated_scalar_field_cref<T, Kind> v) {
      auto ts = tag_size(v);
      if (v.descriptor().is_packed()) {
        return narrow_size(ts + len_size(v.size() * sizeof(T)));
      } else {
        return narrow_size(v.size() * (ts + sizeof(T)));
      }
    }

    uint32_t operator()(repeated_enum_field_cref v) {
      auto ts = tag_size(v);
      if (v.descriptor().is_packed()) {
        auto s = util::transform_accumulate(v, [](enum_value e) { return varint_size(int64_t{e.number()}); });
        cache_size(narrow_size(s));
        return narrow_size(ts + len_size(s));
      } else {
        return narrow_size(
            util::transform_accumulate(v, [ts](enum_value e) { return ts + varint_size(int64_t{e.number()}); }));
      }
    }

    uint32_t operator()(repeated_string_field_cref v) {
      auto ts = tag_size(v);
      return narrow_size(
          util::transform_accumulate(v, [ts](const std::string_view e) { return ts + len_size(e.size()); }));
    }

    uint32_t operator()(repeated_bytes_field_cref v) {
      auto ts = tag_size(v);
      // NOLINTNEXTLINE(performance-unnecessary-value-param)
      return narrow_size(util::transform_accumulate(v, [ts](const bytes_view e) { return ts + len_size(e.size()); }));
    }

    uint32_t operator()(message_value_cref msg) {
      return narrow_size(util::transform_accumulate(
          msg.fields(), [this](field_cref f) { return f.has_value() ? f.visit(*this) : 0; }));
    }

    uint32_t operator()(message_field_cref v) {
      if (v.descriptor().is_delimited()) {
        return narrow_size((2 * tag_size(v)) + (*this)(*v));
      } else {
        decltype(auto) msg_size = *cache_itr++;
        auto s = (*this)(*v);
        msg_size = s;
        return narrow_size(tag_size(v) + len_size(s));
      }
    }

    uint32_t operator()(repeated_message_field_cref v) {
      auto ts = tag_size(v);
      if (v.descriptor().is_delimited()) {
        return narrow_size(
            util::transform_accumulate(v, [this, ts](message_value_cref msg) { return (2 * ts) + (*this)(msg); }));
      } else {
        return narrow_size(util::transform_accumulate(v, [this, ts](message_value_cref msg) {
          decltype(auto) msg_size = *cache_itr++;
          auto s = (*this)(msg);
          msg_size = s;
          return ts + len_size(s);
        }));
      }
    }
  };

  [[nodiscard]] static std::size_t message_size(const message_value_cref &item, size_cache cache) {
    auto itr = cache.begin();
    field_visitor calc{itr};
    return calc(item);
  }
};

bool utf8_validation_failed(const field_descriptor_t &desc, const auto &str) {
#if HPP_PROTO_NO_UTF8_VALIDATION
  [[maybe_unused]] desc;
  [[maybe_unused]] str;
#else
  if (desc.requires_utf8_validation()) {
    return !::is_utf8(str.data(), str.size());
  }
#endif
  return false;
}

template <typename Archive>
struct field_serializer {
  // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
  std::span<uint32_t>::iterator &cache_itr;
  Archive &archive;
  // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)

  constexpr static wire_type wire_type_map[] = {
      wire_type::varint,           // 0
      wire_type::fixed_64,         // TYPE_DOUBLE = 1,
      wire_type::fixed_32,         // TYPE_FLOAT = 2,
      wire_type::varint,           // TYPE_INT64 = 3,
      wire_type::varint,           // TYPE_UINT64 = 4,
      wire_type::varint,           // TYPE_INT32 = 5,
      wire_type::fixed_64,         // TYPE_FIXED64 = 6,
      wire_type::fixed_32,         // TYPE_FIXED32 = 7,
      wire_type::varint,           // TYPE_BOOL = 8,
      wire_type::length_delimited, // TYPE_STRING = 9,
      wire_type::sgroup,           // TYPE_GROUP = 10,
      wire_type::length_delimited, // TYPE_MESSAGE = 11,
      wire_type::length_delimited, // TYPE_BYTES = 12,
      wire_type::varint,           // TYPE_UINT32 = 13,
      wire_type::varint,           // TYPE_ENUM = 14,
      wire_type::fixed_32,         // TYPE_SFIXED32 = 15,
      wire_type::fixed_64,         // TYPE_SFIXED64 = 16,
      wire_type::varint,           // TYPE_SINT32 = 17,
      wire_type::varint,           // TYPE_SINT64 = 18
  };

  static vint32_t make_tag(int32_t number, wire_type type) {
    return static_cast<vint32_t>(static_cast<int32_t>(static_cast<uint32_t>(number) << 3U | std::to_underlying(type)));
  }

  static vint32_t make_tag(const field_descriptor_t &desc) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    return make_tag(desc.proto().number, wire_type_map[std::to_underlying(desc.proto().type)]);
  }

  template <typename T, field_kind_t Kind>
  bool operator()(scalar_field_cref<T, Kind> v) {
    const field_descriptor_t &desc = v.descriptor();
    return archive(make_tag(desc), T{v.value()});
  }

  bool operator()(enum_field_cref v) { return archive(make_tag(v.descriptor()), varint{v.value().number()}); }

  bool operator()(string_field_cref v) {
    auto str = v.value();
    return !utf8_validation_failed(v.descriptor(), str) && archive(make_tag(v.descriptor()), varint{str.size()}, str);
  }

  bool operator()(bytes_field_cref v) { return archive(make_tag(v.descriptor()), varint{v.value().size()}, v.value()); }

  template <typename T, field_kind_t Kind>
  bool operator()(repeated_scalar_field_cref<T, Kind> v) {
    const field_descriptor_t &desc = v.descriptor();
    if (desc.is_packed()) {
      const uint32_t byte_count = concepts::varint<T> ? *cache_itr++ : static_cast<uint32_t>(sizeof(T) * v.size());
      return archive(make_tag(desc.proto().number, wire_type::length_delimited), varint{byte_count}) &&
             std::ranges::all_of(v, [this](auto e) { return archive(T{e}); });
    } else {
      const auto tag = make_tag(desc);
      return std::ranges::all_of(v, [this, tag](auto e) { return archive(tag, T{e}); });
    }
  }

  bool operator()(repeated_enum_field_cref v) {
    const field_descriptor_t &desc = v.descriptor();
    if (desc.is_packed()) {
      return archive(make_tag(desc.proto().number, wire_type::length_delimited), varint{*cache_itr++}) &&
             std::ranges::all_of(v, [this](auto e) { return archive(varint{e.number()}); });
    } else {
      const auto tag = make_tag(desc);
      return std::ranges::all_of(v, [this, tag](auto e) { return archive(tag, varint{e.number()}); });
    }
  }

  bool operator()(repeated_string_field_cref v) {
    const field_descriptor_t &desc = v.descriptor();
    const auto tag = make_tag(desc);

    return std::ranges::all_of(
        v, [&](std::string_view e) { return !utf8_validation_failed(desc, e) && archive(tag, varint{e.size()}, e); });
  }

  bool operator()(repeated_bytes_field_cref v) {
    const field_descriptor_t &desc = v.descriptor();
    const auto tag = make_tag(desc);
    return std::ranges::all_of(v, [this, &tag](const auto &e) { return archive(tag, varint{e.size()}, e); });
  }

  bool operator()(message_value_cref item) {
    return std::ranges::all_of(item.fields(), [&](field_cref f) { return !f.has_value() || f.visit(*this); });
  }

  struct message_tag_writer {
    field_serializer *serializer;
    int32_t number;
    bool is_delimited;
    message_tag_writer(const message_tag_writer &) = delete;
    message_tag_writer(message_tag_writer &&) = delete;
    message_tag_writer(field_serializer *ser, const field_descriptor_t &desc)
        : serializer(ser), number(desc.proto().number), is_delimited(desc.is_delimited()) {
      if (is_delimited) {
        serializer->archive(make_tag(number, wire_type::sgroup));
      } else {
        serializer->archive(make_tag(number, wire_type::length_delimited), varint{*serializer->cache_itr++});
      }
    };

    message_tag_writer &operator=(const message_tag_writer &) = delete;
    message_tag_writer &operator=(message_tag_writer &&) = delete;
    ~message_tag_writer() {
      if (is_delimited) {
        serializer->archive(make_tag(number, wire_type::egroup));
      }
    }
  };

  bool operator()(message_field_cref item) {
    const field_descriptor_t &desc = item.descriptor();
    message_tag_writer tag_writer{this, desc};
    return (*this)(item.value());
  }

  bool operator()(repeated_message_field_cref item) {
    const field_descriptor_t &desc = item.descriptor();
    return std::ranges::all_of(item, [&](auto e) {
      message_tag_writer tag_writer{this, desc};
      return (*this)(e);
    });
  }
};

[[nodiscard]] bool serialize(const message_value_cref &item, std::span<uint32_t>::iterator &cache_itr, auto &archive) {
  field_serializer ser{cache_itr, archive};
  return ser(item);
}
} // namespace pb_serializer

} // namespace hpp::proto
