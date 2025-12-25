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
#include <expected>

#include <hpp_proto/binpb/deserialize.hpp>
#include <hpp_proto/binpb/serialize.hpp>

namespace hpp::proto {
using std::expected;
using std::unexpected;
template <typename F>
  requires std::regular_invocable<F>
consteval auto write_binpb(F make_object) {
  constexpr auto obj = make_object();
  constexpr auto sz = pb_serializer::message_size_calculator<decltype(obj)>::message_size(obj);
  if constexpr (sz == 0) {
    return std::span<std::byte>{};
  } else {
    pb_context<> ctx;
    std::array<std::byte, sz> buffer = {};
    if (auto result = pb_serializer::serialize(obj, buffer, ctx); !result.ok()) {
      throw std::system_error(std::make_error_code(result.ec));
    }
    return buffer;
  }
}

template <concepts::has_meta T, concepts::contiguous_byte_range Buffer>
status write_binpb(T &&msg, Buffer &buffer, concepts::is_pb_context auto &ctx) {
  decltype(auto) v = detail::as_modifiable(ctx, buffer);
  return pb_serializer::serialize(std::forward<T>(msg), v, ctx);
}

template <concepts::has_meta T, concepts::contiguous_byte_range Buffer>
status write_binpb(T &&msg, Buffer &buffer, concepts::is_option_type auto &&...option) {
  pb_context ctx{std::forward<decltype(option)>(option)...};
  return write_binpb(std::forward<T>(msg), buffer, ctx);
}

template <concepts::contiguous_byte_range Buffer = std::vector<std::byte>>
expected<Buffer, std::errc> write_binpb(concepts::has_meta auto const &msg, concepts::is_option_type auto &&...option) {
  Buffer buffer;
  if (auto result = write_binpb(msg, buffer, std::forward<decltype(option)>(option)...); !result.ok()) {
    return unexpected(result.ec);
  } else {
    return buffer;
  }
}

/// @brief serialize a message to the end of the supplied buffer
template <concepts::has_meta T>
status append_proto(T &&msg, concepts::resizable_contiguous_byte_container auto &buffer) {
  constexpr bool overwrite_buffer = false;
  pb_context<> ctx;
  return pb_serializer::serialize<overwrite_buffer>(std::forward<T>(msg), buffer, ctx);
}

template <concepts::has_meta T>
constexpr static expected<T, std::errc> read_binpb(concepts::input_byte_range auto const &buffer,
                                                   concepts::is_option_type auto &&...option) {
  T msg{};
  pb_context ctx{std::forward<decltype(option)>(option)...};
  if (auto result = pb_serializer::deserialize(msg, buffer, ctx); !result.ok()) {
    return unexpected(result.ec);
  }
  return msg;
}

template <concepts::has_meta T, concepts::input_byte_range Buffer>
status read_binpb(T &msg, const Buffer &buffer, concepts::is_pb_context auto &ctx) {
  msg = {};
  return pb_serializer::deserialize(msg, buffer, ctx);
}

template <concepts::has_meta T, std::size_t N>
constexpr static expected<T, std::errc> read_binpb(const char (&buffer)[N], concepts::is_option_type auto &&...option) {
  constexpr auto span_size = N == 0 ? 0 : N - 1;
  auto span = std::span<const char>{buffer, span_size};
  return read_binpb<T>(span, std::forward<decltype(option)>(option)...);
}

template <concepts::has_meta T, std::size_t N>
status read_binpb(T &msg, const char (&buffer)[N], concepts::is_option_type auto &&...option) {
  constexpr auto span_size = N == 0 ? 0 : N - 1;
  auto span = std::span<const char>{buffer, span_size};
  return read_binpb(msg, span, std::forward<decltype(option)>(option)...);
}

template <concepts::has_meta T, concepts::input_byte_range Buffer>
status read_binpb(T &msg, const Buffer &buffer, concepts::is_option_type auto &&...option) {
  pb_context ctx{std::forward<decltype(option)>(option)...};
  return read_binpb(msg, buffer, ctx);
}

template <typename T, template <typename Traits> class Extendee>
struct extension_base {
  constexpr static auto number() {
    using field_meta_t = std::tuple_element_t<0, typename hpp::proto::util::meta_of<T>::type>;
    return field_meta_t::number;
  }

  template <typename Traits>
  status get_from(const Extendee<Traits> &extendee, concepts::is_option_type auto &&...option) {
    auto &fields = pb_serializer::get_unknown_fields(extendee);
    decltype(fields.begin()) itr;

    if constexpr (requires { fields.find(number()); }) {
      itr = fields.find(number());
    } else {
      itr = std::find_if(fields.begin(), fields.end(), [](const auto &item) { return item.first == number(); });
    }

    if (itr != fields.end()) {
      return read_binpb(*static_cast<T *>(this), itr->second, std::forward<decltype(option)>(option)...);
    }

    return {};
  }

  template <typename Traits>
  status set_to(Extendee<Traits> &extendee, concepts::is_option_type auto &&...option) const {
    auto &fields = pb_serializer::get_unknown_fields(extendee);
    using fields_type = std::decay_t<decltype(fields)>;
    using bytes_type = typename fields_type::value_type::second_type;
    bytes_type data;

    pb_context ctx{std::forward<decltype(option)>(option)...};
    if (auto result = write_binpb(*static_cast<const T *>(this), data, ctx); !result.ok()) [[unlikely]] {
      return result;
    }

    if (data.size()) {
      if constexpr (concepts::associative_container<fields_type>) {
        fields[number()] = std::move(data);
      } else {
        detail::as_modifiable(ctx, fields).emplace_back(number(), data);
      }
    }
    return {};
  }

  template <typename Traits>
  static bool in(const Extendee<Traits> &extendee) {
    auto &fields = pb_serializer::get_unknown_fields(extendee);
    if constexpr (requires { fields.count(number()); }) {
      return fields.count(number()) > 0;
    } else {
      return std::find_if(fields.begin(), fields.end(), [](const auto &item) { return item.first == number(); }) !=
             fields.end();
    }
  }
};

status pack_any(concepts::is_any auto &any, concepts::has_meta auto const &msg) {
  any.type_url = message_type_url(msg);
  return write_binpb(msg, any.value);
}

status pack_any(concepts::is_any auto &any, concepts::has_meta auto const &msg,
                concepts::is_option_type auto &&...option) {
  any.type_url = message_type_url(msg);
  auto ctx = pb_context{std::forward<decltype(option)>(option)...};
  decltype(auto) v = detail::as_modifiable(ctx, any.value);
  return write_binpb(msg, v);
}

status unpack_any(concepts::is_any auto const &any, concepts::has_meta auto &msg,
                  concepts::is_option_type auto &&...option) {
  if (std::string_view{any.type_url}.ends_with(message_name(msg))) {
    return read_binpb(msg, any.value, std::forward<decltype(option)>(option)...);
  }
  return std::errc::invalid_argument;
}

template <concepts::has_meta T>
expected<T, std::errc> unpack_any(concepts::is_any auto const &any, concepts::is_option_type auto &&...option) {
  T msg;
  if (auto result = unpack_any(any, msg, std::forward<decltype(option)>(option)...); !result.ok()) {
    return unexpected(result.ec);
  } else {
    return msg;
  }
}

} // namespace hpp::proto
