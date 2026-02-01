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
template <auto Mode>
struct serialization_option_t {
  using option_type = serialization_option_t<Mode>;
  static constexpr auto serialization_mode = Mode;
};

/// @brief Serialization option to enforce contiguous buffer usage.
///
/// @details This mode assumes or requires that the serialization happens into a single
/// contiguous memory block.
/// This option only affects out_sink-based write_binpb() APIs. Buffer-based serialization
/// always uses contiguous output and ignores these mode options.
///
/// **Pros:**
/// - **Highest Performance:** Eliminates bound checking overhead for individual fields
///   during serialization, as space is validated or allocated upfront.
///
/// **Cons:**
/// - **High Memory Requirement:** Requires a single contiguous buffer large enough to
///   hold the entire serialized message.
/// - **Potential Allocation Failure:** For very large messages, allocating a single
///   large buffer might fail or trigger expensive reallocations.
constexpr auto contiguous_mode = serialization_option_t<serialization_mode::contiguous>{};

/// @brief Serialization option for adaptive behavior (Speed Optimized).
///
/// @details This is the default mode. It attempts to determine the most efficient
/// strategy based on the message size and available buffer space.
/// This option only affects out_sink-based write_binpb() APIs. Buffer-based serialization
/// always uses contiguous output and ignores these mode options.
///
/// **Pros:**
/// - **Balanced Performance:** Uses the fast contiguous path if the message fits within
///   the current chunk or buffer, avoiding per-field bound checks.
/// - **Safety:** Automatically falls back to chunked serialization if the message exceeds
///   the contiguous space, ensuring data integrity without manual intervention.
///
/// **Cons:**
/// - **Slight Overhead:** Involves a minimal overhead to calculate sizes and check
///   buffer capacity before deciding on the strategy.
/// - **Higher Object Code Size:** Includes both contiguous and chunked serialization
///   paths, which can increase compiled code size compared to fixed-mode builds.
constexpr auto adaptive_mode = serialization_option_t<serialization_mode::adaptive>{};

/// @brief Serialization option to enforce chunked serialization (Size/Memory Optimized).
///
/// @details This mode forces the serializer to write data in chunks, using bound checking
/// for every write operation.
/// This option only affects out_sink-based write_binpb() APIs. Buffer-based serialization
/// always uses contiguous output and ignores these mode options.
///
/// **Pros:**
/// - **Low Memory Footprint:** Minimizes peak memory usage by streaming data into
///   smaller chunks, ideal for memory-constrained environments.
/// - **Handles Large Messages:** Can serialize messages that are larger than any single
///   available contiguous memory block.
///
/// **Cons:**
/// - **Lower Performance:** The constant bound checking and state management for chunks
///   incur a CPU performance penalty compared to contiguous serialization.
constexpr auto chunked_mode = serialization_option_t<serialization_mode::chunked>{};

template <uint32_t N>
struct recursion_limit_t {
  using option_type = recursion_limit_t<N>;
  static constexpr uint32_t max_recursion_depth = N;
};

template <uint32_t N>
constexpr auto recursion_limit = recursion_limit_t<N>{};

/// @brief Consteval function to serialize a message at compile-time.
/// @tparam F A callable that returns a message object.
/// @param make_object A function that constructs the message to be serialized.
/// @return A std::array or std::span containing the serialized binary data.
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

/// @brief Serializes a message into a provided buffer using a given context.
/// @tparam T Type of the message, must satisfy concepts::has_meta.
/// @tparam Buffer A contiguous byte range.
/// @param msg The message to serialize.
/// @param buffer The buffer to write the serialized data into.
/// @param ctx The protobuf serialization context.
/// @return status indicating success or failure.
template <concepts::has_meta T, concepts::contiguous_byte_range Buffer>
status write_binpb(T &&msg, Buffer &buffer, concepts::is_pb_context auto &ctx) {
  decltype(auto) v = detail::as_modifiable(ctx, buffer);
  return pb_serializer::serialize(std::forward<T>(msg), v, ctx);
}

/// @brief Serializes a message into a provided sink using a given context.
/// @tparam T Type of the message, must satisfy concepts::has_meta.
/// @tparam Sink A chunked output sink.
/// @param msg The message to serialize.
/// @param sink The sink to write the serialized data into.
/// @param ctx The protobuf serialization context.
/// @return status indicating success or failure.
template <concepts::has_meta T, concepts::out_sink Sink>
status write_binpb(T &&msg, Sink &sink, concepts::is_pb_context auto &ctx) {
  return pb_serializer::serialize(std::forward<T>(msg), sink, ctx);
}

/// @brief Serializes a message into a provided buffer with optional configuration.
/// @tparam T Type of the message, must satisfy concepts::has_meta.
/// @tparam Buffer A contiguous byte range.
/// @param msg The message to serialize.
/// @param buffer The buffer to write the serialized data into.
/// @param option Optional configuration parameters (e.g., alloc_from, max_size_cache_on_stack).
/// @return status indicating success or failure.
template <concepts::has_meta T, concepts::contiguous_byte_range Buffer>
status write_binpb(T &&msg, Buffer &buffer, concepts::is_option_type auto &&...option) {
  pb_context ctx{std::forward<decltype(option)>(option)...};
  return write_binpb(std::forward<T>(msg), buffer, ctx);
}

/// @brief Serializes a message into a provided sink with optional configuration.
/// @tparam T Type of the message, must satisfy concepts::has_meta.
/// @tparam Sink A chunked output sink.
/// @param msg The message to serialize.
/// @param sink The sink to write the serialized data into.
/// @param option Optional configuration parameters (e.g., max_size_cache_on_stack).
/// @return status indicating success or failure.
template <concepts::has_meta T, concepts::out_sink Sink>
status write_binpb(T &&msg, Sink &sink, concepts::is_option_type auto &&...option) {
  pb_context ctx{std::forward<decltype(option)>(option)...};
  return write_binpb(std::forward<T>(msg), sink, ctx);
}
/// @brief Serializes a message and returns the resulting buffer.
/// @tparam Buffer The container type for the serialized data, defaults to std::vector<std::byte>.
/// @param msg The message to serialize.
/// @param option Optional configuration parameters.
/// @return A std::expected containing the buffer on success, or an error code on failure.
template <concepts::contiguous_byte_range Buffer = std::vector<std::byte>>
expected<Buffer, std::errc> write_binpb(concepts::has_meta auto const &msg, concepts::is_option_type auto &&...option) {
  expected<Buffer, std::errc> result;
  if (auto status = write_binpb(msg, *result, std::forward<decltype(option)>(option)...); !status.ok()) [[unlikely]] {
    result = unexpected(status.ec);
  }
  return result;
}

/// @brief serialize a message to the end of the supplied buffer
template <concepts::has_meta T>
status append_binpb(T &&msg, concepts::resizable_contiguous_byte_container auto &buffer) {
  constexpr bool overwrite_buffer = false;
  pb_context<> ctx;
  return pb_serializer::serialize<overwrite_buffer>(std::forward<T>(msg), buffer, ctx);
}

/// @brief Deserializes a message from a byte range and returns the message object.
/// @tparam T Type of the message to deserialize, must satisfy concepts::has_meta.
/// @param buffer The input byte range containing serialized data.
/// @param option Optional configuration parameters (e.g., alloc_from).
/// @details This API does not catch std::bad_alloc thrown by standard containers.
/// @return A std::expected containing the deserialized message on success, or an error code on failure.
template <concepts::has_meta T>
constexpr static expected<T, std::errc> read_binpb(concepts::input_byte_range auto const &buffer,
                                                   concepts::is_option_type auto &&...option) {
  expected<T, std::errc> result;
  pb_context ctx{std::forward<decltype(option)>(option)...};
  if (auto status = pb_serializer::deserialize(*result, buffer, ctx); !status.ok()) [[unlikely]] {
    result = unexpected(status.ec);
  }
  return result;
}

/// @brief Deserializes a message from a byte range into an existing message object using a context.
/// @tparam T Type of the message, must satisfy concepts::has_meta.
/// @tparam Buffer Input byte range type.
/// @param msg The message object to deserialize into.
/// @param buffer The input byte range.
/// @param ctx The protobuf serialization context.
/// @details This API does not catch std::bad_alloc thrown by standard containers.
/// @return status indicating success or failure.
template <concepts::has_meta T, concepts::input_byte_range Buffer>
status read_binpb(T &msg, const Buffer &buffer, concepts::is_pb_context auto &ctx) {
  msg = {};
  return pb_serializer::deserialize(msg, buffer, ctx);
}

/// @brief Deserializes a message from a character array (e.g., a string literal).
/// @tparam T Type of the message.
/// @tparam N Size of the character array.
/// @param buffer The character array.
/// @param option Optional configuration parameters.
/// @details This API does not catch std::bad_alloc thrown by standard containers.
/// @return A std::expected containing the deserialized message on success, or an error code on failure.
template <concepts::has_meta T, std::size_t N>
constexpr static expected<T, std::errc> read_binpb(const char (&buffer)[N], concepts::is_option_type auto &&...option) {
  constexpr auto span_size = N == 0 ? 0 : N - 1;
  auto span = std::span<const char>{buffer, span_size};
  return read_binpb<T>(span, std::forward<decltype(option)>(option)...);
}

/// @brief Deserializes a message from a character array into an existing message object.
/// @tparam T Type of the message.
/// @tparam N Size of the character array.
/// @param msg The message object to deserialize into.
/// @param buffer The character array.
/// @param option Optional configuration parameters.
/// @return status indicating success or failure.
template <concepts::has_meta T, std::size_t N>
status read_binpb(T &msg, const char (&buffer)[N], concepts::is_option_type auto &&...option) {
  constexpr auto span_size = N == 0 ? 0 : N - 1;
  auto span = std::span<const char>{buffer, span_size};
  return read_binpb(msg, span, std::forward<decltype(option)>(option)...);
}

/// @brief Deserializes a message from a byte range into an existing message object with optional configuration.
/// @tparam T Type of the message.
/// @tparam Buffer Input byte range type.
/// @param msg The message object to deserialize into.
/// @param buffer The input byte range.
/// @param option Optional configuration parameters.
/// @return status indicating success or failure.
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
  expected<T, std::errc> result;
  if (auto status = unpack_any(any, *result, std::forward<decltype(option)>(option)...); !status.ok()) [[unlikely]] {
    result = unexpected(status.ec);
  }
  return result;
}

} // namespace hpp::proto
