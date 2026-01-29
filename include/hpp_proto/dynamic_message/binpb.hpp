/**
 * @file dynamic_message/binpb.hpp
 * @brief Runtime facilities for parsing, building, and serializing protobuf messages using descriptors only.
 *
 * The dynamic message layer exposes:
 * - descriptor-driven factories (`dynamic_message_factory`) to load FileDescriptorSets and produce mutable/const views.
 * - field and message reference types (`*_field_mref` / `*_field_cref`, `*_value_mref` / `*_value_cref`)
 *   that provide typed accessors, mutation helpers, and serialization hooks without generated code.
 *   * field_refs point at a specific field slot within a message (with presence/descriptor info); value_refs wrap the
 *     underlying value itself (e.g., messages, enums, strings) and can be used by field_refs to expose typed access.
 * - utilities and traits to support JSON/proto encoding, well-known types, and enum access patterns.
 *
 * This header is the main entry point when working with dynamic messages in hpp_proto.
 */
#pragma once
#include <cstddef>
#include <span>
#include <utility>

#include <hpp_proto/dynamic_message/expected_message_mref.hpp>
#include <hpp_proto/dynamic_message/field_visit.hpp>
#include <hpp_proto/dynamic_message/pb_serializer_ext.hpp>
namespace hpp::proto {

[[nodiscard]] status read_binpb(message_value_mref msg, auto &&buffer) {
  msg.reset();
  auto context = pb_context{alloc_from(msg.memory_resource())};
  return pb_serializer::deserialize(msg, std::forward<decltype(buffer)>(buffer), context);
}

template <std::size_t N>
[[nodiscard]] status read_binpb(message_value_mref msg, const char (&buffer)[N]) {
  constexpr auto span_size = N == 0 ? 0 : N - 1;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay,-warnings-as-errors)
  auto span = std::span<const char>{buffer, span_size};
  return read_binpb(msg, span);
}

[[nodiscard]] status write_binpb(const message_value_cref &msg, concepts::contiguous_byte_range auto &buffer,
                                 concepts::is_option_type auto &&...option) {
  pb_context ctx{std::forward<decltype(option)>(option)...};
  decltype(auto) v = detail::as_modifiable(ctx, buffer);
  return pb_serializer::serialize(msg, v, ctx);
}

[[nodiscard]] status write_binpb(const message_value_cref &msg, concepts::out_sink auto &sink,
                                 concepts::is_option_type auto &&...option) {
  pb_context ctx{std::forward<decltype(option)>(option)...};
  return pb_serializer::serialize(msg, sink, ctx);
}
} // namespace hpp::proto
