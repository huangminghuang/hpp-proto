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

#include <cassert>

#include <hpp_proto/dynamic_message/enum_fields.hpp>
#include <hpp_proto/dynamic_message/field_refs.hpp>
#include <hpp_proto/dynamic_message/message_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_enum_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_message_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_scalar_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_string_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_bytes_fields.hpp>
#include <hpp_proto/dynamic_message/scalar_fields.hpp>
#include <hpp_proto/dynamic_message/string_fields.hpp>
#include <hpp_proto/dynamic_message/bytes_fields.hpp>
#include <hpp_proto/dynamic_message/types.hpp>
#include <hpp_proto/pb_serializer.hpp>

namespace hpp::proto {
using enum field_kind_t;

inline auto field_cref::visit(auto &&visitor) const {
  switch (field_kind()) {
  case KIND_DOUBLE:
    return visitor(double_field_cref{*descriptor_, *storage_});
  case KIND_FLOAT:
    return visitor(float_field_cref{*descriptor_, *storage_});
  case KIND_INT64:
    return visitor(int64_field_cref{*descriptor_, *storage_});
  case KIND_UINT64:
    return visitor(uint64_field_cref{*descriptor_, *storage_});
  case KIND_INT32:
    return visitor(int32_field_cref{*descriptor_, *storage_});
  case KIND_FIXED64:
    return visitor(fixed64_field_cref{*descriptor_, *storage_});
  case KIND_FIXED32:
    return visitor(fixed32_field_cref{*descriptor_, *storage_});
  case KIND_BOOL:
    return visitor(bool_field_cref{*descriptor_, *storage_});
  case KIND_STRING:
    return visitor(string_field_cref{*descriptor_, *storage_});
  case KIND_MESSAGE:
    return visitor(message_field_cref{*descriptor_, *storage_});
  case KIND_BYTES:
    return visitor(bytes_field_cref{*descriptor_, *storage_});
  case KIND_UINT32:
    return visitor(uint32_field_cref{*descriptor_, *storage_});
  case KIND_ENUM:
    return visitor(enum_field_cref{*descriptor_, *storage_});
  case KIND_SFIXED32:
    return visitor(sfixed32_field_cref{*descriptor_, *storage_});
  case KIND_SFIXED64:
    return visitor(sfixed64_field_cref{*descriptor_, *storage_});
  case KIND_SINT32:
    return visitor(sint32_field_cref{*descriptor_, *storage_});
  case KIND_SINT64:
    return visitor(sint64_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_DOUBLE:
    return visitor(repeated_double_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_FLOAT:
    return visitor(repeated_float_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_INT64:
    return visitor(repeated_int64_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_UINT64:
    return visitor(repeated_uint64_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_INT32:
    return visitor(repeated_int32_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_FIXED64:
    return visitor(repeated_fixed64_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_FIXED32:
    return visitor(repeated_fixed32_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_BOOL:
    return visitor(repeated_bool_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_STRING:
    return visitor(repeated_string_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_MESSAGE:
    return visitor(repeated_message_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_BYTES:
    return visitor(repeated_bytes_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_UINT32:
    return visitor(repeated_uint32_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_ENUM:
    return visitor(repeated_enum_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_SFIXED32:
    return visitor(repeated_sfixed32_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_SFIXED64:
    return visitor(repeated_sfixed64_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_SINT32:
    return visitor(repeated_sint32_field_cref{*descriptor_, *storage_});
  case KIND_REPEATED_SINT64:
    return visitor(repeated_sint64_field_cref{*descriptor_, *storage_});
  }
  unreachable();
}

inline auto field_mref::visit(auto &&visitor) const {
  switch (field_kind()) {
  case KIND_DOUBLE:
    return visitor(double_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_FLOAT:
    return visitor(float_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_INT64:
    return visitor(int64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_UINT64:
    return visitor(uint64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_INT32:
    return visitor(int32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_FIXED64:
    return visitor(fixed64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_FIXED32:
    return visitor(fixed32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_BOOL:
    return visitor(bool_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_STRING:
    return visitor(string_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_MESSAGE:
    return visitor(message_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_BYTES:
    return visitor(bytes_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_UINT32:
    return visitor(uint32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_ENUM:
    return visitor(enum_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_SFIXED32:
    return visitor(sfixed32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_SFIXED64:
    return visitor(sfixed64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_SINT32:
    return visitor(sint32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_SINT64:
    return visitor(sint64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_DOUBLE:
    return visitor(repeated_double_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_FLOAT:
    return visitor(repeated_float_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_INT64:
    return visitor(repeated_int64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_UINT64:
    return visitor(repeated_uint64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_INT32:
    return visitor(repeated_int32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_FIXED64:
    return visitor(repeated_fixed64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_FIXED32:
    return visitor(repeated_fixed32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_BOOL:
    return visitor(repeated_bool_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_STRING:
    return visitor(repeated_string_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_BYTES:
    return visitor(repeated_bytes_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_UINT32:
    return visitor(repeated_uint32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_ENUM:
    return visitor(repeated_enum_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_MESSAGE:
    return visitor(repeated_message_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_SFIXED32:
    return visitor(repeated_sfixed32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_SFIXED64:
    return visitor(repeated_sfixed64_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_SINT32:
    return visitor(repeated_sint32_field_mref{*descriptor_, *storage_, *memory_resource_});
  case KIND_REPEATED_SINT64:
    return visitor(repeated_sint64_field_mref{*descriptor_, *storage_, *memory_resource_});
  }
  unreachable();
}

inline void field_mref::clone_from(const field_cref &other) const noexcept {
  assert(this->descriptor_ == &other.descriptor());
  this->visit([&](const auto &specific_mref) {
    using cref_type = typename std::decay_t<decltype(specific_mref)>::cref_type;
    specific_mref.clone_from(cref_type{*descriptor_, *other.storage_});
  });
}

inline void field_mref::set_null() noexcept {
  const auto *msg_descriptor = descriptor().message_field_type_descriptor();
  if (msg_descriptor != nullptr && msg_descriptor->wellknown == wellknown_types_t::VALUE) {
    auto msg = message_field_mref{*descriptor_, *storage_, *memory_resource_}.emplace();
    (void)msg.fields()[0].set(enum_number(0)).has_value();
  } else {
    reset();
  }
}

} // namespace hpp::proto
