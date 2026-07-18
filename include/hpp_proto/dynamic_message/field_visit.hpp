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

#include <hpp_proto/binpb.hpp>
#include <hpp_proto/dynamic_message/bytes_fields.hpp>
#include <hpp_proto/dynamic_message/enum_fields.hpp>
#include <hpp_proto/dynamic_message/field_refs.hpp>
#include <hpp_proto/dynamic_message/message_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_bytes_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_enum_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_message_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_scalar_fields.hpp>
#include <hpp_proto/dynamic_message/repeated_string_fields.hpp>
#include <hpp_proto/dynamic_message/scalar_fields.hpp>
#include <hpp_proto/dynamic_message/string_fields.hpp>
#include <hpp_proto/dynamic_message/types.hpp>

namespace hpp_proto {
using enum field_kind_t;

namespace detail {
inline decltype(auto) visit_runtime_field(field_kind_t kind, auto &&visitor, auto &&make_ref) {
  switch (kind) {
  case KIND_DOUBLE:
    return visitor(make_ref.template operator()<double_field_cref, double_field_mref>());
  case KIND_FLOAT:
    return visitor(make_ref.template operator()<float_field_cref, float_field_mref>());
  case KIND_INT64:
    return visitor(make_ref.template operator()<int64_field_cref, int64_field_mref>());
  case KIND_UINT64:
    return visitor(make_ref.template operator()<uint64_field_cref, uint64_field_mref>());
  case KIND_INT32:
    return visitor(make_ref.template operator()<int32_field_cref, int32_field_mref>());
  case KIND_FIXED64:
    return visitor(make_ref.template operator()<fixed64_field_cref, fixed64_field_mref>());
  case KIND_FIXED32:
    return visitor(make_ref.template operator()<fixed32_field_cref, fixed32_field_mref>());
  case KIND_BOOL:
    return visitor(make_ref.template operator()<bool_field_cref, bool_field_mref>());
  case KIND_STRING:
    return visitor(make_ref.template operator()<string_field_cref, string_field_mref>());
  case KIND_MESSAGE:
    return visitor(make_ref.template operator()<message_field_cref, message_field_mref>());
  case KIND_BYTES:
    return visitor(make_ref.template operator()<bytes_field_cref, bytes_field_mref>());
  case KIND_UINT32:
    return visitor(make_ref.template operator()<uint32_field_cref, uint32_field_mref>());
  case KIND_ENUM:
    return visitor(make_ref.template operator()<enum_field_cref, enum_field_mref>());
  case KIND_SFIXED32:
    return visitor(make_ref.template operator()<sfixed32_field_cref, sfixed32_field_mref>());
  case KIND_SFIXED64:
    return visitor(make_ref.template operator()<sfixed64_field_cref, sfixed64_field_mref>());
  case KIND_SINT32:
    return visitor(make_ref.template operator()<sint32_field_cref, sint32_field_mref>());
  case KIND_SINT64:
    return visitor(make_ref.template operator()<sint64_field_cref, sint64_field_mref>());
  case KIND_REPEATED_DOUBLE:
    return visitor(make_ref.template operator()<repeated_double_field_cref, repeated_double_field_mref>());
  case KIND_REPEATED_FLOAT:
    return visitor(make_ref.template operator()<repeated_float_field_cref, repeated_float_field_mref>());
  case KIND_REPEATED_INT64:
    return visitor(make_ref.template operator()<repeated_int64_field_cref, repeated_int64_field_mref>());
  case KIND_REPEATED_UINT64:
    return visitor(make_ref.template operator()<repeated_uint64_field_cref, repeated_uint64_field_mref>());
  case KIND_REPEATED_INT32:
    return visitor(make_ref.template operator()<repeated_int32_field_cref, repeated_int32_field_mref>());
  case KIND_REPEATED_FIXED64:
    return visitor(make_ref.template operator()<repeated_fixed64_field_cref, repeated_fixed64_field_mref>());
  case KIND_REPEATED_FIXED32:
    return visitor(make_ref.template operator()<repeated_fixed32_field_cref, repeated_fixed32_field_mref>());
  case KIND_REPEATED_BOOL:
    return visitor(make_ref.template operator()<repeated_bool_field_cref, repeated_bool_field_mref>());
  case KIND_REPEATED_STRING:
    return visitor(make_ref.template operator()<repeated_string_field_cref, repeated_string_field_mref>());
  case KIND_REPEATED_MESSAGE:
    return visitor(make_ref.template operator()<repeated_message_field_cref, repeated_message_field_mref>());
  case KIND_REPEATED_BYTES:
    return visitor(make_ref.template operator()<repeated_bytes_field_cref, repeated_bytes_field_mref>());
  case KIND_REPEATED_UINT32:
    return visitor(make_ref.template operator()<repeated_uint32_field_cref, repeated_uint32_field_mref>());
  case KIND_REPEATED_ENUM:
    return visitor(make_ref.template operator()<repeated_enum_field_cref, repeated_enum_field_mref>());
  case KIND_REPEATED_SFIXED32:
    return visitor(make_ref.template operator()<repeated_sfixed32_field_cref, repeated_sfixed32_field_mref>());
  case KIND_REPEATED_SFIXED64:
    return visitor(make_ref.template operator()<repeated_sfixed64_field_cref, repeated_sfixed64_field_mref>());
  case KIND_REPEATED_SINT32:
    return visitor(make_ref.template operator()<repeated_sint32_field_cref, repeated_sint32_field_mref>());
  case KIND_REPEATED_SINT64:
    return visitor(make_ref.template operator()<repeated_sint64_field_cref, repeated_sint64_field_mref>());
  }
  std::unreachable();
}
} // namespace detail

inline auto field_cref::visit(auto &&visitor) const {
  auto make_ref = [this]<typename CRef, typename /*MRef*/> { return CRef{*descriptor_, *storage_}; };
  return detail::visit_runtime_field(field_kind(), visitor, make_ref);
}

inline auto field_mref::visit(auto &&visitor) const {
  auto make_ref = [this]<typename /*CRef*/, typename MRef> { return MRef{*descriptor_, *storage_, *memory_resource_}; };
  return detail::visit_runtime_field(field_kind(), visitor, make_ref);
}

inline void field_mref::clone_from(const field_cref &other) const {
  assert(this->descriptor_ == &other.descriptor());
  this->visit([&](const auto &specific_mref) {
    using cref_type = std::decay_t<decltype(specific_mref)>::cref_type;
    specific_mref.clone_from(cref_type{*descriptor_, *other.storage_});
  });
}

inline void field_mref::set_null() {
  const auto *msg_descriptor = descriptor().message_field_type_descriptor();
  if (msg_descriptor != nullptr && msg_descriptor->wellknown == wellknown_types_t::VALUE) {
    auto msg = message_field_mref{*descriptor_, *storage_, *memory_resource_}.emplace();
    (void)msg.fields()[0].set(enum_number(0)).has_value();
  } else {
    reset();
  }
}

} // namespace hpp_proto
