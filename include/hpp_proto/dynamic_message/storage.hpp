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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <variant>

namespace hpp::proto {
template <typename T>
struct scalar_storage_base {
  T content;
  alignas(8) uint32_t size; // only used for string and bytes
  uint32_t selection; // 0 means no value; otherwise it means the selection index in oneof or 1 for non-oneof fields
};

template <typename T>
struct repeated_storage_base {
  T *content;
  alignas(8) uint32_t capacity;
  uint32_t size;
};

using bytes_storage_t = scalar_storage_base<const std::byte *>;
using string_storage_t = scalar_storage_base<const char *>;

union value_storage {
  scalar_storage_base<int64_t> of_int64;
  scalar_storage_base<uint64_t> of_uint64;
  scalar_storage_base<int32_t> of_int32;
  scalar_storage_base<uint32_t> of_uint32;
  scalar_storage_base<double> of_double;
  scalar_storage_base<float> of_float;
  scalar_storage_base<bool> of_bool;
  scalar_storage_base<value_storage *> of_message; ///< used for message and group types
  bytes_storage_t of_bytes;
  string_storage_t of_string;
  repeated_storage_base<int64_t> of_repeated_int64;
  repeated_storage_base<uint64_t> of_repeated_uint64;
  repeated_storage_base<int32_t> of_repeated_int32;
  repeated_storage_base<uint32_t> of_repeated_uint32;
  repeated_storage_base<double> of_repeated_double;
  repeated_storage_base<float> of_repeated_float;
  repeated_storage_base<bool> of_repeated_bool;
  repeated_storage_base<bytes_view> of_repeated_bytes;
  repeated_storage_base<std::string_view> of_repeated_string;
  repeated_storage_base<value_storage> of_repeated_message;

  value_storage() : of_int64{0ULL, 0U, 0U} {}

  [[nodiscard]] bool has_value() const noexcept {
    // This implementation relies on a layout hack where the 'selection' field of
    // scalar types and the 'size' field of repeated types are at the same
    // memory offset. Reading from an inactive union member (e.g. of_int32.selection)
    // when another member is active is a strict aliasing violation and thus
    // undefined behavior.
    // We use std::memcpy to safely access the bytes at the given offset, which
    // is a standard-compliant way to perform this type of type-punning.
    // Compilers will optimize this memcpy to a single efficient instruction.
    static_assert(offsetof(scalar_storage_base<bool>, selection) == offsetof(repeated_storage_base<bool>, size));
    uint32_t value = 0;
    std::memcpy(&value, &this->of_repeated_int64.size, sizeof(value));
    return value != 0;
  }
  void reset() noexcept {
    // Similar to has_value(), we use memcpy to avoid undefined behavior when
    // writing to an inactive union member.
    static_assert(offsetof(scalar_storage_base<bool>, selection) == offsetof(repeated_storage_base<bool>, size));
    uint32_t zero = 0;
    std::memcpy(&this->of_repeated_int64.size, &zero, sizeof(zero));
  }
};
} // namespace hpp::proto
