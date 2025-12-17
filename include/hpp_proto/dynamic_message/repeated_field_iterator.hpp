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
#include <compare>
#include <cstddef>
#include <iterator>

namespace hpp::proto {

template <typename Field>
class repeated_field_iterator {
  const Field *field_ = nullptr;
  std::size_t index_ = 0;

public:
  using iterator_category = std::random_access_iterator_tag;
  using value_type = typename Field::reference;
  using difference_type = std::ptrdiff_t;
  using reference = typename Field::reference;
  using pointer = void;
  repeated_field_iterator() = default;
  repeated_field_iterator(const Field *field, std::size_t index) noexcept : field_(field), index_(index) {}
  repeated_field_iterator(const repeated_field_iterator &) noexcept = default;
  repeated_field_iterator(repeated_field_iterator &&) noexcept = default;
  repeated_field_iterator &operator=(const repeated_field_iterator &) noexcept = default;
  repeated_field_iterator &operator=(repeated_field_iterator &&) noexcept = default;
  ~repeated_field_iterator() noexcept = default;
  repeated_field_iterator &operator++() noexcept {
    ++index_;
    return *this;
  }
  repeated_field_iterator operator++(int) noexcept {
    repeated_field_iterator tmp = *this;
    ++(*this);
    return tmp;
  }
  repeated_field_iterator &operator--() noexcept {
    --index_;
    return *this;
  }
  repeated_field_iterator operator--(int) noexcept {
    repeated_field_iterator tmp = *this;
    --(*this);
    return tmp;
  }
  repeated_field_iterator &operator+=(std::ptrdiff_t n) noexcept {
    index_ = static_cast<std::size_t>(static_cast<std::ptrdiff_t>(index_) + n);
    return *this;
  }
  repeated_field_iterator &operator-=(std::ptrdiff_t n) noexcept {
    index_ = static_cast<std::size_t>(static_cast<std::ptrdiff_t>(index_) - n);
    return *this;
  }
  repeated_field_iterator operator+(std::ptrdiff_t n) const noexcept {
    repeated_field_iterator tmp = *this;
    tmp += n;
    return tmp;
  }
  repeated_field_iterator operator-(std::ptrdiff_t n) const noexcept {
    repeated_field_iterator tmp = *this;
    tmp -= n;
    return tmp;
  }

  std::ptrdiff_t operator-(const repeated_field_iterator &other) const noexcept {
    return static_cast<std::ptrdiff_t>(index_) - static_cast<std::ptrdiff_t>(other.index_);
  }

  friend repeated_field_iterator operator+(std::ptrdiff_t n, const repeated_field_iterator &rhs) noexcept {
    return rhs + n;
  }

  std::strong_ordering operator<=>(const repeated_field_iterator &other) const noexcept {
    assert(field_ == other.field_);
    return index_ <=> other.index_;
  }

  bool operator==(const repeated_field_iterator &other) const noexcept {
    assert(field_ == other.field_);
    return index_ == other.index_;
  }

  reference operator*() const noexcept { return (*field_)[index_]; }
  reference operator[](std::ptrdiff_t n) const noexcept { return *(*this + n); }
};

} // namespace hpp::proto

