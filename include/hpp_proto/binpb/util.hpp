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
#include <numeric>

namespace hpp::proto::util {

template <typename Range, typename UnaryOperation>
constexpr uint32_t transform_accumulate(const Range &range, const UnaryOperation &unary_op) {
  // **DO NOT** use std::transform_reduce() because it would apply unary_op in **unspecified** order
  auto total =
      std::accumulate(range.begin(), range.end(), std::size_t{0},
                      [&unary_op](std::size_t acc, const auto &elem) constexpr { return acc + unary_op(elem); });
  return static_cast<uint32_t>(total);
}

template <typename T, typename Range>
void append_range(T &v, const Range &range) {
  if constexpr (requires { v.append_range(range); }) {
    v.append_range(range);
  } else {
    v.insert(v.end(), range.begin(), range.end());
  }
}

} // namespace hpp::proto::util
