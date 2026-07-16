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

#include <cstdint>
#include <limits>

namespace hpp_proto {

inline constexpr std::uint32_t default_max_recursion_depth = 100;

/// Limit nested message recursion for binary protobuf and dynamic-message JSON operations.
/// The root message does not consume the recursion budget.
/// UINT32_MAX is reserved so the internal recursion counter cannot wrap.
template <std::uint32_t N>
struct recursion_limit_t {
  // Parentheses protect against Windows headers defining max as a function-like macro.
  // NOLINTNEXTLINE(readability-redundant-parentheses)
  static_assert(N < (std::numeric_limits<std::uint32_t>::max)(), "recursion limit must be less than UINT32_MAX");
  using option_type = recursion_limit_t<N>;
  static constexpr std::uint32_t max_recursion_depth = N;
};

template <std::uint32_t N>
constexpr auto recursion_limit = recursion_limit_t<N>{};

namespace detail {

struct runtime_recursion_limit {
  using option_type = runtime_recursion_limit;
  std::uint32_t max_recursion_depth;
};

/// Tracks one active recursive message/group scope. active_depth includes the root scope;
/// max_nested_depth controls how many additional scopes may be entered below it.
class recursion_scope {
  std::uint32_t *active_depth_ = nullptr;

public:
  explicit constexpr recursion_scope(std::uint32_t &active_depth, std::uint32_t max_nested_depth) noexcept {
    // Parentheses protect against Windows headers defining max as a function-like macro.
    // NOLINTNEXTLINE(readability-redundant-parentheses)
    if (active_depth <= max_nested_depth && active_depth != (std::numeric_limits<std::uint32_t>::max)()) [[likely]] {
      ++active_depth;
      active_depth_ = &active_depth;
    }
  }

  recursion_scope(const recursion_scope &) = delete;
  recursion_scope &operator=(const recursion_scope &) = delete;
  recursion_scope(recursion_scope &&) = delete;
  recursion_scope &operator=(recursion_scope &&) = delete;

  constexpr ~recursion_scope() {
    if (active_depth_ != nullptr) {
      --*active_depth_;
    }
  }

  [[nodiscard]] constexpr bool ok() const noexcept { return active_depth_ != nullptr; }
};

} // namespace detail
} // namespace hpp_proto
