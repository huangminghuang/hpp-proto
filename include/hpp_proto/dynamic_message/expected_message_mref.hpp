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

#include <expected>
#include <string_view>
#include <utility>

#include <hpp_proto/dynamic_message/message_fields.hpp>
#include <hpp_proto/dynamic_message/types.hpp>

namespace hpp::proto {
namespace util {
// Extract first argument type from callables/functions.
template <typename T, typename = void>
struct callable_arg;

// function pointer
template <typename Ret, typename Arg>
struct callable_arg<Ret (*)(Arg), void> {
  using type = Arg;
};

// free function type
template <typename Ret, typename Arg>
struct callable_arg<Ret(Arg), void> {
  using type = Arg;
};

// member function pointer (non-const)
template <typename ClassType, typename Ret, typename Arg>
struct callable_arg<Ret (ClassType::*)(Arg), void> {
  using type = Arg;
};

// member function pointer (const)
template <typename ClassType, typename Ret, typename Arg>
struct callable_arg<Ret (ClassType::*)(Arg) const, void> {
  using type = Arg;
};

// functor/lambda fallback: peel off operator()
template <typename T>
struct callable_arg<T, std::void_t<decltype(&T::operator())>> {
  using type = typename callable_arg<decltype(&T::operator())>::type;
};

template <typename T>
using callable_arg_t = typename callable_arg<T>::type;

} // namespace util

/**
 * @brief Fluent wrapper around `message_value_mref` that carries `std::expected` and
 *        supports chainable mutations.
 *
 * Each mutator returns a new `expected_message_mref`; chaining stops on the first failure,
 * and `done()` produces `expected<void, dynamic_message_errc>` for easy combination.
 */
class expected_message_mref {
  std::expected<message_value_mref, dynamic_message_errc> obj_;

public:
  explicit expected_message_mref(std::expected<message_value_mref, dynamic_message_errc> &&o) : obj_(std::move(o)) {}
  explicit expected_message_mref(message_value_mref msg) : obj_(msg) {}

  template <typename T>
  [[nodiscard]] expected_message_mref set_field_by_name(std::string_view name, T &&v) const {
    return expected_message_mref{obj_.and_then([name, v = std::forward<T>(v)](message_value_mref msg) mutable {
      return msg.set_field_by_name(name, std::forward<T>(v));
    })};
  }

  template <typename T>
  [[nodiscard]] expected_message_mref set_field_by_number(std::uint32_t number, T &&v) const {
    return expected_message_mref{obj_.and_then([number, v = std::forward<T>(v)](message_value_mref msg) mutable {
      return msg.set_field_by_number(number, std::forward<T>(v));
    })};
  }

  template <typename Mutator>
  [[nodiscard]] expected_message_mref modify_field_by_name(std::string_view name, Mutator &&mutator) const {
    return expected_message_mref{
        obj_.and_then([name, mutator = std::forward<Mutator>(mutator)](message_value_mref o) mutable {
          return o.modify_field_by_name(name, std::forward<Mutator>(mutator));
        })};
  }

  template <typename Mutator>
  [[nodiscard]] expected_message_mref modify_field_by_number(std::uint32_t number, Mutator &&mutator) const {
    return expected_message_mref{
        obj_.and_then([number, mutator = std::forward<Mutator>(mutator)](message_value_mref o) mutable {
          return o.modify_field_by_number(number, std::forward<Mutator>(mutator));
        })};
  }

  [[nodiscard]] bool has_value() const noexcept { return obj_.has_value(); }
  [[nodiscard]] explicit operator bool() const noexcept { return static_cast<bool>(obj_); }
  [[nodiscard]] auto operator->() const noexcept { return obj_.operator->(); }
  [[nodiscard]] auto operator*() const noexcept { return *obj_; }
  [[nodiscard]] auto value() const noexcept { return obj_.value(); }
  [[nodiscard]] auto error() const noexcept { return obj_.error(); }

  [[nodiscard]] std::expected<void, dynamic_message_errc> done() const noexcept {
    return obj_.and_then([](auto) { return std::expected<void, dynamic_message_errc>{}; });
  }
};

inline expected_message_mref dynamic_message_factory::get_message(std::string_view name,
                                                                  std::pmr::monotonic_buffer_resource &mr) const {
  const auto *desc = pool_.get_message_descriptor(name);
  if (desc != nullptr) {
    return expected_message_mref{message_value_mref{*desc, mr}};
  }
  return expected_message_mref{std::unexpected(dynamic_message_errc::unknown_message_name)};
}

} // namespace hpp::proto
