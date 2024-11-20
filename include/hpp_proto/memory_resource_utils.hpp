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

#include <concepts>
#include <hpp_proto/field_types.hpp>
#include <memory_resource>
#include <ranges>
#include <span>
#include <string_view>

namespace hpp::proto {
// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables)
namespace concepts {
template <typename T>
concept memory_resource = !std::copyable<T> && std::destructible<T> && requires(T &object) {
  { object.allocate(8, 8) } -> std::same_as<void *>;
};

template <typename T>
concept has_memory_resource =
    requires(T &object) { requires memory_resource<std::remove_cvref_t<decltype(object.memory_resource())>>; };

template <typename T>
concept resizable = requires {
  std::declval<T &>().resize(1);
  std::declval<T>()[0];
};

template <typename T>
concept not_resizable = !resizable<T>;

template <typename T>
concept contiguous_byte_range = byte_type<typename std::ranges::range_value_t<T>> && std::ranges::contiguous_range<T>;

template <typename T>
concept contiguous_output_byte_range =
    contiguous_byte_range<T> && std::ranges::output_range<T, typename std::ranges::range_value_t<T>>;

template <typename T>
concept resizable_contiguous_byte_container = contiguous_byte_range<T> && resizable<T>;

template <typename T>
concept is_pb_context = requires { typename std::decay_t<T>::is_pb_context; };

template <typename T>
concept is_option_type = requires { typename std::decay_t<T>::option_type; };

template <typename T>
concept dynamic_sized_view =
    std::derived_from<T, std::span<typename T::element_type>> || std::same_as<T, std::string_view>;

template <typename T>
concept strict_allocation_context = is_pb_context<T> && requires { requires T::always_allocate; };
} // namespace concepts
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)
template <concepts::memory_resource T, bool Strict = false>
class alloc_from {
  T *mr;

public:
  using option_type = alloc_from<T>;
  constexpr static auto always_allocate = Strict;
  explicit alloc_from(T &m) : mr(&m) {} // NOLINT(hicpp-member-init)
  ~alloc_from() = default;
  alloc_from(const alloc_from &other) = default;
  alloc_from(alloc_from &&other) = default;
  alloc_from &operator=(const alloc_from &) = default;
  alloc_from &operator=(alloc_from &&) = default;
  [[nodiscard]] T &memory_resource() const { return *mr; }
};

// Always allocate memory for string and bytes fields when
// deserializing non-owning messages.
template <concepts::memory_resource T>
class strictly_alloc_from : public alloc_from<T, true> {
public:
  using option_type = strictly_alloc_from<T>;
  explicit strictly_alloc_from(T &m) : alloc_from<T, true>(m) {}
};

template <typename... T>
struct pb_context : T::option_type... {
  using is_pb_context = void;
  template <typename... U>
  constexpr explicit pb_context(U &&...ctx) : T::option_type(std::forward<U>(ctx))... {}

  template <concepts::is_option_type U>
  [[nodiscard]] constexpr auto &get() const {
    if constexpr (std::derived_from<pb_context, U>) {
      return static_cast<const U &>(*this);
    } else {
      return static_cast<const std::reference_wrapper<U> &>(*this).get();
    }
  }
};

template <typename... U>
pb_context(U &&...u) -> pb_context<std::remove_cvref_t<U>...>;

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables)
template <concepts::memory_resource T>
T &get_memory_resource(T &v) {
  return v;
}

template <concepts::has_memory_resource T>
auto &get_memory_resource(T &v) {
  return v.memory_resource();
}
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

namespace detail {

// NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
template <typename T, typename ByteT>
struct raw_data_iterator {
  const ByteT *base;

  using iterator_category = std::random_access_iterator_tag;
  using difference_type = std::size_t;
  using value_type = T;
  using reference = value_type &;
  using pointer = value_type *;

  // NOLINTBEGIN(bugprone-sizeof-expression)
  constexpr std::size_t operator-(raw_data_iterator other) const { return (this->base - other.base) / sizeof(T); }
  // NOLINTEND(bugprone-sizeof-expression)

  constexpr bool operator==(raw_data_iterator other) { return other.base == this->base; }
  constexpr bool operator!=(raw_data_iterator s) { return !(*this == s); }

  constexpr raw_data_iterator &operator++() {
    this->base += sizeof(T);
    return *this;
  }

  constexpr raw_data_iterator &operator+=(std::size_t n) {
    this->base += (n * sizeof(T));
    return *this;
  }

  constexpr raw_data_iterator &operator--() {
    this->base -= sizeof(T);
    return *this;
  }

  constexpr raw_data_iterator &operator-=(std::size_t n) {
    this->base -= (n * sizeof(T));
    return *this;
  }

  constexpr T operator*() const {
    // NOLINTBEGIN(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
    std::array<ByteT, sizeof(T)> v;
    if (std::endian::little == std::endian::native) {
      std::copy(base, base + sizeof(T), v.data());
    } else {
      std::reverse_copy(base, base + sizeof(T), v.data());
    }
    // NOLINTEND(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
    return std::bit_cast<T>(v);
  }
};

/// The `arena_vector` class adapts an existing hpp::proto::equality_comparable_span or std::string_view, allowing the
/// underlying memory to be allocated from a designated memory resource. This memory resource releases the allocated
/// memory only upon its destruction, similar to std::pmr::monotonic_buffer_resource.
///
/// `arena_vector` will never deallocate its underlying memory in any circumstance; that is, `resize()` and
/// `push_back()`
///  will always allocate new memory blocks from the associate memory resource without calling `deallocate()`.
///
/// @tparam View
/// @tparam MemoryResource

template <concepts::dynamic_sized_view View, concepts::memory_resource MemoryResource>
class arena_vector {
public:
  using value_type = typename View::value_type;
  using reference = value_type &;
  using const_reference = const value_type &;
  using pointer = value_type *;
  using const_pointer = const value_type *;
  using difference_type = std::size_t;
  using iterator = pointer;
  using const_iterator = const iterator;

  static_assert(std::is_trivially_destructible_v<value_type>);

  constexpr MemoryResource &memory_resource() { return mr; }

  // NOLINTBEGIN(bugprone-easily-swappable-parameters)
  constexpr arena_vector(View &view, MemoryResource &mr) : mr(mr), view_(view) {}
  constexpr arena_vector(View &view, concepts::has_memory_resource auto &ctx)
      : mr(ctx.memory_resource()), view_(view) {}
  // NOLINTEND(bugprone-easily-swappable-parameters)

  constexpr void resize(std::size_t n) {
    if (capacity_ < n) {
      data_ = static_cast<value_type *>(mr.allocate(n * sizeof(value_type), alignof(value_type)));
      assert(data_ != nullptr);
      std::uninitialized_copy(view_.begin(), view_.end(), data_);
      std::uninitialized_default_construct(data_ + view_.size(), data_ + n);
      capacity_ = n;
    } else if (n > view_.size()) {
      std::uninitialized_default_construct(data_ + view_.size(), data_ + n);
    }
    view_ = View(data_, n);
  }

  constexpr arena_vector &operator=(const std::ranges::sized_range auto &r) {
    assign_range(std::forward<decltype(r)>(r));
    return *this;
  }

  [[nodiscard]] constexpr value_type *data() const { return data_; }
  constexpr reference operator[](std::size_t n) { return data_[n]; }
  [[nodiscard]] constexpr std::size_t size() const { return view_.size(); }
  [[nodiscard]] constexpr value_type *begin() const { return data_; }
  [[nodiscard]] constexpr value_type *end() const { return data_ + size(); }

  constexpr reference front() { return data_[0]; }
  constexpr reference back() { return data_[size() - 1]; }

  constexpr void push_back(const value_type &v) { emplace_back(v); }

  template <class... Args>
  // NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
  constexpr reference emplace_back(Args &&...args) {
    std::size_t n = size(); // NOLINT(cppcoreguidelines-init-variables)
    assign_range_with_size(view_, n + 1);
    std::construct_at(data_ + n, std::forward<Args>(args)...);
    return data_[size() - 1];
  }

  constexpr void clear() {
    view_ = View{};
    data_ = nullptr;
    capacity_ = 0;
  }

  constexpr void assign_range(const View &r) { assign_range_with_size(r, std::ranges::size(r)); }

  constexpr void append_range(const View &r) {
    auto old_size = view_.size();
    auto n = std::ranges::size(r);
    assign_range_with_size(view_, old_size + n);
    std::ranges::uninitialized_copy(r, std::span{data_ + old_size, n});
  }

  constexpr void reserve(std::size_t n) {
    if (capacity_ < n) {
      auto new_data = static_cast<value_type *>(mr.allocate(n * sizeof(value_type), alignof(value_type)));
      std::ranges::uninitialized_copy(view_, std::span{new_data, n});
      data_ = new_data;
      capacity_ = n;
      view_ = View{data_, view_.size()};
    }
  }

  template <typename ByteT>
  constexpr void append_raw_data(const ByteT *start_pos, std::size_t num_elements) {
    auto old_size = view_.size();
    std::size_t n = old_size + num_elements;
    assign_range_with_size(view_, n);
    // NOLINTNEXTLINE(bugprone-branch-clone)
    if (std::is_constant_evaluated() || (sizeof(value_type) > 1 && std::endian::little != std::endian::native)) {
      using input_it = raw_data_iterator<value_type, ByteT>;
      std::uninitialized_copy(input_it{start_pos}, input_it{start_pos + (num_elements * sizeof(value_type))},
                              data_ + old_size);
    } else {
      std::memcpy(data_ + old_size, start_pos, num_elements * sizeof(value_type));
    }
  }

private:
  // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
  MemoryResource &mr;
  View &view_;
  // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
  value_type *data_ = nullptr;
  std::size_t capacity_ = 0;

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  constexpr void assign_range_with_size(const View &r, std::size_t n) {
    if (capacity_ < n) {
      auto new_data = static_cast<value_type *>(mr.allocate(n * sizeof(value_type), alignof(value_type)));
      std::ranges::uninitialized_copy(r, std::span{new_data, n});
      data_ = new_data;
    } else if (view_.data() != r.data()) {
      std::ranges::copy(r, data_);
    }

    view_ = View{data_, n};
  }
};
// NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

template <concepts::dynamic_sized_view View, concepts::has_memory_resource Context>
arena_vector(View &view, Context &ctx)
    -> arena_vector<View, std::remove_reference_t<decltype(std::declval<Context>().memory_resource())>>;

constexpr auto as_modifiable(concepts::is_pb_context auto &&context, concepts::dynamic_sized_view auto &view) {
  return detail::arena_vector{view, std::forward<decltype(context)>(context)};
}

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables)
template <typename T>
  requires(!concepts::dynamic_sized_view<T>)
constexpr T &as_modifiable(const auto & /* unused */, T &view) {
  return view;
}
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

} // namespace detail
} // namespace hpp::proto
