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
concept dynamic_sized_view = std::derived_from<T, std::span<typename T::element_type>> ||
                             std::same_as<T, hpp::proto::equality_comparable_span<typename T::element_type>> ||
                             std::same_as<T, std::string_view>;

template <typename T>
concept byte_serializable =
    std::is_arithmetic_v<T> || std::same_as<hpp::proto::boolean, T> || std::same_as<std::byte, T>;
} // namespace concepts

template <concepts::memory_resource T>
class alloc_from {
  T *mr;

public:
  using option_type = alloc_from<T>;
  explicit alloc_from(T &m) : mr(&m) {}
  ~alloc_from() = default;
  alloc_from(const alloc_from &other) = default;
  alloc_from(alloc_from &&other) = default;
  alloc_from &operator=(const alloc_from &) = default;
  alloc_from &operator=(alloc_from &&) = default;
  [[nodiscard]] T &memory_resource() const { return *mr; }
};

template <uint32_t n>
struct max_size_cache_on_stack_t {
  using option_type = max_size_cache_on_stack_t<n>;
  static constexpr auto max_size_cache_on_stack = n;
};

/// @brief max size in bytes which can be used for allocating size cache on stack
///
/// @details To accelerate Protobuf serialization, a size cache is utilized to store the serialized byte count of
/// variable-length fields before the fields’ content is serialized. If the total size of the size cache required is
/// less than or equal to max_size_cache_on_stack, the cache is allocated directly on the stack. Otherwise, it is
/// allocated on the heap.
template <uint32_t n = 1024>
constexpr auto max_size_cache_on_stack = max_size_cache_on_stack_t<n>{};

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

template <concepts::memory_resource T>
T &get_memory_resource(T &v) {
  return v;
}

template <concepts::has_memory_resource T>
auto &get_memory_resource(T &v) {
  return v.memory_resource();
}

namespace detail {
template <concepts::byte_serializable T, std::ranges::contiguous_range Range>
class bit_cast_view_t : public std::ranges::view_interface<bit_cast_view_t<T, Range>> {
  using base_value_type = std::ranges::range_value_t<Range>;
  using base_type = std::span<const base_value_type>;
  static constexpr auto chunk_size = sizeof(T);
  base_type base;

public:
  class iterator {
    const base_value_type *current;

  public:
    using iterator_category = std::input_iterator_tag;
    using difference_type = std::size_t;
    using value_type = T;
    using reference = value_type &;
    using pointer = value_type *;

    constexpr explicit iterator(const base_value_type *cur = nullptr) : current(cur) {}
    constexpr ~iterator() = default;
    constexpr iterator(const iterator &) = default;
    constexpr iterator(iterator &&) = default;
    constexpr iterator &operator=(const iterator &) = default;
    constexpr iterator &operator=(iterator &&) = default;
    constexpr bool operator==(const iterator &) const = default;

    constexpr iterator &operator++() {
      current += chunk_size; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      return *this;
    }
    constexpr void operator++(int) const { ++*this; }

    constexpr value_type operator*() const {
      std::array<base_value_type, chunk_size> v; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
      auto source = std::span{current, chunk_size};
      if (std::endian::little == std::endian::native) {
        std::ranges::copy(source, v.data());
      } else {
        std::ranges::reverse_copy(source, v.data());
      }
      return std::bit_cast<T>(v);
    }
  };
  constexpr explicit bit_cast_view_t(const Range &input_range) : base(input_range.data(), input_range.size()) {
    assert((input_range.size() % chunk_size) == 0);
  }

  [[nodiscard]] constexpr iterator begin() const { return iterator{base.data()}; }
  [[nodiscard]] constexpr iterator end() const {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return iterator{base.data() + base.size()};
  }
};

template <typename T, concepts::contiguous_byte_range Bytes>
auto bit_cast_view(const Bytes &input_range) {
  return bit_cast_view_t<T, Bytes>{input_range};
}

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
// NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
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

  constexpr arena_vector(View &view, MemoryResource &mr) : mr(mr), view_(view) {}
  constexpr arena_vector(View &view, concepts::has_memory_resource auto &ctx)
      : mr(ctx.memory_resource()), view_(view) {}
  constexpr ~arena_vector() = default;
  arena_vector(const arena_vector &) = delete;
  arena_vector(arena_vector &&) = delete;
  arena_vector &operator=(const arena_vector &) = delete;
  arena_vector &operator=(arena_vector &&) = delete;

  constexpr void resize(std::size_t n) {
    if (capacity_ < n) [[likely]] {
      auto new_data = static_cast<value_type *>(mr.allocate(n * sizeof(value_type), alignof(value_type)));
      if (view_.size() < n) [[likely]] {
        std::uninitialized_copy(view_.begin(), view_.end(), new_data);
        std::uninitialized_default_construct(new_data + view_.size(), new_data + n);
      } else {
        std::uninitialized_copy(view_.begin(), view_.begin() + static_cast<std::ptrdiff_t>(n), new_data);
      }
      data_ = new_data;
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
  constexpr reference emplace_back(Args &&...args) {
    std::size_t n = size();
    assign_range_with_size(view_, n + 1);
    std::construct_at(data_ + n, std::forward<Args>(args)...);
    return data_[size() - 1];
  }

  constexpr void clear() {
    view_ = View{};
    data_ = nullptr;
    capacity_ = 0;
  }

  template <std::ranges::sized_range R>
    requires std::same_as<value_type, std::ranges::range_value_t<R>>
  constexpr void assign_range(const R &r) {
    assign_range_with_size(r, std::ranges::size(r));
  }

  template <std::ranges::sized_range R>
  constexpr void append_range(const R &r) {
    auto old_size = view_.size();
    auto n = std::ranges::size(r);
    assign_range_with_size(view_, old_size + n);
    std::ranges::uninitialized_copy(r, std::span{data_ + old_size, n});
  }

  template <typename Iterator>
  constexpr void append_range(Iterator first, Iterator last) {
    auto old_size = view_.size();
    auto n = std::distance(first, last);
    assign_range_with_size(view_, old_size + n);
    std::uninitialized_copy(first, last, std::span{data_ + old_size, n});
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

  constexpr void append_raw_data(concepts::contiguous_byte_range auto const &data) {
    auto old_size = view_.size();
    auto num_elements = data.size() / sizeof(value_type);
    assign_range_with_size(view_, old_size + num_elements);
    auto destination = std::span{data_ + old_size, num_elements};
    if (std::is_constant_evaluated() || (sizeof(value_type) > 1 && std::endian::little != std::endian::native)) {
      auto source_view = bit_cast_view<value_type>(data);
      std::uninitialized_copy(source_view.begin(), source_view.end(), destination.begin());
    } else {
      std::memcpy(destination.data(), data.data(), data.size());
    }
  }

private:
  MemoryResource &mr;
  View &view_;
  value_type *data_ = nullptr;
  std::size_t capacity_ = 0;

  constexpr void assign_range_with_size(std::ranges::sized_range auto const &r, std::size_t n) {
    if (capacity_ < n) {
      auto new_data = static_cast<value_type *>(mr.allocate(n * sizeof(value_type), alignof(value_type)));
      std::ranges::uninitialized_copy(r, std::span{new_data, n});
      data_ = new_data;
      capacity_ = n;
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

constexpr auto as_modifiable(concepts::is_pb_context auto &context, concepts::dynamic_sized_view auto &view) {
  return detail::arena_vector{view, context};
}
template <typename T>
  requires(!concepts::dynamic_sized_view<T>)
constexpr auto as_modifiable(const auto & /* unused */, T &&view) -> decltype(std::forward<T>(view)) {
  return std::forward<T>(view);
}

} // namespace detail
} // namespace hpp::proto
