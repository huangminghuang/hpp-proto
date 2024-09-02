#pragma once

#include <concepts>
#include <hpp_proto/field_types.hpp>
#include <memory_resource>
#include <ranges>
#include <span>
#include <string_view>

#if !defined(__cpp_lib_ranges)
namespace std {
namespace ranges {

template <typename T>
using range_value_t = std::iter_value_t<decltype(std::begin(std::declval<T &>()))>;

template <class T>
concept range = requires(T &t) {
  std::begin(t); // equality-preserving for forward iterators
  std::end(t);
};

template <typename T>
concept contiguous_range = requires(T &t) {
  {
    std::data(t)
  } -> std::same_as<std::add_pointer_t<std::iter_reference_t<decltype(std::begin(std::declval<T &>()))>>>;
  std::size(t);
};

template <class T>
concept input_range = std::ranges::range<T> && std::input_iterator<std::ranges::iterator_t<T>>;

template <class R, class T>
concept output_range = std::ranges::range<R> && std::output_iterator<std::ranges::iterator_t<R>, T>;

template <typename Range1, typename Range2>
constexpr bool equal(Range1 &&r1, Range2 &&r2) {
  return std::equal(std::begin(r1), std::end(r1), std::begin(r2), std::end(r2));
}

template <typename RG1, typename RG2, typename BinaryPredicate>
constexpr bool equal(RG1 &&r1, RG2 &&r2, BinaryPredicate p) {
  return std::equal(std::begin(r1), std::end(r1), std::begin(r2), std::end(r2), p);
}

} // namespace ranges
} // namespace std
#endif

#if !defined(__cpp_lib_ranges_contains)
// NOLINTBEGIN(cert-dcl58-cpp)
namespace std::ranges {
template <std::ranges::input_range R, class T>
constexpr bool contains(R &&r, const T &value) {
  return std::find(std::begin(std::forward<R>(r)), std::end(std::forward<R>(r)), value) != std::end(std::forward<R>(r));
}
} // namespace std::ranges
// NOLINTEND(cert-dcl58-cpp)
#endif

namespace hpp::proto {
namespace concepts {
template <typename T>
concept memory_resource = !std::copyable<T> && requires(T &object) {
  { object.allocate(8, 8) } -> std::same_as<void *>;
};

template <typename T>
concept has_memory_resource = requires(T &object) {
  object.memory_resource();
  requires memory_resource<std::remove_cvref_t<decltype(object.memory_resource())>>;
};

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
concept is_pb_context = requires { typename std::remove_cvref_t<T>::is_pb_context; };

template <typename T>
concept is_auxiliary_context = memory_resource<T> || requires { typename T::auxiliary_context_type; };

template <typename T>
concept dynamic_sized_view =
    std::same_as<T, std::span<typename T::element_type, std::dynamic_extent>> || std::same_as<T, std::string_view>;

} // namespace concepts

template <typename T>
struct pb_context_base {
  using type = typename T::auxiliary_context_type;
};

template <concepts::memory_resource T>
struct pb_context_base<T> {
  using type = std::reference_wrapper<T>;
};

template <typename... T>
struct pb_context : pb_context_base<T>::type... {
  using is_pb_context = void;
  template <typename... U>
  constexpr explicit pb_context(U &&...ctx) : pb_context_base<T>::type(std::forward<U>(ctx))... {}

  template <concepts::is_auxiliary_context U>
  [[nodiscard]] constexpr auto &get() const {
    if constexpr (std::copyable<U>) {
      return static_cast<const U &>(*this);
    } else {
      return static_cast<const std::reference_wrapper<U> &>(*this).get();
    }
  }

  template <typename U, typename... Rest>
  [[nodiscard]] auto &get_memory_resource() const {
    if constexpr (concepts::memory_resource<U>) {
      return this->template get<U>();
    } else {
      return this->get_memory_resource<Rest...>();
    }
  }

  template <typename U, typename... Rest>
  constexpr static bool has_memory_resource_impl() {
    if constexpr (concepts::memory_resource<U>) {
      return true;
    } else if constexpr (sizeof...(Rest) > 0) {
      return has_memory_resource_impl<Rest...>();
    } else {
      return false;
    }
  }

  template <typename... U>
  constexpr static bool has_memory_resource() {
    if constexpr (sizeof...(U) > 0) {
      return has_memory_resource_impl<U...>();
    } else {
      return false;
    }
  }

  [[nodiscard]] auto &memory_resource() const
    requires(has_memory_resource<T...>())
  {
    return get_memory_resource<T...>();
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

template <typename T>
using memory_resource_type = std::remove_reference_t<decltype(get_memory_resource(std::declval<T>))>;

namespace concepts {
template <typename T>
concept context_with_memory_resource = requires(T &v) { get_memory_resource(v); };
} // namespace concepts

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

/// The `arena_vector` class adapts an existing std::span or std::string_view, allowing the underlying
/// memory to be allocated from a designated memory resource. This memory resource releases the allocated
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
  // static_assert(std::is_nothrow_default_constructible_v<value_type>);
  static_assert(std::is_nothrow_copy_constructible_v<value_type>);

  constexpr MemoryResource &memory_resource() { return mr; }

  constexpr arena_vector(View &view, MemoryResource &mr) : mr(mr), view_(view) {}
  constexpr arena_vector(View &view, concepts::has_memory_resource auto &ctx)
      : mr(ctx.memory_resource()), view_(view) {}

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

  constexpr void assign_range(std::ranges::sized_range auto &&r) {
    assign_range_with_size(std::forward<decltype(r)>(r), std::ranges::size(r));
  }

  constexpr void append_range(std::ranges::sized_range auto &&r) {
    auto old_size = view_.size();
    auto n = std::ranges::size(r);
    assign_range_with_size(view_, old_size + n);
    std::ranges::uninitialized_copy(std::forward<decltype(r)>(r), std::span{data_ + old_size, n});
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
    if (std::is_constant_evaluated() || (sizeof(value_type) > 1 && std::endian::little != std::endian::native)) {
      using input_it = raw_data_iterator<value_type, ByteT>;
      std::uninitialized_copy(input_it{start_pos}, input_it{start_pos + num_elements * sizeof(value_type)},
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

  constexpr void assign_range_with_size(std::ranges::sized_range auto &&r, std::size_t n) {
    if (capacity_ < n) {
      auto new_data = static_cast<value_type *>(mr.allocate(n * sizeof(value_type), alignof(value_type)));
      std::ranges::uninitialized_copy(std::forward<decltype(r)>(r), std::span{new_data, n});
      data_ = new_data;
    } else {
      if constexpr (std::same_as<std::remove_cvref_t<decltype(r)>, View>) {
        if (view_.data() != r.data()) {
          std::ranges::copy(std::forward<decltype(r)>(r), data_);
        }
      } else {
        std::ranges::copy(std::forward<decltype(r)>(r), data_);
      }
    }
    view_ = View{data_, n};
  }
};
// NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

template <concepts::dynamic_sized_view View, concepts::has_memory_resource Context>
arena_vector(View &view, Context &ctx)
    -> arena_vector<View, std::remove_reference_t<decltype(std::declval<Context>().memory_resource())>>;

} // namespace detail

constexpr auto as_modifiable(auto &&context, concepts::dynamic_sized_view auto &view) {
  return detail::arena_vector{view, context};
}

template <typename T>
  requires(!concepts::dynamic_sized_view<T>)
constexpr T &as_modifiable(auto && /* unused */, T &view) {
  return view;
}

} // namespace hpp::proto
