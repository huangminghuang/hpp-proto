#pragma once

#include <concepts>
#include <hpp_proto/field_types.h>
#include <ranges>
#include <span>
#include <string_view>

#if !defined(__cpp_lib_ranges)
namespace std {
namespace ranges {

template <typename T>
using range_value_t = std::iter_value_t<decltype(std::begin(std::declval<T &>()))>;

template <class T>
using iterator_t = decltype(std::ranges::begin(std::declval<T &>()));

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

} // namespace ranges
} // namespace std
#endif

#if !defined(__cpp_lib_ranges_contains)
namespace std {
namespace ranges {
template <std::ranges::input_range R, class T>
constexpr bool contains(R &&r, const T &value) {
  return std::find(std::begin(r), std::end(r), value) != std::end(r);
}
} // namespace ranges
} // namespace std
#endif

namespace hpp::proto {
namespace concepts {
template <typename T>
concept memory_resource = requires(T &object) {
  { object.allocate(8, 8) } -> std::same_as<void *>;
};

template <typename T>
concept has_memory_resource = requires(T &object) {
  object.memory_resource();
  requires memory_resource<std::remove_cvref_t<decltype(object.memory_resource())>>;
};

template <typename T>
concept contiguous_byte_range = byte_type<typename std::ranges::range_value_t<T>> && std::ranges::contiguous_range<T>;

template <typename T>
concept contiguous_output_byte_range =
    contiguous_byte_range<T> && std::ranges::output_range<T, typename std::ranges::range_value_t<T>>;

template <typename T>
concept resizable_contiguous_byte_container = contiguous_byte_range<T> && requires(T &v) { v.resize(0); };

template <typename T>
concept is_aux_contexts = requires { typename T::is_aux_contexts; };

} // namespace concepts

template <typename... T>
struct aux_contexts : std::reference_wrapper<T>... {
  using is_aux_contexts = void;
  constexpr aux_contexts(T &...ctx) : std::reference_wrapper<T>(ctx)... {}

  template <typename U>
  U &get() const {
    return static_cast<const std::reference_wrapper<U> &>(*this).get();
  }

  template <typename U, typename... Rest>
  auto &get_memory_resource() const {
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

  auto &memory_resource() const
    requires(has_memory_resource<T...>())
  {
    return get_memory_resource<T...>();
  }
};

namespace detail {

template <typename Base, concepts::memory_resource MemoryResource>
class growable_span {
  MemoryResource &mr;

public:
  using value_type = typename Base::value_type;
  MemoryResource &memory_resource() { return mr; }

  growable_span(Base &base, MemoryResource &mr) : mr(mr), base_(base) {}

  void resize(std::size_t n) {
    if (data_ == nullptr || n > base_.size()) {
      data_ = static_cast<value_type *>(mr.allocate(n * sizeof(value_type), alignof(value_type)));
      assert(data_ != nullptr);
      std::uninitialized_copy(base_.begin(), base_.end(), data_);

      if constexpr (!std::is_trivial_v<value_type>) {
        std::uninitialized_default_construct(data_ + base_.size(), data_ + n);
      } else {
#ifdef __cpp_lib_start_lifetime_as
        std::start_lifetime_as_array(data_ + base.size(), n);
#endif
      }
      base_ = Base{data_, n};
    } else {
      base_ = Base(base_.data(), n);
    }
  }

  value_type *data() const { return data_; }
  value_type &operator[](std::size_t n) { return data_[n]; }
  std::size_t size() const { return base_.size(); }
  value_type *begin() const { return data_; }
  value_type *end() const { return data_ + size(); }

  void push_back(const value_type &v) {
    resize(size() + 1);
    data_[size() - 1] = v;
  }

  void clear() {
    base_ = Base{};
    data_ = nullptr;
  }

private:
  Base &base_;
  value_type *data_ = nullptr;
};
} // namespace detail

template <typename T>
constexpr auto make_growable(concepts::has_memory_resource auto &&context, std::span<T> &base) {
  return detail::growable_span{base, context.memory_resource()};
}

constexpr auto make_growable(concepts::has_memory_resource auto &&context, std::string_view &base) {
  return detail::growable_span{base, context.memory_resource};
}

template <typename T>
constexpr auto make_growable(concepts::memory_resource auto &mr, std::span<T> &base) {
  return detail::growable_span{base, mr};
}

constexpr auto make_growable(concepts::memory_resource auto &mr, std::string_view &base) {
  return detail::growable_span{base, mr};
}

template <typename T>
constexpr T &make_growable(auto && /* unused */, T &base) {
  return base;
}

} // namespace hpp::proto
