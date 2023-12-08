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
  object.memory_resource;
  requires memory_resource<std::remove_cvref_t<decltype(object.memory_resource)>>;
};

template <typename T>
concept contiguous_byte_range = byte_type<typename std::ranges::range_value_t<T>> && std::ranges::contiguous_range<T>;

} // namespace concepts

namespace detail {

template <typename Base, concepts::memory_resource MemoryResource>
class growable_span {
public:
  using value_type = typename Base::value_type;
  MemoryResource &memory_resource;

  growable_span(Base &base, MemoryResource &mr) : memory_resource(mr), base_(base) {}

  void resize(std::size_t n) {
    if (data_ == nullptr || n > base_.size()) {
      data_ = static_cast<value_type *>(memory_resource.allocate(n * sizeof(value_type), alignof(value_type)));
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

template <typename T>
constexpr auto make_growable(concepts::has_memory_resource auto &&context, std::span<T> &base) {
  return growable_span{base, context.memory_resource};
}

constexpr auto make_growable(concepts::has_memory_resource auto &&context, std::string_view &base) {
  return growable_span{base, context.memory_resource};
}

template <typename T>
constexpr T &make_growable(auto && /* unused */, T &base) {
  return base;
}

} // namespace detail

} // namespace hpp::proto
