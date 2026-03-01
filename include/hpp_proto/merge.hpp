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

#include <concepts>
#include <cstddef>
#include <iterator>
#include <tuple>
#include <type_traits>
#include <utility>

#include <hpp_proto/binpb/concepts.hpp>
#include <hpp_proto/binpb/meta.hpp>
#include <hpp_proto/binpb/util.hpp>

namespace hpp_proto {
template <typename>
inline constexpr bool dependent_false_v = false;

namespace detail {
template <typename Tuple1, typename Tuple2, std::size_t... I>
constexpr auto zip_tuples_impl(const Tuple1 &t1, const Tuple2 &t2, std::index_sequence<I...>) -> decltype(auto) {
  return std::make_tuple(std::make_pair(std::get<I>(t1), std::get<I>(t2))...);
}

template <typename... T1, typename... T2>
constexpr auto zip_tuples(const std::tuple<T1...> &t1, const std::tuple<T2...> &t2) -> decltype(auto) {
  static_assert(sizeof...(T1) == sizeof...(T2), "Tuples must have the same size.");
  return zip_tuples_impl(t1, t2, std::make_index_sequence<sizeof...(T1)>{});
}
} // namespace detail

template <concepts::is_pb_context Context>
struct message_merger {
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  Context &ctx;

  template <concepts::has_meta T, typename U>
    requires concepts::isomorphic_message<T, std::decay_t<U>>
  constexpr void perform(T &dest, U &&source) {
    return std::apply(
        [this, &dest, &source](auto &&...metas) {
          // NOLINTNEXTLINE(bugprone-use-after-move,hicpp-invalid-access-moved)
          (this->perform(metas, metas.first.get(dest), metas.second.get(std::forward<U>(source))), ...);
        },
        detail::zip_tuples(typename util::meta_of<T>::type{}, typename util::meta_of<std::decay_t<U>>::type{}));
  }

  template <typename MetaT, typename MetaU, typename T, typename U>
  void perform(std::pair<MetaT, MetaU>, T &dest, U &&source) {
    if constexpr (concepts::variant<T>) {
      if (source.index() > 0) {
        if (dest.index() == source.index()) {
          using alt_metas =
              decltype(detail::zip_tuples(typename MetaT::alternatives_meta{}, typename MetaU::alternatives_meta{}));
          perform(alt_metas(), dest, std::forward<U>(source), std::make_index_sequence<std::tuple_size_v<alt_metas>>());
          return;
        }

        if constexpr (std::same_as<T, std::decay_t<U>>) {
          dest = std::forward<U>(source);
        } else {
          assign(dest, std::forward<U>(source),
                 std::make_index_sequence<std::tuple_size_v<typename MetaU::alternatives_meta>>());
        }
      }
    } else if constexpr (MetaT::explicit_presence() || !concepts::singular<T>) {
      perform(dest, std::forward<U>(source));
    } else {
      if (!MetaU::omit_value(source)) {
        perform(dest, source);
      }
    }
  }

  template <typename MetaPairs, concepts::variant T, typename U, std::size_t FirstIndex, std::size_t... Indices>
  void perform(MetaPairs metas, T &dest, U &&source, std::index_sequence<FirstIndex, Indices...>) {
    if (dest.index() == FirstIndex + 1) {
      perform(std::get<FirstIndex>(metas), std::get<FirstIndex + 1>(dest),
              std::get<FirstIndex + 1>(std::forward<U>(source)));
    } else {
      perform(metas, dest, std::forward<U>(source), std::index_sequence<Indices...>());
    }
  }

  template <typename MetaPairs, concepts::variant T, concepts::variant U>
  constexpr void perform(MetaPairs, T &, const U &, std::index_sequence<>) {}

  template <concepts::variant T, typename U, std::size_t FirstIndex, std::size_t... Indices>
  void assign(T &dest, const U &source, std::index_sequence<FirstIndex, Indices...>) {
    if (source.index() == FirstIndex + 1) {
      perform(dest.template emplace<FirstIndex + 1>(), std::get<FirstIndex + 1>(source));
    } else {
      assign(dest, source, std::index_sequence<Indices...>());
    }
  }

  template <concepts::variant T, typename U>
  void assign(T &, const U &, std::index_sequence<>) {}

  template <concepts::optional T, typename U>
  constexpr void perform(T &dest, U &&source) {
    if constexpr (concepts::has_meta<typename T::value_type>) {
      if (source.has_value()) {
        if (!dest.has_value()) {
          perform(dest.emplace(), *std::forward<U>(source));
        } else {
          perform(*dest, *std::forward<U>(source));
        }
      }
    } else {
      if (source.has_value()) {
        perform(dest.emplace(), *std::forward<U>(source));
      }
    }
  }

  template <concepts::repeated T, typename U>
    requires(std::convertible_to<typename U::value_type, std::remove_const_t<typename T::value_type>> &&
             !std::is_lvalue_reference_v<U>)
  constexpr void perform(T &dest, U &&source) {
    if constexpr (std::ranges::contiguous_range<U>) {
      if (dest.empty()) {
        if constexpr (requires { dest = std::forward<U>(source); }) {
          dest = std::forward<U>(source);
          return;
        } else if constexpr (requires {
                               dest.assign(std::make_move_iterator(source.begin()),
                                           std::make_move_iterator(source.end()));
                             }) {
          dest.assign(std::make_move_iterator(source.begin()), std::make_move_iterator(source.end()));
          return;
        }
      }
    }
    decltype(auto) v = detail::as_modifiable(ctx, dest);
    auto first = std::make_move_iterator(source.begin());
    auto last = std::make_move_iterator(source.end());
    if constexpr (requires { v.insert(v.end(), first, last); }) {
      v.insert(v.end(), first, last);
    } else {
      v.append_range(first, last);
    }
  }

  template <concepts::repeated T, typename U>
    requires std::convertible_to<typename U::value_type, std::remove_const_t<typename T::value_type>>
  constexpr void perform(T &dest, const U &source) {
    if constexpr (std::ranges::contiguous_range<U>) {
      if (dest.empty()) {
        if constexpr (requires { dest = source; }) {
          dest = source;
          return;
        } else if constexpr (requires { dest.assign(source.begin(), source.end()); }) {
          dest.assign(source.begin(), source.end());
          return;
        }
      }
    }
    decltype(auto) v = detail::as_modifiable(ctx, dest);
    util::append_range(v, source);
  }

  template <concepts::repeated T, typename U>
    requires(!std::convertible_to<typename U::value_type, std::remove_const_t<typename T::value_type>>)
  constexpr void perform(T &dest, auto const &source) {
    decltype(auto) x = detail::as_modifiable(ctx, dest);
    auto orig_size = dest.size();
    x.resize(dest.size() + source.size());
    for (std::size_t i = 0; i < source.size(); ++i) {
      perform(dest[i + orig_size], source[i]);
    }
  }

  template <concepts::is_pair T, typename U>
  constexpr void perform(T &dest, const U &source) {
    dest.first = source.first;
    perform(dest.second, source.second);
  }

  template <concepts::associative_container T, typename U>
  constexpr void perform(T &dest, U &&source) {
    if (!source.empty()) {
      if constexpr (std::same_as<T, std::decay_t<U>>) {
        if (dest.empty()) {
          dest = std::forward<U>(source);
          return;
        }
      }
      insert_or_replace(dest, std::forward<U>(source));
    }
  }

  template <typename T, typename U>
    requires requires { typename T::mapped_type; }
  constexpr void insert_or_replace(T &dest, const U &source) {
    T tmp;
    tmp.swap(dest);
    if constexpr (std::same_as<T, U>) {
      dest = source;
    } else {
      dest.insert(source.begin(), source.end());
    }
    if constexpr (requires { dest.insert(sorted_unique, tmp.begin(), tmp.end()); }) {
      dest.insert(sorted_unique, tmp.begin(), tmp.end());
    } else {
      dest.insert(tmp.begin(), tmp.end());
    }
  }

  template <typename T>
    requires requires { typename T::mapped_type; }
  // NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
  constexpr void insert_or_replace(T &dest, T &&source) {
    source.swap(dest);
    if constexpr (requires { dest.insert(sorted_unique, source.begin(), source.end()); }) {
      // flat_map
      dest.insert(sorted_unique, source.begin(), source.end());
    } else if constexpr (requires { dest.merge(source); }) {
      // std::map, std::unordered_map
      dest.merge(source);
    } else {
      dest.insert(source.begin(), source.end());
    }
  }

  template <typename T>
    requires(concepts::pb_unknown_fields<T> || concepts::pb_extensions<T>)
  constexpr void perform(T &dest, const T &source) {
    perform(dest.fields, source.fields);
  }

  template <concepts::singular T, typename U>
  constexpr void perform(T &dest, U &&source) {
    if constexpr (requires { dest = std::forward<U>(source); }) {
      dest = std::forward<U>(source);
    } else if constexpr (requires { dest.assign_range(source); }) {
      dest.assign_range(source);
    } else if constexpr (requires { dest.assign(source.begin(), source.end()); }) {
      dest.assign(source.begin(), source.end());
    } else if constexpr (requires { detail::as_modifiable(ctx, dest).assign_range(source); }) {
      auto v = detail::as_modifiable(ctx, dest);
      v.assign_range(source);
    } else {
      static_assert(dependent_false_v<U>, "invalid operation");
    }
  }
};

/// @brief Merge the fields from the `source` message into `dest` message.
/// @details Singular fields supplied in `source` overwrite those in `dest`, except embedded messages which merge.
/// Repeated fields append the values from `source`. For non-owning traits, map fields behave like repeated fields;
/// entries are appended without deduplication, so if a key appears multiple times only the last value should be
/// considered authoritative. Both messages must share the same concrete type.
template <concepts::has_meta T, typename U>
  requires concepts::isomorphic_message<T, std::decay_t<U>>
constexpr void merge(T &dest, U &&source, concepts::is_option_type auto &&...option) {
  pb_context ctx{std::forward<decltype(option)>(option)...};
  message_merger merger{ctx};
  merger.perform(dest, std::forward<U>(source));
}

} // namespace hpp_proto
