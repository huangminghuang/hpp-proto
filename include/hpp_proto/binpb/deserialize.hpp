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

#include <hpp_proto/binpb/concepts.hpp>
#include <hpp_proto/binpb/meta.hpp>
#include <hpp_proto/binpb/sfvint.hpp>
#include <hpp_proto/binpb/utf8.hpp>
#include <hpp_proto/binpb/util.hpp>
#include <hpp_proto/binpb/varint.hpp>

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
namespace hpp::proto {

[[noreturn]] inline void unreachable() {
#if __cpp_lib_unreachable
  std::unreachable();
#else
#if defined(_MSC_VER) && !defined(__clang__) // MSVC
  __assume(false);
#else                                        // GCC, Clang
  __builtin_unreachable();
#endif
#endif
}

namespace pb_serializer {
template <typename T>
struct input_span {
  using value_type = T;
  const value_type *_begin = nullptr;
  const value_type *_end = nullptr;

  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  constexpr input_span() = default;
  constexpr input_span(const value_type *b, const value_type *e) : _begin(b), _end(e) {}
  constexpr input_span(const value_type *b, std::size_t n) : _begin(b), _end(b + n) {}
  [[nodiscard]] constexpr const value_type *data() const { return _begin; }
  [[nodiscard]] constexpr std::size_t size() const { return static_cast<std::size_t>(_end - _begin); }
  [[nodiscard]] constexpr bool empty() const { return _begin == _end; }

  [[nodiscard]] constexpr const value_type *begin() const { return _begin; }
  [[nodiscard]] constexpr const value_type *end() const { return _end; }

  constexpr const value_type &operator[](std::size_t n) const { return *(_begin + n); }
  constexpr const value_type &next() { return *_begin++; }
  [[nodiscard]] constexpr input_span<T> subspan(std::size_t offset, std::size_t count) const {
    return {_begin + offset, _begin + offset + count};
  }

  [[nodiscard]] constexpr std::pair<input_span<value_type>, input_span<T>> split(std::size_t n) const {
    return std::make_pair(input_span<value_type>{_begin, _begin + n}, input_span<value_type>{_begin + n, _end});
  }

  constexpr input_span<T> consume(std::size_t n) {
    const T *old_begin = _begin;
    _begin += n;
    return {old_begin, _begin};
  }

  template <typename U, std::size_t N>
  constexpr void consume(std::array<U, N> &arr) {
    std::copy(_begin, _begin + N, arr.data());
    _begin += N;
  }

  void revert(std::size_t n) { _begin -= n; }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

  constexpr void advance_to(const value_type *new_pos) { _begin = new_pos; }
};

constexpr static std::size_t slope_size = 16;
constexpr static std::size_t patch_buffer_size = 2 * slope_size;
inline constexpr std::size_t stack_segment_threshold = 8;

template <typename Byte>
struct input_buffer_region : input_span<Byte> {
  const Byte *_slope_begin = nullptr;
  constexpr input_buffer_region() = default;
  constexpr input_buffer_region(input_span<Byte> range, const Byte *s) : input_span<Byte>{range}, _slope_begin(s) {}
  constexpr explicit input_buffer_region(std::span<const Byte> bytes)
      : input_span<Byte>{bytes.data(), bytes.size()}, _slope_begin(nullptr) {}

  [[nodiscard]] constexpr std::ptrdiff_t slope_distance() const { return this->_begin - _slope_begin; }
  [[nodiscard]] constexpr bool has_next_region() const { return this->_end > _slope_begin; }

  constexpr input_span<Byte> consume_packed_varints(std::size_t max_size) {
    if (this->size() >= max_size) {
      return this->consume(max_size);
    } else if (has_next_region()) {
      // find the last position where a varint terminated in the slope area. If the position is not found,
      // we have at least a non-terminated varint, just return a empty range to indicate error.
      auto slope_area = std::span{_slope_begin, this->_end};
      auto it = std::ranges::find_if(slope_area | std::views::reverse,
                                     [](auto v) { return std::bit_cast<std::int8_t>(v) >= 0; });
      if (it == slope_area.rend()) {
        return {};
      }
      return this->consume(this->size() - std::distance(slope_area.rbegin(), it));
    } else {
      return {};
    }
  }
};

///
/// We adopt the same optimization technique as
/// [EpsCopyInputStream](https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/parse_context.h)
/// for protobuf deserialization. Input buffers are structured into a sequence of overlapping regions, where
/// each consecutive region overlaps by slope_size bytes. For a sequence of input buffers (b_1, b_2, ..., b_n), patch
/// buffers are inserted between chunks to create a new sequence (b_1, p_1, b_2, p_2, ..., b_n, p_n). Each patch
/// buffer p_i contains the last slope_size bytes of b_i and the first slope_size bytes of b_{i+1}.
///

// NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
template <typename Byte, typename Context, bool Contiguous>
struct basic_in {
  using byte_type = Byte;
  input_buffer_region<Byte> current;
  input_span<input_buffer_region<Byte>> rest;
  ptrdiff_t size_exclude_current = 0; // the remaining size excluding those in current region without slope area
  Context &context;                   // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

  constexpr static bool endian_swapped = std::endian::little != std::endian::native;

  constexpr void set_current_region(const input_buffer_region<Byte> &next_region) {
    current._begin = next_region._begin;
    if (size_exclude_current + next_region.slope_distance() >= 0) {
      current._end = next_region._end;
      size_exclude_current += next_region.slope_distance();
      current._slope_begin = std::min(next_region._slope_begin, current._end);
    } else {
      current._end = current._begin + size_exclude_current;
      current._slope_begin = std::min(next_region._slope_begin, current._end);
      size_exclude_current = std::distance(current._slope_begin, current._end);
    }
  }

  constexpr void maybe_advance_region() {
    std::ptrdiff_t offset = 0;
    while ((offset = current.slope_distance()) > 0 && !rest.empty()) {
      [[maybe_unused]] auto current_in_avail = in_avail();
      set_current_region(rest.next());
      current.consume(static_cast<std::size_t>(offset));
      if (!std::is_constant_evaluated()) {
        assert(current_in_avail == in_avail());
      }
    }
  }

public:
  using is_basic_in = void;
  constexpr static bool contiguous = Contiguous;
  [[nodiscard]] constexpr ptrdiff_t region_size() const { return current._end - current._begin; }
  [[nodiscard]] constexpr ptrdiff_t in_avail() const {
    if constexpr (contiguous) {
      return region_size();
    } else {
      return size_exclude_current - current.slope_distance();
    }
  }
  [[nodiscard]] constexpr const byte_type *data() const { return current.data(); }

  constexpr basic_in(input_buffer_region<Byte> cur, const input_span<input_buffer_region<Byte>> &rest,
                     ptrdiff_t size_exclude_current, Context &ctx)
      : current(cur), rest(rest), size_exclude_current(size_exclude_current), context(ctx) {}

  constexpr basic_in(std::span<input_buffer_region<Byte>> regions, std::span<Byte> patch_buffer_cache, Context &ctx)
      : context(ctx) {
    // pre (std::size(source) > 0 && regions.size() == std::size(source) * 2)
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    Byte *patch_buffer = patch_buffer_cache.data();
    std::size_t region_index = 0;
    bool first_segment = true;
    auto source = regions.subspan(regions.size() / 2);
    for (const auto &segment : source) {
      const auto segment_size = segment.size();
      if (!first_segment && segment_size == 0) {
        continue;
      }
      size_exclude_current += static_cast<std::ptrdiff_t>(segment_size);
      if (segment_size <= slope_size) {
        auto &seg_region = regions[region_index];
        if (first_segment) {
          seg_region._begin = patch_buffer;
        }
        patch_buffer = std::copy(segment.begin(), segment.end(), patch_buffer);
        seg_region._slope_begin = patch_buffer;
      } else {
        if (!first_segment) {
          patch_buffer = std::copy_n(segment.begin(), slope_size, patch_buffer);
          regions[region_index]._end = patch_buffer;
          ++region_index;
        }
        auto &seg_region = regions[region_index];
        seg_region._begin = segment.data();
        seg_region._end = seg_region._begin + segment_size;
        seg_region._slope_begin = seg_region._end - slope_size;

        auto &patch_region = regions[++region_index];
        patch_region._begin = patch_buffer;
        patch_buffer = std::copy(seg_region._slope_begin, seg_region._end, patch_buffer);
        patch_region._slope_begin = patch_buffer;
      }
      first_segment = false;
    }
    if (!regions.empty()) {
      // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      regions[region_index]._end = patch_buffer;
      regions[region_index]._slope_begin = patch_buffer;
      std::fill_n(patch_buffer, slope_size, Byte{0});
      rest = input_span{regions.data(), region_index + 1};
      auto &next_region = rest.next();
      current._begin = next_region._begin;
      current._end = next_region._end;
      size_exclude_current += (next_region.slope_distance());
      current._slope_begin = std::min(next_region._slope_begin, current._end);
    }
  }

  basic_in(const basic_in &) = default;
  basic_in(basic_in &&) = default;
  basic_in &operator=(const basic_in &) = default;
  basic_in &operator=(basic_in &&) = default;
  ~basic_in() = default;

  [[nodiscard]] basic_in copy() const { return *this; }

  constexpr status deserialize(bool &item) {
    if (auto p = unchecked_parse_bool(current, item); p <= current._end) [[likely]] {
      current.advance_to(p);
      return {};
    }
    return std::errc::bad_message;
  }

  constexpr status deserialize(boolean &item) { return deserialize(item.value); }

  template <concepts::byte_deserializable T>
  constexpr status deserialize(T &item) {
    std::array<std::remove_const_t<byte_type>, sizeof(item)> value = {};
    if constexpr (endian_swapped) {
      std::ranges::reverse_copy(current.consume(sizeof(item)), value.begin());
    } else {
      std::ranges::copy(current.consume(sizeof(item)), value.begin());
    }
    item = std::bit_cast<T>(value);
    return {};
  }

  template <typename T>
    requires concepts::is_enum<T> && (sizeof(T) > 1)
  constexpr status deserialize(T &item) {
    return deserialize(varint{static_cast<int64_t>(item)});
  }

  template <concepts::varint T>
  constexpr status deserialize(T &item) {
    if (auto p = unchecked_parse_varint(current, item); p <= current._end) [[likely]] {
      current.advance_to(p);
      return {};
    }
    return std::errc::bad_message;
  }

  // Helper: append raw data path for packed deserialization (no byte-swap required)
  template <typename ValueType>
  constexpr status do_deserialize_packed_append_raw(std::size_t n, auto &item, std::size_t nbytes,
                                                    std::size_t new_size) {
    item.reserve(new_size);
    if constexpr (contiguous) {
      item.append_raw_data(current.consume(nbytes));
      return {};
    } else {
      while (n > 0) {
        maybe_advance_region();
        auto k = std::min<std::ptrdiff_t>(n, region_size() / static_cast<std::ptrdiff_t>(sizeof(ValueType)));
        item.append_raw_data(current.consume(static_cast<std::size_t>(k) * sizeof(ValueType)));
        n -= k;
      }
      return {};
    }
  }

  // Helper: resize-and-copy path for packed deserialization (handles byte-swap and constant evaluation)
  template <typename ValueType>
  constexpr status do_deserialize_packed_resize(std::size_t n, auto &item, std::size_t old_size, std::size_t new_size,
                                                std::size_t nbytes) {
    item.resize(new_size);
    auto target = std::span{item.data() + old_size, n};
    constexpr bool requires_byteswap = (sizeof(ValueType) > 1 && endian_swapped);
    if (std::is_constant_evaluated() || requires_byteswap) {
      std::array<byte_type, sizeof(ValueType)> v{};
      for (auto &elem : target) {
        maybe_advance_region();
        current.consume(v);
        if constexpr (requires_byteswap) {
          std::ranges::reverse(v);
        }
        elem = std::bit_cast<ValueType>(v);
      }
    } else {
      void *ptr = target.data();
      if constexpr (contiguous) {
        std::memcpy(ptr, current.consume(nbytes).data(), nbytes);
      } else {
        while (nbytes > 0) {
          maybe_advance_region();
          std::size_t k = std::min(nbytes, static_cast<std::size_t>(region_size()));
          std::memcpy(ptr, current.consume(k).data(), k);
          ptr = static_cast<char *>(ptr) + k;
          nbytes -= k;
        }
      }
    }
    return {};
  }

  constexpr status deserialize_packed(std::size_t n, auto &&item) {
    using value_type = typename std::remove_cvref_t<decltype(item)>::value_type;
    std::size_t nbytes = n * sizeof(value_type);
    if (std::cmp_less(in_avail(), nbytes)) [[unlikely]] {
      return std::errc::bad_message;
    }
    constexpr bool requires_byteswap = (sizeof(value_type) > 1 && endian_swapped);

    auto old_size = item.size();
    auto new_size = old_size + n;
    if constexpr (requires { item.append_raw_data(std::span<byte_type>{}); } && !requires_byteswap) {
      return do_deserialize_packed_append_raw<value_type>(n, item, nbytes, new_size);
    } else {
      return do_deserialize_packed_resize<value_type>(n, item, old_size, new_size, nbytes);
    }
  }

#if defined(__x86_64__) || defined(_M_AMD64) // x64
  // workaround for C++20 doesn't support static in constexpr function
  static bool has_bmi2() {
    auto check = [] {
#if defined(_MSC_VER) && !defined(__clang__)
      int cpuInfo[4];
      __cpuidex(cpuInfo, 7, 0);
      return (cpuInfo[1] & (1 << 8)) != 0; // Check BMI2 bit
#elif defined(__GNUC__) || defined(__clang__)
      return __builtin_cpu_supports("bmi2");
#else
      return false;
#endif
    };
    static bool result = check();
    return result;
  }
#endif // x64
  template <typename Item>
  constexpr status deserialize_packed_boolean(std::size_t size, Item &item) {
    auto old_size = item.size();
    item.resize(old_size + size);
    std::span new_region{item.begin() + static_cast<std::ptrdiff_t>(old_size), item.end()};
    for (auto &v : new_region) {
      if constexpr (!contiguous) {
        maybe_advance_region();
      }
      if (auto r = deserialize(v); !r.ok()) [[unlikely]] {
        return r;
      }
    }
    return {};
  }

  template <concepts::varint T>
  constexpr status parse_packed_varints_in_a_region(auto current, auto &&it) {
    using value_type = std::decay_t<decltype(*it)>;
    while (current.size()) {
      T underlying;
      auto p = unchecked_parse_varint(current, underlying);
      if (p > current._end) [[unlikely]] {
        return std::errc::bad_message;
      }
      current.advance_to(p);
      *it = static_cast<value_type>(underlying.value);
      ++it;
    }
    return std::errc{};
  };

  template <concepts::varint T>
  constexpr status parse_packed_varints_in_regions(std::uint32_t bytes_count, auto &item) {
    auto it = item.data();
    while (bytes_count > 0) {
      maybe_advance_region();
      auto data = current.consume_packed_varints(bytes_count);
      if (data.empty()) [[unlikely]] {
        return std::errc::bad_message;
      }
      bytes_count -= static_cast<std::uint32_t>(data.size());
      if (auto result = parse_packed_varints_in_a_region<T>(data, it); !result.ok()) [[unlikely]] {
        return result;
      }
    }
    return {};
  }

  template <concepts::varint T, typename Item>
  constexpr status deserialize_packed_varint([[maybe_unused]] std::uint32_t bytes_count, std::size_t size, Item &item) {
    auto old_size = static_cast<std::ptrdiff_t>(item.size());
    item.resize(item.size() + size);
    std::span new_region{std::next(item.begin(), old_size), item.end()};
#if defined(__x86_64__) || defined(_M_AMD64) // x64
    if constexpr (sfvint_parser_allowed<Context>()) {
      if (!std::is_constant_evaluated() && has_bmi2()) {
        using value_type = typename Item::value_type;
        sfvint_parser<T, value_type> parser(new_region.data());
        if constexpr (!contiguous) {
          while (bytes_count > region_size()) {
            auto saved_begin = current.begin();
            auto p = parser.parse_partial(current);
            if (p == nullptr) [[unlikely]] {
              return std::errc::bad_message;
            }
            current.advance_to(p);
            bytes_count -= static_cast<std::uint32_t>(current.begin() - saved_begin);
            maybe_advance_region();
          }
        }
        if (bytes_count > 0) {
          if (parser.parse(current.consume(bytes_count)) == nullptr) [[unlikely]] {
            return std::errc::bad_message;
          }
        }
        return {};
      }
    }
#endif

    if constexpr (contiguous) {
      return parse_packed_varints_in_a_region<T>(current.consume(bytes_count), new_region.data());
    } else {
      return parse_packed_varints_in_regions<T>(bytes_count, new_region);
    }
  }

  constexpr status skip_varint() {
    // varint must terminated in 10 bytes
    const auto *last = std::min(current.begin() + 10, current.end());
    const auto *pos = std::find_if(current.begin(), last, [](auto v) { return static_cast<int8_t>(v) >= 0; });
    if (pos == last) [[unlikely]] {
      return std::errc::bad_message;
    }
    current.advance_to(pos + 1);
    return {};
  }

  constexpr status skip_length_delimited() {
    vuint32_t len;
    if (auto result = deserialize(len); !result.ok()) [[unlikely]] {
      return result;
    }
    return skip(len.value);
  }

  constexpr status skip(std::size_t length) {
    if (std::cmp_less(in_avail(), length)) [[unlikely]] {
      return std::errc::bad_message;
    }
    current.consume(length);
    return {};
  }

  // split the object at the specified length;
  // return the first half and set the current
  // object as the second half.
  constexpr auto split(std::size_t length) {
    assert(std::cmp_greater_equal(in_avail(), length));
    auto new_begin = current._begin;
    const Byte *new_end = nullptr;
    const Byte *new_slope_begin = nullptr;
    std::ptrdiff_t new_size_exclude_current = 0;

    if (current.size() >= length) {
      new_end = current._begin + length;
      new_slope_begin = std::min(new_end, current._slope_begin);
      new_size_exclude_current = std::distance(new_slope_begin, new_end);
    } else {
      new_end = current._end;
      new_slope_begin = current._slope_begin;
      new_size_exclude_current = static_cast<std::ptrdiff_t>(length) + current.slope_distance();
    }

    current.consume(length);
    auto new_region = input_buffer_region<Byte>{{new_begin, new_end}, new_slope_begin};
    auto result = basic_in<byte_type, Context, contiguous>{new_region, rest, new_size_exclude_current, context};
    if (!std::is_constant_evaluated()) {
      assert(std::cmp_equal(result.in_avail(), length));
    }
    return result;
  }

  template <concepts::non_owning_bytes T>
  constexpr status read_bytes(uint32_t length, T &item) {
    assert(std::cmp_greater_equal(region_size(), length));
    auto data = current.consume(length);
    item = T{(const typename T::value_type *)data.data(), length};
    return {};
  }

  constexpr auto unwind_tag(uint32_t tag) {
    auto tag_len = varint_size<varint_encoding::normal>(tag);
    basic_in<byte_type, Context, contiguous> dup(*this);
    dup.current.revert(tag_len);
    return dup;
  }

  constexpr status operator()(auto &&...item) {
    status result;
    (void)(((result = deserialize(item)).ok()) && ...);
    return result;
  }

  constexpr std::size_t count_number_of_varints_in_region(std::size_t n) {
    auto [data, remaining] = current.subspan(0, n).split(n - (n % 8));

    std::size_t result = 0;
    auto popcount = [](uint64_t v) -> int {
#if defined(__x86_64__) && defined(__GNUC__) && !defined(__clang__)
      if (!std::is_constant_evaluated()) {
        if (__builtin_cpu_supports("popcnt")) {
          int64_t count;
          __asm__("popcntq %1, %0" : "=r"(count) : "rm"(v));
          return count;
        }
      }
#endif
      return std::popcount(v);
    };

    while (data.size()) {
      uint64_t v = 0;
      auto bytes = data.consume(sizeof(v));
      std::memcpy(&v, bytes.data(), sizeof(v));
      result += static_cast<std::size_t>(popcount(~v & 0x8080808080808080ULL));
    }

    if (remaining.size()) {
      uint64_t v = UINT64_MAX;
      std::memcpy(&v, remaining.data(), remaining.size());
      result += static_cast<std::size_t>(popcount(~v & 0x8080808080808080ULL));
    }
    return result;
  }

  // Given the fact that the next n bytes are all variable length integers,
  // find the number of integers in the range.
  constexpr std::optional<std::size_t> number_of_varints(std::uint32_t bytes_count) {
    std::ptrdiff_t num_bytes = bytes_count;
    if (region_size() >= num_bytes) [[likely]] {
      if (std::bit_cast<int8_t>(current[bytes_count - 1]) < 0) [[unlikely]] {
        // if the last element is unterminated, just return empty to indicate error
        return {};
      }
      return count_number_of_varints_in_region(bytes_count);
    } else if (num_bytes <= in_avail()) {
      if constexpr (!contiguous) {
        basic_in archive(*this);
        std::size_t result = 0;
        while (num_bytes > 0 && in_avail() > 0) {
          archive.maybe_advance_region();
          if (num_bytes > archive.region_size()) {
            auto n = archive.region_size();
            result += archive.count_number_of_varints_in_region(n);
            archive.current.consume(n);
            num_bytes -= static_cast<uint32_t>(n);
          } else {
            if (std::bit_cast<int8_t>(archive.current[num_bytes - 1]) < 0) [[unlikely]] {
              // if the last element is unterminated, just return empty to indicate error
              return {};
            }
            return result + archive.count_number_of_varints_in_region(num_bytes);
          }
        }
      }
    }
    return {};
  }

  constexpr std::uint32_t read_tag() {
    maybe_advance_region();
    // Safety invariant: input regions provide at least 10 readable bytes (slope/patch buffer).
    std::int64_t res; // NOLINT(cppcoreguidelines-init-variables)
    if (auto p = shift_mix_parse_varint<std::uint32_t, 4>(current, res); p <= current._end) {
      current.advance_to(p);
      return static_cast<std::uint32_t>(res);
    }
    return 0;
  }

  constexpr bool match_tag(std::uint32_t tag) {
    maybe_advance_region();
    std::int64_t res; // NOLINT(cppcoreguidelines-init-variables)
    if (auto p = shift_mix_parse_varint<std::uint32_t, 4>(current, res); p <= current._end) {
      if (std::cmp_equal(res, tag)) {
        current.advance_to(p);
        return true;
      }
    }
    return false;
  }
};
// NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

constexpr status deserialize_unknown_fields(concepts::associative_container auto &unknown_fields, uint32_t field_num,
                                            std::size_t field_len, concepts::is_basic_in auto &archive) {
  return archive.deserialize_packed(field_len, unknown_fields[field_num]);
}

constexpr status deserialize_unknown_fields(concepts::uint32_pair_contiguous_range auto &unknown_fields,
                                            uint32_t field_num, std::size_t field_len,
                                            concepts::is_basic_in auto &archive) {
  auto itr = std::find_if(unknown_fields.begin(), unknown_fields.end(),
                          [field_num](const auto &e) { return e.first == field_num; });

  using fields_type = std::remove_cvref_t<decltype(unknown_fields)>;
  using bytes_type = typename fields_type::value_type::second_type;

  if (itr == unknown_fields.end() && archive.in_avail() == archive.region_size()) [[likely]] {
    bytes_type field_span;
    if (auto result = archive.deserialize_packed(field_len, detail::as_modifiable(archive.context, field_span));
        !result.ok()) {
      return result;
    }
    unknown_fields.push_back({field_num, field_span});
    return {};
  }
  // the extension with the same field number exists, append the content to the previously parsed.
  return archive.deserialize_packed(field_len,
                                    detail::as_modifiable(archive.context, const_cast<bytes_type &>(itr->second)));
}

constexpr status deserialize_unknown_fields(concepts::contiguous_byte_range auto &unknown_fields, uint32_t,
                                            std::size_t field_len, concepts::is_basic_in auto &archive) {
  return archive.deserialize_packed(field_len, unknown_fields);
}

constexpr void deserialize_unknown_enum(auto &unknown_fields, uint32_t field_num, int64_t value,
                                        concepts::is_basic_in auto &archive) {
  std::array<std::byte, 16> data{};
  auto tag = make_tag(field_num, wire_type::varint);
  auto *p = unchecked_pack_varint(varint{tag}, data.data());
  p = unchecked_pack_varint(varint{value}, p);
  std::span field_span{data.data(), static_cast<std::size_t>(p - data.data())};
  using unknown_fields_t = std::remove_cvref_t<decltype(unknown_fields)>;
  if constexpr (concepts::contiguous_byte_range<unknown_fields_t>) {
    util::append_range(unknown_fields, field_span);
  } else if constexpr (concepts::associative_container<unknown_fields_t>) {
    util::append_range(unknown_fields[field_num], field_span);
  } else if constexpr (concepts::uint32_pair_contiguous_range<unknown_fields_t>) {
    auto itr = std::find_if(unknown_fields.begin(), unknown_fields.end(),
                            [field_num](const auto &e) { return e.first == field_num; });
    if (itr == unknown_fields.end()) {
      unknown_fields.push_back({field_num, field_span});
    } else {
      using bytes_type = typename unknown_fields_t::value_type::second_type;
      decltype(auto) v = detail::as_modifiable(archive.context, const_cast<bytes_type &>(itr->second));
      util::append_range(v, field_span);
    }
  }
}

template <typename T>
constexpr status skip_field(uint32_t tag, concepts::is_basic_in auto &archive, T &unknown_fields) {
  if constexpr (std::is_empty_v<T>) {
    return do_skip_field(tag, archive);
  } else {
    auto unwound_archive = archive.unwind_tag(tag);
    if (auto result = skip_fields_match_tag(tag, archive); !result.ok()) [[unlikely]] {
      return result;
    }

    auto field_len = static_cast<std::size_t>(unwound_archive.in_avail() - archive.in_avail());
    auto field_archive = unwound_archive.split(field_len);

    return deserialize_unknown_fields(unknown_fields, tag_number(tag), field_len, field_archive);
  }
}

constexpr status do_skip_field(uint32_t tag, concepts::is_basic_in auto &archive) {
  if (tag == 0) [[unlikely]] {
    return std::errc::bad_message;
  }
  switch (proto::tag_type(tag)) {
  case wire_type::varint:
    return archive.skip_varint();
  case wire_type::length_delimited:
    return archive.skip_length_delimited();
  case wire_type::fixed_64:
    return archive.skip(8);
  case wire_type::sgroup:
    return do_skip_group(tag_number(tag), archive);
  case wire_type::fixed_32:
    return archive.skip(4);
  default:
    return std::errc::bad_message;
  }
}

constexpr status skip_fields_match_tag(uint32_t tag, concepts::is_basic_in auto &archive) {
  if (auto result = do_skip_field(tag, archive); !result.ok()) {
    return result;
  }

  while (archive.match_tag(tag)) {
    if (auto result = do_skip_field(tag, archive); !result.ok()) {
      return result;
    }
  }
  return {};
}

constexpr status do_skip_group(uint32_t field_num, concepts::is_basic_in auto &archive) {
  while (archive.in_avail() > 0) {
    auto tag = archive.read_tag();

    const uint32_t next_field_num = tag_number(tag);
    const wire_type next_type = proto::tag_type(tag);

    if (next_type == wire_type::egroup && field_num == next_field_num) {
      return {};
    } else if (archive.in_avail() <= 0) [[unlikely]] {
      return std::errc::bad_message;
    }
    if (auto result = do_skip_field(tag, archive); !result.ok()) {
      return result;
    }
  }
  return std::errc::bad_message;
}

template <typename T>
constexpr std::optional<std::size_t> count_packed_elements(uint32_t length, concepts::is_basic_in auto &archive) {
  if constexpr (concepts::byte_deserializable<T>) {
    if (length % sizeof(T) == 0) [[likely]] {
      return length / sizeof(T);
    } else {
      return {};
    }
  } else if constexpr (std::same_as<T, bool> || std::same_as<T, boolean> || concepts::is_enum<T> ||
                       concepts::varint<T>) {
    return archive.number_of_varints(length);
  } else {
    static_assert(!sizeof(T));
  }
}

constexpr status count_unpacked_elements(uint32_t input_tag, std::size_t &count, concepts::is_basic_in auto &archive) {
  auto new_archive = archive.copy();
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-do-while)
  do {
    if (auto result = do_skip_field(input_tag, new_archive); !result.ok()) {
      return result;
    }

    ++count;

    if (new_archive.in_avail() == 0) {
      return {};
    }
  } while (new_archive.read_tag() == input_tag);
  return {};
}

constexpr status count_groups(uint32_t input_tag, std::size_t &count, concepts::is_basic_in auto &archive) {
  auto new_archive = archive.copy();
  if (tag_type(input_tag) != wire_type::sgroup) {
    return std::errc::bad_message;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-do-while)
  do {
    if (auto result = do_skip_group(tag_number(input_tag), new_archive); !result.ok()) {
      return result;
    }

    ++count;

    if (new_archive.in_avail() == 0) {
      return {};
    }
  } while (new_archive.read_tag() == input_tag);
  return {};
}

template <typename Meta>
constexpr status deserialize_packed_repeated(Meta, auto &&item, concepts::is_basic_in auto &archive,
                                             auto &unknown_fields) {
  using type = std::remove_reference_t<decltype(item)>;
  using value_type = typename type::value_type;

  using encode_type =
      std::conditional_t<std::same_as<typename Meta::type, void> || concepts::char_or_byte<value_type> ||
                             std::same_as<typename Meta::type, type>,
                         value_type, typename Meta::type>;

  vuint32_t byte_count;
  if (auto result = archive(byte_count); !result.ok()) [[unlikely]] {
    return result;
  }
  if (byte_count == 0) {
    if constexpr (concepts::char_or_byte<value_type>) {
      // for string or bytes, override existing value
      item = {};
    }
    return {};
  }

  decltype(auto) v = detail::as_modifiable(archive.context, item);
  if constexpr (requires { v.resize(1); }) {
    [[maybe_unused]] auto old_size = std::ssize(v);
    auto result = deserialize_packed_repeated_with_byte_count<encode_type>(v, byte_count, archive);
    if constexpr (Meta::closed_enum()) {
      if (!result.ok()) [[unlikely]] {
        return result;
      }
      auto start_itr = std::next(v.begin(), old_size);
      auto itr = std::remove_if(start_itr, v.end(), [&](auto v) {
        if (!Meta::valid_enum_value(v)) {
          deserialize_unknown_enum(unknown_fields, Meta::number, std::to_underlying(v), archive);
          return true;
        }
        return false;
      });
      v.resize(static_cast<std::size_t>(std::distance(v.begin(), itr)));
    }
    return result;
  } else {
    using context_t = std::decay_t<decltype(archive.context)>;
    static_assert(concepts::has_memory_resource<context_t>, "memory resource is required");
    return {};
  }
}

template <typename EncodeType>
constexpr status deserialize_packed_repeated_with_byte_count(concepts::resizable auto &&v, vuint32_t byte_count,
                                                             concepts::is_basic_in auto &archive) {
  // packed repeated vector,
  auto n = count_packed_elements<EncodeType>(static_cast<uint32_t>(byte_count), archive);
  if (!n.has_value()) {
    return std::errc::bad_message;
  }
  std::size_t size = *n;
  if constexpr (std::same_as<EncodeType, boolean> || std::same_as<EncodeType, bool>) {
    return archive.deserialize_packed_boolean(size, v);
  } else if constexpr (concepts::char_or_byte<EncodeType>) {
    v.resize(0);
    return archive.deserialize_packed(size, v);
  } else if constexpr (concepts::byte_deserializable<EncodeType>) {
    return archive.deserialize_packed(size, v);
  } else if constexpr (concepts::is_enum<EncodeType>) {
    return archive.template deserialize_packed_varint<vint64_t>(byte_count, size, v);
  } else {
    static_assert(concepts::varint<EncodeType>);
    return archive.template deserialize_packed_varint<EncodeType>(byte_count, size, v);
  }
}

template <typename MetaType, typename ValueType>
struct deserialize_element_type {
  using type = ValueType;
};

template <concepts::is_map_entry MetaType, typename ValueType>
struct deserialize_element_type<MetaType, ValueType> {
  using type = typename MetaType::mutable_type;
};

// NOLINTBEGIN(readability-function-cognitive-complexity)
template <typename Meta>
constexpr status deserialize_unpacked_repeated(Meta meta, uint32_t tag, auto &&item,
                                               concepts::is_basic_in auto &archive, auto &unknown_fields) {
  using type = std::remove_reference_t<decltype(item)>;
  using value_type = typename type::value_type;

  decltype(auto) v = detail::as_modifiable(archive.context, item);
  if (tag_type(tag) !=
      tag_type<std::conditional_t<std::same_as<typename Meta::type, void>, value_type, typename Meta::type>>()) {
    return std::errc::bad_message;
  }

  std::size_t count = 0;
  if (auto result = count_unpacked_elements(tag, count, archive); !result.ok()) [[unlikely]] {
    return result;
  }
  auto old_size = item.size();
  const std::size_t new_size = item.size() + count;
  using element_type = typename deserialize_element_type<typename Meta::type, value_type>::type;
  auto deserialize_element = [&](element_type &element) {
    if constexpr (concepts::has_meta<element_type>) {
      return deserialize_sized(element, archive);
    } else {
      return deserialize_field(element, meta, tag, archive, unknown_fields);
    }
  };

  if constexpr (concepts::associative_container<type>) {
    if constexpr (concepts::flat_map<type>) {
      reserve(v, new_size);
    } else if constexpr (requires { v.reserve(new_size); }) {
      v.reserve(new_size);
    }
  } else {
    if constexpr (meta.closed_enum()) {
      v.reserve(new_size);
    } else if constexpr (requires { v.resize(new_size); }) {
      v.resize(new_size);
    }
  }

  for (auto i = old_size; i < new_size; ++i) {
    if constexpr (concepts::associative_container<type>) {
      element_type element;

      if (auto result = deserialize_element(element); !result.ok()) {
        return result;
      }

      auto val = static_cast<value_type>(std::move(element));
      if constexpr (requires { v.insert_or_assign(std::move(val.first), std::move(val.second)); }) {
        v.insert_or_assign(std::move(val.first), std::move(val.second));
      } else { // pre-C++23 std::map
        v[std::move(val.first)] = std::move(val.second);
      }
    } else if constexpr (std::same_as<element_type, value_type> && !meta.closed_enum()) {
      if (auto result = deserialize_element(v[i]); !result.ok()) [[unlikely]] {
        return result;
      }
    } else {
      element_type element;
      if (auto result = deserialize_element(element); !result.ok()) [[unlikely]] {
        return result;
      }
      if constexpr (meta.closed_enum()) {
        if (meta.valid_enum_value(element)) {
          v.push_back(element);
        } else {
          deserialize_unknown_enum(unknown_fields, tag_number(tag), std::to_underlying(element), archive);
        }
      } else {
        v[i] = std::move(static_cast<value_type>(std::move(element)));
      }
    }

    if (i < new_size - 1) {
      // no error handling here, because  `count_unpacked_elements()` already checked the tag
      archive.maybe_advance_region();
      (void)archive.read_tag();
    }
  }
  return {};
}
// NOLINTEND(readability-function-cognitive-complexity)

template <typename Meta>
constexpr status deserialize_repeated_group(Meta, uint32_t tag, auto &&item, concepts::is_basic_in auto &archive) {
  decltype(auto) v = detail::as_modifiable(archive.context, item);

  std::size_t count = 0;
  if (auto result = count_groups(tag, count, archive); !result.ok()) [[unlikely]] {
    return result;
  }
  auto old_size = item.size();
  const std::size_t new_size = item.size() + count;

  v.resize(new_size);

  for (auto i = old_size; i < new_size; ++i) {
    if (auto result = deserialize_group(tag_number(tag), v[i], archive); !result.ok()) [[unlikely]] {
      return result;
    }

    if (i < new_size - 1) {
      // no error handling here, because  `count_groups()` already checked the tag
      archive.maybe_advance_region();
      (void)archive.read_tag();
    }
  }
  return {};
}

constexpr status deserialize_field(boolean &item, auto, uint32_t tag, concepts::is_basic_in auto &archive,
                                   auto & /* unknown_fields*/) {
  if (tag_type(tag) != wire_type::varint) [[unlikely]] {
    return std::errc::bad_message;
  }
  return archive(item.value);
}

template <typename Meta>
constexpr status deserialize_field(concepts::is_enum auto &item, Meta, uint32_t tag,
                                   concepts::is_basic_in auto &archive, auto &unknown_fields) {
  if (tag_type(tag) != wire_type::varint) [[unlikely]] {
    return std::errc::bad_message;
  }
  vint64_t value;
  if (auto result = archive(value); !result.ok()) [[unlikely]] {
    return result;
  }
  using enum_type = std::remove_reference_t<decltype(item)>;

  if constexpr (Meta::closed_enum() && Meta::explicit_presence()) {
    if (!Meta::valid_enum_value(static_cast<enum_type>(value.value))) [[unlikely]] {
      deserialize_unknown_enum(unknown_fields, Meta::number, value, archive);
      return std::errc::value_too_large;
    }
  }

  item = static_cast<enum_type>(value.value);

  return {};
}

constexpr status deserialize_field(concepts::optional_indirect_view auto &item, auto meta, uint32_t tag,
                                   concepts::is_basic_in auto &archive, auto &unknown_fields) {
  using context_t = std::decay_t<decltype(archive.context)>;
  static_assert(concepts::has_memory_resource<context_t>, "memory resource is required");
  using element_type = std::remove_cvref_t<decltype(*item)>;
  if (item.has_value()) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    return deserialize_field(const_cast<element_type &>(*item), meta, tag, archive, unknown_fields);
  } else {
    void *buffer = archive.context.memory_resource().allocate(sizeof(element_type), alignof(element_type));
    auto loaded = new (buffer) element_type; // NOLINT(cppcoreguidelines-owning-memory)
    if (auto result = deserialize_field(*loaded, meta, tag, archive, unknown_fields); !result.ok()) [[unlikely]] {
      return result;
    }
    item = loaded;
    return {};
  }
}

constexpr status deserialize_field(concepts::indirect auto &item, auto meta, uint32_t tag,
                                   concepts::is_basic_in auto &archive, auto &unknown_fields) {
  return deserialize_field(*item, meta, tag, archive, unknown_fields);
}

template <typename T>
constexpr status deserialize_field(indirect_view<T> &item, auto meta, uint32_t tag, concepts::is_basic_in auto &archive,
                                   auto &unknown_fields) {
  void *buffer = archive.context.memory_resource().allocate(sizeof(T), alignof(T));
  auto loaded = new (buffer) T; // NOLINT(cppcoreguidelines-owning-memory)
  item = loaded;
  return deserialize_field(*loaded, meta, tag, archive, unknown_fields);
}

constexpr status deserialize_field(bool_proxy item, auto meta, uint32_t tag, concepts::is_basic_in auto &archive,
                                   auto &unknown_fields) {
  bool v; // NOLINT(cppcoreguidelines-init-variables)
  if (auto result = deserialize_field(v, meta, tag, archive, unknown_fields); !result.ok()) [[unlikely]] {
    return result;
  }
  item = v;
  return {};
}

template <concepts::optional T>
  requires(!concepts::optional_indirect_view<T>)
constexpr status deserialize_field(T &item, auto meta, uint32_t tag, concepts::is_basic_in auto &archive,
                                   auto &unknown_fields) {
  status result;
  using type = std::remove_reference_t<T>;
  if constexpr (meta.closed_enum()) {
    typename type::value_type tmp;
    result = deserialize_field(tmp, meta, tag, archive, unknown_fields);
    if (result.ok()) [[likely]] {
      item = tmp;
    } else if (result == std::errc::value_too_large) {
      return {};
    }
  } else if constexpr (concepts::singular<typename type::value_type>) {
    result = deserialize_field(item.emplace(), meta, tag, archive, unknown_fields);
  } else if constexpr (requires { item.emplace(); }) {
    decltype(auto) value = item.has_value() ? *item : item.emplace();
    result = deserialize_field(value, meta, tag, archive, unknown_fields);
  } else {
    item = typename type::value_type{};
    result = deserialize_field(*item, meta, tag, archive, unknown_fields);
  }

  return result;
}

template <typename Meta>
constexpr status deserialize_field(concepts::oneof_type auto &item, Meta, uint32_t tag,
                                   concepts::is_basic_in auto &archive, auto &unknown_fields) {
  using type = std::remove_reference_t<decltype(item)>;
  static_assert(std::same_as<std::remove_cvref_t<decltype(std::get<0>(type{}))>, std::monostate>);
  return deserialize_oneof<0, typename Meta::alternatives_meta>(tag, item, archive, unknown_fields);
}

template <typename Meta>
constexpr status deserialize_field(concepts::arithmetic auto &item, Meta meta, uint32_t tag,
                                   concepts::is_basic_in auto &archive, auto &unknown_fields) {
  using type = std::remove_reference_t<decltype(item)>;
  using serialize_type = typename util::get_serialize_type<Meta, type>::type;
  if constexpr (!std::same_as<type, serialize_type>) {
    serialize_type value;
    if (auto result = deserialize_field(value, meta, tag, archive, unknown_fields); !result.ok()) [[unlikely]] {
      return result;
    }
    item = static_cast<type>(value);
    return {};
  } else {
    if (tag_type<type>() != tag_type(tag)) [[unlikely]] {
      return std::errc::bad_message;
    }
    return archive(item);
  }
}

constexpr status deserialize_field(concepts::has_meta auto &item, auto meta, uint32_t tag,
                                   concepts::is_basic_in auto &archive, auto & /* unknown_fields*/) {
  if constexpr (!meta.is_delimited()) {
    if (tag_type(tag) == wire_type::length_delimited) [[likely]] {
      return deserialize_sized(item, archive);
    } else {
      return std::errc::bad_message;
    }
  } else {
    if (tag_type(tag) == wire_type::sgroup) [[likely]] {
      return deserialize_group(tag_number(tag), item, archive);
    } else {
      return std::errc::bad_message;
    }
  }
}

template <typename Meta>
constexpr status deserialize_field(std::ranges::range auto &item, Meta meta, uint32_t tag,
                                   concepts::is_basic_in auto &archive, auto &unknown_fields) {
  using type = std::remove_reference_t<decltype(item)>;

  if constexpr (concepts::contiguous_byte_range<type>) {
    if (tag_type(tag) != wire_type::length_delimited) [[unlikely]] {
      return std::errc::bad_message;
    }
    if (auto result = deserialize_packed_repeated(meta, item, archive, unknown_fields); !result.ok()) {
      return result;
    }
    return utf8_validation_failed(meta, item) ? std::errc::bad_message : std::errc{};
  } else if constexpr (meta.is_delimited()) {
    // repeated group
    return deserialize_repeated_group(meta, tag, item, archive);
  } else { // repeated non-group
    if constexpr (concepts::maybe_packed_type<type>) {
      if (tag_type(tag) == wire_type::length_delimited) [[likely]] {
        return deserialize_packed_repeated(meta, item, archive, unknown_fields);
      }
    }
    return deserialize_unpacked_repeated(meta, tag, item, archive, unknown_fields);
  }
}

template <std::size_t Index, concepts::tuple Meta>
constexpr status deserialize_oneof(uint32_t tag, auto &&item, concepts::is_basic_in auto &archive,
                                   auto &unknown_fields) {
  if constexpr (Index < std::tuple_size_v<Meta>) {
    using meta = typename std::tuple_element_t<Index, Meta>;
    if (meta::number == tag_number(tag)) {
      if constexpr (meta::closed_enum()) {
        std::variant_alternative_t<Index + 1, std::decay_t<decltype(item)>> v;
        auto result = deserialize_field(v, meta{}, tag, archive, unknown_fields);
        if (result.ok()) [[likely]] {
          std::get<Index + 1>(item) = v;
          return {};
        } else if (result == std::errc::value_too_large) {
          return {};
        }
        return result;
      } else if constexpr (requires { item.template emplace<Index + 1>(); }) {
        auto &v = (item.index() == Index + 1) ? std::get<Index + 1>(item) : item.template emplace<Index + 1>();
        return deserialize_field(v, meta{}, tag, archive, unknown_fields);
      } else {
        if (item.index() != Index + 1) {
          item = std::variant_alternative_t<Index + 1, std::decay_t<decltype(item)>>{};
        }
        return deserialize_field(std::get<Index + 1>(item), meta{}, tag, archive, unknown_fields);
      }
    } else {
      return deserialize_oneof<Index + 1, Meta>(tag, std::forward<decltype(item)>(item), archive, unknown_fields);
    }
  } else {
    unreachable();
    return {};
  }
}

template <std::uint32_t Index>
constexpr status deserialize_field_by_index(uint32_t tag, concepts::has_meta auto &item,
                                            concepts::is_basic_in auto &archive, auto &&unknown_fields) {
  if constexpr (Index != UINT32_MAX) {
    using type = std::remove_reference_t<decltype(item)>;
    using Meta = typename util::field_meta_of<type, Index>::type;
    return deserialize_field(Meta::get(item), Meta(), tag, archive, unknown_fields);
  } else if (archive.in_avail() > 0) {
    return skip_field(tag, archive, unknown_fields);
  } else {
    return std::errc::bad_message;
  }
}

constexpr status deserialize_field_by_tag(uint32_t tag, concepts::has_meta auto &item,
                                          concepts::is_basic_in auto &archive, auto &&unknown_fields) {
  using type = std::remove_cvref_t<decltype(item)>;
  using dispatcher_t = util::reverse_indices<type>;
  if (tag_number(tag) == 0) {
    return std::errc::bad_message;
  }
  return dispatcher_t::dispatch(tag_number(tag), [&](auto index) {
    return deserialize_field_by_index<decltype(index)::value>(tag, item, archive, unknown_fields);
  });
}

constexpr auto &get_unknown_fields(auto &item)
  requires requires { item.unknown_fields_.fields; }
{
  return item.unknown_fields_.fields;
}

constexpr auto &get_unknown_fields(auto &item)
  requires requires { item.extensions; }
{
  return item.extensions.fields;
}

constexpr std::monostate get_unknown_fields(auto &) { return {}; }

constexpr status deserialize_group(uint32_t field_num, auto &&item, concepts::is_basic_in auto &archive) {
  decltype(auto) unknown_fields = get_unknown_fields(item);
  decltype(auto) modifiable_unknown_fields = detail::as_modifiable(archive.context, unknown_fields);
  while (archive.in_avail() > 0) {
    auto tag = archive.read_tag();
    if (proto::tag_type(tag) == wire_type::egroup && field_num == tag_number(tag)) {
      return {};
    }
    if (auto result = deserialize_field_by_tag(tag, item, archive, modifiable_unknown_fields); !result.ok())
        [[unlikely]] {
      return result;
    }
  }

  return std::errc::bad_message;
}

constexpr status deserialize(auto &&item, concepts::is_basic_in auto &archive) {
  if constexpr (requires { item.is_map_entry(); }) {
    if (item.is_map_entry() && archive.in_avail() > 0) {
      // Map entries must start with field number 1 (the key), matching protobuf validation.
      auto tag = std::bit_cast<uint8_t>(*archive.data());
      if (tag_number(tag) != 1) {
        return std::errc::bad_message;
      }
    }
  }

  decltype(auto) unknown_fields = get_unknown_fields(item);
  decltype(auto) modifiable_unknown_fields = detail::as_modifiable(archive.context, unknown_fields);
  while (archive.in_avail() > 0) {
    auto tag = archive.read_tag();
    if (auto result = deserialize_field_by_tag(tag, item, archive, modifiable_unknown_fields); !result.ok()) {
      [[unlikely]] return result;
    }
  }

  return archive.in_avail() == 0 ? std::errc{} : std::errc::bad_message;
}

constexpr status deserialize_sized(auto &&item, concepts::is_basic_in auto &archive) {
  vuint32_t len;
  if (auto result = archive(len); !result.ok()) [[unlikely]] {
    return result;
  }
  if (len == 0) [[unlikely]] {
    if constexpr (requires { item.is_map_entry(); }) {
      if (item.is_map_entry()) {
        return std::errc::bad_message;
      }
    }
    return {};
  }

  if (len < archive.in_avail()) [[likely]] {
    auto new_archive = archive.split(len);
    return deserialize(item, new_archive);
  } else if (len == archive.in_avail()) {
    return deserialize(item, archive);
  }
  return std::errc::bad_message;
}

constexpr status extract_length_delimited_field(uint32_t number, bytes_view &bytes, concepts::is_basic_in auto &archive)
  requires(std::remove_cvref_t<decltype(archive)>::contiguous)
{
  while (archive.in_avail() > 0) {
    auto tag = archive.read_tag();

    if (tag_number(tag) == number) {
      if (tag_type(tag) != wire_type::length_delimited) {
        return std::errc::bad_message;
      }
      vuint32_t len;
      if (auto result = archive(len); !result.ok() || len == 0) [[unlikely]] {
        return result;
      }

      if (len <= archive.in_avail()) [[likely]] {
        return archive.read_bytes(len, bytes);
      }
      return std::errc::bad_message;
    } else if (auto result = do_skip_field(tag, archive); !result.ok()) {
      return result;
    }
  }
  return archive.in_avail() == 0 ? std::errc{} : std::errc::bad_message;
}

template <typename Context, typename Byte>
struct contiguous_input_archive_base {
  std::array<Byte, patch_buffer_size> patch_buffer;
  std::array<input_buffer_region<Byte>, 2> regions = {};
  constexpr explicit contiguous_input_archive_base(const auto &buffer, Context &) {
    regions[1] = input_buffer_region<Byte>{std::span{std::ranges::data(buffer), std::ranges::size(buffer)}};
  }
};

// when memory resource is used, the patch buffer must come from it because
// the decoded string or bytes may refer to the memory in patch buffer
template <concepts::has_memory_resource Context, typename Byte>
struct contiguous_input_archive_base<Context, Byte> {
  std::span<Byte> patch_buffer;
  std::array<input_buffer_region<Byte>, 2> regions = {};
  constexpr explicit contiguous_input_archive_base(const auto &buffer, Context &context)
      : patch_buffer(static_cast<Byte *>(context.memory_resource().allocate(patch_buffer_size, 1)), patch_buffer_size) {
    regions[1] = input_buffer_region<Byte>{std::span{std::ranges::data(buffer), std::ranges::size(buffer)}};
  }
};

template <concepts::is_pb_context Context, typename Byte>
struct contiguous_input_archive : contiguous_input_archive_base<Context, Byte>, basic_in<Byte, Context, true> {
  constexpr contiguous_input_archive(const auto &buffer, Context &context) noexcept
      : contiguous_input_archive_base<Context, Byte>(buffer, context),
        basic_in<Byte, Context, true>(this->regions, this->patch_buffer, context) {}

  constexpr ~contiguous_input_archive() noexcept = default;
  contiguous_input_archive(const contiguous_input_archive &) = delete;
  contiguous_input_archive(contiguous_input_archive &&) = delete;
  contiguous_input_archive &operator=(const contiguous_input_archive &) = delete;
  contiguous_input_archive &operator=(contiguous_input_archive &&) = delete;
};

template <concepts::contiguous_byte_range Buffer, concepts::is_pb_context Context>
contiguous_input_archive(const Buffer &,
                         Context &) -> contiguous_input_archive<Context, std::ranges::range_value_t<Buffer>>;

constexpr status deserialize(auto &item, concepts::contiguous_byte_range auto const &buffer) {
  pb_context<> ctx;
  return deserialize(item, buffer, ctx);
}

constexpr status deserialize(auto &item, std::span<const std::byte> buffer, concepts::is_pb_context auto &context) {
  contiguous_input_archive archive{buffer, context};
  return deserialize(item, archive);
}

constexpr status deserialize(auto &item, concepts::contiguous_byte_range auto const &buffer,
                             concepts::is_pb_context auto &context) {
  if (std::is_constant_evaluated()) {
    contiguous_input_archive archive{buffer, context};
    return deserialize(item, archive);
  } else {
    contiguous_input_archive archive{std::as_bytes(std::span{std::ranges::data(buffer), std::ranges::size(buffer)}),
                                     context};
    return deserialize(item, archive);
  }
}

status deserialize(auto &item, concepts::is_pb_context auto &context, concepts::chunked_byte_range auto const &buffer,
                   std::span<input_buffer_region<const std::byte>> regions, std::span<std::byte> patch_buffer_cache) {
  constexpr bool is_contiguous = false;
  auto archive =
      basic_in<std::byte, std::decay_t<decltype(context)>, is_contiguous>(buffer, regions, patch_buffer_cache, context);
  return deserialize(item, archive);
}

status deserialize(auto &item, concepts::chunked_byte_range auto const &buffer,
                   concepts::is_pb_context auto &context) {
  const auto num_segments = std::size(buffer);
  const auto num_regions = num_segments * 2;
  const auto patch_buffer_bytes_count = num_segments * patch_buffer_size;

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
  std::array<std::byte, 1024> tmp_buffer;
  std::pmr::monotonic_buffer_resource mr{tmp_buffer.data(), tmp_buffer.size()};

  std::pmr::vector<std::byte> patch_buffer(patch_buffer_bytes_count, &mr);
  std::pmr::vector<input_buffer_region<std::byte>> regions(num_regions, &mr);

  std::ranges::transform(
      buffer, std::next(regions.begin(), static_cast<std::ptrdiff_t>(num_segments)), [](const auto &b) {
        return input_buffer_region<std::byte>{std::as_bytes(std::span{std::ranges::data(b), std::ranges::size(b)})};
      });

  constexpr bool is_contiguous = false;
  auto archive = basic_in<std::byte, std::decay_t<decltype(context)>, is_contiguous>(
      std::span{regions.data(), regions.size()}, std::span{patch_buffer.data(), patch_buffer.size()}, context);
  return deserialize(item, archive);
}

} // namespace pb_serializer
} // namespace hpp::proto
// NOLINTEND(bugprone-easily-swappable-parameters)
