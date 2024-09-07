
#pragma once

#include <algorithm>
#include <fstream>
#include <hpp_proto/pb_serializer.hpp>
#include <ranges>
#include <span>
#include <string>
#include <vector>

inline std::string read_file(const char *filename) {
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(in.tellg());
  in.seekg(0, std::ios::beg);
  in.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  return contents;
}

std::array<char, 2> to_hex(hpp::proto::concepts::byte_type auto c) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  const auto uc = static_cast<unsigned char>(c);
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
  return {qmap[uc >> 4U], qmap[uc & 0x0FU]};
  // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
}

std::string to_hex(hpp::proto::concepts::contiguous_byte_range auto const &data) {
  std::string result;
  result.resize(data.size() * 2);
  int index = 0;
  for (auto b : data) {
    std::ranges::copy(to_hex(b), &result[index]);
    index += 2;
  }
  return result;
}

inline std::ostream &operator<<(std::ostream &os, const std::vector<std::byte> &bytes) { return os << to_hex(bytes); }

inline std::ostream &operator<<(std::ostream &os, std::span<const std::byte> bytes) { return os << to_hex(bytes); }

struct monotonic_buffer_resource {
  std::size_t size;
  std::unique_ptr<char[]> mem;
  void *cur = nullptr;
  explicit monotonic_buffer_resource(std::size_t sz) : size(sz), mem(new char[sz]), cur(mem.get()) {}
  monotonic_buffer_resource(const monotonic_buffer_resource &) = delete;
  monotonic_buffer_resource(monotonic_buffer_resource &&) = delete;

  monotonic_buffer_resource &operator=(const monotonic_buffer_resource &) = delete;
  monotonic_buffer_resource &operator=(monotonic_buffer_resource &&) = delete;

  ~monotonic_buffer_resource() = default;
  void *allocate(std::size_t n, std::size_t alignment) {
    if (std::align(alignment, n, cur, size) != nullptr) {
      size -= n;
      auto *result = cur;
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      cur = static_cast<char *>(cur) + n;
      // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      return result;
    }
    throw std::bad_alloc{};
  }
};

template <hpp::proto::compile_time_string str>
constexpr auto operator""_bytes_view() {
  return static_cast<hpp::proto::bytes_view>(hpp::proto::bytes_literal<str>{});
}

template <hpp::proto::compile_time_string str>
constexpr auto operator""_bytes() {
  return static_cast<std::vector<std::byte>>(hpp::proto::bytes_literal<str>{});
}
