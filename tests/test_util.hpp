
#pragma once

#include <algorithm>
#include <cstdio>
#include <hpp_proto/pb_serializer.hpp>
#include <iostream>
#include <ranges>
#include <span>
#include <string>
#include <vector>

inline std::string descriptorset_from_file(const char *filename) {
  std::string contents;
  std::unique_ptr<std::FILE, decltype(&std::fclose)> file{std::fopen(filename, "rb"), &std::fclose};
  auto f = file.get();
  if (f != nullptr) {
    std::fseek(f, 0, SEEK_END);
    contents.resize(std::ftell(f));
    std::fseek(f, 0, SEEK_SET);
    std::fread(contents.data(), 1, contents.size(), f);
  }
  return contents;
}

template <typename T>
std::string to_hex(const T &data) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string result;
  result.resize(data.size() * 2);
  int index = 0;
  for (auto b : data) {
    const auto c = static_cast<unsigned>(b);
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
    result[index++] = qmap[c >> 4U];
    result[index++] = qmap[c & 0x0FU];
    // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
  }
  return result;
}

// NOLINTBEGIN(cert-dcl58-cpp)
namespace std {
inline std::ostream &operator<<(std::ostream &os, std::byte b) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  char result[] = "\\x00";
  const auto c = static_cast<unsigned char>(b);
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
  result[2] = qmap[c >> 4U];
  result[3] = qmap[c & 0x0FU];
  // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
  return os << static_cast<const char *>(result);
}

inline std::ostream &operator<<(std::ostream &os, const std::vector<std::byte> &bytes) {
  for (auto b : bytes) {
    os << b;
  }
  return os;
}

inline std::ostream &operator<<(std::ostream &os, std::span<const std::byte> bytes) {
  for (auto b : bytes) {
    os << b;
  }
  return os;
}
} // namespace std
// NOLINTEND(cert-dcl58-cpp)

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
