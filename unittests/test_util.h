
#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <span>
#include <algorithm>
#include <ranges>
#include <hpp_proto/pb_serializer.h>

namespace std {
inline std::ostream &operator<<(std::ostream &os, std::byte b) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  char result[] = "\\x00";
  const unsigned char c = static_cast<unsigned char>(b);
  result[2] = qmap[c >> 4];
  result[3] = qmap[c & '\x0F'];
  return os << result;
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

struct monotonic_buffer_resource {
  std::size_t size;
  void *mem = 0;
  void *cur = 0;
  monotonic_buffer_resource(std::size_t sz) : size(sz), mem(malloc(sz)), cur(mem) {}
  monotonic_buffer_resource(const monotonic_buffer_resource&) = delete;
  ~monotonic_buffer_resource() { free(mem); }
  void *allocate(std::size_t n, std::size_t alignment) {
    if (std::align(alignment, n, cur, size)) {
      size -= n;
      auto result = cur;
      cur = (char *)cur + n;
      return result;
    }
    throw std::bad_alloc{};
  }
};
