
#pragma once

#include <fstream>
#include <string>
#include <vector>
#include <span>
#include <hpp_proto/pb_serializer.h>

inline std::string descriptorset_from_file(const char* filename) {
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(in.tellg());
  in.seekg(0, std::ios::beg);
  in.read(&contents[0], contents.size());
  return contents;
}

template <typename T>
std::string to_hex(const T &data) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string result;
  result.resize(data.size() * 2);
  int index = 0;
  for (auto b : data) {
    unsigned char c = static_cast<unsigned char>(b);
    result[index++] = qmap[c >> 4];
    result[index++] = qmap[c & '\x0F'];
  }
  return result;
}

namespace std {
inline std::ostream &operator<<(std::ostream &os, std::byte b) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  char result[] = "\\x00";
  unsigned char c = static_cast<unsigned char>(b);
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

struct monotonic_memory_resource {
  std::size_t size;
  void *mem = 0;
  void *cur = 0;
  monotonic_memory_resource(std::size_t sz) : size(sz), mem(malloc(sz)), cur(mem) {}
  ~monotonic_memory_resource() { free(mem); }
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

template <typename T, hpp::proto::encoding_rule Rule>
constexpr bool ensure_all_fields_encoding_rule() {
  using meta = typename hpp::proto::traits::meta_of<T>::type;
  return std::apply([](auto... field_meta) { return ((field_meta.encoding == Rule) && ...); }, meta());
}

std::span<const std::byte> to_byte_span(const char *str) {
  return std::span<const std::byte>{reinterpret_cast<const std::byte *>(str), strlen(str)};
}

template <typename RG1, typename RG2>
bool equal_range(RG1 &&r1, RG2 &&r2) {
  return std::equal(r1.begin(), r1.end(), r2.begin(), r2.end());
}

template <typename RG1, typename RG2, typename BinaryPredicate>
bool equal_range(RG1 &&r1, RG2 &&r2, BinaryPredicate p) {
  return std::equal(r1.begin(), r1.end(), r2.begin(), r2.end(), p);
}
