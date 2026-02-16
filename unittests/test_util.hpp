
#pragma once

#include <algorithm>
#include <fstream>
#include <hpp_proto/binpb.hpp>
#include <ostream>
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

std::array<char, 2> to_hex(hpp_proto::concepts::byte_type auto c) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  const auto uc = static_cast<unsigned char>(c);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
  return {qmap[uc >> 4U], qmap[uc & 0x0FU]};
}

std::string to_hex(hpp_proto::concepts::contiguous_byte_range auto const &data) {
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

template <hpp_proto::compile_time_string str>
constexpr auto operator""_bytes() {
  return hpp_proto::bytes_literal<str>{};
}

template <hpp_proto::compile_time_string cts>
std::ostream &operator<<(std::ostream &os, hpp_proto::bytes_literal<cts> v) {
  return os << std::span<const std::byte>(v);
}

template <hpp_proto::concepts::reservable_flat_map Map>
std::ostream &operator<<(std::ostream &os, const Map &map) {
  os << "{";
  bool is_first = true;
  for (const auto &entry : map) {
    if (!is_first) {
      os << ", ";
      is_first = false;
    }
    os << entry.first << ": " << entry.second;
  }
  return os;
}
