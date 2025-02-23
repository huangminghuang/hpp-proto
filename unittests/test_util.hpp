
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

template <hpp::proto::compile_time_string str>
constexpr auto operator""_bytes_view() {
  hpp::proto::bytes_literal<str> data;
  return hpp::proto::bytes_view{data.data(), data.size()};
}

template <hpp::proto::compile_time_string str>
constexpr auto operator""_bytes() {
  return static_cast<std::vector<std::byte>>(hpp::proto::bytes_literal<str>{});
}
