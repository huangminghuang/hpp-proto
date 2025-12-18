
#pragma once

#include <algorithm>
#include <fstream>
#include <hpp_proto/binpb.hpp>
#include <hpp_proto/json.hpp>
#include <ranges>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

inline std::string read_file(const std::string &filename) {
  std::ifstream in(filename.c_str(), std::ios::in | std::ios::binary);
  if (!in) { // Checks if the stream is in a failed state
    throw std::system_error{std::make_error_code(std::errc::no_such_file_or_directory), filename};
  }
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(static_cast<std::string::size_type>(in.tellg()));
  in.seekg(0, std::ios::beg);
  in.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  return contents;
}

std::array<char, 2> to_hex(hpp::proto::concepts::byte_type auto c) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  const auto uc = static_cast<unsigned char>(c);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
  return {qmap[uc >> 4U], qmap[uc & 0x0FU]};
}

std::string to_hex(hpp::proto::concepts::contiguous_byte_range auto const &data) {
  std::string result;
  result.resize(data.size() * 2);
  std::size_t index = 0;
  for (auto b : data) {
    std::ranges::copy(to_hex(b), &result[index]);
    index += 2;
  }
  return result;
}

template <hpp::proto::compile_time_string str>
constexpr auto operator""_bytes() {
  return hpp::proto::bytes_literal<str>{};
}

// NOLINTBEGIN(cert-dcl58-cpp)
namespace std {
template <glz::glaze_t T>
inline std::ostream &operator<<(ostream &os, const T &v) {
#ifndef HPP_PROTO_DISABLE_GLAZE
  return os << hpp::proto::write_json(v).value();
#else
  return os;
#endif
}

inline std::ostream &operator<<(std::ostream &os, const vector<byte> &bytes) { return os << to_hex(bytes); }
inline std::ostream &operator<<(std::ostream &os, span<const byte> bytes) { return os << to_hex(bytes); }

template <typename T>
inline std::ostream &operator<<(ostream &os, const vector<T> &c) {
  os << '[';
  if (!c.empty()) {
    std::for_each(c.begin(), c.end(), [&os](const T &v) { os << ", " << v; });
  }
  os << ']';
  return os;
}

template <typename Enum>
  requires std::is_enum_v<Enum>
inline std::ostream &operator<<(std::ostream &os, Enum value) {
  return os << static_cast<int64_t>(static_cast<std::underlying_type_t<Enum>>(value));
}

template <typename T, std::size_t ExtentL, typename U, std::size_t ExtentR>
inline bool operator==(std::span<T, ExtentL> lhs, std::span<U, ExtentR> rhs) {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  return std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

} // namespace std

namespace hpp::proto {
template <compile_time_string cts>
std::ostream &operator<<(std::ostream &os, bytes_literal<cts> v) {
  return os << std::span<const std::byte>(v);
}

template <typename T>
std::ostream &operator<<(std::ostream &os, const equality_comparable_span<T> &span) {
  os << '[';
  bool first = true;
  for (const auto &value : span) {
    if (!first) {
      os << ", ";
    }
    first = false;
    os << value;
  }
  os << ']';
  return os;
}
} // namespace hpp::proto

// NOLINTEND(cert-dcl58-cpp)

#ifdef __GNUC__
#ifdef __apple_build_version__
#pragma clang diagnostic ignored "-Wmissing-designated-field-initializers"
#else
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
#endif
