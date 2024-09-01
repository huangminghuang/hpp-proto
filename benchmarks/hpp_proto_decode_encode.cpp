#include "owning/benchmark_messages_proto3.pb.hpp"
#include <fstream>
#include <iostream>

std::vector<char> read_data_file(const char *filename) {
  std::filebuf buf;
  if (buf.open(filename, std::ios::binary | std::ios::in) == nullptr) {
    std::cerr << "Open file " << filename << " for read failed\n";
    throw std::system_error{std::make_error_code(std::errc::no_such_file_or_directory)};
  }

  return {std::istreambuf_iterator<char>{&buf}, std::istreambuf_iterator<char>{}};
}

int main(int argc, const char **argv) {
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " filename\n";
    return 1;
  }
  auto data = read_data_file(argv[1]);
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

  owning::benchmarks::proto3::GoogleMessage1 message;
  if (!hpp::proto::read_proto(message, data).ok()) {
    std::cerr << "decode failure\n";
    return 1;
  }
  if (!hpp::proto::write_proto(message, data).ok()) {
    std::cerr << "encode failure\n";
    return 1;
  }
  return 0;
}