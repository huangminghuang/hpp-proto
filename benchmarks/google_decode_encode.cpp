#include "benchmark_messages_proto3.pb.h"
#include <fstream>
#include <iostream>

std::string read_data_file(const char *filename) {
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

  benchmarks::proto3::GoogleMessage1 message;
  if (!message.ParseFromArray(data.data(), static_cast<int>(data.size()))) {
    std::cerr << "decode failure\n";
    return 1;
  }
  if (!message.SerializeToString(&data)) {
    std::cerr << "encode failure\n";
    return 1;
  }
  return 0;
}