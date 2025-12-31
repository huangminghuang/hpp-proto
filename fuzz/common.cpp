#include "common.hpp"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <vector>

std::vector<char> read_file(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in.is_open()) {
    return {};
  }
  std::vector<char> contents;
  in.seekg(0, std::ios::end);
  auto size = in.tellg();
  if (size <= 0) {
    return {};
  }
  contents.resize(static_cast<std::size_t>(size));
  in.seekg(0, std::ios::beg);
  in.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  return contents;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables,misc-use-anonymous-namespace)
hpp::proto::dynamic_message_factory factory;

extern "C" __attribute__((visibility("default"))) int LLVMFuzzerInitialize(int *, char ***) {
  std::filesystem::path desc_path = "unittest.desc.binpb";
  auto cflite_path = std::filesystem::path("build-out") / desc_path;
  if (std::filesystem::exists(cflite_path)) {
    desc_path = cflite_path;
  }
  

  if (!std::filesystem::exists(desc_path)) {
    std::cerr << "Could not find " << desc_path.c_str() << "\n";
    return -1;
  }

  return factory.init(read_file(desc_path)) ? 0 : -1;
}
