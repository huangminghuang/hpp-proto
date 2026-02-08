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
  if (!in.read(contents.data(), static_cast<std::streamsize>(contents.size()))) {
    return {};
  }
  return contents;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables,misc-use-anonymous-namespace)
hpp_proto::dynamic_message_factory factory;

// NOLINTNEXTLINE(readability-non-const-parameter)
extern "C" __attribute__((visibility("default"))) int LLVMFuzzerInitialize(int *pargc, char ***pargv) {
  std::span<char *> args(*pargv, *pargc);
  auto desc_file = std::filesystem::path(args[0]).parent_path() / "unittest.desc.binpb";
  if (!std::filesystem::exists(desc_file)) {
    std::cerr << "cannot find unittest.desc.binpb\n";
    return -1;
  }

  return factory.init(read_file(desc_file)) ? 0 : -1;
}
