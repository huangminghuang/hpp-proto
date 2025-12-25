#include <fstream>
#include <vector>
#include "common.hpp"

std::vector<char> read_file(const char *filename) {
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  std::vector<char> contents;
  in.seekg(0, std::ios::end);
  contents.resize(static_cast<std::size_t>(in.tellg()));
  in.seekg(0, std::ios::beg);
  in.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  return contents;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables,misc-use-anonymous-namespace)
hpp::proto::dynamic_message_factory factory;

extern "C" __attribute__((visibility("default"))) int LLVMFuzzerInitialize(int *, char ***) {
  return factory.init(read_file("../tests/unittest.desc.binpb")) ? 0 : -1;
}