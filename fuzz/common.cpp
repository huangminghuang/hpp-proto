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

namespace {
using factory_expected_t = decltype(hpp_proto::dynamic_message_factory::create(std::declval<std::vector<char> &>()));
factory_expected_t factory{std::unexpected(hpp_proto::dynamic_message_errc::unknown_message_name)};
} // namespace

hpp_proto::dynamic_message_factory &get_factory() {
  assert(factory.has_value());
  return factory.value();
}

// NOLINTNEXTLINE(readability-non-const-parameter)
extern "C" __attribute__((visibility("default"))) int LLVMFuzzerInitialize(int *pargc, char ***pargv) {
  std::span<char *> args(*pargv, *pargc);
  auto desc_file = std::filesystem::path(args[0]).parent_path() / "unittest.desc.binpb";
  if (!std::filesystem::exists(desc_file)) {
    std::cerr << "cannot find unittest.desc.binpb\n";
    return -1;
  }

  auto result = hpp_proto::dynamic_message_factory::create(read_file(desc_file));
  if (!result.has_value()) {
    std::cerr << "failed to initialize dynamic_message_factory\n";
    return -1;
  }
  factory = std::move(result);
  return 0;
}
