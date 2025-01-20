#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include <google/protobuf/unittest_proto3.pb.hpp>

inline std::string read_file(const char *filename) {
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(in.tellg());
  in.seekg(0, std::ios::beg);
  in.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  return contents;
}

int main(int argc, const char **argv) {
  std::string data = read_file(argv[1]);
  FuzzedDataProvider provider((const uint8_t *)data.data(), data.size());
  std::vector<std::vector<char>> input;

  while (input.size() < 9) {
    auto v = provider.ConsumeBytes<char>(provider.ConsumeIntegralInRange<int>(10, 128));
    if (v.empty()) {
      break;
    }
    input.push_back(std::move(v));
  };

  auto v = provider.ConsumeRemainingBytes<char>();
  if (!v.empty())
    input.push_back(std::move(v));

  proto3_unittest::TestAllTypes message;
  auto status = hpp::proto::read_proto(message, input);
  return status.ok() ? 0 : 1;
}