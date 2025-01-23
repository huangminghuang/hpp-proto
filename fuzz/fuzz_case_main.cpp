#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

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
  if (argc != 2) {
    return 1;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  std::string data = read_file(argv[1]);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  return LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t *>(data.data()), data.size());
}