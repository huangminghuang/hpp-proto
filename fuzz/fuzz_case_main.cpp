#include <fstream>
#include <iterator>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);

std::string read_file(const char *filename);

int main(int argc, char **argv) {
  if (argc != 2) {
    return 1;
  }
  if (LLVMFuzzerInitialize(&argc, &argv) != 0) {
    fprintf(stderr, "Factory not initialized\n");
    return -1;
  }
  const auto filename = *std::next(argv);
  std::string data = read_file(filename);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  return LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t *>(data.data()), data.size());
}
