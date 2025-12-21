#include <fstream>
#include <vector>

std::vector<char> read_file(const char *filename) {
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  std::vector<char> contents;
  in.seekg(0, std::ios::end);
  contents.resize(static_cast<std::size_t>(in.tellg()));
  in.seekg(0, std::ios::beg);
  in.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  return contents;
}