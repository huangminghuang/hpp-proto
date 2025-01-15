#include <google/protobuf/unittest_proto3.pb.hpp>
#include <fstream>


inline std::string read_file(const char *filename) {
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(in.tellg());
  in.seekg(0, std::ios::beg);
  in.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  return contents;
}

int main(int argc, const char** argv) {
  std::string data = read_file(argv[1]);
  proto3_unittest::TestAllTypes message;
  auto status = hpp::proto::read_proto(message, data);
  return status.ok() ? 0 : 1;
}