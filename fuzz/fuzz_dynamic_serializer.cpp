#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include <hpp_proto/dynamic_serializer.hpp>

using namespace std::string_view_literals;

const std::array messages_names = {"proto3_unittest.TestAllTypes"sv,      "proto3_unittest.TestUnpackedTypes"sv,
                                   "protobuf_unittest.TestAllTypes"sv,    "protobuf_unittest.TestMap"sv,
                                   "protobuf_unittest.TestPackedTypes"sv, "protobuf_unittest.TestUnpackedTypes"sv};

inline std::string read_file(const std::string &filename) {
  std::ifstream in(filename.c_str(), std::ios::in | std::ios::binary);
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(static_cast<std::string::size_type>(in.tellg()));
  in.seekg(0, std::ios::beg);
  in.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  return contents;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  auto descriptors = read_file("../tests/unittest.desc.binpb");
  auto ser = hpp::proto::dynamic_serializer::make(descriptors);

  FuzzedDataProvider fdp(data, size);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
  auto message_name = messages_names[fdp.ConsumeIntegralInRange<unsigned>(0, messages_names.size() - 1)];
  auto status = ser->proto_to_json(message_name, fdp.ConsumeRemainingBytes<char>());
  return status.has_value() ? 0 : 1;
}