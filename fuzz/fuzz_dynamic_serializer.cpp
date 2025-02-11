#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include <google/protobuf/map_unittest.desc.hpp>
#include <google/protobuf/unittest.desc.hpp>
#include <google/protobuf/unittest_proto3.desc.hpp>
#include <hpp_proto/dynamic_serializer.hpp>

using namespace std::string_view_literals;

const std::array messages_names = {"proto3_unittest.TestAllTypes"sv,      "proto3_unittest.TestUnpackedTypes"sv,
                                   "protobuf_unittest.TestAllTypes"sv,    "protobuf_unittest.TestMap"sv,
                                   "protobuf_unittest.TestPackedTypes"sv, "protobuf_unittest.TestUnpackedTypes"sv};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  auto ser = hpp::proto::dynamic_serializer::make(
      hpp::proto::file_descriptors::desc_set_google_protobuf_unittest_proto3_proto(),
      hpp::proto::file_descriptors::desc_set_google_protobuf_unittest_proto(),
      hpp::proto::file_descriptors::desc_set_google_protobuf_map_unittest_proto());

  FuzzedDataProvider fdp(data, size);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
  auto message_name = messages_names[fdp.ConsumeIntegralInRange<unsigned>(0, messages_names.size() - 1)];
  auto status = ser->proto_to_json(message_name, fdp.ConsumeRemainingBytes<char>());
  return status.has_value() ? 0 : 1;
}