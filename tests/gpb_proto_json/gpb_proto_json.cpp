#include "gpb_proto_json.hpp"
#include <fstream>
#ifndef GPB_PROTO_JSON_STATIC_DEFINE
#include <google/protobuf/compiler/importer.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/util/json_util.h>

namespace gpb_based {
namespace gpb = google::protobuf;
std::string proto_to_json(const gpb::DescriptorPool &pool, const char *message_name, std::string_view data) {
  const auto *message_descriptor = pool.FindMessageTypeByName(message_name);
  // NOLINTBEGIN(misc-const-correctness)
  gpb::DynamicMessageFactory factory(&pool);
  // NOLINTEND(misc-const-correctness)

  std::unique_ptr<gpb::Message> message{factory.GetPrototype(message_descriptor)->New()};
  message->ParseFromArray(data.data(), static_cast<int>(data.size()));

  std::string result;
  const gpb::util::JsonPrintOptions options;

  (void)gpb::util::MessageToJsonString(*message, &result, options);

  return result;
}

void write_file(const std::string &filename, std::string_view data) {
  std::ofstream file(filename, std::ios_base::binary);
  file.write(data.data(), static_cast<std::streamsize>(data.size()));
}

std::string proto_to_json(std::string_view filedescriptorset_stream, const char *message_name, std::string_view data) {
  gpb::FileDescriptorSet fileset;
  fileset.ParseFromArray(filedescriptorset_stream.data(), (int)filedescriptorset_stream.size());

  gpb::SimpleDescriptorDatabase database;
  for (int i = 0; i < fileset.file_size(); ++i) {
    database.Add(fileset.file(i));
  }

  const gpb::DescriptorPool pool(&database);
  auto json = proto_to_json(pool, message_name, data);
  using namespace std::string_literals;
  write_file("data/"s + std::string(message_name) + ".pb", data);
  write_file("data/"s + std::string(message_name) + ".json", json);
  return json;
}

} // namespace gpb_based
#else
namespace gpb_based {

std::string read_file(const std::string& filename) {
  std::ifstream in(filename.c_str(), std::ios::in | std::ios::binary);
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(in.tellg());
  in.seekg(0, std::ios::beg);
  in.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  return contents;
}

std::string proto_to_json(std::string_view /* unused */, const char *message_name, std::string_view data) {
  using namespace std::string_literals;
  auto pb_data = read_file("data/"s + message_name + ".pb");
  if (data == pb_data) {
    return read_file("data/"s + message_name + ".json");
  }
  return {};
}

} // namespace gpb_based

#endif
