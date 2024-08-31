#include "gpb_proto_json.h"
#include <google/protobuf/compiler/importer.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/util/json_util.h>

namespace gpb_based {
namespace gpb = google::protobuf;

std::string proto_to_json(const gpb::DescriptorPool &pool, const char *message_name, std::string_view data) {

  const auto* message_descriptor = pool.FindMessageTypeByName(message_name);
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

std::string json_to_proto(const gpb::DescriptorPool &pool, const char *message_name, std::string_view data) {
  const auto* message_descriptor = pool.FindMessageTypeByName(message_name);
  // NOLINTBEGIN(misc-const-correctness)
  gpb::DynamicMessageFactory factory(&pool);
  // NOLINTEND(misc-const-correctness)

  std::unique_ptr<gpb::Message> message{factory.GetPrototype(message_descriptor)->New()};
  (void)gpb::util::JsonStringToMessage(std::string{data}, message.get());
  return message->SerializeAsString();
}

std::string proto_to_json(std::string_view filedescriptorset_stream, const char *message_name, std::string_view data) {
  gpb::FileDescriptorSet fileset;
  fileset.ParseFromArray(filedescriptorset_stream.data(),(int) filedescriptorset_stream.size());

  gpb::SimpleDescriptorDatabase database;
  for (int i = 0; i < fileset.file_size(); ++i) {
    database.Add(fileset.file(i));
  }

  const gpb::DescriptorPool pool(&database);
  return proto_to_json(pool, message_name, data);
}

std::string json_to_proto(std::string_view filedescriptorset_stream, const char *message_name, std::string_view data) {
  gpb::FileDescriptorSet fileset;
  fileset.ParseFromArray(filedescriptorset_stream.data(), (int)filedescriptorset_stream.size());

  gpb::SimpleDescriptorDatabase database;
  for (int i = 0; i < fileset.file_size(); ++i) {
    database.Add(fileset.file(i));
  }

  const gpb::DescriptorPool pool(&database);
  return json_to_proto(pool, message_name, data);
}
} // namespace gpb_based
