#include "gpb_proto_json.h"
#include <google/protobuf/compiler/importer.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/util/json_util.h>

namespace gpb_based {
namespace gpb = google::protobuf;

std::string proto_to_json(const gpb::DescriptorPool &pool, const char *message_name, std::string_view data,
                          PrintOption option = NONE) {

  auto message_descriptor = pool.FindMessageTypeByName(message_name);
  gpb::DynamicMessageFactory factory(&pool);

  std::unique_ptr<gpb::Message> message{factory.GetPrototype(message_descriptor)->New()};
  message->ParseFromString(data);

  std::string result;
  gpb::json::PrintOptions options;
  options.always_print_primitive_fields = (option == ALWAYS_PRINT_PRIMITIVE_FIELDS);

  (void)gpb::util::MessageToJsonString(*message, &result, options);

  return result;
}

std::string json_to_proto(const gpb::DescriptorPool &pool, const char *message_name, std::string_view data) {
  auto message_descriptor = pool.FindMessageTypeByName(message_name);
  gpb::DynamicMessageFactory factory(&pool);

  std::unique_ptr<gpb::Message> message{factory.GetPrototype(message_descriptor)->New()};
  (void)gpb::util::JsonStringToMessage(data, message.get());
  return message->SerializeAsString();
}

std::string proto_to_json(std::string_view filedescriptorset_stream, const char *message_name, std::string_view data,
                          PrintOption option) {
  gpb::FileDescriptorSet fileset;
  fileset.ParseFromString(filedescriptorset_stream);

  gpb::SimpleDescriptorDatabase database;
  for (int i = 0; i < fileset.file_size(); ++i) {
    database.AddUnowned(&fileset.file(i));
  }

  gpb::DescriptorPool pool(&database);
  return proto_to_json(pool, message_name, data, option);
}

std::string json_to_proto(std::string_view filedescriptorset_stream, const char *message_name, std::string_view data) {
  gpb::FileDescriptorSet fileset;
  fileset.ParseFromString(filedescriptorset_stream);

  gpb::SimpleDescriptorDatabase database;
  for (int i = 0; i < fileset.file_size(); ++i) {
    database.AddUnowned(&fileset.file(i));
  }

  gpb::DescriptorPool pool(&database);
  return json_to_proto(pool, message_name, data);
}
} // namespace gpb_based
