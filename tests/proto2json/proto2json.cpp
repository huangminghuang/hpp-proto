#include "proto2json.h"
#include <google/protobuf/compiler/importer.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/util/json_util.h>
namespace gpb = google::protobuf;

std::string proto_to_json(const gpb::DescriptorPool *pool, const char *message_name, std::string_view data,
                          PrintOption option = NONE) {

  auto message_descriptor = pool->FindMessageTypeByName(message_name);
  gpb::DynamicMessageFactory factory(pool);

  auto message = factory.GetPrototype(message_descriptor)->New();
  message->ParseFromString(data);

  std::string result;
  gpb::json::PrintOptions options;
  options.always_print_primitive_fields = (option == ALWAYS_PRINT_PRIMITIVE_FIELDS);

  (void)!gpb::util::MessageToJsonString(*message, &result, options).ok();

  return result;
}

std::string proto_to_json(const char *dir, const char *proto_file_name, const char *message_name, std::string_view data,
                          PrintOption option) {
  namespace gpb = google::protobuf;

  gpb::compiler::MultiFileErrorCollector error_collector;
  gpb::compiler::DiskSourceTree source_tree;
  source_tree.MapPath("", dir);
  gpb::compiler::Importer importer(&source_tree, &error_collector);
  importer.Import(proto_file_name);
  return proto_to_json(importer.pool(), message_name, data, option);
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
  return proto_to_json(&pool, message_name, data, option);
}