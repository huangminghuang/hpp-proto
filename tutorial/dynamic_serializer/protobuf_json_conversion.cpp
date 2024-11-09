#include <hpp_proto/dynamic_serializer.hpp>
#include <iostream>

inline std::string read_file(const std::string &filename) {
  std::ifstream in(filename.c_str(), std::ios::in | std::ios::binary);
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(in.tellg());
  in.seekg(0, std::ios::beg);
  in.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  return contents;
}

int main(int argc, const char **argv) {
  auto args = std::span<const char *>{argv, static_cast<std::size_t>(argc)};

  auto descriptors = read_file("addressbook_proto3.desc.pb");

  auto ser = hpp::proto::dynamic_serializer::make(descriptors);
  if (!ser.has_value()) {
    std::cerr << "unable to create the dynamic serializer\n";
    return 1;
  }

  std::string addressbook_pb;
  const char *message_name = "tutorial.AddressBook";
  const char *addressbook_json = R"({"people":[{"name":"Alex","id":1},{"name":"Bob", "id":2}]})";
  if (!ser->json_to_proto(message_name, addressbook_json, addressbook_pb).ok()) {
    std::cerr << "unable to convert from json to protobuf\n";
    return 1;
  }

  bool pretty_print = false;
  if (args.size() == 2 && std::string_view{args[1]} == "--pretty-print") {
    pretty_print = true;
  }

  std::string new_addressbook_json;
  auto jsonfy_result = pretty_print
                           ? ser->proto_to_json<glz::opts{.prettify = true}>(message_name, new_addressbook_json)
                           : ser->proto_to_json(message_name, new_addressbook_json);

  if (!jsonfy_result.has_value()) {
    std::cerr << "unable to convert from protobuf to json\n";
    return 1;
  }
  std::cout << jsonfy_result.value() << "\n";
  return 0;
}