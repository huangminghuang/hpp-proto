#include "gpb_proto_json.hpp"
#include <cxxopts.hpp>
#include <fstream>
#include <iostream>

std::string descriptorset(const char *filename) {
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  std::string contents;
  in.seekg(0, std::ios::end);
  contents.resize(in.tellg());
  in.seekg(0, std::ios::beg);
  in.read(&contents[0], contents.size());
  return contents;
}

int main(int argc, char **argv) {

  cxxopts::Options options(argv[0],
                           "Read a JSON-format message of the given type from standard input, write it in protobuf "
                           "to standard output and vice versa");

  // clang-format off
  options.add_options()("descriptor_set_in", "The FILE containing a FileDescriptorSet (a "
                                             "protocol buffer defined in descriptor.proto). ", cxxopts::value<std::string>())
                       ("decode", "The type name of the protobuf encoded message from stdin", cxxopts::value<std::string>())
                       ("encode", "The type name of the json formatted message from stdin"", cxxopts::value<std::string>())
                       ("h,help", "Print usage");
  // clang-format on

  auto result = options.parse(argc, argv);

  if (result.count("help")) {
    std::cout << options.help()
              << "\n;
        return 0;
  }

  if (!result.count("descriptor_set_in")) {
    std::cerr << "--descriptor_set_in must be specified\n";
    return 1;
  } 

  if ((result.count("decode") == 0) ^ (result.count("encode") == 0)) {
    std::cerr << "either --encode or --decode must be specified\n";
    return 1;
  }

  std::string input(std::istreambuf_iterator<char>{std::cin}, std::istreambuf_iterator<char>{});
  std::string output;

  if (result.count("encode")) {
    output = json_to_proto(descriptorset(result["descriptor_set_in"]), result["encode"], input);
  } else if (result.count("decode")) {
    output = proto_to_json(descriptorset(result["descriptor_set_in"]), result["decode"], input);
  }

  std::copy(output.begin(), output.end(), std::ostream_iterator<char>(std::cout));

  return 0;
}