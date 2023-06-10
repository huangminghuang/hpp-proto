#include <string_view>

namespace gpb_based {
enum PrintOption {
  NONE,
  ALWAYS_PRINT_PRIMITIVE_FIELDS
};


std::string proto_to_json(std::string_view filedescriptorset_stream, const char *message_name, std::string_view data,
                          PrintOption option = NONE);

std::string json_to_proto(std::string_view filedescriptorset_stream, const char *message_name, std::string_view data);
}