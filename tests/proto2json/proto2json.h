#include <string_view>

enum PrintOption {
  NONE,
  ALWAYS_PRINT_PRIMITIVE_FIELDS
};

std::string proto_to_json(const char *dir, const char *proto_file_name, const char *message_name,
                          std::string_view &data, PrintOption option = NONE);

std::string proto_to_json(std::string_view filedescriptorset_stream, const char *message_name, std::string_view data,
                          PrintOption option = NONE);
