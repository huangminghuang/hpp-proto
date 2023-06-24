#include <string_view>
#include "gpb_proto_json_export.h"
namespace gpb_based {
enum PrintOption {
  NONE,
  ALWAYS_PRINT_PRIMITIVE_FIELDS
};

GPB_PROTO_JSON_EXPORT
std::string  proto_to_json(std::string_view filedescriptorset_stream, const char *message_name, std::string_view data,
                          PrintOption option = NONE);

GPB_PROTO_JSON_EXPORT
std::string json_to_proto(std::string_view filedescriptorset_stream, const char *message_name,
                                               std::string_view data);
}