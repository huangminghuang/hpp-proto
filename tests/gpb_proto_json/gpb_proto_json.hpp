#include <string_view>
#include <string>
#include "gpb_proto_json_export.h"
namespace gpb_based {

GPB_PROTO_JSON_EXPORT
std::string  proto_to_json(std::string_view filedescriptorset_stream, const char *message_name, std::string_view data);

GPB_PROTO_JSON_EXPORT
std::string json_to_proto(std::string_view filedescriptorset_stream, const char *message_name,
                                               std::string_view data);
}