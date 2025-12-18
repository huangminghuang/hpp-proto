#include "gpb_proto_json_export.h"
#include <string>
#include <string_view>
namespace gpb_based {

GPB_PROTO_JSON_EXPORT
std::string binpb_to_json(std::string_view filedescriptorset_stream, const char *message_name, std::string_view data);

} // namespace gpb_based