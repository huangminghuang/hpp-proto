#include "hpp_options_test.desc.hpp"
#include "hpp_options_test.msg.hpp"

static_assert(requires {
  hpp_proto::file_descriptors::hpp_options_custom_proto::file_descriptor_;
  hpp_proto::file_descriptors::hpp_options_custom_proto::file_descriptor_set();
});

// NOLINTNEXTLINE(bugprone-exception-escape)
int main() {
  test::Msg1 msg;
  msg.string_field = "abc";
  return 0;
}
