#include <unordered_map>
#include <map>
#include "hpp_options_test.msg.hpp"

int main() {
  Msg1 msg1;
  Msg2 msg2;
  Msg3 msg3;

  static_assert(std::same_as<decltype(msg1.f1_non_owning), std::string_view>);
  static_assert(std::same_as<decltype(msg2.f1), std::string>);
  static_assert(std::same_as<decltype(msg3.f1), std::string>);
  static_assert(std::same_as<decltype(msg3.f2_non_owning), std::string_view>);
  static_assert(std::same_as<decltype(msg3.string_keyed_map_field), std::unordered_map<std::string, std::int32_t>>);
  static_assert(std::same_as<decltype(msg3.int32_keyed_map_field), std::map<std::int32_t, std::int32_t>>);
  return 0;
}