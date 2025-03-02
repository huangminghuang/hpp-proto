#include "hpp_options_test.msg.hpp"

int main() {
  Msg1 msg1;
  Msg2 msg2;
  Msg3 msg3;

  static_assert(std::same_as<decltype(msg1.f1_non_owning), std::string_view>);
  static_assert(std::same_as<decltype(msg2.f1), std::string>);
  static_assert(std::same_as<decltype(msg3.f1), std::string>);
  static_assert(std::same_as<decltype(msg3.f2_non_owning), std::string_view>);
  return 0;
}