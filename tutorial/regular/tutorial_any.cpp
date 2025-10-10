#include <iostream>
#include <source_location>

#include "addressbook_proto3.pb.hpp" // required for write_proto() and read_proto()
#include "any_demo.pb.hpp"

using Person = tutorial::Person<>;
using AnyDemo = tutorial::AnyDemo<>;

inline void expect(bool condition, const std::source_location location = std::source_location::current()) {
  if (!condition) {
    std::cerr << "assertion failure at " << location.file_name() << ":" << location.line() << "\n";
    exit(1);
  }
}

int main() {
  using enum Person::PhoneType;
  Person alex{.name = "Alex",
              .id = 1,
              .email = "alex@email.com",
              .phones = {{.number = "19890604", .type = PHONE_TYPE_MOBILE}},
              .nested_message = {{.bb = 89}},
              .map_string_nested_message = {{"Tiananmen", {.bb = 89}}, {"Square", {.bb = 64}}},
              .oneof_field = "https://en.wikipedia.org/wiki/1989_Tiananmen_Square_protests_and_massacre"};

 AnyDemo message;
  expect(hpp::proto::pack_any(message.any_value.emplace(), alex).ok());

  std::vector<std::byte> buffer;
  expect(hpp::proto::write_proto(message, buffer).ok());

  auto write_result = hpp::proto::write_proto(message);
  expect(write_result.has_value());

  auto any_demo = hpp::proto::read_proto<AnyDemo>(write_result.value());
  expect(any_demo.has_value());
  // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
  auto unpacked_result = hpp::proto::unpack_any<Person>(any_demo.value().any_value.value());
  expect(unpacked_result.has_value());
  expect(alex == unpacked_result.value());

  return 0;
}