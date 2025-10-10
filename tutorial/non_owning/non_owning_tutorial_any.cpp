#include <iostream>
#include <memory_resource>
#include <source_location>

#include "addressbook_proto3.pb.hpp" // required for write_proto() and read_proto()
#include "any_demo.pb.hpp"

inline void expect(bool condition, const std::source_location location = std::source_location::current()) {
  if (!condition) {
    std::cerr << "assertion failure at " << location.file_name() << ":" << location.line() << "\n";
    exit(1);
  }
}

using Person = tutorial::Person<hpp::proto::non_owning_traits>;
using AnyDemo = tutorial::AnyDemo<hpp::proto::non_owning_traits>;

int main() {
  using namespace std::string_view_literals;
  using enum Person::PhoneType;

  std::array<Person::PhoneNumber, 1> alex_phones{{{.number = "19890604"sv, .type = PHONE_TYPE_MOBILE}}};
  std::array<std::pair<std::string_view, Person::NestedMessage>, 2> alex_map_string_nested_message{
      {{"Tiananmen"sv, {.bb = 89}}, {"Square"sv, {.bb = 64}}}};

  Person alex{.name = "Alex"sv,
                        .id = 1,
                        .email = "alex@email.com"sv,
                        .phones = alex_phones,
                        .nested_message = {{.bb = 89}},
                        .map_string_nested_message = alex_map_string_nested_message,
                        .oneof_field = "https://en.wikipedia.org/wiki/1989_Tiananmen_Square_protests_and_massacre"sv};

  std::pmr::monotonic_buffer_resource pool;

  AnyDemo message;
  expect(hpp::proto::pack_any(message.any_value.emplace(), alex, hpp::proto::alloc_from{pool}).ok());

  std::pmr::vector<std::byte> buffer{&pool};
  expect(hpp::proto::write_proto(message, buffer).ok());

  auto any_demo = hpp::proto::read_proto<AnyDemo>(buffer, hpp::proto::alloc_from{pool});
  expect(any_demo.has_value());

  auto unpacked_result =
      // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
      hpp::proto::unpack_any<Person>(any_demo.value().any_value.value(), hpp::proto::alloc_from{pool});
  expect(unpacked_result.has_value());
  expect(alex == unpacked_result.value());

  return 0;
}