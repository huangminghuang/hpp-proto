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

int main() {
  using namespace std::string_view_literals;
  using enum tutorial::Person::PhoneType;

  std::array<tutorial::Person::PhoneNumber, 1> alex_phones{{{.number = "19890604"sv, .type = PHONE_TYPE_MOBILE}}};
  std::array<std::pair<std::string_view, tutorial::Person::NestedMessage>, 2> alex_map_string_nested_message{
      {{"Tiananmen"sv, {.bb = 89}}, {"Square"sv, {.bb = 64}}}};

  tutorial::Person alex{.name = "Alex"sv,
                        .id = 1,
                        .email = "alex@email.com"sv,
                        .phones = alex_phones,
                        .nested_message = {{.bb = 89}},
                        .map_string_nested_message = alex_map_string_nested_message,
                        .oneof_field = "https://en.wikipedia.org/wiki/1989_Tiananmen_Square_protests_and_massacre"sv};

  std::pmr::monotonic_buffer_resource pool;
  hpp::proto::pb_context ctx{pool};

  tutorial::AnyDemo message;
  expect(hpp::proto::pack_any(message.any_value.emplace(), alex, ctx).ok());

  std::pmr::vector<std::byte> buffer{&pool};
  expect(hpp::proto::write_proto(message, buffer).ok());

  tutorial::AnyDemo new_message;

  expect(hpp::proto::read_proto(new_message, buffer, ctx).ok());

  tutorial::Person person;
  expect(hpp::proto::unpack_any(new_message.any_value.value(), person, ctx).ok());

  return 0;
}