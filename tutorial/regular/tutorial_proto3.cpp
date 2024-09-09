#include <iostream>
#include <source_location>

#include "addressbook_proto3.glz.hpp" // required for write_json() and read_json()
#include "addressbook_proto3.pb.hpp"  // required for write_proto() and read_proto()

inline void expect(bool condition, const std::source_location location = std::source_location::current()) {
  if (!condition) {
    std::cerr << "assertion failure at " << location.file_name() << ":" << location.line() << "\n";
    exit(1);
  }
}

int main() {
  using enum tutorial::Person::PhoneType;
  tutorial::AddressBook address_book{
      .people = {{.name = "Alex",
                  .id = 1,
                  .email = "alex@email.com",
                  .phones = {{.number = "19890604", .type = PHONE_TYPE_MOBILE}},
                  .nested_message = {{.bb = 89}},
                  .map_string_nested_message = {{"Tiananmen", {.bb = 89}}, {"Square", {.bb = 64}}},
                  .oneof_field = "https://en.wikipedia.org/wiki/1989_Tiananmen_Square_protests_and_massacre"},
                 {.name = "Bob",
                  .id = 2,
                  .email = "bob@email.com",
                  .phones = {{.number = "22222222", .type = PHONE_TYPE_HOME}},
                  .nested_message = {},
                  .map_string_nested_message = {},
                  .oneof_field = {}}}};

  std::vector<std::byte> buffer;
  expect(hpp::proto::write_proto(address_book, buffer).ok());

  tutorial::AddressBook new_address_book;
  expect(hpp::proto::read_proto(new_address_book, buffer).ok());
  expect(address_book == new_address_book);

  std::vector<tutorial::Person> &people = address_book.people;
  expect(people.size() == 2);
  tutorial::Person &alex = address_book.people[0];
  std::string &alex_name = alex.name;
  expect(alex_name == "Alex");
  int32_t &alex_id = alex.id;
  expect(alex_id == 1);
  std::vector<tutorial::Person::PhoneNumber> &alex_phones = alex.phones;
  expect(alex_phones[0].number == "19890604");
  expect(alex_phones[0].type == PHONE_TYPE_MOBILE);
  std::optional<tutorial::Person::NestedMessage> &alex_nested_message = alex.nested_message;
  expect(alex_nested_message.has_value());
  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  expect(alex_nested_message->bb == 89);
  // NOLINTEND(bugprone-unchecked-optional-access)

  std::variant<std::monostate, uint32_t, tutorial::Person::NestedMessage, std::string, hpp::proto::bytes>
      &alex_oneof_field = alex.oneof_field;

  expect(alex_oneof_field.index() == tutorial::Person::oneof_field_oneof_case::oneof_string);
  expect(std::get<std::string>(alex_oneof_field) ==
         "https://en.wikipedia.org/wiki/1989_Tiananmen_Square_protests_and_massacre");

  std::string json;

  expect(hpp::proto::write_json(address_book, json).ok());

  if (auto pe = hpp::proto::read_json(new_address_book, json); !pe.ok()) {
    std::cerr << "read json error: " << pe.message(json) << "\n";
    return 1;
  }
  expect(address_book == new_address_book);

  return 0;
}