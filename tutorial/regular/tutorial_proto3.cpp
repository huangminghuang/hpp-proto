#include <iostream>
#include <source_location>

#include "addressbook_proto3.glz.hpp" // required for write_json() and read_json()
#include "addressbook_proto3.pb.hpp"  // required for write_binpb() and read_binpb()

inline void expect(bool condition, const std::source_location location = std::source_location::current()) {
  if (!condition) {
    std::cerr << "assertion failure at " << location.file_name() << ":" << location.line() << "\n";
    exit(1);
  }
}

using Person = tutorial::Person<::hpp_proto::stable_traits>;
using AddressBook = tutorial::AddressBook<::hpp_proto::stable_traits>;

int main() {
  using enum Person::PhoneType;
  AddressBook address_book{
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

  auto write_result = hpp_proto::write_binpb(address_book);
  expect(write_result.has_value());

  auto read_result = hpp_proto::read_binpb<AddressBook>(write_result.value());
  expect(address_book == read_result.value());

  std::vector<Person> &people = address_book.people;
  expect(people.size() == 2);
  Person &alex = address_book.people[0];
  std::string &alex_name = alex.name;
  expect(alex_name == "Alex");
  int32_t &alex_id = alex.id;
  expect(alex_id == 1);
  std::vector<Person::PhoneNumber> &alex_phones = alex.phones;
  expect(alex_phones[0].number == "19890604");
  expect(alex_phones[0].type == PHONE_TYPE_MOBILE);
  std::optional<Person::NestedMessage> &alex_nested_message = alex.nested_message;
  expect(alex_nested_message.has_value());
  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  expect(alex_nested_message->bb == 89);
  // NOLINTEND(bugprone-unchecked-optional-access)

  std::variant<std::monostate, uint32_t, Person::NestedMessage, std::string, hpp_proto::bytes> &alex_oneof_field =
      alex.oneof_field;

  expect(alex_oneof_field.index() == Person::oneof_field_oneof_case::oneof_string);
  expect(std::get<std::string>(alex_oneof_field) ==
         "https://en.wikipedia.org/wiki/1989_Tiananmen_Square_protests_and_massacre");

  auto write_json_result = hpp_proto::write_json(address_book);
  expect(write_json_result.has_value());
  auto read_json_result = hpp_proto::read_json<glz::opts{}, AddressBook>(write_json_result.value());
  expect(address_book == read_json_result.value());
  return 0;
}
