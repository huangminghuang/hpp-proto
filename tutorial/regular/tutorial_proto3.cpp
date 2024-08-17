#include <iostream>
#include <source_location>

#include "addressbook_proto3.glz.hpp" // required for write_json() and read_json()
#include "addressbook_proto3.pb.hpp"  // required for write_proto() and read_proto()

inline void assert_true(bool condition, const std::source_location location = std::source_location::current()) {
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
                  .phones = {{.number = "22222222", .type = PHONE_TYPE_HOME}}}}};

  std::vector<std::byte> buffer;

  if (!hpp::proto::write_proto(address_book, buffer).ok()) {
    std::cerr << "protobuf serialization failed\n";
    return 1;
  }

  tutorial::AddressBook new_address_book;

  if (!hpp::proto::read_proto(new_address_book, buffer).ok()) {
    std::cerr << "protobuf deserialization failed\n";
    return 1;
  }

  assert_true(address_book == new_address_book);

  std::vector<tutorial::Person> &people = address_book.people;
  assert_true(people.size() == 2);
  tutorial::Person &alex = address_book.people[0];
  std::string &alex_name = alex.name;
  assert_true(alex_name == "Alex");
  int32_t &alex_id = alex.id;
  assert_true(alex_id == 1);
  std::vector<tutorial::Person::PhoneNumber> &alex_phones = alex.phones;
  assert_true(alex_phones[0].number == "19890604");
  assert_true(alex_phones[0].type == PHONE_TYPE_MOBILE);
  std::optional<tutorial::Person::NestedMessage> &alex_nested_message = alex.nested_message;
  assert_true(alex_nested_message.has_value());
  assert_true(alex_nested_message->bb == 89);

  std::variant<std::monostate, uint32_t, tutorial::Person::NestedMessage, std::string, hpp::proto::bytes>
      &alex_oneof_field = alex.oneof_field;

  assert_true(alex_oneof_field.index() == tutorial::Person::oneof_field_oneof_case::oneof_string);
  assert_true(std::get<std::string>(alex_oneof_field) == "https://en.wikipedia.org/wiki/1989_Tiananmen_Square_protests_and_massacre");

  std::string json;

  if (auto we = hpp::proto::write_json(address_book, json); !we.ok()) {
    std::cerr << "write json error\n";
    return 1;
  }

  if (auto pe = hpp::proto::read_json(new_address_book, json); !pe.ok()) {
    std::cerr << "read json error: " << pe.message(json) << "\n";
    return 1;
  }
  assert_true(address_book == new_address_book);

  return 0;
}