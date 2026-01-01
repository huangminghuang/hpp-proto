#include <iostream>
#include <source_location>

#include "addressbook_proto2.glz.hpp" // required for write_json() and read_json()
#include "addressbook_proto2.pb.hpp"  // required for write_binpb() and read_binpb()

inline void expect(bool condition, const std::source_location location = std::source_location::current()) {
  if (!condition) {
    std::cerr << "assertion failure at " << location.file_name() << ":" << location.line() << "\n";
    exit(1);
  }
}

using Person = tutorial::Person<>;
using AddressBook = tutorial::AddressBook<>;

int main() {
  using enum Person::PhoneType;
  tutorial::AddressBook address_book{.people = {{.name = "Alex",
                                                 .id = 1,
                                                 .email = "alex@email.com",
                                                 .phones = {{.number = "19890604", .type = PHONE_TYPE_MOBILE}}},
                                                {.name = "Bob",
                                                 .id = 2,
                                                 .email = "bob@email.com",
                                                 .phones = {{.number = "22222222", .type = PHONE_TYPE_HOME}}}}};

  auto write_result = hpp::proto::write_binpb(address_book);
  expect(write_result.has_value());

  auto read_result = hpp::proto::read_binpb<AddressBook>(write_result.value());
  expect(address_book == read_result.value());

  std::vector<Person> &people = address_book.people;
  expect(people.size() == 2);
  Person &alex = address_book.people[0];
  hpp::proto::optional<std::string> &alex_name = alex.name;
  expect(alex_name.has_value());
  expect(alex_name.value() == "Alex");
  expect(*alex_name == "Alex");
  expect(alex_name.value() == "Alex");

  hpp::proto::optional<int32_t> &alex_id = alex.id;
  expect(alex_id.has_value());
  expect(*alex_id == 1);
  expect(alex_id.value() == 1);
  expect(alex_id.value() == 1);

  std::vector<Person::PhoneNumber> &alex_phones = alex.phones;
  hpp::proto::optional<std::string> &alex_phone_number = alex_phones[0].number;
  expect(alex_phone_number.has_value());
  expect(*alex_phone_number == "19890604");
  expect(alex_phone_number.value() == "19890604");

  hpp::proto::optional<Person::PhoneType, PHONE_TYPE_HOME> &alex_phone_type = alex_phones[0].type;
  expect(alex_phone_type.has_value());
  expect(*alex_phone_type == PHONE_TYPE_MOBILE);
  expect(alex_phone_type.value() == PHONE_TYPE_MOBILE);

  // default phone type value
  hpp::proto::optional<Person::PhoneType, PHONE_TYPE_HOME> default_phone_type_value;
  expect(!default_phone_type_value.has_value());
  expect(default_phone_type_value.value() == PHONE_TYPE_HOME);
  default_phone_type_value = PHONE_TYPE_MOBILE;
  expect(default_phone_type_value.has_value());
  default_phone_type_value.reset();
  expect(!default_phone_type_value.has_value());

  auto write_json_result = hpp::proto::write_json(address_book);
  expect(write_json_result.has_value());
  auto read_json_result = hpp::proto::read_json<AddressBook>(write_json_result.value());
  expect(address_book == read_json_result.value());

  // pretty print json, with indent level 3
  write_json_result = hpp::proto::write_json(address_book, hpp::proto::indent_level<3>);
  expect(write_json_result.has_value());
  std::cout << write_json_result.value() << "\n";

  return 0;
}