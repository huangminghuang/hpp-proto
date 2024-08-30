#include <iostream>
#include <source_location>

#include "addressbook_proto2.pb.hpp" // required for write_proto() and read_proto()
#include "addressbook_proto2.glz.hpp" // required for write_json() and read_json()

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
                 .phones = {{.number = "19890604", .type = PHONE_TYPE_MOBILE}}},
                 {.name = "Bob",
                  .id = 2,
                  .email = "bob@email.com",
                  .phones = {{.number = "22222222", .type = PHONE_TYPE_HOME}}} }};

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

  // NOLINTBEGIN(misc-const-correctness)
  std::vector<tutorial::Person>& people = address_book.people;
  // NOLINTEND(misc-const-correctness)
  assert_true(people.size() == 2);
  tutorial::Person& alex = address_book.people[0];
  hpp::proto::optional<std::string>& alex_name = alex.name;
  assert_true(alex_name.has_value());
  assert_true(alex_name.value() == "Alex");
  assert_true(*alex_name == "Alex");
  assert_true(alex_name.value_or_default() == "Alex");

  hpp::proto::optional<int32_t>& alex_id = alex.id;
  assert_true(alex_id.has_value());
  assert_true(*alex_id == 1);
  assert_true(alex_id.value() == 1);
  assert_true(alex_id.value_or_default() == 1);

  std::vector<tutorial::Person::PhoneNumber>& alex_phones = alex.phones;
  hpp::proto::optional<std::string>& alex_phone_number = alex_phones[0].number;
  assert_true(alex_phone_number.has_value());
  assert_true(*alex_phone_number == "19890604");
  assert_true(alex_phone_number.value() == "19890604");
  assert_true(alex_phone_number.value_or_default() == "19890604");

  hpp::proto::optional<tutorial::Person::PhoneType, PHONE_TYPE_HOME>& alex_phone_type = alex_phones[0].type;
  assert_true(alex_phone_type.has_value());
  assert_true(*alex_phone_type == PHONE_TYPE_MOBILE);
  assert_true(alex_phone_type.value() == PHONE_TYPE_MOBILE);
  assert_true(alex_phone_type.value_or_default() == PHONE_TYPE_MOBILE);

  // default phone type value
  hpp::proto::optional<tutorial::Person::PhoneType, PHONE_TYPE_HOME> default_phone_type_value;
  assert_true(!default_phone_type_value.has_value());
  assert_true(default_phone_type_value.value_or_default() == PHONE_TYPE_HOME);
  default_phone_type_value = PHONE_TYPE_MOBILE;
  assert_true(default_phone_type_value.has_value());
  default_phone_type_value.reset();
  assert_true(!default_phone_type_value.has_value());

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