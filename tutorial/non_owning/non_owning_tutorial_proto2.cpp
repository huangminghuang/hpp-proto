#include <iostream>
#include <memory_resource>
#include <source_location>

#include "addressbook_proto2.glz.hpp" // required for write_json() and read_json()
#include "addressbook_proto2.pb.hpp"  // required for write_proto() and read_proto()

inline void expect(bool condition, const std::source_location location = std::source_location::current()) {
  if (!condition) {
    std::cerr << "assertion failure at " << location.file_name() << ":" << location.line() << "\n";
    exit(1);
  }
}

inline std::string_view string_dup(std::string_view str, std::pmr::monotonic_buffer_resource *mbr) {
  char *buf = static_cast<char *>(mbr->allocate(str.size(), 1));
  std::copy(str.begin(), str.end(), buf);
  return {buf, str.size()};
}

int main() {
  using enum tutorial::Person::PhoneType;
  using namespace std::string_view_literals;
  using namespace std::string_literals;

  std::pmr::monotonic_buffer_resource pool;
  tutorial::AddressBook address_book;

  std::pmr::vector<tutorial::Person> people{&pool};
  people.resize(2);
  people[0].name = "Alex"sv;
  people[0].id = 1;
  people[0].email = "alex@email.com"sv;

  std::pmr::vector<tutorial::Person::PhoneNumber> alex_phones{&pool};
  alex_phones.resize(1);
  alex_phones[0].number = "19890604"sv;
  alex_phones[0].type = PHONE_TYPE_MOBILE;
  people[0].phones = alex_phones;

  people[1].name = string_dup("bob", &pool);

  people[1].id = 2;
  people[1].email = string_dup("bob@email.com", &pool);

  std::pmr::vector<tutorial::Person::PhoneNumber> bob_phones{&pool};
  bob_phones.push_back({.number = "22222222"sv, .type = PHONE_TYPE_HOME});
  people[1].phones = bob_phones;

  address_book.people = people;

  std::pmr::vector<std::byte> buffer{&pool};

  expect(hpp::proto::write_proto(address_book, buffer).ok());

  auto read_result = hpp::proto::read_proto<tutorial::AddressBook>(buffer, hpp::proto::pb_context{pool});
  expect(read_result.has_value());
  expect(address_book == read_result.value());

  {
    std::span<const tutorial::Person> people = address_book.people;
    expect(people.size() == 2);
    const tutorial::Person &alex = address_book.people[0];
    const hpp::proto::optional<std::string_view> &alex_name = alex.name;
    expect(alex_name.has_value());
    expect(*alex_name == "Alex");
    const hpp::proto::optional<int32_t> &alex_id = alex.id;
    expect(alex_id.has_value());
    expect(*alex_id == 1);
    std::span<const tutorial::Person::PhoneNumber> alex_phones = alex.phones;
    expect(alex_phones[0].number == "19890604");
    expect(alex_phones[0].type == PHONE_TYPE_MOBILE);
  }

  auto write_json_result = hpp::proto::write_json(address_book);
  expect(write_json_result.has_value());
  auto read_json_result = hpp::proto::read_json<tutorial::AddressBook>(write_json_result.value(), hpp::proto::json_context{pool});
  expect(address_book == read_json_result.value());

  return 0;
}