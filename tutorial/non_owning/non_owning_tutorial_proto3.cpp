#include <iostream>
#include <memory_resource>
#include <source_location>

#include "addressbook_proto3.glz.hpp" // required for write_json() and read_json()
#include "addressbook_proto3.pb.hpp"  // required for write_binpb() and read_binpb()

inline void expect(bool condition, const std::source_location location = std::source_location::current()) {
  if (!condition) {
    std::cerr << "assertion failure at " << location.file_name() << ":" << location.line() << "\n";
    exit(1);
  }
}

inline std::string_view string_dup(std::string_view str, std::pmr::monotonic_buffer_resource *mbr) {
  char *buf = static_cast<char *>(mbr->allocate(str.size(), 1));
  std::ranges::copy(str, buf);
  return {buf, str.size()};
}

using Person = tutorial::Person<hpp_proto::non_owning_traits>;
using AddressBook = tutorial::AddressBook<hpp_proto::non_owning_traits>;

int main() {
  using enum Person::PhoneType;
  using namespace std::string_view_literals;

  std::pmr::monotonic_buffer_resource pool;
  AddressBook address_book;

  std::pmr::vector<Person::PhoneNumber> alex_phones{&pool};
  alex_phones.push_back({.number = "19890604"sv, .type = PHONE_TYPE_MOBILE});

  using PhoneNumberSpan = hpp_proto::equality_comparable_span<const Person::PhoneNumber>;

  std::pmr::vector<Person> people{&pool};
  people.resize(2);
  people[0].name = "Alex"sv;
  people[0].id = 1;
  people[0].email = "alex@email.com"sv;
  people[0].phones = alex_phones;
  people[0].nested_message = {{.bb = 89}};

  std::pmr::vector<std::pair<std::string_view, Person::NestedMessage>> map_string_nested_message(
      {{"Tiananmen", {.bb = 89}}, {"Square", {.bb = 64}}}, &pool);
  people[0].map_string_nested_message = map_string_nested_message;
  people[0].oneof_field = "https://en.wikipedia.org/wiki/1989_Tiananmen_Square_protests_and_massacre"sv;

  people[1].name = string_dup("bob", &pool);

  people[1].id = 2;
  people[1].email = string_dup("bob@email.com", &pool);

  std::pmr::vector<Person::PhoneNumber> bob_phones{&pool};
  bob_phones.push_back({.number = "22222222"sv, .type = PHONE_TYPE_HOME});
  people[1].phones = bob_phones;

  address_book.people = people;

  auto write_result = hpp_proto::write_binpb<std::span<const std::byte>>(address_book, hpp_proto::alloc_from{pool});
  expect(write_result.has_value());

  auto read_result = hpp_proto::read_binpb<AddressBook>(write_result.value(), hpp_proto::alloc_from{pool});
  expect(read_result.has_value());
  expect(address_book == read_result.value());

  {
    std::span<const Person> people = address_book.people;
    expect(people.size() == 2);
    const Person &alex = people[0];
    std::string_view alex_name = alex.name;
    expect(alex_name == "Alex");
    const int32_t &alex_id = alex.id;
    expect(alex_id == 1);
    std::span<const Person::PhoneNumber> alex_phones = alex.phones;
    expect(alex_phones[0].number == "19890604");
    expect(alex_phones[0].type == PHONE_TYPE_MOBILE);

    const std::optional<Person::NestedMessage> &alex_nested_message = alex.nested_message;
    expect(alex_nested_message.has_value());
    // NOLINTBEGIN(bugprone-unchecked-optional-access)
    expect(alex_nested_message->bb == 89);
    // NOLINTEND(bugprone-unchecked-optional-access)
    std::span<const std::pair<std::string_view, Person::NestedMessage>> map_string_nested_message =
        alex.map_string_nested_message;
    expect(std::ranges::equal(map_string_nested_message, address_book.people[0].map_string_nested_message));

    const std::variant<std::monostate, uint32_t, Person::NestedMessage, std::string_view, hpp_proto::bytes_view>
        &alex_oneof_field = alex.oneof_field;
    expect(alex_oneof_field.index() == Person::oneof_field_oneof_case::oneof_string);
    expect(std::get<Person::oneof_field_oneof_case::oneof_string>(alex_oneof_field) ==
           "https://en.wikipedia.org/wiki/1989_Tiananmen_Square_protests_and_massacre");
  }

#ifndef HPP_PROTO_DISABLE_GLAZE
  auto write_json_result =
      hpp_proto::write_json<hpp_proto::json_opts{}, std::pmr::string>(address_book, hpp_proto::alloc_from{pool});
  expect(write_json_result.has_value());
  auto read_json_result =
      hpp_proto::read_json<glz::opts{}, AddressBook>(write_json_result.value(), hpp_proto::alloc_from{pool});
  expect(address_book == read_json_result.value());
#endif
  return 0;
}