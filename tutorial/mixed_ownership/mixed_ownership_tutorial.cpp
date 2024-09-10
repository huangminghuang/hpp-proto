#include <iostream>
#include <memory_resource>
#include <source_location>

#include "non_owning/addressbook_proto3.pb.hpp"
#include "regular/addressbook_proto3.pb.hpp"

inline void expect(bool condition, const std::source_location location = std::source_location::current()) {
  if (!condition) {
    std::cerr << "assertion failure at " << location.file_name() << ":" << location.line() << "\n";
    exit(1);
  }
}

int main() {
  using enum regular::tutorial::Person::PhoneType;
  regular::tutorial::AddressBook address_book{
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

  non_owning::tutorial::AddressBook new_address_book;
  std::pmr::monotonic_buffer_resource pool;

  hpp::proto::pb_context pb_ctx{pool};
  expect(hpp::proto::read_proto(new_address_book, buffer, pb_ctx).ok());

  {
    using namespace non_owning;
    hpp::proto::equality_comparable_span<const tutorial::Person> people = new_address_book.people;
    expect(people.size() == 2);
    const tutorial::Person &alex = people[0];
    std::string_view alex_name = alex.name;
    expect(alex_name == "Alex");
    const int32_t &alex_id = alex.id;
    expect(alex_id == 1);
    hpp::proto::equality_comparable_span<const tutorial::Person::PhoneNumber> alex_phones = alex.phones;
    expect(alex_phones[0].number == "19890604");
    using enum tutorial::Person::PhoneType;
    expect(alex_phones[0].type == PHONE_TYPE_MOBILE);

    const std::optional<tutorial::Person::NestedMessage> &alex_nested_message = alex.nested_message;
    expect(alex_nested_message.has_value());
    // NOLINTBEGIN(bugprone-unchecked-optional-access)
    expect(alex_nested_message->bb == 89);
    // NOLINTEND(bugprone-unchecked-optional-access)
    hpp::proto::equality_comparable_span<const std::pair<std::string_view, tutorial::Person::NestedMessage>> map_string_nested_message =
        alex.map_string_nested_message;
    expect(map_string_nested_message.size() == 2);
    const std::variant<std::monostate, uint32_t, tutorial::Person::NestedMessage, std::string_view,
                       hpp::proto::bytes_view> &alex_oneof_field = alex.oneof_field;
    expect(alex_oneof_field.index() == tutorial::Person::oneof_field_oneof_case::oneof_string);
    expect(std::get<tutorial::Person::oneof_field_oneof_case::oneof_string>(alex_oneof_field) ==
           "https://en.wikipedia.org/wiki/1989_Tiananmen_Square_protests_and_massacre");
  }

  return 0;
}