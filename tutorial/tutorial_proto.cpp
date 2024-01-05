#include <iostream>
#include "tutorial.pb.hpp"

int main() {
  tutorial::AddressBook address_book{
      .people = {{.name = "Alex",
                 .id = 1,
                 .email = "alex@email.com",
                 .phones = {{.number = "1111111", .type = tutorial::Person::PhoneType::MOBILE}}},
                 {.name = "Bob",
                  .id = 2,
                  .email = "bob@email.com",
                  .phones = {{.number = "22222222", .type = tutorial::Person::PhoneType::HOME}}} }};

  std::vector<std::byte> buffer;

  if (auto ec = hpp::proto::write_proto(address_book, buffer); ec.failure()) {
    std::cerr << "protobuf serialization failed\n";
    return 1;
  }

  tutorial::AddressBook new_address_book;

  if (auto ec = hpp::proto::read_proto(new_address_book, buffer); ec.failure()) {
    std::cerr << "protobuf deserialization failed\n";
    return 1;
  }

  return 0;
}