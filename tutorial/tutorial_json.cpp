#include "tutorial.glz.hpp"
#include <iostream>

int main() {
  tutorial::AddressBook address_book{
      .people = {{.name = "Alex",
                  .id = 1,
                  .email = "alex@email.com",
                  .phones = {{.number = "1111111", .type = tutorial::Person::PhoneType::MOBILE}}},
                 {.name = "Bob",
                  .id = 2,
                  .email = "bob@email.com",
                  .phones = {{.number = "22222222", .type = tutorial::Person::PhoneType::HOME}}}}};

  std::string json;

  if (auto e = hpp::proto::write_json(address_book, json); !e.ok()) {
    std::cerr << "write json error\n";
    return 1;
  }

  tutorial::AddressBook new_book;
  if (auto e = hpp::proto::read_json(new_book, json); !e.ok()) {
    std::cerr << "read json error: " << e.message(json) << "\n";
    return 1;
  }

  return 0;
} 