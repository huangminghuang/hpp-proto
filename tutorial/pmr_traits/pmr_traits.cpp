#include <iostream>
#include <memory_resource>
#include <source_location>
#include <vector>

#include "addressbook_proto3.glz.hpp"
#include "addressbook_proto3.pb.hpp"

// Define custom traits that use std::pmr containers
struct pmr_traits : hpp::proto::default_traits {
  using string_t = std::pmr::string;
  using bytes_t = std::pmr::vector<std::byte>;

  template <typename T>
  using repeated_t = std::pmr::vector<T>;

  template <typename Key, typename Value>
  using map_t = std::pmr::map<Key, Value>;
};

using PmrAddressBook = tutorial::AddressBook<pmr_traits>;
using PmrPerson = tutorial::Person<pmr_traits>;

inline void expect(bool condition, const std::source_location location = std::source_location::current()) {
  if (!condition) {
    std::cerr << "assertion failure at " << location.file_name() << ":" << location.line() << "\n";
    exit(1);
  }
}

int main() {
  // Create a monotonic buffer resource on the stack
  std::array<std::byte, 4096> buffer;
  std::pmr::monotonic_buffer_resource pool{buffer.data(), buffer.size()};
  std::pmr::set_default_resource(&pool);

  // Create an address book that allocates from the pool
  PmrAddressBook address_book;

  // Add a person
  PmrPerson person;
  person.name = "John Doe";
  person.id = 1234;
  person.email = "jdoe@example.com";
  person.phones.push_back({.number = "555-4321", .type = PmrPerson::PhoneType::PHONE_TYPE_HOME});

  address_book.people.push_back(std::move(person));

  // Serialize to binary
  std::vector<std::byte> binary_data;
  auto write_result = hpp::proto::write_binpb(address_book, binary_data);
  expect(write_result.ok());

  // Deserialize from binary into a new object using the same pool
  PmrAddressBook read_book;
  auto read_result = hpp::proto::read_binpb(read_book, binary_data, hpp::proto::alloc_from(pool));

  expect(read_result.ok());
  expect(address_book == read_book);
  expect(read_book.people[0].name == "John Doe");

  // Demonstrate that memory was allocated from the pool
  expect(read_book.people.get_allocator().resource() == &pool);
  expect(read_book.people[0].name.get_allocator().resource() == &pool);

  std::cout << "Successfully serialized and deserialized using PMR traits!" << std::endl;

#ifndef HPP_PROTO_DISABLE_GLAZE
  // JSON serialization works with PMR traits too
  auto json_result = hpp::proto::write_json(address_book);
  expect(json_result.has_value());

  PmrAddressBook json_read_book;
  auto json_read_result = hpp::proto::read_json(json_read_book, json_result.value(), hpp::proto::alloc_from(pool));
  expect(json_read_result.ok());
  expect(address_book == json_read_book);

  // Demonstrate that memory was allocated from the pool
  expect(json_read_book.people.get_allocator().resource() == &pool);
  expect(json_read_book.people[0].name.get_allocator().resource() == &pool);
  std::cout << "Successfully serialized and deserialized JSON using PMR traits!" << std::endl;
#endif

  return 0;
}
