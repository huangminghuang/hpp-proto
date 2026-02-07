#include <iostream>
#include <memory_resource>
#include <source_location>
#include <vector>

#include "addressbook_proto3.glz.hpp"
#include "addressbook_proto3.pb.hpp"

using PmrAddressBook = tutorial::AddressBook<hpp_proto::pmr_traits>;
using PmrPerson = tutorial::Person<hpp_proto::pmr_traits>;
using PmrPhoneNumber = PmrPerson::PhoneNumber;

inline void expect(bool condition, const std::source_location location = std::source_location::current()) {
  if (!condition) {
    std::cerr << "assertion failure at " << location.file_name() << ":" << location.line() << "\n";
    exit(1);
  }
}

int main() {
  // Create a monotonic buffer resource on the stack
  std::array<std::byte, 4096> buffer{};
  std::pmr::monotonic_buffer_resource pool{buffer.data(), buffer.size()};

  // This is the only way to propagate the memory resource to nested objects.
  // Do not change the default resource until all mutations are complete.
  std::pmr::set_default_resource(&pool);

  std::pmr::polymorphic_allocator<> alloc{&pool};

  // Create an address book that allocates from the pool and deliberately skip its destructor
  // to avoid unnecessary overhead.
  auto *address_book = alloc.new_object<PmrAddressBook>();

  // Add a person
  address_book->people.emplace_back(
      "John Doe", 1234, "jdoe@example.com",
      std::initializer_list<PmrPhoneNumber>{{.number = "555-4321", .type = PmrPerson::PhoneType::PHONE_TYPE_HOME}});

  // Serialize to binary
  std::vector<std::byte> binary_data;
  auto write_result = hpp_proto::write_binpb(*address_book, binary_data);
  expect(write_result.ok());

  // Deserialize from binary into a new object using the same pool
  auto *read_book = alloc.new_object<PmrAddressBook>();
  auto read_result = hpp_proto::read_binpb(*read_book, binary_data);

  expect(read_result.ok());
  expect(*address_book == *read_book);
  expect(read_book->people[0].name == "John Doe");

  std::cout << "Successfully serialized and deserialized using PMR traits!\n";

#ifndef HPP_PROTO_DISABLE_GLAZE
  // JSON serialization works with PMR traits too
  auto json_result = hpp_proto::write_json(*address_book);
  expect(json_result.has_value());

  auto *json_read_book = alloc.new_object<PmrAddressBook>();
  auto json_read_result = hpp_proto::read_json(*json_read_book, json_result.value());
  expect(json_read_result.ok());
  expect(*address_book == *json_read_book);

  // Demonstrate that memory was allocated from the pool
  expect(json_read_book->people.get_allocator().resource() == &pool);
  expect(json_read_book->people[0].name.get_allocator().resource() == &pool);
  std::cout << "Successfully serialized and deserialized JSON using PMR traits!\n";
#endif

  return 0;
}
