#include <iostream>
#include <memory_resource>
#include <source_location>
#include <vector>

#include "addressbook_proto3.glz.hpp"
#include "addressbook_proto3.pb.hpp"

#if defined(__has_include)
#if __has_include(<sanitizer/lsan_interface.h>)
#if defined(__SANITIZE_ADDRESS__)
#include <sanitizer/lsan_interface.h>
#define HPP_PROTO_HAS_LSAN 1
#endif
#endif
#endif

using PmrAddressBook = tutorial::AddressBook<hpp::proto::pmr_traits>;
using PmrPerson = tutorial::Person<hpp::proto::pmr_traits>;
using PmrPhoneNumber = PmrPerson::PhoneNumber;

struct lsan_ignoring_resource final : std::pmr::memory_resource {
  explicit lsan_ignoring_resource(std::pmr::memory_resource *upstream) : upstream_(upstream) {}

private:
  void *do_allocate(std::size_t bytes, std::size_t alignment) override {
    void *ptr = upstream_->allocate(bytes, alignment);
#if defined(HPP_PROTO_HAS_LSAN)
    __lsan_ignore_object(ptr);
#endif
    return ptr;
  }

  void do_deallocate(void *ptr, std::size_t bytes, std::size_t alignment) override {
    upstream_->deallocate(ptr, bytes, alignment);
  }

  bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override { return this == &other; }

  std::pmr::memory_resource *upstream_;
};

inline void expect(bool condition, const std::source_location location = std::source_location::current()) {
  if (!condition) {
    std::cerr << "assertion failure at " << location.file_name() << ":" << location.line() << "\n";
    exit(1);
  }
}

int main() {
  // Create a monotonic buffer resource on the stack
  std::array<std::byte, 4096> buffer{};
  lsan_ignoring_resource lsan_resource{std::pmr::get_default_resource()};
  std::pmr::monotonic_buffer_resource pool{buffer.data(), buffer.size(), &lsan_resource};

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
  auto write_result = hpp::proto::write_binpb(*address_book, binary_data);
  expect(write_result.ok());

  // Deserialize from binary into a new object using the same pool
  auto *read_book = alloc.new_object<PmrAddressBook>();
  auto read_result = hpp::proto::read_binpb(*read_book, binary_data);

  expect(read_result.ok());
  expect(*address_book == *read_book);
  expect(read_book->people[0].name == "John Doe");

  std::cout << "Successfully serialized and deserialized using PMR traits!\n";

#ifndef HPP_PROTO_DISABLE_GLAZE
  // JSON serialization works with PMR traits too
  auto json_result = hpp::proto::write_json(*address_book);
  expect(json_result.has_value());

  auto *json_read_book = alloc.new_object<PmrAddressBook>();
  auto json_read_result = hpp::proto::read_json(*json_read_book, json_result.value());
  expect(json_read_result.ok());
  expect(*address_book == *json_read_book);

  // Demonstrate that memory was allocated from the pool
  expect(json_read_book->people.get_allocator().resource() == &pool);
  expect(json_read_book->people[0].name.get_allocator().resource() == &pool);
  std::cout << "Successfully serialized and deserialized JSON using PMR traits!\n";
#endif

  return 0;
}
