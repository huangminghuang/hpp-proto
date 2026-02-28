# Dynamic Messages (Tutorial)

Dynamic messages provide a powerful way to work with Protocol Buffers schema at runtime, without needing to generate C++ code beforehand. This is particularly useful for scenarios like:

*   Loading and interacting with schemas discovered or uploaded at runtime (e.g., plugins, user-defined data formats).
*   Achieving predictable memory allocations using caller-owned memory resources like `std::pmr::monotonic_buffer_resource`.
*   Mirroring generated protobuf semantics (presence, defaults, oneof, enums, well-known types) through a type-safe API based on descriptors.
*   Serializing and deserializing messages via binary proto or JSON formats, adhering to the same validation rules as compile-time generated code.

This guide will walk you through building and manipulating protobuf messages dynamically using `hpp-proto`'s descriptor-driven API. The examples mirror the style found in `tutorial/dynamic_message/tutorial_proto3_dynamic.cpp`.

## Prerequisites: Generate a FileDescriptorSet

Before you can work with dynamic messages, you need a binary representation of your `.proto` schema. You can generate this using `protoc` (your protoc-gen-hpp plugin is not needed for this step):

```bash
protoc --include_imports --descriptor_set_out=addressbook_proto3.desc.binpb addressbook_proto3.proto
```
This command will create `addressbook_proto3.desc.binpb`, a binary file containing the descriptor information for your `addressbook.proto` file and all its imported dependencies.

## 1) Build a Factory

The `hpp_proto::dynamic_message_factory` is responsible for owning and managing the loaded descriptors. Individual dynamic messages created by the factory will borrow a caller-owned `std::pmr::monotonic_buffer_resource` for their allocations.

### CMake Linking

`dynamic_message_factory` is provided by the `hpp_proto::dynamic_message` target:

```cmake
target_link_libraries(your_target PRIVATE hpp_proto::dynamic_message)
```

### API Notes

* `dynamic_message_factory` has no default constructor. Create it via `dynamic_message_factory::create(...)`.
* `create(...)` returns `std::expected<dynamic_message_factory, dynamic_message_errc>`.
* `create(...)` overloads accept an optional allocator parameter via
  `dynamic_message_factory::impl_allocator_type`.
* By design, `create(...)` does not catch `std::bad_alloc` thrown by standard containers.

```cpp
#include <hpp_proto/dynamic_message/binpb.hpp>
#include <fstream>
#include <vector>
#include <string>
#include <iostream>

// Helper function to read a file into a string (for demonstration)
std::string read_file_into_string(const std::string& filename) {
    std::ifstream is(filename, std::ios::binary);
    if (!is) {
        std::cerr << "Error: Could not open file " << filename << "\n";
        return {};
    }
    return std::string((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
}

int main() {
    // Load the generated FileDescriptorSet
    std::string filedescriptorset_binpb = read_file_into_string("addressbook_proto3.desc.binpb");
    if (filedescriptorset_binpb.empty()) {
        std::cerr << "Error: Failed to load descriptor file.\n";
        return 1;
    }

    auto factory_result = hpp_proto::dynamic_message_factory::create(filedescriptorset_binpb);
    if (!factory_result.has_value()) {
        std::cerr << "Error: Factory initialization failed (bad descriptors).\n";
        return 1;
    }
    auto factory = std::move(factory_result).value();

    // ... rest of your code
    return 0;
}
```

## 2) Create a Message

Once the factory is initialized, you can create dynamic message instances. Each message requires its own `std::pmr::monotonic_buffer_resource` for memory management.

```cpp
// ... (inside main after factory initialization)

    std::pmr::monotonic_buffer_resource mr; // Arena for this message instance
    auto em_expected = factory.get_message("tutorial.Person", mr); // Using the package.MessageName
    
    if (!em_expected) {
        std::cerr << "Error: Unknown message name or failed to create message\n";
        return 1;
    }
    
    hpp_proto::message_value_mref msg = *em_expected; // Mutable reference to the dynamic message

    // ...
```

## 3) Untyped Field Access (Set/Get by Name/Number)

`set_field_by_name/number` and `field_value_by_name/number` are convenient helpers for accessing fields dynamically. They return `std::expected` to indicate success or failure.

```cpp
// ... (inside main, after creating msg)

    // No-exception style: check the expected result
    auto result_set_name = msg.set_field_by_name("name", "John Doe");
    if (!result_set_name) {
        std::cerr << "Error setting name.\n";
    }

    auto result_set_id = msg.set_field_by_name("id", 1234);
    if (!result_set_id) {
        std::cerr << "Error setting id.\n";
    }

    auto name_expected = msg.field_value_by_name<std::string_view>("name");
    if (name_expected.has_value()) {
        std::cout << "Person name (untyped access): " << *name_expected << "\n";
    } else {
        std::cerr << "Error getting name.\n";
    }

    // Exception style: use .value() if you're certain it won't fail or want exceptions
    try {
        int id_val = msg.field_value_by_number<std::int32_t>(2).value();
        std::cout << "Person ID (untyped access, exception style): " << id_val << "\n";
    } catch (const std::bad_expected_access& e) {
        std::cerr << "Error getting ID: " << e.what() << "\n";
    }

    // Special notes:
    // - For Proto2/oneof fields, `has_value()` drives presence. Scalar fields will return defaults if unset.
    // - Message fields must be explicitly materialized (e.g., via `emplace()`) before dereferencing.
```

## 4) Typed Field References (Preferred)

For more robust and type-aware access, use typed field references (`_mref` for mutable, `_cref` for const). These references directly correspond to protobuf types (`int32_field_mref`, `string_field_mref`, `enum_field_mref`, `message_field_mref`, etc.).

```cpp
// ... (inside main)

    using namespace std::string_view_literals;

    // Accessing an int32 field
    if (auto int_ref_expected = msg.typed_ref_by_name<hpp_proto::int32_field_mref>("id")) {
        int_ref_expected->set(5678); // Exact type match is enforced
    } else {
        std::cerr << "Error getting typed ref for id.\n";
    }

    // Accessing a string field
    if (auto str_ref_expected = msg.typed_ref_by_name<hpp_proto::string_field_mref>("email")) {
        str_ref_expected->set("dynamic@example.com"sv);
    } else {
        std::cerr << "Error getting typed ref for email.\n";
    }

    // Accessing an enum field inside a repeated message field
    if (auto phones_ref_expected = msg.typed_ref_by_name<hpp_proto::repeated_message_field_mref>("phones")) {
        auto phones_list = *phones_ref_expected;
        auto phone_msg = phones_list.emplace_back();
        if (auto enum_ref_expected = phone_msg.typed_ref_by_name<hpp_proto::enum_field_mref>("type")) {
            auto enum_set_result_num = enum_ref_expected->set(hpp_proto::enum_number{tutorial::Person::MOBILE});
            if (!enum_set_result_num) {
                std::cerr << "Error setting enum by number.\n";
            }
            auto enum_set_result_name = enum_ref_expected->set(hpp_proto::enum_name{"HOME"sv});
            if (!enum_set_result_name) {
                std::cerr << "Error setting enum by name.\n";
            }
        } else {
            std::cerr << "Error getting typed ref for phone.type.\n";
        }
    } else {
        std::cerr << "Error getting typed ref for phones.\n";
    }
```

### Message Fields (Nested Messages)

For nested message fields, you must check their presence and then `emplace()` to allocate and get a mutable child message reference.

```cpp
// ... (inside main)

    auto address_book_expected = factory.get_message("tutorial.AddressBook", mr);
    if (!address_book_expected) {
        std::cerr << "Error: Failed to create AddressBook message.\n";
        return 1;
    }
    hpp_proto::message_value_mref address_book_msg = *address_book_expected;

    auto people_repeated_expected = address_book_msg.typed_ref_by_name<hpp_proto::repeated_message_field_mref>("people");
    if (people_repeated_expected) {
        auto people_list = *people_repeated_expected;
        
        // Emplace a new Person message into the repeated field
        hpp_proto::message_value_mref new_person = people_list.emplace_back();
        
        // Now set fields on the new_person message
        new_person.set_field_by_name("name", "Jane Doe").value();
        new_person.set_field_by_name("id", 100).value();

        // Access and add a phone number to new_person
        auto phones_list_expected = new_person.typed_ref_by_name<hpp_proto::repeated_message_field_mref>("phones");
        if (phones_list_expected) {
            auto phones_list = *phones_list_expected;
            hpp_proto::message_value_mref new_phone = phones_list.emplace_back();
            new_phone.set_field_by_name("number", "111-222-3333").value();
            new_phone.set_field_by_name("type", hpp_proto::enum_name{"WORK"sv}).value();
        }
    }
    std::cout << "\nCreated dynamic AddressBook with a Person.\n";
```
**Important:** Reading a message field without first checking its presence (e.g., calling `has_value()` on an optional message reference) might lead to undefined behavior. For scalar, string, bytes, and enum fields, a default value is typically returned when unset.



### Repeated Fields

Repeated fields can be mutated using methods like `reserve`, `resize`, `push_back`, `emplace_back`, `set`, or `adopt`. Be aware that operations that might reallocate the underlying storage (like `reserve` or `resize`) can invalidate existing references to elements within that repeated field. Always reacquire references after such mutations.

#### Map Fields

In Protocol Buffers, a map field like `map<key_type, value_type> my_map = N;` is syntactic sugar for a repeated message field. `hpp-proto`'s dynamic API treats it exactly this way.

A map is exposed as a `repeated_message_field_mref`. Each element in this repeated field is a small message (a "map entry") containing two fields:
*   `key`: Field number **1**
*   `value`: Field number **2**

To add a new entry to a map, you `emplace_back` a new map entry message and then set its `key` and `value` fields by their numbers.

```cpp
// Given a .proto definition with a map:
// message MyMessage {
//   map<string, int32> attributes = 1;
// }

// ... inside main, assuming 'msg' is a dynamic message of type 'MyMessage'
auto map_ref_expected = msg.typed_ref_by_name<hpp_proto::repeated_message_field_mref>("attributes");
if (map_ref_expected) {
    auto map_field = *map_ref_expected;
    
    // Add a new entry to the map
    hpp_proto::message_value_mref new_entry = map_field.emplace_back();
    
    // Set the key (field number 1)
    new_entry.set_field_by_number(1, "level"sv);
    
    // Set the value (field number 2)
    new_entry.set_field_by_number(2, 42);

    // Add another entry
    hpp_proto::message_value_mref another_entry = map_field.emplace_back();
    another_entry.set_field_by_number(1, "power"sv).value();
    another_entry.set_field_by_number(2, 9001).value();
}
```

```cpp
// ... (inside main, continuing from AddressBook example)

    // Accessing the "people" repeated field again
    auto people_ref_expected = address_book_msg.typed_ref_by_name<hpp_proto::repeated_message_field_mref>("people");
    if (people_ref_expected) {
        auto people_list = *people_ref_expected;
        people_list.reserve(5); // Ensure capacity
        
        // Add another person
        hpp_proto::message_value_mref another_person = people_list.emplace_back();
        another_person.set_field_by_name("name", "Alex Smith").value();
        another_person.set_field_by_name("id", 200).value();
        
        // You can also set elements from a sized range (e.g., an array)
        // Note: For complex types like messages, direct "set" from a range usually implies a copy or move
        // For primitive types (like repeated_int32), it's more straightforward.
    }

## 5) Const Views with `cref()`

Every mutable reference (`_mref`) has a corresponding constant sibling (`_cref`). Call `cref()` on a message or field reference to obtain read-only access.

```cpp
// ... (inside main)

    hpp_proto::message_value_cref address_book_cref = address_book_msg.cref();
    if (auto people_cref_expected = address_book_cref.typed_ref_by_name<hpp_proto::repeated_message_field_cref>("people")) {
        auto people_list_cref = *people_cref_expected;
        if (!people_list_cref.empty()) {
            hpp_proto::message_value_cref first_person_cref = people_list_cref[0];
            auto name_cref_expected = first_person_cref.typed_ref_by_name<hpp_proto::string_field_cref>("name");
            if (name_cref_expected) {
                std::cout << "First person's name (const access): " << name_cref_expected->value() << "\n";
            }
        }
    }
```

## 6) Exceptions vs. `std::expected`

`hpp-proto` embraces `std::expected` for error handling, allowing for a no-exception style of programming.

*   **No-exception style**: Chain operations using `.and_then()` on `std::expected` returns, and check `.has_value()` or `.error()` to handle errors explicitly. Helpers like `hpp_proto::expected_message_mref` are designed for this fluent style.
*   **Exception style**: If exceptions are preferred, simply call `.value()` on the `std::expected` return types. This will throw `std::bad_optional_access` if the `expected` holds an error.

## 7) Full Example (`tutorial_proto3_dynamic.cpp`)

The `hpp_proto::expected_message_mref` is a fluent wrapper that streamlines chained mutations on dynamic messages. It automatically propagates `std::expected` errors, allowing complex operations to be written concisely.

A full, working example demonstrating dynamic message creation, field access, and manipulation (including nested messages and repeated fields) can be found in `tutorial/dynamic_message/tutorial_proto3_dynamic.cpp`. Additional snippets and test cases are also available in `tests/dynamic_message_test.cpp`.

For instance, adding a new person to an address book might look like this:

```cpp
// ... (from tutorial/dynamic_message/tutorial_proto3_dynamic.cpp)

    std::pmr::monotonic_buffer_resource mr;
    hpp_proto::expected_message_mref address_book_expected = factory.get_message("tutorial.AddressBook", mr);
    if (!address_book_expected) {
        // Handle error
        return 1;
    }
    hpp_proto::message_value_mref address_book_msg = *address_book_expected;

    // Use expected_message_mref for fluent chaining with error propagation
    address_book_expected
        .mutate_field_by_name("people", [&](hpp_proto::repeated_message_field_mref people) {
            return hpp_proto::expected_message_mref{people.emplace_back()}
                .set_field_by_name("name", "Alex")
                .set_field_by_name("id", 1)
                .mutate_field_by_name("phones", [](hpp_proto::repeated_message_field_mref phones) {
                    return hpp_proto::expected_message_mref{phones.emplace_back()}
                        .set_field_by_name("number", "19890604")
                        .set_field_by_name("type", hpp_proto::enum_name{"MOBILE"sv})
                        .done(); // End phone number chain
                })
                .done(); // End person chain
        })
        .done(); // End address book chain

    std::cout << "\nDynamically created AddressBook content:\n";
    std::cout << hpp_proto::write_json(address_book_msg).value() << "\n";

    // Binary serialization/deserialization also works
    std::string binary_data;
    hpp_proto::write_binpb(address_book_msg, binary_data).value();

    hpp_proto::message_value_mref deserialized_address_book = *factory.get_message("tutorial.AddressBook", mr);
    hpp_proto::read_binpb(deserialized_address_book, binary_data).value();
    
    std::cout << "\nDeserialized dynamic AddressBook content:\n";
    std::cout << hpp_proto::write_json(deserialized_address_book).value() << "\n";
```

## 8) Safety Reminders

When working with dynamic messages, it's crucial to keep the following in mind:

*   **Memory Resource Lifetime**: The `std::pmr::monotonic_buffer_resource` (or any `std::pmr::memory_resource`) you provide must remain alive and valid for as long as any `message_value_mref`, `message_value_cref`, or field references (`*_field_mref`/`*_cref`) that use that resource are in scope. Dynamic messages allocate all their internal data (strings, vectors, nested messages) from this resource.
*   **Repeated Field References**: Operations that modify the size or capacity of repeated fields (e.g., `reserve`, `resize`, `push_back`, `emplace_back` on a `repeated_*_field_mref`) can invalidate existing references to elements within that repeated field. Always reacquire references to individual elements after such mutations.
*   **Message Field Presence**: When reading scalar, string, bytes, or enum fields, accessing an unset field will return its default value. However, for nested message fields, always check `has_value()` before dereferencing (`.value()`) to ensure the message has been materialized. Directly accessing an unset message field can lead to undefined behavior.
