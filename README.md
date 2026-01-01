# Hpp-proto
![linux](https://github.com/huangminghuang/hpp-proto/actions/workflows/linux.yml/badge.svg)![macos](https://github.com/huangminghuang/hpp-proto/actions/workflows/macos.yml/badge.svg)![windows](https://github.com/huangminghuang/hpp-proto/actions/workflows/windows.yml/badge.svg)
[![codecov](https://codecov.io/github/huangminghuang/hpp-proto/graph/badge.svg?token=C2DD0WLCRC&flag=ci)](https://codecov.io/github/huangminghuang/hpp-proto)[![Codacy Badge](https://app.codacy.com/project/badge/Grade/c629f1cf7a7c45b3b3640362da4ac95a)](https://app.codacy.com/gh/huangminghuang/hpp-proto/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

Hpp-proto is a modern, high-performance, and header-only C++23 implementation of Google's Protocol Buffers. It is designed from the ground up for extreme performance and minimal code size, making it an ideal choice for resource-constrained environments, real-time systems, and performance-critical applications.

The library leverages modern C++ features and a trait-based design to generate clean, efficient, and highly customizable C++ aggregates from your `.proto` files. It provides first-class support for both binary and JSON serialization, gRPC integration, and dynamic messages.

## Key Features

*   **High Performance**: Outperforms the official Google Protobuf library in many common use cases, especially in combined "set and serialize" operations.
*   **Modern C++23 Design**: Uses concepts, `consteval`, `std::span`, and other modern features for maximum type safety and performance. The generated code is clean, idiomatic, and easy to work with.
*   **Header-Only Core**: The core serialization library is header-only (with one external dependency for UTF-8 validation), simplifying integration into any build system.
*   **JSON Support**: First-class serialization and deserialization to and from the canonical ProtoJSON format, powered by the high-performance [glaze](https://github.com/stephenberry/glaze) library.
*   **Trait-Based Customization**: A unique trait-based system allows you to customize the generated types without modifying the generated code. Easily swap in custom containers, allocators (like `std::pmr`), or string types to perfectly match your application's memory management strategy.
*   **Non-Owning Deserialization**: Supports a "non-owning" mode that deserializes into views (`std::string_view`, `std::span`), drastically reducing allocations and memory copies.
*   **gRPC Integration**: A built-in adapter allows you to use `hpp-proto` generated messages directly in your gRPC client and server applications. ([docs/grpc-adapter.md](docs/grpc-adapter.md)).
*   **Dynamic Messages**: A descriptor-driven API allows for runtime processing of messages (including JSON/proto I/O) without needing the compile-time generated types. ([docs/dynamic_message.md](docs/dynamic_message.md)).
*   **Minimal Code Size**: Generates significantly smaller binary sizes compared to libprotobuf.
*   **Supports Editions, Proto2, and Proto3**: Fully compatible with modern Protobuf features.

## Performance Highlights

Hpp-proto is optimized for scenarios where messages are built or modified and then serialized. While Google's library may be faster in raw serialization of already-constructed objects, hpp-proto shows superior overall performance in combined set-and-serialize benchmarks.

<table>
  <tr>
    <td>
      <a href="benchmarks/Mac_bench.json"><img src="benchmarks/Mac_bench.png" alt="Mac Benchmark" width="400"></a>
    </td>
    <td>
      <a href="benchmarks/Linux_bench.json"><img src="benchmarks/Linux_bench.png" alt="Linux Benchmark" width="400"></a>
    </td>
  </tr>
</table>

For more details, see the [benchmarks](benchmarks/ReadMe.md) directory.

## Getting Started

This guide will walk you through creating a simple application using `hpp-proto` with CMake.

### Prerequisites

*   A C++23 compatible compiler (e.g., Clang 19+, GCC 13+).
*   CMake (version 3.24 or newer).
*   The `protoc` compiler. You can download it from the [official Protocol Buffers releases page](https://protobuf.dev/downloads).

### Step 1: Define Your Protocol Format 

Create a file named `addressbook.proto`:

```protobuf
// addressbook.proto
syntax = "proto3";

package tutorial;

message Person {
  string name = 1;
  int32 id = 2;
  string email = 3;

  enum PhoneType {
    MOBILE = 0;
    HOME = 1;
    WORK = 2;
  }

  message PhoneNumber {
    string number = 1;
    PhoneType type = 2;
  }

  repeated PhoneNumber phones = 4;
}

message AddressBook {
  repeated Person people = 1;
}
```

### Step 2: Set Up Your CMake Project

Create a `CMakeLists.txt` file. We recommend using `FetchContent` to integrate `hpp-proto` seamlessly.

```cmake
cmake_minimum_required(VERSION 3.25)
project(hpp_proto_tutorial LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  hpp_proto
  GIT_REPOSITORY https://github.com/huangminghuang/hpp-proto.git
  GIT_TAG main
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(hpp_proto)

# Create a library from our .proto file.
# The generated headers will be available to targets that link against it.
add_library(addressbook_lib INTERFACE addressbook.proto)
target_include_directories(addressbook_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(TARGET addressbook_lib)

# Create our main executable
add_executable(tutorial_proto main.cpp)

# Link the generated code and hpp-proto to our executable
target_link_libraries(tutorial_proto PRIVATE addressbook_lib)
```

### Step 3: Write the C++ Code

Create a `main.cpp` file to define a `Person`, serialize it to binary and JSON, and then deserialize it back.

```cpp
#include "addressbook.pb.hpp"   // For binary serialization
#include "addressbook.glz.hpp"  // For JSON serialization
#include <iostream>
#include <cassert>

// By default, generated messages use std::string, std::vector, etc.
using Person = tutorial::Person<>;

int main() {
    Person p;
    p.id = 1234;
    p.name = "John Doe";
    p.email = "jdoe@example.com";
    p.phones.push_back({.number = "555-4321", .type = Person::PhoneType::HOME});

    // --- Binary Serialization ---
    std::string binary_buffer;
    if (!hpp::proto::write_binpb(p, binary_buffer).ok()) {
        std::cerr << "Binary serialization failed!" << std::endl;
        return 1;
    }

    Person p_from_binary;
    if (!hpp::proto::read_binpb(p_from_binary, binary_buffer).ok()) {
        std::cerr << "Binary deserialization failed!" << std::endl;
        return 1;
    }
    assert(p == p_from_binary);
    std::cout << "Binary round-trip successful!" << std::endl;

    // --- JSON Serialization ---
    std::string json_buffer;
    // Use indent<2> for pretty-printing
    if (!hpp::proto::write_json(p, json_buffer, hpp::proto::indent<2>).ok()) {
        std::cerr << "JSON serialization failed!" << std::endl;
        return 1;
    }
    std::cout << "\nSerialized JSON:\n" << json_buffer << std::endl;

    Person p_from_json;
    if (!hpp::proto::read_json(p_from_json, json_buffer).ok()) {
        std::cerr << "JSON deserialization failed!" << std::endl;
        return 1;
    }
    assert(p == p_from_json);
    std::cout << "\nJSON round-trip successful!" << std::endl;

    return 0;
}
```

### Step 4: Build and Run

From your project directory:

```bash
cmake -B build
cmake --build build
./build/tutorial_proto
```

You should see output indicating that both binary and JSON round-trips were successful.

## Advanced Usage & Concepts

### Trait-Based Design

One of `hpp-proto`'s most powerful features is its trait-based design, which decouples the generated message layout from specific container types. This lets you tailor the memory-management strategy (value-owning, arena-backed, view-only) for your messages without regenerating code.

*   **What Traits Customize**:
    *   `string_t`, `bytes_t`: Swap `std::string`/`std::vector<std::byte>` for `std::pmr::string`, `std::string_view`, or other string/byte containers.
    *   `repeated_t<T>`: Choose storage for repeated fields, like `std::pmr::vector`, `small_vector`, or `std::span`.
    *   `map_t<Key, Value>`: Use custom map-like containers (`flat_map`, `btree`, etc.).
    *   `optional_recursive_t<T>`: Control lifetimes for recursive messages.
    *   `unknown_fields_range_t`: Define how unknown fields are stored.

*   **Supplied Traits**:
    *   `hpp::proto::default_traits`: The default. Uses standard STL containers (`std::string`, `std::vector`).
    *   `hpp::proto::non_owning_traits`: Zero-copy views using `std::string_view` and `hpp::proto::equality_comparable_span`. Ideal for performance-critical parsing where you can guarantee the backing buffer outlives the message view.
    *   `hpp::proto::keep_unknown_fields<Base>`: A mixin to enable unknown-field retention for any base trait.

*   **Example: Using PMR Allocators**

  Simply define a new traits struct and use it as a template argument for your message.
  ```cpp
  #include <memory_resource>

  struct pmr_traits : hpp::proto::default_traits {
    using string_t = std::pmr::string;
    using bytes_t = std::pmr::vector<std::byte>;
    template <typename T>
    using repeated_t = std::pmr::vector<T>;
  };

  // This person will use PMR containers
  using PmrPerson = tutorial::Person<pmr_traits>;
  
  std::pmr::monotonic_buffer_resource mr;
  // When deserializing non-owning types, provide the memory resource.
  auto result = hpp::proto::read_binpb<PmrPerson>(buffer, hpp::proto::alloc_from{mr});
  ```

## Limitations

*   **JSON Options**: Lacks support for some of the extended JSON print options found in Google's C++ implementation, like `always_print_fields_with_no_presence` or `preserve_proto_field_names`.

---

For more examples and advanced use cases, please see the [tutorial](tutorial) directory.
