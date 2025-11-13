# Hpp-proto
![linux](https://github.com/huangminghuang/hpp-proto/actions/workflows/linux.yml/badge.svg)![macos](https://github.com/huangminghuang/hpp-proto/actions/workflows/macos.yml/badge.svg)![windows](https://github.com/huangminghuang/hpp-proto/actions/workflows/windows.yml/badge.svg)
[![codecov](https://codecov.io/github/huangminghuang/hpp-proto/graph/badge.svg?token=C2DD0WLCRC)](https://codecov.io/github/huangminghuang/hpp-proto)[![Codacy Badge](https://app.codacy.com/project/badge/Grade/c629f1cf7a7c45b3b3640362da4ac95a)](https://app.codacy.com/gh/huangminghuang/hpp-proto/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

Hpp-proto is a lightweight, high-performance Protocol Buffers implementation in C++23. Generated messages are templates that map Protocol Buffers definitions to simple C++ aggregates whose member types are supplied by a trait parameter. The default trait sticks to familiar C++ standard library types so you can use the messages like plain aggregates. Apart from UTF-8 validation, the serialization code for these mapped aggregates is entirely header-only, keeping dependencies minimal.

Compared to Google’s implementation, hpp-proto adopts a minimalistic design that greatly reduces code size while offering superior performance in benchmarks where runtime reflection is unnecessary. Trait-driven generation also enables tailored memory layouts: swap in a view-based or arena-backed trait without touching generated code. These capabilities make hpp_proto an excellent choice for performance-critical, real-time, or resource-constrained environments. For gRPC usage, see [docs/grpc-adapter.md](docs/grpc-adapter.md) which details the client/server adapters, streaming caveats, and links to runnable tutorials/tests.
# Features
* Supports Protocol Buffers syntax 2 and 3 and [editions](https://protobuf.dev/editions/overview/).
* Supports the serialization of [ProtoJSON format](https://protobuf.dev/programming-guides/json/), utilizing a slightly modified version of the [glaze](https://github.com/stephenberry/glaze) library.
* Significantly smaller code size compared to Google's C++ implementation.
* Faster performance than Google's C++ implementation.
* Maps all Protocol Buffers message definitions to templated C++ aggregates whose member types come from user-provided traits.
* Aside from [UTF-8 validation](https://github.com/simdutf/is_utf8), all generated code and the core library are header-only.
* Each generated C++ aggregate is associated with static C++ reflection data for efficient Protocol Buffers encoding and decoding.
* All generated message types are equality-comparable, making them useful in unit testing.
* Completely exception-free.
* Ships ready-made trait sets, including owning (`hpp::proto::default_traits`) and view-based (`hpp::proto::non_owning_traits`) configurations, and composes them with mixins such as `hpp::proto::keep_unknown_fields`.
* Pick the trait per instantiation: alias the same generated message as an owning struct in one TU and a view in another, or supply a custom trait to integrate with your allocator, span, or container types.
* Enables compile-time serialization.

## Trait-Based Design
- **Goals**  
  - Decouple generated message layouts from specific container types.  
  - Let projects pick memory-management strategies (value-owning, arena-backed, view-only) without regenerating code.  
  - Support incremental migration: different translation units can use different traits for the same `.proto` without ABI conflicts.

- **What Traits Customize**  
  - `string_t`, `bytes_t`: swap `std::string`/`std::vector<std::byte>` for `std::pmr::string`, ropes, or view types.  
  - `repeated_t<T>`: choose storage for repeated fields; e.g. `std::pmr::vector`, `small_vector`, or spans.  
  - `map_t<Key, Value>`: hook map-like containers that match your performance profile (flat_map, ordered map, btree, etc.).  
- `optional_recursive_t<T>`: control how recursive embedded messages manage lifetimes; defaults to heap-based or view-based holders.  
- `unknown_fields_range_t`: determine how unknown data is preserved or discarded (mix in `keep_unknown_fields` to retain them).

- **Supplied Traits**  
  - `hpp::proto::default_traits`: owning aggregates backed by STL containers.  
  - `hpp::proto::non_owning_traits`: zero-copy views using `std::string_view` and `hpp::proto::equality_comparable_span`. Map fields are exposed as simple sequences of key/value pairs; no deduplication is attempted while reading or writing, so applications should treat the last entry for a repeated key as authoritative.  
  - `hpp::proto::keep_unknown_fields<Base>`: decorator that enables unknown-field retention for any base trait.

- **Custom Trait Example**

  ```cpp
  struct pmr_traits : hpp::proto::default_traits {
    using string_t = std::pmr::string;
    using bytes_t = std::pmr::vector<std::byte>;
    template <typename T>
    using repeated_t = std::pmr::vector<T>;
  };

  using PmrPerson = tutorial::Person<pmr_traits>;
  ```

  Because metadata generators (`pb_meta`, `glz::meta`, descriptors) mirror the message’s trait parameter, the rest of the API continues to work when you plug in your own containers.

  **Important:** Keep the composability contract intact: if you alias repeated/map containers to trivially destructible views (e.g. `std::span`) while `string_t`/`bytes_t` are owning types (e.g. `std::string`), destructors for nested values may never run, leaking resources. Always ensure the lifetime semantics between repeated/map containers and the element types remain compatible.

## Limitations
* Lacks runtime reflection support.
* Lacks support for extra json print options in the google C++ protobuf implementation like `always_print_fields_with_no_presence`, `always_print_enums_as_ints`,
  `preserve_proto_field_names` or`unquote_int64_if_possible`.

## Comparison with google protobuf C++ implementation
### System Configuration

| Platform |      Mac           |            Linux                |
|----------|--------------------|---------------------------------|
|    OS    |    MacOS 15.3.1    |         Ubuntu 22.04            |
|   CPU    | M1 Pro/MK193LL/A   |  Intel Core i9-11950H @ 2.60GHz |
| Compiler | Apple clang 16.0.0 |           gcc 12.3.0            |

Google protobuf version 29.3

### Runtime Performance 

We measured the runtime performance using the dataset and the benchmarks.proto definition from Google Protocol Buffers version 3.6.0. The benchmarks focus on three core operations: deserialization, setting a message (set_message), and setting a message combined with serialization (set_message and serialize). The performance was evaluated on two implementations: Google Protocol Buffers and hpp-proto, with regular and arena/non-owning modes being tested for each operation. 

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

The performance benchmarks clearly demonstrate the overall efficiency of the hpp_proto library compared to Google’s implementation across deserialization, setting a message, and setting a message with serialization operations. However, for the serialization operation alone, Google’s implementation may be faster than hpp-proto. This comes at the expense of the set_message operation, where hpp_proto significantly outperforms Google’s implementation.

It’s important to note that in real-world applications, setting a message is a prerequisite before serialization can take place. While Google’s implementation may offer faster serialization times, the combined time required for both setting a message and serializing shows that hpp_proto delivers better performance overall.


[Benchmark code is available here](benchmarks/benchmark.cpp)
### Code Size
We compared the code sizes of three equivalent programs: [hpp_proto_decode_encode](benchmarks/hpp_proto_decode_encode.cpp), [google_decode_encode](benchmarks/google_decode_encode.cpp) and [google_decode_encode_lite](benchmarks/google_decode_encode_lite.cpp). These programs are responsible for decoding and encoding messages defined in [benchmarks.proto](https://github.com/protocolbuffers/protobuf/blob/v3.6.0/benchmarks/benchmarks.proto), using the hpp-proto and Google Protocol Buffers implementations. The google_decode_encode program is statically linked with libprotobuf, while google_decode_encode_lite is linked with libprotobuf-lite.

<table>
  <tr>
    <td>
      <a href="benchmarks/Mac_sizes.json"><img src="benchmarks/Mac_sizes.png" alt="Mac Size Comparison" width="400"></a>
    </td>
    <td>
      <a href="benchmarks/Linux_sizes.json"><img src="benchmarks/Linux_sizes.png" alt="Linux Size Comparison" width="400"></a>
    </td>
  </tr>
</table>
 

## Getting Started
This section provides a quick introduction to the basic usage of hpp-proto to help you get started with minimal setup. It covers the essential steps required to integrate hpp-proto into your project and begin working with Protocol Buffers. For more advanced usage scenarios, optimizations, and additional features, please refer to the detailed examples in the [tutorial](tutorial) directory and [code generation guide](docs/Code_Generation_Guide.md) of the repository.

### Install google protoc 
If you haven’t installed the `protoc` compiler, [download the package](https://protobuf.dev/downloads) and follow the instructions in the README.

### [optional] Install hpp-proto

The hpp-proto library can be directly installed locally then use cmake `find_package` to solve the dependency,  or it can be used via cmake `FetchContent` mechanism.

```bash
git clone https://github.com/huangminghuang/hpp-proto.git 
cd hpp-proto
# use installed protoc by default or specify '-DHPP_PROTO_PROTOC=compile' to download google protobuf and compile protoc from source
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$HOME/local -Bbuild -S .
cmake --build build --target install
```

### Defining Your Protocol Format 

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

### Code generation 

```bash
    export PATH=$PATH:/path/to/protoc-gen-hpp
    protoc -I=$SRC_DIR --hpp_out=$DST_DIR $SRC_DIR/addressbook.proto
```

This generates the following files in your specified destination directory:

- `addressbook.msg.hpp`, the header which declares your generated messages.
- `addressbook.pb.hpp`, which contains the overloaded functions required for protobuf decoding/encoding.
- `addressbook.glz.hpp`, which contains the template specializations for JSON decoding/encoding.
- `addressbook.desc.hpp`, which contains the protobuf descriptors of the generated messages.


#### Code generation with CMake
<details open><summary> find_package  </summary>
<p>

```cmake
cmake_minimum_required(VERSION 3.24)

project(hpp_proto_tutorial 
        VERSION 1.0.0
        LANGUAGES CXX)

find_package(hpp_proto CONFIG REQUIRED)

add_library(addressbook_lib INTERFACE addressbook.proto)
target_include_directories(addressbook_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(TARGET addressbook_lib)

add_executable(tutorial_proto addressbook.cpp)
target_link_libraries(tutorial_proto PRIVATE addressbook_lib)
```
</p>
</details>

<details open><summary> FetchContent  </summary>
<p>

```cmake
cmake_minimum_required(VERSION 3.24)

project(hpp_proto_tutorial 
        VERSION 1.0.0
        LANGUAGES CXX)

include(FetchContent)

FetchContent_Declare(
  hpp_proto
  GIT_REPOSITORY https://github.com/huangminghuang/hpp-proto.git 
  GIT_TAG main
  GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(hpp_proto)
add_library(addressbook_lib INTERFACE addressbook.proto)
target_include_directories(addressbook_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_hpp(TARGET addressbook_lib)

add_executable(tutorial_proto addressbook.cpp)
target_link_libraries(tutorial_proto PRIVATE addressbook_lib)
```
</p>
</details>

## The hpp-proto API

Generated `.msg.hpp` headers stay lightweight: they declare only the data structures and avoid pulling in serialization helpers. Messages that depend on container types are emitted as templates whose member types come from the supplied `Traits` parameter. Nested enums and helper structs move into sibling namespaces and are re-exported through aliases so existing call sites can keep using familiar names.

```cpp
// addressbook_proto3.msg.hpp (excerpt)
namespace tutorial {

namespace Person__ {
  enum class PhoneType {
    PHONE_TYPE_UNSPECIFIED = 0,
    PHONE_TYPE_MOBILE = 1,
    PHONE_TYPE_HOME = 2,
    PHONE_TYPE_WORK = 3
  };

  template <typename Traits = ::hpp::proto::default_traits>
  struct PhoneNumber {
    using hpp_proto_traits_type = Traits;
    typename Traits::string_t number;
    PhoneType type = PhoneType::PHONE_TYPE_UNSPECIFIED;

    [[no_unique_address]] hpp::proto::pb_unknown_fields<Traits> unknown_fields_;
    bool operator==(const PhoneNumber&) const = default;
  };
} // namespace Person__

template <typename Traits = ::hpp::proto::default_traits>
struct Person {
  using hpp_proto_traits_type = Traits;
  using PhoneType = Person__::PhoneType;
  using PhoneNumber = Person__::PhoneNumber<Traits>;

  typename Traits::string_t name;
  std::int32_t id = {};
  typename Traits::string_t email;
  Traits::template repeated_t<PhoneNumber> phones;

  [[no_unique_address]] hpp::proto::pb_unknown_fields<Traits> unknown_fields_;
  bool operator==(const Person&) const = default;
};

template <typename Traits = ::hpp::proto::default_traits>
struct AddressBook {
  using hpp_proto_traits_type = Traits;
  Traits::template repeated_t<Person<Traits>> people;

  [[no_unique_address]] hpp::proto::pb_unknown_fields<Traits> unknown_fields_;
  bool operator==(const AddressBook&) const = default;
};

}
```

### Choosing Traits

Pick the trait that matches the memory model you need and alias it for readability:

```cpp
using OwningPerson = tutorial::Person<>;
using PersonView = tutorial::Person<hpp::proto::non_owning_traits>;
using PersonWithUnknowns = tutorial::Person<hpp::proto::keep_unknown_fields<hpp::proto::default_traits>>;
using WorkspaceAddressBook = tutorial::AddressBook<my_custom_traits>;
```

The same pattern applies to nested types: `OwningPerson::PhoneNumber` and `PersonView::PhoneNumber` refer to different instantiations of the generated template. The supporting metadata (`pb_meta`, `glz::meta`, descriptors) follows the message’s trait parameter automatically.

### Protobuf encoding/decoding APIs

The hpp-proto library provides an efficient and convenient interface for encoding and decoding Protobuf messages in C++. The two core functions are:

-	`write_proto()`: Serializes a generated C++ message object into the binary Protobuf format.
-	`read_proto()`: Deserializes a binary Protobuf-encoded buffer back into the corresponding C++ message object.

These APIs offer overloads that return either an `hpp::proto::status` or an `std::expected` (containing the result or an error). Alias the generated templates first, then invoke the helpers with the trait that matches your use case.

<details> 
<summary>Owning traits (`hpp::proto::default_traits`)</summary>
<p>

```cpp
#include <addressbook.pb.hpp>

using Person = tutorial::Person<>;

Person in_msg;
in_msg.name = "john";

std::string out_buffer;
if (!hpp::proto::write_proto(in_msg, out_buffer).ok()) {
  // Handle error.
}
assert(out_buffer == "\x0a\x04john");

std::expected<std::string, std::errc> write_result = hpp::proto::write_proto<std::string>(in_msg);
assert(write_result.value() == "\x0a\x04john");

std::string_view in_buffer = out_buffer;
Person out_msg;
if (!hpp::proto::read_proto(out_msg, in_buffer).ok()) {
  // Handle error.
}
assert(out_msg.name == "john");

std::expected<Person, std::errc> read_result = hpp::proto::read_proto<Person>(in_buffer);
assert(read_result.value().name == "john");
```
</p>
</details>
<details> <summary>View traits (`hpp::proto::non_owning_traits`)</summary>
<p>
In non-owning mode, variable-length fields become lightweight views such as `std::string_view` or `hpp::proto::equality_comparable_span`. Instead of copying values, the deserialized message references memory owned by a caller-provided buffer. Make sure that buffer outlives the message instance.

#### Key Differences in Non-Owning Mode

- `write_proto()`: No difference between regular and non-owning modes.
- `read_proto()`: Requires an option object containing a memory resource for managing allocations.

The memory resource must have an `allocate()` member function equivalent to [std::pmr::memory_resource::allocate](https://en.cppreference.com/w/cpp/memory/memory_resource/allocate), ensuring it returns at least the requested amount of memory and *never* indicates an error by returning `nullptr`. Errors should only be communicated through exceptions. 
Additionally, all allocated memory must be properly released when the memory resource is destroyed. 
For most use cases, [std::pmr::monotonic_buffer_resource](https://en.cppreference.com/w/cpp/memory/monotonic_buffer_resource) is recommended.


#### Providing Memory Resource to `read_proto()`

The option object allows you to specify memory resources for `read_proto()`:
-	`alloc_from`: All memory used by the deserialized value is allocated from the provided memory resource.

```cpp
#include <addressbook.pb.hpp>

using PersonView = tutorial::Person<hpp::proto::non_owning_traits>;

std::pmr::monotonic_buffer_resource pool;
std::string_view in_buffer = "\x0a\x04john";
PersonView out_msg;
if (!hpp::proto::read_proto(out_msg, in_buffer, hpp::proto::alloc_from{pool}).ok()) {
  // Handle error.
}
assert(out_msg.name == "john");

std::expected<PersonView, std::errc> read_result =
    hpp::proto::read_proto<PersonView>(in_buffer, hpp::proto::alloc_from{pool});
assert(read_result->name == "john");
```
</p>
</details>


### JSON encoding/decoding APIs
The hpp-proto library also supports encoding and decoding the C++ message objects to and from [canonical JSON encoding](https://protobuf.dev/programming-guides/proto3/#json) using the modified (glaze)[https://github.com/stephenberry/glaze] library. This ensures compatibility with the canonical JSON encoding of Protobuf messages. The key functions are:

-	`write_json()`: Serialize  a C++ message object into a JSON string.
-	`read_json()`: Deserialize a JSON string back into the corresponding C++ message object.

Similar to Protobuf APIs, the JSON APIs provide overloads that return either a status or an expected object.
In addition, `write_json()` can take an additional `indent` object for pretty printing. 
Below is a demonstration of how to use these functions for encoding and decoding in regular and non-owning modes.

<details><summary> Owning traits (`hpp::proto::default_traits`) </summary>
<p>

```cpp
#include "addressbook.glz.hpp"

using Person = tutorial::Person<>;
std::string out_json;
Person in_msg;
in_msg.name = "john";
if (!hpp::proto::write_json(in_msg, out_json).ok()) {
    // Handle error.
}

auto write_result = hpp::proto::write_json(in_msg);
assert(write_result.value() == out_json);

// Pretty printing with 3 spaces indent
if (!hpp::proto::write_json(in_msg, out_json, hpp::proto::indent<3>{}).ok()) {
    // Handle error.
}

Person out_msg;
std::string_view in_json = out_json;
if (!hpp::proto::read_json(out_msg, in_json).ok()) {
    // Handle error.
}

auto read_result = hpp::proto::read_json<Person>(in_json);
assert(read_result.value() == out_msg);
```
</p>
</details>
<details><summary> View traits (`hpp::proto::non_owning_traits`) </summary>
<p>

```cpp
#include "addressbook.glz.hpp"

using PersonView = tutorial::Person<hpp::proto::non_owning_traits>;
std::pmr::monotonic_buffer_resource pool;

std::string in_json = R"({"name":"john"})";
PersonView out_person;
if (!hpp::proto::read_json(out_person, in_json, hpp::proto::alloc_from{pool}).ok()) {
    // Handle error.
}

auto read_result = hpp::proto::read_json<PersonView>(in_json, hpp::proto::alloc_from{pool});
assert(read_result.value() == out_person);
```
</p>
</details>
