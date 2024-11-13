# Hpp-proto
![linux](https://github.com/huangminghuang/hpp-proto/actions/workflows/linux.yml/badge.svg)![macos](https://github.com/huangminghuang/hpp-proto/actions/workflows/macos.yml/badge.svg)![windows](https://github.com/huangminghuang/hpp-proto/actions/workflows/windows.yml/badge.svg)
[![codecov](https://codecov.io/github/huangminghuang/hpp-proto/graph/badge.svg?token=C2DD0WLCRC)](https://codecov.io/github/huangminghuang/hpp-proto)[![Codacy Badge](https://app.codacy.com/project/badge/Grade/c629f1cf7a7c45b3b3640362da4ac95a)](https://app.codacy.com/gh/huangminghuang/hpp-proto/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

Hpp-proto is a lightweight, high-performance Protocol Buffers implementation for C++20. It maps Protocol Buffers messages directly to simple C++ aggregates, using only C++ built-in or standard library types. Apart from UTF-8 validation, the serialization code for these mapped aggregates is entirely header-only, ensuring minimal dependencies and efficient performance.

Compared to Google’s implementation, hpp-proto features a minimalistic design that significantly reduces code size while delivering superior performance in our benchmarks when runtime reflection is not required. This makes hpp-proto an ideal choice for performance-critical, resource-constrained environments where minimizing binary size is a priority.
# Features
* Supports Protocol Buffers syntax 2 and 3 (excluding `service`) and [editions](https://protobuf.dev/editions/overview/).
* Supports the serialization of [ProtoJSON format](https://protobuf.dev/programming-guides/json/), utilizing a slightly modified version of the [glaze](https://github.com/stephenberry/glaze) library.
* Significantly smaller code size compared to Google's C++ implementation.
* Faster performance than Google's C++ implementation.
* Maps all Protocol Buffers message definitions to simple C++ aggregates using standard C++ library types.
* Aside from [UTF-8 validation](https://github.com/simdutf/is_utf8), all generated code and the core library are header-only.
* Each generated C++ aggregate is associated with static C++ reflection data for efficient Protocol Buffers encoding and decoding.
* All generated message types are equality-comparable, making them useful in unit testing.
* Completely exception-free.
* Supports non-owning mode code generation, mapping string and repeated fields to `std::string_view` and `hpp::proto::equality_comparable_span` which derives from `std::span` and adds the equality comparator.
* Enables compile-time serialization.

## Limitations
* Lacks runtime reflection support.
* Lacks support for extra json print options like `always_print_fields_with_no_presence`, `always_print_enums_as_ints`,
  `preserve_proto_field_names` or`unquote_int64_if_possible`.
* Unknown fields are always discarded during deserialization.

## Comparison with google protobuf C++ implementation
### System Configuration

| Platform |      Mac         |            Linux                |
|----------|------------------|---------------------------------|
|    OS    |    MacOS 14.7    |         Ubuntu 22.04            |
|   CPU    | M1 Pro/MK193LL/A |  Intel Core i9-11950H @ 2.60GHz |
| Compiler | Apple clang 15.0 |           gcc 12.3.0            |

Google protobuf version 28.2

### Runtime Performance 

We measured the runtime performance using the dataset and the benchmarks.proto definition from Google Protocol Buffers version 3.6.0. The benchmarks focus on three core operations: deserialization, setting a message (set_message), and setting a message combined with serialization (set_message and serialize). The performance was evaluated on two implementations: Google Protocol Buffers and hpp-proto, with regular and arena/non-owning modes being tested for each operation. 

<table><thead>
  <tr>
    <th colspan="7"> Operations CPU time on Mac </th>
  </tr></thead>
<tbody>
  <tr>
    <td></td>
    <td colspan="2">deserialize</td>
    <td colspan="2">set_message</td>
    <td colspan="2">set_message and serialize</td>
  </tr>
  <tr>
    <td></td>
    <td>regular</td>
    <td>arena/non_owning</td>
    <td>regular</td>
    <td>arena/non_owning</td>
    <td>regular</td>
    <td>arena/non_owning</td>
  </tr>
 <tr>
   <td>google CPU time</td>
   <td><div align="right">475.0&nbsp;ns</div></td>
   <td><div align="right">366.0&nbsp;ns</div></td>
   <td><div align="right">382.0&nbsp;ns</div></td>
   <td><div align="right">268.0&nbsp;ns</div></td>
   <td><div align="right">509.0&nbsp;ns</div></td>
   <td><div align="right">426.0&nbsp;ns</div></td>
 </tr>
 <tr>
   <td>hpp_proto CPU time</td>
   <td><div align="right">283.0&nbsp;ns</div></td>
   <td><div align="right">170.0&nbsp;ns</div></td>
   <td><div align="right">81.0&nbsp;ns</div></td>
   <td><div align="right">8.38&nbsp;ns</div></td>
   <td><div align="right">285.0&nbsp;ns</div></td>
   <td><div align="right">182.0&nbsp;ns</div></td>
 </tr>
 <tr>
   <td>hpp_proto speedup factor</td>
   <td><div align="right">1.67</div></td>
   <td><div align="right">2.15</div></td>
   <td><div align="right">4.71</div></td>
   <td><div align="right">31.98</div></td>
   <td><div align="right">1.78</div></td>
   <td><div align="right">2.34</div></td>
 </tr>
</tbody>
</table>

<table><thead>
  <tr>
    <th colspan="7"> Operations CPU time on Linux </th>
  </tr></thead>
<tbody>
  <tr>
    <td></td>
    <td colspan="2">deserialize</td>
    <td colspan="2">set_message</td>
    <td colspan="2">set_message and serialize</td>
  </tr>
  <tr>
    <td></td>
    <td>regular</td>
    <td>arena/non_owning</td>
    <td>regular</td>
    <td>arena/non_owning</td>
    <td>regular</td>
    <td>arena/non_owning</td>
  </tr>
 <tr>
   <td>google CPU time</td>
   <td><div align="right">443.0&nbsp;ns</div></td>
   <td><div align="right">255.0&nbsp;ns</div></td>
   <td><div align="right">120.0&nbsp;ns</div></td>
   <td><div align="right">114.0&nbsp;ns</div></td>
   <td><div align="right">247.0&nbsp;ns</div></td>
   <td><div align="right">242.0&nbsp;ns</div></td>
 </tr>
 <tr>
   <td>hpp_proto CPU time</td>
   <td><div align="right">198.0&nbsp;ns</div></td>
   <td><div align="right">160.0&nbsp;ns</div></td>
   <td><div align="right">34.6&nbsp;ns</div></td>
   <td><div align="right">11.3&nbsp;ns</div></td>
   <td><div align="right">142.0&nbsp;ns</div></td>
   <td><div align="right">122.0&nbsp;ns</div></td>
 </tr>
 <tr>
   <td>hpp_proto speedup factor</td>
   <td><div align="right">2.23</div></td>
   <td><div align="right">1.59</div></td>
   <td><div align="right">3.47</div></td>
   <td><div align="right">10.08</div></td>
   <td><div align="right">1.73</div></td>
   <td><div align="right">1.98</div></td>
 </tr>
</tbody>
</table>

The performance benchmarks clearly demonstrate the overall efficiency of the hpp_proto library compared to Google’s implementation across deserialization, setting a message, and setting a message with serialization operations. However, for the serialization operation alone, Google’s implementation may be faster than hpp-proto. This comes at the expense of the set_message operation, where hpp_proto significantly outperforms Google’s implementation.

It’s important to note that in real-world applications, setting a message is a prerequisite before serialization can take place. While Google’s implementation may offer faster serialization times, the combined time required for both setting a message and serializing shows that hpp_proto delivers better performance overall.


[Benchmark code is available here](benchmarks/benchmark.cpp)
### Code Size
We compared the code sizes of three equivalent programs: [hpp_proto_decode_encode](benchmarks/hpp_proto_decode_encode.cpp), [google_decode_encode](benchmarks/google_decode_encode.cpp) and [google_decode_encode_lite](benchmarks/google_decode_encode_lite.cpp). These programs are responsible for decoding and encoding messages defined in [benchmarks.proto](https://github.com/protocolbuffers/protobuf/blob/v3.6.0/benchmarks/benchmarks.proto), using the hpp-proto and Google Protocol Buffers implementations. The google_decode_encode program is statically linked with libprotobuf, while google_decode_encode_lite is linked with libprotobuf-lite.

<table>
<thead>
  <tr>
    <th colspan="3"> Code size in bytes </th>
  </tr></thead>
<tbody>
  <tr>
    <td> </td>
    <td> Mac </td>
    <td> Linux </td>
  </tr>
  <tr>
    <td> google_decode_encode </td>
    <td><div align="right">2624344</div></td>
    <td><div align="right">3410088</div></td>
  </tr>
  <tr>
    <td> google_decode_encode_lite </td>
    <td><div align="right">1106408</div></td>
    <td><div align="right">1474208</div></td>
  </tr>
  <tr>
    <td> hpp_proto_decode_encoded </td>
    <td><div align="right">114152</div></td>
    <td><div align="right">87144</div></td>
  </tr>
</tbody>
</table>
 
The comparison highlights a significant reduction in code size when using hpp-proto compared to Google’s Protocol Buffers implementations. On macOS, hpp-proto offers a 22.99x reduction in size compared to google_decode_encode and a 9.68x reduction compared to google_decode_encode_lite. The reduction is even more pronounced on Linux, where hpp-proto reduces the code size by 39.13x compared to google_decode_encode and by 16.91x compared to google_decode_encode_lite.


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
protobuf_generate(TARGET addressbook_lib
                  LANGUAGE hpp
# uncomment the next line for non-owning mode                 
#                 PLUGIN_OPTIONS non_owning 
)

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
protobuf_generate(TARGET addressbook_lib
                  LANGUAGE hpp
# uncomment the next line for non-owning mode  
#                 PLUGIN_OPTIONS non_owning 
)

add_executable(tutorial_proto addressbook.cpp)
target_link_libraries(tutorial_proto PRIVATE addressbook_lib)
```
</p>
</details>

## The hpp-proto API

The mapping from proto messages to their C++ counterparts is straight forward, as shown in the following generated code. 
Notice that the `*.msg.hpp` only contains the minimum message definitions and avoid the inclusion of headers related to the protobuf/JSON 
encoding/decoding facilities. This makes those generated structures easier to be used as basic vocabulary types among modules without incurring unnecessary dependencies. 

Below are the examples of the generated code for the `addressbook.proto` file in regular and non-owning modes.
<details><summary> Regular Mode </summary>
<p>

```cpp
// addressbook.msg.hpp
namespace tutorial {

using namespace hpp::proto::literals;
struct Person {
  enum class PhoneType {
    MOBILE = 0,
    HOME = 1,
    WORK = 2 
  };

  struct PhoneNumber {
    std::string number = {};
    PhoneType type = PhoneType::MOBILE;

    bool operator == (const PhoneNumber&) const = default;
  };

  std::string name = {};
  int32_t id = {};
  std::string email = {};
  std::vector<PhoneNumber> phones;

  bool operator == (const Person&) const = default;
};

struct AddressBook {
  std::vector<Person> people;

  bool operator == (const AddressBook&) const = default;
};
}

// addressbook.pb.hpp
#include "addressbook.msg.hpp"
namespace tutorial {
  auto pb_meta(const Person &) -> std::tuple<...> ;
  auto pb_meta(const Person::PhoneNumber &) -> std::tuple<...> ;
  auto pb_meta(const AddressBook &) -> std::tuple<...>;
}
```
</p>
</details>
<details><summary> Non-owning Mode </summary>
<p>

```cpp
// addressbook.msg.hpp
namespace tutorial {

using namespace hpp::proto::literals;
struct Person {
  enum class PhoneType {
    MOBILE = 0,
    HOME = 1,
    WORK = 2 
  };

  struct PhoneNumber {
    std::string_view number = {};
    PhoneType type = PhoneType::MOBILE;

    bool operator == (const PhoneNumber&) const = default;
  };

  std::string_view name = {};
  int32_t id = {};
  std::string_view email = {};
  hpp::proto::equality_comparable_span<const PhoneNumber> phones;

  bool operator == (const Person&) const = default;
};

struct AddressBook {
  hpp::proto::equality_comparable_span<const Person> people;

  bool operator == (const AddressBook&) const = default;
};
}

// addressbook.pb.hpp
#include "addressbook.msg.hpp"
namespace tutorial {
  auto pb_meta(const Person &) -> std::tuple<...> ;
  auto pb_meta(const Person::PhoneNumber &) -> std::tuple<...> ;
  auto pb_meta(const AddressBook &) -> std::tuple<...>;
}
```
</p>
</details>

### Protobuf encoding/decoding APIs

The hpp-proto library provides convenient functions for encoding and decoding Protobuf messages in C++. The core functions are:

-	write_proto: Used to serialize a C++ structure into a Protobuf message format, typically stored in a binary buffer (e.g., std::vector<std::byte>).
-	read_proto: Used to deserialize a Protobuf-encoded binary buffer back into the corresponding C++ structure.

These APIs allow you to serialize and deserialize data efficiently, with overloads that return either a success/error status or an expected object (containing the result or an error). Below is the demonstration of how to use these functions in regular and non-owning modes.

</details>
<details><summary> Regular Mode </summary>
<p>

```cpp
#include "addressbook.pb.hpp"

int main() {
  using enum tutorial::Person::PhoneType;
  tutorial::AddressBook address_book{
      .people = {{.name = "Alex",
                 .id = 1,
                 .email = "alex@email.com",
                 .phones = {{.number = "1111111", 
                             .type = MOBILE}}},
                 {.name = "Bob",
                  .id = 2,
                  .email = "bob@email.com",
                  .phones = {{.number = "22222222", 
                              .type = HOME}}} }};

  std::vector<std::byte> buffer;

  if (!hpp::proto::write_proto(address_book, buffer).ok()) {
    std::cerr << "protobuf serialization failed\n";
    return 1;
  }

  // alternatively, use the overload returning an expected object
  hpp::proto::expected<std::vector<std::byte>, std::errc> write_result 
    = hpp::proto::write_proto(address_book);
  assert(write_result.value() == buffer);

  tutorial::AddressBook new_address_book;

  if (!hpp::proto::read_proto(new_address_book, buffer).ok()) {
    std::cerr << "protobuf deserialization failed\n";
    return 1;
  }

  // alternatively, use the overload returning an expected object
  hpp::proto::expected<tutorial::AddressBook, std::errc> read_result 
    = hpp::proto::read_proto<tutorial::AddressBook>(buffer);
  assert(read_result.value() == new_address_book);
  return 0;
}
```
</p>
</details>

<details><summary> Non-owning Mode </summary>
<p>

```cpp
#include "addressbook.pb.hpp"
#include <memory_resource>

int main() {
  using enum tutorial::Person::PhoneType;
  using namespace std::string_view_literals;
  std::pmr::monotonic_buffer_resource pool;
  std::pmr::vector<tutorial::Person::PhoneNumber> alex_phones{&pool};
  alex_phones.push_back({.number = "1111111"sv, .type = MOBILE});
  std::pmr::vector<tutorial::Person> people{&pool};
  people.reserve(2);
  people.emplace_back("Alex"sv, 1, "alex@email.com"sv, alex_phones);
  std::pmr::vector<tutorial::Person::PhoneNumber> bob_phones{&pool};
  bob_phones.push_back({.number = "22222222"sv, .type = HOME});
  people.emplace_back("Bob"sv, 2, "bob@email.com"sv, bob_phones);

  tutorial::AddressBook address_book;
  address_book.people = people;

  std::pmr::vector<std::byte> buffer{&pool};

  if (!hpp::proto::write_proto(address_book, buffer).ok()) {
    std::cerr << "protobuf serialization failed\n";
    return 1;
  }

  // alternatively, use the overload returning an expected object
  hpp::proto::expected<std::pmr::vector<std::byte>, std::errc> write_result 
    = hpp::proto::write_proto<std::pmr::vector<std::byte>>(address_book);
  assert(write_result.value() == buffer);

  tutorial::AddressBook new_address_book;

  if (!hpp::proto::read_proto(new_address_book, buffer, hpp::proto::pb_context{pool}).ok()) {
    std::cerr << "protobuf deserialization failed\n";
    return 1;
  }

  // alternatively, use the overload returning an expected object
  hpp::proto::expected<tutorial::AddressBook, std::errc> read_result 
    = hpp::proto::read_proto<tutorial::AddressBook>(buffer, hpp::proto::pb_context{pool});
  assert(read_result.value() == new_address_book);

  return 0;
}
```
</p>
</details>

### JSON encoding/decoding APIs

The hpp-proto library also supports encoding and decoding Protobuf messages to and from [canonical JSON encoding](https://protobuf.dev/programming-guides/proto3/#json) using the modified (glaze)[https://github.com/stephenberry/glaze] library. This ensures compatibility with the canonical JSON encoding of Protobuf messages. The key functions are:

-	`write_json`: Used to serialize a C++ structure into a JSON string.
-	`read_json`: Used to deserialize a JSON string back into the corresponding C++ structure.

Similar to Protobuf, the JSON APIs provide overloads that return either a success/error status or an expected object. Below is a demonstration of how to use these functions for encoding and decoding in regular and non-owning modes.

</details>
<details><summary> Regular Mode </summary>
<p>

```cpp

#include "addressbook.glz.hpp"

// ....
std::string json;

if (!hpp::proto::write_json(address_book, json).ok()) {
    std::cerr << "write json error\n";
    return 1;
}

// alternatively, use the overload returning an expected object
auto write_result = hpp::proto::write_json(address_book);
assert(write_result.value() == json);

tutorial::AddressBook new_book;
if (auto e = hpp::proto::read_json(new_book, json); !e.ok()) {
    std::cerr << "read json error: " << e.message(json) << "\n";
    return 1;
}

// alternatively, use the overload returning an expected object
auto read_result = hpp::proto::read_json<tutorial::AddressBook>(json);
assert(read_result.value() == new_address_book);
```
</p>
</details>
<details><summary> Non-owning Mode </summary>
<p>

```cpp

#include "addressbook.glz.hpp"

// ....
std::pmr::string json{&pool};

if (!hpp::proto::write_json(address_book, json).ok()) {
    std::cerr << "write json error\n";
    return 1;
}

// alternatively, use the overload returning an expected object
auto write_result = hpp::proto::write_json<std::pmr::string>(address_book, hpp::proto::json_context{pool});
assert(write_result.value() == json);

tutorial::AddressBook new_book;
if (auto e = hpp::proto::read_json(new_book, json, hpp::proto::json_context{pool}); !e.ok()) {
    std::cerr << "read json error: " << e.message(json) << "\n";
    return 1;
}

// alternatively, use the overload returning an expected object
auto read_result = hpp::proto::read_json<tutorial::AddressBook>(json, hpp::proto::json_context{pool});
assert(read_result.value() == new_address_book);
```
</p>
</details>