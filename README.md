# Hpp-proto
![linux](https://github.com/huangminghuang/hpp-proto/actions/workflows/linux.yml/badge.svg)![macos](https://github.com/huangminghuang/hpp-proto/actions/workflows/macos.yml/badge.svg)![windows](https://github.com/huangminghuang/hpp-proto/actions/workflows/windows.yml/badge.svg)
[![codecov](https://codecov.io/github/huangminghuang/hpp-proto/graph/badge.svg?token=C2DD0WLCRC)](https://codecov.io/github/huangminghuang/hpp-proto)[![Codacy Badge](https://app.codacy.com/project/badge/Grade/c629f1cf7a7c45b3b3640362da4ac95a)](https://app.codacy.com/gh/huangminghuang/hpp-proto/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

Hpp-proto is a lightweight, high-performance Protocol Buffers implementation in C++20. It maps Protocol Buffers messages directly to simple C++ aggregates, using only C++ built-in or standard library types. Apart from UTF-8 validation, the serialization code for these mapped aggregates is entirely header-only, ensuring minimal dependencies and efficient performance.

Compared to Google’s implementation, hpp-proto adopts a minimalistic design that greatly reduces code size while offering superior performance in benchmarks where runtime reflection is unnecessary. Additionally, hpp-proto supports a non-owning mode, mapping all variable-length fields to lightweight types such as std::string_view or equality_comparable_span. This mode allows users to customize memory management during deserialization, further enhancing efficiency. These features make hpp-proto an excellent choice for performance-critical, real-time, or resource-constrained environments.
# Features
* Supports Protocol Buffers syntax 2 and 3 and [editions](https://protobuf.dev/editions/overview/).
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

| Platform |      Mac           |            Linux                |
|----------|--------------------|---------------------------------|
|    OS    |    MacOS 14.7      |         Ubuntu 22.04            |
|   CPU    | M1 Pro/MK193LL/A   |  Intel Core i9-11950H @ 2.60GHz |
| Compiler | Apple clang 16.0.0 |           gcc 12.3.0            |

Google protobuf version 29.3

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
   <td><div align="right">472.0&nbsp;ns</div></td>
   <td><div align="right">346.0&nbsp;ns</div></td>
   <td><div align="right">372.0&nbsp;ns</div></td>
   <td><div align="right">250.0&nbsp;ns</div></td>
   <td><div align="right">516.0&nbsp;ns</div></td>
   <td><div align="right">398.0&nbsp;ns</div></td>
 </tr>
 <tr>
   <td>hpp_proto CPU time</td>
   <td><div align="right">294.0&nbsp;ns</div></td>
   <td><div align="right">177.0&nbsp;ns</div></td>
   <td><div align="right">72.6&nbsp;ns</div></td>
   <td><div align="right">8.38&nbsp;ns</div></td>
   <td><div align="right">275.0&nbsp;ns</div></td>
   <td><div align="right">181.0&nbsp;ns</div></td>
 </tr>
 <tr>
   <td>hpp_proto speedup factor</td>
   <td><div align="right">1.61</div></td>
   <td><div align="right">1.95</div></td>
   <td><div align="right">5.12</div></td>
   <td><div align="right">29.83</div></td>
   <td><div align="right">1.88</div></td>
   <td><div align="right">2.20</div></td>
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
   <td><div align="right">253.0&nbsp;ns</div></td>
   <td><div align="right">257.0&nbsp;ns</div></td>
   <td><div align="right">117.0&nbsp;ns</div></td>
   <td><div align="right">111.0&nbsp;ns</div></td>
   <td><div align="right">220.0&nbsp;ns</div></td>
   <td><div align="right">224.0&nbsp;ns</div></td>
 </tr>
 <tr>
   <td>hpp_proto CPU time</td>
   <td><div align="right">202.0&nbsp;ns</div></td>
   <td><div align="right">144.0&nbsp;ns</div></td>
   <td><div align="right">33.6&nbsp;ns</div></td>
   <td><div align="right">10.9&nbsp;ns</div></td>
   <td><div align="right">140.0&nbsp;ns</div></td>
   <td><div align="right">115.0&nbsp;ns</div></td>
 </tr>
 <tr>
   <td>hpp_proto speedup factor</td>
   <td><div align="right">1.25</div></td>
   <td><div align="right">1.78</div></td>
   <td><div align="right">3.48</div></td>
   <td><div align="right">10.18</div></td>
   <td><div align="right">1.57</div></td>
   <td><div align="right">1.95</div></td>
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
    <td><div align="right">2683720</div></td>
    <td><div align="right">3467520</div></td>
  </tr>
  <tr>
    <td> google_decode_encode_lite </td>
    <td><div align="right">1128296</div></td>
    <td><div align="right">1505200</div></td>
  </tr>
  <tr>
    <td> hpp_proto_decode_encoded </td>
    <td><div align="right">139608</div></td>
    <td><div align="right">100640</div></td>
  </tr>
</tbody>
</table>
 
The comparison highlights a significant reduction in code size when using hpp-proto compared to Google’s Protocol Buffers implementations. On macOS, hpp-proto offers a 19.22x reduction in size compared to google_decode_encode and a 8.08x reduction compared to google_decode_encode_lite. The reduction is even more pronounced on Linux, where hpp-proto reduces the code size by 34.45x compared to google_decode_encode and by 14.96x compared to google_decode_encode_lite.


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
protobuf_generate_hpp(TARGET addressbook_lib
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
protobuf_generate_hpp(TARGET addressbook_lib
# uncomment the next line for non-owning mode  
#                     PLUGIN_OPTIONS non_owning 
)

add_executable(tutorial_proto addressbook.cpp)
target_link_libraries(tutorial_proto PRIVATE addressbook_lib)
```
</p>
</details>

## The hpp-proto API

The mapping from proto messages to their C++ message types is straight forward, as shown in the following generated code. 
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

The hpp-proto library provides an efficient and convenient interface for encoding and decoding Protobuf messages in C++. The two core functions are:

-	`write_proto()`: Serializes a generated C++ message object into the binary Protobuf format.
-	`read_proto()`: Deserializes a binary Protobuf-encoded buffer back into the corresponding C++ message object.

These APIs offer flexible usage with overloads for returning either a status or an std::expected object (containing the result or an error). Below are demonstrations of their usage in both regular and non-owning modes.

<details> <summary>Regular mode APIs</summary>
<p>

```cpp
#include <addressbook.pb.hpp> // Include "*.pb.hpp" for Protobuf APIs

// ....
tutorial::Person in_msg, out_msg;
msg1.name = "john";

std::string out_buffer;
using namespace hpp::proto;
// Serialize using the status return API
if (!write_proto(in_msg, out_buffer).ok()) {
  // Handle error
}
assert(out_buffer == "\x0a\x04john");

// Serialize using the expected return API
expected<std::string, std::errc> write_result = write_proto<std::string>(in_msg);
assert(write_result.value() == "\x0a\x04john");

std::string_view in_buffer = "\x0a\x04john";
// Deserialize using the status return API
if (!read_proto(out_msg, in_buffer).ok()) {
  // Handle error
}
assert(out_msg.name == "john");

// Deserialize using the expected return API
expected<Person, std::errc> read_result = read_proto<Person>(in_msg);
assert(read_result.value().name == "john");

```
</p>
</details>
<details> <summary>Non-owning mode APIs</summary>
<p>

In non-owning mode, variable-length fields in messages are mapped to lightweight types such as `std::string_view` or `equality_comparable_span`. Instead of copying values, non-owning messages provide views to the original data, requiring careful lifetime management of referenced memory to avoid invalid access.

#### Key Differences in Non-Owning Mode

- `write_proto()`: No difference between regular and non-owning modes.
- `read_proto()`: Requires an option object containing a memory resource for managing allocations.

The memory resource must have an `allocate()` member function equivalent to [std::pmr::memory_resource::allocate](https://en.cppreference.com/w/cpp/memory/memory_resource/allocate), ensuring it returns at least the requested amount of memory and *never* indicates an error by returning `nullptr`. Errors should only be communicated through exceptions. 
Additionally, all allocated memory must be properly released when the memory resource is destroyed. 
For most use cases, [std::pmr::monotonic_buffer_resource](https://en.cppreference.com/w/cpp/memory/monotonic_buffer_resource) is recommended.


#### Providing Memory Resource to `read_proto()`

Two option objects allow you to specify memory resources for `read_proto()`:
-	`alloc_from`: Permits the deserialized value to reference memory within the input buffer.
-	`strictly_alloc_from`: Ensures that all memory used by the deserialized value is allocated from the provided memory resource.

Below is an example demonstrating the differences between these two options:

```cpp
#include <addressbook.pb.hpp> // Include "*.pb.hpp" for Protobuf APIs

// ....
std::string_view in_buffer = "\x0a\x04john";
std::array<char, 16> arena;
std::pmr::monotonic_buffer_resource pool{arena.data(), arena.size()};

tutorial::Person out_msg;
using namespace hpp::proto;
// Deserialization using alloc_from
if (!read_proto(out_msg, in_buffer, alloc_from{pool}).ok()) {
  // Handle error
}
assert(out_msg.name == "john");
// out_msg.name references in_buffer
assert(out_msg.name.data() == in_buffer.data() + 2);

// Deserialize using strictly_alloc_from
if(!read_proto(out_msg, in_buffer, strictly_alloc_from{pool}).ok()) {
  // Handle error
}
assert(out_msg.name == "john");
// out_msg.name now references arena
assert(out_msg.name.data() == arena.data());
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

</details>
<details><summary> Regular Mode </summary>
<p>

```cpp

#include "addressbook.glz.hpp" // Include the "*.glz.hpp" for JSON APIs

// ....
std::string out_json;
tutorial::Person in_msg;
in_msg.name = "john";
using namespace hpp::proto;
// Serialize using the status return API
if (!write_json(in_msg, out_json).ok()) {
    // Handle error
}

// Serialize using the expected return API
auto write_result = write_json(in_msg);
assert(write_result.value() == out_json);

// Pretty printing with 3 spaces indent
if (!write_json(in_msg, out_json, indent<3>{}).ok()) {
    // Handle error
}

tutorial::Person out_msg;
// Deserialize using the status return API
if (!read_json(out_msg, json).ok()) {
    // Handle error
}

// Deserialize using the expected return API
auto read_result = read_json<tutorial::Person>(json);
assert(read_result.value() == out_msg);
```
</p>
</details>
<details><summary> Non-owning Mode </summary>
<p>

```cpp

#include "addressbook.glz.hpp" // Include the "*.glz.hpp" for JSON APIs

// ....
std::pmr::monotonic_buffer_resource pool;

std::string in_json = R"({"name":"john"})";
tutorial::Person out_person;
if (!read_json(out_person, in_json, alloc_from{pool}).ok()) {
    // Handle error
}

// alternatively, use the overload returning an expected object
auto read_result = read_json<tutorial::Person>(in_json, alloc_from{pool});
assert(read_result.value() == out_person);
```
</p>
</details>