# Hpp-proto
![linux](https://github.com/huangminghuang/hpp-proto/actions/workflows/linux.yml/badge.svg)![macos](https://github.com/huangminghuang/hpp-proto/actions/workflows/macos.yml/badge.svg)![windows](https://github.com/huangminghuang/hpp-proto/actions/workflows/windows.yml/badge.svg)
[![codecov](https://codecov.io/github/huangminghuang/hpp-proto/graph/badge.svg?token=C2DD0WLCRC)](https://codecov.io/github/huangminghuang/hpp-proto)

Hpp-proto is a lightweight, high-performance Protocol Buffers implementation for C++20. It maps Protocol Buffers messages directly to simple C++ aggregates, using only C++ built-in or standard library types. Apart from UTF-8 validation, the serialization code for these mapped aggregates is entirely header-only, ensuring minimal dependencies and efficient performance.

# Features

* Significantly smaller code size compared to Google's implementation.
* Faster performance than Google's implementation.
* Maps all Protocol Buffers message definitions to simple C++ aggregates using standard C++ library types.
* Aside from [UTF-8 validation](https://github.com/simdutf/is_utf8), all generated code and the core library are header-only.
* Each generated C++ aggregate is associated with static C++ reflection data for efficient Protocol Buffers encoding and decoding.
* Includes metadata for JSON serialization in each generated C++ aggregate, utilizing a slightly modified version of the [glaze](https://github.com/stephenberry/glaze) library.
* Completely exception-free.
* Supports non-owning mode code generation, mapping string and repeated fields to `std::string_view` and `std::span`.
* Enables compile-time serialization.

## Limitations

* Supports only Protocol Buffers syntax 2 and 3 (excluding `service`), with no edition support.
* Lacks runtime reflection support.
* Unknown fields are discarded during deserialization.

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
    <th colspan="7"> Operations CPU time</th>
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

This drastic reduction is a result of hpp-proto’s minimalistic design, which avoids the overhead associated with Google’s full libprotobuf and libprotobuf-lite libraries. The smaller code size makes hpp-proto an attractive option for performance-critical and resource-constrained environments where minimizing binary size is essential.

## Getting Started
This section provides a quick introduction to the basic usage of hpp-proto to help you get started with minimal setup. It covers the essential steps required to integrate hpp-proto into your project and begin working with Protocol Buffers. For more advanced usage scenarios, optimizations, and additional features, please refer to the detailed examples and guides in the tutorial directory of the repository.

### Install google protoc 
If you haven’t installed the `protoc` compiler, [download the package](https://protobuf.dev/downloads) and follow the instructions in the README.

### [optional] Install hpp-proto

Hpp-proto can be directly installed locally then use cmake `find_package` to solve the dependency,  or it can be used via cmake `FetchContent` mechanism.

```bash
git clone https://github.com/huangminghuang/hpp-proto.git 
cd hpp-proto
# use installed protoc by default or specify '-DHPP_PROTO_PROTOC=compile' to compile protoc 
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$HOME/local -Bbuild -S .
cmake --build build --target install
```

### Defining Your Protocol Format 
```protobuf
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
##### find_package 
```cmake
cmake_minimum_required(VERSION 3.24)

project(hpp_proto_tutorial 
        VERSION 1.0.0
        LANGUAGES CXX)

find_package(hpp_proto CONFIG REQUIRED)

add_library(addressbook_lib INTERFACE addressbook.proto)
target_include_directories(addressbook_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(TARGET addressbook_lib
                  LANGUAGE hpp)

add_executable(tutorial_proto addressbook.cpp)
target_link_libraries(tutorial_proto PRIVATE addressbook_lib)
```

#### FetchContent
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
                  LANGUAGE hpp)

add_executable(tutorial_proto addressbook.cpp)
target_link_libraries(tutorial_proto PRIVATE addressbook_lib)
```

## The hpp-proto API

The mapping from proto messages to their C++ counterparts is straight forward, as shown in the following generated code. 
Notice that the `*.msg.hpp` only contains the minimum message definitions and avoid the inclusion of headers related to the protobuf/JSON 
encoding/decoding facilities. This makes those generated structures easier to be used as basic vocabulary types among modules without incurring unnecessary dependencies. 
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

// addressbook.pb.hpp
#include "addressbook.msg.hpp"
namespace tutorial {
    auto pb_meta(const Person &) -> std::tuple<...> ;
    auto pb_meta(const Person::PhoneNumber &) -> std::tuple<...> ;
    auto pb_meta(const AddressBook &) -> std::tuple<...>;
}
```

### Protobuf encoding/decoding APIs

```cpp
#include "addressbook.pb.hpp"

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

  if (!hpp::proto::write_proto(address_book, buffer).ok()) {
    std::cerr << "protobuf serialization failed\n";
    return 1;
  }

  tutorial::AddressBook new_address_book;

  if (!hpp::proto::read_proto(new_address_book, buffer).ok()) {
    std::cerr << "protobuf deserialization failed\n";
    return 1;
  }

  return 0;
}
```

### JSON encoding/decoding APIs

hpp-proto utilizes (glaze)[https://github.com/stephenberry/glaze] for JSON encoding/decoding.
To support the [canonical JSON encoding](https://protobuf.dev/programming-guides/proto3/#json) of protobuf messages; hpp-proto generates `*.glz.hpp` files to contain the template specializations necessary to meet the specification. The APIs for JSON encoding/decoding is similar to those of protobuf encoding/decoding.

```cpp

#include "addressbook.glz.hpp"

// ....
std::string json;

if (!hpp::proto::write_json(address_book, json).ok()) {
    std::cerr << "write json error\n";
    return 1;
}

tutorial::AddressBook new_book;
if (auto e = hpp::proto::read_json(new_book, json); !e.ok()) {
    std::cerr << "read json error: " << e.message(json) << "\n";
    return 1;
}
```