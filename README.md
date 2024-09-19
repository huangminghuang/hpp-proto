# hpp-proto

hpp-proto is a C++20-based tool that simplifies the use of Protocol Buffers in C++. The tool achieves this by generating C++ aggregate types from .proto files and providing a header only library to encode/decode Protobuf data using these types. It's worth noting that the generated aggregate types heavily use the C++ Standard Library containers such as std::vector and std::string, in contrast to the Google implementation, which makes them easier to use and integrate with existing C++ code bases. 

## Features
* All Protocol Buffers message definitions are mapped to simple C++ aggregates based on standard C++ library.
* Except the usage of [is_utf8](https://github.com/simdutf/is_utf8) library, all generated code and the core library are header only. 
* Each generated C++ aggregate are associated with static C++ reflection data for protobuf encoding and decoding.
* Each generated C++ aggregate also contains meta data for JSON serialization using slightly modified [glaze](https://github.com/stephenberry/glaze) library.
* Only Protocol Buffers syntax 2 and 3 (except `service`) are supported, no edition support currently.
* Support non-owning mode code generation which maps string and repeated fields to std::string_view and std::span.
* Support compile time serialization.
* Far smaller code size (less than 3% of the google counterparts in our test cases).
* Faster execution time (20% to 55% faster than the google counterparts in our test cases).

## Comparison with google protobuf C++ implementation
### Runtime Performance 

We measured the runtime performance with the [dataset](https://github.com/protocolbuffers/protobuf/tree/v3.6.0/benchmarks/datasets/google_message1) and the [benchmarks.proto](https://github.com/protocolbuffers/protobuf/blob/v3.6.0/benchmarks/benchmarks.proto) definition from google protobuf version 3.6.0. Three different cases are benchmarked: deserialization, set_message, and set_message plus serialization.  


Below are results with Apple MacBook Pro, Model MK193LL/A, Chip Apple M1 Pro.
| Name                      | deserialize | set_message | set_message + serialize |
|---------------------------|-------------|-------------|-------------------------|
| google                    | 463 ns      |  383 ns     | 500 ns                  |
| google arena allocation   | 359 ns      |  258 ns     | 415 ns                  |
| hpp_proto owning          | 291 ns      | 78.6 ns     | 284 ns                  |
| hpp_proto non_owning      | 176 ms      | 8.39 ns     | 185 ns                  |


Below are the result with Ubuntu 22.04, Intel Core i9-11950H @ 2.60GHz
| Name                      | deserialize | set_message | set_message + serialize |
|---------------------------|-------------|-------------|-------------------------|
| google                    | 244 ns      |  116 ns     | 221 ns                  |
| google arena allocation   | 251 ns      |  113 ns     | 226 ns                  |
| hpp_proto owning          | 197 ns      | 31.7 ns     | 131 ns                  |
| hpp_proto non_owning      | 168 ms      | 10.9 ns     | 121 ns                  |

[Benchmark code is available here](benchmarks/benchmark.cpp)
### Code Size
We compare the code sizes for the equivalent programs (hpp_proto_decode_encoded, google_decode_encode and google_decode_encode_lite) for decoding and encoding the message defined in
[benchmark_message_proto3.proto](benchmakrs/benchmark_message_proto3.proto) using hpp-proto and google protobuf implementation version 28.0. The `google_decode_encode` and `google_decode_encode_lite` program are statically linked with `libprotobuf` and `libprotobuf-lite` respectively.

Below are the results for code size in bytes on
 - Mac:  Apple M1 Mac with Apple clang version 15.0.0
 - Ubuntu 22.04: x86-64 with gcc 12.3.0

|  name                    |   Mac                   | Ubuntu 22.04    |
|--------------------------|-------------------------|-----------------|
| hpp_proto_decode_encoded |   114136                | 87152           | 
| google_decode_encode     |  2686232                | 3396696         |
| google_decode_encode_lite|  1139544                | 1474208         |

## Getting Started

### [optional] Install google protoc 
hpp-proto requires google protoc for code generation. It can either use the existing  protoc installation on your system or automatically compiling protoc from source. 

### [optional] Install hpp-proto

hpp-proto can be directly installed locally then use cmake `find_package` to solve the dependency,  or it can be used via cmake `FetchContent` mechanism.

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
    protoc -I=$SRC_DIR --plugin=protoc-gen-hpp=$HOME/local/bin/protoc-gen-hpp --hpp_out=$DST_DIR $SRC_DIR/addressbook.proto
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

hpp-proto utilize (glaze)[https://github.com/stephenberry/glaze] for JSON encoding/decoding.
However, to support the [canonical JSON encoding](https://protobuf.dev/programming-guides/proto3/#json) of protobuf messages; hpp-proto generates `*.glz.hpp` files to contain the template specializations necessary to meet the specification. The APIs for JSON encoding/decoding is similar to those of protobuf encoding/decoding.

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