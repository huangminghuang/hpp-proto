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

We measured the runtime performance with the [dataset](https://github.com/protocolbuffers/protobuf/tree/v3.6.0/benchmarks/datasets/google_message1) and the [benchmarks.proto](https://github.com/protocolbuffers/protobuf/blob/v3.6.0/benchmarks/benchmarks.proto) definition from google protobuf version 3.6.0. Three different cases are benchmarked: deserialization, set_message, and set_message plus serialization.  

|                                  Mac operation CPU time                                                |
|-----------|------------------------------|------------------------------|------------------------------|
|           |      deserialize             |          set_message         |   set_message and serialize  |
|-----------|-----------|------------------|-----------|------------------|-----------|------------------|
|           |  regular  | arena/non_owning |  regular  | arena/non_owning |  regular  | arena/non_owning |
|-----------|-----------|------------------|-----------|------------------|-----------|------------------|
| google    |  475.0 ns |         366.0 ns |  382.0 ns |         268.0 ns |  509.0 ns |         426.0 ns |
| hpp_proto |  283.0 ns |         170.0 ns |   81.0 ns |          8.38 ns |  285.0 ns |         182.0 ns |
|-----------|-----------|------------------|-----------|------------------|-----------|------------------|
| hpp_proto |           |                  |           |                  |           |                  |
|  speedup  |   159.00% |          211.06% |   511.04% |         3067.93% |   243.94% |          232.69% |


|                                  Linux operation CPU time                                              |
|-----------|------------------------------|------------------------------|------------------------------|
|           |      deserialize             |          set_message         |   set_message and serialize  |
|-----------|-----------|------------------|-----------|------------------|-----------|------------------|
|           |  regular  | arena/non_owning |  regular  | arena/non_owning |  regular  | arena/non_owning |
|-----------|-----------|------------------|-----------|------------------|-----------|------------------|
| google    |  443.0 ns |         255.0 ns |  120.0 ns |         114.0 ns |  247.0 ns |         242.0 ns |
| hpp_proto |  198.0 ns |         160.0 ns |   34.6 ns |          11.3 ns |  142.0 ns |         122.0 ns |
|-----------|-----------|------------------|-----------|------------------|-----------|------------------|
| hpp_proto |           |                  |           |                  |           |                  |
|  speedup  |   270.18% |          163.35% |   321.07% |         1018.33% |   167.14% |          195.24% |

[Benchmark code is available here](benchmarks/benchmark.cpp)
### Code Size
We compare the code sizes for the equivalent programs [hpp_proto_decode_encoded](benchmakrs/hpp_proto_decode_encoded.cpp), [google_decode_encode](benchmakrs/google_decode_encode.cpp) and [google_decode_encode_lite](benchmakrs/google_decode_encode_lite.cpp) for decoding and encoding the message defined in
[benchmark_message_proto3.proto](benchmakrs/benchmark_message_proto3.proto) using hpp-proto and google protobuf implementation version 28.2. The `google_decode_encode` and `google_decode_encode_lite` program are statically linked with `libprotobuf` and `libprotobuf-lite` respectively.

|                 Code size in bytes                |
|-----------------------------|-----------|---------|
|                             |   Mac     | Linux   |
|-----------------------------|-----------|---------|
| google_decode_encode        |  2624344  | 3410088 |
| google_decode_encode_lite   |  1106408  | 1474208 |
| hpp_proto_decode_encoded    |   114152  |   87144 | 
|-----------------------------|-----------|---------|
 
| Hpp-proto code size reduction ratio compared to  |
|---------------------------|-----------|----------|
|                           |    Mac    |  Linux   |
|---------------------------|-----------|----------|
| google_decode_encode      |  22.99:1  | 39.13:1  |
| google_decode_encode_lite |   9.68:1  | 16.91:1  |       

## Getting Started
This section provides a quick introduction to the basic usage of hpp-proto to help you get started with minimal setup. It covers the essential steps required to integrate hpp-proto into your project and begin working with Protocol Buffers. For more advanced usage scenarios, optimizations, and additional features, please refer to the detailed examples and guides in the tutorial directory of the repository.

### Install google protoc 
If you haven’t installed the `protoc` compiler, [download the package](https://protobuf.dev/downloads) and follow the instructions in the README.

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