# Code Generation Guide

Describes exactly what C++ code the hpp-proto plugin of the protocol buffer compiler generates for any given protocol definition. 

## Compiler Invocation

### Compiler Invocation from CMake

After the hpp-proto package has been added via `find_package` or `FetchContent`, the protocol buffer compiler can be invoked with 
`protobuf_generate` function in the following form:

```cmake
protobuf_generate(
    TARGET <TargetName> 
    LANGUAGE hpp
    [IMPORT_DIRS <dirs>]
    [PROTOC_OUT_DIR <output_dir>]
    [PROTOS <protobuf_files>]
    [PLUGIN_OPTIONS <plugin_options>])
```

    - IMPORT_DIRS: Common parent directories for the schema files.
    - PROTOC_OUT_DIR: Output directory of generated source files. Defaults to CMAKE_CURRENT_BINARY_DIR.
    - PROTOS: List of proto schema files. If omitted, then every source file ending in proto of TARGET will be used.
    - PLUGIN_OPTIONS: A comma separated string that is forwarded to protoc-gen-hpp plugin to customize code generation. The customization options includes:
        * `root_namespace=`: prepend a root namespace to the generated code on top of the package.
        * `top_directory=`: prepend a directory to all the importing dependencies.
        * `proto2_explicit_presence=`: for proto2 only, make all optional fields implicit presence except the scopes specified. This options can be specified multiple times. For example: `proto2_explicit_presence=.pkg1.msg1.field1,proto2_explicit_presence=.pkg1.msg2` specifies the `field1` of `pkg1.msg1` and all fields of `pkg1.msg2` should adopt explicit presence (i.e. use std::optional)
        * `non_owning`: generate non-owning messages. 

The compiler creates several header files for each .proto file input.
The names of the output files are computed by taking the name of the .proto file and making two changes:

The extension (.proto) is replaced with  `.msg.hpp`, `.pb.hpp`, `.glz.hpp` and `.desc.hpp` for each header files.
The proto path (specified with the --proto_path= or -I command-line flag) is replaced with the output path (specified with the --hpp_out flag).


Example:
```
add_library(non_owning_unittest_proto3_proto_lib INTERFACE)
target_include_directories(non_owning_unittest_proto3_proto_lib INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(
    TARGET non_owning_unittest_proto3_proto_lib
    LANGUAGE hpp
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/non_owning
    PROTOS ${CMAKE_CURRENT_SOURCE_DIR}/google/protobuf/unittest_proto3.proto
    PLUGIN_OPTIONS non_owning,root_namespace=non_owning,top_directory=non_owning)
```



### Compiler Invocation from command line


```
protoc --plugin=<protoc-gen-hpp path> --hpp_out=[<plugin_options>:]<output_dir> [--proto_path=<dir>] <protobuf_files...>
```


## Packages 

If a .proto file contains a package declaration, the entire contents of the file will be placed in a corresponding C++ namespace. For example, given the package declaration:
```
package foo.bar;
```
All declarations in the file will reside in the `foo::bar` namespace. 

In certain cases, you may want to use `hpp-proto` and the official google Protobuf in the same program. You can use the  `root_namespace` option when invoking protocol buffer compiler to customize the top level namespace of the generated files. 

For example, invoking the compiler as follows:
```
protoc --proto_path=src --plugin=protoc-gen-hpp=$HOME/local/bin/protoc-gen-hpp --hpp_out root_namespace=baz:build/gen src/foo.proto
```
All declarations in the file will reside in the `baz::foo::bar` namespace. 

## Messages

Given a simple message declaration:

```
message Foo {}

```
The protocol buffer compiler generates a struct called Foo. 

## Fields
In addition to the methods described in the previous section, the protocol buffer compiler generates a set of member variables  for each field defined within the message in the .proto file. 

### Implicit Presence Fields (proto3)

```
syntax = "proto3"; 
message Foo {
    int32  f1 = 1;
    string f2 = 2;
    bytes  f3 = 3;
}
```

The compiler will generate the following `struct`:
```
struct Foo {
    int32_t f1;
    std::string f2;
    std::vector<std::byte> f3;
};
```

### Explicit Presence  Fields (proto2) 
For either of these field definitions:
```
syntax = "proto2"; 
message Foo {
    optional int32  f1 = 1;
    optional string f2 = 2;
    optional bytes  f3 = 3;
}
```

The compiler will generate the following `struct`:

```
struct Foo {
    hpp::proto::optional<int32_t> f1;
    hpp::proto::optional<std::string> f2;
    hpp::proto::optional<std::vector<std::byte>> f3;
};
```

`hpp::proto::optional<T>` has all the members functions of `std::optional<T>` with the addition of `value_or_default()` which returns the default value when the contained value is not present. 

Furthermore, the specialization of `hpp::proto::optional<bool>` deletes the type conversion operator to bool to avoid the confusion between value not present versus value is false. 

In most case, it may not be necessary to differentiate the value not present and default value cases for all optional fields. The `proto2_explicit_presence` plugin option can be used to generate code that only apply `hpp::proto::optional` to a specific set of fields.


### Optional Embedded Message Fields (proto2 and proto3)

Given the message type:
```protobuf
message Bar {}
```
For any of these field definitions:

```
//proto2
optional Bar foo = 1;

//proto3
Bar foo = 1;
```
The compiler will generate `std::optional<Bar> foo;` member variable. 

### Repeated Fields
Given a repeated field of type `T` in a message, the compiler will generate  `std::vector<T>` for the corresponding field. 

### Oneof fields

```protobuf
message TestOneof {
  oneof foo {
    int32 foo_int = 1;
    string foo_string = 2;
    NestedMessage foo_message = 3;
    NestedMessage foo_lazy_message = 4 [lazy = true];
  }
  message NestedMessage {
    double required_double = 1;
  }
}
```

```C++
struct TestOneof {
  struct NestedMessage {
    double required_double = {};

    bool operator == (const NestedMessage&) const = default;
  };

  enum foo_oneof_case : int {
    foo_int = 1,
    foo_string = 2,
    foo_message = 3,
    foo_lazy_message = 4
  };

  std::variant<std::monostate, int32_t, std::string, NestedMessage, NestedMessage> foo;

  bool operator == (const TestOneof&) const = default;
};
```


### Map fields

```proto
message TestMap {
  map<int32, int32> map1 = 1;
}
```

```C++
struct TestMap {
  hpp::proto::flat_map<int32_t,int32_t> map1;

  bool operator == (const TestMap&) const = default;
};
```

### Any Type

```protobuf
message TestAny {
  int32 int32_value = 1;
  google.protobuf.Any any_value = 2;
  repeated google.protobuf.Any repeated_any_value = 3;
  string text = 4;
}
```

```C++
struct TestAny {
  int32_t int32_value = {};
  std::optional<::google::protobuf::Any> any_value;
  std::vector<::google::protobuf::Any> repeated_any_value;
  std::string text = {};

  bool operator == (const TestAny&) const = default;
};
```

```C++
    TestAny message;
    google::protobuf::FieldMask fm{.paths = {"/usr/share", "/usr/local/share"}};
    expect(hpp::proto::pack_any(message.any_value.emplace(), fm).ok());

    std::vector<char> buf;
    expect(hpp::proto::write_proto(message, buf).ok());

    TestAny message2;
    expect(hpp::proto::read_proto(message2, buf).ok());
    google::protobuf::FieldMask fm2;
    expect(hpp::proto::unpack_any(message2.any_value.value(), fm2).ok());
    expect(fm == fm2);
```

## Non-owning Mode

Non-owning Mode is similar to the arena allocation in google protobuf implementation that helps you optimize your memory usage and improve performance. Generating code in non-owning mode will make all  owning containers in the generated regular mode code like std::string or std::vector to use std::string_view and std::span instead. 

