# Dynamic Messages (Tutorial)

## Why dynamic messages?
- Load and work with schemas discovered at runtime (plugins, user uploads) without regenerating C++ code.
- Keep allocations predictable by using a caller-owned `std::pmr::monotonic_buffer_resource` instead of the heap.
- Mirror generated protobuf semantics (presence, defaults, oneof, enums, well-known types) in a type-safe API based on descriptors.
- Serialize/deserialize via proto or JSON with the same validation rules used by generated code.

Build and mutate protobuf messages at runtime using descriptors and a monotonic arena. This guide walks from factory creation to typed field access, mirroring the style in `tutorial/dynamic_message/tutorial_proto3_dynamic.cpp`.

## 1) Build a factory
Load a `FileDescriptorSet` (or `distinct_file_descriptor_pb_array`) and initialize the factory. The factory owns descriptors; individual messages borrow a caller-owned `std::pmr::monotonic_buffer_resource`. The dynamic tutorial builds the factory from the compiled descriptor header:

```cpp
#include <hpp_proto/dynamic_message.hpp>

// Read the serialized FileDescriptorSet generated from
  //   `protoc --include_imports --descriptor_set_out=addressbook_proto3.desc.binpb addressbook_proto3.proto`
std::string filedescriptorset_binpb = read_file("addressbook_proto3.desc.binpb");

hpp::proto::dynamic_message_factory factory;
if (!factory.init(filedescriptorset_binpb)) {
  // handle init failure (bad descriptors)
}
```

## 2) Create a message
Each message lives in its own arena.
```cpp
std::pmr::monotonic_buffer_resource mr;
auto em = factory.get_message("protobuf_unittest.TestAllTypes", mr);
if (!em) {
  // handle unknown message name
}
hpp::proto::message_value_mref msg = *em;
```

## 3) Untyped field access (set/get by name/number)
`set_field_by_name/number` and `field_value_by_name/number` are convenience helpers. They return `std::expected`; check before using.

```cpp
// No-exception style
auto r = msg.set_field_by_name("optional_int32", 123);
if (!r) { /* handle dynamic_message_errc */ }

auto val_expected = msg.field_value_by_number<std::int32_t>(1);
assert(val_expected.has_value());
assert(*val_expected == 123);

// Exception style: throws only if you call .value() on a failed expected
msg.set_field_by_name("optional_int32", 123).value();
int v = msg.field_value_by_name<std::int32_t>("optional_int32").value();
```

Special notes:
- Proto2/oneof: `has_value()` drives presence; scalars still return defaults when unset.
- Message fields must be materialized (see below) before dereferencing; otherwise behavior is undefined.

## 4) Typed field refs (preferred)
Typed refs follow protobuf type names: `int32_field_mref`, `sint32_field_mref`, `fixed32_field_mref`, `string_field_mref`, `bytes_field_mref`, `enum_field_mref`, `message_field_mref`, and their `repeated_*` counterparts. Use `typed_ref_by_name/number` to get them safely:

```cpp
using namespace std::string_view_literals;
using namespace hpp::proto::literals; // for "_bytes"

if (auto int_ref_expected = msg.typed_ref_by_name<hpp::proto::int32_field_mref>("optional_int32")) {
  int_ref_expected->set(321); // exact type match
}

if (auto str_ref_expected = msg.typed_ref_by_name<hpp::proto::string_field_mref>("optional_string")) {
  str_ref_expected->set("hello"sv);
}

if (auto bytes_ref_expected = msg.typed_ref_by_number<hpp::proto::bytes_field_mref>(12)) {
  bytes_ref_expected->set("ab"_bytes);
}

if (auto enum_ref_expected = msg.typed_ref_by_name<hpp::proto::enum_field_mref>("optional_nested_enum")) {
  auto result = enum_ref_expected->set(hpp::proto::enum_number{1});
  if (!result) { /* handle invalid enum value */ }
  // alternatively:
  (void)enum_ref_expected->set(hpp::proto::enum_name{"FOO"sv});
}
```

### Message fields
Check presence, then `emplace()` to allocate and get a child message ref. Always re-fetch after `reserve/resize` on repeated messages.
```cpp
auto nested_expected = msg.typed_ref_by_name<hpp::proto::message_field_mref>("optional_nested_message");
if (nested_expected) {
  auto child = nested_expected->emplace();  // allocates in msg arena
  (void)child.set_field_by_name("bb", 7); // second parameter must match the declared type exactly
}
```
Reading a message field without `has_value()` is undefined; for scalar/string/bytes/enum fields a default is returned when unset.

### Repeated fields
Mutate with `reserve`, `resize`, `push_back`, `emplace_back`, `set`, or `adopt`.
```cpp
if (auto rep_int_expected = msg.typed_ref_by_name<hpp::proto::repeated_int32_field_mref>("repeated_int32")){
  auto rep_int = *rep_int_expected; 
  rep_int.reserve(2);
  rep_int.push_back(10);
  rep_int.push_back(20);
  // alternatively, you can set from an sized range
  std::array<std::int32_t, 2> my_int32_array{30, 40};
  (void)rep_int.set(my_int32_array);
}

if (auto rep_msg_expected = msg.typed_ref_by_name<hpp::proto::repeated_message_field_mref>("repeated_nested_message")){
  auto rep_msg = *rep_msg_expected;
  auto elem = rep_msg.emplace_back();
  (void)elem.set_field_by_name("bb", 42);
}
```
After growth, previously held element refs may be invalid; reacquire via `operator[]`.

## 5) Typed access via `typed_ref_by_name/number` (value vs. expected)
- `typed_ref_by_name/number` on `message_value_mref` returns `expected<typed_ref, dynamic_message_errc>`.
- `typed_ref_by_name/number` on `message_value_cref` returns the const version.
Use `.has_value()`/`.value()` or chain with `.and_then()` to stay exception-free.

```cpp
auto set_result = msg.typed_ref_by_name<hpp::proto::string_field_mref>("optional_string")
    .and_then([](auto ref) {
      ref.set("world");
      return std::expected<void, hpp::proto::dynamic_message_errc>{};
    });
if (!set_result) {
  // handle error
}
// equivalent one-liner:
(void)msg.set_field_by_name("optional_string", "world"sv);
```

## 6) Const views with `cref()`
Every mutable ref has a const sibling: call `cref()` on a message or a field ref to get read-only access.

```cpp
auto msg_cref = msg.cref();
if (auto s = msg_cref.typed_ref_by_name<hpp::proto::string_field_cref>("optional_string")){
  std::string_view sv = s->value();
}
```

## 7) Exceptions vs. `expected`
- **No-exception:** Use `.has_value()`, `.and_then()`, and helpers like `expected_message_mref` (see `tutorial/dynamic_message/tutorial_proto3_dynamic.cpp`).
- **Exception style:** call `.value()` on the expected return type.

## 8) Full example (dynamic tutorial)
`hpp::proto::expected_message_mref` is a fluent wrapper around `message_value_mref` that carries `std::expected` and lets you chain mutations; chaining stops on the first error and `done()` yields `expected<void, dynamic_message_errc>`. The dynamic tutorial combines these pieces to build an address book:
```cpp
std::pmr::monotonic_buffer_resource mr;
auto address_book = factory.get_message("tutorial.AddressBook", mr);

// add a person (chain everything through expected_message_mref)
address_book.mutate_field_by_name("people", [&](hpp::proto::repeated_message_field_mref people) {
  return hpp::proto::expected_message_mref{people.emplace_back()}
      .set_field_by_name("name", "Alex")
      .set_field_by_name("id", 1)
      .mutate_field_by_name("phones", [](hpp::proto::repeated_message_field_mref phones) {
        return hpp::proto::expected_message_mref{phones.emplace_back()}
            .set_field_by_name("number", "19890604")
            .set_field_by_name("type", hpp::proto::enum_name{"PHONE_TYPE_MOBILE"})
            .done();
      })
      .done();
});
```
More working snippets live in `tests/dynamic_message_test.cpp` (e.g., “nested message set/get” and “repeated push_back appends elements”).

## 9) Safety reminders
- Keep the arena (`std::pmr::monotonic_buffer_resource`) alive as long as any message/field refs are used.
- Repeated-field growth can invalidate element refs; reacquire after `reserve`/`resize`.
- Always check `has_value()` before reading a message field; scalars/strings/bytes/enums return defaults when unset.
