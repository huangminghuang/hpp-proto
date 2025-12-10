# Dynamic Message API

The dynamic message layer lets you parse, inspect, and construct protobuf messages at runtime using only descriptors—no generated C++ types are required. It mirrors most of the generated API surface (field presence, reflection, JSON/proto serialization) while keeping allocations in a caller-provided `std::pmr::monotonic_buffer_resource`.

## Rationale
- Load schemas discovered at runtime (plugins, user uploads) without recompiling.
- Keep allocations fast and deterministic by using a monotonic buffer instead of `new`.
- Offer a uniform field access API that matches generated code semantics (presence, oneof, repeated, enums) while staying type-safe through `*_field_mref/cref` wrappers.
- Support JSON/proto I/O with the same validation rules used by generated messages.

## Core Types
- `dynamic_message_factory`: owns a descriptor pool built from a `google::protobuf::FileDescriptorSet` or a `distinct_file_descriptor_pb_array`. Produces `message_value_mref` instances bound to a caller-supplied memory resource.
- `message_value_mref` / `message_value_cref`: mutable/const views over a message instance. Provide `field_by_name/number`, `typed_ref_by_name/number`, and `field_value_by_name/number` helpers.
- **Untyped vs. typed refs (with examples):**
  - Untyped:
    ```cpp
    auto f = msg.field_by_name("count");
    if (f && f->set(42)) {
      // handle errors 
    }
    ```
  - Typed helper:
    ```cpp
    if (auto int_ref = msg.typed_ref_by_name<hpp::proto::int32_field_mref>("count")) {
      int_ref->set(42);
    } else {
      // handle errors
    }
    ```
- `*_field_mref` / `*_field_cref`: typed accessors for scalar, enum, string/bytes, and message fields (singular and repeated). Repeated mutators expose `reserve`, `resize`, `push_back`, `emplace_back`, `set`, `adopt`, and `clear`.
- JSON helpers: `hpp::proto::write_json` / `hpp::proto::read_json` operate on `message_value_mref/cref` given a `dynamic_message_factory`.
- Most lookup APIs return `std::expected<...>`; call `.has_value()` or `.value()` (or use `.and_then()`) and handle `dynamic_message_errc` on failure.

## Memory Model and Caveats
- **Single arena per message:** A `message_value_mref` stores all field data in the `std::pmr::monotonic_buffer_resource` you pass at creation. That resource must outlive every view (`mref`/`cref`) derived from the message.
- **No reclamation on clear:** `clear()` resets sizes/presence but does not return memory to the resource. Reuse messages with the same arena or recreate the arena to reclaim memory.
- **Repeated fields:** `reserve()` grows capacity and preserves size; `resize()` default-constructs new elements; `clear()` resets size only. All repeated `reserve()` APIs are `const` to mirror reference semantics.
- **Presence vs. defaults:** `field_descriptor_by_{name,json_name,number}` return `nullptr` when missing. Presence for proto2 optional/oneof follows descriptor rules; proto3 scalars treat “not set” as default values.
- **Thread safety:** Individual message instances are not thread-safe; add your own synchronization if multiple threads access the same message.
- **Reference invalidation:** Repeated field accessors behave like vectors—calls to `reserve`, `resize`, or mutating helpers can reallocate and invalidate previously taken `*_field_mref`/`*_value_mref` references to elements. Fetch fresh refs after growth before reading or writing. For example:
  ```cpp
  auto rep = msg.typed_ref_by_name<hpp::proto::repeated_message_field_mref>("repeated_nested").value();
  auto first = rep.emplace_back();  // ok to use now
  rep.reserve(10);                  // may reallocate; `first` is now invalid
  // BAD: first.field_by_name("x") ...   // undefined behavior
  auto first_again = rep[0];        // reacquire after growth
  ```

## Getting Descriptors
Export a descriptor set with protoc:
```bash
protoc --descriptor_set_out=unittest.desc.binpb --include_imports your.proto
```

Load it into the factory:
```cpp
#include <hpp_proto/dynamic_message.hpp>

std::pmr::monotonic_buffer_resource descriptor_mr;
google::protobuf::FileDescriptorSet<hpp::proto::non_owning_traits> fileset;
auto data = read_file("unittest.desc.binpb");              // user-defined helper
auto ok = hpp::proto::read_proto(fileset, data, hpp::proto::alloc_from{descriptor_mr}).ok();
assert(ok);

hpp::proto::dynamic_message_factory factory{std::move(fileset), descriptor_mr};
```

Alternatively, build from in-memory `file_descriptor_pb` slices:
```cpp
using hpp::proto::file_descriptor_pb;
const hpp::proto::distinct_file_descriptor_pb_array<2> descs{
    file_descriptor_pb{primary_data},
    file_descriptor_pb{dependency_data},
};
hpp::proto::dynamic_message_factory factory{descs, descriptor_mr};
```
(Each entry in `descs` must describe a different file.)

## Constructing and Mutating Messages
```cpp
std::pmr::monotonic_buffer_resource mr;
auto maybe_msg = factory.get_message("mypkg.Message", mr);
if (!maybe_msg) throw std::runtime_error("unknown message");
auto msg = *maybe_msg; // message_value_mref

// Scalars
if (auto int_field = msg.field_by_name("count")) {
  int_field->set(42);
}

// Enums
if (auto enum_field = msg.field_by_number(3)) {
  enum_field->set(hpp::proto::enum_name{"OPEN"});
}

// Nested message
if (auto nested_field = msg.typed_ref_by_name<hpp::proto::message_field_mref>("config")) {
  auto nested = nested_field->emplace();
  if (auto flag = nested.field_by_name("flag")) {
    flag->set(true);
  }
}

// Repeated
if (auto tags = msg.typed_ref_by_name<hpp::proto::repeated_string_field_mref>("tags")) {
  tags->reserve(4);
  tags->push_back("alpha");
  tags->push_back("beta");
}

// Handling errors from expected-returning APIs
auto maybe_field = msg.field_by_name("missing_field");
if (!maybe_field) {
  // maybe_field.error() is dynamic_message_errc::no_such_field
}
auto maybe_typed = msg.typed_ref_by_name<hpp::proto::repeated_int32_field_mref>("repeated_int32");
maybe_typed.and_then([](auto f) {
  f.push_back(123);
  return std::expected<void, hpp::proto::dynamic_message_errc>{};
});
```

## Serialization
```cpp
std::string binary;
auto status = hpp::proto::write_proto(msg.cref(), binary);
if (!status.ok()) throw std::runtime_error(status.message());

std::string json;
hpp::proto::write_json(msg.cref(), json, factory); // factory provides type info

// Parse
auto maybe_msg2 = factory.get_message("mypkg.Message", mr);
auto msg2 = *maybe_msg2;
hpp::proto::read_proto(msg2, binary);
hpp::proto::read_json(msg2, json, factory);
```

## JSON Tips
- Pass the factory to `read_json`/`write_json` so enum names and well-known types resolve correctly.
- Unknown enum names produce errors; numeric enums are preserved even if the name is unknown.
- Well-known types (Timestamp, Any, Duration, etc.) follow the same formatting as generated code.

## Troubleshooting
- **Missing descriptors:** `get_message` returns `std::nullopt` if the full name is not in the factory’s pool. Verify the descriptor set contains imports (`--include_imports`).
- **Lifetime errors:** Crashes or garbled data often mean the `monotonic_buffer_resource` was destroyed before message views. Keep the arena alive for the message’s entire use.
- **Growing repeated fields:** Use `reserve()` to avoid repeated reallocations in the arena; `clear()` does not free memory.
- **Oneof or presence confusion:** Check descriptors via `field_descriptor_by_*`; `nullptr` indicates an unknown field number/name.

## More Examples
- End-to-end mutation and JSON/proto I/O: `tests/dynamic_message_test.cpp`.
- Well-known types round-trips: `tests/well_known_types_tests.cpp`.
- Reserved/arena-aware usage of repeated fields: see the `repeated_*` cases in `tests/dynamic_message_test.cpp`.
