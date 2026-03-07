# Front-End API Guide

This guide documents the primary user-facing serialization/deserialization APIs:

- `write_binpb` / `read_binpb`
- `write_json` / `read_json`

It also explains binary sink modes and allocator-related options.

## Quick Map

| API family | Input/Output style | Return type |
|---|---|---|
| `write_binpb(msg, buffer, ...)` | write protobuf binary into contiguous buffer | `hpp_proto::status` |
| `write_binpb(msg, sink, ...)` | write protobuf binary into chunked sink | `hpp_proto::status` |
| `write_binpb<Buffer>(msg, ...)` | allocate/return serialized buffer | `std::expected<Buffer, std::errc>` |
| `read_binpb(msg, buffer, ...)` | parse binary into existing message | `hpp_proto::status` |
| `read_binpb<T>(buffer, ...)` | parse binary and return message | `std::expected<T, std::errc>` |
| `write_json(value, buffer, ...)` | write JSON into caller buffer | `hpp_proto::json_status` |
| `write_json<Buffer>(value, ...)` | allocate/return JSON buffer | `std::expected<Buffer, hpp_proto::json_status>` |
| `read_json(value, input, ...)` | parse JSON into existing message | `hpp_proto::json_status` |
| `read_json<T>(input, ...)` | parse JSON and return message | `std::expected<T, hpp_proto::json_status>` |

## Binary APIs (`read_binpb` / `write_binpb`)

### Contiguous buffer write

```cpp
std::vector<std::byte> out;
auto st = hpp_proto::write_binpb(message, out);
```

Use this for standard in-memory serialization.

### Sink write (stream/chunk oriented)

```cpp
my_sink sink;
auto st = hpp_proto::write_binpb(message, sink, hpp_proto::adaptive_mode);
```

`sink` is an output adapter that receives serialized bytes in one or more writable chunks.  
The sink must satisfy the `out_sink` concept:

- `sink.set_message_size(std::size_t) -> void`
- `sink.next_chunk() -> std::span<std::byte>`
- `sink.chunk_size() -> std::size_t`
- `sink::slice_type` type alias

Write flow:

1. `write_binpb` computes encoded size and calls `sink.set_message_size(size)`.
2. Based on selected mode, it uses either a single chunk write or a chunk-by-chunk write.
3. In chunked path, serializer repeatedly calls `sink.next_chunk()` to get writable spans and fills them until done.

Practical guidance:

- `next_chunk()` should return writable storage that remains valid until the serializer moves to the next chunk.
- Returning an empty span means no writable capacity and will fail serialization.
- `chunk_size()` should reflect the typical/guaranteed chunk capacity, used by `adaptive_mode` to decide contiguous vs chunked path.

Supported mode options:

- `hpp_proto::contiguous_mode`: one-shot write into first chunk; fastest when sink chunk is large enough.
- `hpp_proto::chunked_mode`: always write in chunks.
- `hpp_proto::adaptive_mode` (default for sink): contiguous if message fits one sink chunk, otherwise chunked.

> Mode options only affect sink-based `write_binpb`. Contiguous-buffer writes are always contiguous.

Minimal sink skeleton:

```cpp
struct my_sink {
  using slice_type = std::span<std::byte>;

  void set_message_size(std::size_t n) { /* reserve/begin frame */ }

  std::size_t chunk_size() const { return 4096; }

  std::span<std::byte> next_chunk() {
    // Return next writable window in your output target.
    return {/* ptr */, /* len */};
  }
};
```

### Read from contiguous/chunked input

```cpp
MyMessage msg;
auto st1 = hpp_proto::read_binpb(msg, bytes);
auto st2 = hpp_proto::read_binpb(msg, chunked_segments);
```

`chunked_segments` is a random-access range of contiguous byte ranges.

### `padded_input` option

`hpp_proto::padded_input` enables a faster contiguous-input parse path by allowing internal loops to skip some boundary checks.

```cpp
std::string_view payload = /* valid protobuf payload only */;
auto st = hpp_proto::read_binpb(message, payload, hpp_proto::padded_input);
```

Required preconditions:

1. The passed range must contain only valid payload bytes (no extra logical bytes in-range).
2. The underlying memory must be readable for at least 16 bytes past the end of the range.
3. The first byte after payload must be `0` (sentinel).

If these preconditions are not guaranteed, do not use `padded_input`.

## JSON APIs (`read_json` / `write_json`)

### Write JSON

```cpp
std::string json;
auto st = hpp_proto::write_json(message, json);
```

### JSON Write Options

You can customize the JSON output by passing a `hpp_proto::json_write_opts` template argument:

```cpp
using opts = hpp_proto::json_write_opts;
auto st = hpp_proto::write_json<opts{.prettify = true}>(message, json);
```

Supported options in `json_write_opts`:

- `prettify` (default: `false`): Enables multi-line, indented JSON output.
- `always_print_fields_with_no_presence` (default: `false`): If `true`, non-presence fields (primitives, repeated, maps) are always included in the output even if they are set to their default values (e.g., `0`, `""`, `false`, `[]`). Presence-tracking fields (like sub-messages or explicit `optional` fields) are still omitted if not set.
- `preserve_proto_field_names` (default: `false`): If `true`, the original field names from the `.proto` file (typically `snake_case`) are used as the primary keys for JSON serialization. **Note: This option only applies to dynamic messages.** For generated messages, use the corresponding plugin option. Regardless of this setting, `read_json` always accepts both naming conventions.
- `escape_control_characters` (default: `true`): Escapes control characters in strings.

### Read JSON

```cpp
MyMessage msg;
auto st = hpp_proto::read_json(msg, json_input);
```

`read_json` supports:

- null-terminated inputs (`const char*`, `std::string`, char arrays)
- non-null-terminated contiguous ranges (`std::string_view`, spans)

## Allocator/Cache Options

### `alloc_from(resource)`

Controls message/object allocations (for example when parsing into non-owning/PMR-oriented messages).

### `cache_alloc_from(resource)`

Controls internal binpb temporary/cache allocations (size cache, chunked-input temp buffers).

### Cache resource resolution

For binpb temp/cache allocations:

1. `cache_alloc_from(...)` if supplied
2. internal default cache resource (1024-byte stack-backed monotonic buffer with default PMR upstream)

`alloc_from(...)` is intentionally separate and not used as fallback for cache/temp storage.

## Failure Semantics

### Existing-output overloads

For APIs that deserialize into an existing output object (`read_binpb(msg, ...)`, `read_json(msg, ...)`):

- on parse failure, prior `msg` contents are not guaranteed to be preserved
- behavior is parser/field-path dependent; treat output as modified-on-failure

### Exception note

`read_binpb`/`read_json` do not catch exceptions from standard containers (for example `std::bad_alloc`).
