# hpp_proto gRPC Adapters

The `hpp_proto::grpc` helpers wrap generated `*.service.hpp` descriptors so you can issue unary or streaming RPCs without manual glue. This guide summarizes how to build stubs, implement callback services, and avoid the common pitfalls we encountered while building the regression suites under `tests/grpc`.

## Requirements
- gRPC C++ 1.51+
- hpp_proto-generated service descriptors (e.g., `helloworld.service.hpp`)
- A `std::shared_ptr<grpc::Channel>` (clients) or `grpc::ServerBuilder` (servers)

## Client Overview
```cpp
#include <hpp_proto/grpc/client.hpp>
#include "helloworld.service.hpp"

using GreeterStub = ::hpp::proto::grpc::Stub<helloworld::Greeter::_methods>;

auto channel = grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials());
GreeterStub stub{channel, grpc::StubOptions{}};

helloworld::HelloRequest<hpp::proto::non_owning_traits> request;
request.name = "hpp-proto";
helloworld::HelloReply<hpp_proto::non_owning_traits> reply;
std::pmr::monotonic_buffer_resource mr;
::grpc::ClientContext ctx;
auto status = stub.call<helloworld::Greeter::SayHello>(ctx, request, reply, hpp::proto::alloc_from{mr});
```

### Streaming Best Practices
The gRPC callback reactors enforce sequencing rules:
- **Client streaming**: Only one `write()` or `write_last()` can be in flight. Wait for `OnWriteDone()` before issuing the next write. If you call `write_last()`, do **not** call `write_done()` afterward—`write_last` already marks completion. (See `tests/grpc/client_stream_tests.cpp`.)
- **Bidirectional streaming**: `ClientBidiReactor` lacks `TryCancel()`. Store the `grpc::ClientContext` you passed to `async_call` and call `context->TryCancel()` when needed. (See `tests/grpc/bidi_stream_tests.cpp`.)
- **Server streaming**: `ServerRPC::write` serialize immediately, so you can reuse buffers between writes.

### Cookbook (see `tests/grpc`)
| Scenario | Reactor | Example |
|----------|---------|---------|
| Unary RPC | none | `tests/grpc/unary_tests.cpp` |
| Client streaming | `ClientCallbackReactor<ClientStreamAggregate>` | `tests/grpc/client_stream_tests.cpp` |
| Server streaming | `ClientCallbackReactor<ServerStreamFanout>` | `tests/grpc/server_stream_tests.cpp` |
| Bidirectional streaming | `ClientCallbackReactor<BidiStreamChat>` + context-managed cancel | `tests/grpc/bidi_stream_tests.cpp` |

### `ClientCallbackReactor` cheat sheet

| Method type | Inherits from | Extras | User overrides |
|-------------|---------------|--------|----------------|
| Unary | `::grpc::ClientUnaryReactor` | `start_call()` convenience helper, `get_response()` decoding helpers | `OnReadInitialMetadataDone`, `OnDone`, `OnCancel` |
| Client streaming | `::grpc::ClientWriteReactor<::grpc::ByteBuffer>` | `write()`, `write_last()`, `write_done()`, `add_hold()/remove_hold()` | `OnReadInitialMetadataDone`, `OnWriteDone`, `OnDone`, `OnCancel` |
| Server streaming | `::grpc::ClientReadReactor<::grpc::ByteBuffer>` | `start_call()`, `start_read()`, `get_response()` | `OnReadInitialMetadataDone`, `OnReadDone`, `OnDone`, `OnCancel` |
| Bidirectional streaming | `::grpc::ClientBidiReactor<::grpc::ByteBuffer, ::grpc::ByteBuffer>` | `start_call()`, `start_read()`, `write()/write_last()/write_done()`, hold helpers (`add_hold`, `remove_hold`) | `OnReadInitialMetadataDone`, `OnReadDone`, `OnWriteDone`, `OnDone`, `OnCancel` |

## Server Overview
`CallbackService<Service, Methods>` wires generated method descriptors into `grpc::ServerBuilder`. Implement `handle(MethodTag)` to return a handler that manages the reactor callbacks.
```cpp
class GreeterService : public ::hpp::proto::grpc::CallbackService<GreeterService, helloworld::Greeter::_methods> {
public:
  struct SayHelloHandler {
    SayHelloHandler(GreeterService &, ::hpp::proto::grpc::ServerRPC<helloworld::Greeter::SayHello> &rpc,
                    ::hpp::proto::grpc::RequestToken<helloworld::Greeter::SayHello> token) {
      helloworld::HelloRequest request;
      auto status = token.get(request);
      if (!status.ok()) {
        rpc.finish(status);
        return;
      }
      helloworld::HelloReply reply{.message = "Hello " + std::string{request.name}};
      rpc.finish(reply);
    }
  };
  auto handle(helloworld::Greeter::SayHello) -> SayHelloHandler;
};
```
Hooks like `on_write_ok`, `on_write_error`, `on_read_ok`, and `on_cancel` are optional to implement but provide insight into streaming progress (see `tutorial/grpc/greeter_server.cpp` and `tests/grpc/test_harness.hpp`).

### `ServerRPC` cheat sheet

| Method type | Inherits from | Extras | Handler hooks |
|-------------|---------------|--------|----------------|
| Unary | `::grpc::ServerUnaryReactor` | `RequestToken::get()`, `finish(response)` overloads that serialize for you | `on_send_initial_metadata_done`, `on_done`, `on_cancel` |
| Client streaming | `::grpc::ServerReadReactor<::grpc::ByteBuffer>` | `start_read()`, `RequestToken::get()`, `finish(response)` | `on_send_initial_metadata_done`, `on_read_ok`, `on_read_error`, `on_done`, `on_cancel` |
| Server streaming | `::grpc::ServerWriteReactor<::grpc::ByteBuffer>` | `write(response)`, `finish(response)` and `finish(status)` helpers | `on_send_initial_metadata_done`, `on_write_ok`, `on_write_error`, `on_done`, `on_cancel` |
| Bidirectional streaming | `::grpc::ServerBidiReactor<::grpc::ByteBuffer, ::grpc::ByteBuffer>` | `start_read()`, `write(response)`, `finish(status)` | `on_send_initial_metadata_done`, `on_read_ok`, `on_write_ok`, `on_write_error`, `on_done`, `on_cancel` |

## Tutorial References
- `tutorial/grpc/greeter_client.cpp`: synchronous unary + streaming clients using non-owning traits (links back to this doc).
- `tutorial/grpc/greeter_server.cpp`: callback handlers with references to streaming hooks.
