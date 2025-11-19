# Manually Running the gRPC Quality Tests

The `run_grpc_test.py` helper starts the in-tree server, discovers its port, and launches the desired gRPC test binary.  When you need to run the server and client separately (for instance when debugging one side), follow the steps below.

## 1. Build the targets you need

Configure the project once and build both the server and whichever test binary you plan to run:

```bash
cmake --preset dev
cmake --build --preset dev --target grpc_test_server grpc_unary_tests
```

Replace `dev` with the preset you normally use, and add additional `grpc_*` targets (for example `grpc_client_stream_tests`) as needed.  The resulting binaries live under `<preset build dir>/tests/grpc/`.

## 2. Start the server and capture its endpoint

`grpc_test_server` writes the endpoint it selected to the path passed as its first argument, which saves you from hard-coding a port. Start it in one terminal:

```bash
build/debug/tests/grpc/grpc_test_server /tmp/hpp_proto_grpc.port
```

Optional second argument: a listen address such as `0.0.0.0:50051` if you want a fixed port. Otherwise the server binds to `127.0.0.1:0` and picks a free port automatically.

Leave the server running; once it prints `grpc_test_server listening on ...` the file you provided contains the endpoint (e.g. `127.0.0.1:37543`).

## 3. Run a client test against that server

Each client binary checks the `HPP_PROTO_GRPC_TEST_ENDPOINT` environment variable. Export it using the contents of the port file and then run the test binary:

```bash
export HPP_PROTO_GRPC_TEST_ENDPOINT=$(cat /tmp/hpp_proto_grpc.port)
build/debug/tests/grpc/grpc_unary_tests
```

You can now iterate on the client while keeping the same server instance running. Run different test binaries (e.g. `grpc_server_stream_tests`, `grpc_bidi_stream_tests`, etc.) the same way—just keep the environment variable exported in the shell where you run them.

## 4. Stop the server

When you are done, return to the server terminal and use `Ctrl+C` to shut it down. Delete the port file if you do not need it anymore.
