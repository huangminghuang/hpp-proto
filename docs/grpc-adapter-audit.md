# gRPC Adapter Audit

## Summary

- **Scope**: review `include/hpp_proto/grpc/client.hpp`, `include/hpp_proto/grpc/server.hpp`, supporting serialization helpers, and tutorial usage.
- **Goal**: surface ergonomics, generality, and documentation gaps before expanding tests/docs.
- **Findings**: see table below (sorted by severity).

## Findings & Recommendations

| Severity | Component | Finding | Recommendation |
|----------|-----------|---------|----------------|
| high | client stub construction (`include/hpp_proto/grpc/client.hpp`) | `Stub` hardcodes `std::apply` initialization without exposing hook for retry policies or channel updates; users must recreate the stub for each policy change. | Add lightweight wrapper or setter to reinitialize `grpc_methods_` when options change; document lifecycle expectations. |
| high | streaming reactors (`client.hpp` / `server.hpp`) | Serialization/deserialization happens exactly when `RequestToken::get`, `ServerRPC::write`, or `ServerRPC::finish` run, so reactors never retain references to request/response objects. This is safe for owning and non-owning traits but currently undocumented. | Document this eager-copy behavior so users understand there is no dangling-reference risk regardless of trait choice. |
| medium | callback reactors logging | No logging hooks for `OnReadDone`/`OnWriteDone` failures; debugging cancellations requires manual overrides. | Provide optional observer/callback interface or macro to inject logging without subclassing every reactor. |
| medium | tutorial coverage (`tutorial/grpc/greeter_*.cpp`) | Tutorials only demonstrate unary + server streaming; client/bidi streaming APIs remain undocumented. | Add streaming examples or link to new tests; highlight default reactor scaffolding in README. |
| medium | error propagation in `ServerRPC::finish` | `finish` already accepts a custom `::grpc::Status`, and the shared serialization helpers (`read_proto` / `write_proto` in `serialization.hpp`) return detailed statuses using `::grpc::StatusCode::INTERNAL`. This guarantees the reactor can propagate exact errors, but the behavior is undocumented. | Document the existing status propagation so users know they can pass their own `Status` and inspect serialization failures. |
| low | naming consistency | Mix of camelCase (e.g., `GrpcMethod`) and snake_case in templates; minor readability friction. | Align with project naming conventions during future refactor. |

## Adapter Coverage Notes

- Reviewed all method categories: unary, client streaming, server streaming, bidi streaming.
- Confirmed `ClientCallbackReactor` and `ServerRPC` specializations cover grpc callback APIs (beta) but rely on internal headers.
- Identified reliance on `::grpc::internal` types; upstream version bumps may break API — document this risk.

## Tutorial & Example Gap Analysis

| Area | Current State | Gap | Action |
|------|---------------|-----|--------|
| Unary RPC | `greeter_client/server` demonstrate basic usage. | No mention of traits/allocator options. | Extend docs to show `hpp::proto::alloc_from` usage and default traits. |
| Server streaming | Sample uses manual reactor; good coverage. | Lack of comments tying to adapter APIs; newbies copy-paste `sleep(1)`. | Update tutorial comments + README to point to official guidance. |
| Client streaming | Missing example. | Users must infer pattern from `ClientCallbackReactor`. | Provide dedicated sample/tests. |
| Bidi streaming | Missing example. | Hard to reason about concurrency/back-pressure expectations. | Provide dedicated sample/tests.

## Remediation Backlog

1. **Document allocator expectations** for client/server reactors (tie into traits doc).
2. **Add streaming tutorials/tests** referencing the new `tests/grpc/*` suites.
3. **Design extension hook** for stub/channel policy updates.
4. **Improve logging/observability** via optional callbacks.
5. **Track grpc internal dependency** risk (pin versions or gate builds).

## References

- Headers: `include/hpp_proto/grpc/client.hpp`, `include/hpp_proto/grpc/server.hpp`.
- Tutorials: `tutorial/grpc/greeter_client.cpp`, `tutorial/grpc/greeter_server.cpp`.
- Research basis: `/specs/002-grpc-quality/research.md`.
