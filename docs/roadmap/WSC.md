# Wallet Session Client

**Owner:** TBD

## Goal

Finish the client in [`crates/client`](../../crates/client/) as a production-ready
library for the [relay protocol](../spec.md), then make its high-level API
available to application protocols and language bindings.

## 1. Review Findings (WSC-1)

Address the outstanding findings from security scanning.

## 2. Generalized Core (WSC-2)

Expose high-level client functions as a library API so application protocols can
be built on top. Transport, pairing, encryption, replay protection and
reliability remain internal to the client; a protocol supplies its messages and
handlers.

This needs a design: the API shape, extension points and error model are not yet
defined.

## 3. WASM Support (WSC-3)

Verify that the client can be exposed as a `wasm-bindgen` module. Audit all
dependencies, confirm the crate compiles for `wasm32-unknown-unknown`, and
document any required platform abstractions.

## 4. Bindings Support (WSC-4)

Provide the same kind of verification for UniFFI bindings. The binding surface
should follow the generalized core and async API rather than exposing internals.

## 5. Async API (WSC-5)

Write a high-level specification for the client's async API: how callers send,
receive, await events and cancel operations, and where the async boundary fits
best for native, WASM and UniFFI consumers. This is a design-level specification,
not an implementation description.

## Acceptance Criteria

* All review findings are resolved or explicitly deferred.
* An application protocol can be implemented on the generalized API without
  copying transport, encryption, replay or reliability code.
* The client compiles for `wasm32-unknown-unknown` and can be loaded as a
  `wasm-bindgen` module.
* UniFFI bindings build and expose the same high-level API surface.
* The async API is documented at a level sufficient to implement a binding.
