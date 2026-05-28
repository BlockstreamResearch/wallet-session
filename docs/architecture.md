# Architecture

Status: current decision record for the proof of concept.

This document records the architecture decisions that guide the current implementation. 
It is not a final production architecture. 
When a change revises one of these decisions, the change should update this document in the same commit.

## Goals

The repository builds a Rust WalletConnect client from small, live-tested primitives.

The current priority is protocol behavior over broad surface area:

- parse and validate protocol data close to the specification;
- build security-sensitive primitives correctly from the beginning;
- use real relay traffic whenever practical;
- keep wallet decisions explicit and reviewable;
- keep the runtime model obvious;
- add local edge-case tests for behavior that live tests cannot cover.

## Crate Boundaries

Current workspace crates:

- `wc-protocol`: DTOs, parsers, identifiers, crypto envelope primitives, relay RPC shapes, namespace validation, and protocol-level errors.
- `wc-transport`: native relay WebSocket I/O and high-level relay request/response routing.
- `wc-core`: wallet-facing runtime behavior over protocol and transport primitives.
- `xtask`: live probes and development harness commands.

Boundary rules:

- `wc-protocol` must not own networking or runtime session state.
- `wc-transport` must not decide wallet approval policy.
- `wc-core` owns wallet behavior: pairing/session orchestration, event emission, approval planning, and request response APIs.
- `xtask` may use production primitives, but production crates must not depend on `xtask`.
- Future UniFFI/Wasm layers should be wrappers only: type conversion, async adaptation, memory/lifetime adaptation, and packaging.

Rationale: WalletConnect behavior spans pairing, relay delivery, encryption, namespace validation, session approval, session requests, expiry, and user rejection. Splitting protocol, transport, and runtime behavior keeps each primitive reviewable and testable.

References:

- [Relay Server RPC](https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc)
- [Relay Client Auth](https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-auth)
- [Session Events](https://specs.walletconnect.com/2.0/specs/clients/sign/session-events)
- [Namespaces](https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces)

## Runtime Model

The core runtime is deliberately foreground-driven:

- one relay connection;
- one `Client` runtime;
- `Client::next_event()` as the polling API;
- in-memory pairings and sessions;
- no background task model yet;
- no concurrent `next_event()` contract.

Rationale: wallet UX is approval-driven, not throughput-driven. 
A single foreground event loop makes security-sensitive behavior easier to inspect. 
It also avoids callback reference cycles, hidden background approval paths, and unclear cancellation semantics.

Current event model:

- pairing proposals become `ClientEvent::SessionProposal`;
- non-proposal pairing messages remain visible as `ClientEvent::PairingMessage`;
- session-topic messages become `ClientEvent::Session`;
- invalid session requests are auto-rejected by the receive path when the rejection is deterministic and does not require user approval.
- permission-changing session updates are surfaced as events and require an explicit approve/reject API call.

Reference:

- [Session Request event](https://specs.walletconnect.com/2.0/specs/clients/sign/session-events#session_request)

## State Model

The current client stores runtime state in memory only:

- pairing subscriptions;
- active session subscriptions;
- acknowledged session records;
- queued events;
- symmetric keys associated with active pairings/sessions.

No symmetric keys, sessions, or pending approvals are persisted in this phase.

Rationale: persistence creates a security boundary. 
Until restore semantics, key storage, corruption handling, and migration behavior are designed, the safer default is to drop state on process exit. 
If the application closes or crashes, the next run starts fresh.

Messages for unknown or untracked runtime state should be dropped or rejected according to the narrow protocol context. 
The client should not infer a session from an incoming message when its in-memory state has been lost.

Deferred:

- secure key storage;
- restore of active sessions;
- storage migration;
- explicit stale-session cleanup after restore.

## Approval Policy

Auto-approval is not allowed.

The current session proposal approval flow is:

1. receive `wc_sessionPropose`;
2. expose it as `ClientEvent::SessionProposal`;
3. caller decides whether to approve or reject;
4. wallet capabilities are used to plan an approved namespace set;
5. core publishes approval only after the caller supplies approval data.

`WalletCapabilities` is the first approval-planning primitive in `wc-core`.

Policy:

- required namespaces are all-or-error;
- optional namespaces approve only the supported chain/method/event intersection;
- accounts must match the capability chain;
- planned namespaces are revalidated with `wc-protocol` namespace validation before approval.

Rationale: namespace approval is a wallet security decision. The core can help calculate a safe approval shape, but the caller still owns user consent.

Session updates follow the same rule.
`wc_sessionUpdate` replaces namespaces, and namespaces contain chains, accounts, methods, and events.
The runtime must not acknowledge or apply such updates inside `Client::next_event()`.
It must expose the update to the caller, then apply it only through an explicit approval primitive.

Current session update flow:

1. receive `wc_sessionUpdate`;
2. expose it as `ClientEvent::Session(SessionClientEvent::SessionUpdate)`;
3. caller compares current and requested namespaces and obtains any required user consent;
4. caller invokes `Client::approve_session_update` or `Client::reject_session_update`;
5. core mutates stored namespaces only after publishing an approval acknowledgement.

Rationale: a protocol acknowledgement is not the same thing as wallet authorization.
The lower-level pairing primitive may build either success or error responses, but the wallet-facing runtime must make the permission boundary obvious.

Reference:

- [Approving a Session Response](https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces#approving-a-session-response)
- [Updating a Session](https://docs.walletconnect.network/wallet-sdk/web/usage#updating-a-session)

## Security Posture

Security should be added alongside feature work when it naturally belongs to the feature. Pure hardening should not run far ahead of behavior, but obvious safety boundaries should be added early.

Current security defaults:

- no auto-approval;
- explicit user/caller approval path;
- explicit permission-change primitives before protocol acknowledgements;
- in-memory state only;
- one connection;
- bounded relay push handling;
- bounded queued relay messages;
- incoming WebSocket frame size limit;
- request timeouts;
- strict JSON-RPC response ID matching;
- subscribed-topic routing;
- cleanup after failed subscribe/unsubscribe;
- redacted key-like types and output where implemented;
- typed errors with sources where there is a lower-level source.

Rationale: the code should make unsafe behavior difficult to express accidentally. Type boundaries and conservative runtime limits are preferred over comments that rely on every caller remembering security-sensitive details.

## Transport Model

`wc-transport` owns the native relay pipe.

Current responsibilities:

- authenticate relay connection URL using protocol primitives;
- open native WebSocket connection;
- send typed relay JSON-RPC requests;
- parse relay JSON-RPC responses;
- route responses by request ID;
- acknowledge `irn_subscription` pushes;
- queue subscribed-topic messages within bounds;
- expose next message by topic.

Rationale: relay transport is a runtime primitive, but relay method DTOs and auth URL construction are protocol primitives. Keeping transport separate avoids mixing WebSocket details into protocol validation.

References:

- [Relay Server RPC methods](https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#methods)
- [Relay subscription](https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscription)

## Documentation Policy

Documentation should be close to the implementation it explains.

Rules:

- prefer specific references near the function/type implementing the behavior;
- include short quotes when they clarify the exact requirement;
- avoid generic top-level reference lists when they do not help the reader verify code;
- avoid Rust docs that only repeat the function or error name;
- explain internal helpers when the reason for the helper is not obvious;
- use doctests where the example is stable and valuable.

Rationale: documentation is a review tool. It should help connect code to protocol behavior, maintained implementations, or edge-case rationale.

## Testing Policy

The development loop is live test first where practical, then local implementation, then local edge-case tests.

Current test layers:

- live relay probes through `xtask`;
- JS harness with pinned dependencies;
- local unit/integration tests for edge cases;
- Rust doctests for stable examples;
- `just check_all` before a feature is considered complete.

Live tests are guidance, not a blocker. If a behavior cannot be live-tested, the limitation should be acknowledged and covered with deterministic local tests.

Rationale: live tests confirm deployed WalletConnect behavior. Local tests cover adversarial, malformed, and edge-case inputs that are difficult or unsafe to produce through a live relay.

## Deferred Decisions

These are intentionally not finalized:

- reconnect/backoff policy beyond current relay request timeouts;
- durable storage and restore;
- persisted symmetric key handling;
- queue capacity as public API;
- explicit drop policy reporting for flooded event queues;
- browser/Wasm transport;
- UniFFI and mobile bindings;
- richer wallet capability model beyond chains/accounts/methods/events;
- CACAO signing and authentication workflow behavior;
- complete production threat model artifact.

Each deferred item should be designed when a feature requires it, with live probes and local tests added in the same slice.
