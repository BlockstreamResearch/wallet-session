# Architecture

Status: current decision record for the proof of concept.

This document records the architecture decisions that guide the current implementation. 
It is not a final production architecture. 
When a change revises one of these decisions, the change should update this document in the same commit.

The current wallet-facing API behavior is specified in [`api-contract.md`](./api-contract.md).
The current WalletConnect SDK parity target is tracked in [`sdk-parity.md`](./sdk-parity.md).

## Goals

The repository builds a Rust WalletConnect client from small, live-tested primitives.

The current priority is protocol behavior over broad surface area:

- parse and validate protocol data close to the specification;
- build security-sensitive primitives correctly from the beginning;
- use real relay traffic whenever practical;
- keep wallet decisions explicit and reviewable;
- keep the runtime model obvious;
- add local edge-case tests for behavior that live tests cannot cover.

## Near-Term Target Sequence

The next target is the remaining Sign authentication and trust behavior, in this order:

1. CACAO message formatting and validation helpers;
2. proposal authentication subrequest handling;
3. Verify/origin trust context surfaced in review data;
4. richer wallet policy primitives for authentication and wallet methods;
5. broader interop scenarios against maintained JS Sign Client flows and selected live demos.

Rationale: authentication and origin trust are closer to the current single-session runtime than mobile/Wasm bindings or persistence. They should be built as explicit wallet decisions first, then hardened with interop and fuzz coverage.

Detailed status and exclusions are tracked in [`sdk-parity.md`](./sdk-parity.md).

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
- `wc-core` top-level exports should describe the single-session wallet API. Lower-level protocol-step primitives belong under `wc_core::low_level` so harness code can use them without making them look like the recommended app surface.
- `xtask` may use production primitives, but production crates must not depend on `xtask`.
- Future UniFFI/Wasm layers should be wrappers only: type conversion, async adaptation, memory/lifetime adaptation, and packaging.

Rationale: WalletConnect behavior spans pairing, relay delivery, encryption, namespace validation, session approval, session requests, expiry, and user rejection. Splitting protocol, transport, and runtime behavior keeps each primitive reviewable and testable.

References:

- [Relay Server RPC](https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc)
- [Relay Client Auth](https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-auth)
- [Session Events](https://specs.walletconnect.com/2.0/specs/clients/sign/session-events)
- [Namespaces](https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces)

## Runtime Model

The core runtime is foreground-driven:

- one relay connection;
- one `SingleSessionClient` runtime;
- one active protocol topic at a time;
- one active session at a time;
- `SingleSessionClient::next_event()` as the polling API;
- in-memory pairing/session state;
- no background task model yet;
- no concurrent `next_event()` contract.

Rationale: wallet UX is approval-driven, not throughput-driven. 
A single foreground event loop makes security-sensitive behavior easier to inspect. 
It also avoids callback reference cycles, hidden background approval paths, and unclear cancellation semantics.
The first production target is a single-session client because replacement is a clearer trust boundary than hidden multi-session routing.

The relay protocol can support many subscribed topics over one WebSocket.
`SingleSessionClient` chooses a narrower runtime:

1. `Idle`;
2. `Pairing`;
3. `Session`.

Subscribing a new pairing topic while a session is active must be an explicit replacement flow.
The caller should tell the user that connecting the new app disconnects the current app, then call a replacement/disconnect operation.
`SingleSessionClient` must not silently replace an active session or keep multiple approved dapp sessions alive.
Consumers must not create multiple `SingleSessionClient` instances to regain multi-session behavior.
One wallet runtime should reuse one client instance; multiple simultaneous instances are a separate multi-session design and require their own state ownership, UX, and threat model.
Reconnect follows the same boundary: the runtime may reopen the relay socket, but it only resubscribes the single active pairing or session topic.

Rationale: a single active session removes scheduler fairness, cross-topic routing, stale-session, and multi-dapp approval edge cases from the first production surface.
If future product requirements need multiple simultaneous sessions, that should be introduced as a separate multi-session client/runtime with its own threat model and tests.

Current event model:

- pairing proposals become `SingleSessionClientEvent::SessionProposal`;
- pairing authentication requests become `SingleSessionClientEvent::SessionAuthenticate`;
- non-proposal pairing messages remain visible as `SingleSessionClientEvent::PairingMessage`;
- session-topic messages become `SingleSessionClientEvent::Session`;
- session requests and session updates are tracked as one-shot pending decisions after they are surfaced, so response helpers cannot be reused to answer the same user-significant request twice;
- an expired active session becomes `SingleSessionClientEvent::SessionExpired` and is removed from the in-memory runtime before another session message is polled;
- a closed relay socket during polling triggers one bounded reconnect attempt and resubscribes the single active topic before polling resumes;
- repeated receive timeouts are treated as a stale-connection signal after a configured threshold;
- automatic reconnects have a cross-call cooldown so repeated peer closes cannot turn polling into relay pressure;
- explicit shutdown marks the client as user-disconnected and disables automatic reconnect;
- invalid session requests are auto-rejected by the receive path when the rejection is deterministic and does not require user approval.
- permission-changing session updates are surfaced as events and require an explicit approve/reject API call.

Reference:

- [Session Request event](https://specs.walletconnect.com/2.0/specs/clients/sign/session-events#session_request)

## State Model

`SingleSessionClient` stores runtime state in memory only:

- at most one active pairing subscription;
- at most one active session subscription;
- at most one acknowledged session record;
- queued events;
- symmetric keys associated with the active pairing or session.

No symmetric keys, sessions, or pending approvals are persisted in this phase.

Rationale: persistence creates a security boundary. 
Until restore semantics, key storage, corruption handling, and migration behavior are designed, the safer default is to drop state on process exit. 
If the application closes or crashes, the next run starts fresh.

Messages for unknown or untracked runtime state should be dropped or rejected according to the narrow protocol context. 
`SingleSessionClient` should not infer a session from an incoming message when its in-memory state has been lost.

Deferred:

- secure key storage;
- restore of active sessions;
- storage migration;
- explicit stale-session cleanup after restore.

## Approval Policy

Auto-approval is not allowed.

The current session proposal approval flow is:

1. receive `wc_sessionPropose`;
2. expose it as `SingleSessionClientEvent::SessionProposal`;
3. caller decides whether to approve or reject;
4. wallet capabilities are used to plan an approved namespace set;
5. core publishes approval only after the caller supplies approval data.

`WalletCapabilities` is the first approval-planning primitive in `wc-core`.

Policy:

- required namespaces are all-or-error;
- optional namespaces approve only the supported chain/method/event intersection;
- accounts must match the capability chain;
- requested `sessionProperties` and `scopedProperties` are answered only with
  wallet-owned supported values;
- unsupported optional properties are omitted, while unsupported required
  properties reject approval planning;
- planned namespaces are revalidated with `wc-protocol` namespace validation before approval.

Rationale: namespace approval is a wallet security decision. The core can help calculate a safe approval shape, but the caller still owns user consent.

Session updates follow the same rule.
`wc_sessionUpdate` replaces namespaces, and namespaces contain chains, accounts, methods, and events.
The runtime must not acknowledge or apply such updates inside `SingleSessionClient::next_event()`.
It must expose the update to the caller, then apply it only through an explicit approval primitive.

Current session update flow:

1. receive `wc_sessionUpdate`;
2. expose it as `SingleSessionClientEvent::Session(SessionClientEvent::SessionUpdate)`;
3. caller compares current and requested namespaces using `SessionNamespacesDiff`;
4. caller invokes `SingleSessionClient::approve_session_update` or `SingleSessionClient::reject_session_update`;
5. core mutates stored namespaces only after publishing an approval acknowledgement.

Rationale: a protocol acknowledgement is not the same thing as wallet authorization.
The lower-level pairing primitive may build either success or error responses, but the wallet-facing runtime must make the permission boundary obvious.
The diff primitive keeps the review surface explicit: added chains, accounts, methods, and events can be shown to wallet policy and UI before acknowledgement.

Reference:

- [Approving a Session Response](https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces#approving-a-session-response)
- [Updating a Session](https://docs.walletconnect.network/wallet-sdk/web/usage#updating-a-session)

Session requests follow the same foreground approval model.
`wc_sessionRequest` asks the wallet to handle a chain-scoped JSON-RPC method.
The receive path may reject requests that are expired or outside the active namespaces, because the spec requires an immediate protocol error for unauthorized chain or method.
Valid requests are exposed to the caller through `SingleSessionClientEvent::Session(SessionClientEvent::SessionRequest)`.

Current session request flow:

1. receive `wc_sessionRequest`;
2. reject deterministically invalid chain, method, or expiry cases;
3. expose valid requests as session events;
4. caller extracts `SessionRequestReview` for UI and policy;
5. caller invokes `SingleSessionClient::respond_session_request_success` or `SingleSessionClient::respond_session_request_error`.

Rationale: the protocol can decide whether a request is authorized by namespace, but only the wallet/user can decide whether to sign or submit it.
The review primitive keeps request id, topic, chain, method, params, and expiry available without requiring application code to downcast raw session payloads.
For EIP-5792 Wallet Call methods, `SessionRequestReview::wallet_call_request` parses the method-specific params for review but still does not execute transactions or disclose capabilities on its own.

Reference:

- [Session Request event](https://specs.walletconnect.com/2.0/specs/clients/sign/session-events#session_request)
- [Session Request RPC method](https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionrequest)
- [EIP-5792 Wallet Call API](https://eips.ethereum.org/EIPS/eip-5792)

Session authentication follows the same explicit decision boundary.
`wc_sessionAuthenticate` asks the wallet to sign CAIP-122/CACAO payloads.
The runtime must not sign or approve authentication inside `SingleSessionClient::next_event()`.
It exposes auth review and explicit approve/reject primitives.

Current session authentication flow:

1. receive `wc_sessionAuthenticate`;
2. expose it as `SingleSessionClientEvent::SessionAuthenticate`;
3. caller extracts `SessionAuthenticateReview` for origin, requester, payload, chain, and expiry review;
4. caller signs authentication messages outside core and builds CACAO objects;
5. caller invokes `SingleSessionClient::approve_session_authenticate` or `SingleSessionClient::reject_session_authenticate`;
6. core publishes a type-1 JSON-RPC response on the requester public-key response topic;
7. if approval includes session namespaces, core derives and subscribes the authenticated session topic and stores an acknowledged session;
8. if approval has no session namespaces, core drops the pairing topic and returns to idle.

Rationale: authentication is a wallet identity decision. CACAO signing, Verify context, and origin policy are security-sensitive primitives and must be explicit API steps rather than side effects of polling.

The maintained SDK derives the authenticated session topic from requester and responder keys, subscribes that topic, stores an acknowledged session when approved methods exist, then publishes the auth success response. `SingleSessionClient` mirrors that shape, but requires the caller to pass the approved session namespaces explicitly so session creation remains a wallet policy decision.

Reference:

- [Maintained Sign Client authentication event](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2568-L2605)
- [Maintained Sign Client authenticated session creation](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1350-L1375)
- [Maintained Sign Client authenticated session subscription](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1377-L1380)
- [Maintained Sign Client authentication approval response](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1405-L1415)
- [Maintained Sign Client authentication rejection](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1433-L1468)
- [CAIP-74 CACAO](https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-74.md#specification)

Session expiry is a local runtime lifecycle event.
`SingleSessionClient` does not run a background expirer, so `SingleSessionClient::next_event()` checks active session expiry before polling relay messages.
When a session is expired, `SingleSessionClient` removes it from memory and returns `SingleSessionClientEvent::SessionExpired`.
The caller can update UI and refuse follow-up actions against that topic.

Rationale: an expired session should not remain available for signing or lifecycle operations.
The maintained Sign Client deletes the stored session and emits `session_expire` from its expirer callback; the proof-of-concept keeps the same transition in the foreground polling path.

Reference:

- [Maintained Sign Client expirer handling](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2714-L2727)

## Security Posture

Security should be added alongside feature work when it naturally belongs to the feature. Pure hardening should not run far ahead of behavior, but obvious safety boundaries should be added early.

Current security defaults:

- no auto-approval;
- explicit user/caller approval path;
- explicit authentication review and rejection path;
- explicit permission-change primitives before protocol acknowledgements;
- in-memory state only;
- one connection;
- bounded relay push handling;
- bounded queued relay messages;
- incoming WebSocket frame size limit;
- request timeouts;
- bounded relay connect retry/backoff;
- bounded automatic reconnect from `SingleSessionClient::next_event`;
- reconnect cooldown across `next_event` calls;
- receive-timeout liveness threshold for quiet sockets;
- explicit user-disconnected state that automatic reconnect must respect;
- closed relay connections are surfaced as explicit runtime errors;
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
- retry opening a relay WebSocket with bounded exponential backoff;
- reopen a relay WebSocket and clear stale local topic routing;
- expose next message by topic.

Reconnect scope in the current transport layer: `RelayReconnectConfig` retries connection establishment, and `RelayClient::reconnect_with_retry` replaces the socket while clearing local subscription IDs and queued messages.
The single-session runtime owns resubscription because it depends on the active `Idle`, `Pairing`, or `Session` state and must keep the one-topic boundary.

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

- reconnect behavior after repeated established-connection loss;
- durable storage and restore;
- persisted symmetric key handling;
- explicit drop policy reporting for flooded event queues;
- browser/Wasm transport;
- UniFFI and mobile bindings;
- CACAO signing and authentication workflow behavior;
- complete production threat model artifact.

Each deferred item should be designed when a feature requires it, with live probes and local tests added in the same slice.
