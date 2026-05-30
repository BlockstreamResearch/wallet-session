# API Contract

Status: current `wc-core` public API contract for the single-session proof of concept.

This document describes the behavior exposed by the top-level `wc_core` API. It does not describe every lower-level DTO or transport primitive.
The broader SDK parity target and deliberate exclusions are tracked in [`sdk-parity.md`](./sdk-parity.md).

## Public Surface

The recommended wallet-facing surface is:

- `SingleSessionClient`
- `SingleSessionClientConfig`
- `SingleSessionRelayConfig`
- `SingleSessionClientEvent`
- `SingleSessionProposal`
- `SingleSessionAuthenticate`
- `SessionExpired`
- `WalletCapabilities`
- `SessionAuthenticateReview`
- `SessionRequestReview`
- `SessionNamespacesDiff`

Lower-level protocol-step items live under `wc_core::low_level`. They are available for harnesses and focused protocol tests, but application code should prefer `SingleSessionClient`.

Rationale: lower-level primitives expose individual protocol steps such as direct publish, direct response, and direct subscription handling. Composing those incorrectly can bypass the single-session runtime boundary.

The `testkit` module is feature-gated and exists for deterministic fuzzing and integration tests. It is not part of the wallet-facing runtime contract.

Source:

- [`wc-core/src/lib.rs`](../crates/wc-core/src/lib.rs)
- [`wc-core/src/client.rs`](../crates/wc-core/src/client.rs)
- [`wc-core/src/client/testkit.rs`](../crates/wc-core/src/client/testkit.rs)

## Runtime Shape

`SingleSessionClient` owns one relay connection and one active protocol topic:

```text
Idle -> Pairing -> Session -> Idle
```

The client is intentionally single-session. Consumers should create one `SingleSessionClient` instance for the wallet runtime and reuse it. Creating multiple clients to hold multiple active sessions is outside this contract.

Application-level replacement must be explicit:

1. tell the user that connecting a new dapp disconnects the current dapp;
2. disconnect or otherwise clear the current session;
3. pair with the new URI.

Source:

- [`SingleSessionClient::pair`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::disconnect`](../crates/wc-core/src/client.rs)
- [`docs/architecture.md`](./architecture.md#runtime-model)

## Configuration

`SingleSessionClientConfig` controls:

- bounded event queue capacity;
- reconnect policy;
- automatic reconnect cooldown;
- receive-timeout threshold before reconnect.

The automatic reconnect cooldown must be non-zero. This prevents a caller from configuring `next_event()` into a tight reconnect loop.

Source:

- [`SingleSessionClientConfig`](../crates/wc-core/src/client.rs)
- [`RelayReconnectConfig`](../crates/wc-transport/src/client.rs)

## Connection Lifecycle

`SingleSessionClient::connect` opens an authenticated relay connection.

`SingleSessionClient::shutdown` closes the socket, clears in-memory state, and disables automatic reconnect. After shutdown, `next_event()` returns `SingleSessionClientError::DisconnectedByUser` until the caller explicitly reconnects.

`SingleSessionClient::reconnect` opens a replacement socket and resubscribes the one active pairing or session topic. It does not restore state from disk and does not subscribe multiple topics.

Source:

- [`SingleSessionClient::connect`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::shutdown`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::reconnect`](../crates/wc-core/src/client.rs)
- [Relay subscribe](https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscribe)

## Event Polling

`SingleSessionClient::next_event()` is the only wallet-facing inbound API.

It checks, in order:

1. expired active session;
2. queued retained events;
3. active session topic;
4. active pairing topic.

It is not a concurrent polling API. Callers should have one foreground polling loop.

If the socket is closed during polling, `next_event()` makes at most one automatic reconnect attempt during that call. Consecutive receive timeouts also trigger automatic reconnect after the configured threshold. Cross-call reconnect cooldown prevents repeated polling from creating relay pressure.

Source:

- [`SingleSessionClient::next_event`](../crates/wc-core/src/client.rs)
- [Session request event](https://specs.walletconnect.com/2.0/specs/clients/sign/session-events#session_request)

## Pairing Flow

`SingleSessionClient::pair(uri)` requires the runtime to be idle. It rejects pairing if a pairing or session is already active.

The method:

1. parses the `wc:` URI;
2. fetches retained pairing-topic messages;
3. subscribes to the pairing topic;
4. queues fetched events within the configured event bound;
5. returns the pairing topic.

Session proposals are surfaced as `SingleSessionClientEvent::SessionProposal`.
Expired proposal messages are surfaced as `SingleSessionClientEvent::SessionProposalExpired`
and close the active pairing topic.

Session authentication requests are surfaced as `SingleSessionClientEvent::SessionAuthenticate`.
Expired authentication messages are surfaced as
`SingleSessionClientEvent::SessionAuthenticateExpired` and close the active pairing topic.

Pairing ping is acknowledged automatically. Pairing delete clears the active pairing.

Source:

- [`SingleSessionClient::pair`](../crates/wc-core/src/client.rs)
- [Pairing API](https://specs.walletconnect.com/2.0/specs/clients/core/pairing)
- [Best practices, session proposal expiry](https://docs.walletconnect.network/wallet-sdk/best-practices#session-proposal-expiry)
- [Relay fetch messages](https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#fetch-messages)
- [Relay subscribe](https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscribe)

## Session Proposal Decisions

`SingleSessionClientEvent::SessionProposal` must be approved or rejected by the caller.

Approval path:

1. caller reviews the proposal;
2. caller builds `SessionProposalApproval`;
3. optional: caller uses `WalletCapabilities::plan_session_approval`;
4. caller calls `approve_session`;
5. core publishes approval and settle messages;
6. core stores the session only after settle acknowledgement.

Rejection path:

1. caller chooses a JSON-RPC error;
2. caller calls `reject_session`;
3. core publishes the rejection and unsubscribes the pairing topic.

Source:

- [`SingleSessionClient::approve_session`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::reject_session`](../crates/wc-core/src/client.rs)
- [`WalletCapabilities::plan_session_approval`](../crates/wc-core/src/capabilities.rs)
- [Session proposal RPC](https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionpropose)
- [Namespace approval](https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces#approving-a-session-response)

## Session Authentication Decisions

`wc_sessionAuthenticate` asks the wallet to sign CAIP-122/CACAO authentication payloads.

The runtime surfaces authentication requests as:

```text
SingleSessionClientEvent::SessionAuthenticate
```

Supported paths:

1. caller receives the auth event;
2. caller calls `session_authenticate_review`;
3. caller applies origin/policy/user review;
4. caller signs authentication messages outside core and builds signed CACAO objects;
5. caller calls one of:
   - `approve_session_authenticate`;
   - `reject_session_authenticate`;
6. core publishes a type-1 JSON-RPC response on the requester public-key response topic;
7. if approval includes session namespaces, core adopts an acknowledged authenticated session;
8. if approval omits session namespaces, core clears the pairing and returns to idle.

Core does not sign authentication payloads and does not auto-approve authentication. 
Auth-created sessions are explicit: the caller opts in by passing namespaces through `SessionAuthenticateApproval::with_session_namespaces`.

Source:

- [`SingleSessionClient::session_authenticate_review`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::approve_session_authenticate`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::reject_session_authenticate`](../crates/wc-core/src/client.rs)
- [`SessionAuthenticateApprovalOutcome`](../crates/wc-core/src/client.rs)
- [`SessionAuthenticateApproval`](../crates/wc-core/src/session_authenticate.rs)
- [`SessionAuthenticateReview`](../crates/wc-core/src/session_authenticate.rs)
- [One-click Auth approval](https://docs.walletconnect.network/wallet-sdk/web/one-click-auth#approving-authentication-requests)
- [Maintained Sign Client authentication request handling](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2568-L2605)
- [Maintained Sign Client authenticated session creation](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1350-L1375)
- [Maintained Sign Client authenticated session subscription](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1377-L1380)
- [Maintained Sign Client authentication approval](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1405-L1415)
- [Maintained Sign Client authentication rejection](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1433-L1468)
- [CAIP-74 CACAO](https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-74.md#specification)

## Session Request Decisions

Valid `wc_sessionRequest` messages are surfaced as:

```text
SingleSessionClientEvent::Session(SessionClientEvent::SessionRequest)
```

The receive path rejects deterministic protocol failures before surfacing an event:

- expired request;
- unauthorized chain;
- unauthorized method.

For a surfaced request, the caller should:

1. call `session_request_review`;
2. show the request to policy/UI;
3. call exactly one of:
   - `respond_session_request_success`;
   - `respond_session_request_error`.

The client tracks surfaced request IDs as one-shot pending decisions. Once a response is acknowledged, the request is removed from the pending set. A second response attempt returns `SessionRequestDecisionMissing`.

Source:

- [`SingleSessionClient::session_request_review`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::respond_session_request_success`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::respond_session_request_error`](../crates/wc-core/src/client.rs)
- [Session request event](https://specs.walletconnect.com/2.0/specs/clients/sign/session-events#session_request)
- [Session request RPC](https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionrequest)

## Session Update Decisions

`wc_sessionUpdate` replaces namespaces. It can add or remove chains, accounts, methods, and events, so it is a permission decision.

The runtime surfaces updates as:

```text
SingleSessionClientEvent::Session(SessionClientEvent::SessionUpdate)
```

The caller should:

1. call `session_update_diff`;
2. review added and removed permissions;
3. call exactly one of:
   - `approve_session_update`;
   - `reject_session_update`.

The client tracks surfaced update IDs as one-shot pending decisions. Once approval or rejection is acknowledged, the update is removed from the pending set. A second decision attempt returns `SessionUpdateDecisionMissing`.

Local namespaces are mutated only after an approval acknowledgement.

Source:

- [`SingleSessionClient::session_update_diff`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::approve_session_update`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::reject_session_update`](../crates/wc-core/src/client.rs)
- [`SessionNamespacesDiff`](../crates/wc-core/src/session_update.rs)
- [Session update RPC](https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionupdate)
- [Updating a session](https://docs.walletconnect.network/wallet-sdk/web/usage#updating-a-session)

## Deterministic Session Lifecycle Messages

Some inbound session messages do not require wallet approval:

- `wc_sessionPing`: acknowledge with `true`;
- `wc_sessionExtend`: acknowledge and refresh expiry;
- `wc_sessionDelete`: acknowledge and clear local session state.

The high-level client handles these inside `next_event()`. The public high-level API does not expose manual response methods for them, which prevents double acknowledgements.

Source:

- [`SingleSessionClient::next_event`](../crates/wc-core/src/client.rs)
- [Session ping RPC](https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionping)
- [Session extend RPC](https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionextend)
- [Session delete RPC](https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessiondelete)

## Outbound Session Lifecycle

The client can publish lifecycle messages for the active session:

- `update_session`;
- `extend_session`;
- `emit_session_event`;
- `disconnect`.

`update_session` waits for acknowledgement before mutating stored namespaces.

`extend_session` waits for acknowledgement before mutating expiry.

`emit_session_event` publishes an event and does not wait for a success acknowledgement.

`disconnect` removes the active session after the relay accepts the delete publish.

Source:

- [`SingleSessionClient::update_session`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::extend_session`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::emit_session_event`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::disconnect`](../crates/wc-core/src/client.rs)
- [Session event RPC](https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionevent)

## Expiry

`SingleSessionClient` does not run a background expirer. `next_event()` checks expiry before polling relay messages.

If the active session is expired:

1. the session is removed from memory;
2. `SingleSessionClientEvent::SessionExpired` is returned;
3. later actions against that topic fail with `SessionMissing`.

If a stale proposal or authentication request is received on the pairing topic,
the pairing topic is removed and an expired event is returned instead of a
review event. If the caller tries to approve or reject a retained proposal/auth
event after its expiry, the method returns an expiry error and clears the
pairing topic without publishing a stale response.

Source:

- [`SessionProposalExpired`](../crates/wc-core/src/client.rs)
- [`SessionAuthenticateRequestExpired`](../crates/wc-core/src/client.rs)
- [`SessionExpired`](../crates/wc-core/src/client.rs)
- [`SingleSessionClient::next_event`](../crates/wc-core/src/client.rs)
- [Best practices, session proposal expiry](https://docs.walletconnect.network/wallet-sdk/best-practices#session-proposal-expiry)
- [Best practices, session request expiry](https://docs.walletconnect.network/wallet-sdk/best-practices#session-request-expiry)
- [Maintained Sign Client expirer handling](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2714-L2727)

## Error Contract

Public errors should expose typed context and preserve lower-level sources where useful.

Important caller-visible state errors:

- `ActivePairingExists`;
- `ActiveSessionExists`;
- `PairingSubscriptionMissing`;
- `SessionMissing`;
- `EventQueueFull`;
- `ReconnectCoolingDown`;
- `DisconnectedByUser`;
- `SessionAuthenticateReview`;
- `SessionRequestDecisionMissing`;
- `SessionUpdateDecisionMissing`.

Source:

- [`SingleSessionClientError`](../crates/wc-core/src/client.rs)
- [`PairingClientError`](../crates/wc-core/src/pairing/error.rs)

## API Snapshot

The checked-in public API snapshot is [`api-snapshots/wc-core.txt`](../api-snapshots/wc-core.txt).

It is generated from rustdoc JSON with `wc-core --all-features`, so it includes:

- top-level `wc_core` exports;
- `wc_core::low_level`;
- feature-gated `wc_core::testkit`.

Update it after an intentional public API change:

```sh
just api_snapshot_update
```

Check it without modifying files:

```sh
just api_snapshot_check
```

`just check_all` runs the snapshot check. Any diff should be reviewed as an API contract change, not treated as formatting churn.

Source:

- [`xtask/src/api_snapshot.rs`](../xtask/src/api_snapshot.rs)
- [`api-snapshots/wc-core.txt`](../api-snapshots/wc-core.txt)

## Live Coverage

The standard live suite is:

```sh
cargo run -p xtask --locked -- scenario
```

That runs:

- relay matrix;
- single-session request;
- single-session lifecycle update;
- single-session disconnect;
- single-session authentication rejection.

Focused high-level scenarios are also available:

- `cargo run -p xtask --locked -- scenario single-session-request`;
- `cargo run -p xtask --locked -- scenario single-session-lifecycle`;
- `cargo run -p xtask --locked -- scenario single-session-disconnect`;
- `cargo run -p xtask --locked -- scenario single-session-authenticate`;
- `cargo run -p xtask --locked -- scenario single-session-authenticate-approve`;
- `cargo run -p xtask --locked -- scenario single-session-live`.

The broader SDK interop scenario is:

```sh
cargo run -p xtask --locked -- scenario interop-live
```

That runs authentication rejection, authentication approval, Verify public-key
fetching, a JS SDK Verify context fixture, an AppKit-style CAIP-25
capability proposal, an AppKit-style link-mode proposal,
`wallet_getCapabilities`, `wallet_sendCalls`, `wallet_getCallsStatus`, and
`wallet_showCallsStatus`.

Focused interop scenarios are also available:

- `cargo run -p xtask --locked -- scenario verify-live`;
- `cargo run -p xtask --locked -- scenario wallet-call-live`;
- `cargo run -p xtask --locked -- scenario appkit-capability-proposal`;
- `cargo run -p xtask --locked -- scenario appkit-link-mode-proposal`;
- `cargo run -p xtask --locked -- scenario wallet-call-get-capabilities`;
- `cargo run -p xtask --locked -- scenario wallet-call-send-calls`;
- `cargo run -p xtask --locked -- scenario wallet-call-get-calls-status`;
- `cargo run -p xtask --locked -- scenario wallet-call-show-calls-status`.

Underlying probe commands remain available:

- `relay-probe --core-single-session-client-session-request`;
- `relay-probe --core-single-session-client-session-lifecycle`;
- `relay-probe --core-single-session-client-disconnect`.
- `relay-probe --core-single-session-client-session-authenticate`.
- `verify-probe --public-key`.

These scenarios cover JS dapp pairing, proposal approval, session settlement,
session request handling, session update handling, disconnect publication,
authentication rejection and approval, Verify context capture, AppKit-style
`sessionProperties`/`scopedProperties` negotiation, redirect/link-mode metadata
preservation, and all four Wallet Call request review methods through the
single-session client.

Source:

- [`xtask/src/relay.rs`](../xtask/src/relay.rs)
- [`xtask/src/scenario.rs`](../xtask/src/scenario.rs)
- [`tools/js-harness/src/verify-context.ts`](../tools/js-harness/src/verify-context.ts)
