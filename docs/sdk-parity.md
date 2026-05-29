# SDK Parity

Status: target matrix for the single-session WalletConnect wallet runtime.

This document defines what "SDK parity" means for this repository. It does not
change the deliberate product boundary from [`architecture.md`](./architecture.md):
one foreground `SingleSessionClient`, one relay connection, one active session,
in-memory state, and no UniFFI/Wasm bindings yet.

## Milestone Target

The target is parity with the WalletConnect Wallet SDK flows that a production
wallet must handle for Sign usage:

- pairing and session lifecycle;
- session requests and wallet responses;
- session authentication with CACAO;
- Verify API context surfaced to wallet policy and UI;
- Wallet Call API request shapes and review helpers;
- interop against maintained JavaScript SDK flows and selected live demos;
- hardening for malformed, replayed, oversized, expired, and unauthorized input.

Deliberate exclusions for this milestone:

- persistence across process restarts;
- multiple simultaneous sessions;
- mobile bindings;
- Wasm bindings;
- Notify, Push, and service-specific product extras unless they become required
  by the Sign authentication/session flows.

## Status Legend

| Status | Meaning |
|---|---|
| Done | Runtime behavior exists, local tests exist, and at least one live probe covers the path where practical. |
| Partial | Types or behavior exist, but approval, policy, live interop, or edge coverage is incomplete. |
| Missing | Not implemented beyond generic protocol primitives. |
| Deferred | Excluded from this milestone by product/runtime decision. |

## Parity Matrix

| Area | SDK behavior | Current status | Target for this milestone | Test target | References |
|---|---|---:|---|---|---|
| Pairing URI | Parse `wc:` URI, extract topic, relay, project context, and symmetric key. | Done | Keep parser strict and extend only when live SDK URI shapes require it. | Local URI edge tests plus live JS URI probes. | [Pairing API](https://specs.walletconnect.com/2.0/specs/clients/core/pairing), [`PairingUri`](../crates/wc-protocol/src/pairing.rs) |
| Relay auth and transport | Connect to relay, authenticate, subscribe, publish, fetch, unsubscribe, and route pushes. | Done for native foreground client | Keep single-connection behavior; reconnect remains bounded and explicit. | `xtask scenario relay-matrix` and local routing/security tests. | [Relay Server RPC](https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc), [`wc-transport`](../crates/wc-transport/src) |
| Envelope crypto | Decode/decrypt and encode/encrypt type 0/type 1/type 2 envelopes. | Done for current runtime needs | Add fixtures only when a new SDK path exposes a new envelope nuance. | Upstream vectors, tamper tests, wrong-key tests, live relay round trips. | [Maintained crypto utils](https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L134-L148), [`Envelope`](../crates/wc-protocol/src/envelope.rs) |
| Session proposal | Receive `wc_sessionPropose`, expose approval review, approve/reject, settle, and store active session. | Done | Keep single-session replacement explicit. Add only SDK fields observed in new interop tests. | `xtask scenario single-session-request` and proposal rejection probes. | [Session proposal RPC](https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionpropose), [Namespaces approval](https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces#approving-a-session-response) |
| Session request | Receive `wc_sessionRequest`, reject deterministic authorization failures, surface valid requests, and respond once. | Done | Add method-specific review helpers for high-value wallet methods. | Live request/response scenario plus duplicate/unauthorized/expired local tests. | [Session request event](https://specs.walletconnect.com/2.0/specs/clients/sign/session-events#session_request), [`SessionRequestReview`](../crates/wc-core/src/session_request.rs) |
| Session lifecycle | Handle update, extend, event, ping, delete, disconnect, and session expiry. | Done | Keep update approval explicit and expiry one-shot. | Lifecycle live scenario plus local one-shot decision tests. | [Session events](https://specs.walletconnect.com/2.0/specs/clients/sign/session-events), [`session_lifecycle`](../crates/wc-core/src/pairing/session_lifecycle.rs) |
| `wc_sessionAuthenticate` reject | Receive auth request, expose review, reject explicitly, publish type-1 error response. | Done | Keep rejection path as the negative control for auth approval. | `xtask scenario single-session-authenticate`. | [One-click Auth, rejecting](https://docs.walletconnect.network/wallet-sdk/web/one-click-auth#rejecting-authentication-requests), [`reject_session_authenticate`](../crates/wc-core/src/client.rs) |
| `wc_sessionAuthenticate` approve | Approve auth with caller-provided CACAO auth objects and optional session namespaces. | Done for caller-supplied auth objects | Core publishes type-1 success, derives the authenticated session topic, and stores the session when namespaces are supplied. CACAO formatting/validation remains separate. | Live JS authenticate approval probe validates the adopted session topic against the maintained SDK result; local response topic/envelope/session tests. | [One-click Auth, approving](https://docs.walletconnect.network/wallet-sdk/web/one-click-auth#approving-authentication-requests), [maintained auth session creation](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1350-L1375), [maintained auth response publish](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1405-L1415) |
| CACAO payloads | Populate auth payload, format auth message, and build CACAO objects. | Done | Keep signing outside core. The caller signs; core formats, validates, and wraps caller-provided signatures. | Doctests for message formatting; fixtures for single-chain and multi-chain payloads. | [One-click Auth, payloads](https://docs.walletconnect.network/wallet-sdk/web/one-click-auth#authentication-objectspayloads), [CAIP-74 CACAO](https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-74.md#specification), [CAIP-122](https://chainagnostic.org/CAIPs/caip-122) |
| Auth plus session | Some auth approvals establish a session; some only authenticate. | Done for caller-supplied namespaces | `SessionAuthenticateApproval::with_session_namespaces` makes session adoption explicit. Without namespaces, approval remains auth-only and clears the pairing. | JS auth-plus-session live fixture; local authenticated session construction test. | [One-click Auth, approving](https://docs.walletconnect.network/wallet-sdk/web/one-click-auth#approving-authentication-requests), [maintained topic subscription](https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1377-L1380) |
| Proposal subrequests | Session proposals can carry authentication subrequests. | Done for authentication | Surface `requests.authentication` alongside proposal review and include `proposalRequestsResponses.authentication` on approval. Keep `walletPay` raw until WalletPay is modeled. | Live proposal-with-auth fixture and local DTO/session-settle tests. | [One-click Auth](https://docs.walletconnect.network/wallet-sdk/web/one-click-auth), [`ProposalAuthRequest`](../crates/wc-protocol/src/dto/session/proposal.rs), [`SessionProposalApproval`](../crates/wc-core/src/pairing/types.rs) |
| Verify API | Surface `verifyContext` for proposal, auth, and request. | Partial | `VerifyContext` DTOs exist, live event fixtures exist, `SingleSessionClient` attaches unresolved metadata-based context, native hash-based resolver support exists, session-request reviews retain the exact SDK-compatible request hash, and Verify v3 JWT attestations can be validated with the fetched P-256 public key. Relay-carried JWT/encrypted-id metadata is now retained on pairing/session messages and can resolve proposal, auth, and request review contexts with explicit clock input. | Live Verify harness, `xtask verify-probe --public-key`, local resolver tests, and runtime review tests. | [Verify API](https://docs.walletconnect.network/wallet-sdk/web/verify#domain-risk-detection), [`VerifyContext`](../crates/wc-protocol/src/verify.rs), [`VerifyResolver`](../crates/wc-core/src/verify_resolver.rs) |
| Verify policy | Wallets should warn on unknown/mismatch/threat states before approval. | Done for local classification | `classify_verify_context` classifies `VALID`, `UNKNOWN`, `INVALID`, and `isScam`; final approve/reject remains caller-owned. | Local policy matrix and live demo smoke tests. | [Verify implementation](https://docs.walletconnect.network/wallet-sdk/web/verify#implementation), [`VerifyContextRisk`](../crates/wc-core/src/verify_policy.rs) |
| Wallet capabilities | Plan approved namespaces from supported chains/accounts/methods/events. | Partial | Extend policy model for auth methods, session properties, scoped properties, and method-specific constraints. | Local approval planner matrix. | [Namespaces](https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces), [`WalletCapabilities`](../crates/wc-core/src/capabilities.rs) |
| Wallet Call API | Handle EIP-5792 wallet request shapes and capability responses. | Done for DTO/review helpers | Keep execution caller-owned. Core recognizes `wallet_getCapabilities`, `wallet_sendCalls`, `wallet_getCallsStatus`, and `wallet_showCallsStatus` but does not submit transactions or disclose capabilities automatically. | Live `wallet_getCapabilities` and `wallet_sendCalls` probes, JSON fixtures, doctests, and malformed-param tests. | [Wallet Call API](https://docs.walletconnect.network/wallet-sdk/android/eip5792), [EIP-5792](https://eips.ethereum.org/EIPS/eip-5792), [`WalletCallRequest`](../crates/wc-protocol/src/dto/session/wallet_call.rs) |
| Session properties | Dapps can request universal or chain-specific capability properties. | Missing | Preserve and review `sessionProperties` and `scopedProperties`; reject unsupported capability claims. | Proposal approval fixtures with CAIP-25 capability data. | [Wallet Call API, capabilities](https://docs.walletconnect.network/wallet-sdk/android/eip5792#capabilities-in-caip-25-connection-requests), [CAIP-25](https://github.com/ChainAgnostic/namespaces/blob/main/eip155/caip25.md) |
| Expiry behavior | Proposal, auth request, session request, and session expiry must be explicit. | Partial | Add auth request expiry and proposal expiry events/errors where not already covered. | Deterministic clock tests; no wall-clock sleeps. | [Pairing API expiry](https://specs.walletconnect.com/2.0/specs/clients/core/pairing), [Sign events](https://specs.walletconnect.com/2.0/specs/clients/sign/session-events) |
| Link mode and redirects | SDKs expose redirect/link-mode metadata for app switching. | Partial | Preserve redirect metadata in review objects. Full link-mode transport is out of native-runtime scope unless needed for parity probes. | DTO tests and metadata preservation tests. | [Mobile linking](https://docs.walletconnect.network/wallet-sdk/android/mobile-linking), [Link Mode](https://docs.walletconnect.network/wallet-sdk/android/link-mode) |
| Interop matrix | Behavior should match maintained JS SDK and selected live demos. | Partial | Add named scenarios for proposal, auth approval/rejection, Verify states, Wallet Call API requests, malformed input, and lifecycle. | `xtask scenario` suites with pinned JS harness dependencies. | [AppKit Lab](https://appkit-lab.reown.com), [WalletConnect demo wallet](https://react-wallet.walletconnect.com) |
| Fuzz and adversarial coverage | Parsers and runtime must reject malformed or hostile input. | Partial | Add fuzz targets for URI, JSON-RPC, namespaces, CAIP, CACAO, and envelopes; add replay/duplicate tests around one-shot decisions. | `cargo fuzz` targets later; local adversarial tests now. | [`wc-protocol`](../crates/wc-protocol/src), [`wc-core` tests](../crates/wc-core/src/pairing/tests.rs) |
| Persistence | Restore sessions/keys across process restarts. | Deferred | Not part of this milestone. Requires a separate key-storage and restore threat model. | None in this milestone. | [`architecture.md` state model](./architecture.md#state-model) |
| Multi-session | Maintain many simultaneous dapp sessions. | Deferred | Not part of this milestone. Future work should introduce a separate multi-session client. | None in this milestone. | [`architecture.md` runtime model](./architecture.md#runtime-model) |
| UniFFI/Wasm | Bind Rust runtime to Swift/Kotlin/JS. | Deferred | Add after API contract freezes. Bindings must remain wrappers only. | Binding generation smoke tests later. | [`architecture.md` crate boundaries](./architecture.md#crate-boundaries) |

## Implementation Order

The next implementation sequence is:

1. Session/scoped properties in proposal approval planning.
2. Expiry coverage for proposal/auth/session-request edges.
3. Interop scenarios for auth approval, Verify states, and Wallet Call API.
4. Fuzz/adversarial parser coverage.
5. API contract freeze and snapshots.

Each slice should follow the repository rule:

1. live probe or maintained-SDK fixture first when practical;
2. protocol/source references next to the primitive being implemented;
3. Rust docs and doctests where they clarify usage or invariants;
4. focused local tests;
5. `just check_all` before marking the slice complete.

## Source Notes

One-click Auth approval should not sign inside `SingleSessionClient`.
WalletConnect documents approval as building auth objects from signed messages and
then calling approval with `auths`; this repository should mirror that boundary.

> "at a minimum, one SIWE message must be signed"

Verify API is a review signal, not a silent allow/deny switch. The wallet-facing
API must expose the context and let caller policy decide.

> "`VALID`, `INVALID` or `UNKNOWN`"

Wallet Call API helpers must not execute wallet calls. Core can parse, validate,
and expose review data; the consuming wallet owns transaction execution.

> "`wallet_sendCalls`: Requests that a wallet submits a batch of calls."
