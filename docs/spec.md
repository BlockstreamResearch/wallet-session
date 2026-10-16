# DRAFT: Web-to-wallet communication

## Introduction

This document describes a web-to-wallet communications architecture.

## Motivation

To create a secure method for exchanging information between a dApp and a wallet, without using WalletConnect, which contains many Ethereum-specific features.

## Scope and Non-Goals

This specification defines the transport layer only. It covers:

- The relay network model and its control protocol.
- Identity, registration, and connection authorization.
- Pairing, key agreement, and session establishment.
- The encrypted message envelope, message catalog, and reliability layer.

The following are out of scope of this specification:

- Application-level session semantics (namespaces, methods, chains, permissions). Any such data is carried as an opaque payload.
- User interface, QR rendering, and deep-link handling beyond the URI format.
- The relay's internal implementation, persistence, and scaling.


# Part I. Network Architecture

## 1. Network

Exchange is happening between two parties -- dApp and Wallet. Main connection point is the Relay, which is responsible for initial connection and messages exchange between dApp and wallet.

Communication is organized around topics. A topic is an 256 bit identifier shared by the clients. Both clients bind to the same topic, and every message published to that topic is delivered to the other subscribed client.

## 2. Network cryptography

Encryption algorithm: XChaCha20-Poly1305
Hashing algorithm: SHA-256  
Ephemeral key agreement between clients: X25519  
Derivation of the symmetric key from an X25519 shared secret: HKDF-SHA256  
Identity keys and connection token signatures: Ed25519

## 3. Relay

Relay is a main connection point between dApp and wallet.

Relay is a web socket server. A client connects to the Relay by providing the topic and its role in the connection URL. The proposer connects with the `Proposer` role specified; the responder connects with the `Responder` role specified.

A connection that presents a different identity than the one holding the slot is rejected while that slot is live or reserved for reconnection. A connection that presents the same identity replaces the holder: the Relay closes the replaced connection and signals `session_ready` to both peers again, so a peer may observe `session_ready` more than once per session. This lets a peer whose socket is half-open reconnect immediately instead of waiting for the Relay to reap the dead connection.

The Relay protocol is JSON text frames only. A peer that sends a binary frame is disconnected.

Once both parties are connected, the Relay sends `session_ready` to both. Neither party sends application messages before receiving that signal.

Messages send by the `Proposer` is send to the `Responder`. Messages send by the `Responder` is send to the `Proposer`.

While a peer is observed disconnected (its slot is in the reconnection grace), the Relay buffers frames addressed to it in FIFO order, up to a maximum number of messages and a per-message TTL (defaults: 256 frames, 60 seconds, inside a 10 second grace window). On overflow the oldest frame is discarded; on reconnect the frames whose TTL has not passed are sent to the peer after `session_ready`, in order, and removed from the queue. Buffered frames belong to the identity that owned the slot: a reservation claimed by a different identity after the grace window starts empty.

The Relay cannot observe end-to-end acknowledgements (§13): `ack` is an application message encrypted between the peers. Relay buffering is therefore best-effort and scoped to the observed-disconnected window. Frames written to a connection that is silently dead may be lost before the Relay notices; recovery is the responsibility of the sender's ack retry (§13).

Relay enforces resource limits to protect itself and its tenants: a bounded handshake deadline, a bounded per-connection outbound queue with a write deadline, keepalive pings with a pong deadline, maximum total and per-identity concurrent connections, a per-identity connection-attempt rate, and a maximum number of concurrent sessions. A peer that stops reading has its outbound queue drained by dropping frames (clients retransmit un-ACKed messages) rather than growing relay memory without bound; a peer that fails the write or pong deadline is disconnected and its slot enters the reconnection grace, so a silently half-open peer is detected before the idle timeout.

TLS is terminated in front of the Relay. The Relay itself speaks plain WebSocket behind that terminator, so the connection URL (including the JWT) is visible to it and to its logs.

### 3.1 Threat model notes

Slot ownership is first-come, first-served per topic and role. A party that learns a topic before its counterpart connects can claim the role slot and block the intended peer; the relay does not know which identity is expected on a slot. Pairing topics and URIs are therefore bearer secrets and must be short-lived. The connection caps above bound but do not eliminate this risk.

Slot takeover means a valid token for an identity is enough to evict that identity's live connection, not just to claim an empty slot. A leaked, logged or replayed token therefore displaces the legitimate peer until it reconnects. This is the reason the relay caps token lifetime (§5); the cap, not the identity check, is what bounds the exposure.

Likewise, identity keys are self-issued: anyone can mint a fresh `did:key` and a valid connection token. Rate limiting by identity raises the cost of abuse, and so would an operator-side ban list, but neither is a substitute for an issuer allowlist or proof of work; the transport-layer threat model accepts this.

## 4. Network identity

Each client derives a long-term identity as a Ed25519 key.

The identity key is stable across reconnects and app restarts, because it is derived from the persisted seed. The relay uses this identity to rate-limit and attribute clients.

The identity key is used to sign the connection token presented to the relay. It is not used to encrypt application messages.

The relay does not ban clients by identity. Banning would require an operator-side allow or deny list, and self-issued identities make a relay-side ban list weak on its own.

## 5. Connection authorization

Every client authenticates its WebSocket connection to the relay with a signed JWT by its identity key. The JWT is sent once, as a query parameter on the connection URL, which establishes a WebSocket connection.

A client may also send an optional `registrationId` query parameter. It is a client-asserted label reserved for relay-operator attribution and future quotas. It is not covered by the JWT signature, so it is **not an authorization mechanism** and the relay must not rate-limit, ban, or otherwise act on it until it is bound to the client identity (for example as a signed claim). Relays accept connections with or without it.

URI scheme for proposer:
```
wss://relay.example.com/?auth=<JWT>&role=proposer&topic=<topic>[&registrationId=<registration-id>]
```

URI scheme for responder:
```
wss://relay.example.com/?auth=<JWT>&role=responder&topic=<topic>[&registrationId=<registration-id>]
```

JWT scheme:
```rust
struct RelayAuthToken {
    iss: String,    // did:key derived from the identity public key
    sub: String,    // random session identifier
    aud: String,    // relay URL
    iat: u64,       // issued-at timestamp
    exp: u64,       // expiry
}
```

In case of reconnection to the same topic, client should authenticate again by the same identity key.

The relay validates the token before the WebSocket upgrade completes:

- the `alg` header must be `EdDSA`, and the signature must verify against the Ed25519 key embedded in `iss`;
- `aud` must equal the relay's configured audience;
- `exp` must be in the future and `iat` may be at most 60 seconds in the future, allowing for clock skew;
- the remaining lifetime must not exceed the relay's maximum accepted token lifetime, default 10 minutes, and the token must be at most 4096 bytes.

The relay does not use `sub`; it is available for the client's own session bookkeeping. A handshake whose query is malformed, longer than 8 KiB, or whose token fails validation is answered with `400 Bad Request` and no upgrade.

## 6. Network participants

Proposer (dApp) -- Initiates a session, creates a pairing, generates a proposal, and requests wallet approval.

Responder (wallet) -- Scans the pairing QR-code, approves or rejects proposals, and signs user requests.

Roles are not permanent: a client can be a proposer in one session and a responder in another. Both roles run the same client implementation and differ only in which side initiates.

## 7. Topic

Topic is a 32-byte value. Topics are derived from initial pairing key clients as a SHA256 hash.

## 8. Pairing

The proposer generates a random 32-byte pairing key and derives the pairing topic from it as a SHA256 hash, then shares both over a URI, rendered as a QR code or deep link, to establish connection through a relay. Topic is derived from pairing key.

```rust
struct PairingUri {
    pairing_key: String,     // 32-byte random symmetric key
    relay_uri: String,       // relay uri link
}
```

URI scheme:
```
	bsconnect://pairing?key=<base64url_key>&relay=<url_encoded_ws_uri>
```

Note: naming of the protocol in URI scheme could be changed.

All initial communications are encrypted by the initial pairing key, which would be replaced by the session key after key agreement.

## 9. Session

A session is the long-lived channel established after a successful pairing. The session key is derived using X25519 key agreement between both clients, E2E encrypted by the pairing key

The proposer generates an ephemeral X25519 keypair and embeds the public key inside the proposal (which itself is encrypted with the pairing key). The responder generates its own ephemeral keypair, and both peers derive the same session key and session topic, using X25519 ECDH for the key agreement and HKDF-SHA256 for the derivation of the session key.

Session establishment flow:

1. proposer creates a session in specific topic in the Relay as a `Proposer` and connects by this topic
2. responder scans QR-code, derives topic from pairing key, and connects to the Relay by this topic.
3. Relay sending `session_ready` control frame to both sides
4. proposer embeds its ephemeral public key in the proposal, encrypted with the pairing key
5. responder derives the session key, and embeds its own ephemeral public key in the approve message, encrypted with the pairing key;
6. proposer derives the same session key;
7. both parties continues exchanging messages by the new session key, using the same session.


# Part II. Relay Protocol


## 10. Message envelope

Every application message travels inside a relay frame. The relay reads the plaintext `topic` to route and forwards the frame, including its `id`, to the peer; it does not decrypt or re-encode the envelope inside `payload`. The outer frame is re-serialized from its parsed fields, so byte-for-byte equality of the outer JSON is not guaranteed, while the `payload` string is forwarded unchanged.

Relay frame:

```
{
  "v": 1,
  "id": "<16 random bytes, base64url>",
  "type": "message",                    // message | session_ready | peer_disconnected
  "topic": "<32 bytes, base64url>",
  "payload": "<envelope JSON, present on `message` frames only>"
}
```

The encrypted envelope carried in `payload`:

```
{
  "version": 1,
  "kind": "<catalog message type>",
  "from": "did:key:<identity>",
  "ts": <unix seconds>,
  "nonce": "<24 bytes, base64url>",
  "data": "<ciphertext || tag, base64url>"
}
```

The envelope `id` and `topic` are those of the enclosing relay frame and are not repeated inside it. The envelope's message type field is named `kind` so it does not collide with the relay frame's `type` field.

`session_ready` and `peer_disconnected` are relay-generated control frames: they carry no payload and are never forwarded to peers. Clients must not send them; the relay closes the connection of a peer that does.

Messages on the pairing topic are encrypted with the pairing key; messages on the session topic with the session key. Receiver must reject an envelope with an unsupported version, a topic it is not subscribed to, an invalid AEAD tag, or a reused nonce.

Receiver must reject any envelope where the `ts` is more than 300 seconds (5 minutes) older or newer than the local system clock. Clients must maintain a list of the frame `id`s received in the last 5 minutes and silently drop any duplicates.

## 11. AEAD AAD and nonce generation


Each sender generates a fresh random sender prefix per key. The counter increments by one per message. A sender must not reuse a (prefix, counter) pair with the same key. Receivers reject reused nonces for the current key.

Nonce scheme: 
```
nonce = sender_prefix (16 random bytes) || counter (8 bytes, starts at 0)
```

The AEAD AAD must be constructed by concatenating the plaintext fields as UTF-8 bytes, without separators or length prefixes: `AAD = version || id || type || topic || from || ts`. Here `version` is the envelope version as a decimal string, `id` and `topic` come from the enclosing relay frame, `type` is the envelope `kind` in snake_case, `from` is the sender's `did:key`, and `ts` is the envelope timestamp as a decimal string of Unix seconds. The receiver must reconstruct this exact AAD byte string and pass it to the cipher during decryption.

## 12. Message types

`proposal` -- Propose a session; carries the ephemeral public key. 
`approve` -- Approve the session; carries the ephemeral public key. 
`reject` -- Reject the proposal. 
`request` -- Application request. 
`response` -- Application response to a request. 
`ack` -- Acknowledge receipt of a message. An application message, E2E encrypted like any other: the relay cannot observe it. 
`disconnect`-- Gracefully close the session. 
`session_delete` -- Notify the peer that the session was deleted. 

`ping` and `pong` -- reserved and not implemented. Liveness is handled by WebSocket ping/pong control frames (§14). 

`session_ready` -- a relay control frame, not an application message (§10).

Payload shapes:

- `proposal`: `{ ephemeralPublicKey, sessionExpiry, proposal }`
- `approve`: `{ ephemeralPublicKey, approval }`
- `reject`: `{ code, message }`
- `request`: `{ requestId, request }`
- `response`: `{ requestId, response }` or `{ requestId, error }`
- `ack`: `{ ackId }`, where `ackId` is the id of the message being acknowledged
- `disconnect`: `{ reason, code, message }`
- `session_delete`: `{ code, message }`

`proposal` and `approval` are opaque application data.

## 13. Reliability

Ack: every message of type `proposal`, `approve`, `reject`, `request`, `response`, `disconnect`, and `session_delete` must be acknowledged with an `ack` whose `ackId` equals the received envelope id. The `ack` message is not itself acknowledged. The receiver sends the `ack` after successfully decrypting and validating the message.


If a sender does not receive an `ack` within 2 seconds, it must retransmit the envelope. Retries must use exponential backoff, doubling from the base delay, up to a maximum of 5 attempts. When the last attempt fails the sender gives up and reports the failure to the application. If the WebSocket disconnects, un-ACKed messages must be held in a local in memory queue and retransmitted immediately upon successful reconnection.

## 14. Connection lifecycle

Liveness is handled with WebSocket ping and pong control frames, not with application messages.

The client sends a WebSocket ping every 30 seconds and requires a WebSocket pong within 10 seconds. If the pong does not arrive, the connection is considered dead and the client reconnects, starting at 250 ms and backing off up to 5 seconds for at most 5 attempts.

The relay pings every 30 seconds and requires traffic from the peer within 10 seconds, after which the peer is disconnected and its slot enters the reconnection grace. Any inbound frame counts as activity, including the peer's own pings and pongs. A peer with no inbound traffic at all for 45 seconds is dropped regardless.


