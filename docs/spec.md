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

Relay is a web socket server. A client connects to the Relay by providing the topic and its role in the connection URL. The proposer connects with the `Proposer` role specified; the responder connects with the `Responder` role specified. Once the session is established, any further attempt to connect to the same topic is rejected.

Once both parties are connected, the Relay sends `session_ready` to both. Neither party sends application messages before receiving that signal.

Messages send by the `Proposer` is send to the `Responder`. Messages send by the `Responder` is send to the `Proposer`.  

Relay maintains a FIFO queue of un-ACKed messages for both sides up to a maximum number of messages and a specific TTL. Upon reconnection, the Relay sent queued messages to the client, removing messages from the queue.

## 4. Network identity

Each client derives a long-term identity as a Ed25519 key.

The identity key is stable across reconnects and app restarts, because it is derived from the persisted seed. The relay uses this identity to rate-limit, attribute, and ban clients.

The identity key is used to sign the connection token presented to the relay. It is not used to encrypt application messages.

## 5. Connection authorization

Every client authenticates its WebSocket connection to the relay with a signed JWT by it's identity key, and a registration id, which should be registered in relay beforehand. Both are sent once, as query parameters on the connection URL, which establish a WebSocket connection.

URI scheme for proposer:
```
wss://relay.example.com/?auth=<JWT>&registrationId=<registration-id>&role=proposer&topic=<topic>
```

URI scheme for responder:
```
wss://relay.example.com/?auth=<JWT>&role=responder&topic=<topic>
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

## 6. Network participants

Proposer (dApp) -- Initiates a session, creates a pairing, generates a proposal, and requests wallet approval.

Responder (wallet) -- Scans the pairing QR-code, approves or rejects proposals, and signs user requests.

Roles are not permanent: a client can be a proposer in one session and a responder in another. Both roles run the same client implementation and differ only in which side initiates. Note that the proposer should have a registration id in order to use the relay server.

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

The encrypted envelope is the only application message unit and is sent directly over the relay connection. The relay reads the plaintext `topic` header to route and forwards the envelope verbatim to the peer; it does not wrap or re-encode it.

```
{
  "v": 1,
  "id": "<16 random bytes, base64url>",
  "type": "<catalog message type>",
  "topic": "<32 bytes, base64url>",
  "from": "did:key:<identity>",
  "ts": <unix seconds>,
  "nonce": "<24 bytes, base64url>",
  "data": "<ciphertext || tag, base64url>"
}
```

Messages on the pairing topic are encrypted with the pairing key; messages on the session topic with the session key. Receiver must reject an envelope with an unsupported version, a topic it is not subscribed to, an invalid AEAD tag, or a reused nonce.

Receiver must reject any envelope where the `ts` is more than 300 seconds (5 minutes) older or newer than the local system clock. Clients must maintain an list of `id`s which was sent for the last 5 minutes and silently drop any duplicates.

Relay control frames are plaintext because the relay must read them. They carry an `op` field instead of message data and are never forwarded to peers:

```
{
  "v": 1,
  "id": "<16 random bytes, base64url>",
  "op": "ping",                         // ping | pong | ack
  "topic": "<32 bytes, base64url>"
}
```

## 11. AEAD AAD and nonce generation


Each sender generates a fresh random sender prefix per key. The counter increments by one per message. A sender must not reuse a (prefix, counter) pair with the same key. Receivers reject reused nonces for the current key.

Nonce scheme: 
```
nonce = sender_prefix (16 random bytes) || counter (8 bytes, starts at 0)
```

The AEAD AAD must be constructed by concatenating the envelope's plaintext fields as UTF-8 bytes: `AAD = version || id || type || topic || from`. The receiver must reconstruct this exact AAD string and pass it to the cipher during decryption. If the relay tampered with the topic or sender ID, the decryption tag will fail to authenticate.

## 12. Message types

`proposal` -- Propose a session; carries the ephemeral public key. 
`approve` -- Approve the session; carries the ephemeral public key. 
`reject` -- Reject the proposal. 
`request` -- Application request. 
`response` -- Application response to a request. 
`ack` -- Acknowledge receipt of a message. 
`ping` -- Liveness check. 
`pong` -- Reply to `ping`. 
`disconnect`-- Gracefully close the session. 
`session_delete` -- Notify the peer that the session was deleted. 
`session_ready` -- notifies that both Proposer and Responder have connected

Payload shapes:

- `proposal`: `{ ephemeralPublicKey, sessionExpiry, proposal }`
- `approve`: `{ ephemeralPublicKey, approval }`
- `reject`: `{ code, message }`
- `request`: `{ requestId, request }`
- `response`: `{ requestId, response }` or `{ requestId, error }`
- `ack`: `{ ackId }`, where `ackId` is the id of the message being acknowledged
- `ping`, `pong`: `{}`
- `disconnect`: `{ reason, code, message }`
- `session_delete`: `{ code, message }`
- `session_ready`:  `{}`

`proposal` and `approval` are opaque application data.

## 13. Reliability

Ack: every message of type `proposal`, `approve`, `reject`, `request`, `response`, `disconnect`, and `session_delete` must be acknowledged with an `ack` whose `ackId` equals the received envelope id. The `ack`, `ping`, and `pong` messages are not acknowledged. The receiver sends the `ack` after successfully decrypting and validating the message.


If a sender does not receive an `ack` within 2 seconds, it must retransmit the envelope. Retries must use exponential backoff up to a maximum of 5 attempts. If the WebSocket disconnects, un-ACKed messages must be held in a local in memory queue and retransmitted immediately upon successful reconnection.

## 14. Connection lifecycle

The client sends `ping` every 30 seconds; if no `pong` is received within 10 seconds, the connection is considered dead and the client reconnects.


