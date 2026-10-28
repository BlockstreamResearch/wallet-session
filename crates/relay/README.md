# Wallet Session Relay

WebSocket relay for the wallet-session protocol: it pairs a proposer and a
responder on a topic, forwards their encrypted envelopes, buffers frames for
peers that are briefly disconnected, and enforces the connection, session, rate
and size limits from [the specification](../../docs/spec.md).

The crate builds a library and one binary, `wallet-session-relay`.

## Configuration

Settings come from `configuration/*.yaml`:

1. `configuration/base.yaml` holds the defaults.
2. `configuration/${APP_ENVIRONMENT}.yaml` overrides them, where
   `APP_ENVIRONMENT` is `local` (default) or `production`.
3. Environment variables override both, with `__` separating nested keys:
   `APPLICATION__PORT=9000`, `LIMITS__MAX_SESSIONS=100`.

`configuration/production.yaml` deliberately sets no `application.audience`, so
a deployment that forgets it fails at startup rather than accepting tokens for
the wrong audience. Set it with `APPLICATION__AUDIENCE=wss://relay.example.com`.

See `configuration/base.yaml` for every key. The ones that matter most:

| Key | Purpose |
| --- | --- |
| `application.host` / `application.port` | WebSocket listener |
| `application.audience` | `aud` required in connection tokens (no default in production) |
| `health.host` / `health.port` | probe listener, separate from the WebSocket port |
| `auth.max_token_lifetime_seconds` | longest remaining lifetime accepted in a token |
| `session.grace_seconds` | how long a disconnected peer's slot is reserved |
| `session.buffer_max_messages` / `session.buffer_ttl_seconds` | frames buffered for it |
| `limits.*` | connection caps, per-identity/per-connection rates, and each identity's share of the global inbound byte budget |
| `connection.*` | frame size, queue capacity, and the handshake, write, ping, pong and idle timeouts |
| `connection.outbound_queue_max_bytes` | bytes held for one peer and not yet written (see [Outbound memory](#outbound-memory)) |
| `connection.outbound_queue_timeout_seconds` | longest a frame may wait in a peer's outbound queue before that peer is dropped |

Values that would make the relay unusable are rejected at startup: zero limits,
zero timeouts, a blank audience, a health address equal to the application
address, a byte-rate burst below the maximum incoming frame (no frame could
ever fit it), an outbound byte budget below the maximum incoming frame, or a
maximum incoming frame above `u32::MAX`. Every byte bucket and outbound budget
must hold a whole frame.

### Outbound memory

Frames waiting for a peer are bounded per peer, in frames and in bytes, and
in time:

- `connection.outbound_queue_max_bytes` (default 1 MiB, four maximal frames)
  caps the bytes held for one connection: its outbound queue, the frame being
  written, and the backlog of buffered frames waiting to enter the queue. A
  reserved slot gets a budget of the same size for what is buffered while its
  peer reconnects, and the connection that reclaims it takes those frames over.
  Bytes are the frame's JSON text, what the relay writes. A full buffer or
  backlog drops its oldest frames; a frame that cannot fit beside the queue is
  dropped, like one that finds `outbound_queue_capacity` full. Clients
  retransmit what is not acknowledged. `session_ready` and `peer_disconnected`
  are not charged, so a full budget never drops them.
- `connection.outbound_queue_timeout_seconds` (default 30) drops a peer whose
  queue holds a frame that was not written within that time of being queued,
  even if every single write met `write_timeout`. A reader too slow to drain
  its queue cannot keep its budget filled indefinitely.

These are per-peer limits only. The relay has no relay-wide cap on outbound
memory: the worst case is about `limits.max_connections ×
outbound_queue_max_bytes` for connected peers (10,000 × 1 MiB, roughly 10 GiB,
with the defaults), plus one budget per slot reserved during its grace window,
plus the copy of the frame each writer is encoding. The inbound byte budgets
limit how fast that memory can fill, not how much of it can be held. Size
`limits.max_connections` and `outbound_queue_max_bytes` together against the
memory available to the relay, and cap the process itself (for example with a
container memory limit): the relay enforces no aggregate bound.

## Running

Relay logs use a short topic tag instead of the bearer topic. Invalid-frame
records report the error class and location without echoing client content.
Stdout is written by a separate thread with an 8 MiB queue; when the sink
falls behind, whole records are dropped and a count is reported after it
recovers. Configure retention and collection for the deployment separately.

From this directory, since the configuration is read from the working
directory:

```bash
cargo run -p wallet-session-relay                     # local, 127.0.0.1:8080
APP_ENVIRONMENT=production APPLICATION__AUDIENCE=wss://relay.example.com \
  cargo run -p wallet-session-relay
```

## Probes

`GET /health` on the health port is liveness; `GET /ready` is readiness and
reports `connections`, `sessions`, and the monotonic `dropped_share_bytes` /
`dropped_global_bytes` counters. A rising drop counter means the relay is
shedding inbound traffic, so alert on its rate of change.

## Deployment

For deployment instructions, see [deployment README](../../deployment/README.md)
