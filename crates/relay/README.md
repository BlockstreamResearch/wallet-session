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
| `application.trusted_proxies` | peers allowed to name the client in `X-Real-IP` (see [Inbound fairness](#inbound-fairness)) |
| `health.host` / `health.port` | probe listener, separate from the WebSocket port |
| `auth.max_token_lifetime_seconds` | longest remaining lifetime accepted in a token |
| `session.grace_seconds` | how long a disconnected peer's slot is reserved |
| `session.buffer_max_messages` / `session.buffer_ttl_seconds` | frames buffered for it |
| `limits.*` | connection caps, per-identity/per-connection rates, and each identity's and source's share of the global inbound byte budget |
| `limits.global_paired_reserve_percent` | part of the global budget only paired sessions may spend |
| `limits.inbound_wire_byte_rate` | rate at which one connection's socket is read, framing and fragments included (see [Wire bytes](#wire-bytes)) |
| `connection.*` | frame size, queue capacity, and the handshake, write, ping, pong and idle timeouts |
| `connection.outbound_queue_max_bytes` | bytes held for one peer and not yet written (see [Outbound memory](#outbound-memory)) |
| `connection.outbound_queue_timeout_seconds` | longest a frame may wait in a peer's outbound queue before that peer is dropped |

Values that would make the relay unusable are rejected at startup: zero limits,
zero timeouts, a blank audience, a health address equal to the application
address, a byte-rate burst below the maximum incoming frame (no frame could
ever fit it), an outbound byte budget below the maximum incoming frame, or a
maximum incoming frame above `u32::MAX`. Every byte bucket and outbound budget
must hold a whole frame, and so must the part of the global burst outside the
paired reserve, which must be below 100 percent. The wire budget may not be
below `inbound_byte_rate`, in burst or in rate. Trusted proxy ranges that
together hold every IPv4 or every IPv6 address (`0.0.0.0/0`, `::/0`, or
`0.0.0.0/1` with `128.0.0.0/1`) are refused: they would let every peer choose
its own source. Narrower ranges are taken as given, so a range that holds
client addresses lets those clients choose theirs.

### Inbound fairness

Every inbound text, ping and pong frame is charged, before it is parsed, to its
connection's own message and byte buckets (`inbound_message_rate`,
`inbound_byte_rate`). A
connection that keeps exceeding them is disconnected. What happens next
depends on whether anything can receive the frame:

- **Paired**: the counterpart is connected. The frame is charged to its
  identity's share (`identity_inbound_byte_rate`), its source's share
  (`source_inbound_byte_rate`) and the relay-wide budget
  (`global_inbound_byte_rate`), then parsed and forwarded.
- **Buffered**: the counterpart is within its reconnect grace window and
  buffering is enabled. The frame will be delivered when it returns, so it is
  charged like a paired one, except that it cannot spend the paired reserve.
- **No receiver**: there is no counterpart, or it is reconnecting while
  buffering is disabled. The frame is dropped without being parsed and without
  spending any shared budget: identities cannot drain the relay-wide budget
  through sessions that have nobody on the other side.

WebSocket pings and pongs are for the relay, not the counterpart. They are
charged to the same budgets whether or not a counterpart is connected, but
without one they cannot spend the paired reserve either. Refusing one still
counts as activity for the idle and pong deadlines.

The shares and what exceeding them does:

- The **identity share** (default 1 MiB/s) caps one `did:key`. A connection
  that keeps exceeding it is disconnected.
- The **source share** (default 1 MiB/s, no larger than the identity share)
  caps every identity connecting from one source together, since identities
  cost nothing to mint. Exhausting it only drops the frame: other clients
  behind the same address must not be able to get a peer disconnected.
- The **global budget** (default 16 MiB/s) caps the relay. Exhausting it only
  drops the frame, so other identities cannot get a peer disconnected.
  `global_paired_reserve_percent` (default 25) of its burst can be spent only
  by paired frames: buffered frames and control frames without a counterpart
  are refused once the budget is down to the reserve, so they cannot starve
  sessions whose peers are talking to each other.

A source is the TCP peer's IPv4 address, or the /64 holding its IPv6 address
(IPv4-mapped peers count as IPv4). When the peer is in
`application.trusted_proxies`, the source is instead the address it writes in
`X-Real-IP`. The header must appear once and hold exactly one address,
otherwise the proxy itself is the source. From any other peer the header is
ignored, so a client that reaches the relay directly cannot pick its source;
the first time that happens the relay logs a warning, since it also means a
proxy in front is missing from the list. `X-Forwarded-For` is never read.
`trusted_proxies` takes a YAML list or one comma-separated string, so
`APPLICATION__TRUSTED_PROXIES=172.20.0.5/32` sets it from the environment.

Compatibility and defaults:

- `application.trusted_proxies` is optional and empty by default: every
  connection is accounted to its TCP peer. `limits.source_inbound_byte_rate`
  and `limits.global_paired_reserve_percent` are required, like the other
  limits; a configuration file written for an earlier version must add them.
- A relay behind a proxy that is not listed accounts every client to the
  proxy's address, so all of them share one source share (1 MiB/s by
  default). List the proxy, or raise the source share.
- Clients behind one NAT address, or one IPv6 /64, share a source share.
- A frame sent before the counterpart connects, or while it is reconnecting
  with buffering disabled, is no longer parsed: an invalid or relay-only frame
  sent then is dropped silently instead of closing the connection. It is
  checked as before once a counterpart is present. Clients should wait for
  `session_ready` before sending, as the protocol already requires.
- `/ready` reports `dropped_source_bytes` beside the other drop counters.

Topology limits:

- The source share is only as scarce as addresses are. A client with many IPv4
  addresses, or with routed IPv6 space (a /48 holds 65,536 /64s), gets one
  share for each; the global budget and the paired reserve remain the bound
  on what such a client can take. As for identities, at most 65,536 sources
  are tracked at once. Past that, a share is forgotten only once it has
  refilled completely (checked at most once a second); until one has, new
  sources spend one share between them instead of displacing a tracked one.
- Trusting a proxy is only safe when the proxy overwrites `X-Real-IP` and
  nothing else reachable from a trusted address can connect to the relay. The
  compose deployment trusts the private ranges Docker assigns its networks
  from, because the relay port is not published and nginx is its only peer
  there (see `deployment/configs/relay/base.yaml.template`). Publishing the
  relay port, attaching other containers to its network, or running a
  relay-port listener on the Docker host breaks that assumption: narrow the
  list to nginx's address.
- nginx resolves the client address it forwards from `X-Forwarded-For` only
  for its own `TRUSTED_PROXY_CIDR`, so the source behind a load balancer or
  CDN is only as accurate as that setting. In the shipped deployment, nginx
  keys its IPv6 per-source limits on the /64, like the relay.
- A relay without a proxy listens directly (`configuration/production.yaml`),
  and its sources are the TCP peers. Nothing in the relay can tell apart
  clients that share an address. Its wire-byte throttle is per connection;
  put a per-source connection cap in front of a directly exposed relay so
  free identities cannot multiply fragment-processing work up to the global
  connection limit.
- Budgets are per process. Each relay instance has its own.

### Wire bytes

The budgets above count what reaches the read loop: complete text messages
and control frames. The WebSocket layer below it does work on every frame,
and a message may arrive in any number of fragments, so a client could send a
text frame without FIN followed by empty continuation frames, six bytes each,
that never form a message and were never charged.

Every connection's socket is therefore read through its own wire budget,
`limits.inbound_wire_byte_rate` (default 1 MiB per 2 seconds), before the
WebSocket layer parses anything. Every byte read counts once: the upgrade
request, frame headers and masks, control frames, the continuations of a
fragmented message, and the payloads of complete messages.

- A read takes no more than the budget holds. While the budget is empty the
  relay leaves the socket alone and tries again when it has refilled, after at
  most a second, so the sender is slowed down by TCP flow control. Nothing is
  dropped, and exceeding the wire budget never disconnects anyone.
- The token, pong and idle deadlines keep running meanwhile. A throttled read
  only holds up this connection's own frames.
- The wire budget is separate from `inbound_byte_rate`: a complete message's
  payload is counted once in each, never twice in one. The default leaves room
  for the framing of a peer that stays within `inbound_byte_rate`, so only
  overhead-heavy traffic, like a fragment flood, is slowed. Keep it above
  `inbound_byte_rate`: the relay refuses to start with a wire burst or rate
  below it.
- `limits.inbound_wire_byte_rate` is required, like the other limits; a
  configuration file written for an earlier version must add it.

Residual limits:

- The wire budget is per connection only. Wire bytes spend no identity, source
  or global budget, because frames that reach nobody must not (see above), and
  a relay-wide wire budget would let one-sided floods slow paired sessions'
  reads. A client's wire throughput therefore scales with its connections, up
  to `limits.max_connections` across identities, and only per-connection
  limits in front of the relay (nginx `limit_conn`) bound how many one source
  holds.
- The budget counts bytes, not frames. An empty continuation costs the relay
  several times more work per byte than a large frame, so at the default rate
  one connection streaming nothing but empty fragments is read at about
  87,000 frames a second. There is no limit on the number of fragments per
  message: tokio-tungstenite has no frame-level read to enforce one.
- Fragments are not messages, so they do not reset the idle deadline; a
  connection that streams them and answers the relay's pings lasts until its
  token expires, read at its wire rate.
- A peer that sends faster than its wire budget queues its own pongs and
  messages behind the bytes waiting for it. If nothing complete gets through
  within `connection.pong_timeout_seconds` of a keepalive ping, the pong
  deadline drops it.

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
`dropped_source_bytes` / `dropped_global_bytes` counters. A rising drop counter
means the relay is shedding inbound traffic, so alert on its rate of change.
Frames dropped because nothing could receive them are not counted.

## Deployment

For deployment instructions, see [deployment README](../../deployment/README.md)
