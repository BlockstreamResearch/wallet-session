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

Values that would make the relay unusable are rejected at startup: zero limits,
zero timeouts, a blank audience, a health address equal to the application
address, a byte-rate burst below the maximum incoming frame (no frame could
ever fit it), or a maximum incoming frame above `u32::MAX`. Every byte bucket must
hold a whole frame.

## Running

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
