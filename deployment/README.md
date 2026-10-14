# Relay Deployment

This stack runs one relay instance behind an nginx reverse proxy:

- `relay` renders its configuration from the templates in `configs/relay`,
  serves the WebSocket protocol on `RELAY_PORT`, and answers probes on
  `HEALTH_PORT`.
- `nginx` is the only published service. It upgrades WebSocket connections to
  the relay and forwards everything else to it.

TLS is not terminated here. Put a load balancer, CDN or ingress that speaks
HTTPS/WSS in front of the published port.

## Layout

- `Dockerfile.relay`: image build, from the repository root context
- `docker-compose.yml`: the two services above
- `configs/compose.env.example`: the single env file for the stack
- `configs/relay/*.template`: rendered into the relay's `configuration/` at
  container start, then read by the binary
- `configs/nginx/default.conf.template`: rendered by the nginx image entrypoint
- `scripts/render-relay-config.sh`: the relay container's entrypoint

## Quick start

From this directory:

```bash
cp ./configs/compose.env.example ./configs/compose.env
# edit APPLICATION_AUDIENCE, then:
docker compose --env-file ./configs/compose.env up --build -d
```

Check it:

```bash
docker compose --env-file ./configs/compose.env ps
docker compose --env-file ./configs/compose.env exec relay \
  sh -c 'curl -fsS "http://127.0.0.1:$HEALTH_PORT/ready"'
```

Clients then connect to `ws://<host>:<RELAY_PUBLIC_PORT>/?auth=<JWT>&role=...&topic=...`,
or `wss://` once TLS is in front.

## Required configuration

Set these in `configs/compose.env`:

- `APPLICATION_AUDIENCE`: the `aud` the relay accepts in connection tokens. The
  container refuses to start without it, which is deliberate: a relay that
  accepts the wrong audience would either reject every client or, worse, accept
  tokens minted for another relay.
- `RELAY_PUBLIC_PORT`: the host port nginx publishes.
- `RELAY_PORT`, `HEALTH_PORT`: in-container ports.
- `MAX_TOKEN_LIFETIME_SECONDS`: longest remaining token lifetime accepted.

Any other relay setting can be added to the same file as `SECTION__KEY=value`
(see `crates/relay/configuration/base.yaml` for the full list), for example:

```bash
LIMITS__MAX_CONNECTIONS=20000
SESSION__GRACE_SECONDS=30
```

The effective configuration is written to `/app/configuration/` in the
container, so it can be inspected with
`docker compose --env-file ./configs/compose.env exec relay cat configuration/base.yaml`.

## Probes

- `GET /health` on `HEALTH_PORT` is liveness.
- `GET /ready` on `HEALTH_PORT` is readiness; `503` means the relay can no
  longer serve sessions.

The compose healthcheck polls `/ready` inside the relay container. Keep
`HEALTH_PORT` off the public interface: it needs no authentication and reports
session counts.

## TLS

The relay and nginx both speak plain HTTP here. Terminate TLS in front of the
published port and forward to it, preserving the `Upgrade` and `Connection`
headers. If you would rather terminate in this stack, mount certificates into
the nginx service, add a `listen 443 ssl` server block to
`configs/nginx/default.conf.template`, and publish `443`.

Connection tokens travel in the URL query string, so they appear in the access
logs of every proxy in the path, including this one. Keep
`MAX_TOKEN_LIFETIME_SECONDS` short, and keep proxy logs private or turn request
logging off for this service.

## Scaling

Sessions and buffered frames live in the relay's process memory: the two peers
of a topic must reach the same instance. Scaling out therefore needs affinity
on the topic (for example a consistent-hash upstream keyed on the `topic` query
parameter), or a single instance. Running more than one instance without
affinity splits sessions across processes; peers that land on different
instances never see each other and the relay never reports them as paired.

## Image builds

```bash
# from the repository root
docker build -f deployment/Dockerfile.relay -t wallet-session-relay:latest .
docker tag wallet-session-relay:latest registry.example.com/wallet-session-relay:latest
docker push registry.example.com/wallet-session-relay:latest
```

CI can run the same build; the context is the repository root, and
`.dockerignore` keeps `target/` and `.git/` out of it.
