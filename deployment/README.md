# Relay Deployment

This stack runs one relay instance behind an nginx reverse proxy:

- `relay` renders its configuration from the templates in `configs/relay`,
  serves the WebSocket protocol on `RELAY_PORT`, and answers probes on
  `HEALTH_PORT`.
- `nginx` is the only published service. It upgrades WebSocket connections to
  the relay and forwards everything else to it.

TLS is not terminated here. Put a load balancer, CDN or ingress that speaks
HTTPS/WSS in front of the published port, or, with nothing in front, add the
`docker-compose.direct.yml` override for local testing or after configuring TLS
in this stack (see [Per-source limits](#per-source-limits)). Do not expose the
direct override's plain HTTP port to the Internet: connection tokens travel in
the URL.

## Layout

- `Dockerfile.relay`: image build, from the repository root context
- `docker-compose.yml`: the two services above
- `docker-compose.direct.yml`: override for when nothing sits in front of the
  stack; adds a per-source connection cap at accept
- `configs/compose.env.example`: the single env file for the stack
- `configs/relay/*.template`: rendered into the relay's `configuration/` at
  container start, then read by the binary
- `configs/nginx/nginx.conf`: nginx main config (worker pool, log defaults)
- `configs/nginx/default.conf.template`: rendered by the nginx image entrypoint
- `configs/nginx/direct/`: the main config, http template and stream front
  that `docker-compose.direct.yml` mounts instead
- `scripts/render-relay-config.sh`: the relay container's entrypoint

## Quick start

From this directory:

```bash
cp ./configs/compose.env.example ./configs/compose.env
# edit APPLICATION_AUDIENCE and set TRUSTED_PROXY_CIDR, then either, behind a
# TLS terminator or load balancer (TRUSTED_PROXY_CIDR = its range):
docker compose --env-file ./configs/compose.env up --build -d
# or, for local-only testing with nothing in front
# (TRUSTED_PROXY_CIDR=127.0.0.1/32; the override binds loopback):
docker compose -f docker-compose.yml -f docker-compose.direct.yml \
  --env-file ./configs/compose.env up --build -d
```

With the override, pass the same `-f` flags to every later `docker compose`
command (or export `COMPOSE_FILE=docker-compose.yml:docker-compose.direct.yml`);
an `up` without them puts the default nginx configuration back.
The override requires Docker Compose 2.24.4 or newer for `!override` and replaces
the base port mapping with a loopback-only one. For a public direct deployment,
configure TLS in this nginx first and deliberately change that mapping.

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
- `TRUSTED_PROXY_CIDR`: the proxy range allowed to assert a client address
  through `X-Forwarded-For`. Use the load balancer / CDN range when TLS
  terminates upstream, or `127.0.0.1/32` when nothing sits in front of this
  stack (the direct override then takes the address from its own front). The
  stack refuses to start without it, because a range that does not match the
  terminator silently collapses the per-source limits into one bucket.
- `RELAY_PUBLIC_PORT`: the host port nginx publishes.
- `RELAY_PORT`, `HEALTH_PORT`: in-container ports.
- `MAX_TOKEN_LIFETIME_SECONDS`: longest remaining token lifetime accepted.

Any other relay setting can be added to the same file as `SECTION__KEY=value`
(see `crates/relay/configuration/base.yaml` for the full list), for example:

```bash
LIMITS__MAX_CONNECTIONS=20000
SESSION__GRACE_SECONDS=30
```

Raising `LIMITS__MAX_CONNECTIONS` also needs nginx's `worker_connections`
raised; see [Capacity](#capacity).

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
headers. If you would rather terminate in this stack, nothing sits in front of
nginx, so use `docker-compose.direct.yml`: mount the certificates into the
nginx service, add `ssl` and the certificate directives to the unix `listen` in
`configs/nginx/direct/default.conf.template`, and set `RELAY_PUBLIC_PORT=443`.
The stream front then caps connections per source before the TLS handshake.

## Logs

Connection tokens and topics travel in the URL query string, so they reach the
logs of every proxy in the path that records the request line. The
configuration shipped here keeps them out of nginx's logs:

- The access log records the path only (`$uri`, never the query). The main
  config turns the stock http-level access log off, because its `main` format
  writes the full request line.
- The http server's error log is at `emerg`. nginx appends the full request
  line to every error-log message raised while it handles a request, whatever
  the level: upstream failures and rate-limit rejections at `error`, worker
  pool and file-descriptor exhaustion at `alert`. `crit` would still pass the
  `alert` lines; only `emerg` withholds them. Those events therefore show only
  as statuses in the access log (502, 503, 500, 408), and a worker pool that is
  already full when a client connects leaves no line at all, except at the
  direct override's stream front. The main config makes `emerg` the default
  for any server block you add; keep it there. An `emerg` message raised while
  handling a request, in practice a failed memory allocation, would still carry
  the request line.
- With the direct override, the stream front logs refused connections at
  `warn` with the client address only; it never sees a request line.

Any upstream terminator, load balancer or CDN must strip the query from its own
logs too. Keep `MAX_TOKEN_LIFETIME_SECONDS` short regardless.

Log retention is left to the host. Both containers write client-driven lines
to stdout: nginx one access-log line per request, `limit_req` rejections
included, and the relay its own records. The compose file sets no `logging:`
options, so the host Docker daemon's driver decides how much is kept:
`json-file` without `max-size` keeps one ever-growing file per container, while
`local` rotates by default. Check it on the host:

```bash
docker info --format '{{.LoggingDriver}}'
docker inspect --format '{{.Name}} {{json .HostConfig.LogConfig}}' \
  $(docker compose --env-file ./configs/compose.env ps -q)
```

If that shows `json-file` without `max-size`, set `log-opts` in the daemon's
`daemon.json`, or give both services a `logging:` section in an override file,
for example `logging: {driver: json-file, options: {max-size: 10m, max-file: '3'}}`.
Under an orchestrator, its own log rotation applies instead.

## Per-source limits

The per-source limits (`PER_IP_*`) are keyed on the client address: the whole
IPv4 address, or the /64 prefix of an IPv6 address, because one subscriber or
LAN normally holds a whole /64 and could otherwise take a fresh budget with
every address in it. Clients behind one IPv4 NAT, or on one shared IPv6 /64,
share a budget; raise the limits if that is normal for your users.
IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) keep the whole address.

When a load balancer, CDN or another proxy sits in front, that address is the
terminator's unless `TRUSTED_PROXY_CIDR` names its range: real_ip then resolves
the client from `X-Forwarded-For`, and forwarded headers from any other peer
are ignored, so the limits cannot be spoofed. The stack requires the variable
for exactly that reason.

`limit_conn` and `limit_req` count a connection only once its request header
is complete. A client that opens connections and never finishes a header is
counted against no source, and enough of them fill nginx's worker pool, after
which nginx resets every new client. `client_header_timeout 10s` releases each
such connection after 10 seconds, but does not cap how many one source holds.
That cap has to apply where connections are accepted, which depends on what
sits in front:

- **A front** (TLS terminator, load balancer, CDN): run `docker-compose.yml`
  alone. The front must buffer each complete request header before forwarding
  it and enforce its own per-client connection limit, and the published port
  must be reachable only from the front. This stack cannot check either. An L4
  load balancer, TLS passthrough, or a front that streams partial headers does
  not meet the requirement.
- **Nothing in front**: add `docker-compose.direct.yml`. It puts an nginx
  `stream {}` front on the published port that caps connections per client
  address at accept (`PER_IP_CONNECTIONS`, same key as above), before any HTTP
  byte is read, and hands each connection to the http server over a unix
  socket with the PROXY protocol, which carries the client address. Do not use
  it behind a front: every client would share the front's address.

nginx listens on IPv4 only inside the container. If Docker forwards IPv6
clients through its userland proxy (for example when the port is published on
IPv6 but the compose network is IPv4-only), nginx sees the proxy's address for
all of them, so they share one budget. Check the address nginx logs for an
IPv6 client before relying on the per-source limits for IPv6.

## Capacity

nginx's connection pool (`worker_connections`) is per worker process, and
every proxied WebSocket holds two entries in the worker that accepted it, the
client side and the relay side; through the direct override's front it holds
four. With the image's stock `worker_connections 1024`, a worker fills at about
511 tunnels, far below the relay's `limits.max_connections` (10000 by default).
A full worker resets new clients at accept or answers 500 at the upstream
connect, and the stack still reports healthy, because the compose healthcheck
probes the relay directly.

`configs/nginx/nginx.conf` and `configs/nginx/direct/nginx.conf` therefore
replace the image's main config with a pool of at least 2 × (direct: 4 ×)
`LIMITS__MAX_CONNECTIONS` plus headroom per worker: 24576 and 49152 for the
default 10000. The relay's limit then binds even if every tunnel lands on one
worker. When you raise `LIMITS__MAX_CONNECTIONS`, raise `worker_connections`
and `worker_rlimit_nofile` in the main config you run in proportion. nginx
allocates each worker's pool when the worker starts, so larger values cost
memory per worker even when idle; check the nginx container's memory after a
change.

Whether the stock pool was the binding limit on a given host depends on its
worker count (`worker_processes auto` starts one per CPU visible to the
container), which this repository does not record. To see the effective values
and whether the descriptor limit could be raised:

```bash
docker compose --env-file ./configs/compose.env exec nginx sh -c \
  'nproc; nginx -T 2>/dev/null | grep -E "^[[:space:]]*(worker_processes|worker_connections|worker_rlimit_nofile)"'
docker compose --env-file ./configs/compose.env logs nginx | grep setrlimit
```

A `setrlimit(RLIMIT_NOFILE, ...) failed` line means the container's hard
descriptor limit is below `worker_rlimit_nofile`; raise it with
`ulimits: {nofile: ...}` on the nginx service.

## Verification status

This stack has not been deployed, and there is no live ingress or production
client to check it against. Both Compose modes passed local structural rendering
with `--no-env-resolution`, and both nginx variants passed `nginx -t` after the
pinned image rendered their templates. A local direct-mode probe with
`PER_IP_CONNECTIONS=1` held one incomplete header and confirmed that a second
connection from the same source was refused. IPv6 forwarding, real clients,
and production TLS remain unverified. Before relying on a deployment:

```bash
# Both variants render (TRUSTED_PROXY_CIDR set in compose.env):
docker compose --env-file ./configs/compose.env config >/dev/null
docker compose -f docker-compose.yml -f docker-compose.direct.yml \
  --env-file ./configs/compose.env config >/dev/null
# After `up`, nginx accepts the rendered configuration; with the direct
# override, the stream front must be the listener on port 80:
docker compose --env-file ./configs/compose.env exec nginx nginx -T
```

The direct override relies on the nginx image entrypoint rendering
`*.stream-template` files into `/etc/nginx/stream-conf.d`. If it did not, the
stream block would be empty and the published port would refuse connections
rather than bypass the cap. Then confirm with real clients that the access log
shows client addresses (and, for IPv6, one key per /64), that connections over
`PER_IP_CONNECTIONS` from one source are refused, including ones that never
finish their request header, and that no nginx log line contains `auth=`.

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
