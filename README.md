# Wallet Session

Relay implementation of the Web-to-Wallet communications protocol, as described in [specification](./docs/spec.md)

## Repository structure

Currently repository contains these crates:

- [core](./crates/core/) -- core types which are shared between client and relay;
- [client](./crates/client/) -- client implementation of the relay protocol;
- [relay](./crates/relay/) -- relay server implementation.

## Relay deployment

For relay deployment instructions, see [deployment directory](./deployment/)
