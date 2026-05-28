# WalletConnect Client POC

Rust workspace for the WalletConnect client proof of concept.

## Crates

- `wc-core`: core WalletConnect single-session client primitives.

## Docs

- [Architecture](docs/architecture.md)
- [API contract](docs/api-contract.md)

## Checks

Run the same checks locally that CI runs:

```sh
cargo rbmt toolchains
cargo rbmt tools
just check_all
```
