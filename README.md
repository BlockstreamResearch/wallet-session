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

## Live Scenarios

Run the default live relay and single-session client suite:

```sh
REOWN_PROJECT_ID=... cargo run -p xtask --locked -- scenario
```

List available scenarios:

```sh
cargo run -p xtask --locked -- scenario --list
```
