# Fuzzing

This directory contains local, offline fuzz targets for parser and DTO
boundaries. Do not point fuzzers at public Reown or WalletConnect services.
Live services are used through bounded `xtask scenario` runs; fuzzing mutates
local inputs only.

The fuzz crate follows the `cargo-fuzz` layout:

<https://rust-fuzz.github.io/book/cargo-fuzz.html>

> A Cargo subcommand for using libFuzzer easily with Rust projects.

Run a short local smoke pass:

```sh
just fuzz_smoke
```

Run a bounded regression pass over every target:

```sh
just fuzz_regression
```

For a shorter local check of the regression recipe:

```sh
just fuzz_regression 10
```

Run the fuzz crate supply-chain check:

```sh
just fuzz_deny
```

The smoke recipe uses `-s none` and `-runs=1` so it works as a deterministic
target/corpus validation check. The regression recipe keeps `-s none` for
host-stable bounded runs and accepts a configurable `-runs` value, defaulting to
`1000`.

Both recipes copy the checked-in seed corpus into `target/fuzz-run-corpus`
before running libFuzzer. This keeps routine smoke and regression runs from
mutating checked-in seed files. Longer local fuzzing should use the default
sanitizer and the checked-in corpus when the host supports it:

```sh
cargo +nightly fuzz run pairing_uri
```

The first target set is intentionally byte-oriented. It covers pairing URIs,
identifiers, envelope decoding, Sign/Pairing JSON-RPC DTOs, AppKit-style Wallet
Call request shapes, namespace validation, CACAO auth payload/message
validation, and single-session runtime state.

The `single_session_state` target uses `wc-core`'s non-default `testkit`
feature. It does not duplicate the one-shot model inside the fuzzer; it calls
the same in-memory pending decision, pairing replacement, session update,
session extend, session delete, and expiry primitives used by the client. This
keeps the fuzzer relay-free while still exercising the state transitions needed
before AppKit-style interop scenarios.

Seed corpus policy:

- keep small, sanitized protocol examples in `fuzz/corpus/*`;
- copy live SDK examples only after removing secrets, topics, project IDs, and
  any user data;
- use AppKit Lab and JS harness captures as corpus seeds, not as fuzz targets.

The `single_session_state` corpus includes sanitized variants for:

- a normal acknowledged session with pending request/update IDs;
- an auth-created session carrying CACAO objects;
- an AppKit-style Wallet Call/capability session with `sessionProperties`,
  `scopedProperties`, redirect metadata, and Wallet Call methods;
- an AppKit Wallet Call matrix session with status-request IDs captured from
  the live scenario;
- an expired link-mode-shaped session.
