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

Run the fuzz crate supply-chain check:

```sh
just fuzz_deny
```

The smoke recipe uses `-s none` and `-runs=1` so it works as a deterministic
target/corpus validation check. Longer local fuzzing should use the default
sanitizer when it works on the host:

```sh
cargo +nightly fuzz run pairing_uri
```

The first target set is intentionally byte-oriented. Structure-aware fuzzing
with `Arbitrary` should be added once these parser boundaries are stable.

Seed corpus policy:

- keep small, sanitized protocol examples in `fuzz/corpus/*`;
- copy live SDK examples only after removing secrets, topics, project IDs, and
  any user data;
- use AppKit Lab and JS harness captures as corpus seeds, not as fuzz targets.
