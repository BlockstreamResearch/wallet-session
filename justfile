set shell := ["bash", "-euo", "pipefail", "-c"]

nightly := `cargo rbmt toolchains --nightly`

# Format code.
fmt:
    cargo +{{nightly}} rbmt fmt

# Check if code is formatted.
fmtcheck:
    cargo +{{nightly}} rbmt fmt --check

# Run clippy through rbmt.
lint:
    cargo +{{nightly}} rbmt --lock-file existing lint

# Build the workspace.
build:
    cargo rbmt --lock-file existing run --toolchain stable -- build --workspace --all-features --verbose

# Build all feature combinations.
build_features:
    cargo rbmt --lock-file existing run --toolchain stable -- hack check --feature-powerset --no-dev-deps

# Run unit tests.
test:
    cargo rbmt --lock-file existing run --toolchain stable -- test --workspace --all-features --no-fail-fast --verbose

# Run cargo-deny checks.
deny:
    cargo rbmt --lock-file existing run --toolchain stable -- deny check advisories bans licenses sources

# Check code the same way CI does.
check_all:
    cargo --version
    rustc --version
    cargo rbmt version
    just fmtcheck
    just lint
    just build
    just build_features
    just test
    just deny
