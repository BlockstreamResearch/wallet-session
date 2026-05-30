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

# Run cargo-deny checks for the excluded fuzz crate.
fuzz_deny:
    cargo deny --manifest-path fuzz/Cargo.toml check --config fuzz/deny.toml advisories bans licenses sources

# Build local libFuzzer targets.
fuzz_build:
    cargo +{{nightly}} fuzz build

# Run short local fuzz smoke tests for parser boundaries.
fuzz_smoke:
    just _fuzz_with_corpus_copy pairing_uri 1
    just _fuzz_with_corpus_copy identifiers 1
    just _fuzz_with_corpus_copy envelope_decode 1
    just _fuzz_with_corpus_copy session_json_rpc 1
    just _fuzz_with_corpus_copy namespaces 1
    just _fuzz_with_corpus_copy cacao 1
    just _fuzz_with_corpus_copy single_session_state 1

# Run a bounded regression fuzz pass over every target.
fuzz_regression runs="1000":
    just _fuzz_with_corpus_copy pairing_uri {{runs}}
    just _fuzz_with_corpus_copy identifiers {{runs}}
    just _fuzz_with_corpus_copy envelope_decode {{runs}}
    just _fuzz_with_corpus_copy session_json_rpc {{runs}}
    just _fuzz_with_corpus_copy namespaces {{runs}}
    just _fuzz_with_corpus_copy cacao {{runs}}
    just _fuzz_with_corpus_copy single_session_state {{runs}}

# Run one fuzz target against a copied corpus so smoke/regression runs do not mutate checked-in seeds.
_fuzz_with_corpus_copy fuzz_target runs:
    mkdir -p target/fuzz-run-corpus/{{fuzz_target}}
    rsync -a --delete fuzz/corpus/{{fuzz_target}}/ target/fuzz-run-corpus/{{fuzz_target}}/
    cargo +{{nightly}} fuzz run -s none {{fuzz_target}} target/fuzz-run-corpus/{{fuzz_target}} -- -runs={{runs}}

# Generate rustdoc JSON used by API snapshot recipes.
api_snapshot_json:
    cargo +{{nightly}} rustdoc -p wc-core --all-features -- -Z unstable-options --output-format json

# Update the checked-in wc-core public API snapshot.
api_snapshot_update: api_snapshot_json
    cargo run -p xtask -- api-snapshot --update

# Check the checked-in wc-core public API snapshot.
api_snapshot_check: api_snapshot_json
    cargo run -p xtask -- api-snapshot --check

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
    just api_snapshot_check
