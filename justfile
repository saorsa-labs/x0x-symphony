# x0x-symphony justfile
#
# Run `just --list` to see every recipe. `just check` is the canonical local
# validation entry point used by contributors, agents, and CI.

default:
    @just --list

# Full validation: formatting, clippy, tests, and documentation.
check: fmt-check lint test doc

# Quick validation for tight development loops.
quick-check: fmt-check lint test

# Format the whole workspace.
fmt:
    cargo fmt --all

# Verify workspace formatting without changing files.
fmt-check:
    cargo fmt --all -- --check

# Run clippy across all workspace targets and features with warnings denied.
lint:
    RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets -- -D warnings

# Run the workspace test suite through nextest with warnings denied.
test:
    RUSTFLAGS="-D warnings" cargo nextest run --workspace --all-features

# Run the workspace test suite through nextest with captured output shown.
test-verbose:
    RUSTFLAGS="-D warnings" cargo nextest run --workspace --all-features --no-capture

# Live preset contract smoke: spawns installed harnesses (claude, pi, codex)
# with the built-in preset argv and asserts no argv/usage rejection. Skips any
# harness not on PATH. Dev-machine recipe; may spend harness tokens.
preset-smoke:
    X0X_SYMPHONY_PRESET_SMOKE=1 cargo nextest run -p x0x-symphony-runner-shell --test preset_live_smoke --no-capture

# Build every workspace member with warnings denied.
build:
    RUSTFLAGS="-D warnings" cargo build --workspace --all-features

# Build every workspace member in release mode with warnings denied.
build-release:
    RUSTFLAGS="-D warnings" cargo build --workspace --release --all-features

# Build rustdoc for every workspace member with warnings denied.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

# Run rustdoc examples for every workspace member.
doc-test:
    RUSTDOCFLAGS="-D warnings" cargo test --doc --workspace --all-features

# Remove build artefacts.
clean:
    cargo clean

# Live two-daemon tracker-integrity race harness (spawns two isolated x0xd daemons).
# Requires an EXPLICIT mode: X0X_V2_APPEND_ONLY=1 (full matrix, x0xd >= 0.33.0)
# or X0X_V2_RACE_MODE=signed (interim fallback, weaker guarantees).
test-v2-race:
    @if [ "${X0X_V2_APPEND_ONLY:-}" = "1" ]; then echo "test-v2-race MODE: append-only (full matrix)"; \
    elif [ "${X0X_V2_RACE_MODE:-}" = "signed" ]; then echo "test-v2-race MODE: signed-fallback (interim, C1 residual open)"; \
    else echo "refusing: set X0X_V2_APPEND_ONLY=1 (full matrix) or X0X_V2_RACE_MODE=signed (interim fallback)"; exit 2; fi
    RUSTFLAGS="-D warnings" cargo nextest run -p x0x-symphony-tracker-x0x-crdt --test v2_two_daemon_race --run-ignored all --no-capture --test-threads=1 --no-fail-fast
