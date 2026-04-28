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
