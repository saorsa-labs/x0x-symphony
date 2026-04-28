# x0x-symphony justfile
#
# Until crates are added in M1, most recipes are stubs that succeed quickly so
# CI plumbing can be wired up against a known-good baseline.

default:
    @just --list

# Full validation (fmt + lint + test + doc)
check: fmt-check lint test doc

# Quick validation (fmt + lint + test)
quick-check: fmt-check lint test

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --all-features --all-targets -- -D warnings

test:
    cargo nextest run --all-features --workspace

test-verbose:
    cargo nextest run --all-features --workspace --no-capture

build:
    cargo build --all-features

build-release:
    cargo build --release --all-features

doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps

clean:
    cargo clean
