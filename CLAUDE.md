# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in the x0x-symphony repo.

## What x0x-symphony is

A decentralized, harness-agnostic agent work orchestration runner built on
[x0x](https://github.com/saorsa-labs/x0x). Conceptually mirrors OpenAI
Symphony's issue-runner pattern but backs it with x0x's gossip transport,
CRDT task lists, MLS group encryption, and post-quantum identity instead of
Linear and a central orchestrator.

x0x-symphony talks to a running `x0xd` daemon over its local REST/WebSocket
API. It does not link x0x as a Rust crate.

## Source of truth

Always read [`docs/design/symphony.md`](docs/design/symphony.md) before making
architectural changes. ADRs in [`docs/adr/`](docs/adr/) record the locked
decisions:

- ADR-0001 — Tracker abstraction
- ADR-0002 — Sharded ownership with TTL fallback
- ADR-0003 — No external tracker in v1.0
- ADR-0004 — x0x TaskList CRDT as the symphony backbone

## Local dependency layout

x0x-symphony expects a sibling x0x checkout at `../x0x` for development. The
runner reaches the running daemon over HTTP/WebSocket; no Cargo path
dependency on x0x is required.

```
projects/
  x0x/             # daemon + CRDT primitives consumed at runtime
  x0x-symphony/    # this repo
```

## Build & test commands

```bash
just --list                                    # all recipes
just check                                     # fmt + clippy + test + doc
just fmt-check
just lint                                      # clippy with -D warnings
just test                                      # cargo nextest
```

Until the workspace has crates, `just` recipes are stubs. See `justfile`.

## Quality standards

Workspace-wide standards inherited from Saorsa Labs CLAUDE.md:

- Zero compilation errors, warnings, test failures, lint violations.
- No `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, `unimplemented!()` in
  production code (tests may use them for clarity).
- All public APIs documented.
- `RUSTFLAGS="-D warnings"` enforced in CI.

## Issue database

This repo uses the same git-committed JSONL tracker pattern as x0x. See
[`issues/schema.md`](issues/schema.md). Issue prefix is `XSY-`. The same
JSONL adapter that x0x-symphony exposes for x0x's `WORKFLOW.md` reads this
file when the runner is dogfooded against itself.

## Roadmap

Five milestones. M0 (this commit) lands the architecture. Subsequent
milestones each add one layer:

- **M1** — Local git_jsonl runner with full Tracker/Runner/Workspace traits.
- **M2** — Claim primitives + validation artefact sink.
- **M3** — x0x TaskList tracker adapter (replaces git_jsonl).
- **M4** — Distributed worker discovery + sandbox profiles + safety hardening.
- **M5** — Cleanup; delete bootstrap adapters; v1.0 release.

See [`docs/design/symphony.md`](docs/design/symphony.md) for the full plan.
