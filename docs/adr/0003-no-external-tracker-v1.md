# ADR-0003 — No external tracker in v1.0

**Status:** Accepted (2026-04-28)
**Deciders:** David Irvine
**Context:** M0 design; relates to ADR-0001

## Context

The original outline plan included a GitHub Issues adapter as either a
mirror or a first-class tracker. Carrying any external-tracker dependency
into v1.0 would compromise the project's core promise: a decentralized,
trust-aware, partition-tolerant work coordination layer that runs on
Saorsa Labs primitives alone.

A GitHub adapter is also genuinely useful as scaffolding while the
shipping `x0x_crdt` adapter is being built — it gives existing GitHub
users a familiar surface during M1–M2.

## Decision

v1.0 ships with **one** tracker adapter: `x0x_crdt`. No GitHub. No
Linear. No SaaS. No file-based fallback.

The `git_jsonl` adapter exists only to bootstrap M1–M2 and is deleted
at M3 when `x0x_crdt` lands.

A GitHub adapter is **not** built at all. The complexity of even a
mirror-mode adapter (auth, webhooks vs CRDT conflict resolution, label
mapping, rate limits) is not worth the M1–M2 lifespan. Operators who
want GitHub presence can run a separate one-way exporter on top of
their `x0x_crdt` backlog at any time; that is a tool, not a runner
adapter.

## Consequences

- The dependency surface for v1.0 is x0xd plus the runner harnesses the
  operator chooses. Nothing else.
- The product story is clean: "Run x0xd; run x0x-symphonyd; that's it."
- Operators who need a synced GitHub view ship a separate exporter.
  This is documented as a non-goal of x0x-symphony and a possible
  community tool.
- M5's release scope is smaller: there is no `tracker/github.rs` to
  delete and no GitHub-specific docs to retire.
