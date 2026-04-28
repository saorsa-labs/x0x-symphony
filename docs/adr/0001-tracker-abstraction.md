# ADR-0001 — Tracker abstraction

**Status:** Accepted (2026-04-28)
**Deciders:** David Irvine
**Context:** M0 design

## Context

x0x-symphony needs to ship before x0x's CRDT TaskList exposes the full
shape we want for symphony-style coordination. The first useful runner
must operate against a git-committed JSONL backlog so it can be
dogfooded immediately.

If we hard-code the runner against JSONL, the eventual switch to x0x's
CRDT TaskList becomes a rewrite, not a refactor. If we hard-code against
TaskList, M1 cannot ship until x0xd exposes claim/handoff semantics that
do not yet exist.

## Decision

Define a single `Tracker` trait that both adapters implement. All
orchestrator, runner, and CLI logic depends only on the trait. The trait
shape is fixed at M0 and may not change without a superseding ADR.

```rust
#[async_trait]
pub trait Tracker: Send + Sync {
    async fn fetch_candidates(&self, ctx: &PollContext) -> Result<Vec<Issue>>;
    async fn fetch_by_ids(&self, ids: &[IssueId]) -> Result<Vec<Issue>>;
    async fn claim(&self, id: &IssueId, agent_id: &AgentId) -> Result<Claim>;
    async fn heartbeat(&self, claim: &Claim) -> Result<()>;
    async fn release(&self, claim: &Claim, reason: ReleaseReason) -> Result<()>;
    async fn handoff(&self, claim: &Claim, handoff: Handoff) -> Result<()>;
}
```

Two adapters in scope:

- `git_jsonl` — bootstrap. Lifespan M1–M2.
- `x0x_crdt` — production. Wraps x0xd's `/task-lists/:id` and `/stores/:id`
  REST endpoints. Lifespan M3 onward.

A `github` adapter is **out of scope** (see ADR-0003).

## Consequences

- M3 swaps adapters without touching orchestrator, runner, or CLI code.
- A misdesigned `Issue` struct becomes a migration headache. M2 freezes
  the data model (including `shard` and `claim` fields per ADR-0002)
  before M3 wires up `x0x_crdt`.
- The trait is intentionally narrow. Anything that smells like a
  tracker-specific feature (e.g. label autocomplete) belongs in an
  adapter-specific extension trait, not the core.
- The cost of two adapters during M1–M2 is borne once and discarded; we
  do not maintain `git_jsonl` after M3.
