# x0x-symphony — Architecture

**Status:** Draft (M0). Source of truth for x0x-symphony architecture. Locked
decisions are captured as ADRs in [`../adr/`](../adr/).

**Audience:** Maintainers, contributors, and coding agents dispatched against
this repo.

---

## 1. Goal

Build a decentralized, harness-agnostic agent work orchestration layer for
the Saorsa Labs ecosystem. Borrow the issue-runner pattern from OpenAI
Symphony, but back it with x0x's gossip transport, CRDT task lists, MLS
group encryption, and post-quantum identity.

End-state v1.0 invariants:

1. **No external tracker.** No Linear, no GitHub, no SaaS. The shipping
   tracker is x0x's CRDT TaskList accessed through `x0xd`'s local REST API.
2. **No central orchestrator.** Any trusted x0x agent can claim work, run a
   coding harness, and publish a signed handoff.
3. **Harness-agnostic.** Codex, Claude Code, kimi, glm, minimax, pi, and
   plain shell scripts are all equal-class runners.
4. **Partition-tolerant.** A network split must not deadlock the system. Two
   agents may, in the worst case, do duplicate work; they must not corrupt
   shared state.
5. **Trust-gated.** Sensitive tasks may only be claimed by agents at
   `Trusted` or `Pinned` identity level. MLS-encrypted task lists scope
   private project work.

## 2. Non-goals

- Compatibility with OpenAI Symphony's binary or wire protocol. We borrow
  the pattern; we do not implement the spec.
- Replacing x0x's own issue tracker, GUI board, or CRDT primitives. We
  layer on top.
- Replacing `communitas-kanban`'s richer board UI. See ADR-0004 for why
  symphony uses x0x TaskList directly and how the two systems can converge
  later.
- General-purpose CI. Symphony dispatches coding-agent runs, not arbitrary
  pipelines.

## 3. Conceptual mapping

| Symphony concept           | x0x-symphony equivalent                                              |
|----------------------------|----------------------------------------------------------------------|
| Linear issue tracker       | git JSONL (M1–M2), then x0x CRDT TaskList (M3+)                      |
| Issue state                | TaskItem checkbox + LWW metadata register                            |
| Issue claim                | Signed CRDT claim record with TTL heartbeat                          |
| Per-issue workspace        | Per-task isolated workspace under runner-controlled root             |
| Codex app-server runner    | Pluggable runner trait with `shell`, `codex`, `claude_code` impls    |
| Tracker polling            | JSONL polling (M1–M2), then gossip pubsub on TaskList topic (M3+)    |
| Status/logging             | x0xd REST + WebSocket + per-issue `proofs/` artefact tree            |
| Handoff state              | Signed handoff payload in TaskItem metadata + linked artefact dir    |
| Linear comments / PR links | TaskItem metadata + optional outbound PR push                        |
| Central orchestrator       | Distributed orchestrators using x0x presence + trust + MLS           |

## 4. Layered model

```
┌─────────────────────────────────────────────────────────────┐
│  CLI: x0x-symphony           Daemon: x0x-symphonyd          │
│  - claim/list/run/handoff    - poll loop + dispatch         │
│  - status/proofs/workers     - worker advertisement         │
└─────────────────────────────────────────────────────────────┘
        │                              │
        ▼                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Orchestrator                                               │
│  Tracker  ◀──▶  Workspace  ◀──▶  Runner  ◀──▶  Handoff      │
│     │                                              │         │
│     ▼                                              ▼         │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐     │
│  │ git_jsonl   │  │ shell        │  │ Validation +    │     │
│  │ (M1–M2)     │  │ codex        │  │ proofs/<id>/<t>/│     │
│  │ x0x_crdt    │  │ claude_code  │  └─────────────────┘     │
│  │ (M3+)       │  │ ...          │                          │
│  └─────────────┘  └──────────────┘                          │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  x0xd REST/WebSocket API (HTTP localhost)                   │
│  /task-lists, /stores, /groups, /presence, /agent           │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  x0x — gossip / CRDT / MLS / ant-quic / presence            │
└─────────────────────────────────────────────────────────────┘
```

x0x-symphony does not link x0x as a Rust crate. The runner reaches the
running daemon over its local REST + WebSocket API. This keeps the runner
language-agnostic (a Python or Go reimplementation could follow the same
contract) and keeps x0x and x0x-symphony independently versioned.

## 5. Component contracts

### 5.1 Tracker

```rust
#[async_trait]
pub trait Tracker: Send + Sync {
    /// Issues currently dispatchable to an agent.
    async fn fetch_candidates(&self, ctx: &PollContext) -> Result<Vec<Issue>>;

    /// Look up the current state of specific issues without polling.
    async fn fetch_by_ids(&self, ids: &[IssueId]) -> Result<Vec<Issue>>;

    /// Claim an issue for `agent_id`. Fails if claim rules reject.
    async fn claim(&self, id: &IssueId, agent_id: &AgentId) -> Result<Claim>;

    /// Refresh the heartbeat on an existing claim.
    async fn heartbeat(&self, claim: &Claim) -> Result<()>;

    /// Release a claim without producing a handoff (e.g. session aborted).
    async fn release(&self, claim: &Claim, reason: ReleaseReason) -> Result<()>;

    /// Append the final handoff and move the issue to `review`.
    async fn handoff(&self, claim: &Claim, handoff: Handoff) -> Result<()>;
}
```

Adapters:

| Adapter      | Backed by                                | Lifespan        |
|--------------|------------------------------------------|-----------------|
| `git_jsonl`  | `issues/issues.jsonl` + git commits      | M1–M2 only      |
| `github`     | GitHub Issues REST API (mirror only)     | (Not built)     |
| `x0x_crdt`   | x0xd `/task-lists/:id` + `/stores/:id`   | M3 → permanent  |

ADR-0001 fixes the trait shape. ADR-0003 mandates that v1.0 ships with only
`x0x_crdt`.

### 5.2 Runner

```rust
#[async_trait]
pub trait Runner: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> &RunnerCapabilities;

    async fn start_session(&self, ctx: SessionContext) -> Result<SessionHandle>;
    async fn run_turn(&self, sess: &mut SessionHandle, prompt: Prompt) -> Result<TurnOutcome>;
    fn stream_events(&self, sess: &SessionHandle) -> EventStream;
    async fn stop_session(&self, sess: SessionHandle) -> Result<UsageReport>;
}
```

Adapters:

| Runner        | Mechanism                                              | Notes                            |
|---------------|--------------------------------------------------------|----------------------------------|
| `shell`       | Spawns a child process with prompt on stdin            | Universal fallback. Default.     |
| `codex`       | Wraps `codex app-server` per Symphony spec             | Optional preset over `shell`.    |
| `claude_code` | Wraps `claude` CLI with non-interactive flags          | Preset over `shell`.             |
| `kimi`/`glm`/`minimax`/`pi` | Configured presets over `shell`          | No bespoke crates.               |

The `shell` runner is the canonical contract: any harness reachable as a
process is a runner via configuration. Bespoke runners exist only for
harnesses with structured event streams worth parsing.

### 5.3 Workspace

```rust
pub trait Workspace: Send + Sync {
    fn root(&self) -> &Path;
    async fn create(&self, issue: &Issue) -> Result<WorkspaceHandle>;
    async fn run_hook(&self, h: &Hook, env: &HookEnv) -> Result<HookOutcome>;
    async fn destroy(&self, handle: WorkspaceHandle) -> Result<()>;
}
```

Invariants (Stage 5 in the original outline; mandatory from M1):

1. One workspace per task. Workspace path is deterministic from the issue
   identifier.
2. Workspace path must remain inside the configured root. Sanitized issue
   IDs only.
3. Coding agent runs only inside its task workspace.
4. Hooks have timeouts. No unbounded wait for approvals.
5. Secrets are never logged; runner config is explicit about which env vars
   are forwarded.

### 5.4 Orchestrator

Single-node first (M1), distributed later (M4). Responsibilities:

- Polling or subscription loop over the configured `Tracker`.
- Eligibility gate (state, blockers, claim availability, trust, capabilities).
- Concurrency limits per `WORKFLOW.md` `agent.max_concurrent_agents` and
  per-state caps.
- Retry with exponential backoff up to `max_retry_backoff_ms`.
- Reconciliation on startup: any in-progress claim owned by this agent is
  resumed or released depending on heartbeat freshness.
- Signed cancellation on operator command or timeout.
- Periodic state snapshot for observability.

### 5.5 Claim manager

Owns the sharded-claim state machine described in §6. Heartbeats run on a
dedicated task; `claim_ttl / 4` cadence by default.

## 6. Sharded ownership with TTL fallback (ADR-0002)

### 6.1 Why not lease + leader

A leader-elected lease is the obvious answer and the wrong one for
x0x-symphony: it requires consensus over a connected core, which forfeits
the partition-tolerance invariant. We accept duplicate work in rare
partition windows in exchange for never blocking on a quorum.

### 6.2 Algorithm

When a task is created, the creator records a frozen ownership record on
the task:

```jsonc
{
  "shard": {
    "primary":   "<agent_id>",
    "backups":   ["<agent_id>", "<agent_id>"],
    "claim_ttl_ms": 3600000,
    "created_view_epoch": 17
  }
}
```

`primary` and `backups` are computed by XOR distance against
`hash(task_id)`. Top three closest agents in the trusted-worker view at
creation time win the slots. The view epoch is recorded so reviewers can
audit which roster was used.

Claim attempts:

1. **Primary may always claim.** Heartbeat starts immediately.
2. **Backup may claim** only if `now − claim.heartbeat_at > claim_ttl_ms`,
   or no claim record exists.
3. **Anyone else is rejected.** Trust evaluation happens before this check;
   non-trusted agents are filtered upstream.
4. Heartbeat updates are CRDT LWW writes keyed by `(issue_id, "claim")`.

### 6.3 Partition reunion

If a primary and a backup are partitioned and both claim:

- On reunion, both claim records merge.
- The orchestrator running on each side observes two claim records.
- Tiebreak: lower-index shard owner wins (primary > backup_0 > backup_1).
  The loser writes an `abandon` record citing the conflict; their work
  product is preserved as a `proofs/<issue>/<ts>-abandoned/` artefact for
  human review but the issue's `handoff` only references the winner.
- Duplicate work is the cost of partition tolerance. By design, primary
  heartbeating prevents the common case; partition windows long enough for
  fallback to fire are observable in operations.

### 6.4 Worker-set view churn

Shard assignment is frozen at task creation. New trusted agents joining
later do not become primaries on existing tasks. This keeps re-shuffling
out of the data plane. A reshard is a deliberate operator action that
rewrites the task record and is rare.

## 7. Data model

### 7.1 Issue (logical)

```jsonc
{
  "id":          "X0X-0042",
  "identifier":  "X0X-0042",
  "title":       "Short imperative title",
  "description": "Markdown",
  "priority":    2,
  "state":       "todo",
  "branch_name": null,
  "url":         null,
  "labels":      ["x0x-symphony"],
  "blocked_by":  [{"id": "X0X-0041", "state": "done"}],
  "shard":       { /* §6.2 */ },
  "claim":       { /* present once claimed */ },
  "handoff":     { /* present once review */ },
  "created_at":  "2026-04-28T...",
  "updated_at":  "2026-04-28T..."
}
```

### 7.2 JSONL adapter mapping (M1–M2)

The above is the in-memory representation. The git_jsonl adapter serializes
one JSON object per line in `issues/issues.jsonl`. State changes commit a
JSONL diff. File locking uses git index lock.

### 7.3 x0x TaskList adapter mapping (M3+)

| Logical field            | x0x primitive                                                |
|--------------------------|--------------------------------------------------------------|
| `state == todo`          | TaskItem checkbox `Empty`                                    |
| `state == in_progress`   | TaskItem checkbox `Claimed`                                  |
| `state == done`          | TaskItem checkbox `Done`                                     |
| `state == review/blocked/cancelled/duplicate` | LWW metadata field `state`                  |
| `priority`, `labels`, `blocked_by`, `branch_name`, `url` | LWW metadata fields              |
| `shard`                  | LWW metadata field, written once at creation                 |
| `claim`                  | LWW metadata field, updated on heartbeat                     |
| `handoff` (small)        | LWW metadata field                                           |
| `handoff` (large blobs)  | KvStore entry, referenced from metadata                      |

The TaskList CRDT in x0x already supports OR-Set checkboxes plus an LWW
register per item; symphony's metadata extensions ride that register. MLS
encryption on the underlying TaskList gives private project work for free.

ADR-0004 records this choice and the convergence path with
`communitas-kanban` / a future `saorsa-kanban` crate.

### 7.4 Validation artefacts

- Small status (exit code, command list, pass/fail) lives in
  `handoff.validation`.
- Large blobs (full stdout, stderr, fmt diffs, clippy reports, runner
  traces) go to `proofs/<issue-id>/<utc-timestamp>/` as files. The
  orchestrator writes; the handoff links by relative path.
- For MLS-encrypted tasks, artefacts are stored under a per-group root and
  encrypted at rest; access mirrors the task list's MLS membership.

## 8. Workflow loader

Loads `WORKFLOW.md` (frontmatter YAML + Liquid-style prompt template).
Required keys:

- `tracker.kind` — `git_issues` (M1–M2) or `x0x` (M3+). `github` is **not**
  a v1 target; see ADR-0003.
- `polling.interval_ms`
- `workspace.root`
- `hooks.{after_create, before_run, after_run, before_remove}` with
  `hooks.timeout_ms`
- `agent.max_concurrent_agents`, `agent.max_concurrent_agents_by_state`,
  `agent.max_turns`, `agent.max_retry_backoff_ms`
- `runner.kind` — `shell` (default), `codex`, `claude_code`. Plus
  runner-specific config blocks: `runner.shell.{...}`, `runner.codex.{...}`,
  `runner.claude_code.{...}`.

The Codex-specific `codex:` block in the current x0x WORKFLOW.md is
preserved as a `runner.codex` namespace for backward compatibility, then
deprecated in M4.

## 9. Lifecycle (locked at M0)

```
              ┌──────────┐
              │   todo   │
              └────┬─────┘
                   │ claim
                   ▼
              ┌──────────┐  ── release ──┐
              │in_progress│              │
              └────┬─────┘               │
                   │ handoff             │
                   ▼                     │
              ┌──────────┐               │
              │  review  │               │
              └────┬─────┘               │
                   │ human-only          │
                   ▼                     │
              ┌──────────┐               │
              │   done   │               │
              └──────────┘               │
              ┌──────────┐               │
              │ blocked  │  ◀────────────┘ (auto when blocked_by changes)
              └──────────┘
              ┌────────────────┐
              │cancelled / dup │  (human-only)
              └────────────────┘
```

Agents move work `todo → in_progress → review`. They do not write `done`.

## 10. Observability

- `x0x-symphony status` — local view: active claims, retry queue, last
  events, validation status.
- `x0x-symphony tasks` — backlog, filtered by state/label/owner.
- `x0x-symphony workers` — reachable trusted workers and their advertised
  capabilities (M4+).
- REST surface served by `x0x-symphonyd` for dashboard integration:
  - `GET /symphony/tasks`
  - `GET /symphony/tasks/:id`
  - `GET /symphony/workers`
  - `GET /symphony/proofs/:id/:ts/{stdout,stderr,manifest.json}`
  - `GET /symphony/events` (SSE)

The existing x0x GUI board view (`renderSpaceBoard` in
`x0x/src/gui/x0x-gui.html`) gains symphony-aware filters and claim badges
in M3 — no parallel UI.

## 11. Security model

Inherits x0x's three-layer identity (Machine → Agent → User) and its
trust store. Symphony adds:

- **Dispatch trust gate.** Only agents at `Trusted` or `Pinned` may claim
  tasks labelled `security-sensitive`. Configurable per project.
- **Sandbox profiles** (M4): `read-only`, `repo-write`, `no-network`,
  `full-dev`, `ci-only`. The `shell` runner enforces via host sandbox
  (`firejail` on Linux, `sandbox-exec` on macOS). Profile is declared on
  the issue; the orchestrator refuses to dispatch a task whose required
  profile cannot be enforced by the available runner.
- **Signed claims and handoffs.** ML-DSA-65 signatures over the claim and
  handoff records using the agent's keypair. Verified on read by the
  Tracker adapter; mismatches are dropped.
- **MLS-only project groups.** Private projects use MLS-encrypted TaskLists
  via x0xd's existing group support. Workers outside the group cannot see
  task content; presence-level discovery still surfaces aggregate counts
  if the policy permits.

## 12. Milestones

| Milestone | Scope                                                                              | Tracker      | Tracker-adapter lifecycle    |
|-----------|------------------------------------------------------------------------------------|--------------|------------------------------|
| **M0**    | This document, ADRs, repo bootstrap, seeded issues                                 | n/a          | —                            |
| **M1**    | `git_jsonl` runner; Tracker / Runner / Workspace traits; orchestrator              | `git_jsonl`  | introduced                   |
| **M2**    | Shard + claim primitives in shared schema; validation artefact sink                | `git_jsonl`  | extended                     |
| **M3**    | `x0x_crdt` adapter; GUI board symphony mode; MLS group dispatch                    | `x0x_crdt`   | `git_jsonl` deleted          |
| **M4**    | Worker advertisement; sandbox profiles; partition reunion; security hardening      | `x0x_crdt`   | —                            |
| **M5**    | Cleanup; observability polish; v0.1.0 release                                      | `x0x_crdt`   | —                            |

The git_jsonl adapter is explicitly throwaway. M3 deletes it; the only
permanent tracker is `x0x_crdt`.

## 13. Open design questions (intentionally not yet locked)

These are tracked as M2/M3 decisions; capturing them here so they are not
lost.

- **Branch / PR push.** Do workers push branches and open PRs themselves,
  or only produce handoff patches that a human or automation pushes? Lean:
  emit signed patch + branch hint in handoff; pushing is a separate
  pluggable step.
- **Cross-repo dispatch.** A task in `x0x` may require a coordinated change
  in `ant-quic`. Modelled as `blocked_by` across separate TaskLists with a
  shared metadata link, or as a single multi-repo issue with multiple
  workspace roots? Lean toward the former.
- **Reshard.** When and how an operator may rewrite an existing task's
  shard slate. Lean: explicit signed reshard event with a reason.
- **Runner attestation.** Whether a runner emits a signed report of which
  binary version, model, and tools were used. Lean: yes, written into the
  handoff as `runner_attestation`.

## 14. References

- OpenAI Symphony — service specification
  <https://github.com/openai/symphony/blob/main/SPEC.md>
- x0x architecture — `~/Desktop/Devel/projects/x0x/CLAUDE.md`
- x0x TaskList CRDT — `x0x/src/crdt/`
- x0x GUI board view — `x0x/src/gui/x0x-gui.html` (`renderSpaceBoard`)
- communitas-kanban — sibling crate; richer model, separate CRDT engine
  (yrs); convergence discussed in ADR-0004 and
  [`saorsa-kanban-convergence.md`](saorsa-kanban-convergence.md)
