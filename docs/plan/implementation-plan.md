# x0x-symphony — Implementation Plan

**Status:** Draft for team review (M0 + 1, 2026-04-28).
**Companion:** [`../design/symphony.md`](../design/symphony.md) (architecture)
and the four ADRs in [`../adr/`](../adr/).

This plan is the *how* and *when*. The architecture is the *what*. Where
they appear to disagree, the architecture wins; raise an ADR.

---

## How to read this plan

- **Each milestone has a gate.** Until the gate passes, the next milestone
  does not start. The gate is defined as a small set of explicit checks,
  not a vibe.
- **Each crate has a fixed public surface.** Adding to it requires a
  superseding ADR.
- **Each issue has acceptance criteria written into `issues.jsonl`.** The
  agent that closes the issue must satisfy them. Reviewers reject otherwise.
- **No issue ships without docs.** If the issue introduces public Rust API,
  it ships with rustdoc on every public item; if it changes behaviour, it
  updates the operator docs in the same handoff.

## Coding and quality standards (inherited)

From the workspace-level Saorsa Labs CLAUDE.md and `crates/x0x-symphony/CLAUDE.md`:

- Zero compilation errors, warnings, test failures, lint violations.
- No `unwrap` / `expect` / `panic!` / `todo!` / `unimplemented!` in
  production code. Tests may use them.
- All public APIs documented with rustdoc.
- `RUSTFLAGS="-D warnings"` and `RUSTDOCFLAGS="-D warnings"` enforced in CI.
- `cargo fmt --all -- --check`, `cargo clippy --all-features --all-targets
  -- -D warnings`, `cargo nextest run --all-features --workspace` all pass
  before any handoff.
- Errors via `thiserror` (library boundaries) and `anyhow`/`eyre` (binary
  boundaries) with context. No naked `Box<dyn Error>`.
- `tracing` for all logs; never `println!` in production code paths.

## Repository conventions

- One Cargo workspace at the repo root. All crates live under `crates/`.
  Crate names prefixed `x0x-symphony-`.
- Binaries live in `crates/x0x-symphony-bin/`, not in lib crates.
- Each crate has a `README.md` that points back at the design doc.
- Integration tests live next to the crate they exercise; the
  cross-crate end-to-end test suite lives in `crates/x0x-symphony-bin/tests/`.
- `proofs/<issue-id>/<utc-timestamp>/` is reserved for validation
  artefacts produced by orchestrator runs; humans do not commit there.

## Milestone gate matrix

| Milestone | Gate                                                                                              |
|-----------|---------------------------------------------------------------------------------------------------|
| **M0**    | Architecture frozen. Four ADRs accepted. Repo bootstrapped. Issues seeded. ✅ Closed 2026-04-28.   |
| **M1**    | Single-host runner picks a `todo` issue, runs a configured runner inside an isolated workspace, writes a `review` handoff back. End-to-end smoke test green. |
| **M2**    | `shard` and `claim` are written by orchestrator. Heartbeat takeover proven by integration test with mocked clock. Validation artefact sink writes to `proofs/`. |
| **M3**    | Orchestrator runs end-to-end against `x0x_crdt` adapter on a live x0xd. `git_jsonl` adapter is deleted from the workspace. GUI board view renders symphony badges. |
| **M4**    | Two `x0x-symphonyd` instances on separate hosts coordinate work via gossip. Sandbox profile enforcement verified. Partition reunion test passes. |
| **M5**    | v0.1.0 published to crates.io. README quickstart works on a clean machine. CHANGELOG written. No `tracker/github*` or `tracker/git_jsonl*` files in the tree. |

Each milestone-complete event is a tagged release: `v0.0.M0`, `v0.0.M1`,
… `v0.1.0`.

---

## M1 — Local git_jsonl runner with full abstractions

**Goal:** prove the pattern end-to-end on a single host. The traits are
permanent; the JSONL adapter is throwaway. Runner pluggability is in
from day one (ADR-0001 is the contract).

### M1 crate layout

```
crates/
  x0x-symphony-core/                 # traits + types only
    src/lib.rs
    src/issue.rs
    src/claim.rs
    src/handoff.rs
    src/error.rs
    src/tracker.rs
    src/runner.rs
    src/workspace.rs
    src/workflow.rs
    Cargo.toml
  x0x-symphony-tracker-git-jsonl/    # bootstrap adapter (deleted at M3)
    src/lib.rs
    tests/round_trip.rs
    Cargo.toml
  x0x-symphony-runner-shell/         # canonical runner + presets
    src/lib.rs
    src/preset/codex.rs
    src/preset/claude_code.rs
    src/preset/kimi.rs
    src/preset/glm.rs
    src/preset/minimax.rs
    src/preset/pi.rs
    tests/run_smoke.rs
    Cargo.toml
  x0x-symphony-workspace/            # workspace manager + hooks
    src/lib.rs
    src/hooks.rs
    src/containment.rs
    tests/containment.rs
    Cargo.toml
  x0x-symphony-orchestrator/         # poll loop + dispatch + retry
    src/lib.rs
    src/dispatch.rs
    src/concurrency.rs
    src/retry.rs
    src/reconcile.rs
    tests/end_to_end.rs
    Cargo.toml
  x0x-symphony-bin/                  # daemon + CLI
    src/bin/x0x-symphonyd.rs
    src/bin/x0x-symphony.rs
    src/cli/{tasks,claim,handoff,status,proofs,config}.rs
    src/api.rs                        # local HTTP surface for the CLI
    tests/cli_smoke.rs
    Cargo.toml
```

### M1 issue inventory (already seeded as XSY-0002..0008)

| Issue     | Title                                                                  | Blocks    |
|-----------|------------------------------------------------------------------------|-----------|
| XSY-0002  | Define Tracker / Runner / Workspace traits as a runnable crate         | 0003–0007 |
| XSY-0003  | Implement git_jsonl Tracker adapter                                    | 0006      |
| XSY-0004  | Implement shell Runner with codex and claude_code presets              | 0006      |
| XSY-0005  | Workspace manager with hook execution and root containment             | 0006      |
| XSY-0006  | Orchestrator: poll loop, dispatch, concurrency, retry                  | 0007      |
| XSY-0007  | Daemon and CLI binaries (x0x-symphonyd, x0x-symphony)                  | 0008      |
| XSY-0008  | M1 operator and runner-authoring guides                                | (M1 gate) |

### M1 detail per issue

**XSY-0002 — Core traits.** Trait shapes are fixed by ADR-0001. Only
data types may be added without an ADR. Tests use stub impls. Crate
exposes nothing else. Deliver rustdoc on every public item with at
least one example per trait method.

**XSY-0003 — git_jsonl adapter.** Module-level doc explicitly notes
the M3 supersession. Use git index lock for serialization on a single
host. Implement `claim` / `heartbeat` with file-mtime fallback when
git is absent (ADR-0002 semantics still hold; only the persistence
medium differs). Round-trip integration test creates → claims →
heartbeats → hands off → moves to `review`. Schema violations produce
structured errors, never panics.

**XSY-0004 — shell runner.** The trait says `start_session` /
`run_turn` / `stream_events` / `stop_session`. The shell impl spawns a
child process configured by `RunnerSpec`, writes the rendered prompt
to stdin, streams stdout and stderr through tokio MPSC channels, and
captures exit + duration + minimal `UsageReport` (token estimates
optional). Hook timeout enforced via `tokio::time::timeout`, never
signals. Two preset configs (`codex`, `claude_code`) ship with tests
asserting the resolved command/args/env. The four other presets
(`kimi`, `glm`, `minimax`, `pi`) ship as configuration only —
expressible by an operator's WORKFLOW.md without code changes — but a
test asserts each preset YAML resolves to a runnable spec.

**XSY-0005 — Workspace manager.** Deterministic path under
`workspace.root`: `<root>/<sanitized-issue-id>/`. Sanitization
whitelist: `[A-Za-z0-9._-]`. Reject any input that contains `..`, a
leading `/`, or a symbolic component that resolves outside root. Hooks
(`after_create`, `before_run`, `after_run`, `before_remove`) execute
under `bash -e -u -o pipefail`, with timeout from
`hooks.timeout_ms`, env vars constrained to those declared in the
WORKFLOW.md plus a deny-list (no `*_TOKEN`, `*_KEY`, `*_SECRET`
unless explicitly allow-listed). Workspace preserved across retries;
deleted only on terminal states.

**XSY-0006 — Orchestrator.** Polls `Tracker::fetch_candidates` at
`polling.interval_ms`. Eligibility: state ∈ active_states, blockers
all terminal, claim free or owned by self with fresh heartbeat,
trust gate passes (M4 hardens this), capability gate passes (M4).
Concurrency caps from `agent.max_concurrent_agents` and
`agent.max_concurrent_agents_by_state`. Retry uses exponential
backoff (base 5 s, cap `agent.max_retry_backoff_ms`). Reconciliation
on startup: any in-progress claim owned by this agent is resumed
(heartbeat fresh) or released (stale). End-to-end smoke test:
seeded `todo` issue, stub runner emits a fake handoff, issue ends in
`review`. Mocked-clock test forces concurrency contention.

**XSY-0007 — Daemon + CLI.** `x0x-symphonyd` reads `WORKFLOW.md`,
loads adapters, runs the orchestrator, exposes a localhost HTTP
surface for the CLI (`/symphony/tasks`, `/symphony/status`,
`/symphony/events` SSE, plus PUT/POST verbs for claim/handoff
operations triggered manually). `x0x-symphony` CLI subcommands:
`tasks`, `claim`, `handoff`, `status`, `proofs {list,show}`,
`config {show,check}`, `routes`. Each subcommand has its own help
text and at least one snapshot-style integration test against a
stub daemon.

**XSY-0008 — M1 docs.** `docs/symphony/operator.md`:
prerequisites, configuring `WORKFLOW.md`, starting the daemon,
common operations (claim, abandon, inspect proofs), troubleshooting.
`docs/symphony/runner-authoring.md`: the `Runner` trait, the shell
runner contract, how to add a preset (config-only) and when to add
a bespoke runner (process protocol). Both reference the design doc
and ADRs rather than restating them. `docs/symphony/README.md` is
updated as the index. Obsidian vault is mirrored
(`Saorsa Labs/Projects/x0x-symphony/Docs/`).

### M1 cross-cutting tasks (XSY-0009..0012, see issues.jsonl)

- **XSY-0009 — CI**: GitHub Actions workflow that runs fmt, clippy,
  nextest, doc, and audit on push and PR. Mirrors x0x's `ci.yml`
  shape; no ant-quic / saorsa-gossip symlinks needed yet.
- **XSY-0010 — justfile recipes** filled in once crates exist
  (currently stubs).
- **XSY-0011 — release.yml** stub (multi-platform build matrix
  scaffolded; no publish until M5).
- **XSY-0012 — security.yml**: `cargo audit` daily on main.

### M1 risks

- **Hook isolation surprises.** Operators run untrusted runner
  commands inside the workspace. M1 keeps the trust model simple: the
  operator vouches for what they configure. M4 adds sandbox profiles.
  Document this loudly in the operator guide.
- **Claim semantics on git_jsonl.** Concurrent agents on one host hit
  the git index lock; the adapter must serialize, not panic. Cover
  with a multi-process integration test using a shared workspace.
- **Tokio channel back-pressure.** Streaming runner output through
  unbounded channels invites OOM on a chatty harness. Use bounded
  channels with explicit drop semantics; emit a `WARN` log when a
  channel is at high-water mark.

---

## M2 — Claim primitives + validation artefact sink

**Goal:** lock the data model that M3 will switch to CRDT. The shape
defined here is what symphony commits to forever; M3 only changes
*where* it lives.

### M2 issue inventory (XSY-0013..0018)

| Issue     | Title                                                                  |
|-----------|------------------------------------------------------------------------|
| XSY-0013  | Implement shard assignment at issue creation                           |
| XSY-0014  | Heartbeat writer + TTL takeover with mocked-clock tests                |
| XSY-0015  | Validation artefact sink: proofs/<issue>/<ts>/                         |
| XSY-0016  | Handoff writer: small status in handoff, links to proof dir            |
| XSY-0017  | Schema freeze: shard / claim / handoff fields documented and validated |
| XSY-0018  | Reconcile abandon-records on startup                                   |

### M2 detail

**XSY-0013 — Shard assignment.** `x0x-symphony issue new "title"`
computes `primary` and `backups` by XOR distance to `hash(task_id)`
across the *currently configured trusted-worker view*. In M2 this
view is a static list in `WORKFLOW.md` under `workers:` (a placeholder
that M4 replaces with live presence-based discovery). Shard fields
are written once; subsequent edits are rejected with a structured
error.

**XSY-0014 — Heartbeat + TTL.** Orchestrator background task refreshes
`claim.heartbeat_at` every `claim_ttl_ms / 4`. On startup, scan all
in-progress issues; for each one, if `claim.by == self_agent_id` and
heartbeat fresh, resume; if stale, release with reason
`expired_heartbeat`; if owned by another agent, leave alone unless
this agent is a backup AND TTL elapsed AND we want to claim.
Mocked-clock test demonstrates each branch.

**XSY-0015 — Proofs sink.** Every dispatch produces
`proofs/<issue>/<utc-ts>/` containing `manifest.json` (runner kind,
preset, command, args, env-allowlist used, exit code, duration,
agent_id, host hostname), `stdout.log`, `stderr.log`, and any files
the runner explicitly emits via a `RunnerArtifact` event. Manifest is
machine-readable. Proofs older than `retention.proofs_days` (default
30) are reaped by a background task; M2 ships the writer, the reaper
ships at M5.

**XSY-0016 — Handoff writer.** When the runner finishes successfully,
the orchestrator constructs a `Handoff` containing `summary`,
`files_changed` (from a `git diff --name-only` inside the workspace),
`validation` (from the configured validation commands' exit codes),
`follow_up` (from the runner's structured output if any), and
`proofs_dir` (relative path). Tracker writes the handoff and moves
state to `review`. ML-DSA-65 signatures over the handoff payload are
deferred to M3 (we do not have x0xd identities yet).

**XSY-0017 — Schema freeze.** `Issue` Rust struct mirrors
`issues/schema.md` exactly. JSONL adapter validates on read and write;
unknown fields are preserved verbatim. Property test asserts
round-trip stability. ADR-0001 referenced; if a new field is needed
later, that needs a superseding ADR.

**XSY-0018 — Abandon record reconciliation.** Implement the partition
reunion logic from ADR-0002 even though M2 is single-host: when the
orchestrator finds two valid claim records on the same issue, the
lower-index slot wins; the loser's claim transitions to an `abandon`
record (a sibling LWW field) citing the conflict. Unit-tested with
synthetic dual-claim records.

### M2 risks

- **Static `workers:` list is a footgun.** Document loudly that this
  is a placeholder; M4 replaces it with live discovery. Operators
  who edit by hand must understand a reshard is an explicit signed
  event, not a list edit.
- **Path reaper race with running orchestrator.** Reaper not in M2;
  noted to keep M2 scope tight.

---

## M3 — x0x_crdt tracker adapter

**Goal:** swap `git_jsonl` for `x0x_crdt`. Same Tracker trait, same
data model. Orchestrator code does not change.

### M3 issue inventory (XSY-0019..0024)

| Issue     | Title                                                                  |
|-----------|------------------------------------------------------------------------|
| XSY-0019  | Implement x0x_crdt Tracker adapter against x0xd REST/WS                |
| XSY-0020  | ML-DSA-65 signing + verification of claim and handoff payloads          |
| XSY-0021  | MLS-encrypted task-list dispatch (private project groups)               |
| XSY-0022  | Trust-gated dispatch using x0xd /agent + /contacts                      |
| XSY-0023  | x0x GUI board view: symphony filters and claim badges (PR to x0x)       |
| XSY-0024  | Delete tracker-git-jsonl crate; tag v0.0.M3                            |

### M3 detail

**XSY-0019 — x0x_crdt adapter.** New crate
`crates/x0x-symphony-tracker-x0x-crdt/`. Talks to `x0xd` over HTTP.
Reads candidates from `GET /task-lists/:id/tasks`, decodes each
TaskItem's checkbox + LWW metadata into an `Issue`. Claims by
`PATCH /task-lists/:id/tasks/:tid` with `action=claim` and a
metadata update carrying the signed claim record. Heartbeats by
metadata-only PATCHes. Handoffs by writing the small handoff into
metadata and any large blobs into a KvStore via `POST /stores/:id/:key`.
Subscribes to `WS /events` for live updates.

**XSY-0020 — Signing.** Symphony reads the daemon's agent identity
via `GET /agent` and signs claim and handoff payloads with the
operator's agent key — exposed via a thin signing endpoint on
`x0xd` (which already has the key). Signatures are verified on read;
mismatches drop the record with a `WARN` log. This depends on a
small x0xd-side endpoint (`POST /agent/sign`) — issue tracked in x0x
itself, not here, blocking XSY-0020.

**XSY-0021 — MLS dispatch.** Per-project task lists may be MLS
group-encrypted. Symphony resolves `WORKFLOW.md`'s `tracker.group`
field to an MLS group, joins on first dispatch, and uses the
group-scoped task list endpoint. Workers outside the group cannot
see or claim. Integration test: two daemons in different MLS groups
do not see each other's tasks.

**XSY-0022 — Trust gate.** Before dispatch, the orchestrator queries
x0xd's `GET /contacts/:agent_id` and rejects claims from agents whose
`TrustLevel < Trusted` for tasks labelled `security-sensitive`.
Configurable per project in `WORKFLOW.md`.

**XSY-0023 — GUI board view.** A small PR to **x0x repo** (not this
one) extends `renderSpaceBoard` in `src/gui/x0x-gui.html` to:
- read symphony metadata fields (`shard`, `claim`, `state`,
  `priority`, `labels`, `handoff.proofs_dir`) and render badges,
- group cards into columns by state (todo / in_progress / review /
  done) instead of just by checkbox state,
- expose a "symphony" filter toggle that hides non-symphony tasks.

This is intentionally a single PR to x0x, not a fork. The PR opens
on x0x with branch `symphony-board-view`.

**XSY-0024 — Delete git_jsonl.** Remove
`crates/x0x-symphony-tracker-git-jsonl/`. Update workspace
`Cargo.toml` and any references. Tag `v0.0.M3`. Update operator
guide to remove the JSONL section.

### M3 gate

End-to-end smoke against a real `x0xd`: start `x0xd`, start
`x0x-symphonyd`, create an issue via CLI, confirm it appears in
the GUI board view with a symphony badge, dispatch it, observe
handoff in the GUI. The `git_jsonl` crate directory is gone.

### M3 risks

- **x0xd surface gaps.** XSY-0020 needs `POST /agent/sign` on x0xd.
  Coordinate with x0x maintainers; track as an x0x issue blocking
  XSY-0020.
- **MLS group lifecycle.** Joining and leaving groups touches MLS
  key management. Lean on x0xd's existing primitives; do not
  re-implement in symphony.
- **GUI PR coordination.** XSY-0023 is a cross-repo deliverable.
  Coordinate the merge of the GUI PR with the symphony release tag.

---

## M4 — Distributed worker discovery + safety hardening

**Goal:** multi-host operation. Symphony becomes truly decentralized.

### M4 issue inventory (XSY-0025..0030)

| Issue     | Title                                                                  |
|-----------|------------------------------------------------------------------------|
| XSY-0025  | Worker advertisement on x0x/symphony/workers gossip topic              |
| XSY-0026  | Live trusted-worker view drives shard slate at issue creation          |
| XSY-0027  | Sandbox profiles (read-only, repo-write, no-network, full-dev, ci-only)|
| XSY-0028  | Sensitive-task gates: Pinned identity + human approval                  |
| XSY-0029  | Partition reunion stress test on a multi-host harness                   |
| XSY-0030  | Deprecate legacy codex: WORKFLOW.md block (warn + cutover plan)         |

### M4 detail

**XSY-0025 — Worker advertisement.** Each `x0x-symphonyd` publishes a
signed `WorkerCard` on `x0x/symphony/workers/v1` with capabilities,
sandbox levels supported, available runner presets, current load,
and platform info. Cards expire (TTL). Other daemons subscribe and
maintain a worker view.

**XSY-0026 — Live shard slate.** Replace M2's static `workers:` list
with the live worker view at issue creation. Records the current
view epoch on the task. Reshard remains an explicit operator action.

**XSY-0027 — Sandbox profiles.** The shell runner takes a `Sandbox`
parameter. Linux: `firejail` wrapper with profile per level. macOS:
`sandbox-exec` with profile. Other OS: refuse to run if profile is
non-trivial. Each profile mapped to a set of allowed syscalls /
filesystem paths / network reach. Documented in
`docs/symphony/security.md`.

**XSY-0028 — Sensitive-task gates.** Tasks labelled
`security-sensitive` require:
- claimer's `TrustLevel == Pinned` (per ADR-0002 plus x0x trust model),
- a human approval step recorded as a signed `ApprovalEvent` on the
  task; orchestrator refuses to dispatch without one.

**XSY-0029 — Partition stress test.** Two-host harness running
`x0x-symphonyd` separated by a configurable network partition. Test
sequence: create task, partition, both sides try to claim, observe
sharded ownership behaviour, heal partition, verify reunion produces
a correct outcome.

**XSY-0030 — Codex block deprecation.** WORKFLOW.md's legacy
`codex:` block emits a `WARN` on load. Operator guide explains the
cutover. Removed at M5.

### M4 risks

- **Sandbox portability.** macOS `sandbox-exec` is being deprecated
  by Apple. M4 ships what works; M5 may need to revisit.
- **Worker view churn.** Live workers join and leave constantly;
  the view epoch must be recorded on each task. Plan: only the
  *task* records the view at creation; the orchestrator keeps a
  continuously updated view for runtime dispatch.

---

## M5 — Cleanup + 1.0 release

**Goal:** zero external-tracker deps in shipping product. Public
release on crates.io. Operator-readable docs. Clean install path.

### M5 issue inventory (XSY-0031..0036)

| Issue     | Title                                                                  |
|-----------|------------------------------------------------------------------------|
| XSY-0031  | Remove legacy codex: WORKFLOW.md block; emit hard error on load         |
| XSY-0032  | Observability: x0x-symphony status, x0x-symphony workers, dashboards    |
| XSY-0033  | Proof-artefact reaper (retention.proofs_days)                           |
| XSY-0034  | README quickstart, CHANGELOG, operator guide polish                     |
| XSY-0035  | Publish to crates.io: x0x-symphony-core, all adapters, bin              |
| XSY-0036  | v0.1.0 release: tag, GitHub release, signed binaries via release.yml    |

### M5 release checklist

- [ ] No `tracker/github*` files in tree (never created).
- [ ] No `tracker/git_jsonl*` files in tree.
- [ ] WORKFLOW.md `runner:` block is the only runner config; legacy
      `codex:` block triggers a hard error on load.
- [ ] CI green on `main`. Audit clean.
- [ ] `cargo publish --dry-run` clean for all member crates.
- [ ] README quickstart verified on a clean macOS and Linux machine.
- [ ] CHANGELOG covers M0..M5.
- [ ] All ADRs marked Accepted with no pending Superseded markers.
- [ ] Obsidian vault `x0x-symphony` MOC reflects v0.1.0.
- [ ] `release.yml` produces signed binaries for the standard target
      matrix (mirrors x0x's matrix).

---

## Cross-cutting concerns

### Versioning

- Pre-1.0: `0.0.MN` after each milestone gate. `M1` → `v0.0.1`,
  `M2` → `v0.0.2`, etc.
- 1.0 release ships at the end of M5 as `v0.1.0`. Yes — the first
  shipping release is `0.1.0`, not `1.0.0`. The "1.0 invariants"
  language refers to *product* maturity, not semver.
- Public APIs of `x0x-symphony-core` follow strict semver from
  `v0.1.0` onward. Trait shape changes need a superseding ADR and
  a major version bump.

### CI

- `.github/workflows/ci.yml` — fmt, clippy, nextest, doc, audit. Runs
  on push and PR.
- `.github/workflows/security.yml` — daily `cargo audit` on `main`.
- `.github/workflows/release.yml` — multi-platform builds and signed
  artefacts on tag push (M5).

### Test strategy

- **Unit tests** in each crate's `src/`, covering pure logic.
- **Integration tests** in each crate's `tests/`, covering adapter
  round-trips and crate-level flows.
- **End-to-end tests** in `crates/x0x-symphony-bin/tests/`, covering
  CLI ↔ daemon ↔ orchestrator ↔ tracker ↔ runner flows. Mocked
  external surfaces (a fake `x0xd`) by default; a separate `--live`
  test profile runs against a real `x0xd`.
- **Property tests** for serialization round-trips and CRDT-like
  reconciliation logic (proptest).
- **Mocked-clock tests** for heartbeat and TTL logic
  (`tokio::time::pause`).

### Documentation discipline

- Every issue that adds or changes public behaviour updates a doc in
  the same handoff. Reviewers reject doc-less behaviour changes.
- Architecture-level changes always raise a new ADR. The four M0
  ADRs are the foundation; any structural pivot inherits or
  supersedes them.
- Obsidian vault is mirrored when any docs in `docs/` change.

### Cross-repo coordination

- **x0x repo dependencies:**
  - `POST /agent/sign` endpoint (M3, blocks XSY-0020) — track as an
    x0x issue and block release of XSY-0020 on its merge.
  - GUI board view PR (M3, XSY-0023) — opens against x0x, merges
    coordinated with symphony's M3 release.
- **No symbolic links between repos.** `x0x-symphony` reaches `x0xd`
  over HTTP only; no Cargo path dependency on x0x.

### Branching strategy

- `main` is always green. All work via short-lived branches and PRs.
- Branch names: `xsy-NNNN-short-slug`.
- One issue per PR. Multi-issue PRs require an explicit reason.
- PRs need at least one human review before merge until M3 ships;
  after that, multi-agent reviews via `/ultrareview` are acceptable
  on bounded scope changes.

### Definition of done (per issue)

An issue may be moved to `review` only when ALL of:

1. Acceptance criteria in the issue record are met.
2. `just check` passes locally (fmt + lint + test + doc, all
   `-D warnings`).
3. Documentation introduced or changed by this issue is committed.
4. Handoff payload is filled in: summary, files_changed, validation,
   follow_up, proofs_dir.
5. The PR is open with the issue identifier in the title.

A human moves issues from `review` to `done`.

---

## Open questions for the team to lock by M2

These were left intentionally open at M0:

1. **Branch / PR push.** Do workers push branches and open PRs
   themselves, or only emit signed patches? Lean: emit patches
   in M2; revisit pushing in M4.
2. **Cross-repo dispatch.** A symphony task may need a coordinated
   change in `ant-quic`. Modelled as `blocked_by` across separate
   TaskLists with a shared metadata link, or as a single multi-repo
   issue with multiple workspace roots? Lean: linked TaskLists in
   M2; multi-workspace in M4 if demand.
3. **Reshard policy.** When and how an operator may rewrite an
   existing task's shard slate. Lean: explicit signed `Reshard`
   event with reason, owner, and timestamp.
4. **Runner attestation.** Whether a runner emits a signed report of
   binary version, model, tools used. Lean: yes, written into the
   handoff as `runner_attestation` from M3.

Each answer becomes an ADR or a tracked decision in `issues.jsonl`
before M2 gate.

---

## Appendix A — full issue dependency graph

```
M0:  XSY-0001 (review)
M1:  0002 → 0003,0004,0005 → 0006 → 0007 → 0008
              0009,0010,0011,0012 (cross-cutting CI)
M2:  0013 → 0014,0015,0016 → 0017 → 0018
M3:  0019 → 0020 (blocked on x0x: POST /agent/sign)
              0021 (MLS) ← needs 0019,0020
              0022 (trust) ← needs 0019
              0023 (GUI PR to x0x) ← parallel
              0024 (delete git_jsonl) ← M3 gate
M4:  0025 → 0026 (live view) ← needs 0025
              0027 (sandbox) ← independent
              0028 (sensitive gates) ← needs 0022,0027
              0029 (partition stress) ← needs 0026
              0030 (codex deprecate) ← independent
M5:  0031,0032,0033,0034 → 0035 → 0036 (v0.1.0)
```

## Appendix B — release tag plan

| Tag         | Lands                          | Approx. issue count |
|-------------|--------------------------------|---------------------|
| `v0.0.0`    | M0 (this commit)               | 1                   |
| `v0.0.1`    | M1 gate                        | 11 (0002–0012)      |
| `v0.0.2`    | M2 gate                        | 6 (0013–0018)       |
| `v0.0.3`    | M3 gate                        | 6 (0019–0024)       |
| `v0.0.4`    | M4 gate                        | 6 (0025–0030)       |
| `v0.1.0`    | M5 gate (public release)       | 6 (0031–0036)       |

## Appendix C — what is *not* in v1.0

These are explicitly out of scope for v0.1.0 and parked for later
review. Listed here so reviewers don't think they were forgotten:

- A GitHub Issues adapter (rejected, ADR-0003).
- A Linear adapter (rejected by the project's first principles).
- A web dashboard separate from x0x's GUI board view.
- A built-in PR-pushing flow (M4 considers it).
- Cross-repo task graphs (handled via linked TaskLists in M3+).
- A graphical workflow builder.
- A general-purpose CI replacement.
- Convergence with `communitas-kanban` into a shared
  `saorsa-kanban` crate (future work, see
  `docs/design/saorsa-kanban-convergence.md`).
