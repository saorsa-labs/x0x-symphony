# x0x-symphony — M1 Execution Plan (2026-07)

**Status:** Ready for team execution.
**Companions:** [`../design/symphony.md`](../design/symphony.md) (architecture, authoritative),
[`implementation-plan.md`](implementation-plan.md) (full M1–M5 plan, 2026-04-28),
ADRs 0001–0004 in [`../adr/`](../adr/).

This document turns the M1 section of the implementation plan into an
executable work package for a team, incorporating the 2026-07-02
production-readiness review findings. Where this plan and the
implementation plan disagree, **this plan wins for M1 execution**; where
either disagrees with the architecture, the architecture wins — raise an
ADR.

---

## 1. Honest current state (2026-07-02 review)

- **M0 is frozen and good.** Architecture doc, 4 accepted ADRs, seeded
  backlog, CI, justfile.
- **Implementation is ~5%.** Of 36 issues: 2 `done` (XSY-0002 core
  traits, XSY-0010 justfile), 2 `review` (XSY-0001 bootstrap docs,
  XSY-0009 CI), 2 `blocked`, 30 `todo`.
- **Only one crate exists** (`x0x-symphony-core`, v0.0.0): trait/type
  definitions plus one stub round-trip test. It is high quality — strict
  lints (`unsafe` forbidden; `unwrap`/`expect`/`panic`/`todo`/
  `unimplemented` denied), full rustdoc, clean fmt/clippy/audit.
- **No runtime component exists**: no tracker adapter, runner, workspace
  manager, orchestrator, binaries, HTTP client, signing, or sandboxing.
- **Known security hole in example code:** the `Workspace` rustdoc stub
  does raw `self.root.join(issue.identifier.as_str())`
  (`crates/x0x-symphony-core/src/workspace.rs:257`) with no
  sanitization. Real implementations MUST NOT copy the stub; §4.1 below
  is mandatory.
- **Stale metadata:** `blocked_by` entries embed a snapshot `state`
  (e.g. XSY-0003 lists XSY-0002 as `todo` though it is `done`). See §8.

## 2. M1 goal and definition of done

**Goal:** the M1 vertical slice — on a single host, `x0x-symphonyd`
picks a `todo` issue from `issues/issues.jsonl`, runs a configured
runner inside a contained workspace, and writes a `review` handoff back
— with the two security controls the design already specifies (path
containment, env allow-list) landing **with** their components, not
later.

**Definition of done (the demo script).** From a clean checkout:

```bash
just check                                   # fmt, clippy -D warnings, nextest, doc — all green
cargo run --bin x0x-symphonyd -- --config WORKFLOW.md &   # daemon starts, loads config, polls
x0x-symphony tasks                           # lists the seeded backlog
# seed a demo todo issue whose runner is a stub shell script
x0x-symphony status                          # shows the claim appear, heartbeat fresh
# ... daemon dispatches: workspace created under workspace.root/<sanitized-id>/,
#     hooks run with timeouts, runner executes, handoff written ...
x0x-symphony tasks --state review            # demo issue is now in review with a handoff
git log --oneline issues/issues.jsonl        # shows the claim + handoff commits
```

Plus: the containment test suite (§4.1) passes; killing the daemon
mid-run and restarting it resumes-or-releases the claim (§5); tag
`v0.0.M1` is cut.

## 3. Work packages (per-issue)

All packages inherit the standards in `implementation-plan.md` ("Coding
and quality standards"): zero warnings, no production
`unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!` (the workspace lint
table already denies them — keep it), `thiserror` at library
boundaries, `tracing` not `println!`, rustdoc on every public item,
`just check` green before every handoff.

### WP-1 · XSY-0003 — git_jsonl Tracker adapter — **M (3–5 d)**

- **Crate:** `crates/x0x-symphony-tracker-git-jsonl` implementing
  `x0x_symphony_core::Tracker` against `issues/issues.jsonl`.
  Module-level doc states the M1–M2 lifespan and points at ADR-0003
  (deleted at M3 by XSY-0024).
- **Design:** one JSON object per line; state changes rewrite the
  issue's line and `git commit` the diff. Serialization on a single
  host via the git index lock; file-mtime fallback when git is absent
  (ADR-0002 semantics unchanged, only the persistence medium differs).
  Deterministic ID allocation (`XSY-` + zero-padded max+1). Unknown
  fields preserved verbatim on rewrite (forward-compat with M2 `shard`/
  `claim`/`handoff` extensions). Schema validation on read returns
  structured `TrackerError::Schema { line, reason }` — never panics,
  never silently skips (log WARN with line number, surface a count).
- **Tasks:** (1) read/parse/validate + preserve-unknown round-trip;
  (2) `fetch_candidates` honoring state + `blocked_by` terminality;
  (3) `claim`/`heartbeat`/`release`/`handoff` transitions with git
  commit per transition; (4) concurrency: two processes on one host
  contend on the index lock — serialize with bounded retry + backoff,
  structured error on exhaustion; (5) multi-process integration test
  for (4); round-trip test create → claim → heartbeat → handoff →
  `review`.
- **Acceptance:** as seeded in XSY-0003, plus: property test that
  parse→serialize is byte-stable for unknown fields; the stale
  `blocked_by.state` snapshot problem (§8) is handled by **always
  resolving blocker state live by id**, never trusting the embedded
  snapshot.
- **Depends on:** XSY-0002 (done). **Blocks:** XSY-0006.

### WP-2 · XSY-0004 — shell Runner + presets — **M (3–5 d)**

- **Crate:** `crates/x0x-symphony-runner-shell` implementing `Runner`.
  Spawns the configured child process, rendered prompt on stdin,
  streams stdout/stderr, captures exit + duration + minimal
  `UsageReport`.
- **Design constraints (hard):**
  - Command + args come from `RunnerSpec` resolved from WORKFLOW.md.
    **Never through a shell** — `tokio::process::Command` with argv
    array. No string interpolation of issue fields into argv; the
    issue content travels only via stdin (the prompt) and the
    workspace. This is the command-injection boundary.
  - Env: start from **empty**, add only WORKFLOW.md-declared vars,
    enforce the deny-list (`*_TOKEN`, `*_KEY`, `*_SECRET` unless
    explicitly allow-listed) — same rule as workspace hooks (§4.1).
  - Streaming through **bounded** tokio mpsc channels with explicit
    drop-oldest or backpressure semantics + WARN at high-water mark
    (implementation-plan "M1 risks": unbounded channels invite OOM).
  - Timeouts via `tokio::time::timeout`, never signals; on timeout,
    kill the process group (child may have forked).
- **Presets:** `codex` and `claude_code` ship with tests asserting
  resolved command/args/env; `kimi`/`glm`/`minimax`/`pi` are
  config-only with a test per preset that the YAML resolves to a
  runnable spec.
- **Acceptance:** as seeded, plus: a test proving a chatty child
  (yes-style output) does not grow memory unboundedly; a test proving
  a hung child is killed at timeout including its children.
- **Depends on:** XSY-0002 (done). **Blocks:** XSY-0006.

### WP-3 · XSY-0005 — Workspace manager (SECURITY-CRITICAL) — **M (3–5 d)**

- **Crate:** `crates/x0x-symphony-workspace` with `src/containment.rs`
  as the dedicated, heavily-tested module. Full spec in §4.1 — path
  containment and ID sanitization land **in this PR**, not later.
- **Design:** deterministic path `<workspace.root>/<sanitized-id>/`;
  hooks (`after_create`, `before_run`, `after_run`, `before_remove`)
  under `bash -e -u -o pipefail` with `hooks.timeout_ms` and the env
  allow-list/deny-list; workspaces preserved across retries, deleted
  only on terminal states; `destroy()` refuses to remove any path that
  fails containment re-validation (defense against config changes
  between create and destroy).
- **Acceptance:** as seeded, plus the §4.1 adversarial test matrix.
- **Depends on:** XSY-0002 (done). **Blocks:** XSY-0006.

### WP-4 · XSY-0006 — Orchestrator — **L (5–8 d)**

- **Crate:** `crates/x0x-symphony-orchestrator` with `dispatch.rs`,
  `concurrency.rs`, `retry.rs`, `reconcile.rs`.
- **Design:** poll loop at `polling.interval_ms`; eligibility gate
  (state ∈ active, blockers terminal — resolved live, claim free or
  self-owned-fresh); concurrency caps
  (`agent.max_concurrent_agents`, per-state caps); retry with
  exponential backoff base 5 s capped at `agent.max_retry_backoff_ms`
  and a **max-attempts cap** (gap in the seeded acceptance — backoff
  alone is not enough; after N attempts move the issue to `blocked`
  with a structured reason); startup reconciliation (§5); heartbeat
  task at `claim_ttl / 4`; graceful shutdown — on SIGINT/SIGTERM stop
  claiming, let in-flight runs finish up to a bounded grace period,
  then release claims with reason `shutdown` (mirrors x0x's shutdown
  discipline).
- **Acceptance:** as seeded (end-to-end smoke with stub runner,
  contention test, mocked-clock reconciliation, no production panics),
  plus: retry-exhaustion test; shutdown-mid-run test proving the claim
  is released and the workspace preserved.
- **Depends on:** WP-1, WP-2, WP-3. **Blocks:** XSY-0007.

### WP-5 · XSY-0007 — Daemon + CLI binaries — **L (5–8 d)**

- **Crate:** `crates/x0x-symphony-bin`: `x0x-symphonyd` (loads
  WORKFLOW.md, runs orchestrator, serves localhost HTTP:
  `/symphony/tasks`, `/symphony/status`, `/symphony/events` SSE, claim/
  handoff verbs) and `x0x-symphony` CLI (`tasks`, `claim`, `handoff`,
  `status`, `proofs {list,show}`, `config {show,check}`, `routes`).
- **Design constraints:** bind `127.0.0.1` only; ephemeral port +
  port-file, or fixed port from config — follow x0x's pattern
  (loopback + bearer token file `0600`) rather than an unauthenticated
  local API; x0x's `src/server/mod.rs` `auth_middleware` +
  `load_or_generate_api_token` are the reference implementation.
  `config check` validates WORKFLOW.md fully (all required keys from
  design §8) and exits non-zero on any missing/invalid key.
- **Acceptance:** as seeded, plus: snapshot-style integration test per
  subcommand against a stub daemon; auth-required test (request
  without token → 401).
- **Depends on:** WP-4. **Blocks:** XSY-0008, M1 gate.

### WP-6 · XSY-0008 — Operator + runner-authoring guides — **S (1–2 d)**

As seeded: `docs/symphony/operator.md`,
`docs/symphony/runner-authoring.md`, index update, Obsidian vault sync.
Must include the **interim security posture** section (§4.3) verbatim
or by reference. **Depends on:** WP-5.

### WP-7 · Cross-cutting: XSY-0009 / 0011 / 0012 — **S each**

- **XSY-0009 (CI)** is in `review`: a maintainer verifies the 3 jobs
  (just check, doc-test, cargo-audit) and flips to `done`.
- **XSY-0011 (release.yml stub):** tag-push trigger, x0x-matching
  matrix, cargo-zigbuild for Linux, **no publish jobs**. Dry-runnable
  on a test tag. Parallel to everything.
- **XSY-0012 (security.yml):** daily 06:00 UTC + PR cargo-audit.
  Parallel to everything.

## 4. Security-first requirements (pulled forward from the review)

### 4.1 Path containment + ID sanitization (lands with WP-3, non-negotiable)

The review's top finding: the only workspace code in the repo today is
the unsanitized stub. The real implementation must:

1. Sanitize issue identifiers against the whitelist `[A-Za-z0-9._-]`;
   reject (structured error, never "fix up") any identifier containing
   other bytes, any `..` sequence, a leading `.`, a leading `/`, or an
   empty result.
2. After joining, **canonicalize and verify prefix**: the resolved
   workspace path must start with the canonicalized `workspace.root`.
   Symlinked components that escape the root are rejected at creation
   AND re-checked at destroy.
3. Adversarial test matrix (in `tests/containment.rs`, all must fail
   closed): `../../etc`, `a/../../b`, absolute paths, identifiers with
   `/` or NUL or unicode normalization tricks (`．．`), a pre-planted
   symlink inside root pointing outside, root itself as identifier,
   4096-byte identifiers.
4. Hook env: constructed from empty + allow-list + deny-list
   (`*_TOKEN`/`*_KEY`/`*_SECRET` blocked unless explicitly
   allow-listed). A test asserts a poisoned parent environment does
   not leak through.

### 4.2 Signing (XSY-0020) — unblock path and hard gate

- **What blocks it:** the cross-repo dependency `x0x:agent-sign-endpoint`
  — symphony needs x0xd to sign payloads with the agent key it holds
  (`POST /agent/sign`). x0x already ships the verify half:
  **stateless `GET/POST /agent/verify` since x0x v0.23.1** (PR #109).
- **Unblock action — DONE 2026-07-02:** filed as
  [saorsa-labs/x0x#133](https://github.com/saorsa-labs/x0x/issues/133)
  (`POST /agent/sign`: localhost + bearer-token protected, mandatory
  domain-separation context, 64 KiB payload cap; response = ML-DSA-65
  signature + agent_id). It is scheduled as WS1.9 (size S, no
  dependencies) in x0x's 2026-07 workplan, so it ships well before
  symphony's M3 needs it. Remaining action: link x0x#133 from
  XSY-0020's `blocked_by`.
- **Hard gate (new, from the review):** the orchestrator must never
  execute **network-sourced** work without a verified signature and a
  passing trust gate. Concretely: the `x0x_crdt` adapter (XSY-0019)
  may land read/list support independently, but its **dispatch/execute
  path must be gated on XSY-0020 (verification) + XSY-0022 (trust)**
  being wired. Proposed as new gate issue XSY-0039 (appendix A) so the
  ordering is tracker-enforced, not tribal knowledge.
- M1 is not exposed: the git_jsonl tracker only reads the local
  operator-controlled repo. State this in the docs anyway (§4.3).

### 4.3 Interim security posture (until XSY-0027 sandbox profiles, M4)

To be stated verbatim in `docs/symphony/operator.md` and the new
`docs/symphony/security.md` (appendix A, XSY-0038):

> Until sandbox profiles land (M4), a runner is a child process with
> repo-write and network access, contained only by workspace pathing.
> Therefore: (1) x0x-symphony executes **only** issues from the local
> git-committed backlog that the operator controls — no network-sourced
> work is dispatched before M3, and at M3 dispatch is hard-gated on
> signature verification + trust level (XSY-0039); (2) hook and runner
> environments are allow-list only, secrets deny-listed by default;
> (3) the operator vouches for every command configured in WORKFLOW.md
> — treat it with the same care as CI config; (4) tasks labelled
> `security-sensitive` are refused outright until XSY-0028.

## 5. Resilience requirements → issue mapping

| Requirement | Where it lands | Status |
|---|---|---|
| Startup reconciliation (resume fresh / release stale claims) | XSY-0006 (M1); extended by XSY-0014/0018 (M2) | seeded |
| Harness run timeouts (incl. process-group kill) | XSY-0004 | seeded; PG-kill added by this plan |
| Hook timeouts | XSY-0005 | seeded |
| Bounded output streaming (OOM guard) | XSY-0004 | risk noted in impl-plan; promoted to acceptance here |
| Retry backoff **with attempts cap** | XSY-0006 | gap — added by this plan |
| Graceful shutdown (release claims, preserve workspaces) | XSY-0006/0007 | gap — added by this plan |
| Orphan-workspace sweep on startup (crash leaves dirs with no claim) | **gap** → new XSY-0037 (M2, appendix A) | new |
| x0xd-unavailable behavior | not an M1 concern (no x0xd dependency until M3); acceptance criterion to add to XSY-0019: poll loop backs off and does not busy-spin or crash when x0xd is down | note on XSY-0019 |
| Workspace cleanup only on terminal states | XSY-0005 | seeded |

## 6. Sequencing and assignment

```
        ┌── WP-1 XSY-0003 tracker ──┐
XSY-0002├── WP-2 XSY-0004 runner  ──┼─► WP-4 XSY-0006 orchestrator ─► WP-5 XSY-0007 bin ─► WP-6 XSY-0008 docs ─► M1 gate
 (done) └── WP-3 XSY-0005 workspace┘
WP-7 (XSY-0009 review-close, XSY-0011, XSY-0012)  — fully parallel at any time
x0x-side: POST /agent/sign = x0x#133 (filed)       — WS1.9 in x0x workplan (unblocks XSY-0020 for M3)
```

- **Wave 1 (parallel, 3 engineers/agents):** WP-1, WP-2, WP-3. Each is
  an independent crate against the frozen core traits. WP-3 goes to
  the strongest security reviewer pairing.
- **Wave 2:** WP-4 (can start its `reconcile.rs`/`retry.rs` scaffolding
  against stub trait impls while wave 1 finishes; integration last).
- **Wave 3:** WP-5, then WP-6. WP-7 anytime.
- Critical path: WP-3/WP-1 → WP-4 → WP-5 → WP-6 ≈ 3–4 weeks with a
  3-person wave 1.

## 7. Review protocol

1. One PR per work package (small follow-ups allowed). PR description
   links the XSY id and quotes its acceptance criteria as a checklist.
2. The session lead (review owner) reviews every PR **against this
   plan**: acceptance criteria, the §4 security requirements, and the
   inherited standards. WP-3 additionally gets an adversarial review
   pass focused solely on `containment.rs` (attempt to construct an
   escaping path).
3. Lints stay strict: the workspace `Cargo.toml` deny-set
   (`unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`,
   `unsafe_code=forbid`) must not be weakened; any `#[allow]` needs a
   comment and reviewer sign-off.
4. Every PR: `just check` green (CI enforces fmt, clippy `-D warnings`,
   nextest, doc, audit). No `#[ignore]` without a linked issue.
5. Handoffs update `issues/issues.jsonl` state in the same PR
   (dogfooding the tracker the moment WP-1 merges).
6. Milestone close: demo script (§2) executed and its transcript
   committed under `proofs/`, tag `v0.0.M1`.

## 8. Recommended JSONL/tracker corrections (maintainer action, not applied here)

1. **Stale `blocked_by` snapshots:** entries embed `state` at write
   time (XSY-0003/0004/0005 list XSY-0002 as `todo`; it is `done`).
   Either refresh the snapshots or (better) treat embedded state as
   advisory-only — WP-1 implements live resolution; schema.md should
   say so.
2. **Close out `review` items:** XSY-0001 and XSY-0009 have been in
   `review` since 2026-04-28; a maintainer should verify and flip to
   `done` (CI is observably green).
3. **Maturity labeling:** README says "Pre-1.0"; recommend "pre-M1
   (design frozen, core traits only)" until the M1 gate passes — the
   review found the current label oversells.
4. **Append the three new issues** from appendix A.

## Appendix A — proposed new issues (schema-compliant, ready to append)

```jsonl
{"id":"XSY-0037","identifier":"XSY-0037","title":"Startup orphan-workspace sweep","description":"On daemon startup, scan workspace.root for directories whose sanitized name matches no live claim owned by this agent. A crash between workspace creation and claim release leaves orphans. Policy: preserve directories matching an issue in a non-terminal state (retry semantics); move directories for terminal/unknown issues to a quarantine dir (workspace.root/.orphaned/<ts>/) rather than deleting; log a WARN summary. Containment re-validation applies to every path touched.","priority":2,"state":"todo","branch_name":null,"url":null,"labels":["x0x-symphony","milestone-m2","workspace","resilience"],"blocked_by":[{"id":"XSY-0005","identifier":"XSY-0005","state":"todo"},{"id":"XSY-0006","identifier":"XSY-0006","state":"todo"}],"created_at":"2026-07-02T00:00:00Z","updated_at":"2026-07-02T00:00:00Z","acceptance":["Sweep runs once at startup before the poll loop","Orphans quarantined, never rm -rf'd, with WARN log","Non-terminal-state workspaces preserved untouched","Containment re-validation on every touched path; escaping paths refused and reported"],"validation":["just fmt-check","just lint","just test"]}
{"id":"XSY-0038","identifier":"XSY-0038","title":"docs/symphony/security.md: interim security posture (pre-sandbox)","description":"Write the interim security posture doc required by the 2026-07 M1 execution plan §4.3: runner = unsandboxed child process until M4; local-backlog-only execution before M3; M3 dispatch hard-gated on signature verification + trust (XSY-0039); env allow-list/deny-list rules; operator vouches for WORKFLOW.md commands; security-sensitive label refused until XSY-0028. XSY-0027 later extends this same file with sandbox profile mapping.","priority":1,"state":"todo","branch_name":null,"url":null,"labels":["x0x-symphony","milestone-m1","security","docs"],"blocked_by":[],"created_at":"2026-07-02T00:00:00Z","updated_at":"2026-07-02T00:00:00Z","acceptance":["docs/symphony/security.md exists and states the four interim rules from the plan","operator.md links to it","Obsidian vault synced"],"validation":["Manual review against plan §4.3"]}
{"id":"XSY-0039","identifier":"XSY-0039","title":"M3 dispatch gate: no execution of network-sourced issues without verified signature + trust","description":"Tracker-enforced ordering for the review's hard gate: the x0x_crdt adapter (XSY-0019) may ship read/list support, but the orchestrator's execute path for issues sourced from x0xd MUST be gated on XSY-0020 (ML-DSA verification of claim/handoff, drop-with-WARN on mismatch) and XSY-0022 (trust-gated dispatch). Until both are wired, network-sourced issues are listed but refused for dispatch with a structured reason. Integration test proves an unsigned or untrusted issue is never executed.","priority":1,"state":"todo","branch_name":null,"url":null,"labels":["x0x-symphony","milestone-m3","security","gate"],"blocked_by":[{"id":"XSY-0019","identifier":"XSY-0019","state":"todo"},{"id":"XSY-0020","identifier":"XSY-0020","state":"blocked"},{"id":"XSY-0022","identifier":"XSY-0022","state":"todo"}],"created_at":"2026-07-02T00:00:00Z","updated_at":"2026-07-02T00:00:00Z","acceptance":["Execute path refuses network-sourced issues lacking verified signature or trust","Refusal is a structured, observable event (status + logs)","Integration test: unsigned issue listed but never dispatched","Gate removal requires this issue done, referenced in the PR"],"validation":["just fmt-check","just lint","just test"]}
```

Cross-repo status: the x0x sign endpoint is filed as
[saorsa-labs/x0x#133](https://github.com/saorsa-labs/x0x/issues/133)
(the verify half `/agent/verify` exists since v0.23.1). Remaining
maintainer action: link x0x#133 from XSY-0020's `blocked_by`
(`x0x:agent-sign-endpoint`).
