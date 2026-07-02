# x0x-symphony — M3 Execution Plan (2026-07)

## 1. M2 close state

M2 is closed at `v0.0.M2`. All Wave A/B/C issues are `done`:
schema freeze v1, lifecycle hooks, shard assignment, heartbeat/TTL takeover,
proof artefact sink, handoff enrichment, startup reconcile abandon proofs,
sandbox Tier 1 (+ C1–C4 trait reshape), orphan sweep, ML-DSA-65 signing.

**Test count**: 147/147. **`just check`**: green. **`#[allow]`**: 1 (async_fn_in_trait).

### Disclosed M2 boundaries (from v0.0.M2 tag annotation)

1. **Signing is local-signer-only.** Verification proves records were signed by
   *this daemon's own* x0xd key. It does not yet establish trust in network agents.
   Network trust anchoring is M3 work (XSY-0022 / XSY-0039).

2. **Signing ships off by default.** Operators set `signing.policy = required`
   to get claim/handoff signing protection.

**Network-sourced dispatch remains default-off through M2.**

## 2. M3 goal and definition of done

**Goal.** Replace the file-based git-jsonl tracker with a live `x0x_crdt`
adapter against x0xd's REST API; establish the network trust anchor
(verified signature + trust level); enforce the dispatch gate on
network-sourced issues; then retire git-jsonl.

**Definition of done (M3).** `x0x_crdt` adapter is live against x0xd and
passes a round-trip integration test; XSY-0039 hard gate passes (network-sourced
dispatch provably cannot execute without verified signature + trust); git-jsonl
is deleted (XSY-0024); `v0.0.M3` tagged with annotation naming disclosed boundaries.

## 3. Ordered path

```
XSY-0019  x0x_crdt Tracker adapter against x0xd REST API
    │
    ├── XSY-0043  distinguish verify-transport-failure from signature-invalid  (M3 BLOCKER)
    ├── XSY-0044  live x0xd /agent/sign + /agent/verify round-trip test         (M3 BLOCKER)
    │
XSY-0022  Trust-gated dispatch using x0xd /agent + /contacts
    │
XSY-0039  HARD GATE: dispatch gate — no execution of network-sourced issues
    │      without verified signature + trust level
    │      (cannot start until XSY-0043 + XSY-0044 closed and audited)
    │
    ├── XSY-0021  MLS-encrypted task-list dispatch (private project comms)
    ├── XSY-0023  x0x GUI board view: symphony filters and claim badges
    │
XSY-0024  Delete tracker-git-jsonl crate; tag v0.0.M3
```

### Hard gates (stop and wait for explicit sign-off)

| Gate | Issue | Criteria |
|------|-------|----------|
| **0039** | M3 dispatch gate | Network-sourced issue provably never dispatched without verified signature + trust level. Integration test + transcript. Audited against XSY-0043 + XSY-0044 prerequisites. |

### M3 blockers on XSY-0039 (cannot flip network dispatch on until both close)

| Issue | Title | Why it blocks |
|-------|-------|---------------|
| **XSY-0043** | Distinguish verify-transport-failure from signature-invalid | x0xd-down must surface as error/degraded-state, never a silent per-issue drop that reads as "no work" |
| **XSY-0044** | Live x0xd sign/verify round-trip integration test | The all-mock suite cannot catch DST/wire drift; drift means production silently drops the entire queue |

### Lower findings (noted, non-blocking for M3-network-off)

| Issue | Title | Notes |
|-------|-------|-------|
| XSY-0045 | Unsigned/invalid claim hides the whole issue | Matters once records are network-sourced; track alongside 0039 |
| XSY-0046 | Additive-schema-vs-signature survival test | Converts deductive argument into a regression guard |

## 4. Standing rules (continuous-run mode)

- **No pausing between waves or milestones** (user directive).
- **Session-lead audit replaces inter-wave approval** — except hard gates.
- **Two hard gates stop and wait**: XSY-0039 (dispatch gate).
- **Network-sourced dispatch stays default-off** through M3 until 0039 passes.
- **Foreground parallel for all builder dispatches** (async stalls on complex prompts).
- **Direct-to-main pattern** (no PRs). Agents set `review`; lead closes to `done`.
- **Lint deny-set immutable**: `unsafe_code = "forbid"`; no unwrap/expect/panic/todo/unimplemented.
