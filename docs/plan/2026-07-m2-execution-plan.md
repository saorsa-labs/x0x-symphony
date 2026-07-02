# x0x-symphony — M2 Execution Plan (2026-07)

**Status:** In execution (continuous run to release-ready).
**Companions:** [`../design/symphony.md`](../design/symphony.md) (architecture, authoritative),
[`2026-07-m1-execution-plan.md`](2026-07-m1-execution-plan.md) (M1, **done** — `v0.0.M1` tagged),
[`implementation-plan.md`](implementation-plan.md) (full M1–M5 plan, 2026-04-28),
ADRs 0001–0004 in [`../adr/`](../adr/).

This document turns the M2 milestone into an executable wave breakdown. Where
this plan and `implementation-plan.md` disagree, **this plan wins for M2
execution**; where either disagrees with the architecture, the architecture
wins — raise an ADR.

## 1. Honest current state (post-M1, 2026-07-02)

- **`v0.0.M1` is tagged at `997bbe0`** (CI-green). All M1 implementation issues
  are `done`. Windows portability fix landed at `f57273b` (`Child` import
  ungated; `windows-latest` compile-gate job in CI; verified 3 ways).
- **6 crates ship**: `-core`, `-tracker-git-jsonl`, `-runner-shell`,
  `-workspace`, `-orchestrator`, `-bin`. 71→72 tests, clippy `-D warnings`
  clean, doc clean, fmt clean. Lint deny-set immutable throughout.
- **M1 is real, not demo-grade**: the daemon runs the §2 lifecycle
  (todo→claim→run→review) end-to-end against a live git_jsonl tracker, with
  concurrency cap, retry-with-attempts-cap, reconcile-on-restart, and
  process-group hook kills. Two M1 boundaries are **disclosed and tracked**:
  (1) lifecycle hooks are **validated but not executed** by dispatch (XSY-0041);
  (2) gate transcripts are curated command logs; SIGKILL-stale recovery is
  covered by the deterministic reconcile unit test, not a live demo.
- **Tracker is `git_jsonl`** (explicitly throwaway; M3 deletes it — XSY-0024).
- **No signing, no shard assignment, no validation sink, no network dispatch
  yet.** M2 brings the first three; M3 brings the fourth behind a hard gate.

## 2. M2 goal and definition of done

**Goal.** Freeze the shared schema; complete the lifecycle primitives that
M1 stubbed (shard, heartbeat+TTL takeover, handoff-with-proofs, validation
sink); wire and execute lifecycle hooks; and land **signed** claims + handoffs
against x0xd's shipped `POST /agent/sign` (pulled forward from M3 — its x0x
blocker, #133, shipped).

**Definition of done (M2).** All Wave A/B/C issues are `done` or `review`;
`just check` green in merged state; the XSY-0020 adversarial review has passed
sign-off; the schema is frozen with an explicit `schema_version`; signatures
cover the exact stored payload bytes and verify on read. `v0.0.M2` tagged with
an annotation naming any disclosed boundaries.

## 3. Waves

### Wave A — schema freeze, hooks, signing (parallel where possible)

| Issue | Title | Notes |
|-------|-------|-------|
| **XSY-0017** | Schema freeze | **Unblocked by ruling §4 below.** Narrow freeze NOW: `schema_version` + today's fields + validation rules. Additive-only evolution. |
| **XSY-0041** | Dispatch executes lifecycle hooks per-issue | Independent — start immediately. Minimal core trait extension, no downcasts; all four lifecycle points tested. |
| **XSY-0020** | ML-DSA-65 signing + verification | **Pulled forward from M3** (x0x#133 shipped). Depends on 0017's frozen bytes. **HARD GATE: adversarial review before merge.** |

### Wave B — lifecycle primitives (after 0017 freezes the schema)

| Issue | Title | Notes |
|-------|-------|-------|
| **XSY-0013** | Shard assignment at issue creation | Unblocked (XSY-0007 done). |
| **XSY-0014** | Heartbeat writer + TTL takeover | Completes M1-partial parts: backup-takeover, lower-index conflict tiebreak (mocked-clock tests). |
| **XSY-0016** | Handoff writer with proofs_dir link | `git diff --name-only` files_changed; validation exit codes; `proofs_dir`. |
| **XSY-0015** | Validation artefact sink | `proofs/<issue>/<ts>/`. Unblocked (XSY-0007 done). |

Wave B's new fields (takeover records, `files_changed`, `proofs_dir`) land as
**additive optional fields with a version bump** — additions never mutate or
re-shape existing frozen fields.

### Wave C — resilience close-out

| Issue | Title | Notes |
|-------|-------|-------|
| **XSY-0018** | Reconcile abandon-records on startup | Depends on XSY-0014. |
| **XSY-0037** | Startup orphan-workspace sweep | Unblocked (XSY-0005/0006 done). Quarantine, never delete. |
| **XSY-0040(d)** | Red-team LOWs | Dir perms/umask, newline-in-env-values, boundary tests. |

## 4. Schema freeze ruling (XSY-0017 scope)

**Ruling:** freeze narrow NOW; additive-only evolution; **unblock from
XSY-0014/0016**. Rationale: a freeze that waits on unbuilt writers isn't
protecting anything, and XSY-0020 needs stable bytes to sign.

1. Add an explicit **`schema_version`** to the frozen schema.
2. **v1 freezes the fields that exist today** plus their validation rules.
3. 0014/0016's new fields land in Wave B as **additive optional fields with a
   version bump** — additions never mutate or re-shape existing fields.
4. XSY-0017's `blocked_by` in the tracker reflects this ruling (cleared).

### Critical coupling rule for XSY-0020 (signing)

> **Signatures cover the exact stored payload bytes** — the serialized
> claim/handoff **as written** to the tracker — **never a re-derived canonical
> projection.** Therefore additive schema growth can never invalidate existing
> signatures.

This rule is stated in both the XSY-0017 schema doc and the XSY-0020 design.

## 5. Security requirements (carried from M1 §4 + M2 additions)

### 5.1 Signing (XSY-0020) — design contract

- **Sign** via `POST /agent/sign` with mandatory domain-separation `context`:
  `x0x-symphony-claim-v1` for claims, `x0x-symphony-handoff-v1` for handoffs.
  The daemon signs the canonical DST `[0xF0]|magic|len(u32 BE)|context|payload`
  (see x0x `src/api/agent_signing.rs`); symphony **reproduces this DST exactly**
  for `POST /agent/verify`.
- **Envelope stored at sign time**: `signature_b64` + `algorithm`
  (`x0x.agent-sign.v2.ml-dsa-65`) + `context` + `public_key_b64`. x0xd's sign
  response returns the ML-DSA-65 public key (which `GET /agent` does *not*
  expose — it returns ML-KEM-768), so the key is captured from the sign
  response, not the identity endpoint.
- **Verify on read** via `/agent/verify`; unsigned/mismatched → drop with `WARN`
  per design §11.
- **What is signed**: the exact stored payload bytes (§4 coupling rule).

### 5.2 Hard gates (stop and wait for explicit sign-off)

These two gates are **not** covered by the continuous-run / session-lead-audit
standing rule. Each requires explicit human sign-off:

1. **XSY-0020 adversarial review** — before merge. Matrix (minimum):
   context cross-replay (claim signature presented as handoff), payload
   substitution, **envelope public-key swap** (verify must check the key
   belongs to the claiming agent, not just that the signature verifies),
   truncation/extension attacks on the stored bytes, algorithm downgrade/null,
   replay across issue IDs, signer/claim-owner mismatch, invalid base64,
   oversized payload, x0xd unavailable, verify-endpoint mismatch.
2. **XSY-0039 verification** — an unsigned or untrusted network-sourced issue
   must be **provably never dispatched**. Integration test + transcript.

### 5.3 Network-sourced dispatch (M3, carried forward)

Default-**off** through M3. Release-ready means the capability **exists behind
the gate**, not that it's enabled. The M4 sandbox decision (design §11) gets
**surfaced at M3 close**, not made unilaterally.

## 6. M3 path (sketch — detailed plan lands at M2 close)

After M2, in order: **XSY-0019** `x0x_crdt` adapter → **XSY-0022** trust-gated
dispatch → **XSY-0039** dispatch gate (**hard**) → **XSY-0021** MLS dispatch +
**XSY-0023** GUI board (PR to x0x) → **XSY-0024** delete `git-jsonl` crate,
tag `v0.0.M3`.

**Definition of release-ready:** `v0.0.M3` tagged — `x0x_crdt` adapter live
against x0xd, signing + trust + dispatch gate enforced and tested, `git-jsonl`
deleted (XSY-0024), docs + vault synced, all audits closed.

## 7. Standing rules (continuous-run mode)

1. **Session-lead audit replaces inter-wave approval.** Report each wave
   complete in the usual format and continue into the next wave immediately.
   Audits happen concurrently; only an audit **FAIL** stops the line
   (fix-forward on PASS-with-notes).
2. The two **hard gates** in §5.2 stop and wait for explicit sign-off.
3. **Network-sourced dispatch stays default-off through M3.**
4. **Per-PR discipline throughout**: lint deny-set immutable; checklists are
   claims; deviations flagged; milestone tags annotated. Issue state: agents
   set `review`; humans (lead) close to `done` after audit.
