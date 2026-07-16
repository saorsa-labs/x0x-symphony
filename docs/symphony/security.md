# x0x-symphony — Security posture and sandbox profiles

This document states x0x-symphony's current security posture after the M3
`x0x_crdt` cutover and the M4/M5 consent/sandbox hardening. The original
interim rules remain useful history: local operator-controlled work can run
without a configured sandbox, but network-sourced dispatch is fail-closed by
default and, when enabled, is gated by signature, trust, consent, and sandbox
availability. The architecture document [`../design/symphony.md`](../design/symphony.md)
§11 remains the authoritative security model.

---

## Threat model summary

When `runner.sandbox` is omitted, a runner is still a **child process with
repo-write and network access**. That unsandboxed mode is intended for local,
operator-controlled development only. Baseline containment rests on two controls:

1. **Workspace path containment** — the runner executes only inside a
   per-issue workspace directory under the configured `workspace.root`.
   Issue identifiers are sanitized against a whitelist, paths are
   canonicalized and prefix-verified, and symbolic links that escape the
   root are rejected at creation and re-checked at destroy. This control
   lands with the workspace manager (XSY-0005 / plan §4.1).
2. **Environment allow-list / deny-list** — hook and runner environments
   start from empty. Only variables declared in `WORKFLOW.md` are added.
   Secrets matching `*_TOKEN`, `*_KEY`, or `*_SECRET` are deny-listed
   unless explicitly allow-listed. This control lands with the runner
   (XSY-0004) and workspace hooks (XSY-0005 / plan §4.1).

These are the primary and secondary boundaries. XSY-0027 adds a tertiary
host-sandbox boundary when `[runner.sandbox]` is configured; omitting the
block intentionally preserves the local-development unsandboxed behavior.

---

## The baseline rules

> Local unsandboxed work is a child process with repo-write and network access,
> contained only by workspace pathing and environment controls. Therefore:
> (1) local work is operator-vouched; network-sourced work is refused unless it
> passes ML-DSA-65 signature verification, x0xd trust, consent policy, and any
> required sandbox gate; (2) hook and runner environments are allow-list only,
> secrets deny-listed by default; (3) the operator vouches for every command
> configured in WORKFLOW.md — treat it with the same care as CI config;
> (4) sensitive tasks require the configured trust/approval path before they can
> execute.

Per-rule controlling issues:

1. **Network execution is gated.** The removed M1/M2 `git_jsonl` tracker read
   only the local `issues/issues.jsonl` backlog. Current runtime uses the
   `x0x_crdt` adapter, so network-sourced issues can be visible, but the
   orchestrator's execute path is hard-gated on XSY-0020 (ML-DSA-65 signature
   verification), XSY-0022 (trust level), XSY-0039 (self-enforcing dispatch
   gate), and ADR-0005 consent policy. Missing approval, verifier errors, or
   unavailable required sandboxing refuse execution.
2. **Environment allow-list / deny-list.** Runner and hook environments
   are constructed from empty plus an explicit allow-list; the deny-list
   blocks `*_TOKEN` / `*_KEY` / `*_SECRET` unless overridden. Implemented
   in the shell runner (XSY-0004) and workspace hooks (XSY-0005).
3. **Operator vouches for WORKFLOW.md.** Every command the orchestrator
   runs comes from `WORKFLOW.md`, resolved to an argv array — never
   through a shell, never with issue fields interpolated into argv. The
   operator who commits `WORKFLOW.md` is the trust root, exactly as with
   CI configuration.
4. **Sensitive work uses trust and consent.** Sensitive/network-sourced work is
   not a label-only bypass. It must satisfy the configured x0xd trust threshold
   and, under `security.network_dispatch: approve`, a signed payload-bound human
   or policy approval before execution.

---

## What this explicitly is NOT

This posture is **not**:

- **A sandbox when `[runner.sandbox]` is absent.** Local development may
  still opt out by omitting the block. When a sandbox block is present,
  the shell runner prepares the structured command plan into a wrapped command
  before process spawn and preserves the existing env-clear, stdio, timeout,
  and process group layers.
- **A process boundary.** ML-DSA-65 signatures authenticate tracker metadata;
  they do not isolate the runner process. Process sandboxing is the separate
  `[runner.sandbox]` layer described below.
- **A substitute for x0xd trust.** ML-DSA-65 signatures authenticate payload
  provenance; they do not decide whether a signer is allowed to run code.
  Network dispatch still consults x0xd trust (`required_trust`) and consent
  policy before execution.
- **A guarantee that approval alone runs code.** Approval is necessary only in
  `approve` mode and is never sufficient by itself: signature, trust, payload
  hash, TTL, consumption, and verifier availability all remain fail-closed
  checks.

**Network-sourced work is visible but fail-closed by default.** The current
`x0x_crdt` adapter (XSY-0019) can read network-sourced issues from x0xd, but
dispatch is default-off via `security.network_dispatch: "off"`. In
`approve` mode, signature provenance + trust must pass before an approval is
surfaced, and a valid signed approval must be verified before execution. In
`auto` mode, signer+trust dispatch is allowed only when
`network_dispatch_auto_ack: true` is deliberately set.

**Self-authored work is exempt cryptographically.** An issue whose verified
ML-DSA-65 provenance is signed by this daemon's own agent id is local by
definition and bypasses the network-dispatch consent gate under every policy.
The exemption is derived only from the verified signature — never from the
issue's `issue_source`/`source` metadata, which an adapter or peer could set —
so it cannot be forged by claiming a `local` marker. Because the exemption
requires provenance, `security.network_dispatch: approve` fails config
validation unless `signing.policy: required`, and an explicit `off` without
required signing warns at startup (locally created issues would otherwise be
refused fail-closed).

**Approval consumption is signed and verified — and refuses on doubt.** When
the gate dispatches an approved task it mints an `ApprovalConsumed` record
signed through x0xd (ML-DSA-65, `x0x-symphony-approval-consumed-v1` context),
and it cryptographically re-verifies every stored consumption record before
trusting it on later evaluations. A consumption record that fails verification
means the replay-protection state is tampered or forged: the gate refuses to
dispatch (`invalid_signature` block) rather than guessing in either direction.
Consumption records may only un-park work in one narrow way: the tracker-level
`requeue_blocked` transition refuses any blocked issue whose reason is not
`awaiting_approval`, so no Tracker-API path can resurrect security-blocked or
retry-exhausted work. That invariant holds within the Tracker API; a hostile
writer inside the replicated tracker group could still mutate raw claim blobs
directly — replicated-writer integrity is tracked in
[#10](https://github.com/saorsa-labs/x0x-symphony/issues/10).

**Dispatch/consumption guarantees in v0.1 (read carefully).** The
approval/consumption store is a per-issue KV blob updated by
read-modify-write, and claim-blob state transitions are not yet
integrity-signed; the structural fix is tracked in
[#10](https://github.com/saorsa-labs/x0x-symphony/issues/10). The actual
semantics are:

- **Single node, no crash:** exactly-once — dispatch is serialized by the
  exclusive claim, and each dispatch stores its signed consumption record
  before the runner starts.
- **Single node, crash windows:** a crash after the consumption record is
  stored but before the runner completes yields **zero** executions with the
  approval already spent. Operator recovery: approve the payload again (a
  fresh approval mints a fresh consumption) or re-issue the task under a new
  id.
- **Concurrent multi-node writers:** the RMW blob update is not a convergent
  set — two nodes that evaluate the same valid approval concurrently (or
  reunite after a partition) can each dispatch once, and a racing write can
  drop an approval or consumption record entirely. Multi-node approval is
  therefore **best-effort**: runners MUST be idempotent.
- **Hostile replicated writers:** unsigned claim-blob transitions (status,
  `release_reason`) mean a hostile writer inside the replicated tracker group
  can mutate issue state directly, bypassing Tracker-API invariants. Pilot
  mitigation: run the symphony TaskList/KvStore only within a trusted,
  closed tracker group (`required_trust`, vetted membership).

**Recovery: dispatch refused with `invalid_signature` consumption state.** A
garbage or tampered consumption record parks the issue as `blocked` with
reason code `invalid_signature` and detail "approval consumption record
failed signature verification". To repair: inspect the approval blob in the
symphony sidecar store — store `symphony-<list-id>`, key
`approval-<task-id>` (x0xd `GET /stores/symphony-<list-id>/keys/approval-<task-id>`);
its `consumed` array holds the offending record(s). Either rewrite that key
with the corrupted entries removed (keeping only records this daemon signed),
or — simpler and safer — re-create the issue with `issue new` (a new task id
starts with empty approval state) and mark the corrupted one done/cancelled.

**Tracker-integrity v2 (`symphony2:` lists) — v1 vs v2 guarantees.** The
paragraphs above describe **v1** lists. Lists addressed as
`symphony2:<uuid>:<creator>` use the tracker-integrity v2 model
(per-author append-only signed event stores + a pure deterministic fold —
normative spec: `docs/design/tracker-integrity-v2.md`); the same threats
resolve differently:

| Threat / property | v1 (`symphony-*` lists) | v2 (`symphony2:` lists) |
|---|---|---|
| State-transition integrity | Claim blobs unsigned; a hostile replicated writer can flip `Blocked` → `Released` directly | Every transition is an ML-DSA-65-signed, hash-chained event; a transition not authored by a roster member at its named epoch, or not fenced by the fold-winning claim, is inadmissible/ineffective |
| Hostile un-park of blocked work | Possible against raw blobs (Tracker-API check only) | Requeue admissible ONLY for `awaiting_approval` blocks with a signed justification binding the exact block hash + parked claim nonce + approver (C6); all other reasons are terminal |
| Impersonating another author | Trust-scoped only | Four-way self-certifying binding (derived key id == envelope signer == store owner == payload actor); fabricated authorship is inadmissible |
| Concurrent approval/consume writers | RMW blob — records can be silently LOST; replay re-enabled | Per-key append-only records; set-union convergence — records cannot be clobbered; duplicates resolve to ONE deterministic fold winner, losers surfaced as diagnostics |
| Double-dispatch under concurrency | Best-effort; both nodes can dispatch | Consume-then-confirm fenced by the fold-winning claim; a competing/healed winner ABORTS with zero local executions. Residual: a live-partition window narrowed by the settle re-read (deterministic + detectable after heal — runners should stay idempotent) |
| Crash after consume, before execute | Approval spent, zero executions (re-approve) | Same fail-toward-zero semantics (re-approve); unchanged by design |
| Equivocation (rewriting own history) | Undetectable | Per-author hash chains: two signed events with one `author_seq` are self-authenticating fork evidence; the forked author's suffix is inadmissible |
| Downgrade | n/a | A `symphony2:` reference with a missing/invalid genesis manifest is REFUSED outright — never silently served as v1 |
| Storage mutability | Mutable KV blobs | `AccessPolicy::AppendOnly` stores (x0x ≥ 0.33.0, released). The daemon-reported anchor (owner AND policy) is verified on every **event store** the tracker touches — own, joined, and read paths alike; silence is refusal. Heartbeat companion stores are **excluded** from this guarantee: they are mutable, non-authoritative liveness hints and never fold inputs. Three remote-manipulation regimes, precisely: **(a) alteration** of an existing observed event — REJECTED (signatures + content-addressed keys); **(b) interior deletion** from an observed chain — DETECTED (the `author_seq`/`prev_own_event_hash` chain breaks and the suffix is inadmissible); **(c) tail withholding** — a remote daemon truncating or withholding the TAIL of its own stream is **undetectable** to an observer that never saw the withheld events; it is indistinguishable from replication lag (design r2 residual, unchanged). Interim `v2_store_policy = "signed"` fallback runs on older daemons with the deletion residual OPEN — the default mode refuses loudly instead |

v2 requires `signing.policy: required`. Heartbeats remain mutable
non-authoritative liveness hints in a `symphony2-hb-*` companion store and
are never fold inputs; the v1 TaskList mirror of a v2 list is a display
projection only — disagreement always resolves toward fold state.

---

## Sandbox profiles (M2/M4)

The shell runner accepts an optional `[runner.sandbox]` / `runner.sandbox:`
block. If omitted, behavior is unchanged and local work runs unsandboxed.
If present, the runner resolves a backend at construction time, prepares a
`CommandPlan` into a `WrappedCommand` plus `SandboxSession`, then builds
`tokio::process::Command` and applies the existing env-clear, stdio-pipe,
timeout, and process-group layers.

Profiles:

| Profile | Filesystem | Network | Secrets |
|---------|------------|---------|---------|
| `read-only` | Workspace mounted read-only; rest of host read-only where the backend supports it | Denied | Denied (`~/.ssh`, `~/.x0x`, `~/.aws`, `~/.config/gcloud`, `~/.gnupg`, browser profiles, plus configured denies) |
| `repo-write` | Workspace writable; rest read-only/masked | Configured LLM/API egress allow-list | Denied by default |
| `no-network` | Workspace writable; rest read-only/masked | Denied | Denied by default |
| `full-dev` | Workspace writable; broad host read/write where supported | Unrestricted | Accessible; use only for trusted, pinned agents |
| `ci-only` | Workspace writable; rest read-only/masked | CI/registry allow-list (GitHub, crates.io, configured registry) | Only CI-scoped secrets the operator explicitly passes |

Backend selection:

| Platform | `backend = auto` order | Notes |
|----------|------------------------|-------|
| Linux | `native` (Landlock + cgroup-v2) → `bwrap` → `landlock-restrict` → `none` | Firejail was deliberately replaced with Bubblewrap. The native backend uses the internal `saorsa-sandbox-launcher`; Bubblewrap provides filesystem, PID, and network namespace isolation, but domain-level egress allow-lists require an outer policy engine such as `srt`; when Bubblewrap is the effective backend, egress allow-list entries are advisory metadata rather than DNS firewall rules. |
| macOS | `srt` → `/usr/bin/sandbox-exec` → `none` | `sandbox-exec` enforces filesystem and coarse network operations from generated SBPL. Domain allow-lists are not DNS-specific; native Seatbelt deferred indefinitely (XSY-0057 → review, per ADR-0006 Amendment 1). |
| Windows | `none` | Tier 1 has no Windows host sandbox; non-local dispatch must fail closed. |

`on_unavailable` controls only local work: `warn` logs and runs the
unwrapped command, while `fail-closed` refuses to spawn. Network-sourced
work is always fail-closed regardless of this setting; a resolved
`backend = none` is not enforceable for `IssueSource::NetworkSourced`.
This preserves the rule that network dispatch remains default-off and cannot
use an unavailable sandbox as an escape hatch.

Resource limits depend on the backend. The Linux native backend places the
launcher/target in a cgroup-v2 leaf when delegation is available; Tier-1 Linux
wrappers fall back to `systemd-run --user --scope` when possible. macOS uses
shell `ulimit` / rlimit inheritance; that is a per-process mechanism rather
than a cgroup-scoped boundary, so forked children are not bounded as strongly as
on Linux.

Every sandbox exposes a `probe()` self-test that returns a structured
`ProbeReport` for write-outside-workspace, secret-read, host-PID, and
non-allowlisted-network checks. Checks can be `not-applicable` when a
backend, platform primitive, or probe dependency is absent, but the report
always records each check explicitly.

---

## Signed claims and handoffs (XSY-0020)

`signing.policy = required` signs claim and handoff payloads at the async
Tracker boundary. The removed JSONL adapter never performed HTTP; the current
x0x CRDT tracker calls x0xd signing/verification through the shared signing
client. Required signing uses a prepare → sign → commit sequence: build the
unsigned payload without writing, call x0xd, re-read and re-check
ownership/state, then write the signed record once. If the record changed
during signing, the signature is discarded and no unsigned fallback is written.

The stored `signature` envelope contains:

- `algorithm`: `x0x.agent-sign.v2.ml-dsa-65`
- `context`: `x0x-symphony-claim-v1` or `x0x-symphony-handoff-v1`
- `public_key_b64` and `signature_b64`: x0xd's ML-DSA-65 public key and
  detached signature
- `payload_sha256`: hex SHA-256 of the raw claim/handoff signing payload bytes
- `signer_agent_id`: x0x agent id returned by `/agent/sign`

Symphony sends raw claim/handoff payload bytes to both `/agent/sign` and
`/agent/verify`. x0xd reconstructs the external domain-separated buffer
internally on both endpoints:

```text
[0xF0] || b"x0x.external-agent-sign.v1" || context_len(u32 BE) || context || payload
```

Do not pre-wrap payloads with that DST before verification; doing so would ask
x0xd to verify `DST(context, DST(context, payload))`.

Verification on read checks, in order: envelope algorithm/context, payload
SHA-256, signer/owner binding, trusted-key belonging, and x0xd's
`/agent/verify` result. A record is rejected if the envelope public key differs
from the trusted resolver's key for the signer, even when `/agent/verify` would
return true for the supplied key. Since XSY-0045, invalid or unsigned **claims**
are stripped from the issue while the issue remains visible with a verification
notice; invalid handoffs still cause the issue record to be refused. Disabled
mode skips signing and verification for local development.

Handoff signatures bind two additive fields into the signed payload:
`issue_id` and `signer_agent_id`. They are required whenever
`handoff.signature` is present and prevent replaying a valid handoff onto a
different issue.

Claim `heartbeat_at` is intentionally excluded from the claim signing payload.
It is a mutable liveness signal, not an attestation; heartbeat refreshes keep
the original signature valid and do not call x0xd.

---

## Hardening milestones

The following issues extend or supersede the original interim posture:

| Issue | Milestone | What it adds |
|-------|-----------|--------------|
| [XSY-0020](../../issues/issues.jsonl) | M2 ✅ landed | ML-DSA-65 signing + verification of claim and handoff payloads |
| [XSY-0027](../../issues/issues.jsonl) | M2 ✅ landed | Sandbox profiles (Bubblewrap / sandbox-exec) with structured command planning |
| [XSY-0022](../../issues/issues.jsonl) | M3 ✅ landed | Trust-gated dispatch using x0xd contacts |
| [XSY-0039](../../issues/issues.jsonl) | M3 ✅ landed | Dispatch gate: orchestrator refuses network-sourced issues without verified signature + trust |
| [XSY-0048..XSY-0056](../../issues/issues.jsonl) | M4 ✅ landed | Consent-gated dispatch, signed approvals, crypto verification, and None-verifier fail-closed hardening |
| [XSY-0042](../../issues/issues.jsonl) | M4 ✅ Linux landed | Native Linux sandbox via `saorsa-sandbox`; macOS native split to XSY-0057 |

The baseline rules above remain the contract; configured sandbox profiles layer
additional defense-in-depth on top.

## Containment status (per ADR-0006)

| Platform | Backend | Status |
|----------|---------|--------|
| **Linux** | Native Landlock (access control) + cgroup-v2 (resource bounding), via the internal `saorsa-sandbox-launcher` binary | Native (XSY-0042); no external tool forked |
| **macOS** | **Tier-1 `sandbox-exec` (external tool)** | External-tool wrapper (XSY-0027). Native macOS Seatbelt **deferred indefinitely** (XSY-0057 → review, 2026-07-07) — see ADR-0006 (M) + Amendment 1. `sandbox-exec` is the industry-standard macOS containment path. The `auto` probe order (`srt` → `sandbox-exec` → `none`) is in the selection table above |

**macOS `sandbox-exec` rationale:** `sandbox-exec` is the path Chromium,
Mozilla, `containerd-shim-darwin`, and Apple's own first-party apps use for
process sandboxing on macOS. It is a front-end to the same Seatbelt/MACF
enforcement path a native `sandbox_init` call would use: it compiles the
generated SBPL profile to bytecode and applies it through the kernel MACF layer.
The deprecation banner has been emitted since macOS Sierra (2016) with no removal in ~9 years; no supported
non-App-Store replacement exists (Apple containerization issue #737, open). A
native backend would save one fork and silence the warning but would add no
containment — see ADR-0006 (M) and Amendment 1 for why native macOS Seatbelt is
deferred (XSY-0057).

**`unsafe` policy:** `saorsa-sandbox` carries `#![forbid(unsafe_code)]`. Symphony
writes zero `unsafe`; the `unsafe` that enforcement depends on lives only inside
vetted crates (`landlock`, maintained by the Landlock kernel author; `libc`;
`tokio`). See ADR-0006 (P).

**Fail-loud-degrade:** if the Linux launcher is missing or a backend `probe()`
fails, the daemon **refuses network-sourced work** (fail-closed). Degrading to
unsandboxed execution is acceptable only for **local-sourced** tasks, and only
with a loud `tracing::warn!`. A network-sourced task with no enforcing backend
never executes.
