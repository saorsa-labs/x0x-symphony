# x0x-symphony — Interim security posture (pre-sandbox)

This document states x0x-symphony's security posture for the M1–M3
window — the period before sandbox profiles land at M4. Until then, a
runner is an unsandboxed child process; this file records the four rules
that make that acceptable and the boundaries that hold. It is the
verbatim source required by the
[2026-07 M1 execution plan](../plan/2026-07-m1-execution-plan.md) §4.3.
XSY-0027 extends this same file with sandbox-profile mapping when M4
arrives; until then, the architecture document
[`../design/symphony.md`](../design/symphony.md) §11 remains the
authoritative security model.

---

## Threat model summary

During M1–M3, a runner is a **child process with repo-write and network
access**. There is no sandbox. Containment rests on two controls:

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

These are the primary and secondary boundaries. There is no tertiary
boundary (sandbox) until M4.

---

## The four interim rules

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

Per-rule controlling issues:

1. **Local-backlog-only execution.** The M1 `git_jsonl` tracker reads only
   `issues/issues.jsonl` — the local, operator-controlled, git-committed
   backlog. No code path exists to dispatch work sourced over the network.
   At M3 the `x0x_crdt` adapter may *list* network-sourced issues, but the
   orchestrator's execute path is hard-gated on XSY-0020 (ML-DSA-65
   signature verification) and XSY-0022 (trust level), tracker-enforced
   by XSY-0039. Until that gate is wired, network issues are listed but
   never dispatched.
2. **Environment allow-list / deny-list.** Runner and hook environments
   are constructed from empty plus an explicit allow-list; the deny-list
   blocks `*_TOKEN` / `*_KEY` / `*_SECRET` unless overridden. Implemented
   in the shell runner (XSY-0004) and workspace hooks (XSY-0005).
3. **Operator vouches for WORKFLOW.md.** Every command the orchestrator
   runs comes from `WORKFLOW.md`, resolved to an argv array — never
   through a shell, never with issue fields interpolated into argv. The
   operator who commits `WORKFLOW.md` is the trust root, exactly as with
   CI configuration.
4. **`security-sensitive` label refused.** Any issue carrying the
   `security-sensitive` label is refused outright by the orchestrator
   until XSY-0028 lands (Pinned identity + human approval step). There is
   no partial handling in the interim window.

---

## What this explicitly is NOT

This posture is **not**:

- **A sandbox.** There is no process isolation, syscall filtering, or
  filesystem namespace confinement until XSY-0027 at M4. The runner has
  the full privileges of the `x0x-symphonyd` process.
- **A process boundary.** Signing claims and handoffs does not isolate the
  runner. ML-DSA-65 signatures authenticate tracker metadata; process
  sandboxing still arrives with XSY-0027 at M4.
- **Trust-gated dispatch.** There is no trust-level evaluation before
  M3. All dispatched work is local and operator-controlled, so the trust
  gate is not yet exercised.

**Network-sourced work is impossible before M3.** The `git_jsonl` tracker
(XSY-0003) has no network code path; it reads only the local
operator-controlled repo. At M3 the `x0x_crdt` adapter (XSY-0019)
introduces network-sourced issues, but dispatch is hard-gated on verified
signature + trust level (XSY-0039) from the moment that path exists.

---

## Signed claims and handoffs (XSY-0020)

`signing.policy = required` signs claim and handoff payloads at the async
Tracker boundary. The sync JSONL helpers still only parse, mutate, and serialize
records; they never perform HTTP. Required signing uses a prepare → sign → commit
sequence: build the unsigned payload without writing, call x0xd, re-read and
re-check ownership/state, then write the signed record once. If the record
changed during signing, the signature is discarded and no unsigned fallback is
written.

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
`/agent/verify` result. The trusted-key resolver for M2 accepts only the local
x0xd agent key learned from `/agent/sign` (or a bootstrap sign probe). A record
is rejected if the envelope public key differs from the resolver's key for the
signer, even when `/agent/verify` would return true for the supplied key.
Invalid or unsigned claim/handoff records are dropped from async read results
with a WARN log in Required mode; Disabled mode skips signing and verification
for local development.

Handoff signatures bind two additive fields into the signed payload:
`issue_id` and `signer_agent_id`. They are required whenever
`handoff.signature` is present and prevent replaying a valid handoff onto a
different issue.

Claim `heartbeat_at` is intentionally excluded from the claim signing payload.
It is a mutable liveness signal, not an attestation; heartbeat refreshes keep
the original signature valid and do not call x0xd.

---

## Future hardening

The following issues extend or supersede this posture, in milestone order:

| Issue | Milestone | What it adds |
|-------|-----------|--------------|
| [XSY-0020](../../issues/issues.jsonl) | M2 | ML-DSA-65 signing + verification of claim and handoff payloads |
| [XSY-0022](../../issues/issues.jsonl) | M3 | Trust-gated dispatch: rejects non-trusted agents on sensitive tasks |
| [XSY-0039](../../issues/issues.jsonl) | M3 | Dispatch gate: orchestrator refuses network-sourced issues without verified signature + trust |
| [XSY-0027](../../issues/issues.jsonl) | M4 | Sandbox profiles (firejail / sandbox-exec) — extends *this file* with profile mapping |
| [XSY-0028](../../issues/issues.jsonl) | M4 | Sensitive-task gates: Pinned identity + human approval step |

When XSY-0027 lands, this document transitions from an interim posture to a
sandbox-enforced one. The four rules above remain as the baseline contract;
the sandbox profiles layer additional defense-in-depth on top.
