# ADR-0005 — Consent-gated network dispatch (per-task approval, not a global switch)

**Status:** Accepted (2026-07-03)
**Deciders:** David Irvine
**Context:** M4; supersedes the enablement path implied by ADR-0004 / §11; extends XSY-0028 / XSY-0039
**Related:** ADR-0002 (sharded TTL), ADR-0004 (x0x TaskList backbone), XSY-0039 (dispatch gate @ `6c02ae1`)

## Context

M3 shipped a verified-signature + trust dispatch gate that is **default-off**,
gated behind a boolean `security.network_dispatch_enabled`. The disclosed M4
operator decision was whether to flip that switch. Two options were considered:

1. **Global enable switch (boolean).** Flip `network_dispatch_enabled = true`
   and every network-sourced task that passes signature + trust runs. Simple,
   but "execute code on the operator's machine from a network source" becomes a
   binary, blunt trust delegation to the signer + trust threshold. A single
   compromised-but-trusted signer, or a single over-broad trust grant, runs
   arbitrary code. This is too coarse for the act that approval represents.

2. **Per-task consent.** Network-sourced dispatch becomes an approval flow:
   every network task surfaces an approval request; a consumer (human, GUI, bot,
   or policy engine) decides execute/reject **per task**, bound to the exact
   payload. The signature + trust gate still runs first; consent is an
   additional layer, not a replacement for it.

## Decision

Adopt **per-task consent**. Replace the boolean enable switch with a policy
enum and a signed, payload-bound approval mechanism.

### Policy enum

```toml
[security]
network_dispatch = "off" | "approve" | "auto"   # default: "off"
approval_ttl = "24h"                            # default
approval_webhook_url = "https://..."           # optional, fire-and-forget
network_dispatch_auto_ack = true                # required ONLY for "auto"
```

- **`off`** (default, unchanged): refuse network dispatch exactly as M3.
- **`approve`**: a network-sourced issue that passes signature + trust enters a
  `PendingApproval` state. Nothing executes until a valid signed
  `ApprovalEvent` lands. This is the recommended production mode.
- **`auto`**: signature + trust pass → execute (M3 post-gate behavior).
  Requires the second key `network_dispatch_auto_ack = true` so a typo can
  never reach `auto`. Documented as **not recommended**: it delegates the
  "run network code" act entirely to the signer + threshold.

**Unknown/unparseable value aborts config load** (fail-closed — a bad value
must never degrade to `auto` or `approve`).

**Backward compatibility:** the legacy boolean `network_dispatch_enabled` maps
`true → approve` (never `auto`) with a deprecation warning, and `false → off`.

### Approval mechanics — binding key (operator decision 2026-07-03)

**An ApprovalEvent is keyed by `issue_id` + canonical content-hash + signer**, NOT
by `claim_id`. Rationale: the dispatch model releases a network-sourced claim when
it enters `PendingApproval` (`block_for_dispatch_refusal` → `tracker.block`), and a
re-poll after approval mints a fresh `claim_id`. Binding to `claim_id` would be
incoherent — the approval would reference a dead claim. The `claim_id` is
**recorded in the event for audit only** (which claim was pending at approval
time); it is not the binding key and is not consulted on re-dispatch.

The ApprovalEvent is signed (x0x-symphony-signing / x0xd identity) and bound to:
- **issue id** — the work item being approved;
- **canonical content-hash** — hash of the canonical issue payload
  (title/body/commands) at approval time. If the payload changes after approval,
  the approval is **void** and the task returns to `PendingApproval`;
- **signer** — the network agent whose signed issue was approved (binds the
  approval to a specific trusted source, not any future signer of the same id).

**Single-execution consumption.** An approval, once valid, authorizes exactly
**one** dispatch execution. Consumption is recorded as a signed
`ApprovalConsumed` event (bound to the same issue_id + content-hash + signer + a
nonce). The gate treats an approval whose `ApprovalConsumed` event exists as
invalid — a re-dispatch of the same payload after execution must be re-approved.
This closes the reuse-across-claims property of the issue_id key: yes an
approval is reusable across claims, but only until it is consumed once.

Denial is a signed event too, and is terminal for the issue's network dispatch
until the payload changes (a new payload = a new content-hash = re-eligible for
approval). Approvals expire at `approval_ttl`; expiry = re-gate.

The consent check lives **inside the existing dispatch gate** in
`dispatch.rs::run_claim`, before any workspace/hook/runner work. The
`6c02ae1` invariant is preserved: anything carrying `signature_provenance` is
network-sourced regardless of its source marker. **Signature + trust
verification still run BEFORE an approval request is ever surfaced** —
consumers must never be asked to approve a task that fails those checks;
those refuse outright.

On restart, approvals are re-verified from the CRDT record: a resumed network
claim with a valid (unexpired, payload-matching, unconsumed, signature-verified)
stored approval executes; with an expired, payload-mismatched, consumed, or
missing approval it returns to `PendingApproval`.

### Consumer surface

- REST: `GET /approvals/pending`, `POST /approvals/{issue_id}`
  (`{verdict: approve|deny}`), signed by the runner/operator identity.
- Events: `approval_requested`, `approval_granted`, `approval_denied`,
  `approval_expired` on the existing observability SSE — no separate server.
- Optional webhook (`approval_webhook_url`): fire-and-forget notification only;
  the decision always returns through the signed `POST /approvals` call, so a
  compromised webhook cannot approve anything.
- CLI: `x0x-symphony approvals list`, `x0x-symphony approve|deny <issue>`.
- GUI: extend the x0x#152 board with a `PendingApproval` column (follow-up PR).

## Security invariants (each gets a regression test)

1. No code path executes a network-sourced task without either `verdict=auto`
   policy or a valid, unexpired, payload-bound, signature-verified approval.
2. Timeout / expiry / missing-approval / approval-API-down all resolve to
   **refusal**, never execution.
3. Approval events are visible in the audit trail (proof artefacts).
4. The `6c02ae1` self-enforcing classification and its regression tests survive
   untouched — extend, never weaken.

## Consequences

- Network dispatch is no longer a single switch to flip; it is an operator
  workflow. This matches the seriousness of running network-sourced code.
- `approve` mode requires the approval API/CLI to be operational for any
  network task to progress; API downtime pauses (does not execute) network work.
- The MLS best-effort boundary (x0x#153) is unchanged: the consent gate is the
  enforcement line until x0xd enforces group-scoped task-list topics.
- Implementation is split across new issues XSY-0048..XSY-0054 rather than
  stretching XSY-0028; XSY-0028's acceptance (Pinned identity + signed
  ApprovalEvent + CLI approve) is satisfied by this work.
