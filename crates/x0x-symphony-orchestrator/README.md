# x0x-symphony-orchestrator

Dispatch orchestrator tying the tracker, runner, workspace, trust gate,
approval gate, heartbeat loop, and proof writer together.

See [`../../docs/symphony/operator.md`](../../docs/symphony/operator.md) for
operator behavior and [`../../docs/design/symphony.md`](../../docs/design/symphony.md)
for the architecture contract.

## Modules

- `clock` — `Clock`/`SystemClock`/`ManualClock` time abstraction.
- `concurrency` — global + per-state concurrency `Budget`.
- `retry` — exponential backoff with an attempts cap.
- `reconcile` — startup reconciliation and claim freshness.
- `dispatch` — signature/trust/approval eligibility gate and the per-issue
  run/retry flow.
- `proofs` / `reaper` — validation artefact manifests and retention cleanup.

## Lifecycle

1. `reconcile()` on startup: release stale self-claims, keep fresh ones.
2. `claim_next()` polls the tracker and claims one eligible issue under the
   concurrency budget.
3. `run_claim()` gates and runs the claim: handoff on success, `blocked` or
   pending-approval release on refusal/exhaustion, `shutdown` release on
   graceful shutdown (workspace preserved).
4. `run()` drives the poll loop and heartbeat until shutdown.
