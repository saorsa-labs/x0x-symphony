# x0x-symphony-orchestrator

Dispatch orchestrator tying the tracker, runner, and workspace together.

See `docs/plan/2026-07-m1-execution-plan.md` WP-4 (XSY-0006).

## Modules

- `clock` — `Clock`/`SystemClock`/`ManualClock` time abstraction.
- `concurrency` — global + per-state concurrency `Budget`.
- `retry` — exponential backoff with an attempts cap.
- `reconcile` — startup reconciliation and claim freshness.
- `dispatch` — eligibility gate and the per-issue run/retry flow.

## Lifecycle

1. `reconcile()` on startup: release stale self-claims, keep fresh ones.
2. `claim_next()` polls the tracker and claims one eligible issue under the
   concurrency budget.
3. `run_claim()` runs the retry loop: handoff on success, `blocked` on
   exhaustion, `shutdown` release on graceful shutdown (workspace preserved).
4. `run()` drives the poll loop and heartbeat until shutdown.
