# Symphony — operator and authoring docs

Operator-facing and runner-authoring guides for x0x-symphony.

| Document | Status |
|----------|--------|
| [`operator.md`](operator.md) | **Present (M1, XSY-0008)** — daemon + CLI operations, configuration, security model, lock semantics |
| [`runner-authoring.md`](runner-authoring.md) | **Present (M1, XSY-0008)** — the `Runner` trait, shell runner contract, presets, worked example |
| [`security.md`](security.md) | Present — interim posture (XSY-0038); extended at M4 by XSY-0027 |
| `x0x-tracker.md` | M3 — pending |
| `distributed-workers.md` | M4 — pending |

The architecture document [`../design/symphony.md`](../design/symphony.md)
remains the single source of truth for the design; these guides describe how
to **operate** and **extend** the M1 implementation and are kept consistent
with shipped behaviour (M1 boundaries are stated explicitly within each
guide).

M1 gate transcripts are under [`../../proofs/m1/`](../../proofs/m1/).
