# Symphony — operator and authoring docs

Operator-facing and runner-authoring guides for x0x-symphony.

| Document | Status |
|----------|--------|
| [`operator.md`](operator.md) | Current — daemon + CLI operations, x0x CRDT tracker, approvals, proofs, worker discovery, sandbox notes |
| [`runner-authoring.md`](runner-authoring.md) | Current for the shell-runner contract and presets |
| [`security.md`](security.md) | Current security posture, consent-gated dispatch, and sandbox profiles |
| [`partition-stress.md`](partition-stress.md) | Ignored multi-daemon partition-reunion harness |

The architecture document [`../design/symphony.md`](../design/symphony.md)
remains the single source of truth for the design; these guides describe how
to **operate** and **extend** the implementation that now uses x0xd TaskLists
through the `x0x_crdt` tracker. The M1/M2 `git_jsonl` runtime tracker was
removed at M3.

Historical M1 gate transcripts remain under [`../../proofs/m1/`](../../proofs/m1/).
