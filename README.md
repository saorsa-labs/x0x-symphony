# x0x-symphony

Decentralized, harness-agnostic agent work orchestration built on
[x0x](https://github.com/saorsa-labs/x0x).

x0x-symphony borrows the operational pattern popularized by OpenAI Symphony —
issue → isolated workspace → coding-agent run → validation → handoff — and
backs it with x0x's gossip transport, CRDT task lists, MLS group encryption,
and post-quantum identity. There is no central tracker, no required SaaS, and
no privileged orchestrator: any trusted x0x agent can claim work, run a coding
harness inside an isolated workspace, and publish a signed handoff back into
the shared backlog.

## Status

pre-M1 (design frozen, core traits only). The architecture and four ADRs are
frozen; only the `x0x-symphony-core` traits crate is implemented so far. The
M1 vertical slice (tracker → runner → workspace → orchestrator → daemon) is
in flight — see
[`docs/plan/2026-07-m1-execution-plan.md`](docs/plan/2026-07-m1-execution-plan.md).
The v1.0 shipping tracker is x0x's native CRDT TaskList, accessed through the
local x0xd REST API; until M3 the daemon reads only the operator-controlled
`issues/issues.jsonl` backlog.

## Design

Read [`docs/design/symphony.md`](docs/design/symphony.md) first. It is the
authoritative architecture document for this project.

Architecture decisions are tracked in [`docs/adr/`](docs/adr/).

## Repositories

x0x-symphony depends on x0x as a sibling checkout:

```
projects/
  x0x/             # github.com/saorsa-labs/x0x
  x0x-symphony/    # this repo
```

The runner consumes the local `x0xd` REST API (default
`http://127.0.0.1:12700`); it does not link x0x as a Rust dependency.

## License

Dual AGPL-3.0-or-later / Commercial. Contact david@saorsalabs.com for
commercial licensing.
