# x0x-symphony-core

Core traits and domain types for x0x-symphony.

This crate contains only the stable abstractions shared by tracker adapters,
runners, workspace managers, and the orchestrator. It intentionally ships no
runtime adapter implementations. The permanent `x0x_crdt` tracker lives in
`crates/x0x-symphony-tracker-x0x-crdt`; the M1/M2 `git_jsonl` bootstrap adapter
was deleted at M3.

Read the architecture first:

- [`../../docs/design/symphony.md`](../../docs/design/symphony.md)
- [`../../docs/adr/0001-tracker-abstraction.md`](../../docs/adr/0001-tracker-abstraction.md)
