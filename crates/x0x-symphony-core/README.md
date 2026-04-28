# x0x-symphony-core

Core traits and domain types for x0x-symphony.

This crate contains only the stable abstractions shared by tracker adapters,
runners, workspace managers, and the orchestrator. It intentionally ships no
adapter implementations; the bootstrap `git_jsonl` adapter and the permanent
`x0x_crdt` adapter live in separate crates.

Read the architecture first:

- [`../../docs/design/symphony.md`](../../docs/design/symphony.md)
- [`../../docs/adr/0001-tracker-abstraction.md`](../../docs/adr/0001-tracker-abstraction.md)
