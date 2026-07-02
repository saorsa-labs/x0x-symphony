# x0x-symphony-bin

Daemon and CLI binaries for the M1 x0x-symphony local runner slice.

- `x0x-symphonyd` loads `WORKFLOW.md`, runs the orchestrator, and serves a
  loopback-only HTTP API guarded by a bearer token in `api-token`.
- `x0x-symphony` talks to that daemon for task, claim, handoff, status,
  proofs, and route inspection commands. It also validates and prints workflow
  configuration locally.

The M1 event stream is intentionally simple: API mutations broadcast an
in-process `task_changed` event, and all clients receive periodic heartbeat
SSE events. External tracker changes made outside this daemon are visible on
polling HTTP reads, but they are not pushed through SSE until a later
cross-process watcher is added.

Hook honesty: this crate validates the required hook keys in `WORKFLOW.md`.
Per-issue lifecycle hook execution remains owned by the workspace/orchestrator
boundary and is not claimed here unless wired and tested in those crates.
