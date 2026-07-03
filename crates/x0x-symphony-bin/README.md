# x0x-symphony-bin

Daemon and CLI binaries for x0x-symphony.

- `x0x-symphonyd` loads `WORKFLOW.md`, connects to x0xd, runs the orchestrator,
  and serves a loopback-only HTTP API guarded by a bearer token in `api-token`.
- `x0x-symphony` talks to that daemon for task, claim, handoff, status,
  workers, approvals, proofs, issue creation, config, and route inspection
  commands. It also validates and prints workflow configuration locally.

The event stream is daemon-local: API mutations and dispatch/approval events
broadcast through in-process SSE, and all clients receive periodic heartbeat
SSE events. External x0xd changes made outside this daemon are visible on
polling HTTP reads, but they are not pushed through SSE until a cross-process
watcher is added.

Hook honesty: this crate validates the required hook keys in `WORKFLOW.md`.
Per-issue lifecycle hook execution remains owned by the workspace/orchestrator
boundary and is not claimed here unless wired and tested in those crates.
