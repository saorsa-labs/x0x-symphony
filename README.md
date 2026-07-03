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

`v0.0.M3` is tagged. Current `main` contains post-M3 M4/M5 work: x0x CRDT
tracking only, worker discovery, consent-gated network dispatch, observability
polish, proof retention, and the Linux native sandbox backend. The M1/M2
`git_jsonl` runtime tracker has been removed; `issues/issues.jsonl` remains only
this repository's historical issue database and handoff log.

Read [`docs/design/symphony.md`](docs/design/symphony.md) first for the design
contract. Operator and runner-authoring guides live in
[`docs/symphony/`](docs/symphony/).

## Repositories

x0x-symphony expects a sibling x0x checkout for development and a running
`x0xd` daemon for real dispatch:

```text
projects/
  x0x/             # github.com/saorsa-labs/x0x
  x0x-symphony/    # this repo
```

The runner consumes the local `x0xd` REST API (default
`http://127.0.0.1:12700`); it does not link x0x as a Rust dependency.

## Quickstart

The commands below were verified on macOS in this worktree. Linux builds and
sandbox paths are CI-validated on `ubuntu-latest`; this README does not claim a
separate local Linux smoke run.

```bash
git clone https://github.com/saorsa-labs/x0x-symphony.git
cd x0x-symphony

cargo build --release
./target/release/x0x-symphonyd --help
./target/release/x0x-symphony --help
./target/release/x0x-symphony config check --config WORKFLOW.md
```

Expected highlights:

- `x0x-symphonyd` requires `--config <CONFIG>` and accepts `--data-dir`,
  `--bind`, and `--agent-id`.
- `x0x-symphony` exposes `tasks`, `claim`, `handoff`, `status`, `workers`,
  `approvals`, `proofs`, `issue`, `config`, and `routes` subcommands.
- `config check` should print `config ok` for the repository `WORKFLOW.md`.

To dispatch real work, start `x0xd` first so `signing.x0xd_url` can answer
`/agent`, `/task-lists`, `/stores`, `/contacts`, `/agent/sign`, and
`/agent/verify`, then start the symphony daemon:

```bash
./target/release/x0x-symphonyd --config WORKFLOW.md --data-dir ~/.x0x-symphony

# in another terminal
./target/release/x0x-symphony --data-dir ~/.x0x-symphony status
./target/release/x0x-symphony --data-dir ~/.x0x-symphony tasks
```

For a complete operator flow (configure workflow, start daemon, create an
issue, approve network-sourced work, and inspect proofs), see
[`docs/symphony/operator.md`](docs/symphony/operator.md#worked-example-end-to-end).

## Design

Architecture decisions are tracked in [`docs/adr/`](docs/adr/). Current
operator guidance, security posture, and runner authoring notes are in
[`docs/symphony/`](docs/symphony/).

## License

Dual AGPL-3.0-or-later / Commercial. Contact david@saorsalabs.com for
commercial licensing.
