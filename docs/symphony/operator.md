# Operator guide

Operational guidance for running an x0x-symphony agent against an x0xd
`TaskList` backlog.

This guide describes the current post-M3 behaviour of `x0x-symphonyd` and the
`x0x-symphony` CLI, including M4/M5 worker discovery, consent-gated dispatch,
proof retention, and sandbox hardening. It is kept consistent with what the
code actually does — where a boundary exists it is stated explicitly rather
than papered over.

For the current security posture see [`security.md`](./security.md); for the
architecture see [`../design/symphony.md`](../design/symphony.md). The ignored
multi-daemon partition reunion harness is documented in
[`partition-stress.md`](./partition-stress.md).

## Current scope (what ships)

Current `main` is a post-M3/M4+ daemon backed by x0xd:

- **Tracker:** the `x0x_crdt` adapter — one x0xd `TaskList` plus its
  deterministic `symphony-<list-id>` `KvStore` sidecar. Claims, heartbeats,
  releases, handoffs, approvals, blocks, and daemon-created issues are written
  through x0xd REST endpoints.
- **Runner:** the shell runner — resolves a `RunnerSpec` from `WORKFLOW.md`
  and executes it as a static argv with the issue prompt streamed over stdin.
- **Workspace:** per-issue workspace created under `workspace.root/<sanitized-id>/`
  with path-containment + ID-sanitization (see `containment.rs`, red-team
  audited against §4.1).
- **Lifecycle hooks:** `after_create`, `before_run`, and `after_run` execute
  inside the per-issue workspace during dispatch; `before_remove` executes only
  immediately before an actual terminal workspace cleanup.
- **Orchestrator:** polls the tracker, claims under global + per-state
  concurrency caps, gates network-sourced tasks on signature/trust/consent,
  retries failed turns with capped exponential backoff, moves an issue to
  `blocked` on retry exhaustion, reconciles stale claims on startup, heartbeats
  held claims at `claim_ttl / 4`, shuts down gracefully, and reaps old proof
  artefacts according to `retention`.
- **Worker discovery:** when enabled, the daemon signs and publishes worker
  cards, maintains a verified live worker view, and uses that view when creating
  new symphony-owned issues.
- **Sandboxing:** optional `runner.sandbox` wraps local shell-runner work.
  Linux can use the native `saorsa-sandbox-launcher` Landlock + cgroup-v2
  backend; macOS remains Tier-1 `sandbox-exec`; network-sourced work fails
  closed if an enforcing backend is required but unavailable.
- **Daemon + CLI:** `x0x-symphonyd` serves a loopback-only HTTP API behind a
  bearer token; `x0x-symphony` is the operator CLI.

### Current boundaries (stated, not hidden)

- **x0xd is required for daemon startup and dispatch.** The daemon reads its
  agent identity from x0xd's `/agent` endpoint and uses `signing.x0xd_url` as
  the base URL for signing, trust, worker discovery, and `TaskList`/`KvStore`
  tracker operations.
- **`issues/issues.jsonl` is no longer a runtime tracker.** The old M1/M2
  `git_jsonl` adapter was deleted at M3. The JSONL file remains only this
  repository's historical issue database and human handoff log.
- **Network dispatch is consent-gated, not merely enabled.** With
  `security.network_dispatch: approve`, a network-sourced task must first pass
  ML-DSA-65 signature verification and x0xd trust, then wait for a signed,
  payload-bound approval before execution. `auto` skips per-task approval only
  when `network_dispatch_auto_ack: true` is set deliberately.
- **Distributed worker discovery is best-effort observability.** The daemon
  publishes and consumes signed worker cards when worker discovery is configured;
  `/symphony/workers` returns the live verified view, or an empty view when a
  test/local API state has no discovery service attached. The operator still
  vouches for every command in `WORKFLOW.md` (see [`security.md`](./security.md)).
- **SSE is an in-process broadcast.** `/symphony/events` streams heartbeats,
  task-change events, and approval events originating from this daemon's own API
  mutations; x0xd gossip updates are visible on the next tracker poll/read but
  are not pushed into this daemon's SSE stream yet.

## Quickstart (local smoke)

From a clean checkout, the build/help/config path does not require x0xd:

```bash
cargo build --release
./target/release/x0x-symphonyd --help
./target/release/x0x-symphony --help
./target/release/x0x-symphony config check --config WORKFLOW.md
```

Expected highlights:

```text
Usage: x0x-symphonyd [OPTIONS] --config <CONFIG>
Usage: x0x-symphony [OPTIONS] <COMMAND>
config ok
```

Real dispatch requires x0xd running at `signing.x0xd_url` (default
`http://127.0.0.1:12700`). The daemon must be able to call `/agent`,
`/task-lists`, `/stores`, `/contacts`, `/agent/sign`, and `/agent/verify`.
Linux CI validates the same build/test path on `ubuntu-latest`; the macOS
commands above were verified locally for this documentation update.

## Worked example: end to end

This example uses a stub runner so the flow is reproducible without giving a
coding harness control of your machine. It still exercises the same daemon,
tracker, approval, and proof surfaces used by real runners.

### 1. Configure a workflow

Create `WORKFLOW.demo.md` in the repository root:

```yaml
---
tracker:
  kind: x0x_crdt
  list_id: x0x-symphony-demo

signing:
  policy: required
  x0xd_url: http://127.0.0.1:12700

polling:
  interval_ms: 1000

retention:
  proofs_days: 7
  reap_interval_secs: 3600

workspace:
  root: /tmp/x0x-symphony-demo/workspaces

hooks:
  timeout_ms: 30000
  after_create: "true"
  before_run: "true"
  after_run: "true"
  before_remove: "true"

agent:
  max_concurrent_agents: 1
  max_concurrent_agents_by_state:
    todo: 1
    in_progress: 1
  max_turns: 1
  max_retry_backoff_ms: 1000

security:
  network_dispatch: "approve"
  approval_ttl: "24h"
  required_trust: trusted

runner:
  kind: shell
  command: /bin/sh
  args:
    - -c
    - |
      cat >/dev/null
      echo "stub runner completed"
  turn_timeout_ms: 30000
  sandbox:
    profile: repo-write
    backend: auto
    on_unavailable: warn
---
You are working on {{ issue.identifier }}: {{ issue.title }}.

{{ issue.description }}
```

Validate before starting the daemon:

```bash
./target/release/x0x-symphony config check --config WORKFLOW.demo.md
# config ok
```

### 2. Start x0xd and the daemon

Start `x0xd` with an identity that can access `x0x-symphony-demo`, then start
`symphonyd` in a separate terminal:

> **Bearer token:** If your `x0xd` requires an API token (e.g. when
> `auth_required` is set), export `X0X_API_TOKEN` before starting the daemon.
> The tracker client, worker gossip publisher, and worker subscriber all read
> this variable. `X0XD_TOKEN` only feeds the trust gate and is **not** used
> for REST/WebSocket authentication.

```bash
mkdir -p /tmp/x0x-symphony-demo/data
./target/release/x0x-symphonyd \
  --config WORKFLOW.demo.md \
  --data-dir /tmp/x0x-symphony-demo/data \
  --bind 127.0.0.1:0
# ... x0x-symphonyd started; port written to /tmp/x0x-symphony-demo/data/daemon.port
```

In another terminal, let the CLI discover the port and token from `--data-dir`:

```bash
./target/release/x0x-symphony --data-dir /tmp/x0x-symphony-demo/data status
# status:
# agent: <local-x0xd-agent-id>
# orchestrator_attached: true
# counts:
# ...
```

### 3. Create a local issue and watch dispatch

Create a local symphony-owned issue through the daemon-backed tracker:

```bash
./target/release/x0x-symphony --data-dir /tmp/x0x-symphony-demo/data \
  issue new \
  --title "Demo local task" \
  --description "Run the stub runner and produce a proof manifest." \
  --priority 2 \
  --label x0x-symphony
# created XSY-0100
```

> **Dispatch status:** The daemon now auto-creates the `TaskList` and
> sidecar `KvStore` on startup, so `issue new` works against a clean x0xd.
> However, full dispatch (claim → run → handoff) depends on the dispatch
> gate / issue-provenance signing regression being resolved. Until that
> lands, the daemon will create the issue but may not dispatch it to a
> runner.

Watch the daemon claim and hand off the task:

```bash
./target/release/x0x-symphony --data-dir /tmp/x0x-symphony-demo/data tasks
# tasks:
# - XSY-0100 [todo] p2 Demo local task

./target/release/x0x-symphony --data-dir /tmp/x0x-symphony-demo/data status
# status:
# agent: <local-x0xd-agent-id>
# orchestrator_attached: true
# counts:
# - review: 1

./target/release/x0x-symphony --data-dir /tmp/x0x-symphony-demo/data tasks --state review
# tasks:
# - XSY-0100 [review] p2 Demo local task
```

For live event output, use the same token that the CLI reads:

```bash
PORT=$(cat /tmp/x0x-symphony-demo/data/daemon.port)
TOKEN=$(cat /tmp/x0x-symphony-demo/data/api-token)
curl -N "http://127.0.0.1:${PORT}/symphony/events?token=${TOKEN}"
# event: heartbeat
# event: task_changed
```

### 4. Approve a network-sourced task

From a second trusted x0x identity (or a peer daemon) publish a task into the
same `x0x-symphony-demo` TaskList. On this daemon, the task is network-sourced,
so `security.network_dispatch: approve` makes it wait for consent after the
signature and trust checks pass:

```bash
./target/release/x0x-symphony --data-dir /tmp/x0x-symphony-demo/data approvals list
# approvals:
# - XSY-0101 [todo] signer agent-abc hash 8b2f3a4c9d10 Network approval demo

./target/release/x0x-symphony --data-dir /tmp/x0x-symphony-demo/data \
  approvals approve XSY-0101 \
  --expected-hash 8b2f3a4c9d10e11f2233445566778899aabbccddeeff00112233445566778899 \
  --expected-signer agent-abc
# XSY-0101 approved
```

Use `--expected-hash` and `--expected-signer` from the latest `approvals list`
output. If the task body or signer changed, the API returns `409 Conflict` and
nothing executes until you re-check and approve the new payload.

### 5. View proof artefacts

After a successful handoff, inspect the proof tree through the CLI:

```bash
./target/release/x0x-symphony --data-dir /tmp/x0x-symphony-demo/data proofs list
# proofs:
# - XSY-0100/2026-07-03T22-15-00Z/manifest.json
# - XSY-0100/2026-07-03T22-15-00Z/stdout.log
# - XSY-0100/2026-07-03T22-15-00Z/stderr.log

./target/release/x0x-symphony --data-dir /tmp/x0x-symphony-demo/data \
  proofs show XSY-0100/2026-07-03T22-15-00Z/manifest.json
# {"issue_id":"XSY-0100", ... "exit_code":0, ...}
```

The same artefacts are available over authenticated HTTP under
`/symphony/proofs/{issue_id}/{timestamp}/...`.

## Configuration

The daemon reads `WORKFLOW.md`, which is YAML front-matter followed by a
Markdown prompt template:

```
---
<tracker / polling / workspace / hooks / agent / runner blocks>
---
<prompt template, with {{ issue.* }} placeholders>
```

`config check` validates **all** required keys from design §8 and exits
non-zero on any missing/invalid key, printing one clear error per problem:

| Block | Required keys |
|-------|---------------|
| `tracker` | `kind` (`x0x_crdt`; aliases `crdt`, `x0x`), `list_id`; optional `group` for x0xd named/MLS scoping |
| `polling` | `interval_ms` (≥ 1) |
| `workspace` | `root` (`~` expanded) |
| `hooks` | `timeout_ms`; `after_create`, `before_run`, `after_run`, and `before_remove` are optional scripts (absent or empty = disabled) |
| `agent` | `max_concurrent_agents`, `max_concurrent_agents_by_state`, `max_turns`, `max_retry_backoff_ms` |
| `retention` | Optional proof reaper settings: `proofs_days` (default 30, ≥ 1) and `reap_interval_secs` (default 3600, ≥ 60) |
| `runner` | `kind` (`shell`); the `runner:` block is then resolved by `RunnerSpec::from_workflow_config` (so `runner.preset` and optional `runner.sandbox` are accepted) |

Minimal x0x CRDT tracker/signing configuration:

```yaml
tracker:
  kind: x0x_crdt
  list_id: x0x-symphony          # x0xd TaskList id/topic
  # group: private-project      # optional x0xd group id, name, or invite

signing:
  policy: required              # disabled for local dev, required for signed records
  x0xd_url: http://127.0.0.1:12700
```

`x0x-symphonyd` always contacts `signing.x0xd_url` during startup to resolve
its agent id from `/agent`. When `signing.policy: required`, claim and handoff
payloads are signed through `/agent/sign` and verified through `/agent/verify`.
The old local JSONL tracker and direct file writer were removed in M3.
`x0x-symphony issue new` now POSTs to the daemon and creates issues through the
configured x0xd TaskList tracker, assigning shards from the live worker view.

Optional runner sandbox schema:

```yaml
runner:
  kind: shell
  preset: claude_code
  sandbox:
    profile: repo-write        # read-only | repo-write | no-network | full-dev | ci-only
    backend: auto              # auto | native | sandbox-runtime | bubblewrap | landlock | sandbox-exec | none
    on_unavailable: warn       # warn for local work, fail-closed to refuse local work
    egress_allow:              # domain metadata / allow-list for network profiles
      - api.anthropic.com
      - api.openai.com
    secrets_deny:              # defaults include SSH, x0x, cloud, GPG, browser profiles
      - ~/.ssh
      - ~/.x0x
    cpu_seconds: 3600          # optional best-effort resource limit
    memory_bytes: 8589934592   # optional best-effort resource limit
```

If `runner.sandbox` is absent, the shell runner is unsandboxed. If present,
`backend: auto` probes at runner construction time: Linux uses native
Landlock+cgroup-v2 (`native`) → `bwrap` → `landlock-restrict` → `none`; macOS
uses `srt` → `/usr/bin/sandbox-exec` → `none`; Windows resolves to `none`.
`on_unavailable` applies only to local work.
Network-sourced work is always fail-closed once that dispatch source exists.
Preset-specific `sandbox_args` can be prepended to child argv as
defense-in-depth (for example, a harness-native `--sandbox` flag), but the host
sandbox remains the enforcement boundary.

### Migrating from the legacy `codex:` block

Older `WORKFLOW.md` files may still carry this unsupported top-level Codex
block:

```yaml
codex:
  app_server: true
```

Current configs must express Codex through the shell runner preset instead:

```yaml
runner:
  kind: shell
  preset: codex
```

The legacy `codex:` top-level block was removed in XSY-0031. Config load and
`config check` now fail with a structured error pointing to this migration path.
See [`runner-authoring.md`](runner-authoring.md#adding-a-preset) for preset
details.

Validate without starting the daemon:

```bash
x0x-symphony config check --config WORKFLOW.md   # prints "config ok" or a list of problems, exit 0/non-zero
x0x-symphony config show   --config WORKFLOW.md   # prints the parsed configuration
```

### Lifecycle hooks

Configured hook scripts run with `/bin/bash -euo pipefail -c` in the per-issue
workspace directory. The hook process environment is explicit and does not
inherit the daemon environment. Dispatch supplies:

- `ISSUE_ID`
- `AGENT_ID`
- `WORKSPACE_DIR`
- `CLAIM_ID`
- `HOOK_PHASE` (`after_create`, `before_run`, `after_run`, or `before_remove`)

`hooks.timeout_ms` applies independently to each hook. Timed-out hooks are
killed with their process group where the platform supports it. `after_create`
and `before_run` failures block the issue and clear the claim; `after_run`
failures are logged as warnings without discarding the runner result.
`before_remove` runs only when a dispatch transition is about to destroy a
workspace because the reached state is configured as terminal; shutdown and
retry releases preserve workspaces and do not fire `before_remove`.

### Proof artefacts

Every dispatch creates `proofs/<issue-id>/<utc-timestamp>/` under the tracked
repository. The directory contains `stdout.log`, `stderr.log`, any
`artifact-*.bin` files emitted by runner artifact events, and a final
`manifest.json`. Successful handoffs link this relative directory in
`handoff.proofs_dir` before the handoff is signed.

`manifest.json` is machine-readable JSON with these fields:

| Field | Type | Meaning |
|-------|------|---------|
| `issue_id` | string | Issue identifier for the run. |
| `agent_id` | string | Agent id that held the claim. |
| `hostname` | string | Hostname observed by the daemon, or `unknown`. |
| `runner_kind` | string | Runner capability kind, such as `shell`. |
| `preset` | string or null | Runner preset name when configured. |
| `command` | string | Executable command recorded by the runner. |
| `args` | array of strings | Static argv recorded by the runner. |
| `env_allowlist` | array of strings | Environment variable names forwarded to the runner. |
| `exit_code` | integer | Final runner exit code (`0` for success, non-zero for failure/timeout/cancel). |
| `duration_ms` | integer | Wall-clock duration of the dispatch in milliseconds. |
| `started_at` | string | RFC3339 UTC dispatch start timestamp. |
| `ended_at` | string | RFC3339 UTC dispatch end timestamp. |
| `hooks` | array of strings | Hook outcomes as `<hook>:<status>`, for example `before_run:succeeded`. |

The daemon reaps timestamped proof run directories older than
`retention.proofs_days` (default 30 days) every
`retention.reap_interval_secs` (default 3600 seconds). Cleanup is
maintenance-only and race-safe: any issue currently `in_progress` or registered
as in-flight by the local daemon is skipped for that scan.

## Observability

The daemon HTTP surface is intentionally small and fully documented here. There
are no undocumented endpoints: every route served by `x0x-symphonyd` is listed
below. `/health` is unauthenticated; every `/symphony/*` route requires the
bearer token described in [Security model](#security-model). `/symphony/events`
also accepts `?token=` for browser `EventSource` clients.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness probe. |
| `GET` | `/symphony/tasks` | List visible tasks; accepts `?state=<state>`. |
| `GET` | `/symphony/tasks/{id}` | Return one full task detail record, including shard, claim, handoff, signature provenance, and approval summary when present. |
| `GET` | `/symphony/status` | Return agent id, state counts, active claims, and whether an orchestrator handle is attached. |
| `GET` | `/symphony/workers` | Return the live verified worker view: `workers`, `view_epoch`, and a note when discovery is not configured. |
| `GET` | `/symphony/events` | Server-Sent Events stream for daemon-local observability. |
| `GET` | `/symphony/approvals/pending` | List network-sourced tasks currently waiting for per-task consent (ADR-0005). |
| `POST` | `/symphony/approvals/{id}` | Store a signed approve/deny decision for one task. |
| `POST` | `/symphony/issues` | Create a symphony-owned issue through the configured tracker. |
| `POST` | `/symphony/claim/{id}` | Claim one task for the local daemon identity. |
| `POST` | `/symphony/handoff/{id}` | Record a handoff for a claimed task. |
| `GET` | `/symphony/proofs` | List top-level proof artefact names. |
| `GET` | `/symphony/proofs/{issue_id}/{ts}/manifest.json` | Return a proof manifest as `application/json`. |
| `GET` | `/symphony/proofs/{issue_id}/{ts}/stdout.log` | Return proof stdout as `text/plain`. |
| `GET` | `/symphony/proofs/{issue_id}/{ts}/stderr.log` | Return proof stderr as `text/plain`. |
| `GET` | `/symphony/proofs/{*name}` | Back-compatible proof artefact reader for safe relative proof paths. |
| `GET` | `/symphony/routes` | Return this route catalog in machine-readable form. |

The SSE stream emits `heartbeat` keepalives and `task_changed` notices from
local API mutations. Approval events added for XSY-0053 are part of the same
stream and are named `approval_requested`, `approval_granted`,
`approval_denied`, and `approval_expired`; see
[ADR-0005](../adr/0005-consent-gated-dispatch.md) for the approval-flow
semantics.

Operator CLI observability commands mirror this surface:

```bash
x0x-symphony status              # counts + active claims
x0x-symphony workers             # live worker card table
x0x-symphony tasks               # task list
x0x-symphony tasks --state todo  # filtered task list
x0x-symphony tasks --id XSY-0001 # single-task detail
```

## Security model

- **Loopback only.** The daemon binds `127.0.0.1` (or `::1`) and rejects any
  non-loopback bind such as `0.0.0.0` at startup. There is no flag to disable
  this.
- **Bearer token, file mode 0600.** The token is a random 32-byte hex string
  in `<data-dir>/api-token`. The daemon sets `0600` permissions on the token
  file both when it generates a new token and when it reads an existing one.
- **Auth-required API.** Every `/symphony/*` route requires
  `Authorization: Bearer <token>`; `/health` is exempt and `/symphony/events`
  (SSE) also accepts `?token=` for `EventSource` clients. A request without a
  valid token returns `401 {"error":"missing or invalid Authorization: Bearer token"}`.

This mirrors x0x's own `auth_middleware` + `load_or_generate_api_token`
pattern (`x0x/src/server/mod.rs`). Full posture in [`security.md`](./security.md).

## Running the daemon

```bash
x0x-symphonyd \
  --config WORKFLOW.md \
  --data-dir ~/.x0x-symphony \   # default; holds daemon.port + api-token
  --bind 127.0.0.1:0 \           # default; 0 = ephemeral, written to daemon.port
  --agent-id symphonyd           # default
```

On start the daemon:

1. loads + validates `WORKFLOW.md` (same checks as `config check`),
2. ensures the configured TaskList and `symphony-<list-id>` KvStore exist in
   x0xd, creating them if missing (idempotent),
3. writes the actual bound port to `<data-dir>/daemon.port`,
4. loads-or-generates the bearer token at `<data-dir>/api-token` (0600),
5. reconciles any stale self-owned claims left from a previous run,
6. enters the poll loop, and
7. serves the HTTP API on the loopback address.

### Shutdown and restart

`SIGINT` / `SIGTERM` trigger a graceful shutdown: the daemon stops claiming,
in-flight runs release their claims with a `shutdown` reason, and
**workspaces are preserved** (never destroyed) so work can resume. The
orchestrator's `reconcile()` then runs on the next start to release any claim
that went stale while the daemon was down.

Because held claims are heartbeated at `claim_ttl / 4`, a brief restart does
not lose a claim; a long outage causes the claim to expire and be released on
the next startup reconciliation. A worked restart transcript is in
`proofs/m1/restart-transcript.md`.

## CLI operations

The CLI reads `<data-dir>/daemon.port` (to build `http://127.0.0.1:<port>`)
and `<data-dir>/api-token` by default; override with `--server` / `--token`.

```bash
x0x-symphony tasks                         # list tasks
x0x-symphony tasks --state review          # filter by state
x0x-symphony tasks --id XSY-0001           # show one task in detail
x0x-symphony status                        # active claims + counts
x0x-symphony workers                       # live worker cards
x0x-symphony claim XSY-0001                # claim a task by id
x0x-symphony handoff XSY-0001 --message "done" [--file path]
x0x-symphony approvals list                # list network tasks awaiting consent
x0x-symphony approvals approve XSY-0002    # approve one network-sourced task
x0x-symphony approvals deny XSY-0003       # deny one network-sourced task
x0x-symphony proofs list                   # list proof artefacts
x0x-symphony proofs show <name>            # show one
x0x-symphony config show   --config WORKFLOW.md
x0x-symphony config check --config WORKFLOW.md
x0x-symphony routes                        # list daemon HTTP routes
```

Output is deterministic text except for the wall-clock-relative `workers` age
field; stable portions remain snapshot-testable and scriptable.

### Approving network-sourced tasks

When `security.network_dispatch: approve`, network-sourced tasks that pass the
ML-DSA-65 signature and trust gate wait for per-task consent before dispatch
(see [ADR-0005](../adr/0005-consent-gated-dispatch.md)). The approval or denial
is itself signed and bound to the issue id, current content hash, and network
signer; changing the payload or signer voids the decision.

```bash
x0x-symphony approvals list
# approvals:
# - XSY-0100 [todo] signer agent-abc hash 8b2f3a4c9d10 Investigate failure

x0x-symphony approvals approve XSY-0100 \
  --expected-hash 8b2f3a4c9d10e11f2233445566778899aabbccddeeff00112233445566778899 \
  --expected-signer agent-abc
# XSY-0100 approved

x0x-symphony approvals deny XSY-0101
# XSY-0101 denied
```

Use `--expected-hash` and `--expected-signer` from a recent list output when an
operator UI may be stale. If either value no longer matches, the daemon returns
`409 Conflict`; re-run `approvals list` before retrying.

## x0x CRDT tracker operations

The daemon uses `x0x-symphony-tracker-x0x-crdt` directly. It maps the
configured `tracker.list_id` to x0xd `/task-lists/<list-id>/tasks` and stores
Symphony-only claim/handoff metadata in `/stores/symphony-<list-id>`. When
`tracker.group` is configured, the adapter resolves or joins the named/MLS
group through x0xd and scopes the task-list id to
`x0x.group.<group-id>.symphony.<list-id>`.

Operational implications:

1. **Run x0xd first.** Daemon startup fails if `signing.x0xd_url` is
   unreachable or `/agent` cannot return the local agent id.
2. **Surfaces are auto-created on startup.** The daemon ensures the configured
   TaskList and its `symphony-<list-id>` KvStore sidecar exist before the poll
   loop starts, creating them via x0xd if missing. x0xd permissions or MLS
   membership still determine what the daemon can see and write.
3. **No git commits or file locks.** The removed M1-M2 JSONL adapter no longer
   writes `issues/issues.jsonl`, takes `.git/index.lock`, or commits tracker
   transitions. The bootstrap issue database remains only as project history and
   for this repository's human handoff records.

## Troubleshooting matrix

| Problem | Symptoms | Fixes |
|---------|----------|-------|
| CLI cannot authenticate | `401` on every `/symphony/*` call; CLI stderr says the bearer token is missing or invalid. | Use the same `--data-dir` as the running daemon, or pass `--server` plus `--token` / `--token-file`. Confirm `<data-dir>/api-token` is mode `0600` and belongs to the current user. |
| x0xd or signing client unavailable | Daemon exits during startup with `failed to read x0xd agent identity`, signing/verification calls fail, or network approvals cannot be signed. | Start x0xd at `signing.x0xd_url`, verify `/agent` responds, export the x0xd API token if that daemon requires one, and keep `signing.policy: required` only when `/agent/sign` and `/agent/verify` are available. |
| Tracker TaskList or group not visible | `tasks` returns a tracker error, the daemon sees an empty queue while another node has tasks, or group-scoped work never appears. | Check `tracker.list_id`, `tracker.group`, x0xd group membership, and MLS permissions. Join the group through x0xd before starting symphonyd; verify the sidecar `symphony-<scoped-list-id>` KvStore exists or is creatable. |
| Sandbox backend unavailable | Local task logs warn and runs unwrapped, or network task is refused with a sandbox-unavailable / fail-closed reason. On Linux, native probe may mention Landlock ABI or cgroup-v2 delegation; on macOS, `/usr/bin/sandbox-exec` may be missing. | For local development, decide whether `on_unavailable: warn` is acceptable. For network work, install/enable an enforcing backend or use a host that supports it. Linux native requires Landlock support and cgroup-v2 delegation; fallback options are `bwrap` or `landlock-restrict`. macOS currently uses Tier-1 `sandbox-exec`; native Seatbelt is XSY-0057. |
| Approval pending forever | `approvals list` repeatedly shows the same issue; `tasks --id` shows an approval summary or release reason such as `awaiting_approval`; no workspace is created. | Confirm `security.network_dispatch: approve` is intentional, then approve with fresh `--expected-hash` and `--expected-signer`. If the API returns `409`, re-run `approvals list`; the content hash or signer changed. If the issue has `approval_verifier_unconfigured`, configure x0xd signing/verification before approving. |
| Signing verifier not configured under `approve` | Network task refuses with `approval_verifier_unconfigured` and does not execute even though an approval event exists. | XSY-0056 is fail-closed by design. Ensure the daemon can build an `X0xdClient` from `signing.x0xd_url`, and that the signing client and trusted-key resolver are injected. Do not switch to `auto` unless you deliberately accept signer+trust-only network execution and set `network_dispatch_auto_ack: true`. |
| Worker not discovered / no shard candidates | `x0x-symphony workers` is empty or stale; new issues do not get the expected primary/backups; `view_epoch` does not advance. | Verify `workers.publish_enabled` is true, x0xd worker gossip endpoints are reachable, clocks are sane relative to card TTL, and the local agent can sign worker cards. Restarting the daemon republishes its card; peers must trust the signer for their view to include it. |
| Proof reaper deletes too aggressively | Old proof run directories disappear sooner than expected, or a reviewer cannot fetch a historical manifest. | Increase `retention.proofs_days`; the minimum is 1 day. Keep artefacts that must survive review outside the timestamped proof run directory or archive them before the reaper window. The reaper skips `in_progress` issues but not already-reviewed historical runs. |
| Proof reaper appears stuck | Old proof directories remain past the configured window. | Check `retention.reap_interval_secs` (minimum 60 seconds), daemon logs, and whether the issue is still `in_progress` or registered in the local in-flight set. Reaper work is maintenance-only; it will not block dispatch. |
| Daemon refuses to bind | Startup error says the bind address must be loopback. | Use `127.0.0.1:0` or `[::1]:0`. x0x-symphonyd intentionally has no non-loopback mode. |
| Issue stuck in `in_progress` after crash | The holder's heartbeat is stale and no new work starts. | Restart the daemon. Startup reconciliation releases stale self-owned claims after `claim_ttl`; fresh claims are preserved. |
| Hooks not running | Expected script output is missing, or `before_remove` never fires. | Confirm the hook key is present and non-empty, `hooks.timeout_ms` is long enough, and the lifecycle point actually occurs. `before_remove` only runs when a workspace is about to be destroyed for a configured terminal state; shutdown and retry releases preserve workspaces. |

## Common pitfalls

- **Trying to use `issues/issues.jsonl` as the runtime queue.** That adapter was
  removed at M3. Use x0xd TaskLists and the daemon `/symphony/issues` API /
  `x0x-symphony issue new` command.
- **Leaving an old top-level `codex:` block in `WORKFLOW.md`.** XSY-0031 made
  this a hard config error. Use `runner: {kind: shell, preset: codex}`.
- **Starting symphonyd before x0xd.** Config validation can pass without x0xd,
  but daemon startup needs `/agent` immediately and dispatch needs the TaskList,
  KvStore, trust, sign, and verify endpoints.
- **Assuming `approve` mode means “execute after I trust the signer.”** Approval
  is a second gate after signature and trust. The task will not run until a
  valid signed approval for the current content hash exists.
- **Approving from stale UI output.** Always copy `--expected-hash` and
  `--expected-signer` from a fresh `approvals list` when multiple operators or
  peers may edit the task.
- **Expecting SSE to mirror all gossip.** SSE reports this daemon's local API
  mutations and dispatch events. Remote x0xd changes become visible on the next
  tracker poll/read.
- **Relying on domain egress allow-lists as a firewall for every backend.** Some
  Tier-1 wrappers treat `egress_allow` as metadata or coarse network policy.
  Confirm the selected backend's enforcement before running untrusted work.
- **Setting proof retention too low for human review.** Handoffs link proof
  directories by relative path; if `proofs_days` is shorter than review latency,
  reviewers may lose stdout/stderr context.
- **Using `--agent-id` to choose the dispatch identity.** With the x0x CRDT
  tracker, the daemon uses the x0xd `/agent` identity; `--agent-id` is retained
  only as a compatibility flag and is ignored for tracker identity.
