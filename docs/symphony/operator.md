# Operator guide

Operational guidance for running an x0x-symphony agent against an x0xd
`TaskList` backlog.

This guide describes the current M3 behaviour of `x0x-symphonyd` and the
`x0x-symphony` CLI. It is kept consistent with what the code actually does —
where a boundary exists it is stated explicitly rather than papered over.

For the interim security posture see [`security.md`](./security.md); for the
architecture see [`../design/symphony.md`](../design/symphony.md). The ignored
multi-daemon partition reunion harness is documented in
[`partition-stress.md`](./partition-stress.md).

## Current scope (what ships)

M3 is a single-daemon vertical slice backed by x0xd:

- **Tracker:** the `x0x_crdt` adapter — one x0xd `TaskList` plus its
  deterministic `symphony-<list-id>` `KvStore` sidecar. Claims, heartbeats,
  releases, handoffs, and blocks are written through x0xd REST endpoints.
- **Runner:** the shell runner — resolves a `RunnerSpec` from `WORKFLOW.md`
  and executes it as a static argv with the issue prompt streamed over stdin.
- **Workspace:** per-issue workspace created under `workspace.root/<sanitized-id>/`
  with path-containment + ID-sanitization (see `containment.rs`, red-team
  audited against §4.1).
- **Lifecycle hooks:** `after_create`, `before_run`, and `after_run` execute
  inside the per-issue workspace during dispatch; `before_remove` executes only
  immediately before an actual terminal workspace cleanup.
- **Orchestrator:** polls the tracker, claims under global + per-state
  concurrency caps, retries failed turns with capped exponential backoff,
  moves an issue to `blocked` on retry exhaustion, reconciles stale claims on
  startup, heartbeats held claims at `claim_ttl / 4`, shuts down gracefully.
- **Daemon + CLI:** `x0x-symphonyd` serves a loopback-only HTTP API behind a
  bearer token; `x0x-symphony` is the operator CLI.

### Current boundaries (stated, not hidden)

- **x0xd is required.** The daemon reads its agent identity from x0xd's
  `/agent` endpoint and uses `signing.x0xd_url` as the base URL for both
  signing and `TaskList`/`KvStore` tracker operations.
- **Distributed worker discovery is best-effort observability.** The daemon
  publishes and consumes signed worker cards when worker discovery is configured;
  `/symphony/workers` returns the live verified view, or an empty view when a
  test/local API state has no discovery service attached. The runner can be
  host-sandboxed when `runner.sandbox` is configured; omitting that block
  intentionally preserves unsandboxed local-development behavior. The operator
  vouches for every command in `WORKFLOW.md` (see [`security.md`](./security.md)).
- **SSE is an in-process broadcast.** `/symphony/events` streams heartbeats and
  task-change events originating from this daemon's own API mutations; x0xd
  gossip updates are visible on the next tracker poll/read but are not pushed
  into this daemon's SSE stream yet.

## Quickstart (the §2 demo)

From a clean checkout:

```bash
just check                                    # fmt, clippy -D warnings, nextest, doc — all green
cargo run --bin x0x-symphonyd -- --config WORKFLOW.md &   # starts, connects to x0xd, polls
x0x-symphony tasks                            # lists the x0xd TaskList backlog
# ... daemon dispatches a todo task: workspace created, runner executes, handoff written ...
x0x-symphony tasks --state review             # the task is now in review with a handoff sidecar
```

A worked, reproducible transcript of this (against a stub runner) is committed
under `proofs/m1/demo-transcript.md`.

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

Minimal M3 tracker/signing configuration:

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
The old local JSONL tracker and `x0x-symphony issue new` writer were removed in
M3; create backlog items in the configured x0xd TaskList until daemon-backed
task creation lands in M4.

Optional runner sandbox schema:

```yaml
runner:
  kind: shell
  preset: claude_code
  sandbox:
    profile: repo-write        # read-only | repo-write | no-network | full-dev | ci-only
    backend: auto              # auto | sandbox-runtime | bubblewrap | landlock | sandbox-exec | none
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
`backend: auto` probes at runner construction time: Linux uses `srt` → `bwrap`
→ `landlock-restrict` → `none`; macOS uses `srt` → `/usr/bin/sandbox-exec` →
`none`; Windows resolves to `none`. `on_unavailable` applies only to local work.
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
2. writes the actual bound port to `<data-dir>/daemon.port`,
3. loads-or-generates the bearer token at `<data-dir>/api-token` (0600),
4. reconciles any stale self-owned claims left from a previous run,
5. enters the poll loop, and
6. serves the HTTP API on the loopback address.

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

## x0x CRDT tracker operations (M3+)

The M3 daemon uses `x0x-symphony-tracker-x0x-crdt` directly. It maps the
configured `tracker.list_id` to x0xd `/task-lists/<list-id>/tasks` and stores
Symphony-only claim/handoff metadata in `/stores/symphony-<list-id>`. When
`tracker.group` is configured, the adapter resolves or joins the named/MLS
group through x0xd and scopes the task-list id to
`x0x.group.<group-id>.symphony.<list-id>`.

Operational implications:

1. **Run x0xd first.** Daemon startup fails if `signing.x0xd_url` is
   unreachable or `/agent` cannot return the local agent id.
2. **TaskList/KvStore availability is an x0xd concern.** The daemon assumes the
   configured TaskList and its sidecar store are available through x0xd. x0xd
   permissions or MLS membership determine what the daemon can see.
3. **No git commits or file locks.** The removed M1-M2 JSONL adapter no longer
   writes `issues/issues.jsonl`, takes `.git/index.lock`, or commits tracker
   transitions. The bootstrap issue database remains only as project history and
   for this repository's human handoff records.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `401` on every `/symphony/*` call | CLI is reading the wrong token; pass `--token` or `--data-dir` matching the running daemon. |
| Daemon exits while reading `/agent` | x0xd is not running at `signing.x0xd_url`, the token is wrong, or x0xd's local agent identity is unavailable. Start x0xd and export `X0X_API_TOKEN` if required. |
| Tasks endpoint returns a tracker error | The configured `tracker.list_id` or group-scoped TaskList/KvStore is missing or not visible to this x0xd identity. Create or join it in x0xd, then retry. |
| Daemon refuses to start: "bind address must be loopback" | `--bind` was set to a non-loopback address. Use `127.0.0.1:0`. |
| Issue stuck in `in_progress` after a crash | Restart the daemon; startup reconciliation releases the stale claim (it has expired past `claim_ttl`). |
| Hooks not running | Confirm the script key is present and non-empty, `hooks.timeout_ms` is long enough, and the lifecycle point actually occurs. `before_remove` only runs when a workspace is about to be destroyed for a configured terminal state. |
