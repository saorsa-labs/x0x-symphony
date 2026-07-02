# Operator guide

Operational guidance for running an x0x-symphony agent against a local
`issues/issues.jsonl` backlog.

This guide describes the current shipped behaviour of `x0x-symphonyd` and the
`x0x-symphony` CLI. It is kept consistent with what the code actually does —
where a boundary exists it is stated explicitly rather than papered over.

For the interim security posture see [`security.md`](./security.md); for the
architecture see [`../design/symphony.md`](../design/symphony.md).

## Current scope (what ships)

M1 is a single-host vertical slice:

- **Tracker:** the `git_jsonl` adapter — one local `issues/issues.jsonl` file,
  every state transition (claim / heartbeat / release / handoff / block)
  committed to a local git repo.
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

### Current boundaries (what still does NOT ship — stated, not hidden)

- **No distributed workers, no MLS.** The runner can be host-sandboxed when
  `runner.sandbox` is configured; omitting that block intentionally preserves
  unsandboxed local-development behavior. Execution is local-backlog-only until
  M3. The operator vouches for every command in `WORKFLOW.md` (see
  [`security.md`](./security.md)).
- **SSE is an in-process broadcast.** `/symphony/events` streams heartbeats and
  task-change events originating from this daemon's own API mutations;
  external edits to the JSONL are visible on the next poll/read but are not
  pushed cross-process.

## Quickstart (the §2 demo)

From a clean checkout:

```bash
just check                                    # fmt, clippy -D warnings, nextest, doc — all green
cargo run --bin x0x-symphonyd -- --config WORKFLOW.md &   # starts, loads config, polls
x0x-symphony tasks                            # lists the backlog
# ... daemon dispatches a todo issue: workspace created, runner executes, handoff written ...
x0x-symphony tasks --state review             # the issue is now in review with a handoff
git log --oneline issues/issues.jsonl         # shows the claim + handoff commits
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
| `tracker` | `kind` (`git_issues`), `path` |
| `polling` | `interval_ms` (≥ 1) |
| `workspace` | `root` (`~` expanded) |
| `hooks` | `timeout_ms`; `after_create`, `before_run`, `after_run`, and `before_remove` are optional scripts (absent or empty = disabled) |
| `agent` | `max_concurrent_agents`, `max_concurrent_agents_by_state`, `max_turns`, `max_retry_backoff_ms` |
| `runner` | `kind` (`shell`); the `runner:` block is then resolved by `RunnerSpec::from_workflow_config` (so `runner.preset` and optional `runner.sandbox` are accepted) |

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

Proof directory cleanup is not implemented in M2; the retention reaper is an
M5 follow-up.

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
x0x-symphony status                        # active claims + counts
x0x-symphony claim XSY-0001                # claim a task by id
x0x-symphony handoff XSY-0001 --message "done" [--file path]
x0x-symphony proofs list                   # list proof artefacts
x0x-symphony proofs show <name>            # show one
x0x-symphony config show   --config WORKFLOW.md
x0x-symphony config check --config WORKFLOW.md
x0x-symphony routes                        # list daemon HTTP routes
```

Output is deterministic text (no wall-clock timestamps) so it is
snapshot-testable and scriptable.

## Tracker lock semantics (M1–M2 git_jsonl adapter)

The M1 `git_jsonl` tracker serializes every state transition
(claim / heartbeat / release / handoff) with a file lock. Three behaviors
matter operationally:

1. **The lock is `<git-dir>/index.lock` — the same path `git` uses.** The
   adapter takes it with an exclusive `create_new` and releases it *before*
   running `git add`/`git commit`, so git can re-acquire its own index lock.
   **Concurrent operator `git` commands** (a manual `git commit`, a second
   symphony process, etc.) contend on this single path. Under contention the
   adapter retries with backoff and, if it cannot acquire the lock within its
   budget, returns a structured `LockExhausted` error instead of corrupting
   the file. If you see `LockExhausted`, another writer is active — wait and
   retry, or serialize your manual git operations.

2. **A crashed process leaves a stale lock that must be removed by hand.** The
   adapter deletes only the lock file *it* created; it does **not** remove
   locks left behind by other (possibly crashed) processes. If a previous run
   was killed while holding `<git-dir>/index.lock`, every subsequent write
   fails with `LockExhausted` until you remove the orphaned file:

   ```sh
   rm -f .git/index.lock   # only after confirming no symphony/git process is running
   ```

   Confirm no writer is actually running before removing it — removing a lock
   that a live process still holds can corrupt the JSONL under concurrent
   writes. (Automated stale-lock recovery with a liveliness probe is tracked
   as a follow-up in XSY-0040.)

3. **Tracker commits skip git hooks (`--no-verify`).** The adapter commits
   issue-line rewrites with `git commit --no-verify`. This is deliberate: the
   tracker owns the issue backlog and must not be blocked by pre-commit or
   pre-push hooks installed in the operator's environment. Any policy you want
   to enforce via hooks must be applied out-of-band (e.g. a CI check on the
   tracker commit, or a separate review step).

For the full concurrency model, retry/backoff tuning, and the M3 supersession
path (this adapter is deleted by XSY-0024 when the `x0x_crdt` tracker becomes
the permanent backend), see the crate-level documentation of
`x0x-symphony-tracker-git-jsonl`.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `401` on every `/symphony/*` call | CLI is reading the wrong token; pass `--token` or `--data-dir` matching the running daemon. |
| `LockExhausted` on writes | A writer (git or another symphony) holds `.git/index.lock`; wait, or remove it only after confirming nothing is running (see above). |
| Daemon exits with a schema violation at startup | `issues/issues.jsonl` has a malformed or blank line. Re-init the file empty (0 bytes) — do **not** seed it with `echo ""`, which adds a blank line. |
| Daemon refuses to start: "bind address must be loopback" | `--bind` was set to a non-loopback address. Use `127.0.0.1:0`. |
| Issue stuck in `in_progress` after a crash | Restart the daemon; startup reconciliation releases the stale claim (it has expired past `claim_ttl`). |
| Hooks not running | Confirm the script key is present and non-empty, `hooks.timeout_ms` is long enough, and the lifecycle point actually occurs. `before_remove` only runs when a workspace is about to be destroyed for a configured terminal state. |
