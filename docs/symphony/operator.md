# Operator guide

Operational guidance for running an x0x-symphony agent against a local
`issues/issues.jsonl` backlog.

This guide describes the **M1 shipped behaviour** of `x0x-symphonyd` and the
`x0x-symphony` CLI. It is kept consistent with what the code actually does —
where an M1 boundary exists it is stated explicitly rather than papered over.

For the interim security posture see [`security.md`](./security.md); for the
architecture see [`../design/symphony.md`](../design/symphony.md).

## M1 scope (what ships)

M1 is a single-host vertical slice:

- **Tracker:** the `git_jsonl` adapter — one local `issues/issues.jsonl` file,
  every state transition (claim / heartbeat / release / handoff / block)
  committed to a local git repo.
- **Runner:** the shell runner — resolves a `RunnerSpec` from `WORKFLOW.md`
  and executes it as a static argv with the issue prompt streamed over stdin.
- **Workspace:** per-issue workspace created under `workspace.root/<sanitized-id>/`
  with path-containment + ID-sanitization (see `containment.rs`, red-team
  audited against §4.1).
- **Orchestrator:** polls the tracker, claims under global + per-state
  concurrency caps, retries failed turns with capped exponential backoff,
  moves an issue to `blocked` on retry exhaustion, reconciles stale claims on
  startup, heartbeats held claims at `claim_ttl / 4`, shuts down gracefully.
- **Daemon + CLI:** `x0x-symphonyd` serves a loopback-only HTTP API behind a
  bearer token; `x0x-symphony` is the operator CLI.

### M1 boundaries (what M1 does NOT do — stated, not hidden)

- **Lifecycle hooks are validated but not executed per issue.** `config check`
  requires and validates the four hook scripts (`after_create`, `before_run`,
  `after_run`, `before_remove`) and their `timeout_ms`, so a malformed
  `WORKFLOW.md` is rejected up front. The workspace crate **has** the tested
  hook-running machinery (`Manager::run_hook` with timeouts + process-group
  kill, covered by `proof_hook_timeout_kills_forked_child_process_group`), but
  the M1 orchestrator dispatch path calls only `Workspace::create()` to obtain
  the session path and does **not** invoke per-issue hooks at run time. Wiring
  per-issue hook execution through dispatch is a tracked follow-up. **Do not
  configure hooks expecting them to run in M1.**
- **No distributed workers, no sandbox, no MLS.** The runner is an unsandboxed
  child process; execution is local-backlog-only until M3. The operator vouches
  for every command in `WORKFLOW.md` (see [`security.md`](./security.md)).
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
| `hooks` | `timeout_ms`, `after_create`, `before_run`, `after_run`, `before_remove` |
| `agent` | `max_concurrent_agents`, `max_concurrent_agents_by_state`, `max_turns`, `max_retry_backoff_ms` |
| `runner` | `kind` (`shell`); the `runner:` block is then resolved by `RunnerSpec::from_workflow_config` (so `runner.preset` is accepted) |

Validate without starting the daemon:

```bash
x0x-symphony config check --config WORKFLOW.md   # prints "config ok" or a list of problems, exit 0/non-zero
x0x-symphony config show   --config WORKFLOW.md   # prints the parsed configuration
```

## Security model (M1)

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
| Hooks not running | Expected in M1 — see "M1 boundaries" above. Hooks are validated by `config check` but not executed per issue. |
