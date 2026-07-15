# Runner authoring guide

How to write and configure a runner for x0x-symphony, and how to add a new
shell preset. This guide targets the current shell runner
(`x0x-symphony-runner-shell`).

For the trait definition see `x0x_symphony_core::Runner`
(`crates/x0x-symphony-core/src/runner.rs`); for the architecture see
[`../design/symphony.md`](../design/symphony.md).

## The `Runner` trait

A runner is anything that implements:

```rust
pub trait Runner: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> &RunnerCapabilities;
    async fn start_session(&self, ctx: SessionContext) -> Result<SessionHandle>;
    async fn run_turn(&self, sess: &mut SessionHandle, prompt: Prompt) -> Result<TurnOutcome>;
    fn stream_events(&self, sess: &SessionHandle) -> EventStream;
    async fn stop_session(&self, sess: SessionHandle) -> Result<UsageReport>;
}
```

The orchestrator drives this contract: it calls `start_session` once per
attempted run, `run_turn` for each prompt (retrying failed turns up to
`max_attempts`), `stream_events` for best-effort telemetry, and `stop_session`
to tear down. A turn resolves to one of:

| `TurnStatus` | Orchestrator action |
|--------------|---------------------|
| `Succeeded` | handoff → `review` |
| `Failed` / `TimedOut` / `Cancelled` | retry with backoff, or `blocked` on exhaustion |

## The shell runner contract

`ShellRunner` executes a resolved `RunnerSpec` directly as an **argv array**.
Four invariants matter for runner authors:

1. **Static argv — no field interpolation into the command.** The command and
   its args come from `RunnerSpec` (resolved from `WORKFLOW.md`); issue fields
   are **never** rendered into argv. This is a security property: an issue
   cannot influence which binary runs.

2. **The prompt is the only issue-content channel, and it goes over stdin.**
   The full prompt (the `WORKFLOW.md` template rendered with `{{ issue.* }}`)
   is written to the child's stdin. The child reads it however it likes; it
   must not expect issue data on the command line.

3. **Environment starts empty, then adds only declared vars.** The child does
   **not** inherit the daemon's environment. `WORKFLOW.md`-declared `env:` vars
   are provided; secret-like names (`*_TOKEN`, `*_KEY`, `SECRET_*`, …) are
   refused unless explicitly allow-listed via the runner's secret-allow list
   (see [`security.md`](./security.md) §4.3, four-rule block). Dangerous
   shell/linker vars (`BASH_ENV`, `LD_PRELOAD`, …) are always denied.

4. **Timeouts and bounded output.** Each turn is bounded by the spec's turn
   timeout; on timeout the runner kills the **whole process group** (not just
   the direct child), so forked grandchildren die too. Runner stdout/stderr is
   streamed through a bounded queue (no unbounded memory growth); overflow
   policy is consulted explicitly (`EventOverflowPolicy`).

These are all backed by proof tests: `proof_timeout_kills_forked_children_process_group`
and `proof_chatty_child_does_not_grow_output_memory_unboundedly`.

## Configuring the runner in `WORKFLOW.md`

```yaml
runner:
  kind: shell
  preset: claude_code        # optional: a named preset (see below)
  turn_timeout_ms: 3600000
  command: /bin/echo         # or rely on a preset's command
```

The `runner:` block is resolved by `RunnerSpec::from_workflow_config`. It
accepts either an explicit `command` (+ optional `args`) or a `preset`. Run
`x0x-symphony config check --config WORKFLOW.md` to validate the block before
starting the daemon.

## Adding a preset

Presets live in `crates/x0x-symphony-runner-shell/src/preset/`. A preset is a
named, validated mapping from a `PresetName` to a fully-formed `RunnerSpec`
(command + args + any required env allow-list entries). The current set:

`Codex`, `ClaudeCode`, `Kimi`, `Glm`, `Minimax`, `Pi`.

### Built-in preset contracts (pinned harness versions)

Each verified preset is pinned to the harness version it was last tested
against (issue #7 — the v0.1.2 `pi`/`claude_code` argvs failed the installed
CLIs' argument parsers):

| Preset | Resolved argv | Tested harness version |
|--------|---------------|------------------------|
| `claude_code` | `claude --print --output-format stream-json --verbose` | Claude Code 2.1.208 (`--verbose` is mandatory with `--print --output-format stream-json`) |
| `pi` | `pi --print` | pi 0.80.3 (non-interactive; reads the prompt from stdin. `--stdin` is rejected) |
| `codex` | `codex exec` | codex-cli 0.144.1 (non-interactive; reads the prompt from stdin. The old `codex app-server` argv speaks JSON-RPC and cannot consume a rendered prompt) |
| `kimi`, `glm`, `minimax` | `<cmd> --stdin` | **unverified** config-only placeholders — pin their contract before relying on them |

If your installed harness version diverges from the pinned one, do not patch
the preset ad hoc: override the command/args in `WORKFLOW.md` instead. Both a
full replacement (`runner.command` + `runner.args`) and a per-preset override
block (`runner.claude_code.args`, `runner.pi.args`, `runner.codex.args`, …)
are supported, and stay static argv — the rendered prompt still arrives on
stdin, never via shell interpolation.

Verify the pinned contracts against the harnesses installed on your machine
with `just preset-smoke` (gated behind `X0X_SYMPHONY_PRESET_SMOKE=1`; skips
harnesses that are not on `PATH`, and only fails on argv/usage rejections,
not on auth or other runtime errors).

To add one:

1. Add the variant to `PresetName` (`preset/mod.rs`), including its
   `as_str()`, `parse()`, and `Display`/`FromStr` arms so it round-trips.
2. Add the variant to `all()`.
3. Resolve it to a `RunnerSpec` (command + argv). Presets are
   **configuration-only**: they produce a command + argv, never inline issue
   fields (invariant #1 above).
4. Add a test that the preset YAML resolves to a runnable spec (mirror the
   existing `*_preset_yaml_resolves_to_runnable_spec` tests in
   `crates/x0x-symphony-runner-shell/tests/run_smoke.rs`).
5. Re-run `just check` (the preset tests are part of the suite).

## A worked example: a stub shell runner

The simplest valid runner is a script that reads the prompt from stdin and
exits 0. This is exactly what the §2 demo and the M1 proof transcripts use.

`scripts/stub-runner.sh`:

```sh
#!/usr/bin/env sh
# Read the rendered prompt from stdin and succeed.
cat > /dev/null
exit 0
```

A `WORKFLOW.md` that uses it:

```yaml
---
runner:
  kind: shell
  command: ./scripts/stub-runner.sh
  turn_timeout_ms: 5000
# … tracker / polling / workspace / hooks / agent blocks …
---
{{ issue.description }}
```

On dispatch the orchestrator claims the issue, the shell runner spawns
`./scripts/stub-runner.sh`, streams the rendered prompt to its stdin, the
script exits 0 → `TurnStatus::Succeeded` → the orchestrator writes a handoff
and moves the issue to `review`. That full flow is reproduced in
`proofs/m1/demo-transcript.md`.

## Runner authoring checklist

- [ ] The command and args come from `RunnerSpec` only — no `issue.*` in argv.
- [ ] Issue content reaches the child **only** via stdin (the prompt).
- [ ] Env starts empty; declare every var; allow-list any secret-like name.
- [ ] Honour the turn timeout; assume the orchestrator will PG-kill on expiry.
- [ ] Stream output, do not buffer unboundedly.
- [ ] `x0x-symphony config check --config WORKFLOW.md` passes.
- [ ] `just check` green.
