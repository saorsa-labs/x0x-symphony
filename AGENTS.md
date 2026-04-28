# AGENTS.md

Operating notes for coding agents (Codex, Claude Code, kimi, glm, minimax, pi,
shell-script runners) working inside an x0x-symphony workspace.

## Workspace contract

When x0x-symphony dispatches a task to you, your working directory is an
isolated checkout root. Stay inside it. The runner enforces root containment
and may terminate sessions that escape.

For x0x-symphony's own development, the workspace contains a single sibling
checkout:

```
<workspace_root>/
  x0x-symphony/    # primary; make changes here
```

For x0x development, the workspace contains:

```
<workspace_root>/
  x0x/
  ant-quic/
  saorsa-gossip/
```

## Required orientation

Before editing code:

1. Read `CLAUDE.md`.
2. Read `docs/design/symphony.md`.
3. Read any ADR or module directly relevant to the issue.
4. Check `issues/schema.md` so issue updates stay machine-readable.

## Project rules

- Use `just` recipes from `justfile` (or fall back to documented `cargo`
  commands when a recipe does not exist yet).
- Keep changes focused on the dispatched issue.
- Production Rust must avoid `unwrap`, `expect`, and `panic!`. Tests may use
  them.
- Use structured errors (`thiserror`, context-rich results).
- Do not edit secrets, local keys, or machine-specific configuration.
- Do not change files outside the issue workspace.

## Validation expectations

Run the narrowest useful validation while developing, then run broader checks
before handoff:

```bash
just fmt-check
just lint
just test
```

If a check cannot run because of missing dependencies, credentials, or host
limits, record that explicitly in the handoff.

## Handoff

The canonical issue database is `issues/issues.jsonl`. When you finish useful
work:

1. Update the issue record for `XSY-XXXX`.
2. Set `state` to `review` for human review, or leave it active if more agent
   work is required.
3. Update `updated_at`.
4. Add a `handoff` object with `summary`, `files_changed`, `validation`,
   `follow_up`.
5. Do not mark the issue `done`; humans close issues after review.

Validation artefacts larger than a few KiB go to
`proofs/<issue-id>/<utc-timestamp>/` and are linked from the handoff.
