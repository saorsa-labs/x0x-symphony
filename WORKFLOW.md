---
# x0x-symphony's own bootstrap workflow profile.
#
# This file dogfoods x0x-symphony against itself: the runner reads this
# WORKFLOW.md when developing x0x-symphony, the same way it reads x0x's
# WORKFLOW.md when developing x0x.
tracker:
  kind: git_issues
  path: issues/issues.jsonl
  project_slug: x0x-symphony
  active_states:
    - todo
    - in_progress
  terminal_states:
    - done
    - cancelled
    - duplicate
  review_states:
    - review
  blocked_states:
    - blocked
  id_prefix: XSY
  lock_mode: git

polling:
  interval_ms: 30000

workspace:
  # Each issue workspace contains:
  #   <root>/<issue>/x0x-symphony
  # Optional sibling checkouts (x0x, ant-quic, saorsa-gossip) may be added
  # by the after_create hook for cross-repo work.
  root: ~/x0x-symphony/workspaces

hooks:
  timeout_ms: 120000

  after_create: |
    set -euo pipefail
    git clone "${X0X_SYMPHONY_REPO_URL:-https://github.com/saorsa-labs/x0x-symphony.git}" x0x-symphony
    git -C x0x-symphony status --short

  before_run: |
    set -euo pipefail
    test -d x0x-symphony/.git
    test -f x0x-symphony/CLAUDE.md
    test -f x0x-symphony/AGENTS.md
    test -f x0x-symphony/justfile

  after_run: |
    set +e
    if [ -d x0x-symphony ]; then
      ( cd x0x-symphony && just fmt-check && just lint )
    fi

  before_remove: |
    set +e
    git -C x0x-symphony status --short || true

agent:
  max_concurrent_agents: 2
  max_concurrent_agents_by_state:
    todo: 1
    in_progress: 1
  max_turns: 8
  max_retry_backoff_ms: 300000

# Default runner: shell. Operators may configure a preset (codex,
# claude_code, kimi, glm, minimax, pi) via runner.preset.
runner:
  kind: shell
  preset: claude_code
  approval_policy: untrusted
  turn_timeout_ms: 3600000
  read_timeout_ms: 5000
  stall_timeout_ms: 300000
---
# x0x-symphony Agent Workflow

You are working on x0x-symphony issue `{{ issue.identifier }}`:
**{{ issue.title }}**.

The Symphony workspace root for this issue contains:

- `x0x-symphony/` — primary repository. Make issue changes here.

## Issue context

- State: `{{ issue.state }}`
- Priority: `{{ issue.priority }}`
- Labels: `{{ issue.labels }}`
- URL/source: `{{ issue.url }}`
- Attempt: `{{ attempt }}`

Description:

{{ issue.description }}

## Required orientation

Before editing code:

1. Read `x0x-symphony/CLAUDE.md`.
2. Read `x0x-symphony/AGENTS.md`.
3. Read `x0x-symphony/docs/design/symphony.md`.
4. Read any ADR or module directly relevant to the issue.
5. Check `x0x-symphony/issues/schema.md` so issue updates stay
   machine-readable.

## Project rules

- Use `just` recipes from `x0x-symphony/justfile`.
- Keep changes focused on this issue.
- Production Rust must avoid `unwrap`, `expect`, and `panic!`. Tests
  may use them.
- Use structured errors (`thiserror`, context-rich results).
- Do not edit secrets, local keys, or machine-specific config.
- Do not change files outside this issue workspace.

## Validation expectations

```bash
cd x0x-symphony
just fmt-check
just lint
just test
```

For documentation-only changes, at minimum run:

```bash
cd x0x-symphony
just fmt-check
```

If a check cannot run because of missing local dependencies, credentials,
or host limits, record that explicitly in the handoff.

## Issue database handoff

The canonical bootstrap issue database is `x0x-symphony/issues/issues.jsonl`.

When you finish useful work:

1. Update the issue record for `{{ issue.identifier }}`.
2. Set `state` to `review` for human review, or leave it active if more
   agent work is required.
3. Update `updated_at`.
4. Add a `handoff` object with `summary`, `files_changed`, `validation`,
   `follow_up`. If proof artefacts exceed a few KiB, write them to
   `proofs/{{ issue.identifier }}/<utc-timestamp>/` and reference via
   `handoff.proofs_dir`.
5. Do not mark the issue `done`; humans close issues after review.

## Final response

Summarize:

- what changed
- files touched
- validation run and result
- any risks or follow-up
