# Git Issue Database Schema

`issues/issues.jsonl` contains one UTF-8 JSON object per line. The file is
intentionally line-oriented so agents and humans can update individual
records with small diffs.

This schema is shared between x0x and x0x-symphony so a single JSONL
adapter implementation can read both. Symphony-specific extensions are
documented inline.

## Required fields

```jsonc
{
  "id":          "XSY-0001",
  "identifier":  "XSY-0001",
  "title":       "Short imperative title",
  "description": "Markdown-capable description",
  "priority":    2,
  "state":       "todo",
  "branch_name": null,
  "url":         null,
  "labels":      ["x0x-symphony"],
  "blocked_by":  [],
  "created_at":  "2026-04-28T00:00:00Z",
  "updated_at":  "2026-04-28T00:00:00Z"
}
```

## Optional fields

Runners and agents may preserve or add:

- `acceptance` — list of acceptance criteria strings.
- `validation` — list of expected validation commands or checks.
- `assignee` — human or agent identifier.
- `estimate` — implementation-defined size estimate.
- `handoff` — final/most recent handoff summary from an agent.
- `links` — related docs, PRs, commits, or external references.

## Symphony extensions

Two symphony-specific top-level fields are defined; both are optional in
M1 and required in M2 onward. They are written by the orchestrator, not
hand-edited.

### `shard`

Frozen at task creation. See ADR-0002.

```jsonc
{
  "shard": {
    "primary":            "<agent_id_hex>",
    "backups":            ["<agent_id_hex>", "<agent_id_hex>"],
    "claim_ttl_ms":       3600000,
    "created_view_epoch": 17
  }
}
```

### `claim`

Present once a worker holds the issue. Updated on heartbeat.

```jsonc
{
  "claim": {
    "by":            "<agent_id_hex>",
    "at":            "2026-04-28T12:00:00Z",
    "heartbeat_at":  "2026-04-28T12:14:00Z",
    "shard_role":    "primary",
    "signature":     "<ml-dsa-65 sig hex>"
  }
}
```

### `handoff`

Same shape on x0x and x0x-symphony.

```jsonc
{
  "handoff": {
    "summary":        "What changed and why",
    "files_changed": ["path/to/file.rs"],
    "validation": [
      {"command": "just fmt-check", "status": "passed"}
    ],
    "follow_up":  ["Anything humans or later agents should know"],
    "proofs_dir": "proofs/XSY-0001/2026-04-28T12-15-00Z"
  }
}
```

`proofs_dir` is a relative path inside the workspace where large
validation artefacts (full stdout, stderr, runner traces, fmt diffs)
are stored. Small status only lives inside `validation`.

## State values

| State        | Meaning                                                     | Agent dispatch? |
|--------------|-------------------------------------------------------------|-----------------|
| `todo`       | Ready for an agent to start if blockers are clear.          | yes             |
| `in_progress`| Claimed or actively being worked.                           | yes (limited)   |
| `review`     | Agent completed useful work; human review required.         | no              |
| `blocked`    | Not dispatchable until blockers are resolved.               | no              |
| `done`       | Human accepted and closed.                                  | no              |
| `cancelled`  | No longer planned.                                          | no              |
| `duplicate`  | Superseded by another issue.                                | no              |

## Priority

Lower numbers are dispatched first:

- `1` — urgent / release-blocking
- `2` — high
- `3` — normal
- `4` — low
- `null` — unsorted backlog

## Blockers

`blocked_by` is a list of issue refs:

```json
[
  {"id": "XSY-0002", "identifier": "XSY-0002", "state": "todo"}
]
```

A `todo` issue with any non-terminal blocker must not be dispatched.

## Update rules

1. Keep `id` and `identifier` stable.
2. Use lowercase labels.
3. Use ISO-8601 UTC timestamps.
4. Agents may move their issue to `review`; humans move reviewed work
   to `done`.
5. Preserve unknown fields so future adapters can extend the model.
6. `shard` is written once at creation and never edited by agents.
7. `claim` is written and refreshed only by the orchestrator.

## CRDT adapter mapping

For the M3 `x0x_crdt` adapter, see
[`../docs/design/symphony.md`](../docs/design/symphony.md) §7.3.
