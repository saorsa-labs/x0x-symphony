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
  "schema_version": 1,
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

`schema_version` is written on every record. Version `1` is the M2 freeze.
Legacy records without the field are read as v1 and upgraded on the next write.

## Schema versioning & freeze (M2)

M2 is the schema freeze point. `schema_version: 1` freezes the issue, issue
reference, state, shard, claim, and handoff fields that exist at M2.

Schema evolution after v1 is **additive-only**:

- New fields must be optional and require a `schema_version` bump.
- Existing v1 fields are never renamed, removed, or re-typed.
- Unknown top-level fields are preserved verbatim across read/write cycles.

Signatures (XSY-0020) cover the serialized claim/handoff payload as stored,
excluding only the signature envelope itself. Claim `heartbeat_at` is also
excluded intentionally: it is a mutable liveness signal, not an ownership
attestation, so heartbeat refreshes do not invalidate the claim signature.
Additive schema growth (new optional fields) can never invalidate an existing
signature when those fields are absent. `BTreeMap`-ordered unknown-field
preservation supports deterministic stored bytes for this rule.

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
    "issue_id":      "XSY-0001",
    "by":            "<agent_id_hex>",
    "at":            "2026-04-28T12:00:00Z",
    "heartbeat_at":  "2026-04-28T12:14:00Z",
    "shard_role":    "primary",
    "signature": {
      "algorithm":       "x0x.agent-sign.v2.ml-dsa-65",
      "context":         "x0x-symphony-claim-v1",
      "public_key_b64":  "<ml-dsa-65-public-key>",
      "signature_b64":   "<detached-ml-dsa-65-signature>",
      "payload_sha256":  "<hex-sha256-of-signed-payload>",
      "signer_agent_id": "<agent_id_hex>"
    }
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
    "proofs_dir": "proofs/XSY-0001/2026-04-28T12-15-00Z",
    "issue_id":   "XSY-0001",
    "signer_agent_id": "<agent_id_hex>",
    "signature": {
      "algorithm":       "x0x.agent-sign.v2.ml-dsa-65",
      "context":         "x0x-symphony-handoff-v1",
      "public_key_b64":  "<ml-dsa-65-public-key>",
      "signature_b64":   "<detached-ml-dsa-65-signature>",
      "payload_sha256":  "<hex-sha256-of-signed-payload>",
      "signer_agent_id": "<agent_id_hex>"
    }
  }
}
```

`proofs_dir` is a relative path inside the workspace where large
validation artefacts (full stdout, stderr, runner traces, fmt diffs)
are stored. Small status only lives inside `validation`.

When `handoff.signature` is present, `handoff.issue_id` and
`handoff.signer_agent_id` are required and are part of the signed payload. They
bind the handoff to one issue and one x0x signer so a valid handoff cannot be
replayed onto another issue.

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

> **Advisory snapshots — live resolution by `id` is authoritative.** The
> `state` embedded in each `blocked_by` entry is a write-time snapshot and
> may be stale (e.g. the blocker has since moved to `done`, as several
> seeded entries do). Treat it as **advisory-only**. Authoritative blocker
> resolution is **live by `id`**: an adapter must look up the referenced
> issue's *current* `state` and act on that, never the embedded snapshot.
> This is what the M1 `git_jsonl` adapter (XSY-0003) implements and what
> the 2026-07 M1 execution plan §8 mandates.

## Update rules

1. Keep `id` and `identifier` stable.
2. Use lowercase labels.
3. Use ISO-8601 UTC timestamps.
4. Agents may move their issue to `review`; humans move reviewed work
   to `done`.
5. Preserve unknown fields verbatim so future adapters can extend the model.
6. Additive schema changes require optional fields and a `schema_version` bump.
7. `shard` is written once at creation and never edited by agents.
8. `claim` is written and refreshed only by the orchestrator.

## CRDT adapter mapping

For the M3 `x0x_crdt` adapter, see
[`../docs/design/symphony.md`](../docs/design/symphony.md) §7.3.
