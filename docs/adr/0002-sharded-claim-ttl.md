# ADR-0002 — Sharded ownership with TTL fallback

**Status:** Accepted (2026-04-28)
**Deciders:** David Irvine
**Context:** M0 design; relates to ADR-0001

## Context

Two trusted agents must not silently both work the same issue. A central
tracker prevents this with a synchronous claim-and-lock; x0x-symphony
cannot do that without forfeiting partition tolerance, which is a v1.0
invariant.

Three options were considered:

1. **Lease + leader.** Strong consistency. Forfeits partition tolerance.
   Rejected.
2. **Deterministic tiebreak.** First-signed-claim wins by timestamp +
   agent-id hash. Cheap; wastes work in every partition.
3. **Sharded ownership with TTL fallback.** Each task is bound at
   creation to a primary owner and an ordered list of backup owners.
   Backups may take over only after the primary's heartbeat goes stale.

## Decision

Adopt sharded ownership with TTL fallback. The shard slate is frozen at
task creation and stored on the task record:

```jsonc
{
  "shard": {
    "primary":              "<agent_id>",
    "backups":              ["<agent_id>", "<agent_id>"],
    "claim_ttl_ms":         3600000,
    "created_view_epoch":   17
  }
}
```

`primary` and `backups` are the three closest trusted agents to
`hash(task_id)` by XOR distance, taken from the trusted-worker view at
creation time. The view epoch is recorded for audit.

Claim rules:

1. The primary may always claim.
2. A backup may claim only if `now - claim.heartbeat_at > claim_ttl_ms`,
   or if no claim exists.
3. Anyone else is rejected.
4. Heartbeat updates run at `claim_ttl / 4` cadence and are CRDT LWW
   writes.

Partition reunion produces at most two valid claim records. Tiebreak:
lower-index shard slot wins (primary > backup_0 > backup_1). The loser
writes an `abandon` record citing the conflict. Their work product is
preserved as `proofs/<issue>/<ts>-abandoned/` for human review; the
issue's accepted handoff references the winner only.

`claim_ttl_ms` defaults to 1 hour. Operators may override per task.

## Consequences

- The system never blocks on a quorum. Partition tolerance is preserved.
- In rare partition windows that exceed the TTL, two agents may
  duplicate work. This cost is accepted by design and observable in
  operations (every abandon record is a metric).
- Shard assignment does not re-shuffle when new trusted workers join.
  A reshard is an explicit signed operator event and must be rare; this
  keeps the data plane stable.
- Shard fields must be present in the data model from M2 onward, even
  though the M1 single-host runner does not enforce them. M2 freezes
  the schema so M3 does not migrate.
