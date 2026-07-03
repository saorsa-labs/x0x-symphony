# Partition reunion stress harness

[ADR-0002](../adr/0002-sharded-claim-ttl.md) defines the partition-reunion guarantee: if a lower-index shard owner
and a higher-index backup both claim during a network split, reunion keeps the
lower-index claim and the loser writes a conflict abandon record under
`proofs/<issue-id>/<timestamp>-abandoned/`.

`x0x-symphony` ships an ignored, phased live harness for this behavior. It is
not part of normal `cargo nextest run`; it only runs when an operator provides
two real `x0x-symphonyd` daemons and selects a phase explicitly.

## What it verifies

The harness drives two daemons, each fronting its own `x0xd`, through:

1. `create` — create a sharded task before the split and record its issue id.
2. `partitioned_claim` — while the operator-enforced partition is active, claim
   the same issue from both daemons and require both local claims to succeed.
3. `healed_verify` — after the partition is healed and the daemons restart to
   trigger startup reconcile, verify both sides converge on the lower-index
   shard owner and the loser has an `abandon.json` proof marker.

The lower-index conflict logic is unit-tested separately in the orchestrator;
this harness is the end-to-end, real-daemon exercise.

## Run it

The reproducible driver is:

```bash
SYMPHONY_PARTITION_X0XD_A_URL=http://127.0.0.1:12700 \
SYMPHONY_PARTITION_X0XD_B_URL=http://127.0.0.1:12701 \
SYMPHONY_PARTITION_CUT_CMD='<your tc/iptables/docker split command>' \
SYMPHONY_PARTITION_HEAL_CMD='<your heal command>' \
bash scripts/partition-stress.sh
```

If the cut/heal commands are omitted, the script pauses between phases so the
operator can apply and remove the network split manually.

The script creates a run directory under `proofs/XSY-0029/`, prepares matching
TaskList/KvStore resources on both `x0xd` daemons, starts both symphony daemons,
passes their API URLs/tokens to the ignored Rust test, and prints a final
PASS/FAIL summary.

## Limitations

- The test does not cut the network itself. A true split must be supplied by
  the operator or by `SYMPHONY_PARTITION_CUT_CMD` / `_HEAL_CMD`.
- Stopping a daemon is only a process-stop simulation. It may exercise restart
  and stale-claim paths, but it does **not** prove the live dual-claim network
  split described by [ADR-0002](../adr/0002-sharded-claim-ttl.md).
- The ignored Rust test compiles in normal workspace builds, but it is skipped
  by normal nextest runs unless `--ignored` and the required environment are
  supplied.
