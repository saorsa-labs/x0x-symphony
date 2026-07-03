//! Deterministic shard assignment for issue ownership.
//!
//! Tracker adapters pass a live worker roster snapshot at issue creation time.
//! This module deliberately keeps the assignment pure so the frozen issue schema
//! does not depend on how that roster was discovered.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::{AgentId, IssueId, Shard};

/// Default number of shard owners: one primary plus two backups.
pub const DEFAULT_REPLICATION_FACTOR: usize = 3;

/// Default claim TTL stored on newly assigned shards: one hour.
pub const DEFAULT_CLAIM_TTL_MS: u64 = 3_600_000;

/// Legacy static worker-list view epoch used only by [`assign`].
///
/// Live issue creation should call [`assign_with_metadata`] with the `WorkerView`
/// epoch captured for that creation.
pub const STATIC_WORKER_VIEW_EPOCH: u64 = 1;

const NODE_ID_BYTES: usize = 32;
type NodeId = [u8; NODE_ID_BYTES];

/// Assign a frozen shard slate for `issue_id` using XOR distance.
///
/// The issue id and each unique worker id are hashed with SHA-256 and compared
/// as 32-byte node identifiers. The worker with the smallest XOR distance is
/// the primary; the next `k - 1` closest workers are backups. Ties are broken
/// by [`AgentId`] ordering so the result is deterministic even for duplicate
/// distances.
///
/// Returns `None` when `workers` is empty. The frozen v1 [`Shard`] schema has a
/// required `primary` field, so an empty M2 static roster is represented by no
/// shard record on the issue and claim code falls back to
/// [`crate::ShardRole::ManualM1`].
#[must_use]
pub fn assign(issue_id: &IssueId, workers: &[AgentId], k: usize) -> Option<Shard> {
    assign_with_metadata(
        issue_id,
        workers,
        k,
        DEFAULT_CLAIM_TTL_MS,
        STATIC_WORKER_VIEW_EPOCH,
    )
}

/// Assign a frozen shard slate with explicit metadata fields.
///
/// This is the same deterministic XOR-distance algorithm as [`assign`], but it
/// lets tracker adapters preserve per-task TTL and worker-view metadata without
/// changing the assignment order.
#[must_use]
pub fn assign_with_metadata(
    issue_id: &IssueId,
    workers: &[AgentId],
    k: usize,
    claim_ttl_ms: u64,
    created_view_epoch: u64,
) -> Option<Shard> {
    let target = node_id(issue_id.as_str());
    let mut ranked = unique_workers(workers)
        .into_iter()
        .map(|worker| (xor_distance(&target, &node_id(worker.as_str())), worker))
        .collect::<Vec<_>>();
    ranked.sort_by(
        |(left_distance, left_worker), (right_distance, right_worker)| {
            left_distance
                .cmp(right_distance)
                .then_with(|| left_worker.cmp(right_worker))
        },
    );

    let primary = ranked.first().map(|(_, worker)| worker.clone())?;
    let backup_count = k.saturating_sub(1).min(ranked.len().saturating_sub(1));
    let backups = ranked
        .iter()
        .skip(1)
        .take(backup_count)
        .map(|(_, worker)| worker.clone())
        .collect();

    Some(Shard::new(
        primary,
        backups,
        claim_ttl_ms,
        created_view_epoch,
    ))
}

fn unique_workers(workers: &[AgentId]) -> Vec<AgentId> {
    workers
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn node_id(value: &str) -> NodeId {
    let digest = Sha256::digest(value.as_bytes());
    let mut id = [0_u8; NODE_ID_BYTES];
    id.copy_from_slice(&digest);
    id
}

fn xor_distance(left: &NodeId, right: &NodeId) -> NodeId {
    std::array::from_fn(|index| left[index] ^ right[index])
}
