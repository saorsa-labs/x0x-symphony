//! Retention cleanup for proof artefact directories.
//!
//! Proof runs are stored as `proofs/<issue-id>/<timestamp>/`, where the
//! timestamp segment is produced by `ProofRun` in `proofs.rs` using the
//! `%Y-%m-%dT%H%M%SZ` UTC format plus an optional `-NN` collision suffix.
//! The reaper walks only those timestamp directories and never deletes proof
//! trees for issues reported as active by the daemon.

use std::{collections::BTreeSet, io, path::Path};

use chrono::{DateTime, NaiveDateTime, Utc};
use tokio::fs::{self, DirEntry, ReadDir};
use tracing::warn;
use x0x_symphony_core::IssueId;

const PROOF_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H%M%SZ";
const PROOF_TIMESTAMP_LEN: usize = "YYYY-MM-DDTHHMMSSZ".len();
const COLLISION_SUFFIX_LEN: usize = 3;

/// Summary of one proof retention scan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReapReport {
    /// Timestamp directories visited under issue-id proof directories.
    pub scanned: u32,
    /// Timestamp directories successfully deleted.
    pub reaped: u32,
    /// Timestamp directories skipped because their issue is active/in-progress.
    pub skipped_active: u32,
    /// Deletion attempts that failed and were logged.
    pub errors: u32,
}

impl ReapReport {
    const fn record_scanned(&mut self) {
        self.scanned = self.scanned.saturating_add(1);
    }

    const fn record_reaped(&mut self) {
        self.reaped = self.reaped.saturating_add(1);
    }

    const fn record_skipped_active(&mut self) {
        self.skipped_active = self.skipped_active.saturating_add(1);
    }

    const fn record_error(&mut self) {
        self.errors = self.errors.saturating_add(1);
    }
}

/// Reap proof run directories older than `retention_days`.
///
/// The scan is race-safe with active work: every timestamp directory whose
/// issue id appears in `active_issue_ids` is skipped before timestamp parsing
/// or deletion. Timestamp names that do not match the exact `ProofRun` naming
/// format are logged and preserved. Filesystem traversal and deletion failures
/// are best-effort; deletion failures increment [`ReapReport::errors`].
#[must_use]
pub async fn reap_old_proofs(
    proofs_dir: &Path,
    now: DateTime<Utc>,
    retention_days: u32,
    active_issue_ids: &BTreeSet<IssueId>,
) -> ReapReport {
    let Some(cutoff) = retention_cutoff(now, retention_days) else {
        warn!(
            retention_days,
            "proof retention window is too large for the current clock; skipping proof reaper scan"
        );
        return ReapReport::default();
    };

    let mut report = ReapReport::default();
    let Some(mut issue_entries) = open_proofs_dir(proofs_dir).await else {
        return report;
    };

    while let Some(issue_entry) = next_entry(&mut issue_entries, proofs_dir).await {
        process_issue_entry(issue_entry, cutoff, active_issue_ids, &mut report).await;
    }

    report
}

async fn process_issue_entry(
    issue_entry: DirEntry,
    cutoff: DateTime<Utc>,
    active_issue_ids: &BTreeSet<IssueId>,
    report: &mut ReapReport,
) {
    if !is_directory(&issue_entry).await {
        return;
    }
    let Some(issue_name) = entry_name(&issue_entry) else {
        return;
    };
    let issue_id = match IssueId::new(issue_name.clone()) {
        Ok(issue_id) => issue_id,
        Err(source) => {
            warn!(issue = issue_name, %source, "skipping proof issue directory with invalid id");
            return;
        }
    };
    let issue_path = issue_entry.path();
    let Some(mut timestamp_entries) = open_issue_dir(&issue_path).await else {
        return;
    };
    let issue_is_active = active_issue_ids.contains(&issue_id);

    while let Some(timestamp_entry) = next_entry(&mut timestamp_entries, &issue_path).await {
        process_timestamp_entry(timestamp_entry, cutoff, issue_is_active, report).await;
    }
}

async fn process_timestamp_entry(
    timestamp_entry: DirEntry,
    cutoff: DateTime<Utc>,
    issue_is_active: bool,
    report: &mut ReapReport,
) {
    if !is_directory(&timestamp_entry).await {
        return;
    }
    report.record_scanned();
    if issue_is_active {
        report.record_skipped_active();
        return;
    }

    let Some(timestamp_name) = entry_name(&timestamp_entry) else {
        return;
    };
    let Some(started_at) = parse_proof_timestamp(timestamp_name.as_str()) else {
        warn!(
            timestamp = timestamp_name,
            path = %timestamp_entry.path().display(),
            "skipping proof directory with unparseable timestamp"
        );
        return;
    };
    if started_at < cutoff {
        delete_timestamp_dir(timestamp_entry.path(), report).await;
    }
}

async fn delete_timestamp_dir(path: std::path::PathBuf, report: &mut ReapReport) {
    match fs::remove_dir_all(&path).await {
        Ok(()) => report.record_reaped(),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            warn!(path = %path.display(), %source, "failed to delete old proof directory");
            report.record_error();
        }
    }
}

async fn open_proofs_dir(proofs_dir: &Path) -> Option<ReadDir> {
    match fs::read_dir(proofs_dir).await {
        Ok(entries) => Some(entries),
        Err(source) if source.kind() == io::ErrorKind::NotFound => None,
        Err(source) => {
            warn!(path = %proofs_dir.display(), %source, "failed to scan proofs directory");
            None
        }
    }
}

async fn open_issue_dir(issue_path: &Path) -> Option<ReadDir> {
    match fs::read_dir(issue_path).await {
        Ok(entries) => Some(entries),
        Err(source) => {
            warn!(path = %issue_path.display(), %source, "failed to scan proof issue directory");
            None
        }
    }
}

async fn next_entry(entries: &mut ReadDir, parent: &Path) -> Option<DirEntry> {
    match entries.next_entry().await {
        Ok(entry) => entry,
        Err(source) => {
            warn!(path = %parent.display(), %source, "failed to read proof directory entry");
            None
        }
    }
}

async fn is_directory(entry: &DirEntry) -> bool {
    match entry.file_type().await {
        Ok(file_type) => file_type.is_dir(),
        Err(source) => {
            warn!(path = %entry.path().display(), %source, "failed to read proof path type");
            false
        }
    }
}

fn entry_name(entry: &DirEntry) -> Option<String> {
    let name = entry.file_name();
    let Some(name) = name.to_str() else {
        warn!(path = %entry.path().display(), "skipping proof path with non-UTF-8 name");
        return None;
    };
    Some(name.to_owned())
}

fn retention_cutoff(now: DateTime<Utc>, retention_days: u32) -> Option<DateTime<Utc>> {
    let retention = chrono::Duration::try_days(i64::from(retention_days))?;
    now.checked_sub_signed(retention)
}

fn parse_proof_timestamp(name: &str) -> Option<DateTime<Utc>> {
    let timestamp = timestamp_prefix(name)?;
    let naive = NaiveDateTime::parse_from_str(timestamp, PROOF_TIMESTAMP_FORMAT).ok()?;
    Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

fn timestamp_prefix(name: &str) -> Option<&str> {
    if name.len() == PROOF_TIMESTAMP_LEN {
        return Some(name);
    }
    if name.len() != PROOF_TIMESTAMP_LEN + COLLISION_SUFFIX_LEN {
        return None;
    }
    let prefix = name.get(..PROOF_TIMESTAMP_LEN)?;
    let suffix = name.get(PROOF_TIMESTAMP_LEN..)?;
    is_collision_suffix(suffix).then_some(prefix)
}

fn is_collision_suffix(suffix: &str) -> bool {
    let bytes = suffix.as_bytes();
    bytes.len() == COLLISION_SUFFIX_LEN
        && bytes[0] == b'-'
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
        && !(bytes[1] == b'0' && bytes[2] == b'0')
}
