//! Bootstrap git-backed JSONL tracker adapter for x0x-symphony.
//!
//! This crate implements [`x0x_symphony_core::Tracker`] for the M1–M2
//! bootstrap period by reading and rewriting one JSON object per line in
//! `issues/issues.jsonl`. It is deliberately temporary: ADR-0003 states that
//! v1.0 ships without external or file-backed trackers, and XSY-0024 deletes
//! this adapter when the M3 `x0x_crdt` tracker becomes the permanent backend.
//!
//! # Concurrency and lock semantics (operators must read this)
//!
//! State transitions are serialized on a single host with a file lock:
//!
//! 1. **Lock path.** The adapter locks `<git-dir>/index.lock` — the *same*
//!    path `git` uses for its own index updates — using `create_new`
//!    (exclusive create). The lock guard is released *before* the adapter
//!    runs `git add`/`git commit`, so git can re-acquire its own index lock.
//!    Consequence: **concurrent operator `git` operations** (e.g. a manual
//!    `git commit`, `git add`, or a second symphony process) contend on this
//!    one path. If contention exceeds the retry budget the adapter returns
//!    [`TrackerError::LockExhausted`] rather than corrupting the file.
//!
//! 2. **Stale foreign locks are not removed.** The guard's `Drop` impl deletes
//!    only the lock file *this process* created. If a previous process
//!    crashed while holding `index.lock`, the orphaned file persists and
//!    `create_new` keeps failing `AlreadyExists` until `LockExhausted`. A
//!    human must remove the stale `<git-dir>/index.lock` by hand. (Removing
//!    foreign locks automatically would require a liveliness probe and is
//!    tracked as a resilience follow-up; see XSY-0040.)
//!
//! 3. **Commits skip hooks.** The adapter commits with `git commit
//!    --no-verify`. This is deliberate: the tracker owns the repository's
//!    issue lines and must not be blocked by pre-commit/pre-push hooks the
//!    operator may have installed. Operators who rely on hooks for policy
//!    must enforce it out-of-band.
//!
//! See `docs/symphony/operator.md` for the operator-facing summary.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod signing;

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{SecondsFormat, Utc};
use serde_json::Value;
use thiserror::Error;
use tracing::{info, warn};
use x0x_symphony_core::{
    sha256_hex, shard, AgentId, Claim, Handoff, Issue, IssueId, IssueState, PollContext,
    ReleaseReason, ReleaseReasonCode, Result as CoreResult, Shard, ShardRole, SignatureEnvelope,
    SymphonyError, Tracker, CLAIM_CONTEXT, HANDOFF_CONTEXT, SIGN_ALGORITHM,
};

use crate::signing::{SignResponse, SigningClient, SigningPolicy, TrustedKeyResolver};

/// Result alias used by the git JSONL tracker adapter.
pub type Result<T> = std::result::Result<T, TrackerError>;

/// Structured errors produced by the git JSONL tracker adapter.
#[derive(Debug, Error)]
pub enum TrackerError {
    /// A JSONL record failed schema validation.
    #[error("schema violation at line {line}: {reason}")]
    Schema {
        /// One-based line number in `issues/issues.jsonl`.
        line: usize,
        /// Human-readable validation failure.
        reason: String,
    },

    /// The adapter could not acquire its serialization lock within the retry budget.
    #[error("lock acquisition exhausted for {path} after {attempts} attempts")]
    LockExhausted {
        /// Lock path that could not be acquired.
        path: PathBuf,
        /// Number of attempts that were made.
        attempts: u32,
    },

    /// The issue identifier was not present in the JSONL file.
    #[error("issue {id} not found")]
    IssueNotFound {
        /// Missing issue identifier.
        id: IssueId,
    },

    /// The requested issue cannot be claimed in its current state.
    #[error("issue {id} is not claimable: {reason}")]
    ClaimRejected {
        /// Issue that rejected the claim.
        id: IssueId,
        /// Human-readable rejection reason.
        reason: String,
    },

    /// A mutation attempted to change the frozen shard slate on an existing issue.
    #[error("issue {id} shard fields are immutable after creation")]
    ShardMutationRejected {
        /// Issue whose shard metadata changed after creation.
        id: IssueId,
    },

    /// The claim supplied to a transition is incomplete or stale.
    #[error("invalid claim: {reason}")]
    InvalidClaim {
        /// Human-readable claim validation failure.
        reason: String,
    },

    /// A file changed while the non-git mtime fallback was protecting a transition.
    #[error("concurrent modification detected for {path}")]
    ConcurrentModification {
        /// File whose mtime changed during a guarded transition.
        path: PathBuf,
    },

    /// A git command failed.
    #[error("git command `{command}` failed with status {status:?}: {stderr}")]
    Git {
        /// Human-readable command name and arguments.
        command: String,
        /// Process exit status, or `None` when the process ended without one.
        status: Option<i32>,
        /// Captured standard error.
        stderr: String,
    },

    /// Adapter I/O failed at a path.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// JSON serialization failed after the record had already passed schema validation.
    #[error("JSON serialization error: {source}")]
    Json {
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },

    /// Signing or verification failed.
    #[error("signing error: {0}")]
    Signing(String),

    /// Core domain validation failed while constructing an adapter value.
    #[error(transparent)]
    Core(#[from] SymphonyError),
}

impl From<TrackerError> for SymphonyError {
    fn from(error: TrackerError) -> Self {
        match error {
            TrackerError::Core(source) => source,
            other => Self::Tracker(other.to_string()),
        }
    }
}

/// Draft data used when creating a new issue through the JSONL adapter.
#[derive(Clone, Debug, PartialEq)]
pub struct IssueDraft {
    title: String,
    description: String,
    priority: Option<u8>,
    labels: Vec<String>,
    blocked_by: Vec<x0x_symphony_core::IssueRef>,
}

impl IssueDraft {
    /// Create an issue draft with the required title.
    ///
    /// # Errors
    ///
    /// Returns [`TrackerError::Core`] when the title is empty.
    pub fn new(title: impl Into<String>) -> Result<Self> {
        let title = title.into();
        if title.trim().is_empty() {
            return Err(SymphonyError::validation("issue.title", "must not be empty").into());
        }
        Ok(Self {
            title,
            description: String::new(),
            priority: None,
            labels: Vec::new(),
            blocked_by: Vec::new(),
        })
    }

    /// Return a copy with a markdown-capable description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Return a copy with a dispatch priority.
    #[must_use]
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Return a copy with one lowercase label appended.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.labels.push(label.into());
        self
    }

    /// Return a copy with one blocker reference appended.
    #[must_use]
    pub fn with_blocker(mut self, blocker: x0x_symphony_core::IssueRef) -> Self {
        self.blocked_by.push(blocker);
        self
    }
}

#[derive(Clone)]
struct SigningRuntime {
    policy: SigningPolicy,
    client: Option<Arc<dyn SigningClient>>,
    resolver: Option<Arc<dyn TrustedKeyResolver>>,
}

impl SigningRuntime {
    const fn disabled() -> Self {
        Self {
            policy: SigningPolicy::Disabled,
            client: None,
            resolver: None,
        }
    }

    fn required(client: Arc<dyn SigningClient>, resolver: Arc<dyn TrustedKeyResolver>) -> Self {
        Self {
            policy: SigningPolicy::Required,
            client: Some(client),
            resolver: Some(resolver),
        }
    }

    fn new(
        policy: SigningPolicy,
        client: Option<Arc<dyn SigningClient>>,
        resolver: Option<Arc<dyn TrustedKeyResolver>>,
    ) -> Self {
        Self {
            policy,
            client,
            resolver,
        }
    }

    fn client(&self) -> Result<&dyn SigningClient> {
        self.client
            .as_deref()
            .ok_or_else(|| TrackerError::Signing("signing client is not configured".to_owned()))
    }

    fn resolver(&self) -> Result<&dyn TrustedKeyResolver> {
        self.resolver.as_deref().ok_or_else(|| {
            TrackerError::Signing("trusted key resolver is not configured".to_owned())
        })
    }
}

/// Builder for [`JsonlTracker`].
#[derive(Clone)]
pub struct JsonlTrackerBuilder {
    repo_root: PathBuf,
    issues_path: PathBuf,
    git_binary: OsString,
    lock_attempts: u32,
    lock_initial_backoff: Duration,
    lock_max_backoff: Duration,
    signing: SigningRuntime,
    shard_workers: Vec<AgentId>,
    shard_replication_factor: usize,
}

impl JsonlTrackerBuilder {
    /// Create a builder rooted at a repository or plain directory.
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        let repo_root = repo_root.into();
        let issues_path = repo_root.join("issues").join("issues.jsonl");
        Self {
            repo_root,
            issues_path,
            git_binary: OsString::from("git"),
            lock_attempts: 50,
            lock_initial_backoff: Duration::from_millis(10),
            lock_max_backoff: Duration::from_millis(250),
            signing: SigningRuntime::disabled(),
            shard_workers: Vec::new(),
            shard_replication_factor: shard::DEFAULT_REPLICATION_FACTOR,
        }
    }

    /// Use a non-default JSONL file path.
    #[must_use]
    pub fn issues_path(mut self, issues_path: impl Into<PathBuf>) -> Self {
        self.issues_path = issues_path.into();
        self
    }

    /// Use a non-default git executable.
    #[must_use]
    pub fn git_binary(mut self, git_binary: impl Into<OsString>) -> Self {
        self.git_binary = git_binary.into();
        self
    }

    /// Set the number of bounded lock acquisition attempts.
    #[must_use]
    pub fn lock_attempts(mut self, attempts: u32) -> Self {
        self.lock_attempts = if attempts == 0 { 1 } else { attempts };
        self
    }

    /// Set the linear backoff bounds used while waiting for the lock.
    #[must_use]
    pub fn lock_backoff(mut self, initial: Duration, max: Duration) -> Self {
        self.lock_initial_backoff = initial;
        self.lock_max_backoff = max;
        self
    }

    /// Enable required signing with injected client and trusted-key resolver.
    #[must_use]
    pub fn required_signing(
        mut self,
        client: Arc<dyn SigningClient>,
        resolver: Arc<dyn TrustedKeyResolver>,
    ) -> Self {
        self.signing = SigningRuntime::required(client, resolver);
        self
    }

    /// Set an explicit signing policy and optional signing dependencies.
    #[must_use]
    pub fn signing(
        mut self,
        policy: SigningPolicy,
        client: Option<Arc<dyn SigningClient>>,
        resolver: Option<Arc<dyn TrustedKeyResolver>>,
    ) -> Self {
        self.signing = SigningRuntime::new(policy, client, resolver);
        self
    }

    /// Configure the static M2 worker roster used for new issue shard assignment.
    ///
    /// This is intentionally a loud placeholder: M4 replaces this static list
    /// with live x0x presence-based trusted-worker discovery. Existing issue
    /// shard slates remain immutable regardless of later worker-list churn.
    #[must_use]
    pub fn shard_workers(mut self, workers: Vec<AgentId>) -> Self {
        self.shard_workers = workers;
        self
    }

    /// Configure the total number of shard owners for newly created issues.
    ///
    /// A value of `3` means one primary plus two backups. The assignment
    /// function saturates edge cases, so values larger than the static roster
    /// simply use every configured worker once.
    #[must_use]
    pub fn shard_replication_factor(mut self, replication_factor: usize) -> Self {
        self.shard_replication_factor = replication_factor;
        self
    }

    /// Build the tracker adapter.
    #[must_use]
    pub fn build(self) -> JsonlTracker {
        JsonlTracker {
            repo_root: self.repo_root,
            issues_path: self.issues_path,
            git_binary: self.git_binary,
            lock_attempts: self.lock_attempts,
            lock_initial_backoff: self.lock_initial_backoff,
            lock_max_backoff: self.lock_max_backoff,
            signing: self.signing,
            shard_workers: self.shard_workers,
            shard_replication_factor: self.shard_replication_factor,
        }
    }
}

impl std::fmt::Debug for JsonlTrackerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonlTrackerBuilder")
            .field("repo_root", &self.repo_root)
            .field("issues_path", &self.issues_path)
            .field("git_binary", &self.git_binary)
            .field("lock_attempts", &self.lock_attempts)
            .field("lock_initial_backoff", &self.lock_initial_backoff)
            .field("lock_max_backoff", &self.lock_max_backoff)
            .field("signing_policy", &self.signing.policy)
            .field("shard_workers", &self.shard_workers)
            .field("shard_replication_factor", &self.shard_replication_factor)
            .finish_non_exhaustive()
    }
}

/// Tracker adapter backed by `issues/issues.jsonl` and git commits.
#[derive(Clone)]
pub struct JsonlTracker {
    repo_root: PathBuf,
    issues_path: PathBuf,
    git_binary: OsString,
    lock_attempts: u32,
    lock_initial_backoff: Duration,
    lock_max_backoff: Duration,
    signing: SigningRuntime,
    shard_workers: Vec<AgentId>,
    shard_replication_factor: usize,
}

impl std::fmt::Debug for JsonlTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonlTracker")
            .field("repo_root", &self.repo_root)
            .field("issues_path", &self.issues_path)
            .field("git_binary", &self.git_binary)
            .field("lock_attempts", &self.lock_attempts)
            .field("lock_initial_backoff", &self.lock_initial_backoff)
            .field("lock_max_backoff", &self.lock_max_backoff)
            .field("signing_policy", &self.signing.policy)
            .field("shard_workers", &self.shard_workers)
            .field("shard_replication_factor", &self.shard_replication_factor)
            .finish_non_exhaustive()
    }
}

impl JsonlTracker {
    /// Create a tracker with default settings for `repo_root`.
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self::builder(repo_root).build()
    }

    /// Create a tracker builder for `repo_root`.
    #[must_use]
    pub fn builder(repo_root: impl Into<PathBuf>) -> JsonlTrackerBuilder {
        JsonlTrackerBuilder::new(repo_root)
    }

    /// Return the JSONL file path used by this tracker.
    #[must_use]
    pub fn issues_path(&self) -> &Path {
        &self.issues_path
    }

    /// Load and validate every issue record from the JSONL file.
    ///
    /// # Errors
    ///
    /// Returns [`TrackerError::Schema`] on the first invalid line and logs the
    /// line number with `tracing::warn`; returns [`TrackerError::Io`] when the
    /// file cannot be read.
    pub fn load_issues(&self) -> Result<Vec<Issue>> {
        self.load_records().map(|records| {
            records
                .records
                .into_iter()
                .map(|record| record.issue)
                .collect()
        })
    }

    /// Create a new `todo` issue with a deterministic `XSY-` identifier.
    ///
    /// The allocated identifier is one greater than the maximum numeric
    /// `XSY-` suffix currently present in the JSONL file, padded to at least
    /// four digits.
    ///
    /// # Errors
    ///
    /// Returns an adapter error if the file cannot be locked, read, validated,
    /// written, or committed.
    pub fn create_issue(&self, draft: IssueDraft) -> Result<Issue> {
        let IssueDraft {
            title,
            description,
            priority,
            labels,
            blocked_by,
        } = draft;
        let mut created = None;
        self.with_records_mutation("x0x-symphony: create issue", |records| {
            let id = records.next_issue_id()?;
            let now = now_utc();
            let mut issue = Issue::new(
                id.clone(),
                id.as_str(),
                title,
                IssueState::new("todo")?,
                now,
            )?;
            issue.description = description;
            issue.priority = priority;
            issue.labels = labels;
            issue.blocked_by = blocked_by;
            issue.shard = shard::assign(&id, &self.shard_workers, self.shard_replication_factor);
            records.records.push(IssueRecord {
                raw_line: String::new(),
                issue: issue.clone(),
                dirty: true,
            });
            created = Some(issue);
            Ok(())
        })?;
        created.ok_or_else(|| TrackerError::InvalidClaim {
            reason: "issue creation did not produce a record".to_owned(),
        })
    }

    fn claim_issue(&self, id: &IssueId, agent_id: &AgentId) -> Result<Claim> {
        let claim = self.prepare_claim(id, agent_id)?;
        self.commit_claim(id, claim)
    }

    fn prepare_claim(&self, id: &IssueId, agent_id: &AgentId) -> Result<Claim> {
        let records = self.load_records()?;
        let record = records
            .find(id)
            .ok_or_else(|| TrackerError::IssueNotFound { id: id.clone() })?;
        ensure_issue_claimable(&record.issue, id)?;
        let shard_role = shard_role_for_agent(&record.issue, agent_id)?;
        Ok(Claim::new(
            Some(id.clone()),
            agent_id.clone(),
            now_utc(),
            shard_role,
        ))
    }

    fn commit_claim(&self, id: &IssueId, claim: Claim) -> Result<Claim> {
        let mut claimed = None;
        let message = format!("x0x-symphony: claim {id}");
        self.with_records_mutation(&message, |records| {
            let record = records.find_mut(id)?;
            ensure_issue_claimable(&record.issue, id)?;
            record.issue.state = IssueState::new("in_progress")?;
            record.issue.claim = Some(claim.clone());
            record.issue.updated_at = now_utc();
            record.dirty = true;
            claimed = Some(claim);
            Ok(())
        })?;
        claimed.ok_or_else(|| TrackerError::InvalidClaim {
            reason: "claim transition did not produce a claim".to_owned(),
        })
    }

    fn heartbeat_claim(&self, claim: &Claim) -> Result<()> {
        let id = claim_issue_id(claim)?;
        let message = format!("x0x-symphony: heartbeat {id}");
        self.with_records_mutation(&message, |records| {
            let record = records.find_mut(&id)?;
            ensure_claim_owner(&record.issue, claim)?;
            let now = now_utc();
            let refreshed = claim.clone().with_heartbeat(now.clone());
            record.issue.claim = Some(refreshed);
            record.issue.updated_at = now;
            record.dirty = true;
            Ok(())
        })
    }

    fn release_claim(&self, claim: &Claim, reason: &ReleaseReason) -> Result<()> {
        let id = claim_issue_id(claim)?;
        let message = format!("x0x-symphony: release {id}");
        self.with_records_mutation(&message, |records| {
            let record = records.find_claim_mut(&id, claim)?;
            ensure_claim_owner(&record.issue, claim)?;
            info!(
                issue_id = %id,
                agent_id = %claim.by,
                reason_code = reason.code.as_str(),
                reason = reason.message.as_str(),
                "releasing JSONL tracker claim"
            );
            if reason.code == ReleaseReasonCode::Conflict {
                record
                    .issue
                    .extra
                    .insert("abandon".to_owned(), conflict_abandon_value(claim, reason)?);
            }
            record.issue.state = IssueState::new("todo")?;
            record.issue.claim = None;
            record.issue.updated_at = now_utc();
            record.dirty = true;
            Ok(())
        })
    }

    fn handoff_claim(&self, claim: &Claim, handoff: Handoff) -> Result<()> {
        let id = claim_issue_id(claim)?;
        self.commit_handoff(&id, claim, handoff)
    }

    fn prepare_handoff(&self, claim: &Claim, handoff: Handoff) -> Result<Handoff> {
        let id = claim_issue_id(claim)?;
        let records = self.load_records()?;
        let record = records
            .find(&id)
            .ok_or_else(|| TrackerError::IssueNotFound { id: id.clone() })?;
        ensure_claim_owner(&record.issue, claim)?;
        let mut prepared = handoff
            .with_issue_id(id)
            .with_signer_agent_id(claim.by.to_string());
        prepared.signature = None;
        Ok(prepared)
    }

    fn commit_handoff(&self, id: &IssueId, claim: &Claim, handoff: Handoff) -> Result<()> {
        let message = format!("x0x-symphony: handoff {id}");
        self.with_records_mutation(&message, |records| {
            let record = records.find_mut(id)?;
            ensure_claim_owner(&record.issue, claim)?;
            validate_signed_handoff_bindings(id, claim, &handoff)?;
            record.issue.state = IssueState::new("review")?;
            record.issue.claim = None;
            record.issue.handoff = Some(handoff);
            record.issue.updated_at = now_utc();
            record.dirty = true;
            Ok(())
        })
    }

    fn block_claim(&self, claim: &Claim, reason: &ReleaseReason) -> Result<()> {
        let id = claim_issue_id(claim)?;
        let message = format!("x0x-symphony: block {id}");
        self.with_records_mutation(&message, |records| {
            let record = records.find_mut(&id)?;
            ensure_claim_owner(&record.issue, claim)?;
            info!(
                issue_id = %id,
                agent_id = %claim.by,
                reason_code = reason.code.as_str(),
                reason = reason.message.as_str(),
                "blocking issue after retry exhaustion"
            );
            record.issue.state = IssueState::new("blocked")?;
            record.issue.claim = None;
            // Persist the structured reason so an operator or later agent can
            // see *why* the issue was blocked. Stored in `extra` under a
            // reserved key as a serialized `ReleaseReason`.
            record.issue.extra.insert(
                "blocked_reason".to_owned(),
                serde_json::to_value(reason).map_err(|source| TrackerError::Json { source })?,
            );
            record.issue.updated_at = now_utc();
            record.dirty = true;
            Ok(())
        })
    }

    async fn sign_claim(&self, mut claim: Claim) -> Result<Claim> {
        let payload = claim.signing_payload_bytes().map_err(TrackerError::from)?;
        let response = self
            .signing
            .client()?
            .sign(CLAIM_CONTEXT, &payload)
            .await
            .map_err(signing_error)?;
        let envelope = envelope_from_sign_response(response, CLAIM_CONTEXT, &payload, &claim.by)?;
        claim.signature = Some(envelope);
        Ok(claim)
    }

    async fn sign_handoff(&self, mut handoff: Handoff, signer: &AgentId) -> Result<Handoff> {
        let payload = handoff
            .signing_payload_bytes()
            .map_err(TrackerError::from)?;
        let response = self
            .signing
            .client()?
            .sign(HANDOFF_CONTEXT, &payload)
            .await
            .map_err(signing_error)?;
        let envelope = envelope_from_sign_response(response, HANDOFF_CONTEXT, &payload, signer)?;
        handoff.signature = Some(envelope);
        Ok(handoff)
    }

    async fn filter_verified_issues(&self, issues: Vec<Issue>) -> Vec<Issue> {
        if self.signing.policy == SigningPolicy::Disabled {
            return issues;
        }
        let mut verified = Vec::with_capacity(issues.len());
        for issue in issues {
            if self.verify_issue(&issue).await {
                verified.push(issue);
            }
        }
        verified
    }

    async fn verify_issue(&self, issue: &Issue) -> bool {
        if let Err(error) = self.verify_issue_result(issue).await {
            warn!(issue_id = %issue.id, error = %error, "dropping issue with invalid signature");
            false
        } else {
            true
        }
    }

    async fn verify_issue_result(&self, issue: &Issue) -> Result<()> {
        if let Some(claim) = &issue.claim {
            self.verify_claim(issue, claim).await?;
        }
        if let Some(handoff) = &issue.handoff {
            self.verify_handoff(issue, handoff).await?;
        }
        Ok(())
    }

    async fn verify_claim(&self, issue: &Issue, claim: &Claim) -> Result<()> {
        if claim.issue_id.as_ref() != Some(&issue.id) {
            return Err(TrackerError::Signing(format!(
                "claim issue_id does not match parent issue {}",
                issue.id
            )));
        }
        let envelope = claim.signature.as_ref().ok_or_else(|| {
            TrackerError::Signing(format!("claim for issue {} is unsigned", issue.id))
        })?;
        if envelope.signer_agent_id != claim.by.to_string() {
            return Err(TrackerError::Signing(format!(
                "claim owner {} does not match signer {}",
                claim.by, envelope.signer_agent_id
            )));
        }
        let payload = claim.signing_payload_bytes().map_err(TrackerError::from)?;
        self.verify_envelope(envelope, CLAIM_CONTEXT, &payload)
            .await
    }

    async fn verify_handoff(&self, issue: &Issue, handoff: &Handoff) -> Result<()> {
        let envelope = handoff.signature.as_ref().ok_or_else(|| {
            TrackerError::Signing(format!("handoff for issue {} is unsigned", issue.id))
        })?;
        if handoff.issue_id.as_ref() != Some(&issue.id) {
            return Err(TrackerError::Signing(format!(
                "handoff issue_id does not match parent issue {}",
                issue.id
            )));
        }
        let signer_agent_id = handoff.signer_agent_id.as_ref().ok_or_else(|| {
            TrackerError::Signing(format!(
                "handoff for issue {} is missing signer_agent_id",
                issue.id
            ))
        })?;
        if signer_agent_id != &envelope.signer_agent_id {
            return Err(TrackerError::Signing(format!(
                "handoff signer binding {signer_agent_id} does not match envelope signer {}",
                envelope.signer_agent_id
            )));
        }
        let payload = handoff
            .signing_payload_bytes()
            .map_err(TrackerError::from)?;
        self.verify_envelope(envelope, HANDOFF_CONTEXT, &payload)
            .await
    }

    async fn verify_envelope(
        &self,
        envelope: &SignatureEnvelope,
        target_context: &str,
        payload: &[u8],
    ) -> Result<()> {
        if envelope.algorithm != SIGN_ALGORITHM {
            return Err(TrackerError::Signing(format!(
                "unsupported signing algorithm {}",
                envelope.algorithm
            )));
        }
        if envelope.context != target_context {
            return Err(TrackerError::Signing(format!(
                "signature context {} does not match {target_context}",
                envelope.context
            )));
        }
        let actual_digest = sha256_hex(payload);
        if envelope.payload_sha256 != actual_digest {
            return Err(TrackerError::Signing(format!(
                "payload digest {} does not match {actual_digest}",
                envelope.payload_sha256
            )));
        }
        let envelope_key = BASE64
            .decode(&envelope.public_key_b64)
            .map_err(|source| TrackerError::Signing(format!("invalid public_key_b64: {source}")))?;
        let trusted_key = self
            .signing
            .resolver()?
            .resolve(&envelope.signer_agent_id)
            .await
            .map_err(signing_error)?;
        if envelope_key != trusted_key {
            return Err(TrackerError::Signing(format!(
                "envelope public key does not belong to signer {}",
                envelope.signer_agent_id
            )));
        }
        let signature = BASE64
            .decode(&envelope.signature_b64)
            .map_err(|source| TrackerError::Signing(format!("invalid signature_b64: {source}")))?;
        // Send raw claim/handoff payload bytes. x0xd reconstructs the external
        // DST internally for both /agent/sign and /agent/verify.
        let valid = self
            .signing
            .client()?
            .verify(target_context, payload, &signature, &envelope_key)
            .await
            .map_err(signing_error)?;
        if valid {
            Ok(())
        } else {
            Err(TrackerError::Signing(
                "x0xd verify endpoint returned false".to_owned(),
            ))
        }
    }

    fn with_records_mutation<F>(&self, commit_message: &str, mutate: F) -> Result<()>
    where
        F: FnOnce(&mut LoadedRecords) -> Result<()>,
    {
        let git_dir = self.discover_git_dir()?;
        let lock_path = self.lock_path(git_dir.as_deref());
        let guard = self.acquire_lock(&lock_path)?;
        let mut records = self.load_records()?;
        let original_shards = records.shard_snapshot();
        mutate(&mut records)?;
        records.ensure_shards_unchanged(&original_shards)?;
        if records.has_dirty_records() {
            if git_dir.is_none() {
                self.ensure_mtime_unchanged(records.modified_at)?;
            }
            self.write_records(&records)?;
        }
        drop(guard);
        if records.has_dirty_records() {
            self.commit_if_git(git_dir.as_deref(), commit_message)?;
        }
        Ok(())
    }

    fn load_records(&self) -> Result<LoadedRecords> {
        let content = match fs::read_to_string(&self.issues_path) {
            Ok(content) => content,
            Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
            Err(source) => {
                return Err(TrackerError::Io {
                    path: self.issues_path.clone(),
                    source,
                });
            }
        };
        let modified_at = self.current_mtime()?;
        let mut records = Vec::new();
        let mut first_schema_error = None;
        let mut schema_error_count = 0_usize;
        for (index, line) in content.lines().enumerate() {
            let line_number = index.saturating_add(1);
            let parsed = if line.trim().is_empty() {
                Err(schema_error(line_number, "empty JSONL record"))
            } else {
                parse_issue_line(line_number, line)
            };
            match parsed {
                Ok(issue) => records.push(IssueRecord {
                    raw_line: line.to_owned(),
                    issue,
                    dirty: false,
                }),
                Err(TrackerError::Schema { line, reason }) => {
                    schema_error_count = schema_error_count.saturating_add(1);
                    if first_schema_error.is_none() {
                        first_schema_error = Some((line, reason));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        if let Some((line, reason)) = first_schema_error {
            return Err(TrackerError::Schema {
                line,
                reason: format!("{schema_error_count} schema violation(s); first: {reason}"),
            });
        }
        Ok(LoadedRecords {
            records,
            modified_at,
        })
    }

    fn write_records(&self, records: &LoadedRecords) -> Result<()> {
        if let Some(parent) = self.issues_path.parent() {
            fs::create_dir_all(parent).map_err(|source| TrackerError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let temp_path = self.temp_write_path();
        let mut file = File::create(&temp_path).map_err(|source| TrackerError::Io {
            path: temp_path.clone(),
            source,
        })?;
        for record in &records.records {
            let line = record.line_text()?;
            file.write_all(line.as_bytes())
                .and_then(|()| file.write_all(b"\n"))
                .map_err(|source| TrackerError::Io {
                    path: temp_path.clone(),
                    source,
                })?;
        }
        file.sync_all().map_err(|source| TrackerError::Io {
            path: temp_path.clone(),
            source,
        })?;
        drop(file);
        fs::rename(&temp_path, &self.issues_path).map_err(|source| TrackerError::Io {
            path: self.issues_path.clone(),
            source,
        })?;
        Ok(())
    }

    fn temp_write_path(&self) -> PathBuf {
        let file_name = self
            .issues_path
            .file_name()
            .map_or_else(|| OsString::from("issues.jsonl"), OsString::from);
        let mut temp_name = file_name;
        temp_name.push(format!(".{}.tmp", std::process::id()));
        self.issues_path.with_file_name(temp_name)
    }

    fn current_mtime(&self) -> Result<Option<SystemTime>> {
        match fs::metadata(&self.issues_path) {
            Ok(metadata) => metadata
                .modified()
                .map(Some)
                .map_err(|source| TrackerError::Io {
                    path: self.issues_path.clone(),
                    source,
                }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(TrackerError::Io {
                path: self.issues_path.clone(),
                source,
            }),
        }
    }

    fn ensure_mtime_unchanged(&self, original_mtime: Option<SystemTime>) -> Result<()> {
        if self.current_mtime()? == original_mtime {
            Ok(())
        } else {
            Err(TrackerError::ConcurrentModification {
                path: self.issues_path.clone(),
            })
        }
    }

    fn lock_path(&self, git_dir: Option<&Path>) -> PathBuf {
        git_dir.map_or_else(
            || self.issues_path.with_file_name("issues.jsonl.lock"),
            |dir| dir.join("index.lock"),
        )
    }

    fn acquire_lock(&self, lock_path: &Path) -> Result<LockGuard> {
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).map_err(|source| TrackerError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        for attempt in 0..self.lock_attempts {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(lock_path)
            {
                Ok(mut file) => {
                    let metadata = format!("pid={}\n", std::process::id());
                    file.write_all(metadata.as_bytes())
                        .map_err(|source| TrackerError::Io {
                            path: lock_path.to_path_buf(),
                            source,
                        })?;
                    return Ok(LockGuard {
                        path: lock_path.to_path_buf(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let next_attempt = attempt.saturating_add(1);
                    if next_attempt >= self.lock_attempts {
                        return Err(TrackerError::LockExhausted {
                            path: lock_path.to_path_buf(),
                            attempts: self.lock_attempts,
                        });
                    }
                    thread::sleep(self.backoff_delay(next_attempt));
                }
                Err(source) => {
                    return Err(TrackerError::Io {
                        path: lock_path.to_path_buf(),
                        source,
                    });
                }
            }
        }
        Err(TrackerError::LockExhausted {
            path: lock_path.to_path_buf(),
            attempts: self.lock_attempts,
        })
    }

    fn backoff_delay(&self, attempt: u32) -> Duration {
        let delay = self.lock_initial_backoff.saturating_mul(attempt.max(1));
        delay.min(self.lock_max_backoff)
    }

    fn discover_git_dir(&self) -> Result<Option<PathBuf>> {
        let output = match Command::new(&self.git_binary)
            .arg("-C")
            .arg(&self.repo_root)
            .arg("rev-parse")
            .arg("--git-dir")
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(TrackerError::Io {
                    path: self.repo_root.clone(),
                    source,
                });
            }
        };
        if !output.status.success() {
            return Ok(None);
        }
        let git_dir = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if git_dir.is_empty() {
            return Ok(None);
        }
        let path = PathBuf::from(git_dir);
        if path.is_absolute() {
            Ok(Some(path))
        } else {
            Ok(Some(self.repo_root.join(path)))
        }
    }

    fn commit_if_git(&self, git_dir: Option<&Path>, message: &str) -> Result<()> {
        if git_dir.is_none() {
            return Ok(());
        }
        let relative = self.relative_issues_path();
        self.run_git(["add", "--"], Some(&relative))?;
        if self.git_diff_cached_is_empty(&relative)? {
            return Ok(());
        }
        self.run_git(
            ["commit", "--no-verify", "-m", message, "--"],
            Some(&relative),
        )
    }

    fn relative_issues_path(&self) -> PathBuf {
        self.issues_path
            .strip_prefix(&self.repo_root)
            .map_or_else(|_| self.issues_path.clone(), Path::to_path_buf)
    }

    fn git_diff_cached_is_empty(&self, relative: &Path) -> Result<bool> {
        let output = Command::new(&self.git_binary)
            .arg("-C")
            .arg(&self.repo_root)
            .arg("diff")
            .arg("--cached")
            .arg("--quiet")
            .arg("--")
            .arg(relative)
            .output()
            .map_err(|source| TrackerError::Io {
                path: self.repo_root.clone(),
                source,
            })?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            status => Err(TrackerError::Git {
                command: format!("git diff --cached --quiet -- {}", relative.display()),
                status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }),
        }
    }

    fn run_git<const N: usize>(&self, args: [&str; N], trailing_path: Option<&Path>) -> Result<()> {
        let mut command = Command::new(&self.git_binary);
        command.arg("-C").arg(&self.repo_root);
        for arg in args {
            command.arg(arg);
        }
        if let Some(path) = trailing_path {
            command.arg(path);
        }
        let output = command.output().map_err(|source| TrackerError::Io {
            path: self.repo_root.clone(),
            source,
        })?;
        if output.status.success() {
            Ok(())
        } else {
            Err(TrackerError::Git {
                command: Self::git_command_string(args, trailing_path),
                status: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }
    }

    fn git_command_string<const N: usize>(args: [&str; N], trailing_path: Option<&Path>) -> String {
        let mut parts = Vec::with_capacity(args.len().saturating_add(3));
        parts.push("git".to_owned());
        parts.extend(args.into_iter().map(str::to_owned));
        if let Some(path) = trailing_path {
            parts.push(path.display().to_string());
        }
        parts.join(" ")
    }
}

#[async_trait]
impl Tracker for JsonlTracker {
    async fn fetch_candidates(&self, ctx: &PollContext) -> CoreResult<Vec<Issue>> {
        let records = self.load_records().map_err(SymphonyError::from)?;
        let terminal_states: BTreeSet<IssueState> = ctx.terminal_states.iter().cloned().collect();
        let mut candidates = records
            .records
            .iter()
            .filter(|record| issue_state_is_active(&record.issue, ctx))
            .filter(|record| blockers_are_terminal(&record.issue, &records, &terminal_states))
            .map(|record| record.issue.clone())
            .collect::<Vec<_>>();
        candidates = self.filter_verified_issues(candidates).await;
        candidates.sort_by(|left, right| {
            priority_sort_key(left)
                .cmp(&priority_sort_key(right))
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(candidates)
    }

    async fn fetch_by_ids(&self, ids: &[IssueId]) -> CoreResult<Vec<Issue>> {
        let records = self.load_records().map_err(SymphonyError::from)?;
        let mut issues = Vec::new();
        for id in ids {
            if let Some(record) = records.records.iter().find(|record| &record.issue.id == id) {
                issues.push(record.issue.clone());
            }
        }
        Ok(self.filter_verified_issues(issues).await)
    }

    async fn claim(&self, id: &IssueId, agent_id: &AgentId) -> CoreResult<Claim> {
        if self.signing.policy == SigningPolicy::Disabled {
            return self.claim_issue(id, agent_id).map_err(SymphonyError::from);
        }
        let claim = self
            .prepare_claim(id, agent_id)
            .map_err(SymphonyError::from)?;
        let signed = self.sign_claim(claim).await.map_err(SymphonyError::from)?;
        self.commit_claim(id, signed).map_err(SymphonyError::from)
    }

    async fn heartbeat(&self, claim: &Claim) -> CoreResult<()> {
        self.heartbeat_claim(claim).map_err(SymphonyError::from)
    }

    async fn release(&self, claim: &Claim, reason: ReleaseReason) -> CoreResult<()> {
        self.release_claim(claim, &reason)
            .map_err(SymphonyError::from)
    }

    async fn handoff(&self, claim: &Claim, handoff: Handoff) -> CoreResult<()> {
        if self.signing.policy == SigningPolicy::Disabled {
            return self
                .handoff_claim(claim, handoff)
                .map_err(SymphonyError::from);
        }
        let id = claim_issue_id(claim).map_err(SymphonyError::from)?;
        let prepared = self
            .prepare_handoff(claim, handoff)
            .map_err(SymphonyError::from)?;
        let signed = self
            .sign_handoff(prepared, &claim.by)
            .await
            .map_err(SymphonyError::from)?;
        self.commit_handoff(&id, claim, signed)
            .map_err(SymphonyError::from)
    }

    async fn fetch_claimed(&self, agent_id: Option<&AgentId>) -> CoreResult<Vec<Issue>> {
        let records = self.load_records().map_err(SymphonyError::from)?;
        let claimed = records
            .records
            .iter()
            .filter(|record| record.issue.claim.is_some())
            .filter(|record| {
                agent_id.is_none_or(|agent| {
                    record
                        .issue
                        .claim
                        .as_ref()
                        .is_some_and(|claim| &claim.by == agent)
                })
            })
            .map(|record| record.issue.clone())
            .collect::<Vec<_>>();
        Ok(self.filter_verified_issues(claimed).await)
    }

    async fn block(&self, claim: &Claim, reason: ReleaseReason) -> CoreResult<()> {
        self.block_claim(claim, &reason)
            .map_err(SymphonyError::from)
    }
}

/// Parse and validate one JSONL issue record.
///
/// # Errors
///
/// Returns [`TrackerError::Schema`] when the line is not a JSON object or does
/// not satisfy the required issue schema.
pub fn parse_issue_line(line_number: usize, line: &str) -> Result<Issue> {
    let value = serde_json::from_str::<Value>(line)
        .map_err(|source| schema_error(line_number, format!("invalid JSON: {source}")))?;
    let Value::Object(_) = value else {
        return Err(schema_error(line_number, "record must be a JSON object"));
    };
    let issue = serde_json::from_value::<Issue>(value)
        .map_err(|source| schema_error(line_number, format!("invalid issue schema: {source}")))?;
    validate_issue(&issue, line_number)?;
    Ok(issue)
}

/// Serialize an issue as one compact JSONL line.
///
/// Unknown fields stored in [`Issue::extra`] are emitted with their JSON values
/// intact so future schema extensions survive M1–M2 rewrites.
///
/// # Errors
///
/// Returns [`TrackerError::Json`] if serde cannot serialize the issue.
pub fn serialize_issue(issue: &Issue) -> Result<String> {
    serde_json::to_string(issue).map_err(|source| TrackerError::Json { source })
}

fn schema_error(line: usize, reason: impl Into<String>) -> TrackerError {
    let reason = reason.into();
    warn!(line, reason = reason.as_str(), "invalid JSONL issue record");
    TrackerError::Schema { line, reason }
}

fn validate_issue(issue: &Issue, line: usize) -> Result<()> {
    validate_non_empty(line, "id", issue.id.as_str())?;
    validate_non_empty(line, "identifier", &issue.identifier)?;
    validate_non_empty(line, "title", &issue.title)?;
    validate_non_empty(line, "state", issue.state.as_str())?;
    validate_non_empty(line, "created_at", &issue.created_at)?;
    validate_non_empty(line, "updated_at", &issue.updated_at)?;
    for (index, label) in issue.labels.iter().enumerate() {
        validate_non_empty(line, format!("labels[{index}]"), label)?;
    }
    for (index, blocker) in issue.blocked_by.iter().enumerate() {
        validate_non_empty(line, format!("blocked_by[{index}].id"), blocker.id.as_str())?;
        validate_non_empty(
            line,
            format!("blocked_by[{index}].identifier"),
            &blocker.identifier,
        )?;
        validate_non_empty(
            line,
            format!("blocked_by[{index}].state"),
            blocker.state.as_str(),
        )?;
    }
    Ok(())
}

fn validate_non_empty(line: usize, field: impl AsRef<str>, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(schema_error(
            line,
            format!("required field `{}` must not be empty", field.as_ref()),
        ))
    } else {
        Ok(())
    }
}

fn issue_state_is_active(issue: &Issue, ctx: &PollContext) -> bool {
    ctx.active_states.iter().any(|state| state == &issue.state)
}

const fn priority_sort_key(issue: &Issue) -> u8 {
    match issue.priority {
        Some(priority) => priority,
        None => u8::MAX,
    }
}

fn blockers_are_terminal(
    issue: &Issue,
    records: &LoadedRecords,
    terminal_states: &BTreeSet<IssueState>,
) -> bool {
    issue.blocked_by.iter().all(|blocker| {
        records
            .find(&blocker.id)
            .is_some_and(|record| terminal_states.contains(&record.issue.state))
    })
}

fn claim_issue_id(claim: &Claim) -> Result<IssueId> {
    claim
        .issue_id
        .clone()
        .ok_or_else(|| TrackerError::InvalidClaim {
            reason: "claim is missing issue_id".to_owned(),
        })
}

fn ensure_issue_claimable(issue: &Issue, id: &IssueId) -> Result<()> {
    if issue.claim.is_some() {
        return Err(TrackerError::ClaimRejected {
            id: id.clone(),
            reason: "issue already has an active claim".to_owned(),
        });
    }
    if issue.state.as_str() != "todo" {
        return Err(TrackerError::ClaimRejected {
            id: id.clone(),
            reason: format!("state is {}", issue.state.as_str()),
        });
    }
    Ok(())
}

fn shard_role_for_agent(issue: &Issue, agent_id: &AgentId) -> Result<ShardRole> {
    let Some(shard) = issue.shard.as_ref() else {
        return Ok(ShardRole::ManualM1);
    };
    if &shard.primary == agent_id {
        return Ok(ShardRole::Primary);
    }
    if let Some(index) = shard.backups.iter().position(|backup| backup == agent_id) {
        return Ok(ShardRole::Backup(index));
    }
    Err(TrackerError::ClaimRejected {
        id: issue.id.clone(),
        reason: format!("agent {agent_id} is not in the issue shard slate"),
    })
}

fn ensure_claim_owner(issue: &Issue, claim: &Claim) -> Result<()> {
    let Some(current) = issue.claim.as_ref() else {
        return Err(TrackerError::InvalidClaim {
            reason: format!("issue {} has no active claim", issue.id),
        });
    };
    if current.by == claim.by {
        Ok(())
    } else {
        Err(TrackerError::InvalidClaim {
            reason: format!(
                "issue {} is claimed by {}, not {}",
                issue.id, current.by, claim.by
            ),
        })
    }
}

fn conflict_abandon_value(claim: &Claim, reason: &ReleaseReason) -> Result<Value> {
    let mut value = serde_json::Map::new();
    value.insert(
        "claim".to_owned(),
        serde_json::to_value(claim).map_err(|source| TrackerError::Json { source })?,
    );
    value.insert(
        "reason".to_owned(),
        serde_json::to_value(reason).map_err(|source| TrackerError::Json { source })?,
    );
    Ok(Value::Object(value))
}

fn validate_signed_handoff_bindings(id: &IssueId, claim: &Claim, handoff: &Handoff) -> Result<()> {
    if handoff.signature.is_none() {
        return Ok(());
    }
    if handoff.issue_id.as_ref() != Some(id) {
        return Err(TrackerError::InvalidClaim {
            reason: format!("signed handoff is not bound to issue {id}"),
        });
    }
    if handoff.signer_agent_id.as_deref() != Some(claim.by.as_str()) {
        return Err(TrackerError::InvalidClaim {
            reason: format!(
                "signed handoff signer does not match claim owner {}",
                claim.by
            ),
        });
    }
    Ok(())
}

fn envelope_from_sign_response(
    response: SignResponse,
    target_context: &str,
    payload: &[u8],
    target_signer: &AgentId,
) -> Result<SignatureEnvelope> {
    if response.algorithm != SIGN_ALGORITHM {
        return Err(TrackerError::Signing(format!(
            "sign response algorithm {} did not match {SIGN_ALGORITHM}",
            response.algorithm
        )));
    }
    if response.context != target_context {
        return Err(TrackerError::Signing(format!(
            "sign response context {} did not match {target_context}",
            response.context
        )));
    }
    if response.agent_id != target_signer.to_string() {
        return Err(TrackerError::Signing(format!(
            "sign response agent {} did not match claim owner {}",
            response.agent_id, target_signer
        )));
    }
    Ok(SignatureEnvelope::new(
        response.algorithm,
        response.context,
        response.public_key_b64,
        response.signature_b64,
        sha256_hex(payload),
        response.agent_id,
    ))
}

fn signing_error(error: impl std::fmt::Display) -> TrackerError {
    TrackerError::Signing(error.to_string())
}

fn now_utc() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

#[derive(Clone, Debug)]
struct IssueRecord {
    raw_line: String,
    issue: Issue,
    dirty: bool,
}

impl IssueRecord {
    fn line_text(&self) -> Result<String> {
        if self.dirty {
            serialize_issue(&self.issue)
        } else {
            Ok(self.raw_line.clone())
        }
    }
}

#[derive(Clone, Debug)]
struct LoadedRecords {
    records: Vec<IssueRecord>,
    modified_at: Option<SystemTime>,
}

impl LoadedRecords {
    fn find(&self, id: &IssueId) -> Option<&IssueRecord> {
        self.records.iter().find(|record| &record.issue.id == id)
    }

    fn shard_snapshot(&self) -> BTreeMap<IssueId, Option<Shard>> {
        self.records
            .iter()
            .map(|record| (record.issue.id.clone(), record.issue.shard.clone()))
            .collect()
    }

    fn ensure_shards_unchanged(
        &self,
        original_shards: &BTreeMap<IssueId, Option<Shard>>,
    ) -> Result<()> {
        for record in &self.records {
            if let Some(original) = original_shards.get(&record.issue.id) {
                if original != &record.issue.shard {
                    return Err(TrackerError::ShardMutationRejected {
                        id: record.issue.id.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn find_mut(&mut self, id: &IssueId) -> Result<&mut IssueRecord> {
        self.records
            .iter_mut()
            .find(|record| &record.issue.id == id)
            .ok_or_else(|| TrackerError::IssueNotFound { id: id.clone() })
    }

    fn find_claim_mut(&mut self, id: &IssueId, claim: &Claim) -> Result<&mut IssueRecord> {
        let position = self.records.iter().position(|record| {
            &record.issue.id == id
                && record
                    .issue
                    .claim
                    .as_ref()
                    .is_some_and(|current| current.by.eq(&claim.by))
        });
        if let Some(index) = position {
            return Ok(&mut self.records[index]);
        }
        if self.records.iter().any(|record| &record.issue.id == id) {
            return Err(TrackerError::InvalidClaim {
                reason: format!("issue {id} has no active claim owned by {}", claim.by),
            });
        }
        Err(TrackerError::IssueNotFound { id: id.clone() })
    }

    fn has_dirty_records(&self) -> bool {
        self.records.iter().any(|record| record.dirty)
    }

    fn next_issue_id(&self) -> Result<IssueId> {
        let mut max_suffix = 0;
        if let Some(value) = self
            .records
            .iter()
            .filter_map(|record| parse_xsy_suffix(record.issue.id.as_str()))
            .max()
        {
            max_suffix = value;
        }
        let next = max_suffix.saturating_add(1);
        IssueId::new(format!("XSY-{next:04}")).map_err(TrackerError::from)
    }
}

fn parse_xsy_suffix(value: &str) -> Option<u32> {
    value
        .strip_prefix("XSY-")
        .and_then(|suffix| suffix.parse::<u32>().ok())
}

#[derive(Debug)]
struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ignored = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_mutation_on_existing_record_is_rejected() -> Result<()> {
        let id = IssueId::new("XSY-0013")?;
        let mut issue = Issue::new(
            id.clone(),
            "XSY-0013",
            "Shard assignment",
            IssueState::new("todo")?,
            "2026-07-02T00:00:00Z",
        )?;
        issue.shard = Some(Shard::new(
            AgentId::new("agent-a")?,
            vec![AgentId::new("agent-b")?],
            shard::DEFAULT_CLAIM_TTL_MS,
            shard::STATIC_WORKER_VIEW_EPOCH,
        ));
        let records = LoadedRecords {
            records: vec![IssueRecord {
                raw_line: serialize_issue(&issue)?,
                issue,
                dirty: false,
            }],
            modified_at: None,
        };
        let snapshot = records.shard_snapshot();
        let mut mutated = records.clone();
        let record = mutated
            .records
            .get_mut(0)
            .ok_or_else(|| TrackerError::InvalidClaim {
                reason: "test record missing".to_owned(),
            })?;
        record.issue.shard = Some(Shard::new(
            AgentId::new("agent-c")?,
            Vec::new(),
            shard::DEFAULT_CLAIM_TTL_MS,
            shard::STATIC_WORKER_VIEW_EPOCH,
        ));

        match mutated.ensure_shards_unchanged(&snapshot) {
            Err(TrackerError::ShardMutationRejected { id: rejected }) => {
                assert_eq!(rejected, id);
                Ok(())
            }
            Err(error) => Err(error),
            Ok(()) => Err(TrackerError::InvalidClaim {
                reason: "shard mutation was accepted".to_owned(),
            }),
        }
    }
}
