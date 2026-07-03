//! Mapping between Symphony issues and x0xd `TaskList`/`KvStore` records.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use x0x_symphony_core::{
    Claim, Handoff, Issue, IssueId, IssueSource, IssueState, ReleaseReason, SymphonyError,
};

use crate::client::{AddTaskDraft, TaskEntry};

/// MIME type used for Symphony JSON blobs in x0xd `KvStore` values.
pub const SYMPHONY_JSON_CONTENT_TYPE: &str = "application/vnd.x0x-symphony+json";

/// Claim blob kind marker.
pub const CLAIM_BLOB_KIND: &str = "x0x-symphony-claim-v1";

/// Handoff blob kind marker.
pub const HANDOFF_BLOB_KIND: &str = "x0x-symphony-handoff-v1";

const SCHEMA_VERSION: u32 = 1;
const DEFAULT_TIMESTAMP: &str = "1970-01-01T00:00:00Z";

/// Result alias for mapping operations.
pub type Result<T> = std::result::Result<T, MappingError>;

/// Errors produced while converting between x0xd and Symphony records.
#[derive(Debug, Error)]
pub enum MappingError {
    /// Core domain validation failed.
    #[error(transparent)]
    Core(#[from] SymphonyError),

    /// JSON encoding or decoding failed.
    #[error("JSON error: {source}")]
    Json {
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },

    /// A `KvStore` blob belongs to a different issue than the `TaskEntry`.
    #[error("{blob_kind} blob belongs to {blob_issue_id}, not task {task_id}")]
    IssueMismatch {
        /// Blob kind being decoded.
        blob_kind: &'static str,
        /// Issue id encoded in the blob.
        blob_issue_id: String,
        /// Task id currently being mapped.
        task_id: String,
    },
}

/// Status of a Symphony claim blob stored in x0xd `KvStore`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimBlobStatus {
    /// Claim is actively held and should appear as [`Issue::claim`].
    Active,
    /// Claim was released without a handoff.
    Released,
    /// Claim completed with a handoff.
    Completed,
    /// Claim exhausted retries or otherwise blocked the issue.
    Blocked,
}

/// Claim metadata stored under `claim-<task-id>` in `symphony-<list-id>`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimBlob {
    /// Blob schema version.
    pub schema_version: u32,
    /// Blob kind marker.
    pub kind: String,
    /// Claim lifecycle status.
    pub status: ClaimBlobStatus,
    /// Claim payload.
    pub claim: Claim,
    /// Structured release/block reason, when the claim is no longer active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_reason: Option<ReleaseReason>,
    /// Last time this blob was written, as ISO-8601 UTC text.
    pub updated_at: String,
}

impl ClaimBlob {
    /// Build an active claim blob.
    #[must_use]
    pub fn active(claim: Claim, updated_at: impl Into<String>) -> Self {
        Self::new(ClaimBlobStatus::Active, claim, None, updated_at)
    }

    /// Build a released claim blob.
    #[must_use]
    pub fn released(claim: Claim, reason: ReleaseReason, updated_at: impl Into<String>) -> Self {
        Self::new(ClaimBlobStatus::Released, claim, Some(reason), updated_at)
    }

    /// Build a completed claim blob.
    #[must_use]
    pub fn completed(claim: Claim, updated_at: impl Into<String>) -> Self {
        Self::new(ClaimBlobStatus::Completed, claim, None, updated_at)
    }

    /// Build a blocked claim blob.
    #[must_use]
    pub fn blocked(claim: Claim, reason: ReleaseReason, updated_at: impl Into<String>) -> Self {
        Self::new(ClaimBlobStatus::Blocked, claim, Some(reason), updated_at)
    }

    /// Return `true` when this blob represents an active claim.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, ClaimBlobStatus::Active)
    }

    fn new(
        status: ClaimBlobStatus,
        claim: Claim,
        release_reason: Option<ReleaseReason>,
        updated_at: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            kind: CLAIM_BLOB_KIND.to_owned(),
            status,
            claim,
            release_reason,
            updated_at: updated_at.into(),
        }
    }
}

/// Handoff metadata stored under `handoff-<task-id>` in `symphony-<list-id>`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HandoffBlob {
    /// Blob schema version.
    pub schema_version: u32,
    /// Blob kind marker.
    pub kind: String,
    /// Handoff payload.
    pub handoff: Handoff,
    /// Last time this blob was written, as ISO-8601 UTC text.
    pub updated_at: String,
}

impl HandoffBlob {
    /// Build a handoff blob.
    #[must_use]
    pub fn new(handoff: Handoff, updated_at: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            kind: HANDOFF_BLOB_KIND.to_owned(),
            handoff,
            updated_at: updated_at.into(),
        }
    }
}

/// Return the `KvStore` id used for Symphony metadata for a `TaskList`.
#[must_use]
pub fn store_id_for_list(list_id: &str) -> String {
    format!("symphony-{list_id}")
}

/// Return the `KvStore` key for a task's claim blob.
#[must_use]
pub fn claim_key(task_id: &str) -> String {
    format!("claim-{task_id}")
}

/// Return the `KvStore` key for a task's handoff blob.
#[must_use]
pub fn handoff_key(task_id: &str) -> String {
    format!("handoff-{task_id}")
}

/// Encode a claim blob as JSON bytes for x0xd `KvStore`.
///
/// # Errors
///
/// Returns [`MappingError::Json`] if the blob cannot be serialized.
pub fn encode_claim_blob(blob: &ClaimBlob) -> Result<Vec<u8>> {
    serde_json::to_vec(blob).map_err(|source| MappingError::Json { source })
}

/// Decode a claim blob from x0xd `KvStore` JSON bytes.
///
/// # Errors
///
/// Returns [`MappingError::Json`] if the blob cannot be decoded.
pub fn decode_claim_blob(bytes: &[u8]) -> Result<ClaimBlob> {
    serde_json::from_slice(bytes).map_err(|source| MappingError::Json { source })
}

/// Encode a handoff blob as JSON bytes for x0xd `KvStore`.
///
/// # Errors
///
/// Returns [`MappingError::Json`] if the blob cannot be serialized.
pub fn encode_handoff_blob(blob: &HandoffBlob) -> Result<Vec<u8>> {
    serde_json::to_vec(blob).map_err(|source| MappingError::Json { source })
}

/// Decode a handoff blob from x0xd `KvStore` JSON bytes.
///
/// # Errors
///
/// Returns [`MappingError::Json`] if the blob cannot be decoded.
pub fn decode_handoff_blob(bytes: &[u8]) -> Result<HandoffBlob> {
    serde_json::from_slice(bytes).map_err(|source| MappingError::Json { source })
}

/// Convert a Symphony issue into an x0xd task creation draft.
#[must_use]
pub fn add_task_draft_from_issue(issue: &Issue) -> AddTaskDraft {
    AddTaskDraft::new(issue.title.clone()).with_description(issue.description.clone())
}

/// Convert a Symphony issue into a `TaskEntry`-shaped projection.
///
/// This helper is primarily used by tests and by callers that need to preview
/// how Symphony fields collapse into x0xd's public `TaskEntry` surface.
#[must_use]
pub fn task_entry_from_issue(issue: &Issue) -> TaskEntry {
    TaskEntry {
        id: issue.id.to_string(),
        title: issue.title.clone(),
        description: issue.description.clone(),
        state: task_state_from_issue(issue),
        assignee: issue.claim.as_ref().map(|claim| claim.by.to_string()),
        priority: issue.priority.unwrap_or_default(),
    }
}

/// Convert an x0xd `TaskEntry` plus optional Symphony `KvStore` blobs into an Issue.
///
/// # Errors
///
/// Returns [`MappingError::Core`] when the `TaskEntry` cannot satisfy the frozen
/// Issue schema and [`MappingError::IssueMismatch`] when a sidecar blob points
/// at a different task.
pub fn issue_from_task(
    task: &TaskEntry,
    claim_blob: Option<&ClaimBlob>,
    handoff_blob: Option<&HandoffBlob>,
) -> Result<Issue> {
    validate_claim_blob(task, claim_blob)?;
    validate_handoff_blob(task, handoff_blob)?;

    let id = IssueId::new(task.id.clone())?;
    let created_at = DEFAULT_TIMESTAMP.to_owned();
    let updated_at = updated_at_for_blobs(claim_blob, handoff_blob);
    let mut issue = Issue::new(
        id,
        task.id.clone(),
        task.title.clone(),
        issue_state_for_task(task, claim_blob, handoff_blob)?,
        created_at,
    )?;
    issue.description.clone_from(&task.description);
    issue.priority = Some(task.priority);
    issue.updated_at = updated_at;
    issue.claim = active_claim_for_issue(claim_blob, handoff_blob);
    issue.handoff = handoff_blob.map(|blob| blob.handoff.clone());
    issue.extra = extra_for_task(task, claim_blob)?;
    Ok(issue)
}

fn task_state_from_issue(issue: &Issue) -> String {
    match issue.state.as_str() {
        "in_progress" => issue.claim.as_ref().map_or_else(
            || "claimed".to_owned(),
            |claim| format!("claimed:{}", claim.by),
        ),
        "review" | "done" => issue
            .claim
            .as_ref()
            .map_or_else(|| "done".to_owned(), |claim| format!("done:{}", claim.by)),
        _ => "empty".to_owned(),
    }
}

fn issue_state_for_task(
    task: &TaskEntry,
    claim_blob: Option<&ClaimBlob>,
    handoff_blob: Option<&HandoffBlob>,
) -> Result<IssueState> {
    if claim_blob.is_some_and(|blob| blob.status == ClaimBlobStatus::Blocked) {
        return IssueState::new("blocked").map_err(Into::into);
    }
    if handoff_blob.is_some() {
        return IssueState::new("review").map_err(Into::into);
    }
    if claim_blob.is_some_and(|blob| blob.status == ClaimBlobStatus::Released) {
        return IssueState::new("todo").map_err(Into::into);
    }
    match normalized_task_state(&task.state).as_str() {
        "claimed" => IssueState::new("in_progress").map_err(Into::into),
        "done" => IssueState::new("done").map_err(Into::into),
        _ => IssueState::new("todo").map_err(Into::into),
    }
}

fn normalized_task_state(state: &str) -> String {
    let lower = state.trim().to_ascii_lowercase();
    if lower == "empty" {
        return "empty".to_owned();
    }
    if lower == "claimed" || lower.starts_with("claimed:") {
        return "claimed".to_owned();
    }
    if lower == "done" || lower.starts_with("done:") {
        return "done".to_owned();
    }
    lower
}

fn active_claim_for_issue(
    claim_blob: Option<&ClaimBlob>,
    handoff_blob: Option<&HandoffBlob>,
) -> Option<Claim> {
    if handoff_blob.is_some() {
        return None;
    }
    claim_blob
        .filter(|blob| blob.status == ClaimBlobStatus::Active)
        .map(|blob| blob.claim.clone())
}

fn updated_at_for_blobs(
    claim_blob: Option<&ClaimBlob>,
    handoff_blob: Option<&HandoffBlob>,
) -> String {
    handoff_blob.map_or_else(
        || {
            claim_blob.map_or_else(
                || DEFAULT_TIMESTAMP.to_owned(),
                |blob| blob.updated_at.clone(),
            )
        },
        |blob| blob.updated_at.clone(),
    )
}

fn extra_for_task(
    task: &TaskEntry,
    claim_blob: Option<&ClaimBlob>,
) -> Result<BTreeMap<String, Value>> {
    let mut extra = BTreeMap::new();
    if let Some(assignee) = &task.assignee {
        extra.insert("x0x_assignee".to_owned(), Value::String(assignee.clone()));
    }
    extra.insert(
        "x0x_task_state".to_owned(),
        Value::String(task.state.clone()),
    );
    extra.insert(
        "issue_source".to_owned(),
        Value::String(IssueSource::NetworkSourced.as_str().to_owned()),
    );
    if let Some(reason) = claim_blob.and_then(|blob| {
        (blob.status == ClaimBlobStatus::Blocked)
            .then(|| blob.release_reason.clone())
            .flatten()
    }) {
        extra.insert(
            "blocked_reason".to_owned(),
            serde_json::to_value(reason).map_err(|source| MappingError::Json { source })?,
        );
    }
    Ok(extra)
}

fn validate_claim_blob(task: &TaskEntry, claim_blob: Option<&ClaimBlob>) -> Result<()> {
    if let Some(issue_id) = claim_blob
        .and_then(|blob| blob.claim.issue_id.as_ref())
        .filter(|issue_id| issue_id.as_str() != task.id)
    {
        return Err(MappingError::IssueMismatch {
            blob_kind: CLAIM_BLOB_KIND,
            blob_issue_id: issue_id.to_string(),
            task_id: task.id.clone(),
        });
    }
    Ok(())
}

fn validate_handoff_blob(task: &TaskEntry, handoff_blob: Option<&HandoffBlob>) -> Result<()> {
    if let Some(issue_id) = handoff_blob
        .and_then(|blob| blob.handoff.issue_id.as_ref())
        .filter(|issue_id| issue_id.as_str() != task.id)
    {
        return Err(MappingError::IssueMismatch {
            blob_kind: HANDOFF_BLOB_KIND,
            blob_issue_id: issue_id.to_string(),
            task_id: task.id.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use x0x_symphony_core::{AgentId, ShardRole, ValidationResult, ValidationStatus};

    use super::*;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn issue_task_entry_issue_round_trip_preserves_core_fields() -> TestResult {
        let id = IssueId::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")?;
        let mut issue = Issue::new(
            id.clone(),
            id.as_str(),
            "Implement CRDT tracker",
            IssueState::new("in_progress")?,
            "2026-07-03T00:00:00Z",
        )?;
        issue.description = "Map TaskEntry to Issue.".to_owned();
        issue.priority = Some(2);
        let claim = Claim::new(
            Some(id.clone()),
            AgentId::new("agent-a")?,
            "2026-07-03T01:00:00Z",
            ShardRole::ManualM1,
        );
        issue.claim = Some(claim.clone());

        let task = task_entry_from_issue(&issue);
        let claim_blob = ClaimBlob::active(claim, "2026-07-03T01:00:00Z");
        let round_trip = issue_from_task(&task, Some(&claim_blob), None)?;

        assert_eq!(round_trip.id, issue.id);
        assert_eq!(round_trip.title, issue.title);
        assert_eq!(round_trip.description, issue.description);
        assert_eq!(round_trip.priority, issue.priority);
        assert_eq!(round_trip.state, IssueState::new("in_progress")?);
        assert!(round_trip.claim.is_some());
        Ok(())
    }

    #[test]
    fn handoff_blob_overlays_done_task_as_review() -> TestResult {
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let task = TaskEntry {
            id: id.to_owned(),
            title: "Review me".to_owned(),
            description: String::new(),
            state: "done:agent-a".to_owned(),
            assignee: Some("agent-a".to_owned()),
            priority: 3,
        };
        let handoff = Handoff::new("ready")
            .with_issue_id(IssueId::new(id)?)
            .with_validation(ValidationResult::new("just test", ValidationStatus::Passed));

        let handoff_blob = HandoffBlob::new(handoff, "2026-07-03T02:00:00Z");
        let issue = issue_from_task(&task, None, Some(&handoff_blob))?;

        assert_eq!(issue.state, IssueState::new("review")?);
        assert!(issue.claim.is_none());
        assert!(issue.handoff.is_some());
        Ok(())
    }

    #[test]
    fn blocked_claim_blob_overlays_task_state() -> TestResult {
        let id = IssueId::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?;
        let claim = Claim::new(
            Some(id.clone()),
            AgentId::new("agent-a")?,
            "2026-07-03T01:00:00Z",
            ShardRole::ManualM1,
        );
        let reason = ReleaseReason::new(
            x0x_symphony_core::ReleaseReasonCode::RetryExhausted,
            "retry cap reached",
        );
        let task = TaskEntry {
            id: id.to_string(),
            title: "Blocked".to_owned(),
            description: String::new(),
            state: "claimed:agent-a".to_owned(),
            assignee: Some("agent-a".to_owned()),
            priority: 3,
        };

        let claim_blob = ClaimBlob::blocked(claim, reason, "2026-07-03T02:00:00Z");
        let issue = issue_from_task(&task, Some(&claim_blob), None)?;

        assert_eq!(issue.state, IssueState::new("blocked")?);
        assert!(issue.claim.is_none());
        assert!(issue.extra.contains_key("blocked_reason"));
        Ok(())
    }

    #[test]
    fn claim_and_handoff_blobs_encode_as_json() -> TestResult {
        let id = IssueId::new("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")?;
        let claim = Claim::new(
            Some(id.clone()),
            AgentId::new("agent-a")?,
            "2026-07-03T01:00:00Z",
            ShardRole::ManualM1,
        );
        let claim_blob = ClaimBlob::active(claim, "2026-07-03T01:00:00Z");
        let encoded_claim = encode_claim_blob(&claim_blob)?;
        assert_eq!(decode_claim_blob(&encoded_claim)?, claim_blob);

        let handoff_blob = HandoffBlob::new(
            Handoff::new("ready").with_issue_id(id),
            "2026-07-03T02:00:00Z",
        );
        let encoded_handoff = encode_handoff_blob(&handoff_blob)?;
        assert_eq!(decode_handoff_blob(&encoded_handoff)?, handoff_blob);
        Ok(())
    }
}
