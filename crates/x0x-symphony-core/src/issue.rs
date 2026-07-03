//! Issue domain model shared by all tracker adapters.

use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{ser::SerializeMap, Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::{Result, SymphonyError};

const ISSUE_SCHEMA_VERSION_V1: u32 = 1;

const fn default_issue_schema_version() -> u32 {
    ISSUE_SCHEMA_VERSION_V1
}

/// Stable tracker identifier for an issue.
///
/// `IssueId` is a newtype rather than a raw string so tracker code cannot
/// accidentally pass an agent identifier where an issue identifier is required.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::IssueId;
///
/// let id = IssueId::new("XSY-0002")?;
/// assert_eq!(id.as_str(), "XSY-0002");
/// # Ok::<(), x0x_symphony_core::SymphonyError>(())
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IssueId(String);

impl IssueId {
    /// Create a non-empty issue identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SymphonyError::Validation`] when `value` is empty or only
    /// whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::IssueId;
    ///
    /// assert!(IssueId::new("XSY-0002").is_ok());
    /// assert!(IssueId::new("   ").is_err());
    /// ```
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SymphonyError::validation("issue.id", "must not be empty"));
        }
        Ok(Self(value))
    }

    /// Borrow the identifier as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::IssueId;
    ///
    /// let id = IssueId::new("XSY-0002")?;
    /// assert_eq!(id.as_str(), "XSY-0002");
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IssueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IssueId {
    type Err = SymphonyError;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

/// Stable x0x agent identifier used for claims and worker identity.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::AgentId;
///
/// let agent = AgentId::new("agent-hex-or-local-dev-id")?;
/// assert_eq!(agent.as_str(), "agent-hex-or-local-dev-id");
/// # Ok::<(), x0x_symphony_core::SymphonyError>(())
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(String);

impl AgentId {
    /// Create a non-empty agent identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SymphonyError::Validation`] when `value` is empty or only
    /// whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::AgentId;
    ///
    /// assert!(AgentId::new("agent-a").is_ok());
    /// assert!(AgentId::new("").is_err());
    /// ```
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SymphonyError::validation("agent.id", "must not be empty"));
        }
        Ok(Self(value))
    }

    /// Borrow the identifier as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::AgentId;
    ///
    /// let agent = AgentId::new("agent-a")?;
    /// assert_eq!(agent.as_str(), "agent-a");
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AgentId {
    type Err = SymphonyError;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

/// Workflow state attached to an issue.
///
/// States are represented as strings rather than an enum because adapters must
/// preserve project-specific states while the orchestrator compares configured
/// active and terminal sets.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::IssueState;
///
/// let state = IssueState::new("todo")?;
/// assert_eq!(state.as_str(), "todo");
/// # Ok::<(), x0x_symphony_core::SymphonyError>(())
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IssueState(String);

impl IssueState {
    /// Create a normalized, non-empty issue state.
    ///
    /// # Errors
    ///
    /// Returns [`SymphonyError::Validation`] when `value` is empty or only
    /// whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::IssueState;
    ///
    /// assert_eq!(IssueState::new("In Progress")?.as_str(), "in progress");
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let normalized = value.into().trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(SymphonyError::validation(
                "issue.state",
                "must not be empty",
            ));
        }
        Ok(Self(normalized))
    }

    /// Borrow the normalized state as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::IssueState;
    ///
    /// let state = IssueState::new("review")?;
    /// assert_eq!(state.as_str(), "review");
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IssueState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IssueState {
    type Err = SymphonyError;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

/// Provenance class for dispatch safety decisions.
///
/// Local issues are operator-controlled backlog items. Network-sourced issues
/// arrived through an x0x-backed adapter and may require additional trust and
/// signature gates before execution.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueSource {
    /// Local operator-controlled backlog item.
    #[default]
    Local,
    /// Network-sourced item received through the x0x CRDT adapter.
    NetworkSourced,
}

impl IssueSource {
    /// Stable marker used in adapter-preserved issue metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::NetworkSourced => "network_sourced",
        }
    }

    /// Resolve an issue's source marker from adapter-preserved metadata.
    ///
    /// Missing or unknown markers default to [`IssueSource::Local`] to preserve
    /// the M1 local-JSONL behavior. Adapters that ingest network records should
    /// set `issue_source` (or legacy `source`) to `network_sourced`.
    #[must_use]
    pub fn from_issue(issue: &Issue) -> Self {
        ["issue_source", "source"]
            .iter()
            .filter_map(|key| issue.extra.get(*key))
            .find_map(Self::from_json_value)
            .unwrap_or(Self::Local)
    }

    fn from_json_value(value: &Value) -> Option<Self> {
        value.as_str().and_then(Self::from_marker)
    }

    fn from_marker(value: &str) -> Option<Self> {
        let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
        match normalized.as_str() {
            "local" => Some(Self::Local),
            "network" | "network_sourced" | "x0x" | "x0x_crdt" => Some(Self::NetworkSourced),
            _ => None,
        }
    }
}

impl fmt::Display for IssueSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Non-serialized signature verification provenance for a network issue.
///
/// Tracker adapters attach this after verifying the source signature they used
/// to accept a network-sourced issue into the local view. It is intentionally
/// skipped by serde so frozen issue schema v1 records do not grow new required
/// fields and so dispatch never infers verification from serialized source
/// markers alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureProvenance {
    /// A signature was verified and binds the issue to this signer.
    Verified {
        /// x0x agent id whose ML-DSA-65 signature verified.
        signer_agent_id: String,
    },
    /// A signature was present but failed verification.
    Invalid {
        /// Verification failure detail suitable for operator logs.
        reason: String,
    },
    /// Verification could not complete because the verifier transport failed.
    TransportError {
        /// Transport failure detail suitable for operator logs.
        reason: String,
    },
}

impl SignatureProvenance {
    /// Build verified signer provenance.
    #[must_use]
    pub fn verified(signer_agent_id: impl Into<String>) -> Self {
        Self::Verified {
            signer_agent_id: signer_agent_id.into(),
        }
    }

    /// Build invalid-signature provenance.
    #[must_use]
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::Invalid {
            reason: reason.into(),
        }
    }

    /// Build verify-transport-error provenance.
    #[must_use]
    pub fn transport_error(reason: impl Into<String>) -> Self {
        Self::TransportError {
            reason: reason.into(),
        }
    }

    /// Return the verified signer id when verification succeeded.
    #[must_use]
    pub fn verified_signer(&self) -> Option<&str> {
        match self {
            Self::Verified { signer_agent_id } => Some(signer_agent_id.as_str()),
            Self::Invalid { .. } | Self::TransportError { .. } => None,
        }
    }
}

/// Minimal blocker reference embedded inside another issue.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{IssueId, IssueRef, IssueState};
///
/// let blocker = IssueRef::new(IssueId::new("XSY-0001")?, "XSY-0001", IssueState::new("done")?);
/// assert_eq!(blocker.identifier, "XSY-0001");
/// # Ok::<(), x0x_symphony_core::SymphonyError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IssueRef {
    /// Stable issue identifier.
    pub id: IssueId,
    /// Human-readable issue key.
    pub identifier: String,
    /// Last known state for the referenced issue.
    pub state: IssueState,
}

impl IssueRef {
    /// Construct an issue reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{IssueId, IssueRef, IssueState};
    ///
    /// let reference = IssueRef::new(IssueId::new("XSY-0001")?, "XSY-0001", IssueState::new("done")?);
    /// assert_eq!(reference.id.as_str(), "XSY-0001");
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    #[must_use]
    pub fn new(id: IssueId, identifier: impl Into<String>, state: IssueState) -> Self {
        Self {
            id,
            identifier: identifier.into(),
            state,
        }
    }
}

/// Normalized issue record consumed by the orchestrator and prompt renderer.
///
/// Unknown JSON fields are preserved in [`Issue::extra`] so bootstrap adapters
/// can round-trip records while later milestones extend the schema.
///
/// # Schema freeze and signatures
///
/// `schema_version == 1` is the M2 freeze for today's issue, claim, shard, and
/// handoff fields. Future schema evolution is additive-only: new fields must be
/// optional and must not rename, remove, or re-type v1 fields.
///
/// Signatures (XSY-0020) cover the EXACT stored payload bytes — the serialized
/// claim/handoff as written — never a re-derived canonical projection.
/// Therefore additive schema growth can never invalidate an existing signature.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{Issue, IssueId, IssueState};
///
/// let issue = Issue::new(
///     IssueId::new("XSY-0002")?,
///     "XSY-0002",
///     "Define core traits",
///     IssueState::new("todo")?,
///     "2026-04-28T00:00:00Z",
/// )?;
/// assert_eq!(issue.identifier, "XSY-0002");
/// # Ok::<(), x0x_symphony_core::SymphonyError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Issue {
    /// Issue schema version.
    ///
    /// Version `1` is the M2 freeze. It is emitted on every write; legacy
    /// records without this field deserialize as version `1`.
    #[serde(default = "default_issue_schema_version")]
    pub schema_version: u32,
    /// Stable tracker-internal identifier.
    pub id: IssueId,
    /// Human-readable issue key.
    pub identifier: String,
    /// Short issue title.
    pub title: String,
    /// Markdown-capable issue description.
    pub description: String,
    /// Dispatch priority where lower values run earlier.
    pub priority: Option<u8>,
    /// Current workflow state.
    pub state: IssueState,
    /// Preferred branch name, when configured.
    pub branch_name: Option<String>,
    /// Source URL, when the task came from an external or mirrored view.
    pub url: Option<String>,
    /// Lowercase issue labels.
    pub labels: Vec<String>,
    /// Blocker references that must be terminal before dispatch.
    pub blocked_by: Vec<IssueRef>,
    /// Optional sharded ownership metadata introduced in M2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard: Option<crate::Shard>,
    /// Optional active claim metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<crate::Claim>,
    /// Optional review handoff metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff: Option<crate::Handoff>,
    /// Non-serialized verified signature provenance attached by network trackers.
    #[serde(skip)]
    pub signature_provenance: Option<SignatureProvenance>,
    /// Creation timestamp as ISO-8601 UTC text.
    pub created_at: String,
    /// Last update timestamp as ISO-8601 UTC text.
    pub updated_at: String,
    /// Adapter-specific fields preserved across read/write cycles.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Serialize for Issue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut issue = serializer.serialize_map(None)?;
        issue.serialize_entry("schema_version", &ISSUE_SCHEMA_VERSION_V1)?;
        issue.serialize_entry("id", &self.id)?;
        issue.serialize_entry("identifier", &self.identifier)?;
        issue.serialize_entry("title", &self.title)?;
        issue.serialize_entry("description", &self.description)?;
        issue.serialize_entry("priority", &self.priority)?;
        issue.serialize_entry("state", &self.state)?;
        issue.serialize_entry("branch_name", &self.branch_name)?;
        issue.serialize_entry("url", &self.url)?;
        issue.serialize_entry("labels", &self.labels)?;
        issue.serialize_entry("blocked_by", &self.blocked_by)?;
        if let Some(shard) = &self.shard {
            issue.serialize_entry("shard", shard)?;
        }
        if let Some(claim) = &self.claim {
            issue.serialize_entry("claim", claim)?;
        }
        if let Some(handoff) = &self.handoff {
            issue.serialize_entry("handoff", handoff)?;
        }
        issue.serialize_entry("created_at", &self.created_at)?;
        issue.serialize_entry("updated_at", &self.updated_at)?;
        for (key, value) in &self.extra {
            if !is_issue_field(key) {
                issue.serialize_entry(key, value)?;
            }
        }
        issue.end()
    }
}

fn is_issue_field(key: &str) -> bool {
    matches!(
        key,
        "schema_version"
            | "id"
            | "identifier"
            | "title"
            | "description"
            | "priority"
            | "state"
            | "branch_name"
            | "url"
            | "labels"
            | "blocked_by"
            | "shard"
            | "claim"
            | "handoff"
            | "created_at"
            | "updated_at"
    )
}

impl Issue {
    /// Construct a minimal issue with sensible defaults for optional fields.
    ///
    /// # Errors
    ///
    /// Returns [`SymphonyError::Validation`] when `identifier`, `title`, or
    /// `created_at` are empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{Issue, IssueId, IssueState};
    ///
    /// let issue = Issue::new(
    ///     IssueId::new("XSY-0002")?,
    ///     "XSY-0002",
    ///     "Define core traits",
    ///     IssueState::new("todo")?,
    ///     "2026-04-28T00:00:00Z",
    /// )?;
    /// assert!(issue.blocked_by.is_empty());
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    pub fn new(
        id: IssueId,
        identifier: impl Into<String>,
        title: impl Into<String>,
        state: IssueState,
        created_at: impl Into<String>,
    ) -> Result<Self> {
        let identifier = identifier.into();
        if identifier.trim().is_empty() {
            return Err(SymphonyError::validation(
                "issue.identifier",
                "must not be empty",
            ));
        }
        let title = title.into();
        if title.trim().is_empty() {
            return Err(SymphonyError::validation(
                "issue.title",
                "must not be empty",
            ));
        }
        let created_at = created_at.into();
        if created_at.trim().is_empty() {
            return Err(SymphonyError::validation(
                "issue.created_at",
                "must not be empty",
            ));
        }
        Ok(Self {
            schema_version: ISSUE_SCHEMA_VERSION_V1,
            id,
            identifier,
            title,
            description: String::new(),
            priority: None,
            state,
            branch_name: None,
            url: None,
            labels: Vec::new(),
            blocked_by: Vec::new(),
            shard: None,
            claim: None,
            handoff: None,
            signature_provenance: None,
            created_at: created_at.clone(),
            updated_at: created_at,
            extra: BTreeMap::new(),
        })
    }

    /// Return `true` when this issue's state is listed in `states`.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{Issue, IssueId, IssueState};
    ///
    /// let issue = Issue::new(IssueId::new("XSY-0002")?, "XSY-0002", "Title", IssueState::new("todo")?, "now")?;
    /// assert!(issue.state_is_any([IssueState::new("todo")?]));
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    pub fn state_is_any<I>(&self, states: I) -> bool
    where
        I: IntoIterator<Item = IssueState>,
    {
        states.into_iter().any(|state| state == self.state)
    }
}
