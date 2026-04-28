//! Issue domain model shared by all tracker adapters.

use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Result, SymphonyError};

/// Stable tracker identifier for an issue.
///
/// `IssueId` is a newtype rather than a raw string so tracker code cannot
/// accidentally pass an agent identifier where an issue identifier is expected.
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Issue {
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
    /// Creation timestamp as ISO-8601 UTC text.
    pub created_at: String,
    /// Last update timestamp as ISO-8601 UTC text.
    pub updated_at: String,
    /// Adapter-specific fields preserved across read/write cycles.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
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
