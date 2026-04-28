//! Tracker trait and dispatch context types.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{AgentId, Claim, Handoff, Issue, IssueId, IssueState, Result};

/// Context supplied when polling a tracker for dispatch candidates.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{IssueState, PollContext};
///
/// let ctx = PollContext::new(vec![IssueState::new("todo")?], vec![IssueState::new("done")?]);
/// assert_eq!(ctx.active_states.len(), 1);
/// # Ok::<(), x0x_symphony_core::SymphonyError>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PollContext {
    /// States eligible for dispatch.
    pub active_states: Vec<IssueState>,
    /// States considered terminal.
    pub terminal_states: Vec<IssueState>,
    /// Agent performing the poll, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
}

impl PollContext {
    /// Construct a polling context with no attached agent identity.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{IssueState, PollContext};
    ///
    /// let ctx = PollContext::new(vec![IssueState::new("todo")?], Vec::new());
    /// assert!(ctx.agent_id.is_none());
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    #[must_use]
    pub fn new(active_states: Vec<IssueState>, terminal_states: Vec<IssueState>) -> Self {
        Self {
            active_states,
            terminal_states,
            agent_id: None,
        }
    }

    /// Return a copy with the polling agent identity attached.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{AgentId, PollContext};
    ///
    /// let ctx = PollContext::new(Vec::new(), Vec::new()).with_agent_id(AgentId::new("agent-a")?);
    /// assert!(ctx.agent_id.is_some());
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    #[must_use]
    pub fn with_agent_id(mut self, agent_id: AgentId) -> Self {
        self.agent_id = Some(agent_id);
        self
    }
}

/// Machine-readable release reason category.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::ReleaseReasonCode;
///
/// assert_eq!(ReleaseReasonCode::RunnerFailed.as_str(), "runner_failed");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReasonCode {
    /// Operator cancelled a run.
    OperatorCancelled,
    /// Runner failed or timed out.
    RunnerFailed,
    /// Claim heartbeat expired.
    ExpiredHeartbeat,
    /// Claim conflict was resolved in favor of another worker.
    Conflict,
    /// Other structured reason.
    Other,
}

impl ReleaseReasonCode {
    /// Return the stable JSON spelling for this reason code.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::ReleaseReasonCode;
    ///
    /// assert_eq!(ReleaseReasonCode::Conflict.as_str(), "conflict");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::OperatorCancelled => "operator_cancelled",
            Self::RunnerFailed => "runner_failed",
            Self::ExpiredHeartbeat => "expired_heartbeat",
            Self::Conflict => "conflict",
            Self::Other => "other",
        }
    }
}

/// Explanation attached when a claim is released without a handoff.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{ReleaseReason, ReleaseReasonCode};
///
/// let reason = ReleaseReason::new(ReleaseReasonCode::RunnerFailed, "exit code 1");
/// assert_eq!(reason.code, ReleaseReasonCode::RunnerFailed);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReleaseReason {
    /// Machine-readable reason category.
    pub code: ReleaseReasonCode,
    /// Human-readable explanation.
    pub message: String,
}

impl ReleaseReason {
    /// Construct a release reason.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{ReleaseReason, ReleaseReasonCode};
    ///
    /// let reason = ReleaseReason::new(ReleaseReasonCode::OperatorCancelled, "manual stop");
    /// assert_eq!(reason.message, "manual stop");
    /// ```
    #[must_use]
    pub fn new(code: ReleaseReasonCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Source of issue state for the orchestrator.
///
/// The trait is deliberately narrow and matches ADR-0001. Bootstrap and CRDT
/// adapters implement the same methods so orchestrator code is adapter-neutral.
///
/// # Examples
///
/// ```no_run
/// use async_trait::async_trait;
/// use x0x_symphony_core::{AgentId, Claim, Handoff, Issue, IssueId, PollContext, ReleaseReason, Result, Tracker};
///
/// struct ReadOnlyTracker;
///
/// #[async_trait]
/// impl Tracker for ReadOnlyTracker {
///     async fn fetch_candidates(&self, _ctx: &PollContext) -> Result<Vec<Issue>> { Ok(Vec::new()) }
///     async fn fetch_by_ids(&self, _ids: &[IssueId]) -> Result<Vec<Issue>> { Ok(Vec::new()) }
///     async fn claim(&self, _id: &IssueId, _agent_id: &AgentId) -> Result<Claim> {
///         Err(x0x_symphony_core::SymphonyError::Tracker("read-only".into()))
///     }
///     async fn heartbeat(&self, _claim: &Claim) -> Result<()> { Ok(()) }
///     async fn release(&self, _claim: &Claim, _reason: ReleaseReason) -> Result<()> { Ok(()) }
///     async fn handoff(&self, _claim: &Claim, _handoff: Handoff) -> Result<()> { Ok(()) }
/// }
/// ```
#[async_trait]
pub trait Tracker: Send + Sync {
    /// Fetch issues currently dispatchable to an agent.
    async fn fetch_candidates(&self, ctx: &PollContext) -> Result<Vec<Issue>>;

    /// Look up current state for specific issue identifiers.
    async fn fetch_by_ids(&self, ids: &[IssueId]) -> Result<Vec<Issue>>;

    /// Claim an issue for `agent_id`.
    async fn claim(&self, id: &IssueId, agent_id: &AgentId) -> Result<Claim>;

    /// Refresh the heartbeat on an existing claim.
    async fn heartbeat(&self, claim: &Claim) -> Result<()>;

    /// Release a claim without producing a handoff.
    async fn release(&self, claim: &Claim, reason: ReleaseReason) -> Result<()>;

    /// Append a final handoff and move the issue to review.
    async fn handoff(&self, claim: &Claim, handoff: Handoff) -> Result<()>;
}
