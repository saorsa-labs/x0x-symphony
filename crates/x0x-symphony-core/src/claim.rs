//! Claim and shard domain types.

use serde::{Deserialize, Serialize};

use crate::{AgentId, IssueId};

/// Role held by a claimant inside an issue's frozen shard slate.
///
/// M1 manual work uses [`ShardRole::ManualM1`]. M2 and later use the primary
/// and backup roles described in ADR-0002.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::ShardRole;
///
/// assert_eq!(ShardRole::Primary.rank(), 0);
/// assert_eq!(ShardRole::Backup(1).rank(), 2);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardRole {
    /// The primary owner may claim immediately.
    Primary,
    /// A backup owner may claim after the primary heartbeat expires.
    Backup(usize),
    /// Manual bootstrap claim used before M2 writes shard records.
    ManualM1,
}

impl ShardRole {
    /// Return the ADR-0002 tiebreak rank; lower ranks win.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::ShardRole;
    ///
    /// assert!(ShardRole::Primary.rank() < ShardRole::Backup(0).rank());
    /// ```
    #[must_use]
    pub const fn rank(&self) -> usize {
        match self {
            Self::Primary => 0,
            Self::Backup(index) => index.saturating_add(1),
            Self::ManualM1 => usize::MAX,
        }
    }
}

/// Frozen ownership record stored on an issue at creation time.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{AgentId, Shard};
///
/// let shard = Shard::new(AgentId::new("primary")?, vec![AgentId::new("backup")?], 3_600_000, 17);
/// assert_eq!(shard.claim_ttl_ms, 3_600_000);
/// # Ok::<(), x0x_symphony_core::SymphonyError>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Shard {
    /// Primary worker allowed to claim immediately.
    pub primary: AgentId,
    /// Ordered backup workers allowed to claim after TTL expiry.
    pub backups: Vec<AgentId>,
    /// Claim heartbeat timeout in milliseconds.
    pub claim_ttl_ms: u64,
    /// Trusted-worker view epoch used to compute the shard slate.
    pub created_view_epoch: u64,
}

impl Shard {
    /// Construct a shard record.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{AgentId, Shard};
    ///
    /// let shard = Shard::new(AgentId::new("primary")?, Vec::new(), 60_000, 1);
    /// assert!(shard.backups.is_empty());
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    #[must_use]
    pub fn new(
        primary: AgentId,
        backups: Vec<AgentId>,
        claim_ttl_ms: u64,
        created_view_epoch: u64,
    ) -> Self {
        Self {
            primary,
            backups,
            claim_ttl_ms,
            created_view_epoch,
        }
    }
}

/// Active claim record for an issue.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{AgentId, Claim, IssueId, ShardRole};
///
/// let claim = Claim::new(
///     Some(IssueId::new("XSY-0002")?),
///     AgentId::new("agent-a")?,
///     "2026-04-28T10:00:00Z",
///     ShardRole::Primary,
/// );
/// assert_eq!(claim.shard_role.rank(), 0);
/// # Ok::<(), x0x_symphony_core::SymphonyError>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    /// Issue this claim belongs to when known at the trait boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_id: Option<IssueId>,
    /// Agent that currently owns the claim.
    pub by: AgentId,
    /// Claim creation timestamp as ISO-8601 UTC text.
    pub at: String,
    /// Last heartbeat timestamp as ISO-8601 UTC text.
    pub heartbeat_at: String,
    /// Claimant's role in the issue's shard slate.
    pub shard_role: ShardRole,
    /// Signature over the claim payload. M1 manual claims may omit this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Claim {
    /// Construct a claim with `heartbeat_at` equal to `at`.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{AgentId, Claim, ShardRole};
    ///
    /// let claim = Claim::new(None, AgentId::new("agent-a")?, "now", ShardRole::ManualM1);
    /// assert_eq!(claim.at, claim.heartbeat_at);
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    #[must_use]
    pub fn new(
        issue_id: Option<IssueId>,
        by: AgentId,
        at: impl Into<String>,
        shard_role: ShardRole,
    ) -> Self {
        let at = at.into();
        Self {
            issue_id,
            by,
            heartbeat_at: at.clone(),
            at,
            shard_role,
            signature: None,
        }
    }

    /// Return a copy of this claim with a refreshed heartbeat timestamp.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{AgentId, Claim, ShardRole};
    ///
    /// let claim = Claim::new(None, AgentId::new("agent-a")?, "t0", ShardRole::ManualM1)
    ///     .with_heartbeat("t1");
    /// assert_eq!(claim.heartbeat_at, "t1");
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    #[must_use]
    pub fn with_heartbeat(mut self, heartbeat_at: impl Into<String>) -> Self {
        self.heartbeat_at = heartbeat_at.into();
        self
    }
}
