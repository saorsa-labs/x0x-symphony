//! Startup reconciliation and claim freshness.
//!
//! On startup the orchestrator must recover a consistent view of the tracker:
//! fresh claims owned by this agent are *resumed*, stale ones (heartbeat older
//! than the claim TTL) are *released* so another worker can pick them up, and
//! foreign claims are left untouched. Heartbeat timestamps are written by the
//! tracker adapters in RFC3339 (see `x0x-symphony-tracker-git-jsonl`); an
//! unparseable timestamp is a hard error rather than an assumption of freshness.

use chrono::{DateTime, Utc};

use crate::{clock::Clock, error::Error, Result};

/// Classify one claimed issue relative to an agent and a clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimStance {
    /// Claimed by `agent_id` and within the TTL — safe to resume.
    FreshSelf,
    /// Claimed by `agent_id` but past the TTL — should be released.
    StaleSelf,
    /// Claimed by a different agent — leave it alone.
    Foreign,
}

/// Parse a claim's RFC3339 `heartbeat_at` timestamp.
///
/// # Errors
///
/// Returns [`Error::BadHeartbeat`] when the timestamp cannot be parsed.
pub fn parse_heartbeat(heartbeat_at: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(heartbeat_at)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|source| Error::BadHeartbeat {
            timestamp: heartbeat_at.to_owned(),
            source,
        })
}

/// Decide a claim's stance: fresh-self, stale-self, or foreign.
///
/// `now` is the orchestrator's current time; `ttl` is the claim heartbeat TTL.
/// An unparseable heartbeat is propagated as an error.
///
/// # Errors
///
/// Returns [`Error::BadHeartbeat`] when the heartbeat timestamp is malformed.
pub fn classify(
    claim: &x0x_symphony_core::Claim,
    owner: &x0x_symphony_core::AgentId,
    now: DateTime<Utc>,
    ttl: chrono::Duration,
) -> Result<ClaimStance> {
    if &claim.by != owner {
        return Ok(ClaimStance::Foreign);
    }
    let heartbeat = parse_heartbeat(&claim.heartbeat_at)?;
    let age = now.signed_duration_since(heartbeat);
    Ok(if age > ttl {
        ClaimStance::StaleSelf
    } else {
        ClaimStance::FreshSelf
    })
}

/// Return `true` when `claim` is owned by `owner` and within the TTL.
///
/// Convenience wrapper around [`classify`] for the eligibility gate.
///
/// # Errors
///
/// Propagates [`Error::BadHeartbeat`].
pub fn is_fresh_self(
    claim: &x0x_symphony_core::Claim,
    owner: &x0x_symphony_core::AgentId,
    clock: &dyn Clock,
    ttl: chrono::Duration,
) -> Result<bool> {
    Ok(matches!(
        classify(claim, owner, clock.now(), ttl)?,
        ClaimStance::FreshSelf
    ))
}

/// Per-issue outcome recorded by [`ReconcileSummary`].
#[derive(Clone, Debug, Default)]
pub struct ReconcileSummary {
    /// Issues whose fresh self-owned claims were kept for resumption.
    pub resumed: usize,
    /// Stale self-owned claims that were released with `expired_heartbeat`.
    pub released: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use std::error::Error;
    use std::result::Result;
    use x0x_symphony_core::{AgentId, Claim, IssueId, ShardRole};

    fn owner() -> Result<AgentId, Box<dyn Error>> {
        Ok(AgentId::new("agent-a")?)
    }

    fn claim_with_heartbeat(agent: &AgentId, ts: &str) -> Result<Claim, Box<dyn Error>> {
        Ok(Claim::new(
            Some(IssueId::new("XSY-9001")?),
            agent.clone(),
            ts,
            ShardRole::ManualM1,
        )
        .with_heartbeat(ts))
    }

    fn ts(value: &str) -> Result<DateTime<Utc>, Box<dyn Error>> {
        Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
    }

    #[test]
    fn fresh_self_within_ttl() -> Result<(), Box<dyn Error>> {
        let owner = owner()?;
        let now = ts("2026-07-02T12:00:00Z")?;
        let claim = claim_with_heartbeat(&owner, "2026-07-02T11:59:00Z")?;
        let stance = classify(&claim, &owner, now, chrono::Duration::minutes(2))?;
        assert_eq!(stance, ClaimStance::FreshSelf);
        Ok(())
    }

    #[test]
    fn stale_self_past_ttl() -> Result<(), Box<dyn Error>> {
        let owner = owner()?;
        let now = ts("2026-07-02T12:00:00Z")?;
        let claim = claim_with_heartbeat(&owner, "2026-07-02T11:00:00Z")?;
        let stance = classify(&claim, &owner, now, chrono::Duration::minutes(2))?;
        assert_eq!(stance, ClaimStance::StaleSelf);
        Ok(())
    }

    #[test]
    fn foreign_claim_is_never_self() -> Result<(), Box<dyn Error>> {
        let owner = owner()?;
        let other = AgentId::new("agent-b")?;
        let now = ts("2026-07-02T12:00:00Z")?;
        let claim = claim_with_heartbeat(&other, "2026-07-02T11:00:00Z")?;
        let stance = classify(&claim, &owner, now, chrono::Duration::seconds(1))?;
        assert_eq!(stance, ClaimStance::Foreign);
        Ok(())
    }

    #[test]
    fn bad_heartbeat_is_an_error() -> Result<(), Box<dyn Error>> {
        let owner = owner()?;
        let now = ts("2026-07-02T12:00:00Z")?;
        let claim = claim_with_heartbeat(&owner, "not-a-timestamp")?;
        assert!(classify(&claim, &owner, now, chrono::Duration::minutes(2)).is_err());
        Ok(())
    }
}
