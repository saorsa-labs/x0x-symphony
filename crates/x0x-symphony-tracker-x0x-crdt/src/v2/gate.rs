//! WP-B: the v2 approval-consumption dispatch gate.
//!
//! Consume-then-execute, failing toward zero executions: the gate refuses to
//! report `Proceed` until a signed [`super::events::ConsumeEventV2`] is
//! durably appended to the local author's append-only store AND a settle
//! re-read confirms that consume is the fold winner for its approval. A
//! crash anywhere in between spends the approval without executing
//! (recovery = re-approval), never the reverse.
//!
//! Deliberate non-inputs, per design r2:
//! - **TTL (C3)** is enforced HERE, at gate time, against a caller-supplied
//!   clock — an expired approval still folds; the gate just refuses to
//!   consume it.
//! - **Trust (C2)** is NOT checked here at all: `required_trust` remains the
//!   caller's dispatch-time policy (in the v1 orchestrator flow it runs
//!   before the approval gate), and it never affects folded state.
//! - The **settle re-read** is an optimization that narrows the documented
//!   live-partition double-consume window; it is NOT a safety bound. The
//!   safety property is the deterministic fold winner: after any heal, all
//!   replicas agree on which consume was effective, losers are surfaced as
//!   diagnostics, and runners must stay idempotent for the residual window.

use std::time::Duration;

use super::events::{
    ApprovalVerdictV2, ConsumeEventV2, TransitionEventV2, TransitionKind, V2_SCHEMA,
};
use super::fold::{fold_v2, FoldOutput, IssueStatusV2};
use super::store::{OwnEventStore, Result, V2StoreError, V2StoreManager};
use x0x_symphony_core::sha256_hex;

/// Gate configuration. Both knobs are gate-time policy, never fold inputs.
#[derive(Clone, Copy, Debug)]
pub struct V2GateConfig {
    /// Maximum age of an approval at consumption time (seconds). Expired
    /// approvals still fold; the gate refuses to consume them (C3).
    pub approval_ttl_secs: u64,
    /// Settle delay between the consume append and the confirming re-read.
    /// Documented as an optimization, not a safety bound; default 2s.
    pub settle: Duration,
}

impl Default for V2GateConfig {
    fn default() -> Self {
        Self {
            approval_ttl_secs: 3600,
            settle: Duration::from_secs(2),
        }
    }
}

/// Outcome of one gate evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V2GateDecision {
    /// A consume was durably appended and confirmed as the fold winner —
    /// the caller may execute exactly this once.
    Proceed {
        /// The consumed approval's event hash.
        approval_event_hash: String,
        /// Our consume's event hash (the winning record).
        consume_event_hash: String,
    },
    /// No valid, unconsumed, unexpired approval exists — park and wait.
    PendingApproval,
    /// An admitted denial covers the issue's current content — do not
    /// dispatch (denials are terminal for that content).
    Denied,
    /// The local agent does not hold the fold-winning claim; only the
    /// winning claimant may consume.
    NotClaimWinner,
    /// After the settle re-read, a competing consume (ordered before ours in
    /// fold order) won the approval — abort WITHOUT executing.
    AbortCompetingConsume {
        /// The contested approval.
        approval_event_hash: String,
        /// Winning consumer.
        winner_author: String,
        /// Winning consume event hash.
        winner_event_hash: String,
    },
    /// After the settle re-read, our consume was not effective (e.g. the
    /// claim winner changed under us) — abort WITHOUT executing.
    AbortIneffective {
        /// Diagnostic reason from the fold, when available.
        reason: String,
    },
}

/// The v2 dispatch gate. Borrows the store manager for I/O; all state
/// decisions delegate to the pure fold.
pub struct V2ApprovalGate<'m> {
    manager: &'m V2StoreManager,
    config: V2GateConfig,
}

impl<'m> V2ApprovalGate<'m> {
    /// Construct a gate over `manager`.
    #[must_use]
    pub const fn new(manager: &'m V2StoreManager, config: V2GateConfig) -> Self {
        Self { manager, config }
    }

    /// Evaluate approvals for `issue_id` and, when authorized, durably
    /// consume one and confirm the consumption won.
    ///
    /// `now_secs`/`entropy_seed` are caller-supplied so the gate itself
    /// stays clock-injectable for tests; production callers pass wall-clock
    /// seconds and any unique seed (e.g. nanosecond timestamp).
    ///
    /// # Errors
    ///
    /// Returns store/signing/client errors, and [`V2StoreError::Refused`]
    /// when the list itself is refused by the fold (downgrade defense).
    pub async fn evaluate_and_consume(
        &self,
        own: &OwnEventStore,
        creator: &str,
        issue_id: &str,
        now_secs: u64,
        entropy_seed: &str,
    ) -> Result<V2GateDecision> {
        // ---- First fold: establish claim fence + approval candidates -----
        let input = self
            .manager
            .read_fold_input(&own.list_uuid, creator)
            .await?;
        let out = fold_v2(&input).map_err(V2StoreError::Refused)?;
        let Some(issue) = out.issues.get(issue_id) else {
            return Err(V2StoreError::Invalid(format!(
                "issue {issue_id} does not exist in the folded list"
            )));
        };

        // Claim fence: only the fold-winning claimant may consume.
        let IssueStatusV2::Claimed {
            claimant,
            claim_nonce,
            claim_event_hash,
        } = &issue.status
        else {
            return Ok(V2GateDecision::NotClaimWinner);
        };
        if claimant != &own.agent_id {
            return Ok(V2GateDecision::NotClaimWinner);
        }
        let claim_nonce = claim_nonce.clone();
        let claim_event_hash = claim_event_hash.clone();

        // Denials are terminal for the issue's current content.
        if out.approvals.values().any(|a| {
            a.approval.issue_id == issue_id
                && a.approval.open_event_hash == issue.open_event_hash
                && a.approval.verdict == ApprovalVerdictV2::Deny
        }) {
            return Ok(V2GateDecision::Denied);
        }

        // Unconsumed approvals, then the gate-time TTL filter (C3): expired
        // approvals folded fine and stay visible; we just refuse them here.
        let candidate = out.unconsumed_approvals(issue_id).into_iter().find(|a| {
            a.approval
                .approved_at
                .saturating_add(self.config.approval_ttl_secs)
                >= now_secs
        });
        let Some(candidate) = candidate else {
            return Ok(V2GateDecision::PendingApproval);
        };
        let approval_event_hash = candidate.event_hash.clone();
        let approver = candidate.approval.actor.clone();

        // ---- Durable consume (consume-then-execute) ----------------------
        let (author_seq, prev_own_event_hash) = out.next_chain_link(&own.agent_id);
        let consume = ConsumeEventV2 {
            schema: V2_SCHEMA,
            kind: "consume".to_owned(),
            list_uuid: own.list_uuid.clone(),
            genesis_manifest_hash: out.genesis_hash.clone(),
            roster_epoch: out.latest_roster_epoch,
            issue_id: issue_id.to_owned(),
            actor: own.agent_id.clone(),
            lamport: out.max_admitted_lamport.saturating_add(1),
            author_seq,
            prev_own_event_hash,
            approval_event_hash: approval_event_hash.clone(),
            approval_payload_sha256: approval_event_hash.clone(),
            approver,
            claim_nonce,
            claimed_event_hash: claim_event_hash,
            entropy: sha256_hex(
                format!("{}:{author_seq}:{entropy_seed}:consume", own.agent_id).as_bytes(),
            ),
        };
        let my_consume_hash = self.manager.append_consume(own, &consume).await?;

        // ---- Settle re-read (optimization, not a safety bound) -----------
        if !self.config.settle.is_zero() {
            tokio::time::sleep(self.config.settle).await;
        }
        let input = self
            .manager
            .read_fold_input(&own.list_uuid, creator)
            .await?;
        let confirm = fold_v2(&input).map_err(V2StoreError::Refused)?;
        Ok(Self::confirm_decision(
            &confirm,
            &approval_event_hash,
            &my_consume_hash,
        ))
    }

    /// Decide the final outcome from the confirming fold: our consume must
    /// be THE effective consume for the approval, else abort.
    fn confirm_decision(
        confirm: &FoldOutput,
        approval_event_hash: &str,
        my_consume_hash: &str,
    ) -> V2GateDecision {
        match confirm.effective_consumes.get(approval_event_hash) {
            Some(winner) if winner.event_hash == my_consume_hash => V2GateDecision::Proceed {
                approval_event_hash: approval_event_hash.to_owned(),
                consume_event_hash: my_consume_hash.to_owned(),
            },
            Some(winner) => V2GateDecision::AbortCompetingConsume {
                approval_event_hash: approval_event_hash.to_owned(),
                winner_author: winner.consume.actor.clone(),
                winner_event_hash: winner.event_hash.clone(),
            },
            None => {
                let reason = confirm
                    .losing_consumes
                    .iter()
                    .find(|d| d.event_hash == my_consume_hash)
                    .map_or_else(
                        || "consume did not take effect".to_owned(),
                        |d| d.reason.clone(),
                    );
                V2GateDecision::AbortIneffective { reason }
            }
        }
    }
}

/// Convenience for building the claim transition a gate-driven dispatcher
/// appends before entering the gate: claims must fence on fold state.
///
/// Returns the complete [`TransitionEventV2`] for a claim by `agent` using
/// the fold's chain link and lamport horizon.
#[must_use]
pub fn build_claim_transition(
    out: &FoldOutput,
    list_uuid: &str,
    agent_id: &str,
    issue_id: &str,
) -> TransitionEventV2 {
    let (author_seq, prev_own_event_hash) = out.next_chain_link(agent_id);
    let lamport = out.max_admitted_lamport.saturating_add(1);
    TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: list_uuid.to_owned(),
        genesis_manifest_hash: out.genesis_hash.clone(),
        roster_epoch: out.latest_roster_epoch,
        issue_id: issue_id.to_owned(),
        actor: agent_id.to_owned(),
        lamport,
        author_seq,
        prev_own_event_hash,
        kind: TransitionKind::Claim {
            claim_nonce: V2StoreManager::derive_claim_nonce(
                agent_id, author_seq, lamport, issue_id,
            ),
        },
    }
}
