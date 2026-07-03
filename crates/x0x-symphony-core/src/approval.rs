//! Approval event domain types for consent-gated network dispatch.
//!
//! Approval events are data-layer records only. They bind operator consent to an
//! issue id, the canonical content hash of the issue payload, and the network
//! signer whose issue was approved. The pending claim id, when present, is
//! retained only for audit and is never part of the binding key or validity
//! check.

use std::{collections::BTreeMap, fmt, time::Duration};

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    sha256_hex, AgentId, Issue, IssueId, Result, SignatureEnvelope, SymphonyError, SIGN_ALGORITHM,
};

/// Domain-separation context for approval and denial records.
pub const APPROVAL_CONTEXT: &str = "x0x-symphony-approval-v1";

/// Domain-separation context for approval-consumption records.
pub const APPROVAL_CONSUMED_CONTEXT: &str = "x0x-symphony-approval-consumed-v1";

/// Canonical SHA-256 hash of an issue payload used for approval binding.
///
/// The hash covers the stable JSON object `{ "body", "commands", "description",
/// "title" }`, where `title` and `description` come from [`Issue`] and `body`
/// and `commands` come from preserved adapter metadata when present. Other issue
/// fields such as state, priority, labels, claim, handoff, and timestamps are
/// intentionally not hashed.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentHash(String);

impl ContentHash {
    /// Create a content hash from a lowercase SHA-256 hex digest.
    ///
    /// # Errors
    ///
    /// Returns [`SymphonyError::Validation`] when the digest is not exactly 64
    /// lowercase hexadecimal characters.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 64 || !value.bytes().all(is_lower_hex) {
            return Err(SymphonyError::validation(
                "approval.content_hash",
                "must be a lowercase SHA-256 hex digest",
            ));
        }
        Ok(Self(value))
    }

    /// Borrow the hex digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Return the deterministic content hash for the issue payload.
///
/// The canonical payload is a no-whitespace JSON object with sorted keys:
/// `body`, `commands`, `description`, and `title`. `body` and `commands` are read
/// from [`Issue::extra`] and are serialized as JSON `null` when absent.
#[must_use]
pub fn content_hash(issue: &Issue) -> ContentHash {
    let payload = canonical_content_payload(issue);
    let Ok(bytes) = serde_json::to_vec(&payload) else {
        return ContentHash(sha256_hex(&[]));
    };
    ContentHash(sha256_hex(&bytes))
}

/// Binding key for approval, denial, and consumption events.
///
/// The key is issue id + canonical content hash + network signer. It
/// deliberately excludes `claim_id`; claim ids are short-lived dispatch audit
/// context and are not consulted when approval is re-read.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ApprovalBindingKey {
    /// Issue whose payload was approved or denied.
    pub issue_id: IssueId,
    /// Canonical content hash of the approved payload.
    pub content_hash: ContentHash,
    /// Network signer whose issue payload was approved.
    pub signer_agent_id: AgentId,
}

impl ApprovalBindingKey {
    /// Construct a binding key.
    #[must_use]
    pub fn new(issue_id: IssueId, content_hash: ContentHash, signer_agent_id: AgentId) -> Self {
        Self {
            issue_id,
            content_hash,
            signer_agent_id,
        }
    }
}

/// Verdict carried by an approval event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalVerdict {
    /// Execute the network-sourced issue once, unless the approval is consumed
    /// or expires before dispatch.
    Approve,
    /// Refuse network dispatch for this signer and payload until the payload
    /// changes and therefore receives a new content hash.
    Deny,
}

/// Signed approval or denial event.
///
/// The event is keyed by [`ApprovalBindingKey`]. `claim_id` is audit-only and is
/// neither part of the key nor consulted by [`ApprovalEvent::is_valid`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApprovalEvent {
    /// Issue whose payload was approved or denied.
    pub issue_id: IssueId,
    /// Canonical hash of the issue payload at approval time.
    pub content_hash: ContentHash,
    /// Network agent whose signed issue was approved.
    pub signer_agent_id: AgentId,
    /// Operator verdict.
    pub verdict: ApprovalVerdict,
    /// Approval timestamp as ISO-8601/RFC3339 UTC text.
    pub approved_at: String,
    /// Agent that issued this approval or denial.
    pub approver_agent_id: AgentId,
    /// Claim that was pending when the event was issued. Audit-only; not a
    /// binding key and not used during validity checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    /// Detached ML-DSA-65 signature over the event payload. Local tests may
    /// construct unsigned events, but unsigned events are invalid on read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureEnvelope>,
}

/// A denial event is an [`ApprovalEvent`] with [`ApprovalVerdict::Deny`].
pub type DenialEvent = ApprovalEvent;

/// Stored approval data for one issue.
///
/// `events` contains signed approval and denial decisions. `consumed` contains
/// signed consumption records that spend approvals for exactly one dispatch.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApprovalState {
    /// Approval and denial events retained for the issue.
    pub events: Vec<ApprovalEvent>,
    /// Consumption events that have spent matching approvals.
    pub consumed: Vec<ApprovalConsumed>,
}

impl ApprovalEvent {
    /// Construct an approval event without a signature envelope.
    #[must_use]
    pub fn approve(
        issue_id: IssueId,
        content_hash: ContentHash,
        signer_agent_id: AgentId,
        approved_at: impl Into<String>,
        approver_agent_id: AgentId,
        claim_id: Option<String>,
    ) -> Self {
        Self::new(
            issue_id,
            content_hash,
            signer_agent_id,
            ApprovalVerdict::Approve,
            approved_at,
            approver_agent_id,
            claim_id,
        )
    }

    /// Construct a denial event without a signature envelope.
    #[must_use]
    pub fn deny(
        issue_id: IssueId,
        content_hash: ContentHash,
        signer_agent_id: AgentId,
        approved_at: impl Into<String>,
        approver_agent_id: AgentId,
        claim_id: Option<String>,
    ) -> Self {
        Self::new(
            issue_id,
            content_hash,
            signer_agent_id,
            ApprovalVerdict::Deny,
            approved_at,
            approver_agent_id,
            claim_id,
        )
    }

    /// Return this event's issue/content/signer binding key.
    #[must_use]
    pub fn binding_key(&self) -> ApprovalBindingKey {
        ApprovalBindingKey::new(
            self.issue_id.clone(),
            self.content_hash.clone(),
            self.signer_agent_id.clone(),
        )
    }

    /// Return deterministic raw bytes signed by x0xd for this event.
    ///
    /// The serialized payload is the event as stored, excluding the signature
    /// envelope itself. `claim_id`, when present, is signed for audit integrity
    /// even though it is not a binding key.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the event cannot be encoded.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut clone = self.clone();
        clone.signature = None;
        serde_json::to_vec(&clone).map_err(Into::into)
    }

    /// Return the SHA-256 hex digest of [`Self::signing_payload_bytes`].
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the event cannot be encoded.
    pub fn signing_payload_sha256(&self) -> Result<String> {
        self.signing_payload_bytes()
            .map(|payload| sha256_hex(&payload))
    }

    /// Evaluate data-layer validity for a previously verified approval event.
    ///
    /// Core has no dependency on the signing crate, so this method validates the
    /// stored signature envelope for presence, context, algorithm, signer, and
    /// payload digest consistency. Callers that have a [`SigningClient`](https://docs.rs/x0x-symphony-signing/latest/x0x_symphony_signing/trait.SigningClient.html)
    /// must cryptographically verify the same payload before treating
    /// [`ApprovalValidity::Valid`] as executable consent.
    #[must_use]
    pub fn is_valid(
        &self,
        issue: &Issue,
        signer: &AgentId,
        now: &str,
        ttl: Duration,
        consumed: &[ApprovalConsumed],
    ) -> ApprovalValidity {
        if !self.signature_envelope_is_consistent() {
            return ApprovalValidity::SignatureInvalid;
        }
        if self.content_hash != content_hash(issue) {
            return ApprovalValidity::HashMismatch;
        }
        if &self.signer_agent_id != signer {
            return ApprovalValidity::SignerMismatch;
        }
        if self.verdict == ApprovalVerdict::Approve && approval_expired(&self.approved_at, now, ttl)
        {
            return ApprovalValidity::Expired;
        }
        if self.verdict == ApprovalVerdict::Approve
            && consumed
                .iter()
                .any(|event| event.matches_binding(&self.binding_key()))
        {
            return ApprovalValidity::Consumed;
        }
        ApprovalValidity::Valid
    }

    /// Return `true` when this valid event denies network dispatch.
    #[must_use]
    pub fn is_denial(&self) -> bool {
        self.verdict == ApprovalVerdict::Deny
    }

    fn new(
        issue_id: IssueId,
        content_hash: ContentHash,
        signer_agent_id: AgentId,
        verdict: ApprovalVerdict,
        approved_at: impl Into<String>,
        approver_agent_id: AgentId,
        claim_id: Option<String>,
    ) -> Self {
        Self {
            issue_id,
            content_hash,
            signer_agent_id,
            verdict,
            approved_at: approved_at.into(),
            approver_agent_id,
            claim_id,
            signature: None,
        }
    }

    fn signature_envelope_is_consistent(&self) -> bool {
        let Some(signature) = &self.signature else {
            return false;
        };
        signature.algorithm == SIGN_ALGORITHM
            && signature.context == APPROVAL_CONTEXT
            && signature.signer_agent_id == self.approver_agent_id.as_str()
            && self
                .signing_payload_sha256()
                .is_ok_and(|digest| digest == signature.payload_sha256)
    }
}

/// Signed consumption event that spends one approval execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApprovalConsumed {
    /// Issue whose approval was consumed.
    pub issue_id: IssueId,
    /// Canonical content hash that was consumed.
    pub content_hash: ContentHash,
    /// Network signer whose approval was consumed.
    pub signer_agent_id: AgentId,
    /// Unique consumption nonce.
    pub nonce: String,
    /// Consumption timestamp as ISO-8601/RFC3339 UTC text.
    pub consumed_at: String,
    /// Detached ML-DSA-65 signature over the consumption payload.
    pub signature: SignatureEnvelope,
}

impl ApprovalConsumed {
    /// Construct an approval-consumption event.
    #[must_use]
    pub fn new(
        issue_id: IssueId,
        content_hash: ContentHash,
        signer_agent_id: AgentId,
        nonce: impl Into<String>,
        consumed_at: impl Into<String>,
        signature: SignatureEnvelope,
    ) -> Self {
        Self {
            issue_id,
            content_hash,
            signer_agent_id,
            nonce: nonce.into(),
            consumed_at: consumed_at.into(),
            signature,
        }
    }

    /// Return this consumption event's issue/content/signer binding key.
    #[must_use]
    pub fn binding_key(&self) -> ApprovalBindingKey {
        ApprovalBindingKey::new(
            self.issue_id.clone(),
            self.content_hash.clone(),
            self.signer_agent_id.clone(),
        )
    }

    /// Return deterministic raw bytes signed by x0xd for this consumption.
    ///
    /// The serialized payload is the consumption event as stored, excluding the
    /// signature envelope itself.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the event cannot be encoded.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        let payload = ApprovalConsumedPayload {
            issue_id: &self.issue_id,
            content_hash: &self.content_hash,
            signer_agent_id: &self.signer_agent_id,
            nonce: &self.nonce,
            consumed_at: &self.consumed_at,
        };
        serde_json::to_vec(&payload).map_err(Into::into)
    }

    /// Return the SHA-256 hex digest of [`Self::signing_payload_bytes`].
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the event cannot be encoded.
    pub fn signing_payload_sha256(&self) -> Result<String> {
        self.signing_payload_bytes()
            .map(|payload| sha256_hex(&payload))
    }

    /// Return `true` when the consumption matches an approval binding key.
    #[must_use]
    pub fn matches_binding(&self, binding: &ApprovalBindingKey) -> bool {
        self.issue_id == binding.issue_id
            && self.content_hash == binding.content_hash
            && self.signer_agent_id == binding.signer_agent_id
    }

    /// Return `true` when the stored signature envelope matches this payload.
    #[must_use]
    pub fn signature_envelope_is_consistent(&self) -> bool {
        self.signature.algorithm == SIGN_ALGORITHM
            && self.signature.context == APPROVAL_CONSUMED_CONTEXT
            && self
                .signing_payload_sha256()
                .is_ok_and(|digest| digest == self.signature.payload_sha256)
    }
}

/// Decision produced by evaluating stored approval and denial events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    /// A valid approval exists and no valid denial blocks it.
    Approved,
    /// A valid denial exists for the current payload; dispatch is ineligible
    /// until the payload changes to a new content hash.
    Denied,
    /// No valid approval or denial exists for the current payload.
    Pending,
}

/// Evaluate stored approval/denial events for the current issue payload.
///
/// Denials are terminal for the current content hash: any valid denial wins over
/// approvals with the same binding key. Approval consumption applies only to
/// `Approve` verdicts; a consumed approval cannot erase a signed denial.
#[must_use]
pub fn approval_decision(
    events: &[ApprovalEvent],
    issue: &Issue,
    signer: &AgentId,
    now: &str,
    ttl: Duration,
    consumed: &[ApprovalConsumed],
) -> ApprovalDecision {
    let mut approved = false;
    for event in events {
        if event.is_valid(issue, signer, now, ttl, consumed) == ApprovalValidity::Valid {
            match event.verdict {
                ApprovalVerdict::Approve => approved = true,
                ApprovalVerdict::Deny => return ApprovalDecision::Denied,
            }
        }
    }
    if approved {
        ApprovalDecision::Approved
    } else {
        ApprovalDecision::Pending
    }
}

/// Result of checking an approval event against the current issue view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalValidity {
    /// Event is payload-matching, within TTL, unconsumed, and has a consistent
    /// signature envelope.
    Valid,
    /// The current issue payload no longer hashes to the approved content hash.
    HashMismatch,
    /// The approval timestamp is older than the configured TTL, or a timestamp
    /// could not be parsed and therefore failed closed.
    Expired,
    /// A matching [`ApprovalConsumed`] event already spent this approval.
    Consumed,
    /// The verified issue signer does not match the event signer.
    SignerMismatch,
    /// The signature envelope is missing or inconsistent with the stored
    /// payload. Cryptographic verifier failures should also map here.
    SignatureInvalid,
}

#[derive(Serialize)]
struct ApprovalConsumedPayload<'a> {
    issue_id: &'a IssueId,
    content_hash: &'a ContentHash,
    signer_agent_id: &'a AgentId,
    nonce: &'a str,
    consumed_at: &'a str,
}

fn canonical_content_payload(issue: &Issue) -> BTreeMap<&'static str, Value> {
    let mut payload = BTreeMap::new();
    payload.insert("body", extra_value_or_null(issue, "body"));
    payload.insert("commands", extra_value_or_null(issue, "commands"));
    payload.insert("description", Value::String(issue.description.clone()));
    payload.insert("title", Value::String(issue.title.clone()));
    payload
}

fn extra_value_or_null(issue: &Issue, key: &str) -> Value {
    issue
        .extra
        .get(key)
        .map_or_else(|| Value::Null, Clone::clone)
}

fn approval_expired(approved_at: &str, now: &str, ttl: Duration) -> bool {
    let Some(approved_at) = parse_timestamp(approved_at) else {
        return true;
    };
    let Some(now) = parse_timestamp(now) else {
        return true;
    };
    let Ok(ttl) = chrono::Duration::from_std(ttl) else {
        return true;
    };
    now.signed_duration_since(approved_at) > ttl
}

fn parse_timestamp(value: &str) -> Option<DateTime<chrono::FixedOffset>> {
    DateTime::parse_from_rfc3339(value).ok()
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{IssueState, APPROVAL_CONSUMED_CONTEXT, APPROVAL_CONTEXT};

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    const APPROVED_AT: &str = "2026-07-03T12:00:00Z";
    const NOW: &str = "2026-07-03T13:00:00Z";

    #[test]
    fn valid_approval_verifies() -> TestResult {
        let issue = issue_with_payload("Ship it", "Body", json!(["just test"]))?;
        let signer = AgentId::new("network-signer")?;
        let event = signed_approval(
            &issue,
            signer.clone(),
            ApprovalVerdict::Approve,
            APPROVED_AT,
        )?;

        assert_eq!(
            event.is_valid(&issue, &signer, NOW, Duration::from_hours(24), &[]),
            ApprovalValidity::Valid
        );
        Ok(())
    }

    #[test]
    fn payload_change_voids_approval() -> TestResult {
        let issue = issue_with_payload("Ship it", "Body", json!(["just test"]))?;
        let mut changed = issue.clone();
        changed.title = "Ship something else".to_owned();
        let signer = AgentId::new("network-signer")?;
        let event = signed_approval(
            &issue,
            signer.clone(),
            ApprovalVerdict::Approve,
            APPROVED_AT,
        )?;

        assert_eq!(
            event.is_valid(&changed, &signer, NOW, Duration::from_hours(24), &[]),
            ApprovalValidity::HashMismatch
        );
        Ok(())
    }

    #[test]
    fn expired_approval_invalid() -> TestResult {
        let issue = issue_with_payload("Ship it", "Body", json!(["just test"]))?;
        let signer = AgentId::new("network-signer")?;
        let event = signed_approval(
            &issue,
            signer.clone(),
            ApprovalVerdict::Approve,
            APPROVED_AT,
        )?;

        assert_eq!(
            event.is_valid(&issue, &signer, NOW, Duration::from_mins(30), &[]),
            ApprovalValidity::Expired
        );
        Ok(())
    }

    #[test]
    fn consumed_approval_invalid() -> TestResult {
        let issue = issue_with_payload("Ship it", "Body", json!(["just test"]))?;
        let signer = AgentId::new("network-signer")?;
        let event = signed_approval(
            &issue,
            signer.clone(),
            ApprovalVerdict::Approve,
            APPROVED_AT,
        )?;
        let consumed = signed_consumed(&event, "nonce-1", "2026-07-03T12:30:00Z")?;

        assert_eq!(
            event.is_valid(&issue, &signer, NOW, Duration::from_hours(24), &[consumed]),
            ApprovalValidity::Consumed
        );
        Ok(())
    }

    #[test]
    fn signer_mismatch_invalid() -> TestResult {
        let issue = issue_with_payload("Ship it", "Body", json!(["just test"]))?;
        let signer = AgentId::new("network-signer")?;
        let other_signer = AgentId::new("other-network-signer")?;
        let event = signed_approval(&issue, signer, ApprovalVerdict::Approve, APPROVED_AT)?;

        assert_eq!(
            event.is_valid(&issue, &other_signer, NOW, Duration::from_hours(24), &[]),
            ApprovalValidity::SignerMismatch
        );
        Ok(())
    }

    #[test]
    fn denial_is_terminal() -> TestResult {
        let issue = issue_with_payload("Ship it", "Body", json!(["just test"]))?;
        let signer = AgentId::new("network-signer")?;
        let denial = signed_approval(&issue, signer.clone(), ApprovalVerdict::Deny, APPROVED_AT)?;
        let approval = signed_approval(
            &issue,
            signer.clone(),
            ApprovalVerdict::Approve,
            APPROVED_AT,
        )?;

        let consumed = signed_consumed(&approval, "nonce-1", "2026-07-03T12:30:00Z")?;
        assert_eq!(
            denial.is_valid(
                &issue,
                &signer,
                NOW,
                Duration::from_mins(30),
                std::slice::from_ref(&consumed)
            ),
            ApprovalValidity::Valid
        );
        assert!(denial.is_denial());
        assert_eq!(
            approval_decision(
                &[approval, denial.clone()],
                &issue,
                &signer,
                NOW,
                Duration::from_mins(30),
                &[consumed]
            ),
            ApprovalDecision::Denied
        );

        let mut changed = issue.clone();
        changed.description = "New payload".to_owned();
        assert_eq!(
            approval_decision(
                &[denial],
                &changed,
                &signer,
                NOW,
                Duration::from_mins(30),
                &[]
            ),
            ApprovalDecision::Pending
        );
        Ok(())
    }

    #[test]
    fn content_hash_deterministic() -> TestResult {
        let issue = issue_with_payload("Ship it", "Body", json!(["just test"]))?;
        let same_payload = issue_with_payload("Ship it", "Body", json!(["just test"]))?;
        let mut changed_unhashed = same_payload.clone();
        changed_unhashed.priority = Some(1);
        changed_unhashed.labels.push("urgent".to_owned());
        let changed_payload =
            issue_with_payload("Ship it", "Different body", json!(["just test"]))?;

        assert_eq!(content_hash(&issue), content_hash(&same_payload));
        assert_eq!(content_hash(&issue), content_hash(&changed_unhashed));
        assert_ne!(content_hash(&issue), content_hash(&changed_payload));
        Ok(())
    }

    #[test]
    fn claim_id_is_audit_only_not_binding_key() -> TestResult {
        let issue = issue_with_payload("Ship it", "Body", json!(["just test"]))?;
        let signer = AgentId::new("network-signer")?;
        let mut first = signed_approval(
            &issue,
            signer.clone(),
            ApprovalVerdict::Approve,
            APPROVED_AT,
        )?;
        let mut second = signed_approval(&issue, signer, ApprovalVerdict::Approve, APPROVED_AT)?;
        first.claim_id = Some("claim-a".to_owned());
        second.claim_id = Some("claim-b".to_owned());

        assert_eq!(first.binding_key(), second.binding_key());
        Ok(())
    }

    fn issue_with_payload(title: &str, body: &str, commands: Value) -> TestResult<Issue> {
        let mut issue = Issue::new(
            IssueId::new("XSY-0049")?,
            "XSY-0049",
            title,
            IssueState::new("todo")?,
            "2026-07-03T00:00:00Z",
        )?;
        issue.description = body.to_owned();
        issue.extra.insert("commands".to_owned(), commands);
        Ok(issue)
    }

    fn signed_approval(
        issue: &Issue,
        signer: AgentId,
        verdict: ApprovalVerdict,
        approved_at: &str,
    ) -> TestResult<ApprovalEvent> {
        let mut event = match verdict {
            ApprovalVerdict::Approve => ApprovalEvent::approve(
                issue.id.clone(),
                content_hash(issue),
                signer,
                approved_at,
                AgentId::new("approver")?,
                Some("claim-for-audit".to_owned()),
            ),
            ApprovalVerdict::Deny => ApprovalEvent::deny(
                issue.id.clone(),
                content_hash(issue),
                signer,
                approved_at,
                AgentId::new("approver")?,
                Some("claim-for-audit".to_owned()),
            ),
        };
        let payload_sha256 = event.signing_payload_sha256()?;
        event.signature = Some(SignatureEnvelope::new(
            SIGN_ALGORITHM,
            APPROVAL_CONTEXT,
            "public-key",
            "signature",
            payload_sha256,
            event.approver_agent_id.to_string(),
        ));
        Ok(event)
    }

    fn signed_consumed(
        event: &ApprovalEvent,
        nonce: &str,
        consumed_at: &str,
    ) -> TestResult<ApprovalConsumed> {
        let placeholder = SignatureEnvelope::new(
            SIGN_ALGORITHM,
            APPROVAL_CONSUMED_CONTEXT,
            "public-key",
            "signature",
            "placeholder",
            "consumer",
        );
        let mut consumed = ApprovalConsumed::new(
            event.issue_id.clone(),
            event.content_hash.clone(),
            event.signer_agent_id.clone(),
            nonce,
            consumed_at,
            placeholder,
        );
        let payload_sha256 = consumed.signing_payload_sha256()?;
        consumed.signature = SignatureEnvelope::new(
            SIGN_ALGORITHM,
            APPROVAL_CONSUMED_CONTEXT,
            "public-key",
            "signature",
            payload_sha256,
            "consumer",
        );
        assert!(consumed.signature_envelope_is_consistent());
        Ok(consumed)
    }
}
