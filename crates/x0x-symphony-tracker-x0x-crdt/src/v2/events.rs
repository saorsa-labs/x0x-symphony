//! Tracker-integrity v2 wire types: signed envelopes, genesis/roster
//! manifests, and transition events.
//!
//! Every stored record is an [`EventEnvelope`] JSON document whose
//! `payload_b64` holds the **exact** bytes that were signed. Readers parse the
//! payload *from those bytes*, so there is no canonical-serialization
//! ambiguity: the event hash is simply `SHA-256(payload bytes)` (lowercase
//! hex), and the same value appears in the record's KV key.
//!
//! Signed-payload bindings follow design r2 finding C8: every payload names
//! `schema`, `list_uuid`, `genesis_manifest_hash`, and (for transitions)
//! `roster_epoch`, `issue_id`, kind-specific claim bindings, `author_seq`,
//! and `prev_own_event_hash`. An event is only admissible in the exact
//! list+epoch it names — a byte-identical replay into another list fails the
//! genesis binding.

use serde::{Deserialize, Serialize};
use x0x_symphony_core::sha256_hex;

use super::identity::{decode_b64, derive_agent_id_hex, verify_external_signature};

/// Schema version for all v2 records.
pub const V2_SCHEMA: u32 = 2;

/// Signing algorithm string produced by x0xd for external signatures.
pub const V2_SIGN_ALGORITHM: &str = "x0x.agent-sign.v2.ml-dsa-65";

/// Domain-separation context for v2 transition events.
pub const TRANSITION_CONTEXT_V2: &str = "x0x-symphony-transition-v2";

/// Domain-separation context for the v2 genesis manifest.
pub const GENESIS_CONTEXT_V2: &str = "x0x-symphony-genesis-v2";

/// Domain-separation context for v2 roster events.
pub const ROSTER_CONTEXT_V2: &str = "x0x-symphony-roster-v2";

/// Domain-separation context for v2 approval records (consumed by WP-B; the
/// WP-A fold verifies them inside requeue justifications).
pub const APPROVAL_CONTEXT_V2: &str = "x0x-symphony-approval-v2";

/// Domain-separation context used only to bootstrap the local signer's
/// public key out of `/agent/sign` (the response carries the key). The signed
/// bytes are a fixed sentinel and are never stored.
pub const BOOTSTRAP_CONTEXT_V2: &str = "x0x-symphony-bootstrap-v2";

/// Domain-separation context for v2 consumption records (the v2 upgrade of
/// `x0x-symphony-approval-consumed-v1`).
pub const CONSUME_CONTEXT_V2: &str = "x0x-symphony-consume-v2";

/// Domain-separation context for v2 handoff records (WP-B2).
pub const HANDOFF_CONTEXT_V2: &str = "x0x-symphony-handoff-v2";

/// Prefix marking a v2 list reference (disjoint namespace, design r2 Q5).
pub const V2_LIST_REF_PREFIX: &str = "symphony2:";

/// KV key holding an author's ML-DSA-65 signing public key (raw bytes).
pub const CARD_SELF_KEY: &str = "card-self";

/// KV key holding the creator's signed genesis manifest.
pub const GENESIS_KEY: &str = "genesis";

/// Key prefix for roster events in the creator's store.
pub const ROSTER_KEY_PREFIX: &str = "roster-";

/// Key prefix for transition events.
pub const EVENT_KEY_PREFIX: &str = "ev-";

/// Key prefix for dispatch-approval events.
pub const APPROVAL_KEY_PREFIX: &str = "ap-";

/// Key prefix for consumption events.
pub const CONSUME_KEY_PREFIX: &str = "cs-";

/// Key prefix for handoff events (WP-B2).
pub const HANDOFF_KEY_PREFIX: &str = "ho-";

/// Return the per-author event-store topic for `(list_uuid, agent_id)`.
///
/// One store per author (design r2 finding C4) keeps x0xd's topic-keyed REST
/// surface working unchanged: each topic has exactly one owner.
#[must_use]
pub fn event_store_topic(list_uuid: &str, agent_id_hex: &str) -> String {
    format!("symphony2-ev-{list_uuid}-{agent_id_hex}")
}

/// Return the per-author heartbeat-store topic for `(list_uuid, agent_id)`.
///
/// Heartbeats are v1-style mutable keys and therefore **cannot** live in the
/// append-only event store; they get a mutable (`signed`-policy) companion
/// store. They are never fold inputs.
#[must_use]
pub fn heartbeat_store_topic(list_uuid: &str, agent_id_hex: &str) -> String {
    format!("symphony2-hb-{list_uuid}-{agent_id_hex}")
}

/// Return the KV key for a transition event: `ev-<issue-id>-<event-hash>`.
#[must_use]
pub fn event_key(issue_id: &str, event_hash_hex: &str) -> String {
    format!("{EVENT_KEY_PREFIX}{issue_id}-{event_hash_hex}")
}

/// Return the KV key for a roster event: `roster-<epoch, zero padded>-<hash>`.
#[must_use]
pub fn roster_key(roster_epoch: u64, event_hash_hex: &str) -> String {
    format!("{ROSTER_KEY_PREFIX}{roster_epoch:010}-{event_hash_hex}")
}

/// Return the KV key for a dispatch approval: `ap-<issue-id>-<event-hash>`.
#[must_use]
pub fn approval_key(issue_id: &str, event_hash_hex: &str) -> String {
    format!("{APPROVAL_KEY_PREFIX}{issue_id}-{event_hash_hex}")
}

/// Return the KV key for a consumption event: `cs-<issue-id>-<event-hash>`.
#[must_use]
pub fn consume_key(issue_id: &str, event_hash_hex: &str) -> String {
    format!("{CONSUME_KEY_PREFIX}{issue_id}-{event_hash_hex}")
}

/// Return the KV key for a handoff event: `ho-<issue-id>-<event-hash>`.
#[must_use]
pub fn handoff_key(issue_id: &str, event_hash_hex: &str) -> String {
    format!("{HANDOFF_KEY_PREFIX}{issue_id}-{event_hash_hex}")
}

/// Validate a v2 list uuid: lowercase `[a-z0-9-]`, 1..=64 chars.
///
/// The uuid is embedded in gossip topics and KV keys, so the alphabet is
/// deliberately conservative.
#[must_use]
pub fn is_valid_list_uuid(list_uuid: &str) -> bool {
    !list_uuid.is_empty()
        && list_uuid.len() <= 64
        && list_uuid
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Validate an agent id: exactly 64 lowercase-hex chars.
#[must_use]
pub fn is_valid_agent_id_hex(agent_id: &str) -> bool {
    agent_id.len() == 64
        && agent_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A v2 list reference: `symphony2:<list-uuid>:<creator-agent-id>`.
///
/// The creator id is part of the address because the genesis manifest lives
/// in the creator's event store; without it a reader could not locate (or
/// refuse) the list. A reference that carries the `symphony2:` prefix but
/// does not parse is a **refused** list, never a v1 fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2ListRef {
    /// List uuid (validated by [`is_valid_list_uuid`]).
    pub list_uuid: String,
    /// Creator agent id, lowercase hex.
    pub creator: String,
}

impl V2ListRef {
    /// Render the canonical string form.
    #[must_use]
    pub fn to_ref_string(&self) -> String {
        format!("{V2_LIST_REF_PREFIX}{}:{}", self.list_uuid, self.creator)
    }

    /// Return true when `list_ref` addresses the v2 namespace (whether or not
    /// it parses — an unparseable v2-prefixed ref must be refused, not
    /// silently treated as v1).
    #[must_use]
    pub fn is_v2_namespace(list_ref: &str) -> bool {
        list_ref.starts_with(V2_LIST_REF_PREFIX)
    }

    /// Parse a `symphony2:<uuid>:<creator>` reference.
    ///
    /// # Errors
    ///
    /// Returns a descriptive reason when the reference is not in the v2
    /// namespace or its components fail validation.
    pub fn parse(list_ref: &str) -> Result<Self, String> {
        let rest = list_ref
            .strip_prefix(V2_LIST_REF_PREFIX)
            .ok_or_else(|| format!("not a v2 list reference: {list_ref}"))?;
        let (list_uuid, creator) = rest
            .split_once(':')
            .ok_or_else(|| "v2 list reference must be symphony2:<uuid>:<creator>".to_owned())?;
        if !is_valid_list_uuid(list_uuid) {
            return Err(format!("invalid v2 list uuid: {list_uuid}"));
        }
        if !is_valid_agent_id_hex(creator) {
            return Err(format!("invalid v2 creator agent id: {creator}"));
        }
        Ok(Self {
            list_uuid: list_uuid.to_owned(),
            creator: creator.to_owned(),
        })
    }
}

/// Stored signed record: exact payload bytes plus a detached ML-DSA-65
/// signature over the x0x external DST for `context`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Always [`V2_SCHEMA`].
    pub schema: u32,
    /// Domain-separation context the signature was produced under.
    pub context: String,
    /// Signing algorithm; must be [`V2_SIGN_ALGORITHM`].
    pub algorithm: String,
    /// Base64 of the exact signed payload bytes.
    pub payload_b64: String,
    /// Base64 ML-DSA-65 public key (1952 decoded bytes).
    pub public_key_b64: String,
    /// Base64 detached ML-DSA-65 signature (3309 decoded bytes).
    pub signature_b64: String,
    /// Claimed signer agent id (lowercase hex); verified against the key.
    pub signer_agent_id: String,
}

impl EventEnvelope {
    /// Decode the envelope from stored KV value bytes.
    ///
    /// # Errors
    ///
    /// Returns a descriptive reason when the bytes are not a v2 envelope.
    pub fn decode(value: &[u8]) -> Result<Self, String> {
        let envelope: Self =
            serde_json::from_slice(value).map_err(|e| format!("envelope decode failed: {e}"))?;
        if envelope.schema != V2_SCHEMA {
            return Err(format!("unsupported envelope schema {}", envelope.schema));
        }
        Ok(envelope)
    }

    /// Encode the envelope to KV value bytes.
    ///
    /// # Errors
    ///
    /// Returns a serialization error message (should be unreachable for this
    /// plain-data struct).
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("envelope encode failed: {e}"))
    }

    /// Return the exact signed payload bytes.
    ///
    /// # Errors
    ///
    /// Returns a descriptive reason when `payload_b64` is not valid base64.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, String> {
        decode_b64("payload_b64", &self.payload_b64)
    }

    /// Verify the envelope cryptographically and structurally, **pure**.
    ///
    /// Checks, in order: schema, algorithm, expected context, base64 fields,
    /// ML-DSA-65 signature over the external DST, and the self-certifying
    /// signer binding `derive_agent_id(public_key) == signer_agent_id`.
    ///
    /// On success returns `(payload bytes, event hash hex)` where the event
    /// hash is `SHA-256(payload bytes)`.
    ///
    /// # Errors
    ///
    /// Returns a descriptive rejection reason on any failed check.
    pub fn verify(&self, expected_context: &str) -> Result<(Vec<u8>, String), String> {
        if self.schema != V2_SCHEMA {
            return Err(format!("unsupported envelope schema {}", self.schema));
        }
        if self.algorithm != V2_SIGN_ALGORITHM {
            return Err(format!("unsupported algorithm {}", self.algorithm));
        }
        if self.context != expected_context {
            return Err(format!(
                "context mismatch: envelope names {}, expected {expected_context}",
                self.context
            ));
        }
        let payload = self.payload_bytes()?;
        if payload.is_empty() {
            return Err("empty payload".to_owned());
        }
        let signature = decode_b64("signature_b64", &self.signature_b64)?;
        let public_key = decode_b64("public_key_b64", &self.public_key_b64)?;
        verify_external_signature(expected_context, &payload, &signature, &public_key)
            .map_err(|e| format!("signature check failed: {e}"))?;
        let derived = derive_agent_id_hex(&public_key);
        if derived != self.signer_agent_id {
            return Err(format!(
                "signer binding failed: key derives to {derived}, envelope claims {}",
                self.signer_agent_id
            ));
        }
        let hash = sha256_hex(&payload);
        Ok((payload, hash))
    }
}

/// Genesis policy hints. Trust is **not** a fold input (design r2 findings
/// C2/C3); `required_trust` is carried only as a dispatch-time policy hint.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenesisPolicy {
    /// Minimum local trust an agent may *choose* to require before acting on
    /// list content. Never affects fold admission or folded state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_trust: Option<String>,
}

/// Signed genesis manifest, stored at [`GENESIS_KEY`] in the creator's event
/// store. Its payload hash is the `genesis_manifest_hash` bound into every
/// other record of the list.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenesisManifestV2 {
    /// Always [`V2_SCHEMA`].
    pub schema: u32,
    /// Record discriminator; always `"genesis"`.
    pub kind: String,
    /// List uuid this manifest creates.
    pub list_uuid: String,
    /// Creator agent id (lowercase hex); must equal the signer and the
    /// anchored owner of the store the manifest is read from.
    pub creator: String,
    /// Initial roster (epoch 0): agent ids allowed to author events.
    pub roster: Vec<String>,
    /// Dispatch-time policy hints (never fold inputs).
    #[serde(default)]
    pub policy: GenesisPolicy,
    /// Creation time (seconds since epoch, informational only — the fold
    /// never reads clocks).
    pub created_at: u64,
}

/// Roster update event, creator-signed, hash-chained (design r2 roster
/// manifest). Stored at [`roster_key`] in the creator's store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RosterEventV2 {
    /// Always [`V2_SCHEMA`].
    pub schema: u32,
    /// Record discriminator; always `"roster"`.
    pub kind: String,
    /// List uuid binding.
    pub list_uuid: String,
    /// Genesis manifest hash binding.
    pub genesis_manifest_hash: String,
    /// Epoch this event establishes; strictly `previous epoch + 1`, starting
    /// at 1 (epoch 0 is the genesis roster).
    pub roster_epoch: u64,
    /// Payload hash of the previous roster event, or the genesis manifest
    /// hash for epoch 1.
    pub prev_roster_hash: String,
    /// The complete new roster at this epoch.
    pub roster: Vec<String>,
    /// Author; v2.0 requires this to equal the creator.
    pub actor: String,
}

/// Reason a claim was parked. Only [`BlockReason::AwaitingApproval`] is ever
/// requeue-able (design r2 finding C6); any other reason is terminal for that
/// claim (admin repair = new issue, not mutation).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum BlockReason {
    /// Parked pending an operator approval.
    AwaitingApproval,
    /// Any other reason; never requeue-able.
    Other {
        /// Free-form detail for humans and diagnostics.
        detail: String,
    },
}

/// Justification bindings required for a `Requeue` transition (design r2
/// finding C6). All fields are verified at fold admission; the embedded
/// approval envelope is signature-checked there too.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequeueJustification {
    /// Full payload hash of the `Block` event being un-parked.
    pub block_event_hash: String,
    /// The winning claim nonce that was parked by that block.
    pub claim_nonce: String,
    /// Payload hash of the approval record.
    pub approval_event_hash: String,
    /// SHA-256 of the approval payload bytes. In v2 the event hash *is* the
    /// payload hash, so this must equal `approval_event_hash`; both are kept
    /// so WP-B key-addressed approvals can evolve the two independently.
    pub approval_payload_sha256: String,
    /// Approver agent id (lowercase hex).
    pub approver: String,
    /// The full signed approval record, embedded so admission can verify the
    /// approval signature without any store lookup.
    pub approval: EventEnvelope,
}

/// Approval record payload signed under [`APPROVAL_CONTEXT_V2`].
///
/// WP-B stores these as their own per-key records; in WP-A they appear
/// embedded in [`RequeueJustification`]. TTL is enforced at dispatch time
/// only (design r2 finding C3) — `approved_at` never affects fold validity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApprovalPayloadV2 {
    /// Always [`V2_SCHEMA`].
    pub schema: u32,
    /// Record discriminator; always `"approval"`.
    pub kind: String,
    /// List uuid binding.
    pub list_uuid: String,
    /// Genesis manifest hash binding.
    pub genesis_manifest_hash: String,
    /// Issue the approval applies to.
    pub issue_id: String,
    /// The `Block` event this approval un-parks.
    pub block_event_hash: String,
    /// The parked claim nonce.
    pub claim_nonce: String,
    /// Approver agent id (lowercase hex); must equal the signer.
    pub approver: String,
    /// Approval time (seconds since epoch); dispatch-time TTL input only.
    pub approved_at: u64,
}

/// Transition kind plus its kind-specific claim bindings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransitionKind {
    /// Create an issue.
    Open {
        /// Issue title.
        title: String,
        /// Issue body/spec.
        spec: String,
        /// `SHA-256(title)`, lowercase hex — the digest v1 issue-creation
        /// provenance signed, kept so v1/v2 cross-checking stays
        /// digest-for-digest (WP-B2). Verified at admission.
        title_sha256: String,
        /// `SHA-256(spec)`, lowercase hex. Verified at admission.
        spec_sha256: String,
    },
    /// Claim an issue for exclusive work.
    Claim {
        /// Fresh nonce fencing this claim instance.
        claim_nonce: String,
    },
    /// Voluntarily release a held claim.
    Release {
        /// Nonce of the claim being released.
        claim_nonce: String,
        /// Payload hash of the claim event being released.
        claimed_event_hash: String,
    },
    /// Park a held claim.
    Block {
        /// Nonce of the claim being parked.
        claim_nonce: String,
        /// Payload hash of the claim event being parked.
        claimed_event_hash: String,
        /// Why the claim parked; only `awaiting_approval` is requeue-able.
        reason: BlockReason,
    },
    /// Complete a held claim (terminal).
    Complete {
        /// Nonce of the claim being completed.
        claim_nonce: String,
        /// Payload hash of the claim event being completed.
        claimed_event_hash: String,
    },
    /// Un-park a claim blocked as `awaiting_approval`, with full C6
    /// justification.
    Requeue {
        /// The verified justification bindings.
        justification: RequeueJustification,
    },
}

impl TransitionKind {
    /// Build an `Open` with its WP-B2 content bindings computed from the
    /// carried content (`title_sha256`/`spec_sha256` — the digests v1
    /// issue-creation provenance signed).
    #[must_use]
    pub fn open(title: impl Into<String>, spec: impl Into<String>) -> Self {
        let title = title.into();
        let spec = spec.into();
        let title_sha256 = sha256_hex(title.as_bytes());
        let spec_sha256 = sha256_hex(spec.as_bytes());
        Self::Open {
            title,
            spec,
            title_sha256,
            spec_sha256,
        }
    }

    /// Stable lowercase name of this kind (matches the serde tag).
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Open { .. } => "open",
            Self::Claim { .. } => "claim",
            Self::Release { .. } => "release",
            Self::Block { .. } => "block",
            Self::Complete { .. } => "complete",
            Self::Requeue { .. } => "requeue",
        }
    }
}

/// A v2 transition event payload, signed under [`TRANSITION_CONTEXT_V2`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransitionEventV2 {
    /// Always [`V2_SCHEMA`].
    pub schema: u32,
    /// List uuid binding (C8).
    pub list_uuid: String,
    /// Genesis manifest hash binding (C8).
    pub genesis_manifest_hash: String,
    /// Roster epoch this event claims membership at.
    pub roster_epoch: u64,
    /// Issue the transition applies to.
    pub issue_id: String,
    /// Author agent id (lowercase hex). Must equal the store owner, the
    /// envelope signer, and the id derived from the signing key (C5).
    pub actor: String,
    /// Lamport timestamp for global ordering; admission caps it at
    /// `max(seen) + 64` (C7).
    pub lamport: u64,
    /// Strictly `+1` per author, starting at 1 (C7 hash chain).
    pub author_seq: u64,
    /// Payload hash of this author's previous event, or the genesis manifest
    /// hash for `author_seq == 1` (C7 hash chain).
    pub prev_own_event_hash: String,
    /// The transition itself.
    #[serde(flatten)]
    pub kind: TransitionKind,
}

impl TransitionEventV2 {
    /// Decode a transition payload from exact signed bytes.
    ///
    /// # Errors
    ///
    /// Returns a descriptive reason when the bytes do not parse as a v2
    /// transition payload.
    pub fn decode(payload: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(payload).map_err(|e| format!("transition decode failed: {e}"))
    }

    /// Serialize the payload to the exact bytes to be signed and stored.
    ///
    /// # Errors
    ///
    /// Returns a serialization error message (unreachable for plain data).
    pub fn to_signed_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("transition encode failed: {e}"))
    }
}

/// Verdict of a v2 dispatch approval (parity with v1 `ApprovalVerdict`).
/// Denials are terminal for the bound issue content: the gate never
/// dispatches an issue revision that carries an admitted denial.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalVerdictV2 {
    /// Authorize dispatch of the bound issue content.
    Approve,
    /// Refuse dispatch of the bound issue content.
    Deny,
}

/// WP-B dispatch-approval event, signed under [`APPROVAL_CONTEXT_V2`] and
/// stored at [`approval_key`] in the APPROVER's own event store. Participates
/// in the approver's per-author hash chain (shared `author_seq` numbering
/// with transitions), so approval history is equivocation-evident too.
///
/// `approved_at` is a gate-time TTL input ONLY (design r2 finding C3): an
/// expired approval still folds; the gate refuses to consume it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApprovalEventV2 {
    /// Always [`V2_SCHEMA`].
    pub schema: u32,
    /// Record discriminator; always `"dispatch_approval"` (distinct from the
    /// requeue-justification approval kind `"approval"`).
    pub kind: String,
    /// List uuid binding (C8).
    pub list_uuid: String,
    /// Genesis manifest hash binding (C8).
    pub genesis_manifest_hash: String,
    /// Roster epoch the approver claims membership at.
    pub roster_epoch: u64,
    /// Issue the approval applies to.
    pub issue_id: String,
    /// Payload hash of the issue's `Open` event — binds the approval to the
    /// exact issue content (v2 analogue of v1's `content_hash`).
    pub open_event_hash: String,
    /// Approver agent id; must satisfy the four-way author binding.
    pub actor: String,
    /// Lamport timestamp (global fold ordering).
    pub lamport: u64,
    /// Per-author chain sequence (shared numbering with transitions).
    pub author_seq: u64,
    /// Previous own-event hash in the approver's chain.
    pub prev_own_event_hash: String,
    /// Approve or deny.
    pub verdict: ApprovalVerdictV2,
    /// Uniqueness entropy so two otherwise-identical approvals are distinct
    /// records.
    pub entropy: String,
    /// Approval time (seconds since epoch); gate-time TTL input only.
    pub approved_at: u64,
    /// v1-interop carrier (WP-B2): the verbatim v1 `ApprovalEvent` JSON
    /// (including its v1 signature envelope) when this record was written
    /// through the v1 `Tracker::store_approval` bridge. Opaque to the fold
    /// — NEVER a fold input — but integrity-covered by this record's own
    /// signature. Empty = absent.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub v1_record_json: String,
}

impl ApprovalEventV2 {
    /// Decode from exact signed bytes.
    ///
    /// # Errors
    ///
    /// Returns a descriptive reason when the bytes do not parse.
    pub fn decode(payload: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(payload).map_err(|e| format!("approval decode failed: {e}"))
    }

    /// Serialize to the exact bytes to be signed and stored.
    ///
    /// # Errors
    ///
    /// Returns a serialization error message (unreachable for plain data).
    pub fn to_signed_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("approval encode failed: {e}"))
    }
}

/// WP-B consumption event, signed under [`CONSUME_CONTEXT_V2`] and stored at
/// [`consume_key`] in the CONSUMER's own event store. Participates in the
/// consumer's per-author hash chain. Set-union convergent: concurrent
/// consumers can never clobber each other's records — duplicates resolve
/// deterministically in fold order and losers are surfaced as diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsumeEventV2 {
    /// Always [`V2_SCHEMA`].
    pub schema: u32,
    /// Record discriminator; always `"consume"`.
    pub kind: String,
    /// List uuid binding (C8).
    pub list_uuid: String,
    /// Genesis manifest hash binding (C8).
    pub genesis_manifest_hash: String,
    /// Roster epoch the consumer claims membership at.
    pub roster_epoch: u64,
    /// Issue the consumption applies to.
    pub issue_id: String,
    /// Consumer agent id; must satisfy the four-way author binding.
    pub actor: String,
    /// Lamport timestamp (global fold ordering; competing consumes for one
    /// approval resolve by fold order).
    pub lamport: u64,
    /// Per-author chain sequence (shared numbering with transitions).
    pub author_seq: u64,
    /// Previous own-event hash in the consumer's chain.
    pub prev_own_event_hash: String,
    /// Payload hash of the approval being consumed.
    pub approval_event_hash: String,
    /// SHA-256 of the approval payload bytes; equals `approval_event_hash`
    /// in v2 (kept separately for WP-B+ evolution, mirroring C6).
    pub approval_payload_sha256: String,
    /// Approver named by the consumed approval.
    pub approver: String,
    /// Fencing nonce of the consumer's fold-winning claim.
    pub claim_nonce: String,
    /// Payload hash of the consumer's fold-winning claim event.
    pub claimed_event_hash: String,
    /// Uniqueness entropy.
    pub entropy: String,
    /// v1-interop carrier (WP-B2): the verbatim v1 `ApprovalConsumed` JSON
    /// (with its mandatory v1 signature envelope) when written through the
    /// v1 `Tracker::store_consumed` bridge. Opaque to the fold. Empty =
    /// absent (e.g. gate-minted consumes).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub v1_record_json: String,
}

impl ConsumeEventV2 {
    /// Decode from exact signed bytes.
    ///
    /// # Errors
    ///
    /// Returns a descriptive reason when the bytes do not parse.
    pub fn decode(payload: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(payload).map_err(|e| format!("consume decode failed: {e}"))
    }

    /// Serialize to the exact bytes to be signed and stored.
    ///
    /// # Errors
    ///
    /// Returns a serialization error message (unreachable for plain data).
    pub fn to_signed_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("consume encode failed: {e}"))
    }
}

/// One validation entry of a v2 handoff — the semantic triple v1's
/// `ValidationResult` carries (command, status, exit code), flattened to
/// plain data so the signed v2 wire shape does not depend on v1 serde.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HandoffValidationV2 {
    /// Command or check that ran.
    pub command: String,
    /// Status string (v1 `ValidationStatus` `snake_case` spelling).
    pub status: String,
    /// Process exit code when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// WP-B2 handoff record, signed under [`HANDOFF_CONTEXT_V2`] and stored at
/// [`handoff_key`] in the AUTHOR's own event store. Participates in the
/// author's per-author hash chain. Carries the v1 handoff payload's semantic
/// fields plus full C8 bindings and the claim fence it was produced under.
/// A handoff never changes issue status — the `complete` transition does.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HandoffEventV2 {
    /// Always [`V2_SCHEMA`].
    pub schema: u32,
    /// Record discriminator; always `"handoff"`.
    pub kind: String,
    /// List uuid binding (C8).
    pub list_uuid: String,
    /// Genesis manifest hash binding (C8).
    pub genesis_manifest_hash: String,
    /// Roster epoch the author claims membership at.
    pub roster_epoch: u64,
    /// Issue the handoff belongs to.
    pub issue_id: String,
    /// Author agent id; must satisfy the four-way author binding.
    pub actor: String,
    /// Lamport timestamp (global fold ordering).
    pub lamport: u64,
    /// Per-author chain sequence (shared numbering with transitions).
    pub author_seq: u64,
    /// Previous own-event hash in the author's chain.
    pub prev_own_event_hash: String,
    /// Fencing nonce of the author's fold-winning claim.
    pub claim_nonce: String,
    /// Payload hash of the author's fold-winning claim event.
    pub claimed_event_hash: String,
    /// Handoff summary (v1 semantic field).
    pub summary: String,
    /// Files changed (v1 semantic field).
    pub files_changed: Vec<String>,
    /// Validation results (v1 semantic field, flattened).
    pub validation: Vec<HandoffValidationV2>,
    /// Follow-up items (v1 semantic field).
    pub follow_up: Vec<String>,
    /// Proofs directory (v1 semantic field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proofs_dir: Option<String>,
}

impl HandoffEventV2 {
    /// Decode from exact signed bytes.
    ///
    /// # Errors
    ///
    /// Returns a descriptive reason when the bytes do not parse.
    pub fn decode(payload: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(payload).map_err(|e| format!("handoff decode failed: {e}"))
    }

    /// Serialize to the exact bytes to be signed and stored.
    ///
    /// # Errors
    ///
    /// Returns a serialization error message (unreachable for plain data).
    pub fn to_signed_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("handoff encode failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn list_ref_roundtrip_and_refusal() -> TestResult {
        let creator = "a".repeat(64);
        let r = V2ListRef::parse(&format!("symphony2:my-list-1:{creator}"))
            .map_err(std::io::Error::other)?;
        assert_eq!(r.list_uuid, "my-list-1");
        assert_eq!(r.to_ref_string(), format!("symphony2:my-list-1:{creator}"));
        assert!(V2ListRef::is_v2_namespace(&r.to_ref_string()));
        assert!(!V2ListRef::is_v2_namespace("symphony-legacy-list"));
        // v2-prefixed but malformed refs must fail parse (⇒ refused upstream).
        assert!(V2ListRef::parse("symphony2:BAD UUID:abc").is_err());
        assert!(V2ListRef::parse("symphony2:list-only").is_err());
        assert!(V2ListRef::parse(&format!("symphony2:list:{}", "Z".repeat(64))).is_err());
        Ok(())
    }

    #[test]
    fn transition_kind_serde_tags_are_stable() -> TestResult {
        let ev = TransitionEventV2 {
            schema: V2_SCHEMA,
            list_uuid: "l".to_owned(),
            genesis_manifest_hash: "g".to_owned(),
            roster_epoch: 0,
            issue_id: "i".to_owned(),
            actor: "a".to_owned(),
            lamport: 1,
            author_seq: 1,
            prev_own_event_hash: "p".to_owned(),
            kind: TransitionKind::Claim {
                claim_nonce: "n".to_owned(),
            },
        };
        let bytes = ev.to_signed_bytes().map_err(std::io::Error::other)?;
        let json: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(json["kind"], "claim");
        assert_eq!(json["claim_nonce"], "n");
        let back = TransitionEventV2::decode(&bytes).map_err(std::io::Error::other)?;
        assert_eq!(back, ev);
        Ok(())
    }

    #[test]
    fn topics_and_keys_are_deterministic() {
        assert_eq!(
            event_store_topic("list-1", "aa"),
            "symphony2-ev-list-1-aa".to_owned()
        );
        assert_eq!(
            heartbeat_store_topic("list-1", "aa"),
            "symphony2-hb-list-1-aa".to_owned()
        );
        assert_eq!(event_key("issue", "hash"), "ev-issue-hash");
        assert_eq!(roster_key(3, "h"), "roster-0000000003-h");
    }
}
