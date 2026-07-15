//! The pure two-phase fold for tracker-integrity v2.
//!
//! [`fold_v2`] maps a set of author streams (exact bytes read from per-author
//! event stores) to folded issue state. It is a **pure function**: no I/O, no
//! clocks, no trust lookups (design r2 findings C2/C3 — trust and TTL are
//! dispatch-time policy, never fold inputs). Two independent fold instances
//! given the same event set produce identical output regardless of input
//! order.
//!
//! The full specification lives in `docs/design/tracker-integrity-v2.md`;
//! the implementation follows it section by section:
//!
//! - **Phase 1 — admission**: genesis resolution (missing/invalid ⇒ the list
//!   is refused entirely, never a v1 fallback), roster chain, four-way author
//!   binding, envelope verification, roster-at-epoch membership, per-author
//!   hash chains (gap/fork ⇒ inadmissible from the break, fork evidence
//!   surfaced), lamport future-dating cap, and C8 list/epoch bindings.
//! - **Phase 2 — state machine**: admitted events ordered by
//!   `(lamport, actor, event_hash)` drive a deterministic per-issue state
//!   machine with claim fencing and C6 requeue justification checks.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::events::{
    ApprovalPayloadV2, BlockReason, EventEnvelope, GenesisManifestV2, RosterEventV2,
    TransitionEventV2, TransitionKind, APPROVAL_CONTEXT_V2, CARD_SELF_KEY, EVENT_KEY_PREFIX,
    GENESIS_CONTEXT_V2, GENESIS_KEY, ROSTER_CONTEXT_V2, ROSTER_KEY_PREFIX, TRANSITION_CONTEXT_V2,
    V2_SCHEMA,
};
use super::identity::derive_agent_id_hex;

/// Admission cap on lamport future-dating: an event whose lamport exceeds the
/// running admitted maximum by more than this constant is inadmissible
/// (design r2 finding C7).
pub const LAMPORT_MAX_SKEW: u64 = 64;

/// One record read verbatim from an author's event store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreRecord {
    /// KV key the record was stored under.
    pub key: String,
    /// Raw value bytes.
    pub value: Vec<u8>,
}

/// The full contents of one author's event store, as anchored and read by
/// the local x0xd replica.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorStream {
    /// Anchored store owner (lowercase hex agent id) reported by x0xd for
    /// this store. The fold trusts this only as *addressing*; every event is
    /// still independently bound to it via the self-certifying key check.
    pub owner: String,
    /// Raw `card-self` value (the author's ML-DSA-65 public key bytes), when
    /// present.
    pub card_self: Option<Vec<u8>>,
    /// All records read from the store (any keys; the fold filters).
    pub records: Vec<StoreRecord>,
}

/// Input to [`fold_v2`]: the list address plus every author stream the
/// reader could fetch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FoldInput {
    /// List uuid from the v2 list reference.
    pub list_uuid: String,
    /// Creator agent id from the v2 list reference.
    pub creator: String,
    /// Author streams (order irrelevant; the fold canonicalizes).
    pub streams: Vec<AuthorStream>,
}

/// Why a v2-addressed list was refused outright (downgrade defense, design
/// r2 Q5). A refused list exposes **no** state — there is no v1 fallback.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ListRefusal {
    /// The creator's stream was not supplied.
    #[error("v2 list refused: creator stream {0} is missing")]
    MissingCreatorStream(String),
    /// The creator's stream has no genesis record.
    #[error("v2 list refused: genesis manifest is missing from creator store")]
    MissingGenesis,
    /// The genesis record exists but failed verification.
    #[error("v2 list refused: invalid genesis manifest: {0}")]
    InvalidGenesis(String),
}

/// Evidence of a per-author chain fork: two signature-valid events by the
/// same author carrying the same `author_seq` (design r2 finding C7).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ForkEvidence {
    /// Forking author.
    pub author: String,
    /// The duplicated sequence number.
    pub author_seq: u64,
    /// Payload hashes of the conflicting events (sorted).
    pub event_hashes: Vec<String>,
}

/// Which fold phase rejected a record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionPhase {
    /// Phase 1 — cryptographic/structural admission.
    Admission,
    /// Phase 2 — the state machine found the event ineffective.
    StateMachine,
}

/// A rejected (or ineffective) record, surfaced for diagnostics. Rejections
/// never change folded state; they exist so hostile or corrupt inputs are
/// visible instead of silently dropped.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Rejection {
    /// Stream owner the record was read from.
    pub author: String,
    /// KV key of the record.
    pub key: String,
    /// Rejecting phase.
    pub phase: RejectionPhase,
    /// Human-readable reason.
    pub reason: String,
}

/// Folded status of a single issue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IssueStatusV2 {
    /// Claimable.
    Open,
    /// Exclusively claimed.
    Claimed {
        /// Claimant agent id.
        claimant: String,
        /// Fencing nonce of the winning claim.
        claim_nonce: String,
        /// Payload hash of the winning claim event.
        claim_event_hash: String,
    },
    /// Parked by the claimant.
    Blocked {
        /// Claimant that parked the issue.
        claimant: String,
        /// Fencing nonce of the parked claim.
        claim_nonce: String,
        /// Payload hash of the parked claim event.
        claim_event_hash: String,
        /// Payload hash of the block event.
        block_event_hash: String,
        /// Why the claim parked.
        reason: BlockReason,
    },
    /// Completed (terminal).
    Done {
        /// Agent that completed the issue.
        completed_by: String,
        /// Payload hash of the completing event.
        complete_event_hash: String,
    },
}

/// Folded state of a single issue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssueStateV2 {
    /// Issue id.
    pub issue_id: String,
    /// Title from the creating `Open` event.
    pub title: String,
    /// Spec/body from the creating `Open` event.
    pub spec: String,
    /// Author of the creating `Open` event.
    pub opened_by: String,
    /// Payload hash of the creating `Open` event.
    pub open_event_hash: String,
    /// Current status.
    pub status: IssueStatusV2,
    /// Payload hashes of every event that *changed* this issue's state, in
    /// application order.
    pub applied: Vec<String>,
}

/// Deterministic output of [`fold_v2`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FoldOutput {
    /// Verified genesis manifest.
    pub genesis: GenesisManifestV2,
    /// `SHA-256` of the genesis payload bytes.
    pub genesis_hash: String,
    /// Highest roster epoch established by the verified roster chain
    /// (0 = genesis roster only).
    pub latest_roster_epoch: u64,
    /// Folded issues, keyed by issue id.
    pub issues: BTreeMap<String, IssueStateV2>,
    /// Highest lamport among admitted events (0 when none) — callers use
    /// this to stamp their next event.
    pub max_admitted_lamport: u64,
    /// Diagnostics: rejected/ineffective records (canonically sorted).
    pub rejections: Vec<Rejection>,
    /// Diagnostics: per-author chain forks (canonically sorted).
    pub forks: Vec<ForkEvidence>,
}

/// An admitted transition candidate flowing from phase 1 to phase 2.
#[derive(Clone, Debug)]
struct Admitted {
    author: String,
    key: String,
    event_hash: String,
    event: TransitionEventV2,
}

/// Fold a v2 list: pure `(event set) -> state`.
///
/// See the module docs and `docs/design/tracker-integrity-v2.md` for the full
/// rule set.
///
/// # Errors
///
/// Returns [`ListRefusal`] when the genesis manifest is missing or invalid —
/// the entire list is refused (downgrade defense); no partial state is
/// exposed.
#[allow(clippy::too_many_lines)] // The phase pipeline reads best as one unit.
pub fn fold_v2(input: &FoldInput) -> Result<FoldOutput, ListRefusal> {
    let mut rejections: Vec<Rejection> = Vec::new();
    let mut forks: Vec<ForkEvidence> = Vec::new();

    // Canonicalize stream order so nothing downstream depends on input order.
    // Duplicate streams for the same owner are merged (records concatenated,
    // then key-sorted); duplicate identical records collapse.
    let streams = canonical_streams(&input.streams);

    // ---- Genesis resolution (refusal gate) --------------------------------
    let creator_stream = streams
        .get(&input.creator)
        .ok_or_else(|| ListRefusal::MissingCreatorStream(input.creator.clone()))?;
    let creator_card = verified_card(creator_stream)
        .map_err(|e| ListRefusal::InvalidGenesis(format!("creator card-self: {e}")))?;
    let genesis_record = creator_stream
        .records
        .iter()
        .find(|r| r.key == GENESIS_KEY)
        .ok_or(ListRefusal::MissingGenesis)?;
    let (genesis, genesis_hash) = verify_genesis(
        genesis_record,
        &input.list_uuid,
        &input.creator,
        &creator_card,
    )
    .map_err(ListRefusal::InvalidGenesis)?;

    // ---- Roster chain ------------------------------------------------------
    // rosters[e] = membership at epoch e; epoch 0 is the genesis roster.
    let mut rosters: Vec<BTreeSet<String>> = vec![genesis.roster.iter().cloned().collect()];
    build_roster_chain(
        creator_stream,
        &input.list_uuid,
        &input.creator,
        &creator_card,
        &genesis_hash,
        &mut rosters,
        &mut rejections,
        &mut forks,
    );
    let latest_roster_epoch = u64::try_from(rosters.len())
        .unwrap_or(u64::MAX)
        .saturating_sub(1);

    // ---- Phase 1: per-stream candidate admission ---------------------------
    let mut per_author: BTreeMap<String, Vec<Admitted>> = BTreeMap::new();
    for (owner, stream) in &streams {
        let card = match verified_card(stream) {
            Ok(card) => card,
            Err(reason) => {
                // No verifiable author key ⇒ every event in the stream is
                // inadmissible (the four-way binding cannot be established).
                for record in event_records(stream) {
                    rejections.push(admission_rejection(owner, &record.key, reason.clone()));
                }
                continue;
            }
        };
        let mut candidates: Vec<Admitted> = Vec::new();
        for record in event_records(stream) {
            match admit_event(
                record,
                owner,
                &card,
                &input.list_uuid,
                &genesis_hash,
                &rosters,
            ) {
                Ok(admitted) => candidates.push(admitted),
                Err(reason) => rejections.push(admission_rejection(owner, &record.key, reason)),
            }
        }
        per_author.insert(owner.clone(), candidates);
    }

    // ---- Phase 1: per-author hash chains (C7) ------------------------------
    let mut chained: Vec<Admitted> = Vec::new();
    for (author, candidates) in &per_author {
        chain_author(
            author,
            candidates,
            &genesis_hash,
            &mut chained,
            &mut rejections,
            &mut forks,
        );
    }

    // ---- Phase 1: lamport future-dating cap (C7) ---------------------------
    let admitted = apply_lamport_cap(chained, &mut rejections);
    let max_admitted_lamport = admitted.iter().map(|a| a.event.lamport).max().unwrap_or(0);

    // ---- Phase 2: deterministic state machine ------------------------------
    let mut ordered = admitted;
    ordered.sort_by(|a, b| {
        (a.event.lamport, &a.author, &a.event_hash).cmp(&(
            b.event.lamport,
            &b.author,
            &b.event_hash,
        ))
    });
    let mut issues: BTreeMap<String, IssueStateV2> = BTreeMap::new();
    for adm in &ordered {
        if let Err(reason) = apply_transition(&mut issues, adm) {
            rejections.push(Rejection {
                author: adm.author.clone(),
                key: adm.key.clone(),
                phase: RejectionPhase::StateMachine,
                reason,
            });
        }
    }

    // Canonical diagnostic order: independent of input order.
    rejections.sort_by(|a, b| (&a.author, &a.key, &a.reason).cmp(&(&b.author, &b.key, &b.reason)));
    rejections.dedup();
    forks.sort_by(|a, b| (&a.author, a.author_seq).cmp(&(&b.author, b.author_seq)));
    forks.dedup();

    Ok(FoldOutput {
        genesis,
        genesis_hash,
        latest_roster_epoch,
        issues,
        max_admitted_lamport,
        rejections,
        forks,
    })
}

/// Merge and canonicalize input streams by owner; sort records by key.
fn canonical_streams(streams: &[AuthorStream]) -> BTreeMap<String, AuthorStream> {
    let mut merged: BTreeMap<String, AuthorStream> = BTreeMap::new();
    for stream in streams {
        let entry = merged
            .entry(stream.owner.clone())
            .or_insert_with(|| AuthorStream {
                owner: stream.owner.clone(),
                card_self: None,
                records: Vec::new(),
            });
        if entry.card_self.is_none() {
            entry.card_self.clone_from(&stream.card_self);
        }
        entry.records.extend(stream.records.iter().cloned());
    }
    for stream in merged.values_mut() {
        stream
            .records
            .sort_by(|a, b| (&a.key, &a.value).cmp(&(&b.key, &b.value)));
        stream.records.dedup();
    }
    merged
}

/// Verify a stream's `card-self` against its anchored owner. Returns the raw
/// public-key bytes on success.
fn verified_card(stream: &AuthorStream) -> Result<Vec<u8>, String> {
    let card = stream
        .card_self
        .clone()
        .or_else(|| {
            stream
                .records
                .iter()
                .find(|r| r.key == CARD_SELF_KEY)
                .map(|r| r.value.clone())
        })
        .ok_or_else(|| "card-self is missing".to_owned())?;
    let derived = derive_agent_id_hex(&card);
    if derived != stream.owner {
        return Err(format!(
            "card-self key derives to {derived}, store owner is {}",
            stream.owner
        ));
    }
    Ok(card)
}

/// Verify the genesis envelope and payload against the list address.
fn verify_genesis(
    record: &StoreRecord,
    list_uuid: &str,
    creator: &str,
    creator_card: &[u8],
) -> Result<(GenesisManifestV2, String), String> {
    let envelope = EventEnvelope::decode(&record.value)?;
    let (payload, hash) = envelope.verify(GENESIS_CONTEXT_V2)?;
    check_envelope_key(&envelope, creator, creator_card)?;
    let genesis: GenesisManifestV2 =
        serde_json::from_slice(&payload).map_err(|e| format!("genesis decode failed: {e}"))?;
    if genesis.schema != V2_SCHEMA {
        return Err(format!("genesis schema {} != {V2_SCHEMA}", genesis.schema));
    }
    if genesis.kind != "genesis" {
        return Err(format!("genesis kind {} != genesis", genesis.kind));
    }
    if genesis.list_uuid != list_uuid {
        return Err(format!(
            "genesis names list {} but the address names {list_uuid}",
            genesis.list_uuid
        ));
    }
    if genesis.creator != creator {
        return Err(format!(
            "genesis names creator {} but the address names {creator}",
            genesis.creator
        ));
    }
    if genesis.roster.is_empty() {
        return Err("genesis roster is empty".to_owned());
    }
    Ok((genesis, hash))
}

/// Require the envelope's signing key to be exactly the author's `card-self`
/// key and its signer to be `expected_signer`. Together with
/// `EventEnvelope::verify` (key ⇒ signer derivation) and `verified_card`
/// (card ⇒ owner derivation) this closes the four-way binding.
fn check_envelope_key(
    envelope: &EventEnvelope,
    expected_signer: &str,
    card: &[u8],
) -> Result<(), String> {
    if envelope.signer_agent_id != expected_signer {
        return Err(format!(
            "envelope signer {} is not {expected_signer}",
            envelope.signer_agent_id
        ));
    }
    let key = super::identity::decode_b64("public_key_b64", &envelope.public_key_b64)?;
    if key != card {
        return Err("envelope signing key differs from the author's card-self key".to_owned());
    }
    Ok(())
}

/// Build the creator-signed roster chain (design r2 roster manifest).
#[allow(clippy::too_many_arguments)]
fn build_roster_chain(
    creator_stream: &AuthorStream,
    list_uuid: &str,
    creator: &str,
    creator_card: &[u8],
    genesis_hash: &str,
    rosters: &mut Vec<BTreeSet<String>>,
    rejections: &mut Vec<Rejection>,
    forks: &mut Vec<ForkEvidence>,
) {
    // Collect verified roster events keyed by epoch.
    let mut by_epoch: BTreeMap<u64, Vec<(String, RosterEventV2, String)>> = BTreeMap::new();
    for record in &creator_stream.records {
        if !record.key.starts_with(ROSTER_KEY_PREFIX) {
            continue;
        }
        let verified = (|| -> Result<(RosterEventV2, String), String> {
            let envelope = EventEnvelope::decode(&record.value)?;
            let (payload, hash) = envelope.verify(ROSTER_CONTEXT_V2)?;
            check_envelope_key(&envelope, creator, creator_card)?;
            let roster: RosterEventV2 = serde_json::from_slice(&payload)
                .map_err(|e| format!("roster decode failed: {e}"))?;
            if roster.schema != V2_SCHEMA || roster.kind != "roster" {
                return Err("roster schema/kind mismatch".to_owned());
            }
            if roster.list_uuid != list_uuid || roster.genesis_manifest_hash != genesis_hash {
                return Err("roster list/genesis binding mismatch".to_owned());
            }
            if roster.actor != creator {
                return Err(format!("roster actor {} is not the creator", roster.actor));
            }
            if roster.roster_epoch == 0 {
                return Err("roster epoch 0 is reserved for the genesis roster".to_owned());
            }
            if roster.roster.is_empty() {
                return Err("roster update is empty".to_owned());
            }
            Ok((roster, hash))
        })();
        match verified {
            Ok((roster, hash)) => by_epoch.entry(roster.roster_epoch).or_default().push((
                record.key.clone(),
                roster,
                hash,
            )),
            Err(reason) => {
                rejections.push(admission_rejection(creator, &record.key, reason));
            }
        }
    }

    // Walk epochs 1..: each must chain to the previous accepted hash.
    let mut prev_hash = genesis_hash.to_owned();
    let mut epoch = 1u64;
    while let Some(candidates) = by_epoch.get(&epoch) {
        let mut linked: Vec<&(String, RosterEventV2, String)> = candidates
            .iter()
            .filter(|(_, roster, _)| roster.prev_roster_hash == prev_hash)
            .collect();
        linked.sort_by(|a, b| a.2.cmp(&b.2));
        linked.dedup_by(|a, b| a.2 == b.2);
        for (key, _, _) in candidates
            .iter()
            .filter(|(_, roster, _)| roster.prev_roster_hash != prev_hash)
        {
            rejections.push(admission_rejection(
                creator,
                key,
                "roster prev-hash does not chain".to_owned(),
            ));
        }
        match linked.as_slice() {
            [] => break,
            [(_, roster, hash)] => {
                rosters.push(roster.roster.iter().cloned().collect());
                prev_hash.clone_from(hash);
                epoch += 1;
            }
            many => {
                // Creator forked its own roster chain: surface evidence and
                // stop the chain before the forked epoch (self-harm only).
                forks.push(ForkEvidence {
                    author: creator.to_owned(),
                    author_seq: epoch,
                    event_hashes: many.iter().map(|(_, _, h)| h.clone()).collect(),
                });
                for (key, _, _) in many {
                    rejections.push(admission_rejection(
                        creator,
                        key,
                        format!("roster chain fork at epoch {epoch}"),
                    ));
                }
                break;
            }
        }
    }

    // Epochs recorded beyond a break are unreachable ⇒ reject for visibility.
    for (e, candidates) in &by_epoch {
        if *e >= epoch {
            for (key, _, _) in candidates {
                rejections.push(admission_rejection(
                    creator,
                    key,
                    format!("roster epoch {e} does not extend the verified chain"),
                ));
            }
        }
    }
}

/// Iterate a stream's transition-event records (`ev-*` keys).
fn event_records(stream: &AuthorStream) -> impl Iterator<Item = &StoreRecord> {
    stream
        .records
        .iter()
        .filter(|r| r.key.starts_with(EVENT_KEY_PREFIX))
}

fn admission_rejection(author: &str, key: &str, reason: String) -> Rejection {
    Rejection {
        author: author.to_owned(),
        key: key.to_owned(),
        phase: RejectionPhase::Admission,
        reason,
    }
}

/// Admit a single transition event: envelope, four-way binding, C8 list
/// bindings, key integrity, roster-at-epoch membership, and (for requeues)
/// the C6 justification.
fn admit_event(
    record: &StoreRecord,
    owner: &str,
    card: &[u8],
    list_uuid: &str,
    genesis_hash: &str,
    rosters: &[BTreeSet<String>],
) -> Result<Admitted, String> {
    let envelope = EventEnvelope::decode(&record.value)?;
    let (payload, event_hash) = envelope.verify(TRANSITION_CONTEXT_V2)?;
    check_envelope_key(&envelope, owner, card)?;
    let event = TransitionEventV2::decode(&payload)?;

    // Four-way binding, final leg (C5): payload actor == store owner
    // (== envelope signer == derived key id, established above).
    if event.actor != owner {
        return Err(format!(
            "event actor {} is not the store owner {owner}",
            event.actor
        ));
    }

    // C8 bindings: schema, list, genesis.
    if event.schema != V2_SCHEMA {
        return Err(format!("event schema {} != {V2_SCHEMA}", event.schema));
    }
    if event.list_uuid != list_uuid {
        return Err(format!(
            "event names list {} but this list is {list_uuid} (cross-list replay?)",
            event.list_uuid
        ));
    }
    if event.genesis_manifest_hash != genesis_hash {
        return Err("event genesis binding does not match this list's genesis".to_owned());
    }

    // Key integrity: the record must be stored under its own content
    // address, `ev-<issue>-<hash>`.
    let expected_key = super::events::event_key(&event.issue_id, &event_hash);
    if record.key != expected_key {
        return Err(format!(
            "record key {} does not match content address {expected_key}",
            record.key
        ));
    }

    // Roster membership at the event's named epoch.
    let epoch =
        usize::try_from(event.roster_epoch).map_err(|_| "roster epoch out of range".to_owned())?;
    let roster = rosters
        .get(epoch)
        .ok_or_else(|| format!("event names unknown roster epoch {}", event.roster_epoch))?;
    if !roster.contains(&event.actor) {
        return Err(format!(
            "actor {} is not a roster member at epoch {}",
            event.actor, event.roster_epoch
        ));
    }

    // C6: requeue justification is verified at admission.
    if let TransitionKind::Requeue { justification } = &event.kind {
        let (approval_payload, approval_hash) = justification
            .approval
            .verify(APPROVAL_CONTEXT_V2)
            .map_err(|e| format!("requeue approval envelope: {e}"))?;
        if approval_hash != justification.approval_event_hash {
            return Err(
                "requeue approval event hash does not match the embedded record".to_owned(),
            );
        }
        if approval_hash != justification.approval_payload_sha256 {
            return Err(
                "requeue approval payload hash does not match the embedded record".to_owned(),
            );
        }
        let approval: ApprovalPayloadV2 = serde_json::from_slice(&approval_payload)
            .map_err(|e| format!("approval decode failed: {e}"))?;
        if approval.schema != V2_SCHEMA || approval.kind != "approval" {
            return Err("approval schema/kind mismatch".to_owned());
        }
        if approval.list_uuid != list_uuid || approval.genesis_manifest_hash != genesis_hash {
            return Err("approval list/genesis binding mismatch".to_owned());
        }
        if approval.issue_id != event.issue_id {
            return Err("approval issue does not match the requeue issue".to_owned());
        }
        if approval.approver != justification.approver {
            return Err("approval approver does not match the justification".to_owned());
        }
        if justification.approval.signer_agent_id != approval.approver {
            return Err("approval signer is not the named approver".to_owned());
        }
        if approval.block_event_hash != justification.block_event_hash {
            return Err("approval block binding does not match the justification".to_owned());
        }
        if approval.claim_nonce != justification.claim_nonce {
            return Err("approval claim nonce does not match the justification".to_owned());
        }
        if !roster.contains(&approval.approver) {
            return Err(format!(
                "approver {} is not a roster member at epoch {}",
                approval.approver, event.roster_epoch
            ));
        }
    }

    Ok(Admitted {
        author: owner.to_owned(),
        key: record.key.clone(),
        event_hash,
        event,
    })
}

/// Enforce the per-author hash chain (C7): `author_seq` strictly 1, 2, 3…
/// with `prev_own_event_hash` linking each event to its predecessor (the
/// genesis hash anchors seq 1). Admission is prefix-only: the first gap,
/// fork, or link break makes that author's remaining events inadmissible.
fn chain_author(
    author: &str,
    candidates: &[Admitted],
    genesis_hash: &str,
    chained: &mut Vec<Admitted>,
    rejections: &mut Vec<Rejection>,
    forks: &mut Vec<ForkEvidence>,
) {
    let mut by_seq: BTreeMap<u64, Vec<&Admitted>> = BTreeMap::new();
    for cand in candidates {
        by_seq.entry(cand.event.author_seq).or_default().push(cand);
    }
    for group in by_seq.values_mut() {
        group.sort_by(|a, b| a.event_hash.cmp(&b.event_hash));
        group.dedup_by(|a, b| a.event_hash == b.event_hash);
    }

    let mut expected_seq = 1u64;
    let mut prev_hash = genesis_hash.to_owned();
    let mut broken: Option<String> = None;
    for (seq, group) in &by_seq {
        if broken.is_some() {
            for cand in group {
                rejections.push(admission_rejection(
                    author,
                    &cand.key,
                    broken.clone().unwrap_or_default(),
                ));
            }
            continue;
        }
        if *seq != expected_seq {
            broken = Some(format!(
                "author chain gap: expected seq {expected_seq}, found {seq}"
            ));
            for cand in group {
                rejections.push(admission_rejection(
                    author,
                    &cand.key,
                    broken.clone().unwrap_or_default(),
                ));
            }
            continue;
        }
        if group.len() > 1 {
            // Fork: two signed events with the same seq — surface evidence,
            // reject everything from the fork point (self-harm only).
            forks.push(ForkEvidence {
                author: author.to_owned(),
                author_seq: *seq,
                event_hashes: group.iter().map(|c| c.event_hash.clone()).collect(),
            });
            broken = Some(format!("author chain fork at seq {seq}"));
            for cand in group {
                rejections.push(admission_rejection(
                    author,
                    &cand.key,
                    broken.clone().unwrap_or_default(),
                ));
            }
            continue;
        }
        let cand = group[0];
        if cand.event.prev_own_event_hash != prev_hash {
            broken = Some(format!("author chain link break at seq {seq}"));
            rejections.push(admission_rejection(
                author,
                &cand.key,
                broken.clone().unwrap_or_default(),
            ));
            continue;
        }
        prev_hash.clone_from(&cand.event_hash);
        expected_seq += 1;
        chained.push(cand.clone());
    }
}

/// Apply the lamport future-dating cap (C7), evaluated to a **fixpoint** so
/// that only events admitted in the FINAL surviving set contribute to the
/// running maximum — a rejected (or truncated) event contributes nothing.
///
/// Each pass walks the surviving candidates in ascending
/// `(lamport, author, event_hash)` order with `running_max` starting at 0:
/// an event whose lamport exceeds `running_max + LAMPORT_MAX_SKEW` is marked
/// rejected (and truncates its author's chain from that `author_seq` —
/// prefix-only admission); admitted events raise `running_max`. Marked
/// events are then removed and the pass repeats on the smaller set, until a
/// pass removes nothing. Because each pass is a pure function of the
/// surviving set and the set only shrinks, the result is deterministic and
/// independent of input order, and no event that was later rejected can have
/// widened the horizon for anyone else.
fn apply_lamport_cap(
    mut candidates: Vec<Admitted>,
    rejections: &mut Vec<Rejection>,
) -> Vec<Admitted> {
    candidates.sort_by(|a, b| {
        (a.event.lamport, &a.author, &a.event_hash).cmp(&(
            b.event.lamport,
            &b.author,
            &b.event_hash,
        ))
    });
    let mut survivors = candidates;
    loop {
        // Side-effect-free pass: mark, never mutate while walking.
        let mut running_max = 0u64;
        let mut lamport_rejected: Vec<bool> = vec![false; survivors.len()];
        let mut truncate_from: BTreeMap<String, u64> = BTreeMap::new();
        for (idx, cand) in survivors.iter().enumerate() {
            if cand.event.lamport > running_max.saturating_add(LAMPORT_MAX_SKEW) {
                lamport_rejected[idx] = true;
                let entry = truncate_from
                    .entry(cand.author.clone())
                    .or_insert(cand.event.author_seq);
                *entry = (*entry).min(cand.event.author_seq);
            } else {
                running_max = running_max.max(cand.event.lamport);
            }
        }
        if truncate_from.is_empty() {
            return survivors;
        }
        // Remove marked events plus every event of a truncated author at or
        // after the truncation seq, then re-evaluate on the smaller set.
        let mut next: Vec<Admitted> = Vec::with_capacity(survivors.len());
        for (idx, cand) in survivors.into_iter().enumerate() {
            if lamport_rejected[idx] {
                rejections.push(admission_rejection(
                    &cand.author,
                    &cand.key,
                    format!(
                        "lamport {} exceeds admitted maximum + {LAMPORT_MAX_SKEW}",
                        cand.event.lamport
                    ),
                ));
            } else if truncate_from
                .get(&cand.author)
                .is_some_and(|from_seq| cand.event.author_seq >= *from_seq)
            {
                rejections.push(admission_rejection(
                    &cand.author,
                    &cand.key,
                    "author chain truncated by a lamport rejection".to_owned(),
                ));
            } else {
                next.push(cand);
            }
        }
        survivors = next;
    }
}

/// Phase 2: apply one admitted transition to the issue map. Returns an error
/// string when the event is ineffective (fenced out, wrong state, …).
fn apply_transition(
    issues: &mut BTreeMap<String, IssueStateV2>,
    adm: &Admitted,
) -> Result<(), String> {
    let event = &adm.event;
    match &event.kind {
        TransitionKind::Open { title, spec } => {
            if issues.contains_key(&event.issue_id) {
                return Err("issue already exists".to_owned());
            }
            issues.insert(
                event.issue_id.clone(),
                IssueStateV2 {
                    issue_id: event.issue_id.clone(),
                    title: title.clone(),
                    spec: spec.clone(),
                    opened_by: event.actor.clone(),
                    open_event_hash: adm.event_hash.clone(),
                    status: IssueStatusV2::Open,
                    applied: vec![adm.event_hash.clone()],
                },
            );
            Ok(())
        }
        TransitionKind::Claim { claim_nonce } => {
            let issue = issue_mut(issues, &event.issue_id)?;
            match &issue.status {
                IssueStatusV2::Open => {
                    issue.status = IssueStatusV2::Claimed {
                        claimant: event.actor.clone(),
                        claim_nonce: claim_nonce.clone(),
                        claim_event_hash: adm.event_hash.clone(),
                    };
                    issue.applied.push(adm.event_hash.clone());
                    Ok(())
                }
                _ => Err("issue is not claimable".to_owned()),
            }
        }
        TransitionKind::Release {
            claim_nonce,
            claimed_event_hash,
        } => {
            let issue = issue_mut(issues, &event.issue_id)?;
            check_claim_fence(issue, &event.actor, claim_nonce, claimed_event_hash)?;
            issue.status = IssueStatusV2::Open;
            issue.applied.push(adm.event_hash.clone());
            Ok(())
        }
        TransitionKind::Block {
            claim_nonce,
            claimed_event_hash,
            reason,
        } => {
            let issue = issue_mut(issues, &event.issue_id)?;
            check_claim_fence(issue, &event.actor, claim_nonce, claimed_event_hash)?;
            issue.status = IssueStatusV2::Blocked {
                claimant: event.actor.clone(),
                claim_nonce: claim_nonce.clone(),
                claim_event_hash: claimed_event_hash.clone(),
                block_event_hash: adm.event_hash.clone(),
                reason: reason.clone(),
            };
            issue.applied.push(adm.event_hash.clone());
            Ok(())
        }
        TransitionKind::Complete {
            claim_nonce,
            claimed_event_hash,
        } => {
            let issue = issue_mut(issues, &event.issue_id)?;
            check_claim_fence(issue, &event.actor, claim_nonce, claimed_event_hash)?;
            issue.status = IssueStatusV2::Done {
                completed_by: event.actor.clone(),
                complete_event_hash: adm.event_hash.clone(),
            };
            issue.applied.push(adm.event_hash.clone());
            Ok(())
        }
        TransitionKind::Requeue { justification } => {
            let issue = issue_mut(issues, &event.issue_id)?;
            apply_requeue(issue, justification, &adm.event_hash)
        }
    }
}

/// Phase-2 requeue: only an `awaiting_approval` block, and only the exact
/// block/claim the (admission-verified) justification names.
fn apply_requeue(
    issue: &mut IssueStateV2,
    justification: &super::events::RequeueJustification,
    event_hash: &str,
) -> Result<(), String> {
    let IssueStatusV2::Blocked {
        claim_nonce,
        block_event_hash,
        reason,
        ..
    } = &issue.status
    else {
        return Err("requeue on an issue that is not blocked".to_owned());
    };
    if *reason != BlockReason::AwaitingApproval {
        return Err("only awaiting_approval blocks are requeue-able (design r2 C6)".to_owned());
    }
    if justification.block_event_hash != *block_event_hash {
        return Err("requeue names a block that is not the current block".to_owned());
    }
    if justification.claim_nonce != *claim_nonce {
        return Err("requeue claim nonce does not match the parked claim".to_owned());
    }
    issue.status = IssueStatusV2::Open;
    issue.applied.push(event_hash.to_owned());
    Ok(())
}

fn issue_mut<'a>(
    issues: &'a mut BTreeMap<String, IssueStateV2>,
    issue_id: &str,
) -> Result<&'a mut IssueStateV2, String> {
    issues
        .get_mut(issue_id)
        .ok_or_else(|| "issue does not exist".to_owned())
}

/// Claim fencing shared by release/block/complete: actor must be the current
/// claimant and both the nonce and the claim event hash must match.
fn check_claim_fence(
    issue: &IssueStateV2,
    actor: &str,
    claim_nonce: &str,
    claimed_event_hash: &str,
) -> Result<(), String> {
    match &issue.status {
        IssueStatusV2::Claimed {
            claimant,
            claim_nonce: current_nonce,
            claim_event_hash,
        } => {
            if claimant != actor {
                return Err(format!("actor {actor} is not the claimant {claimant}"));
            }
            if current_nonce != claim_nonce {
                return Err("claim nonce does not match the winning claim".to_owned());
            }
            if claim_event_hash != claimed_event_hash {
                return Err("claimed event hash does not match the winning claim".to_owned());
            }
            Ok(())
        }
        _ => Err("issue is not claimed".to_owned()),
    }
}
