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
    ApprovalEventV2, ApprovalPayloadV2, ApprovalVerdictV2, BlockReason, ConsumeEventV2,
    EventEnvelope, GenesisManifestV2, HandoffEventV2, RosterEventV2, TransitionEventV2,
    TransitionKind, APPROVAL_CONTEXT_V2, APPROVAL_KEY_PREFIX, CARD_SELF_KEY, CONSUME_CONTEXT_V2,
    CONSUME_KEY_PREFIX, EVENT_KEY_PREFIX, GENESIS_CONTEXT_V2, GENESIS_KEY, HANDOFF_CONTEXT_V2,
    HANDOFF_KEY_PREFIX, ROSTER_CONTEXT_V2, ROSTER_KEY_PREFIX, TRANSITION_CONTEXT_V2, V2_SCHEMA,
};
use super::identity::derive_agent_id_hex;
use x0x_symphony_core::sha256_hex;

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

/// Resource budgets for untrusted fold input. Violations REFUSE the list
/// (fail-closed): an input that exceeds a budget is treated as hostile or
/// broken, never partially processed. Overridable programmatically
/// (`V2StoreManager::with_limits`, `X0xCrdtTrackerBuilder::v2_fold_limits`);
/// the defaults are generous for real symphony rosters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FoldLimits {
    /// Maximum members in the genesis roster or any roster update.
    pub max_roster_members: usize,
    /// Maximum records read/folded per author stream.
    pub max_records_per_stream: usize,
    /// Maximum bytes for any single stored record value (envelope bytes —
    /// covers roster/genesis/transition payloads uniformly).
    pub max_record_bytes: usize,
}

impl Default for FoldLimits {
    fn default() -> Self {
        Self {
            max_roster_members: 256,
            max_records_per_stream: 4096,
            max_record_bytes: 256 * 1024,
        }
    }
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
    /// Resource budgets enforced over this input (fail-closed).
    pub limits: FoldLimits,
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
    /// A resource budget ([`FoldLimits`]) was exceeded. Fail-closed: the
    /// list is refused rather than partially processed.
    #[error("v2 list refused: budget exceeded: {0}")]
    BudgetExceeded(String),
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
    /// Membership at [`Self::latest_roster_epoch`]. Readers use this to
    /// decide which per-author stores to join — including members added by
    /// roster UPDATES, not just the genesis roster.
    pub current_roster: BTreeSet<String>,
    /// Folded issues, keyed by issue id.
    pub issues: BTreeMap<String, IssueStateV2>,
    /// Highest lamport among admitted events (0 when none) — callers use
    /// this to stamp their next event.
    pub max_admitted_lamport: u64,
    /// Diagnostics: rejected/ineffective records (canonically sorted).
    pub rejections: Vec<Rejection>,
    /// Diagnostics: per-author chain forks (canonically sorted).
    pub forks: Vec<ForkEvidence>,
    /// Admitted dispatch approvals (WP-B), keyed by approval event hash.
    pub approvals: BTreeMap<String, AdmittedApprovalV2>,
    /// Effective (fold-winning) consumes (WP-B), keyed by the consumed
    /// approval's event hash — at most one per approval, ever.
    pub effective_consumes: BTreeMap<String, EffectiveConsumeV2>,
    /// Diagnostics: consume attempts that lost (duplicate, unfenced, or
    /// referencing an unknown approval), in fold order.
    pub losing_consumes: Vec<ConsumeDiagnostic>,
    /// Recorded handoffs (WP-B2), keyed by issue id, in fold order. A
    /// handoff is recorded only when fenced by the fold-winning claim at
    /// its fold position; it never changes issue status.
    pub handoffs: BTreeMap<String, Vec<HandoffRecordV2>>,
    /// Per-author chain tips over the ADMITTED set: highest `author_seq` and
    /// that event's hash. Appenders use [`FoldOutput::next_chain_link`].
    pub author_chain_tips: BTreeMap<String, ChainTipV2>,
}

/// A recorded (fold-fenced) handoff (WP-B2).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HandoffRecordV2 {
    /// Payload hash of the handoff event.
    pub event_hash: String,
    /// The handoff payload.
    pub handoff: HandoffEventV2,
}

/// Tip of one author's admitted hash chain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainTipV2 {
    /// Highest admitted `author_seq`.
    pub author_seq: u64,
    /// Payload hash of that event.
    pub last_event_hash: String,
}

impl FoldOutput {
    /// Dispatch approvals for `issue_id` that are admitted, bind the issue's
    /// current `Open` content, carry an `approve` verdict, are not consumed,
    /// and are not overridden by an admitted denial of the same content
    /// (denials are terminal, v1 parity).
    ///
    /// Return `(next_author_seq, prev_own_event_hash)` for appending this
    /// author's next chained event: `(tip.seq + 1, tip.hash)`, or
    /// `(1, genesis_hash)` for an author with no admitted events yet.
    #[must_use]
    pub fn next_chain_link(&self, author: &str) -> (u64, String) {
        self.author_chain_tips.get(author).map_or_else(
            || (1, self.genesis_hash.clone()),
            |tip| (tip.author_seq + 1, tip.last_event_hash.clone()),
        )
    }

    /// TTL is deliberately NOT applied here (design r2 finding C3): expired
    /// approvals still fold; the dispatch gate refuses them at gate time.
    #[must_use]
    pub fn unconsumed_approvals(&self, issue_id: &str) -> Vec<&AdmittedApprovalV2> {
        let Some(issue) = self.issues.get(issue_id) else {
            return Vec::new();
        };
        let denied = self.approvals.values().any(|a| {
            a.approval.issue_id == issue_id
                && a.approval.open_event_hash == issue.open_event_hash
                && a.approval.verdict == ApprovalVerdictV2::Deny
        });
        if denied {
            return Vec::new();
        }
        self.approvals
            .values()
            .filter(|a| {
                a.approval.issue_id == issue_id
                    && a.approval.open_event_hash == issue.open_event_hash
                    && a.approval.verdict == ApprovalVerdictV2::Approve
                    && !self.effective_consumes.contains_key(&a.event_hash)
            })
            .collect()
    }
}

/// An admitted dispatch approval (WP-B).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdmittedApprovalV2 {
    /// Payload hash of the approval event.
    pub event_hash: String,
    /// The approval payload.
    pub approval: ApprovalEventV2,
}

/// The fold-winning consume for one approval (WP-B).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectiveConsumeV2 {
    /// Payload hash of the consume event.
    pub event_hash: String,
    /// The consume payload.
    pub consume: ConsumeEventV2,
}

/// A consume attempt that did not win (WP-B diagnostics: losing/duplicate
/// consumes are surfaced, never silently dropped).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsumeDiagnostic {
    /// Consumer (stream owner) of the losing attempt.
    pub author: String,
    /// KV key of the losing record.
    pub key: String,
    /// Payload hash of the losing consume event.
    pub event_hash: String,
    /// Approval the attempt referenced.
    pub approval_event_hash: String,
    /// Why the attempt lost.
    pub reason: String,
}

/// A chained record's payload after phase-1 admission.
#[derive(Clone, Debug)]
enum ChainedPayload {
    Transition(TransitionEventV2),
    Approval(ApprovalEventV2),
    Consume(ConsumeEventV2),
    Handoff(HandoffEventV2),
}

/// An admitted chained candidate flowing from phase 1 to phase 2. Common
/// chain/ordering fields are lifted out of the payload so chain and lamport
/// enforcement is uniform across record types.
#[derive(Clone, Debug)]
struct Admitted {
    author: String,
    key: String,
    event_hash: String,
    lamport: u64,
    author_seq: u64,
    prev_own_event_hash: String,
    payload: ChainedPayload,
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
    // then key-sorted); duplicate identical records collapse. An owner whose
    // merged input carries CONFLICTING card-self values is rejected outright
    // — two different self-certifying keys for one agent id is an anomaly,
    // and any pick-one rule would make fold output depend on input order.
    // Budgets (fail-closed) — enforced on the RAW input BEFORE any merge
    // or dedup work, so oversize hostile input cannot consume memory/CPU
    // during canonicalization. Every violation refuses the list outright.
    let limits = input.limits;
    if input.streams.len() > limits.max_roster_members.saturating_add(1) {
        return Err(ListRefusal::BudgetExceeded(format!(
            "input carries {} streams (max {} roster members + creator)",
            input.streams.len(),
            limits.max_roster_members
        )));
    }
    for stream in &input.streams {
        if stream.records.len() > limits.max_records_per_stream {
            return Err(ListRefusal::BudgetExceeded(format!(
                "raw stream {} carries {} records (max {})",
                stream.owner,
                stream.records.len(),
                limits.max_records_per_stream
            )));
        }
        if let Some(record) = stream
            .records
            .iter()
            .find(|r| r.value.len() > limits.max_record_bytes)
        {
            return Err(ListRefusal::BudgetExceeded(format!(
                "record {} in raw stream {} is {} bytes (max {})",
                record.key,
                stream.owner,
                record.value.len(),
                limits.max_record_bytes
            )));
        }
    }
    let (streams, conflicted) = canonical_streams(&input.streams);
    // Post-merge re-check: duplicate raw streams for one owner can sum past
    // the per-stream cap even when each raw copy is within it.
    for (owner, stream) in &streams {
        if stream.records.len() > limits.max_records_per_stream {
            return Err(ListRefusal::BudgetExceeded(format!(
                "merged stream {owner} carries {} records (max {})",
                stream.records.len(),
                limits.max_records_per_stream
            )));
        }
    }
    if let Some(reason) = conflicted.get(&input.creator) {
        return Err(ListRefusal::InvalidGenesis(format!(
            "creator card-self conflict: {reason}"
        )));
    }

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
    if genesis.roster.len() > limits.max_roster_members {
        return Err(ListRefusal::BudgetExceeded(format!(
            "genesis roster has {} members (max {})",
            genesis.roster.len(),
            limits.max_roster_members
        )));
    }

    // ---- Roster chain ------------------------------------------------------
    // rosters[e] = membership at epoch e; epoch 0 is the genesis roster.
    let mut rosters: Vec<BTreeSet<String>> = vec![genesis.roster.iter().cloned().collect()];
    build_roster_chain(
        creator_stream,
        &input.list_uuid,
        &input.creator,
        &creator_card,
        &genesis_hash,
        limits.max_roster_members,
        &mut rosters,
        &mut rejections,
        &mut forks,
    )?;
    let latest_roster_epoch = u64::try_from(rosters.len())
        .unwrap_or(u64::MAX)
        .saturating_sub(1);
    let current_roster = rosters.last().cloned().unwrap_or_default();

    // ---- Phase 1: per-stream candidate admission ---------------------------
    let mut per_author: BTreeMap<String, Vec<Admitted>> = BTreeMap::new();
    for (owner, stream) in &streams {
        if let Some(reason) = conflicted.get(owner) {
            // Conflicting card-self: no deterministic four-way binding is
            // possible — reject every event, surfaced per record.
            for record in event_records(stream) {
                rejections.push(admission_rejection(owner, &record.key, reason.clone()));
            }
            continue;
        }
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
    let max_admitted_lamport = admitted.iter().map(|a| a.lamport).max().unwrap_or(0);
    let mut author_chain_tips: BTreeMap<String, ChainTipV2> = BTreeMap::new();
    for adm in &admitted {
        let tip = author_chain_tips
            .entry(adm.author.clone())
            .or_insert_with(|| ChainTipV2 {
                author_seq: adm.author_seq,
                last_event_hash: adm.event_hash.clone(),
            });
        if adm.author_seq >= tip.author_seq {
            tip.author_seq = adm.author_seq;
            tip.last_event_hash.clone_from(&adm.event_hash);
        }
    }

    // ---- Phase 2: deterministic state machine ------------------------------
    let mut ordered = admitted;
    ordered.sort_by(|a, b| {
        (a.lamport, &a.author, &a.event_hash).cmp(&(b.lamport, &b.author, &b.event_hash))
    });
    let mut issues: BTreeMap<String, IssueStateV2> = BTreeMap::new();
    let mut approvals: BTreeMap<String, AdmittedApprovalV2> = BTreeMap::new();
    let mut effective_consumes: BTreeMap<String, EffectiveConsumeV2> = BTreeMap::new();
    let mut losing_consumes: Vec<ConsumeDiagnostic> = Vec::new();
    let mut handoffs: BTreeMap<String, Vec<HandoffRecordV2>> = BTreeMap::new();
    // Approvals are an order-independent SET (spec §2.4): collect ALL of
    // them BEFORE the ordered walk, so a consume is never misdiagnosed as
    // referencing an unknown approval merely because the approval carries a
    // later fold position (e.g. an approver's lamport running ahead).
    for adm in &ordered {
        if let ChainedPayload::Approval(approval) = &adm.payload {
            approvals.insert(
                adm.event_hash.clone(),
                AdmittedApprovalV2 {
                    event_hash: adm.event_hash.clone(),
                    approval: approval.clone(),
                },
            );
        }
    }
    for adm in &ordered {
        match &adm.payload {
            ChainedPayload::Transition(event) => {
                if let Err(reason) = apply_transition(&mut issues, adm, event) {
                    rejections.push(Rejection {
                        author: adm.author.clone(),
                        key: adm.key.clone(),
                        phase: RejectionPhase::StateMachine,
                        reason,
                    });
                }
            }
            ChainedPayload::Approval(_) => {
                // Collected in the pre-pass above (order-independent set).
            }
            ChainedPayload::Consume(consume) => {
                match consume_effectiveness(&issues, &approvals, &effective_consumes, consume) {
                    Ok(()) => {
                        effective_consumes.insert(
                            consume.approval_event_hash.clone(),
                            EffectiveConsumeV2 {
                                event_hash: adm.event_hash.clone(),
                                consume: consume.clone(),
                            },
                        );
                    }
                    Err(reason) => losing_consumes.push(ConsumeDiagnostic {
                        author: adm.author.clone(),
                        key: adm.key.clone(),
                        event_hash: adm.event_hash.clone(),
                        approval_event_hash: consume.approval_event_hash.clone(),
                        reason,
                    }),
                }
            }
            ChainedPayload::Handoff(handoff) => {
                // WP-B2: a handoff is recorded only when fenced by the
                // fold-winning claim at this position; it never changes
                // issue status.
                match handoff_fence(&issues, handoff) {
                    Ok(()) => handoffs.entry(handoff.issue_id.clone()).or_default().push(
                        HandoffRecordV2 {
                            event_hash: adm.event_hash.clone(),
                            handoff: handoff.clone(),
                        },
                    ),
                    Err(reason) => rejections.push(Rejection {
                        author: adm.author.clone(),
                        key: adm.key.clone(),
                        phase: RejectionPhase::StateMachine,
                        reason,
                    }),
                }
            }
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
        current_roster,
        issues,
        max_admitted_lamport,
        rejections,
        forks,
        approvals,
        effective_consumes,
        losing_consumes,
        handoffs,
        author_chain_tips,
    })
}

/// Phase 2 (WP-B2): a handoff is recorded iff its issue is Claimed at this
/// fold position and the handoff's actor/nonce/claim-hash all fence.
fn handoff_fence(
    issues: &BTreeMap<String, IssueStateV2>,
    handoff: &HandoffEventV2,
) -> Result<(), String> {
    let Some(issue) = issues.get(&handoff.issue_id) else {
        return Err("handoff on an issue that does not exist".to_owned());
    };
    check_claim_fence(
        issue,
        &handoff.actor,
        &handoff.claim_nonce,
        &handoff.claimed_event_hash,
    )
}

/// Merge and canonicalize input streams by owner; sort records by key.
///
/// Returns `(streams, conflicted)`: an owner appears in `conflicted` (with a
/// deterministic, order-independent reason) when its merged input carries
/// MORE THAN ONE distinct `card-self` value — across explicit `card_self`
/// fields and `card-self` records alike. Such an owner cannot be bound
/// deterministically and is rejected by the caller; any pick-one rule would
/// make fold output depend on which stream copy arrived first.
fn canonical_streams(
    streams: &[AuthorStream],
) -> (BTreeMap<String, AuthorStream>, BTreeMap<String, String>) {
    let mut merged: BTreeMap<String, AuthorStream> = BTreeMap::new();
    let mut cards: BTreeMap<String, BTreeSet<Vec<u8>>> = BTreeMap::new();
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
        if let Some(card) = &stream.card_self {
            cards
                .entry(stream.owner.clone())
                .or_default()
                .insert(card.clone());
        }
        entry.records.extend(stream.records.iter().cloned());
    }
    let mut conflicted: BTreeMap<String, String> = BTreeMap::new();
    for stream in merged.values_mut() {
        stream
            .records
            .sort_by(|a, b| (&a.key, &a.value).cmp(&(&b.key, &b.value)));
        stream.records.dedup();
        let candidates = cards.entry(stream.owner.clone()).or_default();
        for record in stream.records.iter().filter(|r| r.key == CARD_SELF_KEY) {
            candidates.insert(record.value.clone());
        }
        if candidates.len() > 1 {
            let hashes: Vec<String> = candidates.iter().map(|card| sha256_hex(card)).collect();
            conflicted.insert(
                stream.owner.clone(),
                format!(
                    "conflicting card-self values for this owner (sha256: {}) — \
                     no deterministic author binding is possible; all events \
                     from this stream are rejected",
                    hashes.join(" vs ")
                ),
            );
        }
    }
    (merged, conflicted)
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
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_roster_chain(
    creator_stream: &AuthorStream,
    list_uuid: &str,
    creator: &str,
    creator_card: &[u8],
    genesis_hash: &str,
    max_roster_members: usize,
    rosters: &mut Vec<BTreeSet<String>>,
    rejections: &mut Vec<Rejection>,
    forks: &mut Vec<ForkEvidence>,
) -> Result<(), ListRefusal> {
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
            Ok((roster, hash)) => {
                if roster.roster.len() > max_roster_members {
                    // A creator-signed oversize roster is fail-closed: the
                    // reader refuses the list rather than budget-bust.
                    return Err(ListRefusal::BudgetExceeded(format!(
                        "roster update {} has {} members (max {max_roster_members})",
                        record.key,
                        roster.roster.len()
                    )));
                }
                by_epoch.entry(roster.roster_epoch).or_default().push((
                    record.key.clone(),
                    roster,
                    hash,
                ));
            }
            Err(reason) => {
                rejections.push(admission_rejection(creator, &record.key, reason));
            }
        }
    }

    // Walk epochs 1..: each must chain to the previous accepted hash.
    // The CUMULATIVE member union across all accepted epochs is budgeted —
    // that union is what actually bounds reader resource use (store joins
    // and reads), and it aligns the pure fold with the read path, which
    // budgets the same union. The per-roster cap above remains as an
    // additional payload-validity rule.
    let mut cumulative: BTreeSet<String> = rosters.first().cloned().unwrap_or_default();
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
                cumulative.extend(roster.roster.iter().cloned());
                if cumulative.len() > max_roster_members {
                    return Err(ListRefusal::BudgetExceeded(format!(
                        "cumulative roster union reaches {} members across \
                         epochs (max {max_roster_members})",
                        cumulative.len()
                    )));
                }
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
    Ok(())
}

/// Iterate a stream's chained records: transitions (`ev-*`), dispatch
/// approvals (`ap-*`), and consumes (`cs-*`). All three share the author's
/// hash chain.
fn event_records(stream: &AuthorStream) -> impl Iterator<Item = &StoreRecord> {
    stream.records.iter().filter(|r| {
        r.key.starts_with(EVENT_KEY_PREFIX)
            || r.key.starts_with(APPROVAL_KEY_PREFIX)
            || r.key.starts_with(CONSUME_KEY_PREFIX)
            || r.key.starts_with(HANDOFF_KEY_PREFIX)
    })
}

fn admission_rejection(author: &str, key: &str, reason: String) -> Rejection {
    Rejection {
        author: author.to_owned(),
        key: key.to_owned(),
        phase: RejectionPhase::Admission,
        reason,
    }
}

/// The C8/addressing fields a chained record declares, lifted into a struct
/// so the shared check keeps a small signature.
struct ChainedBindings<'a> {
    record_key: &'a str,
    expected_key: &'a str,
    schema: u32,
    event_list_uuid: &'a str,
    event_genesis: &'a str,
    roster_epoch: u64,
    actor: &'a str,
}

/// Common C5/C8/roster admission checks shared by all chained record types.
/// Returns the roster set at the record's named epoch on success.
fn check_chained_common<'r>(
    b: &ChainedBindings<'_>,
    owner: &str,
    list_uuid: &str,
    genesis_hash: &str,
    rosters: &'r [BTreeSet<String>],
) -> Result<&'r BTreeSet<String>, String> {
    let ChainedBindings {
        record_key,
        expected_key,
        schema,
        event_list_uuid,
        event_genesis,
        roster_epoch,
        actor,
    } = *b;
    // Four-way binding, final leg (C5): payload actor == store owner
    // (== envelope signer == derived key id, established by the caller).
    if actor != owner {
        return Err(format!(
            "event actor {actor} is not the store owner {owner}"
        ));
    }
    // C8 bindings: schema, list, genesis.
    if schema != V2_SCHEMA {
        return Err(format!("event schema {schema} != {V2_SCHEMA}"));
    }
    if event_list_uuid != list_uuid {
        return Err(format!(
            "event names list {event_list_uuid} but this list is {list_uuid} (cross-list replay?)"
        ));
    }
    if event_genesis != genesis_hash {
        return Err("event genesis binding does not match this list's genesis".to_owned());
    }
    // Key integrity: content addressing.
    if record_key != expected_key {
        return Err(format!(
            "record key {record_key} does not match content address {expected_key}"
        ));
    }
    // Roster membership at the record's named epoch.
    let epoch =
        usize::try_from(roster_epoch).map_err(|_| "roster epoch out of range".to_owned())?;
    let roster = rosters
        .get(epoch)
        .ok_or_else(|| format!("event names unknown roster epoch {roster_epoch}"))?;
    if !roster.contains(actor) {
        return Err(format!(
            "actor {actor} is not a roster member at epoch {roster_epoch}"
        ));
    }
    Ok(roster)
}

/// Admit one chained record, dispatching on its key prefix.
fn admit_event(
    record: &StoreRecord,
    owner: &str,
    card: &[u8],
    list_uuid: &str,
    genesis_hash: &str,
    rosters: &[BTreeSet<String>],
) -> Result<Admitted, String> {
    if record.key.starts_with(EVENT_KEY_PREFIX) {
        admit_transition(record, owner, card, list_uuid, genesis_hash, rosters)
    } else if record.key.starts_with(APPROVAL_KEY_PREFIX) {
        admit_approval(record, owner, card, list_uuid, genesis_hash, rosters)
    } else if record.key.starts_with(CONSUME_KEY_PREFIX) {
        admit_consume(record, owner, card, list_uuid, genesis_hash, rosters)
    } else if record.key.starts_with(HANDOFF_KEY_PREFIX) {
        admit_handoff(record, owner, card, list_uuid, genesis_hash, rosters)
    } else {
        Err("not a chained record".to_owned())
    }
}

/// Admit a WP-B2 handoff: envelope under [`HANDOFF_CONTEXT_V2`], four-way
/// binding, C8 bindings, roster-at-epoch. The claim fence is phase-2 (it
/// depends on issue state at the handoff's fold position).
fn admit_handoff(
    record: &StoreRecord,
    owner: &str,
    card: &[u8],
    list_uuid: &str,
    genesis_hash: &str,
    rosters: &[BTreeSet<String>],
) -> Result<Admitted, String> {
    let envelope = EventEnvelope::decode(&record.value)?;
    let (payload, event_hash) = envelope.verify(HANDOFF_CONTEXT_V2)?;
    check_envelope_key(&envelope, owner, card)?;
    let event = HandoffEventV2::decode(&payload)?;
    if event.kind != "handoff" {
        return Err(format!("handoff record kind {} != handoff", event.kind));
    }
    let expected_key = super::events::handoff_key(&event.issue_id, &event_hash);
    check_chained_common(
        &ChainedBindings {
            record_key: &record.key,
            expected_key: &expected_key,
            schema: event.schema,
            event_list_uuid: &event.list_uuid,
            event_genesis: &event.genesis_manifest_hash,
            roster_epoch: event.roster_epoch,
            actor: &event.actor,
        },
        owner,
        list_uuid,
        genesis_hash,
        rosters,
    )?;
    Ok(Admitted {
        author: owner.to_owned(),
        key: record.key.clone(),
        event_hash,
        lamport: event.lamport,
        author_seq: event.author_seq,
        prev_own_event_hash: event.prev_own_event_hash.clone(),
        payload: ChainedPayload::Handoff(event),
    })
}

/// Admit a WP-B dispatch approval: envelope under [`APPROVAL_CONTEXT_V2`],
/// four-way binding, C8 bindings, roster-at-epoch.
fn admit_approval(
    record: &StoreRecord,
    owner: &str,
    card: &[u8],
    list_uuid: &str,
    genesis_hash: &str,
    rosters: &[BTreeSet<String>],
) -> Result<Admitted, String> {
    let envelope = EventEnvelope::decode(&record.value)?;
    let (payload, event_hash) = envelope.verify(APPROVAL_CONTEXT_V2)?;
    check_envelope_key(&envelope, owner, card)?;
    let event = ApprovalEventV2::decode(&payload)?;
    if event.kind != "dispatch_approval" {
        return Err(format!(
            "approval record kind {} != dispatch_approval",
            event.kind
        ));
    }
    let expected_key = super::events::approval_key(&event.issue_id, &event_hash);
    check_chained_common(
        &ChainedBindings {
            record_key: &record.key,
            expected_key: &expected_key,
            schema: event.schema,
            event_list_uuid: &event.list_uuid,
            event_genesis: &event.genesis_manifest_hash,
            roster_epoch: event.roster_epoch,
            actor: &event.actor,
        },
        owner,
        list_uuid,
        genesis_hash,
        rosters,
    )?;
    Ok(Admitted {
        author: owner.to_owned(),
        key: record.key.clone(),
        event_hash,
        lamport: event.lamport,
        author_seq: event.author_seq,
        prev_own_event_hash: event.prev_own_event_hash.clone(),
        payload: ChainedPayload::Approval(event),
    })
}

/// Admit a WP-B consume: envelope under [`CONSUME_CONTEXT_V2`], four-way
/// binding, C8 bindings, roster-at-epoch, and the v2 hash-identity check.
/// The claim fence and duplicate resolution are phase-2 (they depend on the
/// issue state at the consume's fold position).
fn admit_consume(
    record: &StoreRecord,
    owner: &str,
    card: &[u8],
    list_uuid: &str,
    genesis_hash: &str,
    rosters: &[BTreeSet<String>],
) -> Result<Admitted, String> {
    let envelope = EventEnvelope::decode(&record.value)?;
    let (payload, event_hash) = envelope.verify(CONSUME_CONTEXT_V2)?;
    check_envelope_key(&envelope, owner, card)?;
    let event = ConsumeEventV2::decode(&payload)?;
    if event.kind != "consume" {
        return Err(format!("consume record kind {} != consume", event.kind));
    }
    if event.approval_payload_sha256 != event.approval_event_hash {
        return Err("consume approval hash fields disagree (v2 identity)".to_owned());
    }
    let expected_key = super::events::consume_key(&event.issue_id, &event_hash);
    check_chained_common(
        &ChainedBindings {
            record_key: &record.key,
            expected_key: &expected_key,
            schema: event.schema,
            event_list_uuid: &event.list_uuid,
            event_genesis: &event.genesis_manifest_hash,
            roster_epoch: event.roster_epoch,
            actor: &event.actor,
        },
        owner,
        list_uuid,
        genesis_hash,
        rosters,
    )?;
    Ok(Admitted {
        author: owner.to_owned(),
        key: record.key.clone(),
        event_hash,
        lamport: event.lamport,
        author_seq: event.author_seq,
        prev_own_event_hash: event.prev_own_event_hash.clone(),
        payload: ChainedPayload::Consume(event),
    })
}

/// Admit a transition event: envelope, four-way binding, C8 list bindings,
/// key integrity, roster-at-epoch membership, and (for requeues) the C6
/// justification.
fn admit_transition(
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

    let expected_key = super::events::event_key(&event.issue_id, &event_hash);
    let roster = check_chained_common(
        &ChainedBindings {
            record_key: &record.key,
            expected_key: &expected_key,
            schema: event.schema,
            event_list_uuid: &event.list_uuid,
            event_genesis: &event.genesis_manifest_hash,
            roster_epoch: event.roster_epoch,
            actor: &event.actor,
        },
        owner,
        list_uuid,
        genesis_hash,
        rosters,
    )?;

    // WP-B2: Open content bindings — the v1-provenance-parity digests must
    // match the carried content exactly.
    if let TransitionKind::Open {
        title,
        spec,
        title_sha256,
        spec_sha256,
    } = &event.kind
    {
        if *title_sha256 != sha256_hex(title.as_bytes()) {
            return Err("open title_sha256 does not match the carried title".to_owned());
        }
        if *spec_sha256 != sha256_hex(spec.as_bytes()) {
            return Err("open spec_sha256 does not match the carried spec".to_owned());
        }
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
        lamport: event.lamport,
        author_seq: event.author_seq,
        prev_own_event_hash: event.prev_own_event_hash.clone(),
        payload: ChainedPayload::Transition(event),
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
        by_seq.entry(cand.author_seq).or_default().push(cand);
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
        if cand.prev_own_event_hash != prev_hash {
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
        (a.lamport, &a.author, &a.event_hash).cmp(&(b.lamport, &b.author, &b.event_hash))
    });
    let mut survivors = candidates;
    loop {
        // Side-effect-free pass: mark, never mutate while walking.
        let mut running_max = 0u64;
        let mut lamport_rejected: Vec<bool> = vec![false; survivors.len()];
        let mut truncate_from: BTreeMap<String, u64> = BTreeMap::new();
        for (idx, cand) in survivors.iter().enumerate() {
            if cand.lamport > running_max.saturating_add(LAMPORT_MAX_SKEW) {
                lamport_rejected[idx] = true;
                let entry = truncate_from
                    .entry(cand.author.clone())
                    .or_insert(cand.author_seq);
                *entry = (*entry).min(cand.author_seq);
            } else {
                running_max = running_max.max(cand.lamport);
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
                        cand.lamport
                    ),
                ));
            } else if truncate_from
                .get(&cand.author)
                .is_some_and(|from_seq| cand.author_seq >= *from_seq)
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

/// Phase 2 (WP-B): decide whether an admitted consume is EFFECTIVE at its
/// fold position. Requirements (all deterministic):
///
/// 1. the referenced approval is admitted, names the same issue, was signed
///    by the approver the consume names, carries an `approve` verdict, and
///    binds the issue's current `Open` content;
/// 2. the consumer holds the fold-winning claim at this position (actor,
///    `claim_nonce`, and claim event hash all fence — a non-winner's consume
///    is never effective);
/// 3. no earlier effective consume exists for the same approval (first in
///    fold order wins; later duplicates are surfaced as diagnostics).
fn consume_effectiveness(
    issues: &BTreeMap<String, IssueStateV2>,
    approvals: &BTreeMap<String, AdmittedApprovalV2>,
    effective_consumes: &BTreeMap<String, EffectiveConsumeV2>,
    consume: &ConsumeEventV2,
) -> Result<(), String> {
    let Some(admitted) = approvals.get(&consume.approval_event_hash) else {
        return Err("references an unknown or inadmissible approval".to_owned());
    };
    let approval = &admitted.approval;
    if approval.issue_id != consume.issue_id {
        return Err("approval issue does not match the consume issue".to_owned());
    }
    if approval.actor != consume.approver {
        return Err("approval approver does not match the consume".to_owned());
    }
    if approval.verdict != ApprovalVerdictV2::Approve {
        return Err("cannot consume a denial".to_owned());
    }
    let Some(issue) = issues.get(&consume.issue_id) else {
        return Err("issue does not exist at the consume's fold position".to_owned());
    };
    if approval.open_event_hash != issue.open_event_hash {
        return Err("approval binds different issue content".to_owned());
    }
    let IssueStatusV2::Claimed {
        claimant,
        claim_nonce,
        claim_event_hash,
    } = &issue.status
    else {
        return Err("issue is not claimed at the consume's fold position".to_owned());
    };
    if claimant != &consume.actor
        || claim_nonce != &consume.claim_nonce
        || claim_event_hash != &consume.claimed_event_hash
    {
        return Err("consume is not fenced by the fold-winning claim".to_owned());
    }
    if effective_consumes.contains_key(&consume.approval_event_hash) {
        return Err("approval already consumed by an earlier fold-ordered consume".to_owned());
    }
    Ok(())
}

/// Phase 2: apply one admitted transition to the issue map. Returns an error
/// string when the event is ineffective (fenced out, wrong state, …).
fn apply_transition(
    issues: &mut BTreeMap<String, IssueStateV2>,
    adm: &Admitted,
    event: &TransitionEventV2,
) -> Result<(), String> {
    match &event.kind {
        TransitionKind::Open { title, spec, .. } => {
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
