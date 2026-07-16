//! Pure-fold tests for tracker-integrity v2 (WP-A).
//!
//! Every test constructs real ML-DSA-65-signed events (saorsa-pqc — the same
//! FIPS-204 implementation x0xd signs with) and drives `fold_v2` directly:
//! the fold is a pure function, so no daemon is required.

use std::error::Error;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use saorsa_pqc::{MlDsa65, MlDsaOperations, MlDsaSecretKey};
use x0x_symphony_core::sha256_hex;
use x0x_symphony_tracker_x0x_crdt::v2::{
    events::{
        approval_key, consume_key, event_key, roster_key, ApprovalPayloadV2, GenesisPolicy,
        APPROVAL_CONTEXT_V2, CARD_SELF_KEY, CONSUME_CONTEXT_V2, GENESIS_CONTEXT_V2, GENESIS_KEY,
        ROSTER_CONTEXT_V2, TRANSITION_CONTEXT_V2,
    },
    fold_v2,
    identity::{assemble_external_dst, derive_agent_id_hex},
    ApprovalEventV2, ApprovalVerdictV2, AuthorStream, BlockReason, ConsumeEventV2, EventEnvelope,
    FoldInput, FoldLimits, FoldOutput, GenesisManifestV2, IssueStatusV2, ListRefusal,
    RequeueJustification, RosterEventV2, StoreRecord, TransitionEventV2, TransitionKind, V2_SCHEMA,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn err(msg: impl Into<String>) -> Box<dyn Error> {
    Box::new(std::io::Error::other(msg.into()))
}

// ---------------------------------------------------------------------------
// Signing fixture
// ---------------------------------------------------------------------------

struct Author {
    id: String,
    pk: Vec<u8>,
    sk: MlDsaSecretKey,
}

impl Author {
    fn generate() -> TestResult<Self> {
        let (pk, sk) = MlDsa65::new().generate_keypair()?;
        let pk = pk.as_bytes().to_vec();
        let id = derive_agent_id_hex(&pk);
        Ok(Self { id, pk, sk })
    }

    fn sign_envelope(&self, context: &str, payload: &[u8]) -> TestResult<EventEnvelope> {
        let canonical = assemble_external_dst(context, payload);
        let sig = MlDsa65::new().sign(&self.sk, &canonical)?;
        Ok(EventEnvelope {
            schema: V2_SCHEMA,
            context: context.to_owned(),
            algorithm: "x0x.agent-sign.v2.ml-dsa-65".to_owned(),
            payload_b64: BASE64.encode(payload),
            public_key_b64: BASE64.encode(&self.pk),
            signature_b64: BASE64.encode(sig.as_bytes()),
            signer_agent_id: self.id.clone(),
        })
    }
}

fn envelope_record(key: &str, envelope: &EventEnvelope) -> TestResult<StoreRecord> {
    Ok(StoreRecord {
        key: key.to_owned(),
        value: envelope.encode().map_err(err)?,
    })
}

// ---------------------------------------------------------------------------
// List fixture: genesis + per-author chains
// ---------------------------------------------------------------------------

struct ListFixture {
    list_uuid: String,
    genesis_hash: String,
    genesis_record: StoreRecord,
}

fn make_genesis(creator: &Author, list_uuid: &str, roster: &[&Author]) -> TestResult<ListFixture> {
    let manifest = GenesisManifestV2 {
        schema: V2_SCHEMA,
        kind: "genesis".to_owned(),
        list_uuid: list_uuid.to_owned(),
        creator: creator.id.clone(),
        roster: roster.iter().map(|a| a.id.clone()).collect(),
        policy: GenesisPolicy::default(),
        created_at: 1_700_000_000,
    };
    let payload = serde_json::to_vec(&manifest)?;
    let genesis_hash = sha256_hex(&payload);
    let envelope = creator.sign_envelope(GENESIS_CONTEXT_V2, &payload)?;
    Ok(ListFixture {
        list_uuid: list_uuid.to_owned(),
        genesis_hash,
        genesis_record: envelope_record(GENESIS_KEY, &envelope)?,
    })
}

/// Tracks one author's chain state so tests can mint valid chains tersely.
struct Chain<'a> {
    author: &'a Author,
    fixture_list: String,
    genesis_hash: String,
    seq: u64,
    prev: String,
}

impl<'a> Chain<'a> {
    fn new(author: &'a Author, fixture: &ListFixture) -> Self {
        Self {
            author,
            fixture_list: fixture.list_uuid.clone(),
            genesis_hash: fixture.genesis_hash.clone(),
            seq: 0,
            prev: fixture.genesis_hash.clone(),
        }
    }

    /// Build the next chained event; returns `(payload_hash, record)`.
    fn next(
        &mut self,
        epoch: u64,
        issue: &str,
        lamport: u64,
        kind: TransitionKind,
    ) -> TestResult<(String, StoreRecord)> {
        self.seq += 1;
        let event = TransitionEventV2 {
            schema: V2_SCHEMA,
            list_uuid: self.fixture_list.clone(),
            genesis_manifest_hash: self.genesis_hash.clone(),
            roster_epoch: epoch,
            issue_id: issue.to_owned(),
            actor: self.author.id.clone(),
            lamport,
            author_seq: self.seq,
            prev_own_event_hash: self.prev.clone(),
            kind,
        };
        let payload = event.to_signed_bytes().map_err(err)?;
        let hash = sha256_hex(&payload);
        let envelope = self.author.sign_envelope(TRANSITION_CONTEXT_V2, &payload)?;
        let record = envelope_record(&event_key(issue, &hash), &envelope)?;
        self.prev.clone_from(&hash);
        Ok((hash, record))
    }
}

impl Chain<'_> {
    /// Build the next chained dispatch approval; returns `(hash, record)`.
    fn next_approval(
        &mut self,
        epoch: u64,
        issue: &str,
        lamport: u64,
        open_event_hash: &str,
        verdict: ApprovalVerdictV2,
        approved_at: u64,
    ) -> TestResult<(String, StoreRecord)> {
        self.seq += 1;
        let event = ApprovalEventV2 {
            schema: V2_SCHEMA,
            kind: "dispatch_approval".to_owned(),
            list_uuid: self.fixture_list.clone(),
            genesis_manifest_hash: self.genesis_hash.clone(),
            roster_epoch: epoch,
            issue_id: issue.to_owned(),
            open_event_hash: open_event_hash.to_owned(),
            actor: self.author.id.clone(),
            lamport,
            author_seq: self.seq,
            prev_own_event_hash: self.prev.clone(),
            verdict,
            entropy: format!("entropy-{}", self.seq),
            approved_at,
            v1_record_json: String::new(),
        };
        let payload = event.to_signed_bytes().map_err(err)?;
        let hash = sha256_hex(&payload);
        let envelope = self.author.sign_envelope(APPROVAL_CONTEXT_V2, &payload)?;
        let record = envelope_record(&approval_key(issue, &hash), &envelope)?;
        self.prev.clone_from(&hash);
        Ok((hash, record))
    }

    /// Build the next chained consume; returns `(hash, record)`.
    #[allow(clippy::too_many_arguments)]
    fn next_consume(
        &mut self,
        epoch: u64,
        issue: &str,
        lamport: u64,
        approval_event_hash: &str,
        approver: &str,
        claim_nonce: &str,
        claimed_event_hash: &str,
    ) -> TestResult<(String, StoreRecord)> {
        self.seq += 1;
        let event = ConsumeEventV2 {
            schema: V2_SCHEMA,
            kind: "consume".to_owned(),
            list_uuid: self.fixture_list.clone(),
            genesis_manifest_hash: self.genesis_hash.clone(),
            roster_epoch: epoch,
            issue_id: issue.to_owned(),
            actor: self.author.id.clone(),
            lamport,
            author_seq: self.seq,
            prev_own_event_hash: self.prev.clone(),
            approval_event_hash: approval_event_hash.to_owned(),
            approval_payload_sha256: approval_event_hash.to_owned(),
            approver: approver.to_owned(),
            claim_nonce: claim_nonce.to_owned(),
            claimed_event_hash: claimed_event_hash.to_owned(),
            entropy: format!("entropy-{}", self.seq),
            v1_record_json: String::new(),
        };
        let payload = event.to_signed_bytes().map_err(err)?;
        let hash = sha256_hex(&payload);
        let envelope = self.author.sign_envelope(CONSUME_CONTEXT_V2, &payload)?;
        let record = envelope_record(&consume_key(issue, &hash), &envelope)?;
        self.prev.clone_from(&hash);
        Ok((hash, record))
    }
}

fn stream(author: &Author, mut records: Vec<StoreRecord>) -> AuthorStream {
    records.push(StoreRecord {
        key: CARD_SELF_KEY.to_owned(),
        value: author.pk.clone(),
    });
    AuthorStream {
        owner: author.id.clone(),
        card_self: Some(author.pk.clone()),
        records,
    }
}

fn fold(
    fixture: &ListFixture,
    creator: &Author,
    streams: Vec<AuthorStream>,
) -> Result<FoldOutput, ListRefusal> {
    fold_v2(&FoldInput {
        list_uuid: fixture.list_uuid.clone(),
        creator: creator.id.clone(),
        streams,
        limits: FoldLimits::default(),
    })
}

fn status_of<'o>(out: &'o FoldOutput, issue: &str) -> TestResult<&'o IssueStatusV2> {
    Ok(&out
        .issues
        .get(issue)
        .ok_or_else(|| err(format!("issue {issue} missing from fold output")))?
        .status)
}

fn rejection_reasons(out: &FoldOutput) -> Vec<String> {
    out.rejections.iter().map(|r| r.reason.clone()).collect()
}

fn assert_some_reason_contains(out: &FoldOutput, needle: &str) -> TestResult {
    if rejection_reasons(out).iter().any(|r| r.contains(needle)) {
        Ok(())
    } else {
        Err(err(format!(
            "expected a rejection containing {needle:?}, got {:?}",
            rejection_reasons(out)
        )))
    }
}

/// Deterministic LCG shuffle so determinism tests need no rand dependency.
fn lcg_shuffle<T>(items: &mut [T], seed: u64) {
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    for i in (1..items.len()).rev() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        #[allow(clippy::cast_possible_truncation)]
        let j = (state >> 33) as usize % (i + 1);
        items.swap(i, j);
    }
}

// ---------------------------------------------------------------------------
// Downgrade defense
// ---------------------------------------------------------------------------

#[test]
fn missing_genesis_refuses_the_list() -> TestResult {
    let a = Author::generate()?;
    let fixture = make_genesis(&a, "list-x", &[&a])?;
    // Creator stream present but WITHOUT the genesis record.
    let result = fold(&fixture, &a, vec![stream(&a, vec![])]);
    assert!(matches!(result, Err(ListRefusal::MissingGenesis)));
    // Creator stream entirely absent.
    let result = fold(&fixture, &a, vec![]);
    assert!(matches!(result, Err(ListRefusal::MissingCreatorStream(_))));
    Ok(())
}

#[test]
fn invalid_genesis_refuses_the_list() -> TestResult {
    let a = Author::generate()?;
    let b = Author::generate()?;
    // Genesis signed for a DIFFERENT list uuid: address binding must fail.
    let foreign = make_genesis(&a, "other-list", &[&a])?;
    let fixture_addr = ListFixture {
        list_uuid: "list-x".to_owned(),
        genesis_hash: foreign.genesis_hash.clone(),
        genesis_record: foreign.genesis_record.clone(),
    };
    let result = fold(
        &fixture_addr,
        &a,
        vec![stream(&a, vec![foreign.genesis_record.clone()])],
    );
    assert!(matches!(result, Err(ListRefusal::InvalidGenesis(_))));

    // Genesis signed by the wrong key (b signs, claims to be a): refused.
    let manifest = GenesisManifestV2 {
        schema: V2_SCHEMA,
        kind: "genesis".to_owned(),
        list_uuid: "list-x".to_owned(),
        creator: a.id.clone(),
        roster: vec![a.id.clone()],
        policy: GenesisPolicy::default(),
        created_at: 1,
    };
    let payload = serde_json::to_vec(&manifest)?;
    let mut envelope = b.sign_envelope(GENESIS_CONTEXT_V2, &payload)?;
    envelope.signer_agent_id.clone_from(&a.id);
    let record = envelope_record(GENESIS_KEY, &envelope)?;
    let fixture2 = ListFixture {
        list_uuid: "list-x".to_owned(),
        genesis_hash: sha256_hex(&payload),
        genesis_record: record.clone(),
    };
    let result = fold(&fixture2, &a, vec![stream(&a, vec![record])]);
    assert!(matches!(result, Err(ListRefusal::InvalidGenesis(_))));
    Ok(())
}

// ---------------------------------------------------------------------------
// Admission: four-way author binding
// ---------------------------------------------------------------------------

#[test]
fn event_signed_by_wrong_key_is_rejected() -> TestResult {
    let a = Author::generate()?;
    let b = Author::generate()?;
    let fixture = make_genesis(&a, "list-b1", &[&a, &b])?;

    // b signs an event whose payload actor and envelope signer both claim a.
    let event = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: fixture.list_uuid.clone(),
        genesis_manifest_hash: fixture.genesis_hash.clone(),
        roster_epoch: 0,
        issue_id: "i1".to_owned(),
        actor: a.id.clone(),
        lamport: 1,
        author_seq: 1,
        prev_own_event_hash: fixture.genesis_hash.clone(),
        kind: TransitionKind::open("t".to_owned(), "s".to_owned()),
    };
    let payload = event.to_signed_bytes().map_err(err)?;
    let hash = sha256_hex(&payload);
    let mut envelope = b.sign_envelope(TRANSITION_CONTEXT_V2, &payload)?;
    envelope.signer_agent_id.clone_from(&a.id); // impersonation attempt
    let record = envelope_record(&event_key("i1", &hash), &envelope)?;

    let out = fold(
        &fixture,
        &a,
        vec![stream(&a, vec![fixture.genesis_record.clone(), record])],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(out.issues.is_empty());
    assert_some_reason_contains(&out, "signer binding failed")?;
    Ok(())
}

#[test]
fn event_in_wrong_store_is_rejected() -> TestResult {
    let a = Author::generate()?;
    let b = Author::generate()?;
    let fixture = make_genesis(&a, "list-b2", &[&a, &b])?;

    // b mints a perfectly valid event, but it is read from a's store.
    let mut chain_b = Chain::new(&b, &fixture);
    let (_, record) = chain_b.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let out = fold(
        &fixture,
        &a,
        vec![stream(&a, vec![fixture.genesis_record.clone(), record])],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(out.issues.is_empty());
    assert_some_reason_contains(&out, "envelope signer")?;
    Ok(())
}

#[test]
fn actor_field_mismatch_is_rejected() -> TestResult {
    let a = Author::generate()?;
    let b = Author::generate()?;
    let fixture = make_genesis(&a, "list-b3", &[&a, &b])?;

    // a signs an event whose payload names b as actor.
    let event = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: fixture.list_uuid.clone(),
        genesis_manifest_hash: fixture.genesis_hash.clone(),
        roster_epoch: 0,
        issue_id: "i1".to_owned(),
        actor: b.id.clone(),
        lamport: 1,
        author_seq: 1,
        prev_own_event_hash: fixture.genesis_hash.clone(),
        kind: TransitionKind::open("t".to_owned(), "s".to_owned()),
    };
    let payload = event.to_signed_bytes().map_err(err)?;
    let hash = sha256_hex(&payload);
    let envelope = a.sign_envelope(TRANSITION_CONTEXT_V2, &payload)?;
    let record = envelope_record(&event_key("i1", &hash), &envelope)?;
    let out = fold(
        &fixture,
        &a,
        vec![stream(&a, vec![fixture.genesis_record.clone(), record])],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(out.issues.is_empty());
    assert_some_reason_contains(&out, "is not the store owner")?;
    Ok(())
}

#[test]
fn missing_or_mismatched_card_self_rejects_stream() -> TestResult {
    let a = Author::generate()?;
    let b = Author::generate()?;
    let fixture = make_genesis(&a, "list-b4", &[&a, &b])?;

    let mut chain_b = Chain::new(&b, &fixture);
    let (_, record) = chain_b.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;

    // No card-self at all.
    let bare = AuthorStream {
        owner: b.id.clone(),
        card_self: None,
        records: vec![record.clone()],
    };
    let out = fold(
        &fixture,
        &a,
        vec![stream(&a, vec![fixture.genesis_record.clone()]), bare],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(out.issues.is_empty());
    assert_some_reason_contains(&out, "card-self is missing")?;

    // card-self present but it is a's key, not b's.
    let wrong_card = AuthorStream {
        owner: b.id.clone(),
        card_self: Some(a.pk.clone()),
        records: vec![record],
    };
    let out = fold(
        &fixture,
        &a,
        vec![stream(&a, vec![fixture.genesis_record.clone()]), wrong_card],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(out.issues.is_empty());
    assert_some_reason_contains(&out, "card-self key derives to")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Admission: roster, chains, lamport, bindings
// ---------------------------------------------------------------------------

#[test]
fn non_roster_author_is_rejected() -> TestResult {
    let a = Author::generate()?;
    let c = Author::generate()?;
    // c is NOT in the roster.
    let fixture = make_genesis(&a, "list-r1", &[&a])?;
    let mut chain_c = Chain::new(&c, &fixture);
    let (_, record) = chain_c.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let out = fold(
        &fixture,
        &a,
        vec![
            stream(&a, vec![fixture.genesis_record.clone()]),
            stream(&c, vec![record]),
        ],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(out.issues.is_empty());
    assert_some_reason_contains(&out, "is not a roster member")?;
    Ok(())
}

#[test]
fn roster_update_admits_new_member_at_new_epoch_only() -> TestResult {
    let a = Author::generate()?;
    let b = Author::generate()?;
    let fixture = make_genesis(&a, "list-r2", &[&a])?;

    // Creator publishes epoch 1 adding b.
    let roster_event = RosterEventV2 {
        schema: V2_SCHEMA,
        kind: "roster".to_owned(),
        list_uuid: fixture.list_uuid.clone(),
        genesis_manifest_hash: fixture.genesis_hash.clone(),
        roster_epoch: 1,
        prev_roster_hash: fixture.genesis_hash.clone(),
        roster: vec![a.id.clone(), b.id.clone()],
        actor: a.id.clone(),
    };
    let payload = serde_json::to_vec(&roster_event)?;
    let rhash = sha256_hex(&payload);
    let envelope = a.sign_envelope(ROSTER_CONTEXT_V2, &payload)?;
    let roster_record = envelope_record(&roster_key(1, &rhash), &envelope)?;

    let mut chain_b = Chain::new(&b, &fixture);
    let (_, ok_record) = chain_b.next(
        1,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    // Same author, epoch 0 (b was not a member then) and epoch 7 (unknown).
    let (_, bad_epoch0) = chain_b.next(
        0,
        "i2",
        2,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let (_, bad_epoch7) = chain_b.next(
        7,
        "i3",
        3,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;

    let out = fold(
        &fixture,
        &a,
        vec![
            stream(&a, vec![fixture.genesis_record.clone(), roster_record]),
            stream(&b, vec![ok_record, bad_epoch0, bad_epoch7]),
        ],
    )
    .map_err(|e| err(e.to_string()))?;
    assert_eq!(out.latest_roster_epoch, 1);
    assert!(out.issues.contains_key("i1"));
    assert!(!out.issues.contains_key("i2"));
    assert!(!out.issues.contains_key("i3"));
    assert_some_reason_contains(&out, "not a roster member at epoch 0")?;
    assert_some_reason_contains(&out, "unknown roster epoch 7")?;
    Ok(())
}

#[test]
fn author_chain_gap_rejects_from_gap() -> TestResult {
    let a = Author::generate()?;
    let fixture = make_genesis(&a, "list-c1", &[&a])?;
    let mut chain = Chain::new(&a, &fixture);
    let (_, r1) = chain.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let (_, _skipped) = chain.next(
        0,
        "i1",
        2,
        TransitionKind::Claim {
            claim_nonce: "n1".to_owned(),
        },
    )?;
    let (_, r3) = chain.next(
        0,
        "i1",
        3,
        TransitionKind::Release {
            claim_nonce: "n1".to_owned(),
            claimed_event_hash: "x".to_owned(),
        },
    )?;
    // Withhold seq 2 — seq 3 must be inadmissible (gap).
    let out = fold(
        &fixture,
        &a,
        vec![stream(&a, vec![fixture.genesis_record.clone(), r1, r3])],
    )
    .map_err(|e| err(e.to_string()))?;
    assert_eq!(status_of(&out, "i1")?, &IssueStatusV2::Open);
    assert_some_reason_contains(&out, "author chain gap")?;
    Ok(())
}

#[test]
fn author_chain_fork_surfaces_evidence_and_rejects_from_fork() -> TestResult {
    let a = Author::generate()?;
    let b = Author::generate()?;
    let fixture = make_genesis(&a, "list-c2", &[&a, &b])?;

    let mut chain = Chain::new(&b, &fixture);
    let (_, r1) = chain.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    // Two conflicting seq-2 events (a fork of b's own history).
    let saved_seq = chain.seq;
    let saved_prev = chain.prev.clone();
    let (_, r2x) = chain.next(
        0,
        "i1",
        2,
        TransitionKind::Claim {
            claim_nonce: "nx".to_owned(),
        },
    )?;
    chain.seq = saved_seq;
    chain.prev = saved_prev;
    let (_, r2y) = chain.next(
        0,
        "i1",
        3,
        TransitionKind::Claim {
            claim_nonce: "ny".to_owned(),
        },
    )?;
    // A continuation after the fork must also be inadmissible.
    let (_, r3) = chain.next(
        0,
        "i1",
        4,
        TransitionKind::Release {
            claim_nonce: "ny".to_owned(),
            claimed_event_hash: "x".to_owned(),
        },
    )?;

    let out = fold(
        &fixture,
        &a,
        vec![
            stream(&a, vec![fixture.genesis_record.clone()]),
            stream(&b, vec![r1, r2x, r2y, r3]),
        ],
    )
    .map_err(|e| err(e.to_string()))?;
    // Fork evidence names the author and duplicated seq with both hashes.
    assert_eq!(out.forks.len(), 1);
    assert_eq!(out.forks[0].author, b.id);
    assert_eq!(out.forks[0].author_seq, 2);
    assert_eq!(out.forks[0].event_hashes.len(), 2);
    // Prefix before the fork survives; the issue exists but is unclaimed.
    assert_eq!(status_of(&out, "i1")?, &IssueStatusV2::Open);
    Ok(())
}

#[test]
fn lamport_future_dating_is_capped() -> TestResult {
    let a = Author::generate()?;
    let fixture = make_genesis(&a, "list-l1", &[&a])?;
    let mut chain = Chain::new(&a, &fixture);
    let (_, r1) = chain.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    // 65 == 1 + LAMPORT_MAX_SKEW: exactly at the boundary, admitted.
    let (_, r2) = chain.next(
        0,
        "i1",
        65,
        TransitionKind::Claim {
            claim_nonce: "n".to_owned(),
        },
    )?;
    // 1_000_000: far beyond the cap, rejected (and truncates the chain).
    let (_, r3) = chain.next(
        0,
        "i2",
        1_000_000,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let out = fold(
        &fixture,
        &a,
        vec![stream(&a, vec![fixture.genesis_record.clone(), r1, r2, r3])],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(matches!(
        status_of(&out, "i1")?,
        IssueStatusV2::Claimed { .. }
    ));
    assert!(!out.issues.contains_key("i2"));
    assert_some_reason_contains(&out, "exceeds admitted maximum")?;
    assert_eq!(out.max_admitted_lamport, 65);
    Ok(())
}

#[test]
fn cross_list_replay_of_byte_identical_event_is_rejected() -> TestResult {
    let a = Author::generate()?;
    // Two lists created by the same author, same uuid even — but distinct
    // genesis manifests (created_at differs ⇒ different genesis hash).
    let fixture1 = make_genesis(&a, "list-cl", &[&a])?;
    let manifest2 = GenesisManifestV2 {
        schema: V2_SCHEMA,
        kind: "genesis".to_owned(),
        list_uuid: "list-cl".to_owned(),
        creator: a.id.clone(),
        roster: vec![a.id.clone()],
        policy: GenesisPolicy::default(),
        created_at: 1_800_000_000,
    };
    let payload2 = serde_json::to_vec(&manifest2)?;
    let genesis2_hash = sha256_hex(&payload2);
    let envelope2 = a.sign_envelope(GENESIS_CONTEXT_V2, &payload2)?;
    let fixture2 = ListFixture {
        list_uuid: "list-cl".to_owned(),
        genesis_hash: genesis2_hash,
        genesis_record: envelope_record(GENESIS_KEY, &envelope2)?,
    };

    // Event authored for list 1.
    let mut chain = Chain::new(&a, &fixture1);
    let (_, record) = chain.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;

    // Replayed byte-identically into list 2: genesis binding must reject it.
    let out = fold(
        &fixture2,
        &a,
        vec![stream(
            &a,
            vec![fixture2.genesis_record.clone(), record.clone()],
        )],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(out.issues.is_empty());
    assert_some_reason_contains(&out, "genesis binding")?;

    // And a replay into a different-uuid list fails the list binding.
    let fixture3 = make_genesis(&a, "list-other", &[&a])?;
    let out = fold(
        &fixture3,
        &a,
        vec![stream(&a, vec![fixture3.genesis_record.clone(), record])],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(out.issues.is_empty());
    assert_some_reason_contains(&out, "names list")?;
    Ok(())
}

#[test]
fn record_stored_under_wrong_key_is_rejected() -> TestResult {
    let a = Author::generate()?;
    let fixture = make_genesis(&a, "list-k1", &[&a])?;
    let mut chain = Chain::new(&a, &fixture);
    let (_, mut record) = chain.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    record.key = event_key("i1", &"0".repeat(64));
    let out = fold(
        &fixture,
        &a,
        vec![stream(&a, vec![fixture.genesis_record.clone(), record])],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(out.issues.is_empty());
    assert_some_reason_contains(&out, "content address")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 2: state machine
// ---------------------------------------------------------------------------

#[test]
fn concurrent_claims_pick_deterministic_winner_in_both_orders() -> TestResult {
    let a = Author::generate()?;
    let b = Author::generate()?;
    let c = Author::generate()?;
    let fixture = make_genesis(&a, "list-s1", &[&a, &b, &c])?;

    let mut chain_a = Chain::new(&a, &fixture);
    let (_open_hash, r_open) = chain_a.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    // Same lamport, different authors: winner = smaller (author, hash).
    let mut chain_b = Chain::new(&b, &fixture);
    let (hash_b, r_claim_b) = chain_b.next(
        0,
        "i1",
        2,
        TransitionKind::Claim {
            claim_nonce: "nb".to_owned(),
        },
    )?;
    let mut chain_c = Chain::new(&c, &fixture);
    let (hash_c, r_claim_c) = chain_c.next(
        0,
        "i1",
        2,
        TransitionKind::Claim {
            claim_nonce: "nc".to_owned(),
        },
    )?;
    let expected_winner = if (b.id.clone(), hash_b.clone()) < (c.id.clone(), hash_c.clone()) {
        b.id.clone()
    } else {
        c.id.clone()
    };

    for flipped in [false, true] {
        let mut streams = vec![
            stream(&a, vec![fixture.genesis_record.clone(), r_open.clone()]),
            stream(&b, vec![r_claim_b.clone()]),
            stream(&c, vec![r_claim_c.clone()]),
        ];
        if flipped {
            streams.reverse();
        }
        let out = fold(&fixture, &a, streams).map_err(|e| err(e.to_string()))?;
        let IssueStatusV2::Claimed { claimant, .. } = status_of(&out, "i1")? else {
            return Err(err("expected claimed"));
        };
        assert_eq!(claimant, &expected_winner);
    }
    Ok(())
}

#[test]
fn stale_claimants_release_is_ineffective() -> TestResult {
    let a = Author::generate()?;
    let b = Author::generate()?;
    let fixture = make_genesis(&a, "list-s2", &[&a, &b])?;

    let mut chain_a = Chain::new(&a, &fixture);
    let (_, r_open) = chain_a.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let (winning_claim_hash, r_claim_a) = chain_a.next(
        0,
        "i1",
        2,
        TransitionKind::Claim {
            claim_nonce: "na".to_owned(),
        },
    )?;
    // b claims later (loses), then tries to release with its own nonce.
    let mut chain_b = Chain::new(&b, &fixture);
    let (losing_claim_hash, r_claim_b) = chain_b.next(
        0,
        "i1",
        3,
        TransitionKind::Claim {
            claim_nonce: "nb".to_owned(),
        },
    )?;
    let (_, r_release_b) = chain_b.next(
        0,
        "i1",
        4,
        TransitionKind::Release {
            claim_nonce: "nb".to_owned(),
            claimed_event_hash: losing_claim_hash,
        },
    )?;

    let out = fold(
        &fixture,
        &a,
        vec![
            stream(&a, vec![fixture.genesis_record.clone(), r_open, r_claim_a]),
            stream(&b, vec![r_claim_b, r_release_b]),
        ],
    )
    .map_err(|e| err(e.to_string()))?;
    let IssueStatusV2::Claimed {
        claimant,
        claim_nonce,
        claim_event_hash,
    } = status_of(&out, "i1")?
    else {
        return Err(err("expected claimed"));
    };
    assert_eq!(claimant, &a.id);
    assert_eq!(claim_nonce, "na");
    assert_eq!(claim_event_hash, &winning_claim_hash);
    assert_some_reason_contains(&out, "is not the claimant")?;
    Ok(())
}

/// Build the standard block/approve fixtures used by the requeue tests.
struct RequeueScenario {
    fixture: ListFixture,
    creator: Author,
    worker: Author,
    approver: Author,
    records_creator: Vec<StoreRecord>,
    records_worker: Vec<StoreRecord>,
    worker_chain_seq: u64,
    worker_chain_prev: String,
    claim_nonce: String,
    block_hash: String,
}

fn requeue_scenario(list: &str) -> TestResult<RequeueScenario> {
    let creator = Author::generate()?;
    let worker = Author::generate()?;
    let approver = Author::generate()?;
    let fixture = make_genesis(&creator, list, &[&creator, &worker, &approver])?;

    let mut chain_c = Chain::new(&creator, &fixture);
    let (_, r_open) = chain_c.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let mut chain_w = Chain::new(&worker, &fixture);
    let claim_nonce = "nonce-w".to_owned();
    let (claim_hash, r_claim) = chain_w.next(
        0,
        "i1",
        2,
        TransitionKind::Claim {
            claim_nonce: claim_nonce.clone(),
        },
    )?;
    let (block_hash, r_block) = chain_w.next(
        0,
        "i1",
        3,
        TransitionKind::Block {
            claim_nonce: claim_nonce.clone(),
            claimed_event_hash: claim_hash,
            reason: BlockReason::AwaitingApproval,
        },
    )?;
    Ok(RequeueScenario {
        records_creator: vec![fixture.genesis_record.clone(), r_open],
        records_worker: vec![r_claim, r_block],
        worker_chain_seq: chain_w.seq,
        worker_chain_prev: chain_w.prev,
        fixture,
        creator,
        worker,
        approver,
        claim_nonce,
        block_hash,
    })
}

fn make_approval(
    scenario: &RequeueScenario,
    block_event_hash: &str,
    claim_nonce: &str,
    genesis_hash: &str,
    issue_id: &str,
) -> TestResult<(EventEnvelope, String)> {
    let approval = ApprovalPayloadV2 {
        schema: V2_SCHEMA,
        kind: "approval".to_owned(),
        list_uuid: scenario.fixture.list_uuid.clone(),
        genesis_manifest_hash: genesis_hash.to_owned(),
        issue_id: issue_id.to_owned(),
        block_event_hash: block_event_hash.to_owned(),
        claim_nonce: claim_nonce.to_owned(),
        approver: scenario.approver.id.clone(),
        approved_at: 1_700_000_100,
    };
    let payload = serde_json::to_vec(&approval)?;
    let hash = sha256_hex(&payload);
    let envelope = scenario
        .approver
        .sign_envelope(APPROVAL_CONTEXT_V2, &payload)?;
    Ok((envelope, hash))
}

fn requeue_event(
    scenario: &RequeueScenario,
    justification: RequeueJustification,
) -> TestResult<StoreRecord> {
    // The worker itself issues the requeue (any roster member may).
    let event = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: scenario.fixture.list_uuid.clone(),
        genesis_manifest_hash: scenario.fixture.genesis_hash.clone(),
        roster_epoch: 0,
        issue_id: "i1".to_owned(),
        actor: scenario.worker.id.clone(),
        lamport: 4,
        author_seq: scenario.worker_chain_seq + 1,
        prev_own_event_hash: scenario.worker_chain_prev.clone(),
        kind: TransitionKind::Requeue { justification },
    };
    let payload = event.to_signed_bytes().map_err(err)?;
    let hash = sha256_hex(&payload);
    let envelope = scenario
        .worker
        .sign_envelope(TRANSITION_CONTEXT_V2, &payload)?;
    envelope_record(&event_key("i1", &hash), &envelope)
}

fn fold_scenario(scenario: &RequeueScenario, requeue: StoreRecord) -> TestResult<FoldOutput> {
    let mut worker_records = scenario.records_worker.clone();
    worker_records.push(requeue);
    fold(
        &scenario.fixture,
        &scenario.creator,
        vec![
            stream(&scenario.creator, scenario.records_creator.clone()),
            stream(&scenario.worker, worker_records),
            stream(&scenario.approver, vec![]),
        ],
    )
    .map_err(|e| err(e.to_string()))
}

#[test]
fn requeue_with_valid_justification_unparks() -> TestResult {
    let scenario = requeue_scenario("list-q1")?;
    let (approval, approval_hash) = make_approval(
        &scenario,
        &scenario.block_hash,
        &scenario.claim_nonce,
        &scenario.fixture.genesis_hash,
        "i1",
    )?;
    let requeue = requeue_event(
        &scenario,
        RequeueJustification {
            block_event_hash: scenario.block_hash.clone(),
            claim_nonce: scenario.claim_nonce.clone(),
            approval_event_hash: approval_hash.clone(),
            approval_payload_sha256: approval_hash,
            approver: scenario.approver.id.clone(),
            approval,
        },
    )?;
    let out = fold_scenario(&scenario, requeue)?;
    assert_eq!(status_of(&out, "i1")?, &IssueStatusV2::Open);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)] // Six independent violation cases, one per binding.
fn requeue_justification_violations_are_rejected_one_by_one() -> TestResult {
    let scenario = requeue_scenario("list-q2")?;
    let (approval, approval_hash) = make_approval(
        &scenario,
        &scenario.block_hash,
        &scenario.claim_nonce,
        &scenario.fixture.genesis_hash,
        "i1",
    )?;
    let valid = RequeueJustification {
        block_event_hash: scenario.block_hash.clone(),
        claim_nonce: scenario.claim_nonce.clone(),
        approval_event_hash: approval_hash.clone(),
        approval_payload_sha256: approval_hash.clone(),
        approver: scenario.approver.id.clone(),
        approval: approval.clone(),
    };

    // (1) Wrong approval event hash.
    let mut j = valid.clone();
    j.approval_event_hash = "0".repeat(64);
    let out = fold_scenario(&scenario, requeue_event(&scenario, j)?)?;
    assert!(matches!(
        status_of(&out, "i1")?,
        IssueStatusV2::Blocked { .. }
    ));
    assert_some_reason_contains(&out, "approval event hash")?;

    // (2) Wrong approval payload hash.
    let mut j = valid.clone();
    j.approval_payload_sha256 = "0".repeat(64);
    let out = fold_scenario(&scenario, requeue_event(&scenario, j)?)?;
    assert!(matches!(
        status_of(&out, "i1")?,
        IssueStatusV2::Blocked { .. }
    ));
    assert_some_reason_contains(&out, "approval payload hash")?;

    // (3) Tampered approval payload (signature must fail).
    let mut j = valid.clone();
    let mut tampered = approval.clone();
    let mut bytes = tampered.payload_bytes().map_err(err)?;
    if let Some(byte) = bytes.last_mut() {
        *byte ^= 0x01;
    }
    tampered.payload_b64 = BASE64.encode(&bytes);
    j.approval = tampered;
    let out = fold_scenario(&scenario, requeue_event(&scenario, j)?)?;
    assert!(matches!(
        status_of(&out, "i1")?,
        IssueStatusV2::Blocked { .. }
    ));
    assert_some_reason_contains(&out, "requeue approval envelope")?;

    // (4) Approver not in roster: approval signed by an outsider.
    let outsider = Author::generate()?;
    let approval_payload = ApprovalPayloadV2 {
        schema: V2_SCHEMA,
        kind: "approval".to_owned(),
        list_uuid: scenario.fixture.list_uuid.clone(),
        genesis_manifest_hash: scenario.fixture.genesis_hash.clone(),
        issue_id: "i1".to_owned(),
        block_event_hash: scenario.block_hash.clone(),
        claim_nonce: scenario.claim_nonce.clone(),
        approver: outsider.id.clone(),
        approved_at: 1,
    };
    let payload = serde_json::to_vec(&approval_payload)?;
    let hash = sha256_hex(&payload);
    let envelope = outsider.sign_envelope(APPROVAL_CONTEXT_V2, &payload)?;
    let j = RequeueJustification {
        block_event_hash: scenario.block_hash.clone(),
        claim_nonce: scenario.claim_nonce.clone(),
        approval_event_hash: hash.clone(),
        approval_payload_sha256: hash,
        approver: outsider.id.clone(),
        approval: envelope,
    };
    let out = fold_scenario(&scenario, requeue_event(&scenario, j)?)?;
    assert!(matches!(
        status_of(&out, "i1")?,
        IssueStatusV2::Blocked { .. }
    ));
    assert_some_reason_contains(&out, "is not a roster member")?;

    // (5) Consistent justification naming the WRONG block: passes admission
    // bindings but must be ineffective at the state machine.
    let wrong_block_hash = "1".repeat(64);
    let (approval_wrong, approval_wrong_hash) = make_approval(
        &scenario,
        &wrong_block_hash,
        &scenario.claim_nonce,
        &scenario.fixture.genesis_hash,
        "i1",
    )?;
    let j = RequeueJustification {
        block_event_hash: wrong_block_hash,
        claim_nonce: scenario.claim_nonce.clone(),
        approval_event_hash: approval_wrong_hash.clone(),
        approval_payload_sha256: approval_wrong_hash,
        approver: scenario.approver.id.clone(),
        approval: approval_wrong,
    };
    let out = fold_scenario(&scenario, requeue_event(&scenario, j)?)?;
    assert!(matches!(
        status_of(&out, "i1")?,
        IssueStatusV2::Blocked { .. }
    ));
    assert_some_reason_contains(&out, "not the current block")?;

    // (6) Consistent justification naming the wrong claim nonce.
    let (approval_wn, approval_wn_hash) = make_approval(
        &scenario,
        &scenario.block_hash,
        "wrong-nonce",
        &scenario.fixture.genesis_hash,
        "i1",
    )?;
    let j = RequeueJustification {
        block_event_hash: scenario.block_hash.clone(),
        claim_nonce: "wrong-nonce".to_owned(),
        approval_event_hash: approval_wn_hash.clone(),
        approval_payload_sha256: approval_wn_hash,
        approver: scenario.approver.id.clone(),
        approval: approval_wn,
    };
    let out = fold_scenario(&scenario, requeue_event(&scenario, j)?)?;
    assert!(matches!(
        status_of(&out, "i1")?,
        IssueStatusV2::Blocked { .. }
    ));
    assert_some_reason_contains(&out, "does not match the parked claim")?;
    Ok(())
}

#[test]
fn non_approval_blocks_are_never_requeueable() -> TestResult {
    let creator = Author::generate()?;
    let worker = Author::generate()?;
    let approver = Author::generate()?;
    let fixture = make_genesis(&creator, "list-q3", &[&creator, &worker, &approver])?;

    let mut chain_c = Chain::new(&creator, &fixture);
    let (_, r_open) = chain_c.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let mut chain_w = Chain::new(&worker, &fixture);
    let (claim_hash, r_claim) = chain_w.next(
        0,
        "i1",
        2,
        TransitionKind::Claim {
            claim_nonce: "n".to_owned(),
        },
    )?;
    // Security block (reason: Other) — terminal for this claim.
    let (block_hash, r_block) = chain_w.next(
        0,
        "i1",
        3,
        TransitionKind::Block {
            claim_nonce: "n".to_owned(),
            claimed_event_hash: claim_hash,
            reason: BlockReason::Other {
                detail: "security".to_owned(),
            },
        },
    )?;

    let scenario = RequeueScenario {
        records_creator: vec![fixture.genesis_record.clone(), r_open],
        records_worker: vec![r_claim, r_block],
        worker_chain_seq: chain_w.seq,
        worker_chain_prev: chain_w.prev.clone(),
        fixture,
        creator,
        worker,
        approver,
        claim_nonce: "n".to_owned(),
        block_hash,
    };
    let (approval, approval_hash) = make_approval(
        &scenario,
        &scenario.block_hash,
        &scenario.claim_nonce,
        &scenario.fixture.genesis_hash,
        "i1",
    )?;
    let requeue = requeue_event(
        &scenario,
        RequeueJustification {
            block_event_hash: scenario.block_hash.clone(),
            claim_nonce: scenario.claim_nonce.clone(),
            approval_event_hash: approval_hash.clone(),
            approval_payload_sha256: approval_hash,
            approver: scenario.approver.id.clone(),
            approval,
        },
    )?;
    let out = fold_scenario(&scenario, requeue)?;
    assert!(matches!(
        status_of(&out, "i1")?,
        IssueStatusV2::Blocked { .. }
    ));
    assert_some_reason_contains(&out, "only awaiting_approval blocks are requeue-able")?;
    Ok(())
}

#[test]
fn full_happy_path_open_claim_block_requeue_reclaim_complete() -> TestResult {
    let scenario = requeue_scenario("list-h1")?;
    let (approval, approval_hash) = make_approval(
        &scenario,
        &scenario.block_hash,
        &scenario.claim_nonce,
        &scenario.fixture.genesis_hash,
        "i1",
    )?;
    let requeue = requeue_event(
        &scenario,
        RequeueJustification {
            block_event_hash: scenario.block_hash.clone(),
            claim_nonce: scenario.claim_nonce.clone(),
            approval_event_hash: approval_hash.clone(),
            approval_payload_sha256: approval_hash,
            approver: scenario.approver.id.clone(),
            approval,
        },
    )?;

    // After the requeue (worker seq 4), the worker re-claims and completes.
    let requeue_payload_hash = {
        let envelope = EventEnvelope::decode(&requeue.value).map_err(err)?;
        let (_, hash) = envelope.verify(TRANSITION_CONTEXT_V2).map_err(err)?;
        hash
    };
    let mut chain_w = Chain {
        author: &scenario.worker,
        fixture_list: scenario.fixture.list_uuid.clone(),
        genesis_hash: scenario.fixture.genesis_hash.clone(),
        seq: scenario.worker_chain_seq + 1,
        prev: requeue_payload_hash,
    };
    let (claim2_hash, r_claim2) = chain_w.next(
        0,
        "i1",
        5,
        TransitionKind::Claim {
            claim_nonce: "nonce-2".to_owned(),
        },
    )?;
    let (_, r_complete) = chain_w.next(
        0,
        "i1",
        6,
        TransitionKind::Complete {
            claim_nonce: "nonce-2".to_owned(),
            claimed_event_hash: claim2_hash,
        },
    )?;

    let mut worker_records = scenario.records_worker.clone();
    worker_records.extend([requeue, r_claim2, r_complete]);
    let out = fold(
        &scenario.fixture,
        &scenario.creator,
        vec![
            stream(&scenario.creator, scenario.records_creator.clone()),
            stream(&scenario.worker, worker_records),
            stream(&scenario.approver, vec![]),
        ],
    )
    .map_err(|e| err(e.to_string()))?;
    let IssueStatusV2::Done { completed_by, .. } = status_of(&out, "i1")? else {
        return Err(err(format!(
            "expected done, got {:?}",
            status_of(&out, "i1")?
        )));
    };
    assert_eq!(completed_by, &scenario.worker.id);
    // Every state change is on the applied log.
    let issue = out
        .issues
        .get("i1")
        .ok_or_else(|| err("issue i1 missing"))?;
    assert_eq!(issue.applied.len(), 6); // open, claim, block, requeue, claim, complete
    Ok(())
}

#[test]
fn release_reopens_and_allows_reclaim_by_other_author() -> TestResult {
    let a = Author::generate()?;
    let b = Author::generate()?;
    let fixture = make_genesis(&a, "list-h2", &[&a, &b])?;

    let mut chain_a = Chain::new(&a, &fixture);
    let (_, r_open) = chain_a.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let (claim_hash, r_claim) = chain_a.next(
        0,
        "i1",
        2,
        TransitionKind::Claim {
            claim_nonce: "na".to_owned(),
        },
    )?;
    let (_, r_release) = chain_a.next(
        0,
        "i1",
        3,
        TransitionKind::Release {
            claim_nonce: "na".to_owned(),
            claimed_event_hash: claim_hash,
        },
    )?;
    let mut chain_b = Chain::new(&b, &fixture);
    let (claim_b_hash, r_claim_b) = chain_b.next(
        0,
        "i1",
        4,
        TransitionKind::Claim {
            claim_nonce: "nb".to_owned(),
        },
    )?;
    let (_, r_complete_b) = chain_b.next(
        0,
        "i1",
        5,
        TransitionKind::Complete {
            claim_nonce: "nb".to_owned(),
            claimed_event_hash: claim_b_hash,
        },
    )?;

    let out = fold(
        &fixture,
        &a,
        vec![
            stream(
                &a,
                vec![fixture.genesis_record.clone(), r_open, r_claim, r_release],
            ),
            stream(&b, vec![r_claim_b, r_complete_b]),
        ],
    )
    .map_err(|e| err(e.to_string()))?;
    let IssueStatusV2::Done { completed_by, .. } = status_of(&out, "i1")? else {
        return Err(err("expected done"));
    };
    assert_eq!(completed_by, &b.id);
    Ok(())
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)] // One rich scenario keeps the shuffles meaningful.
fn fold_is_order_independent_under_random_shuffles() -> TestResult {
    // Rich scenario: 3 authors, roster update, competing claims, a chain
    // fork, a lamport outlier, and a completed issue.
    let a = Author::generate()?;
    let b = Author::generate()?;
    let c = Author::generate()?;
    let fixture = make_genesis(&a, "list-d1", &[&a, &b, &c])?;

    let mut chain_a = Chain::new(&a, &fixture);
    let (_, r1) = chain_a.next(
        0,
        "i1",
        1,
        TransitionKind::open("t1".to_owned(), "s1".to_owned()),
    )?;
    let (_, r2) = chain_a.next(
        0,
        "i2",
        2,
        TransitionKind::open("t2".to_owned(), "s2".to_owned()),
    )?;
    let mut chain_b = Chain::new(&b, &fixture);
    let (hb, r3) = chain_b.next(
        0,
        "i1",
        3,
        TransitionKind::Claim {
            claim_nonce: "nb".to_owned(),
        },
    )?;
    let mut chain_c = Chain::new(&c, &fixture);
    let (_, r4) = chain_c.next(
        0,
        "i1",
        3,
        TransitionKind::Claim {
            claim_nonce: "nc".to_owned(),
        },
    )?;
    let (_, r5) = chain_b.next(
        0,
        "i1",
        4,
        TransitionKind::Complete {
            claim_nonce: "nb".to_owned(),
            claimed_event_hash: hb.clone(),
        },
    )?;
    // c forks its own chain at seq 2.
    let saved_seq = chain_c.seq;
    let saved_prev = chain_c.prev.clone();
    let (_, r6) = chain_c.next(
        0,
        "i2",
        5,
        TransitionKind::Claim {
            claim_nonce: "nc2".to_owned(),
        },
    )?;
    chain_c.seq = saved_seq;
    chain_c.prev = saved_prev;
    let (_, r7) = chain_c.next(
        0,
        "i2",
        6,
        TransitionKind::Claim {
            claim_nonce: "nc3".to_owned(),
        },
    )?;
    // a future-dates an event far beyond the cap.
    let (_, r8) = chain_a.next(
        0,
        "i2",
        9_999_999,
        TransitionKind::Claim {
            claim_nonce: "na".to_owned(),
        },
    )?;

    let base_streams = vec![
        stream(&a, vec![fixture.genesis_record.clone(), r1, r2, r8]),
        stream(&b, vec![r3, r5]),
        stream(&c, vec![r4, r6, r7]),
    ];
    let reference = fold(&fixture, &a, base_streams.clone()).map_err(|e| err(e.to_string()))?;
    let reference_json = serde_json::to_value(&reference)?;

    // Sanity on the reference outcome itself. The b-vs-c lamport tie on i1
    // is broken by (author, hash), which depends on the generated keypairs:
    // if b wins, b's complete lands (Done); if c wins, b's complete is
    // correctly fenced out (Claimed by c). Both are legitimate — the point
    // of THIS test is that shuffles agree, not who wins.
    assert!(matches!(
        status_of(&reference, "i1")?,
        IssueStatusV2::Done { .. } | IssueStatusV2::Claimed { .. }
    ));
    assert_eq!(reference.forks.len(), 1);

    for seed in 0..10u64 {
        let mut streams = base_streams.clone();
        lcg_shuffle(&mut streams, seed);
        for s in &mut streams {
            lcg_shuffle(&mut s.records, seed.wrapping_add(7));
        }
        let shuffled = fold(&fixture, &a, streams).map_err(|e| err(e.to_string()))?;
        assert_eq!(
            serde_json::to_value(&shuffled)?,
            reference_json,
            "fold output diverged for shuffle seed {seed}"
        );
    }
    Ok(())
}

/// FIX 2 (Codex review of PR #11): a later-rejected event must not have
/// widened the lamport horizon for anyone else. Under the pre-fix
/// single-pass cap, A's chain-valid pair (seq1 lamport=200, seq2 lamport=60)
/// let B's lamport=120 ride on a horizon that collapsed once A's seq1 was
/// rejected and A's chain truncated. The fixpoint must reject ALL of them:
/// with only survivors contributing, no event here fits within 0 + 64.
#[test]
fn lamport_rejected_events_do_not_widen_the_horizon_for_others() -> TestResult {
    let a = Author::generate()?;
    let b = Author::generate()?;
    let fixture = make_genesis(&a, "list-l2", &[&a, &b])?;

    let mut chain_a = Chain::new(&a, &fixture);
    let (_, r_high_first) = chain_a.next(
        0,
        "i1",
        200,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let (_, r_low_second) = chain_a.next(
        0,
        "i1",
        60,
        TransitionKind::Claim {
            claim_nonce: "na".to_owned(),
        },
    )?;
    let mut chain_b = Chain::new(&b, &fixture);
    let (_, r_other_author) = chain_b.next(
        0,
        "i2",
        120,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;

    let base_streams = vec![
        stream(
            &a,
            vec![fixture.genesis_record.clone(), r_high_first, r_low_second],
        ),
        stream(&b, vec![r_other_author]),
    ];
    let reference = fold(&fixture, &a, base_streams.clone()).map_err(|e| err(e.to_string()))?;
    assert!(
        reference.issues.is_empty(),
        "no event may survive: {:?}",
        reference.issues
    );
    assert_eq!(reference.max_admitted_lamport, 0);
    assert_some_reason_contains(&reference, "exceeds admitted maximum")?;
    assert_some_reason_contains(&reference, "truncated by a lamport rejection")?;

    // The fixpoint outcome must be order-independent too.
    let reference_json = serde_json::to_value(&reference)?;
    for seed in 0..5u64 {
        let mut streams = base_streams.clone();
        lcg_shuffle(&mut streams, seed);
        for s in &mut streams {
            lcg_shuffle(&mut s.records, seed.wrapping_add(3));
        }
        let shuffled = fold(&fixture, &a, streams).map_err(|e| err(e.to_string()))?;
        assert_eq!(
            serde_json::to_value(&shuffled)?,
            reference_json,
            "fixpoint diverged for shuffle seed {seed}"
        );
    }
    Ok(())
}

/// The reviewer's direct counterexample shape: two future-dated authors must
/// both be rejected — A's rejected lamport=100 contributes nothing, so
/// B's lamport=200 has no horizon to ride on.
#[test]
fn cross_author_future_dating_rejects_both_authors() -> TestResult {
    let a = Author::generate()?;
    let b = Author::generate()?;
    let fixture = make_genesis(&a, "list-l3", &[&a, &b])?;

    let mut chain_a = Chain::new(&a, &fixture);
    let (_, r_a) = chain_a.next(
        0,
        "i1",
        100,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let mut chain_b = Chain::new(&b, &fixture);
    let (_, r_b) = chain_b.next(
        0,
        "i2",
        200,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;

    let out = fold(
        &fixture,
        &a,
        vec![
            stream(&a, vec![fixture.genesis_record.clone(), r_a]),
            stream(&b, vec![r_b]),
        ],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(out.issues.is_empty());
    assert_eq!(out.max_admitted_lamport, 0);
    let lamport_rejections = rejection_reasons(&out)
        .iter()
        .filter(|r| r.contains("exceeds admitted maximum"))
        .count();
    assert_eq!(lamport_rejections, 2);
    Ok(())
}

// ---------------------------------------------------------------------------
// WP-B: dispatch approvals + consumes in the fold
// ---------------------------------------------------------------------------

/// Common WP-B scenario: creator opens i1, worker claims it, approver is a
/// roster member.
struct WpbScenario {
    fixture: ListFixture,
    creator: Author,
    worker: Author,
    approver: Author,
    creator_records: Vec<StoreRecord>,
    worker_records: Vec<StoreRecord>,
    worker_chain: (u64, String),
    open_hash: String,
    claim_hash: String,
    claim_nonce: String,
}

fn wpb_scenario(list: &str) -> TestResult<WpbScenario> {
    let creator = Author::generate()?;
    let worker = Author::generate()?;
    let approver = Author::generate()?;
    let fixture = make_genesis(&creator, list, &[&creator, &worker, &approver])?;
    let mut chain_c = Chain::new(&creator, &fixture);
    let (open_hash, r_open) = chain_c.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let mut chain_w = Chain::new(&worker, &fixture);
    let claim_nonce = "nonce-w".to_owned();
    let (claim_hash, r_claim) = chain_w.next(
        0,
        "i1",
        2,
        TransitionKind::Claim {
            claim_nonce: claim_nonce.clone(),
        },
    )?;
    Ok(WpbScenario {
        creator_records: vec![fixture.genesis_record.clone(), r_open],
        worker_records: vec![r_claim],
        worker_chain: (chain_w.seq, chain_w.prev.clone()),
        fixture,
        creator,
        worker,
        approver,
        open_hash,
        claim_hash,
        claim_nonce,
    })
}

fn fold_wpb(
    scenario: &WpbScenario,
    approver_records: Vec<StoreRecord>,
    extra_worker: Vec<StoreRecord>,
) -> TestResult<FoldOutput> {
    let mut worker_records = scenario.worker_records.clone();
    worker_records.extend(extra_worker);
    fold(
        &scenario.fixture,
        &scenario.creator,
        vec![
            stream(&scenario.creator, scenario.creator_records.clone()),
            stream(&scenario.worker, worker_records),
            stream(&scenario.approver, approver_records),
        ],
    )
    .map_err(|e| err(e.to_string()))
}

#[test]
fn valid_approval_folds_and_is_unconsumed() -> TestResult {
    let scenario = wpb_scenario("list-wb1")?;
    let mut chain_ap = Chain::new(&scenario.approver, &scenario.fixture);
    let (ap_hash, r_ap) = chain_ap.next_approval(
        0,
        "i1",
        3,
        &scenario.open_hash,
        ApprovalVerdictV2::Approve,
        100,
    )?;
    let out = fold_wpb(&scenario, vec![r_ap], vec![])?;
    assert!(out.approvals.contains_key(&ap_hash));
    let unconsumed = out.unconsumed_approvals("i1");
    assert_eq!(unconsumed.len(), 1);
    assert_eq!(unconsumed[0].event_hash, ap_hash);
    Ok(())
}

#[test]
fn ttl_is_not_a_fold_input_ancient_approval_still_folds() -> TestResult {
    let scenario = wpb_scenario("list-wb2")?;
    let mut chain_ap = Chain::new(&scenario.approver, &scenario.fixture);
    // approved_at = 1 (ancient). The fold must neither reject nor hide it —
    // TTL is gate-time policy only (design r2 C3).
    let (ap_hash, r_ap) = chain_ap.next_approval(
        0,
        "i1",
        3,
        &scenario.open_hash,
        ApprovalVerdictV2::Approve,
        1,
    )?;
    let out = fold_wpb(&scenario, vec![r_ap], vec![])?;
    assert!(out.approvals.contains_key(&ap_hash));
    assert_eq!(out.unconsumed_approvals("i1").len(), 1);
    Ok(())
}

#[test]
fn approval_admission_bindings_each_violated() -> TestResult {
    let scenario = wpb_scenario("list-wb3")?;

    // (1) Wrong record kind inside the signed payload.
    let bad_kind = ApprovalEventV2 {
        schema: V2_SCHEMA,
        kind: "approval".to_owned(),
        list_uuid: scenario.fixture.list_uuid.clone(),
        genesis_manifest_hash: scenario.fixture.genesis_hash.clone(),
        roster_epoch: 0,
        issue_id: "i1".to_owned(),
        open_event_hash: scenario.open_hash.clone(),
        actor: scenario.approver.id.clone(),
        lamport: 3,
        author_seq: 1,
        prev_own_event_hash: scenario.fixture.genesis_hash.clone(),
        verdict: ApprovalVerdictV2::Approve,
        entropy: "e".to_owned(),
        approved_at: 100,
        v1_record_json: String::new(),
    };
    let payload = bad_kind.to_signed_bytes().map_err(err)?;
    let hash = sha256_hex(&payload);
    let envelope = scenario
        .approver
        .sign_envelope(APPROVAL_CONTEXT_V2, &payload)?;
    let record = envelope_record(&approval_key("i1", &hash), &envelope)?;
    let out = fold_wpb(&scenario, vec![record], vec![])?;
    assert!(out.approvals.is_empty());
    assert_some_reason_contains(&out, "!= dispatch_approval")?;

    // (2) Approval read from the WRONG store (four-way binding).
    let mut chain_ap = Chain::new(&scenario.approver, &scenario.fixture);
    let (_, r_ap) = chain_ap.next_approval(
        0,
        "i1",
        3,
        &scenario.open_hash,
        ApprovalVerdictV2::Approve,
        100,
    )?;
    let mut creator_records = scenario.creator_records.clone();
    creator_records.push(r_ap);
    let out = fold(
        &scenario.fixture,
        &scenario.creator,
        vec![
            stream(&scenario.creator, creator_records),
            stream(&scenario.worker, scenario.worker_records.clone()),
            stream(&scenario.approver, vec![]),
        ],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(out.approvals.is_empty());
    assert_some_reason_contains(&out, "envelope signer")?;

    // (3) Non-roster approver.
    let outsider = Author::generate()?;
    let mut chain_out = Chain::new(&outsider, &scenario.fixture);
    let (_, r_out) = chain_out.next_approval(
        0,
        "i1",
        3,
        &scenario.open_hash,
        ApprovalVerdictV2::Approve,
        100,
    )?;
    let out = fold(
        &scenario.fixture,
        &scenario.creator,
        vec![
            stream(&scenario.creator, scenario.creator_records.clone()),
            stream(&scenario.worker, scenario.worker_records.clone()),
            stream(&outsider, vec![r_out]),
        ],
    )
    .map_err(|e| err(e.to_string()))?;
    assert!(out.approvals.is_empty());
    assert_some_reason_contains(&out, "is not a roster member")?;

    // (4) Wrong content address (key does not match payload hash).
    let mut chain_ap = Chain::new(&scenario.approver, &scenario.fixture);
    let (_, mut r_ap) = chain_ap.next_approval(
        0,
        "i1",
        3,
        &scenario.open_hash,
        ApprovalVerdictV2::Approve,
        100,
    )?;
    r_ap.key = approval_key("i1", &"0".repeat(64));
    let out = fold_wpb(&scenario, vec![r_ap], vec![])?;
    assert!(out.approvals.is_empty());
    assert_some_reason_contains(&out, "content address")?;
    Ok(())
}

#[test]
fn denial_hides_approvals_for_same_content() -> TestResult {
    let scenario = wpb_scenario("list-wb4")?;
    let mut chain_ap = Chain::new(&scenario.approver, &scenario.fixture);
    let (_, r_ok) = chain_ap.next_approval(
        0,
        "i1",
        3,
        &scenario.open_hash,
        ApprovalVerdictV2::Approve,
        100,
    )?;
    let (_, r_deny) = chain_ap.next_approval(
        0,
        "i1",
        4,
        &scenario.open_hash,
        ApprovalVerdictV2::Deny,
        101,
    )?;
    let out = fold_wpb(&scenario, vec![r_ok, r_deny], vec![])?;
    assert_eq!(out.approvals.len(), 2);
    assert!(out.unconsumed_approvals("i1").is_empty());
    Ok(())
}

#[test]
fn non_winner_consume_is_losing_and_winner_consume_is_effective() -> TestResult {
    let scenario = wpb_scenario("list-wb5")?;
    let mut chain_ap = Chain::new(&scenario.approver, &scenario.fixture);
    let (ap_hash, r_ap) = chain_ap.next_approval(
        0,
        "i1",
        3,
        &scenario.open_hash,
        ApprovalVerdictV2::Approve,
        100,
    )?;

    // The approver also claims (later; loses) and tries to consume fenced on
    // its own losing claim.
    let (loser_claim_hash, r_loser_claim) = chain_ap.next(
        0,
        "i1",
        4,
        TransitionKind::Claim {
            claim_nonce: "nonce-l".to_owned(),
        },
    )?;
    let (_, r_loser_consume) = chain_ap.next_consume(
        0,
        "i1",
        5,
        &ap_hash,
        &scenario.approver.id,
        "nonce-l",
        &loser_claim_hash,
    )?;

    // The fold-winning worker consumes with the correct fence.
    let mut chain_w = Chain {
        author: &scenario.worker,
        fixture_list: scenario.fixture.list_uuid.clone(),
        genesis_hash: scenario.fixture.genesis_hash.clone(),
        seq: scenario.worker_chain.0,
        prev: scenario.worker_chain.1.clone(),
    };
    let (win_hash, r_win_consume) = chain_w.next_consume(
        0,
        "i1",
        6,
        &ap_hash,
        &scenario.approver.id,
        &scenario.claim_nonce,
        &scenario.claim_hash,
    )?;

    let out = fold_wpb(
        &scenario,
        vec![r_ap, r_loser_claim, r_loser_consume],
        vec![r_win_consume],
    )?;
    // Loser surfaced, not effective; winner effective; approval consumed.
    let effective = out
        .effective_consumes
        .get(&ap_hash)
        .ok_or_else(|| err("no effective consume"))?;
    assert_eq!(effective.event_hash, win_hash);
    assert_eq!(effective.consume.actor, scenario.worker.id);
    assert_eq!(out.losing_consumes.len(), 1);
    assert!(out.losing_consumes[0].reason.contains("not fenced"));
    assert!(out.unconsumed_approvals("i1").is_empty());
    Ok(())
}

#[test]
fn duplicate_consumes_resolve_deterministically_with_loser_flagged() -> TestResult {
    let scenario = wpb_scenario("list-wb6")?;
    let mut chain_ap = Chain::new(&scenario.approver, &scenario.fixture);
    let (ap_hash, r_ap) = chain_ap.next_approval(
        0,
        "i1",
        3,
        &scenario.open_hash,
        ApprovalVerdictV2::Approve,
        100,
    )?;
    let mut chain_w = Chain {
        author: &scenario.worker,
        fixture_list: scenario.fixture.list_uuid.clone(),
        genesis_hash: scenario.fixture.genesis_hash.clone(),
        seq: scenario.worker_chain.0,
        prev: scenario.worker_chain.1.clone(),
    };
    let (first_hash, r_c1) = chain_w.next_consume(
        0,
        "i1",
        4,
        &ap_hash,
        &scenario.approver.id,
        &scenario.claim_nonce,
        &scenario.claim_hash,
    )?;
    let (second_hash, r_c2) = chain_w.next_consume(
        0,
        "i1",
        5,
        &ap_hash,
        &scenario.approver.id,
        &scenario.claim_nonce,
        &scenario.claim_hash,
    )?;

    let base = (vec![r_ap], vec![r_c1, r_c2]);
    let reference = fold_wpb(&scenario, base.0.clone(), base.1.clone())?;
    let effective = reference
        .effective_consumes
        .get(&ap_hash)
        .ok_or_else(|| err("no effective consume"))?;
    // Fold order: lamport 4 before 5 — the first consume wins.
    assert_eq!(effective.event_hash, first_hash);
    assert_eq!(reference.losing_consumes.len(), 1);
    assert_eq!(reference.losing_consumes[0].event_hash, second_hash);
    assert!(reference.losing_consumes[0]
        .reason
        .contains("already consumed"));

    // Shuffled input order agrees.
    let reference_json = serde_json::to_value(&reference)?;
    let shuffled = fold_wpb(&scenario, base.0, {
        let mut v = base.1;
        v.reverse();
        v
    })?;
    assert_eq!(serde_json::to_value(&shuffled)?, reference_json);
    Ok(())
}

#[test]
fn consume_of_unknown_approval_is_losing() -> TestResult {
    let scenario = wpb_scenario("list-wb7")?;
    let mut chain_w = Chain {
        author: &scenario.worker,
        fixture_list: scenario.fixture.list_uuid.clone(),
        genesis_hash: scenario.fixture.genesis_hash.clone(),
        seq: scenario.worker_chain.0,
        prev: scenario.worker_chain.1.clone(),
    };
    let (_, r_consume) = chain_w.next_consume(
        0,
        "i1",
        4,
        &"9".repeat(64),
        &scenario.approver.id,
        &scenario.claim_nonce,
        &scenario.claim_hash,
    )?;
    let out = fold_wpb(&scenario, vec![], vec![r_consume])?;
    assert!(out.effective_consumes.is_empty());
    assert_eq!(out.losing_consumes.len(), 1);
    assert!(out.losing_consumes[0].reason.contains("unknown"));
    Ok(())
}

/// Codex blocker 3 regression: duplicate streams claiming one owner with
/// DIFFERENT card-self values must fold identically in both input orders —
/// the owner is rejected as conflicted (no pick-one rule), and a creator
/// conflict refuses the whole list.
#[test]
fn conflicting_card_self_rejects_owner_order_independently() -> TestResult {
    let creator = Author::generate()?;
    let member = Author::generate()?;
    let imposter = Author::generate()?; // source of the second key bytes
    let fixture = make_genesis(&creator, "list-cardconflict", &[&creator, &member])?;

    let mut creator_chain = Chain::new(&creator, &fixture);
    let (_open_hash, open) = creator_chain.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let mut member_chain = Chain::new(&member, &fixture);
    let (_claim_hash, claim) = member_chain.next(
        0,
        "i1",
        2,
        TransitionKind::Claim {
            claim_nonce: "n1".to_owned(),
        },
    )?;

    let genuine = stream(&member, vec![claim]);
    // Same owner id, different self-card bytes (an anomaly no deterministic
    // rule can bind): the fold must reject the owner outright.
    let conflicting = AuthorStream {
        owner: member.id.clone(),
        card_self: Some(imposter.pk.clone()),
        records: vec![StoreRecord {
            key: CARD_SELF_KEY.to_owned(),
            value: imposter.pk.clone(),
        }],
    };

    let creator_stream = stream(&creator, vec![fixture.genesis_record.clone(), open]);
    let forward = fold(
        &fixture,
        &creator,
        vec![creator_stream.clone(), genuine.clone(), conflicting.clone()],
    )
    .map_err(|e| err(format!("{e}")))?;
    let reverse = fold(
        &fixture,
        &creator,
        vec![conflicting.clone(), genuine.clone(), creator_stream],
    )
    .map_err(|e| err(format!("{e}")))?;

    assert_eq!(
        forward, reverse,
        "fold output must be stream-order-independent"
    );
    assert!(
        matches!(status_of(&forward, "i1")?, IssueStatusV2::Open),
        "the conflicted owner's claim must not take effect"
    );
    assert_some_reason_contains(&forward, "conflicting card-self")?;

    // Creator conflict: the entire list is refused, both orders.
    let creator_conflicting = AuthorStream {
        owner: creator.id.clone(),
        card_self: Some(imposter.pk.clone()),
        records: Vec::new(),
    };
    let creator_stream = stream(&creator, vec![fixture.genesis_record.clone()]);
    for streams in [
        vec![creator_stream.clone(), creator_conflicting.clone()],
        vec![creator_conflicting, creator_stream],
    ] {
        let refused = fold(&fixture, &creator, streams);
        assert!(
            matches!(&refused, Err(ListRefusal::InvalidGenesis(reason)) if reason.contains("card-self conflict")),
            "creator card conflict must refuse the list, got {refused:?}"
        );
    }
    Ok(())
}

/// Codex blocker 4 regression: a consume whose approval carries a LATER
/// fold position (higher lamport) is still effective — approvals are an
/// order-independent set collected before the ordered walk.
#[test]
fn consume_is_effective_when_its_approval_orders_later_in_fold() -> TestResult {
    let creator = Author::generate()?;
    let worker = Author::generate()?;
    let approver = Author::generate()?;
    let fixture = make_genesis(
        &creator,
        "list-late-approval",
        &[&creator, &worker, &approver],
    )?;

    let mut creator_chain = Chain::new(&creator, &fixture);
    let (open_hash, open) = creator_chain.next(
        0,
        "i1",
        1,
        TransitionKind::open("t".to_owned(), "s".to_owned()),
    )?;
    let mut worker_chain = Chain::new(&worker, &fixture);
    let (claim_hash, claim) = worker_chain.next(
        0,
        "i1",
        2,
        TransitionKind::Claim {
            claim_nonce: "n1".to_owned(),
        },
    )?;
    // Approval at lamport 10 — AFTER the consume's fold position (3).
    let mut approver_chain = Chain::new(&approver, &fixture);
    let (approval_hash, approval) =
        approver_chain.next_approval(0, "i1", 10, &open_hash, ApprovalVerdictV2::Approve, 1_000)?;
    let (consume_hash, consume) =
        worker_chain.next_consume(0, "i1", 3, &approval_hash, &approver.id, "n1", &claim_hash)?;

    let base_streams = || {
        vec![
            stream(&creator, vec![fixture.genesis_record.clone(), open.clone()]),
            stream(&worker, vec![claim.clone(), consume.clone()]),
            stream(&approver, vec![approval.clone()]),
        ]
    };
    let out = fold(&fixture, &creator, base_streams()).map_err(|e| err(format!("{e}")))?;
    assert!(
        out.effective_consumes
            .get(&approval_hash)
            .is_some_and(|c| c.event_hash == consume_hash),
        "the consume must be effective even though its approval folds later; \
         losing: {:?}",
        out.losing_consumes
    );
    assert!(out.losing_consumes.is_empty());

    // Shuffle determinism across stream orders.
    for seed in 0..6u64 {
        let mut streams = base_streams();
        lcg_shuffle(&mut streams, seed);
        let shuffled = fold(&fixture, &creator, streams).map_err(|e| err(format!("{e}")))?;
        assert_eq!(shuffled, out, "seed {seed} disagreed");
    }
    Ok(())
}

/// Codex round-3 item 1: resource budgets are FAIL-CLOSED — every violation
/// refuses the list outright (never partial processing).
#[test]
fn budget_violations_refuse_the_list() -> TestResult {
    let creator = Author::generate()?;
    let fixture = make_genesis(&creator, "list-budget", &[&creator])?;
    let tiny = FoldLimits {
        max_roster_members: 2,
        max_records_per_stream: 3,
        max_record_bytes: 64 * 1024,
    };
    let fold_limited = |streams: Vec<AuthorStream>, limits: FoldLimits| {
        fold_v2(&FoldInput {
            list_uuid: fixture.list_uuid.clone(),
            creator: creator.id.clone(),
            streams,
            limits,
        })
    };

    // (a) genesis roster over budget.
    let wide: Vec<Author> = (0..3)
        .map(|_| Author::generate())
        .collect::<Result<_, _>>()?;
    let wide_refs: Vec<&Author> = wide.iter().collect();
    let big_fixture = make_genesis(&creator, "list-budget", &wide_refs)?;
    let refused = fold_v2(&FoldInput {
        list_uuid: big_fixture.list_uuid.clone(),
        creator: creator.id.clone(),
        streams: vec![stream(&creator, vec![big_fixture.genesis_record.clone()])],
        limits: tiny,
    });
    assert!(
        matches!(&refused, Err(ListRefusal::BudgetExceeded(r)) if r.contains("genesis roster")),
        "genesis roster over budget must refuse, got {refused:?}"
    );

    // (b) records per stream over budget (card-self + genesis + 3 events = 5 > 3).
    let mut chain = Chain::new(&creator, &fixture);
    let mut records = vec![fixture.genesis_record.clone()];
    for (i, issue) in ["i1", "i2", "i3"].iter().enumerate() {
        let (_, rec) = chain.next(
            0,
            issue,
            (i + 1) as u64,
            TransitionKind::open("t".to_owned(), "s".to_owned()),
        )?;
        records.push(rec);
    }
    let refused = fold_limited(vec![stream(&creator, records)], tiny);
    assert!(
        matches!(&refused, Err(ListRefusal::BudgetExceeded(r)) if r.contains("records")),
        "stream record count over budget must refuse, got {refused:?}"
    );

    // (c) single record value over the byte budget.
    let tiny_bytes = FoldLimits {
        max_record_bytes: 16,
        ..tiny
    };
    let refused = fold_limited(
        vec![stream(&creator, vec![fixture.genesis_record.clone()])],
        tiny_bytes,
    );
    assert!(
        matches!(&refused, Err(ListRefusal::BudgetExceeded(r)) if r.contains("bytes")),
        "record over the byte budget must refuse, got {refused:?}"
    );

    // (d) creator-signed roster UPDATE over budget.
    let update = RosterEventV2 {
        schema: V2_SCHEMA,
        kind: "roster".to_owned(),
        list_uuid: fixture.list_uuid.clone(),
        genesis_manifest_hash: fixture.genesis_hash.clone(),
        roster_epoch: 1,
        prev_roster_hash: fixture.genesis_hash.clone(),
        roster: vec![creator.id.clone(), "a".repeat(64), "b".repeat(64)],
        actor: creator.id.clone(),
    };
    let payload = serde_json::to_vec(&update)?;
    let hash = sha256_hex(&payload);
    let envelope = creator.sign_envelope(ROSTER_CONTEXT_V2, &payload)?;
    let record = envelope_record(&roster_key(1, &hash), &envelope)?;
    let refused = fold_limited(
        vec![stream(
            &creator,
            vec![fixture.genesis_record.clone(), record],
        )],
        tiny,
    );
    assert!(
        matches!(&refused, Err(ListRefusal::BudgetExceeded(r)) if r.contains("roster update")),
        "roster update over budget must refuse, got {refused:?}"
    );
    Ok(())
}
