//! WP-B gate tests: consume-then-execute over an in-memory daemon double
//! (the v2 analogue of v0.1.3's mock-crypto orchestrator gate tests).
//!
//! The double honors the append-only contract (PUT to an existing key →
//! 409) and supports staging "concurrently arriving" peer records that
//! become visible only after the local consume is written — the live
//! partition-heal race, deterministically reproduced.

use std::{collections::BTreeMap, error::Error, sync::Arc};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use reqwest::StatusCode;
use saorsa_pqc::{MlDsa65, MlDsaOperations, MlDsaSecretKey};
use tokio::sync::Mutex;
use x0x_symphony_core::sha256_hex;
use x0x_symphony_signing::{AgentInfo, SignResponse, SigningClient, SigningError, VerifyOutcome};
use x0x_symphony_tracker_x0x_crdt::v2::events::GenesisPolicy;
use x0x_symphony_tracker_x0x_crdt::{
    client::{ClientError, KvKeyEntry, KvValue, StoreCreateOutcome, StoreDetailEntry},
    v2::{
        events::{
            approval_key, event_key, event_store_topic, APPROVAL_CONTEXT_V2, CARD_SELF_KEY,
            GENESIS_CONTEXT_V2, GENESIS_KEY, TRANSITION_CONTEXT_V2,
        },
        fold_v2,
        gate::build_claim_transition,
        identity::{assemble_external_dst, derive_agent_id_hex},
        ApprovalEventV2, ApprovalVerdictV2, EventEnvelope, GenesisManifestV2, StorePolicyMode,
        TransitionEventV2, TransitionKind, V2ApprovalGate, V2GateConfig, V2GateDecision,
        V2StoreApi, V2StoreManager, V2_SCHEMA,
    },
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn err(msg: impl Into<String>) -> Box<dyn Error> {
    Box::new(std::io::Error::other(msg.into()))
}

// ---------------------------------------------------------------------------
// Signing fixtures
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
        Ok(Self {
            id: derive_agent_id_hex(&pk),
            pk,
            sk,
        })
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

/// `SigningClient` backed by a local ML-DSA-65 keypair (the mock-crypto
/// pattern: real signatures, no daemon).
struct LocalSigner {
    author: Arc<Author>,
}

#[async_trait]
impl SigningClient for LocalSigner {
    async fn sign(
        &self,
        context: &str,
        payload: &[u8],
    ) -> std::result::Result<SignResponse, SigningError> {
        let canonical = assemble_external_dst(context, payload);
        let sig = MlDsa65::new()
            .sign(&self.author.sk, &canonical)
            .map_err(|e| SigningError::InvalidResponse(format!("{e}")))?;
        Ok(SignResponse {
            agent_id: self.author.id.clone(),
            public_key_b64: BASE64.encode(&self.author.pk),
            signature_b64: BASE64.encode(sig.as_bytes()),
            algorithm: "x0x.agent-sign.v2.ml-dsa-65".to_owned(),
            context: context.to_owned(),
        })
    }

    async fn verify(
        &self,
        _context: &str,
        _payload: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
    ) -> std::result::Result<VerifyOutcome, SigningError> {
        Ok(VerifyOutcome::Valid)
    }

    async fn agent_identity(&self) -> std::result::Result<AgentInfo, SigningError> {
        Ok(AgentInfo {
            agent_id: self.author.id.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// In-memory daemon double
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockDaemon {
    kv: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    /// Records that become visible only after the first consume (`cs-*`)
    /// write — simulates a partition healing right as we consume.
    staged: Mutex<Vec<(String, String, Vec<u8>)>>,
}

impl MockDaemon {
    async fn seed(&self, topic: &str, key: &str, value: Vec<u8>) {
        self.kv
            .lock()
            .await
            .insert((topic.to_owned(), key.to_owned()), value);
    }

    async fn stage(&self, topic: &str, key: &str, value: Vec<u8>) {
        self.staged
            .lock()
            .await
            .push((topic.to_owned(), key.to_owned(), value));
    }

    async fn count_keys_with_prefix(&self, topic: &str, prefix: &str) -> usize {
        self.kv
            .lock()
            .await
            .keys()
            .filter(|(t, k)| t == topic && k.starts_with(prefix))
            .count()
    }
}

#[async_trait]
impl V2StoreApi for MockDaemon {
    async fn create_kv_store_with_policy(
        &self,
        _name: &str,
        topic: &str,
        policy: Option<&str>,
    ) -> std::result::Result<StoreCreateOutcome, ClientError> {
        Ok(StoreCreateOutcome {
            id: topic.to_owned(),
            policy: policy.map(str::to_owned),
        })
    }

    async fn join_kv_store(
        &self,
        _topic: &str,
        _expected_owner: &str,
    ) -> std::result::Result<(), ClientError> {
        Ok(())
    }

    async fn kv_store_detail(
        &self,
        topic: &str,
    ) -> std::result::Result<Option<StoreDetailEntry>, ClientError> {
        Ok(Some(StoreDetailEntry {
            id: topic.to_owned(),
            owner: None,
            policy: Some("append_only".to_owned()),
        }))
    }

    async fn list_kv_keys(&self, topic: &str) -> std::result::Result<Vec<KvKeyEntry>, ClientError> {
        let kv = self.kv.lock().await;
        Ok(kv
            .keys()
            .filter(|(t, _)| t == topic)
            .map(|(_, key)| KvKeyEntry {
                key: key.clone(),
                content_type: None,
                content_hash: None,
                size: 0,
                updated_at: None,
            })
            .collect())
    }

    async fn get_kv(
        &self,
        topic: &str,
        key: &str,
    ) -> std::result::Result<Option<KvValue>, ClientError> {
        let kv = self.kv.lock().await;
        Ok(kv
            .get(&(topic.to_owned(), key.to_owned()))
            .map(|value| KvValue {
                key: key.to_owned(),
                value: value.clone(),
                content_type: None,
                content_hash: None,
                created_at: None,
                updated_at: None,
            }))
    }

    async fn put_kv(
        &self,
        topic: &str,
        key: &str,
        value: &[u8],
        _content_type: &str,
    ) -> std::result::Result<(), ClientError> {
        {
            let mut kv = self.kv.lock().await;
            let entry = (topic.to_owned(), key.to_owned());
            if kv.contains_key(&entry) {
                // Append-only: PUT to an existing key is refused (WP-X).
                return Err(ClientError::Http {
                    status: StatusCode::CONFLICT,
                    body: "append_only: key exists".to_owned(),
                });
            }
            kv.insert(entry, value.to_vec());
        }
        if key.starts_with("cs-") {
            // Release "concurrently arriving" peer records.
            let staged: Vec<_> = self.staged.lock().await.drain(..).collect();
            let mut kv = self.kv.lock().await;
            for (t, k, v) in staged {
                kv.insert((t, k), v);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Scenario setup
// ---------------------------------------------------------------------------

struct GateWorld {
    daemon: Arc<MockDaemon>,
    manager: V2StoreManager,
    creator: Author,
    approver: Author,
    list_uuid: String,
    genesis_hash: String,
    open_hash: String,
    issue_id: String,
    approver_seq: u64,
    approver_prev: String,
}

impl GateWorld {
    /// Build: creator store (card-self + genesis + open i1), approver store
    /// (card-self), own store bound via the manager; roster = all three plus
    /// an optional extra member.
    async fn new(list_uuid: &str, extra_member: Option<&Author>) -> TestResult<Self> {
        let daemon = Arc::new(MockDaemon::default());
        let me = Arc::new(Author::generate()?);
        let creator = Author::generate()?;
        let approver = Author::generate()?;

        let mut roster = vec![creator.id.clone(), me.id.clone(), approver.id.clone()];
        if let Some(extra) = extra_member {
            roster.push(extra.id.clone());
        }
        let manifest = GenesisManifestV2 {
            schema: V2_SCHEMA,
            kind: "genesis".to_owned(),
            list_uuid: list_uuid.to_owned(),
            creator: creator.id.clone(),
            roster,
            policy: GenesisPolicy::default(),
            created_at: 1,
        };
        let genesis_payload = serde_json::to_vec(&manifest)?;
        let genesis_hash = sha256_hex(&genesis_payload);
        let genesis_env = creator.sign_envelope(GENESIS_CONTEXT_V2, &genesis_payload)?;

        let issue_id = "i1".to_owned();
        let open = TransitionEventV2 {
            schema: V2_SCHEMA,
            list_uuid: list_uuid.to_owned(),
            genesis_manifest_hash: genesis_hash.clone(),
            roster_epoch: 0,
            issue_id: issue_id.clone(),
            actor: creator.id.clone(),
            lamport: 1,
            author_seq: 1,
            prev_own_event_hash: genesis_hash.clone(),
            kind: TransitionKind::Open {
                title: "t".to_owned(),
                spec: "s".to_owned(),
            },
        };
        let open_payload = open.to_signed_bytes().map_err(err)?;
        let open_hash = sha256_hex(&open_payload);
        let open_env = creator.sign_envelope(TRANSITION_CONTEXT_V2, &open_payload)?;

        let creator_topic = event_store_topic(list_uuid, &creator.id);
        daemon
            .seed(&creator_topic, CARD_SELF_KEY, creator.pk.clone())
            .await;
        daemon
            .seed(
                &creator_topic,
                GENESIS_KEY,
                genesis_env.encode().map_err(err)?,
            )
            .await;
        daemon
            .seed(
                &creator_topic,
                &event_key(&issue_id, &open_hash),
                open_env.encode().map_err(err)?,
            )
            .await;

        let approver_topic = event_store_topic(list_uuid, &approver.id);
        daemon
            .seed(&approver_topic, CARD_SELF_KEY, approver.pk.clone())
            .await;

        let signer: Arc<dyn SigningClient> = Arc::new(LocalSigner {
            author: Arc::clone(&me),
        });
        let manager = V2StoreManager::new(
            Arc::clone(&daemon) as Arc<dyn V2StoreApi>,
            signer,
            StorePolicyMode::AppendOnly,
        );

        Ok(Self {
            daemon,
            manager,
            creator,
            approver,
            list_uuid: list_uuid.to_owned(),
            genesis_hash: genesis_hash.clone(),
            open_hash,
            issue_id,
            approver_seq: 0,
            approver_prev: genesis_hash,
        })
    }

    fn approval_event(&mut self, verdict: ApprovalVerdictV2, approved_at: u64) -> ApprovalEventV2 {
        self.approver_seq += 1;
        ApprovalEventV2 {
            schema: V2_SCHEMA,
            kind: "dispatch_approval".to_owned(),
            list_uuid: self.list_uuid.clone(),
            genesis_manifest_hash: self.genesis_hash.clone(),
            roster_epoch: 0,
            issue_id: self.issue_id.clone(),
            open_event_hash: self.open_hash.clone(),
            actor: self.approver.id.clone(),
            lamport: 10 + self.approver_seq,
            author_seq: self.approver_seq,
            prev_own_event_hash: self.approver_prev.clone(),
            verdict,
            entropy: format!("approver-entropy-{}", self.approver_seq),
            approved_at,
        }
    }

    /// Sign + seed one approver record and advance the approver chain.
    async fn publish_approval(
        &mut self,
        verdict: ApprovalVerdictV2,
        approved_at: u64,
    ) -> TestResult<String> {
        let event = self.approval_event(verdict, approved_at);
        let payload = event.to_signed_bytes().map_err(err)?;
        let hash = sha256_hex(&payload);
        let envelope = self.approver.sign_envelope(APPROVAL_CONTEXT_V2, &payload)?;
        let topic = event_store_topic(&self.list_uuid, &self.approver.id);
        self.daemon
            .seed(
                &topic,
                &approval_key(&self.issue_id, &hash),
                envelope.encode().map_err(err)?,
            )
            .await;
        self.approver_prev.clone_from(&hash);
        Ok(hash)
    }

    /// Bind the own store and claim the issue through the manager.
    async fn setup_own_claim(
        &self,
    ) -> TestResult<x0x_symphony_tracker_x0x_crdt::v2::OwnEventStore> {
        let own = self.manager.ensure_own_store(&self.list_uuid).await?;
        let input = self
            .manager
            .read_fold_input(&self.list_uuid, &self.creator.id)
            .await?;
        let out = fold_v2(&input).map_err(|e| err(e.to_string()))?;
        let claim = build_claim_transition(&out, &self.list_uuid, &own.agent_id, &self.issue_id);
        self.manager.append_transition(&own, &claim).await?;
        Ok(own)
    }

    fn gate_config() -> V2GateConfig {
        V2GateConfig {
            approval_ttl_secs: 3600,
            settle: std::time::Duration::ZERO,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn happy_path_consumes_exactly_once() -> TestResult {
    let mut world = GateWorld::new("gate-happy", None).await?;
    let ap_hash = world
        .publish_approval(ApprovalVerdictV2::Approve, 1_000)
        .await?;
    let own = world.setup_own_claim().await?;

    let gate = V2ApprovalGate::new(&world.manager, GateWorld::gate_config());
    let decision = gate
        .evaluate_and_consume(&own, &world.creator.id, &world.issue_id, 1_100, "seed-1")
        .await?;
    let V2GateDecision::Proceed {
        approval_event_hash,
        ..
    } = decision
    else {
        return Err(err(format!("expected Proceed, got {decision:?}")));
    };
    assert_eq!(approval_event_hash, ap_hash);

    // Exactly-once: a second evaluation must NOT re-dispatch.
    let second = gate
        .evaluate_and_consume(&own, &world.creator.id, &world.issue_id, 1_101, "seed-2")
        .await?;
    assert_eq!(second, V2GateDecision::PendingApproval);
    assert_eq!(
        world.daemon.count_keys_with_prefix(&own.topic, "cs-").await,
        1,
        "exactly one durable consume record"
    );
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One deterministic partition-heal narrative.
async fn competing_consume_after_partition_heal_aborts_without_executing() -> TestResult {
    let competitor = Author::generate()?;
    let mut world = GateWorld::new("gate-race", Some(&competitor)).await?;
    let ap_hash = world
        .publish_approval(ApprovalVerdictV2::Approve, 1_000)
        .await?;
    let own = world.setup_own_claim().await?;

    // The competitor — in the other partition — claimed EARLIER: its claim
    // sits at lamport 2 (right after the open at 1), while ours lands at 12
    // (the approval seeded above pushed the local horizon to 11). Its
    // consume sits at lamport 15: after the approval (11) so the approval is
    // admitted by then, and after both claims, so it is fenced by the
    // fold-winning (competitor's) claim. Our consume (13) is unfenced at its
    // position — the competitor's is the effective one once visible.
    let comp_topic = event_store_topic(&world.list_uuid, &competitor.id);
    let comp_claim = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: world.list_uuid.clone(),
        genesis_manifest_hash: world.genesis_hash.clone(),
        roster_epoch: 0,
        issue_id: world.issue_id.clone(),
        actor: competitor.id.clone(),
        lamport: 2,
        author_seq: 1,
        prev_own_event_hash: world.genesis_hash.clone(),
        kind: TransitionKind::Claim {
            claim_nonce: "nonce-comp".to_owned(),
        },
    };
    let claim_payload = comp_claim.to_signed_bytes().map_err(err)?;
    let comp_claim_hash = sha256_hex(&claim_payload);
    let claim_env = competitor.sign_envelope(TRANSITION_CONTEXT_V2, &claim_payload)?;

    let comp_consume = x0x_symphony_tracker_x0x_crdt::v2::ConsumeEventV2 {
        schema: V2_SCHEMA,
        kind: "consume".to_owned(),
        list_uuid: world.list_uuid.clone(),
        genesis_manifest_hash: world.genesis_hash.clone(),
        roster_epoch: 0,
        issue_id: world.issue_id.clone(),
        actor: competitor.id.clone(),
        lamport: 15,
        author_seq: 2,
        prev_own_event_hash: comp_claim_hash.clone(),
        approval_event_hash: ap_hash.clone(),
        approval_payload_sha256: ap_hash.clone(),
        approver: world.approver.id.clone(),
        claim_nonce: "nonce-comp".to_owned(),
        claimed_event_hash: comp_claim_hash.clone(),
        entropy: "comp-entropy".to_owned(),
    };
    let consume_payload = comp_consume.to_signed_bytes().map_err(err)?;
    let comp_consume_hash = sha256_hex(&consume_payload);
    let consume_env = competitor.sign_envelope(
        x0x_symphony_tracker_x0x_crdt::v2::events::CONSUME_CONTEXT_V2,
        &consume_payload,
    )?;

    // Stage: card-self + claim + consume become visible only after OUR
    // consume is written (partition heals mid-gate).
    world
        .daemon
        .stage(&comp_topic, CARD_SELF_KEY, competitor.pk.clone())
        .await;
    world
        .daemon
        .stage(
            &comp_topic,
            &event_key(&world.issue_id, &comp_claim_hash),
            claim_env.encode().map_err(err)?,
        )
        .await;
    world
        .daemon
        .stage(
            &comp_topic,
            &x0x_symphony_tracker_x0x_crdt::v2::events::consume_key(
                &world.issue_id,
                &comp_consume_hash,
            ),
            consume_env.encode().map_err(err)?,
        )
        .await;

    let gate = V2ApprovalGate::new(&world.manager, GateWorld::gate_config());
    let decision = gate
        .evaluate_and_consume(&own, &world.creator.id, &world.issue_id, 1_100, "seed-1")
        .await?;
    match decision {
        V2GateDecision::AbortCompetingConsume {
            approval_event_hash,
            winner_author,
            winner_event_hash,
        } => {
            assert_eq!(approval_event_hash, ap_hash);
            assert_eq!(winner_author, competitor.id);
            assert_eq!(winner_event_hash, comp_consume_hash);
        }
        other => {
            return Err(err(format!(
                "expected AbortCompetingConsume, got {other:?}"
            )))
        }
    }

    // The final fold agrees: competitor's consume effective, ours losing.
    let input = world
        .manager
        .read_fold_input(&world.list_uuid, &world.creator.id)
        .await?;
    let out = fold_v2(&input).map_err(|e| err(e.to_string()))?;
    let effective = out
        .effective_consumes
        .get(&ap_hash)
        .ok_or_else(|| err("no effective consume"))?;
    assert_eq!(effective.consume.actor, competitor.id);
    assert_eq!(out.losing_consumes.len(), 1);
    assert_eq!(out.losing_consumes[0].author, own.agent_id);
    Ok(())
}

#[tokio::test]
async fn crash_after_consume_recovers_via_reapproval() -> TestResult {
    let mut world = GateWorld::new("gate-crash", None).await?;
    let first_ap = world
        .publish_approval(ApprovalVerdictV2::Approve, 1_000)
        .await?;
    let own = world.setup_own_claim().await?;

    let gate = V2ApprovalGate::new(&world.manager, GateWorld::gate_config());
    let first = gate
        .evaluate_and_consume(&own, &world.creator.id, &world.issue_id, 1_100, "seed-1")
        .await?;
    assert!(matches!(first, V2GateDecision::Proceed { .. }));
    // CRASH here: the approval is spent, nothing executed (fail toward
    // zero). Re-evaluation must NOT grant a second execution...
    let after_crash = gate
        .evaluate_and_consume(&own, &world.creator.id, &world.issue_id, 1_101, "seed-2")
        .await?;
    assert_eq!(after_crash, V2GateDecision::PendingApproval);

    // ...until the operator re-approves.
    let second_ap = world
        .publish_approval(ApprovalVerdictV2::Approve, 1_200)
        .await?;
    let gate = V2ApprovalGate::new(&world.manager, GateWorld::gate_config());
    let recovered = gate
        .evaluate_and_consume(&own, &world.creator.id, &world.issue_id, 1_300, "seed-3")
        .await?;
    let V2GateDecision::Proceed {
        approval_event_hash,
        ..
    } = recovered
    else {
        return Err(err(format!("expected Proceed, got {recovered:?}")));
    };
    assert_eq!(approval_event_hash, second_ap);
    assert_ne!(second_ap, first_ap);

    // One effective consume per approval, ever.
    let input = world
        .manager
        .read_fold_input(&world.list_uuid, &world.creator.id)
        .await?;
    let out = fold_v2(&input).map_err(|e| err(e.to_string()))?;
    assert_eq!(out.effective_consumes.len(), 2);
    assert!(out.effective_consumes.contains_key(&first_ap));
    assert!(out.effective_consumes.contains_key(&second_ap));
    assert!(out.losing_consumes.is_empty());
    Ok(())
}

#[tokio::test]
async fn expired_approval_folds_but_gate_refuses() -> TestResult {
    let mut world = GateWorld::new("gate-ttl", None).await?;
    world
        .publish_approval(ApprovalVerdictV2::Approve, 1_000)
        .await?;
    let own = world.setup_own_claim().await?;

    // TTL 3600, approved at 1_000, now 10_000 → expired at the gate.
    let gate = V2ApprovalGate::new(&world.manager, GateWorld::gate_config());
    let decision = gate
        .evaluate_and_consume(&own, &world.creator.id, &world.issue_id, 10_000, "seed-1")
        .await?;
    assert_eq!(decision, V2GateDecision::PendingApproval);

    // C3: the expired approval still folds and is still unconsumed.
    let input = world
        .manager
        .read_fold_input(&world.list_uuid, &world.creator.id)
        .await?;
    let out = fold_v2(&input).map_err(|e| err(e.to_string()))?;
    assert_eq!(out.approvals.len(), 1);
    assert_eq!(out.unconsumed_approvals(&world.issue_id).len(), 1);
    assert!(out.effective_consumes.is_empty());
    Ok(())
}

#[tokio::test]
async fn denial_blocks_and_non_winner_cannot_consume() -> TestResult {
    let mut world = GateWorld::new("gate-deny", None).await?;
    world
        .publish_approval(ApprovalVerdictV2::Approve, 1_000)
        .await?;
    world
        .publish_approval(ApprovalVerdictV2::Deny, 1_001)
        .await?;
    let own = world.setup_own_claim().await?;

    let gate = V2ApprovalGate::new(&world.manager, GateWorld::gate_config());
    let decision = gate
        .evaluate_and_consume(&own, &world.creator.id, &world.issue_id, 1_100, "seed-1")
        .await?;
    assert_eq!(decision, V2GateDecision::Denied);

    // Without a claim at all (fresh world), the gate refuses to consume.
    let mut world2 = GateWorld::new("gate-nowin", None).await?;
    world2
        .publish_approval(ApprovalVerdictV2::Approve, 1_000)
        .await?;
    let own2 = world2.manager.ensure_own_store(&world2.list_uuid).await?;
    let gate2 = V2ApprovalGate::new(&world2.manager, GateWorld::gate_config());
    let decision2 = gate2
        .evaluate_and_consume(&own2, &world2.creator.id, &world2.issue_id, 1_100, "seed-1")
        .await?;
    assert_eq!(decision2, V2GateDecision::NotClaimWinner);
    Ok(())
}
