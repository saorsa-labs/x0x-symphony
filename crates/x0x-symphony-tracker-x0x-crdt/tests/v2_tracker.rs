//! WP-B2 tests: the v2 `Tracker` surface driven through the REAL
//! `x0x_symphony_core::Tracker` trait over an in-memory daemon double.
//!
//! Two families:
//!
//! - **v2-specific**: open→claim→handoff→complete happy path, blocked/
//!   requeue driving the C6 gate, deterministic claim-race resolution,
//!   the approval bridge (store/load round-trip), and consume-then-confirm
//!   failing closed under a divergent-claim heal.
//! - **parity**: the same orchestration scenarios (claim/heartbeat/release,
//!   block/requeue, handoff→review), written once against `&dyn Tracker`
//!   and executed on BOTH the v1 tracker (in-memory x0xd double) and the
//!   v2 tracker (in-memory store double). Behavior at the trait surface
//!   must agree — that is what lets the orchestrator stay adapter-neutral.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use reqwest::StatusCode;
use saorsa_pqc::{MlDsa65, MlDsaOperations, MlDsaSecretKey};
use tokio::sync::Mutex;

use x0x_symphony_core::{
    content_hash, sha256_hex, AgentId, ApprovalEvent, ApprovalVerdict, Handoff, IssueId,
    IssueState, PollContext, ReleaseReason, ReleaseReasonCode, SignatureEnvelope, Tracker,
    ValidationResult, ValidationStatus,
};
use x0x_symphony_signing::{AgentInfo, SignResponse, SigningClient, SigningError, VerifyOutcome};
use x0x_symphony_tracker_x0x_crdt::{
    client::{
        AddTaskDraft, ClientError, EventStream, JoinedGroup, KvKeyEntry, KvValue,
        NamedGroupDetails, NamedGroupEntry, StoreCreateOutcome, StoreDetailEntry, TaskAction,
        TaskEntry, TaskListEntry, X0xdApi,
    },
    v2::{
        events::{
            approval_key, event_key, event_store_topic, ApprovalEventV2, ApprovalVerdictV2,
            EventEnvelope, GenesisManifestV2, GenesisPolicy, TransitionEventV2, TransitionKind,
            APPROVAL_CONTEXT_V2, CARD_SELF_KEY, GENESIS_CONTEXT_V2, GENESIS_KEY,
            TRANSITION_CONTEXT_V2, V2_SCHEMA,
        },
        identity::{assemble_external_dst, derive_agent_id_hex},
        StorePolicyMode, V2ListRef, V2StoreApi, V2StoreManager, V2Tracker,
    },
    X0xCrdtTracker,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn err(msg: impl Into<String>) -> Box<dyn Error> {
    Box::new(std::io::Error::other(msg.into()))
}

// ---------------------------------------------------------------------------
// Signing fixtures (mock-crypto pattern: real ML-DSA-65, no daemon)
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
// In-memory x0xd double: implements BOTH the v1 `X0xdApi` (tasks + kv
// blobs + the v2 display TaskList) and the v2 `V2StoreApi` (append-only
// event stores). Append-only is enforced for `symphony2-ev-*` topics only,
// exactly like x0x WP-X.
// ---------------------------------------------------------------------------

struct StagedBatch {
    trigger_prefix: String,
    records: Vec<(String, String, Vec<u8>)>,
}

#[derive(Default)]
struct InMemoryX0xd {
    kv: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    tasks: Mutex<BTreeMap<String, Vec<TaskEntry>>>,
    lists: Mutex<BTreeSet<String>>,
    kv_stores: Mutex<BTreeSet<String>>,
    /// Daemon-anchored owner + policy per store topic — the double mocks
    /// the anchoring NEGOTIATION (create anchors to the local agent with
    /// the requested policy; join anchors to the expected owner), never
    /// blessing topics by name.
    anchors: Mutex<BTreeMap<String, (String, String)>>,
    /// The daemon's local agent identity (owner of created stores).
    local_agent: Mutex<Option<String>>,
    /// Topics passed to `join_kv_store`, for join-path assertions.
    joins: Mutex<Vec<String>>,
    /// When set, writes to heartbeat companion stores fail (blocker-1
    /// failure injection: heartbeats are non-authoritative).
    fail_heartbeat_puts: Mutex<bool>,
    /// Records that become visible only after a key with the batch's
    /// trigger prefix is written — deterministic partition-heal staging.
    staged: Mutex<Vec<StagedBatch>>,
}

impl InMemoryX0xd {
    async fn set_local_agent(&self, agent: &str) {
        *self.local_agent.lock().await = Some(agent.to_owned());
    }

    /// Anchor `topic` to `owner` with `policy`, as the daemon would after a
    /// network ownership lookup (used for directly seeded peer stores).
    async fn anchor(&self, topic: &str, owner: &str, policy: &str) {
        self.anchors
            .lock()
            .await
            .insert(topic.to_owned(), (owner.to_owned(), policy.to_owned()));
    }

    async fn seed(&self, topic: &str, key: &str, value: Vec<u8>) {
        self.kv
            .lock()
            .await
            .insert((topic.to_owned(), key.to_owned()), value);
    }

    async fn stage(&self, trigger_prefix: &str, records: Vec<(String, String, Vec<u8>)>) {
        self.staged.lock().await.push(StagedBatch {
            trigger_prefix: trigger_prefix.to_owned(),
            records,
        });
    }

    async fn count_keys_with_prefix(&self, topic: &str, prefix: &str) -> usize {
        self.kv
            .lock()
            .await
            .keys()
            .filter(|(t, k)| t == topic && k.starts_with(prefix))
            .count()
    }

    async fn is_append_only(&self, topic: &str) -> bool {
        self.anchors
            .lock()
            .await
            .get(topic)
            .is_some_and(|(_, policy)| policy == "append_only")
    }
}

#[async_trait]
impl V2StoreApi for InMemoryX0xd {
    async fn create_kv_store_with_policy(
        &self,
        _name: &str,
        topic: &str,
        policy: Option<&str>,
    ) -> std::result::Result<StoreCreateOutcome, ClientError> {
        self.kv_stores.lock().await.insert(topic.to_owned());
        if let Some(agent) = self.local_agent.lock().await.clone() {
            self.anchors
                .lock()
                .await
                .entry(topic.to_owned())
                .or_insert((agent, policy.unwrap_or("signed").to_owned()));
        }
        Ok(StoreCreateOutcome {
            id: topic.to_owned(),
            policy: policy.map(str::to_owned),
        })
    }

    async fn join_kv_store(
        &self,
        topic: &str,
        expected_owner: &str,
    ) -> std::result::Result<(), ClientError> {
        self.joins.lock().await.push(topic.to_owned());
        let mut anchors = self.anchors.lock().await;
        match anchors.get(topic) {
            Some((owner, _)) if owner != expected_owner => Err(ClientError::Http {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                body: format!("expected owner mismatch: anchored to {owner}"),
            }),
            Some(_) => Ok(()),
            None => {
                // Anchoring a store the double has never heard of mirrors a
                // join whose network lookup succeeded; the policy of a
                // remote v2 event store is append_only in these tests.
                anchors.insert(
                    topic.to_owned(),
                    (expected_owner.to_owned(), "append_only".to_owned()),
                );
                Ok(())
            }
        }
    }

    async fn kv_store_detail(
        &self,
        topic: &str,
    ) -> std::result::Result<Option<StoreDetailEntry>, ClientError> {
        let anchors = self.anchors.lock().await;
        Ok(anchors.get(topic).map(|(owner, policy)| StoreDetailEntry {
            id: topic.to_owned(),
            owner: Some(owner.clone()),
            policy: Some(policy.clone()),
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
        if *self.fail_heartbeat_puts.lock().await && topic.starts_with("symphony2-hb-") {
            return Err(ClientError::Http {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: "injected heartbeat-store failure".to_owned(),
            });
        }
        if self.is_append_only(topic).await {
            let kv = self.kv.lock().await;
            if kv.contains_key(&(topic.to_owned(), key.to_owned())) {
                return Err(ClientError::Http {
                    status: StatusCode::CONFLICT,
                    body: "append_only: key exists".to_owned(),
                });
            }
        }
        {
            let mut kv = self.kv.lock().await;
            kv.insert((topic.to_owned(), key.to_owned()), value.to_vec());
        }
        // Release any staged batches whose trigger fired.
        let fired: Vec<StagedBatch> = {
            let mut staged = self.staged.lock().await;
            let (fired, kept): (Vec<_>, Vec<_>) = staged
                .drain(..)
                .partition(|b| key.starts_with(&b.trigger_prefix));
            *staged = kept;
            fired
        };
        if !fired.is_empty() {
            let mut kv = self.kv.lock().await;
            for batch in fired {
                for (t, k, v) in batch.records {
                    kv.insert((t, k), v);
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl X0xdApi for InMemoryX0xd {
    async fn list_task_lists(&self) -> std::result::Result<Vec<TaskListEntry>, ClientError> {
        Ok(self
            .lists
            .lock()
            .await
            .iter()
            .map(|id| TaskListEntry {
                id: id.clone(),
                topic: id.clone(),
            })
            .collect())
    }

    async fn create_task_list(
        &self,
        _name: &str,
        topic: &str,
    ) -> std::result::Result<String, ClientError> {
        self.lists.lock().await.insert(topic.to_owned());
        self.tasks.lock().await.entry(topic.to_owned()).or_default();
        Ok(topic.to_owned())
    }

    async fn list_named_groups(&self) -> std::result::Result<Vec<NamedGroupEntry>, ClientError> {
        Ok(Vec::new())
    }

    async fn get_named_group(
        &self,
        group_id: &str,
    ) -> std::result::Result<NamedGroupDetails, ClientError> {
        Err(ClientError::Http {
            status: StatusCode::NOT_FOUND,
            body: format!("no group {group_id}"),
        })
    }

    async fn join_group(
        &self,
        invite: &str,
        _display_name: Option<&str>,
    ) -> std::result::Result<JoinedGroup, ClientError> {
        Err(ClientError::Http {
            status: StatusCode::NOT_FOUND,
            body: format!("no invite {invite}"),
        })
    }

    async fn list_tasks(&self, list_id: &str) -> std::result::Result<Vec<TaskEntry>, ClientError> {
        Ok(self
            .tasks
            .lock()
            .await
            .get(list_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn add_task(
        &self,
        list_id: &str,
        draft: AddTaskDraft,
    ) -> std::result::Result<String, ClientError> {
        let mut tasks = self.tasks.lock().await;
        let list = tasks.entry(list_id.to_owned()).or_default();
        let id = sha256_hex(format!("{list_id}:{}:{}", draft.title, list.len()).as_bytes());
        list.push(TaskEntry {
            id: id.clone(),
            title: draft.title,
            description: draft.description.unwrap_or_default(),
            state: "empty".to_owned(),
            assignee: None,
            priority: 0,
        });
        Ok(id)
    }

    async fn update_task(
        &self,
        list_id: &str,
        task_id: &str,
        action: TaskAction,
    ) -> std::result::Result<(), ClientError> {
        let mut tasks = self.tasks.lock().await;
        let list = tasks.entry(list_id.to_owned()).or_default();
        let Some(task) = list.iter_mut().find(|t| t.id == task_id) else {
            return Err(ClientError::Http {
                status: StatusCode::NOT_FOUND,
                body: format!("no task {task_id}"),
            });
        };
        task.state = match action {
            TaskAction::Claim => "claimed".to_owned(),
            TaskAction::Complete => "done".to_owned(),
        };
        Ok(())
    }

    async fn list_kv_stores(&self) -> std::result::Result<Vec<TaskListEntry>, ClientError> {
        Ok(self
            .kv_stores
            .lock()
            .await
            .iter()
            .map(|id| TaskListEntry {
                id: id.clone(),
                topic: id.clone(),
            })
            .collect())
    }

    async fn create_kv_store(
        &self,
        _name: &str,
        topic: &str,
    ) -> std::result::Result<String, ClientError> {
        self.kv_stores.lock().await.insert(topic.to_owned());
        Ok(topic.to_owned())
    }

    async fn list_kv_keys(
        &self,
        store_id: &str,
    ) -> std::result::Result<Vec<KvKeyEntry>, ClientError> {
        V2StoreApi::list_kv_keys(self, store_id).await
    }

    async fn put_kv(
        &self,
        store_id: &str,
        key: &str,
        value: &[u8],
        content_type: &str,
    ) -> std::result::Result<(), ClientError> {
        V2StoreApi::put_kv(self, store_id, key, value, content_type).await
    }

    async fn get_kv(
        &self,
        store_id: &str,
        key: &str,
    ) -> std::result::Result<Option<KvValue>, ClientError> {
        V2StoreApi::get_kv(self, store_id, key).await
    }

    async fn subscribe_events(&self) -> std::result::Result<EventStream, ClientError> {
        Err(ClientError::Http {
            status: StatusCode::NOT_IMPLEMENTED,
            body: "no event stream in the in-memory double".to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// v2 world
// ---------------------------------------------------------------------------

struct V2World {
    daemon: Arc<InMemoryX0xd>,
    me: Arc<Author>,
    tracker: V2Tracker,
    list_uuid: String,
    genesis_hash: String,
}

impl V2World {
    /// Single-author world: the local agent IS the creator; genesis is
    /// self-published by `ensure_surfaces` with roster `[me]`, or
    /// pre-seeded with `extra_members` in the roster.
    async fn new(list_uuid: &str, extra_members: &[&Author]) -> TestResult<Self> {
        let daemon = Arc::new(InMemoryX0xd::default());
        let me = Arc::new(Author::generate()?);
        daemon.set_local_agent(&me.id).await;
        let manager = V2StoreManager::new(
            daemon.clone(),
            Arc::new(LocalSigner { author: me.clone() }),
            StorePolicyMode::AppendOnly,
        );
        let mut genesis_hash = String::new();
        if !extra_members.is_empty() {
            // Pre-seed a multi-member genesis (creator-signed) so
            // ensure_surfaces sees a foldable list and does not publish.
            let mut roster = vec![me.id.clone()];
            roster.extend(extra_members.iter().map(|a| a.id.clone()));
            let manifest = GenesisManifestV2 {
                schema: V2_SCHEMA,
                kind: "genesis".to_owned(),
                list_uuid: list_uuid.to_owned(),
                creator: me.id.clone(),
                roster,
                policy: GenesisPolicy::default(),
                created_at: 1,
            };
            let payload = serde_json::to_vec(&manifest)?;
            genesis_hash = sha256_hex(&payload);
            let envelope = me.sign_envelope(GENESIS_CONTEXT_V2, &payload)?;
            let topic = event_store_topic(list_uuid, &me.id);
            daemon.seed(&topic, CARD_SELF_KEY, me.pk.clone()).await;
            daemon
                .seed(&topic, GENESIS_KEY, envelope.encode().map_err(err)?)
                .await;
            for member in extra_members {
                let peer_topic = event_store_topic(list_uuid, &member.id);
                daemon.anchor(&peer_topic, &member.id, "append_only").await;
                daemon
                    .seed(&peer_topic, CARD_SELF_KEY, member.pk.clone())
                    .await;
            }
        }
        let tracker = V2Tracker::new(
            manager,
            V2ListRef {
                list_uuid: list_uuid.to_owned(),
                creator: me.id.clone(),
            },
            AgentId::new(me.id.clone())?,
            Some(daemon.clone() as Arc<dyn X0xdApi>),
            Duration::ZERO,
        );
        tracker.ensure_surfaces().await?;
        if genesis_hash.is_empty() {
            // Self-published genesis: recover its hash from the store.
            let topic = event_store_topic(list_uuid, &me.id);
            let value = V2StoreApi::get_kv(daemon.as_ref(), &topic, GENESIS_KEY)
                .await?
                .ok_or_else(|| err("genesis missing after ensure_surfaces"))?;
            let envelope = EventEnvelope::decode(&value.value).map_err(err)?;
            let (_, hash) = envelope.verify(GENESIS_CONTEXT_V2).map_err(err)?;
            genesis_hash = hash;
        }
        Ok(Self {
            daemon,
            me,
            tracker,
            list_uuid: list_uuid.to_owned(),
            genesis_hash,
        })
    }
}

fn poll_ctx() -> TestResult<PollContext> {
    Ok(PollContext::new(
        vec![IssueState::new("todo")?],
        vec![IssueState::new("done")?, IssueState::new("review")?],
    ))
}

fn draft(title: &str, description: &str) -> x0x_symphony_core::IssueDraft {
    x0x_symphony_core::IssueDraft {
        title: title.to_owned(),
        description: Some(description.to_owned()),
        priority: None,
        labels: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// v2-specific tests
// ---------------------------------------------------------------------------

/// Happy path through the REAL trait: open → claim → handoff (+Complete)
/// — proving dispatch works end-to-end on a v2 list with a fold-backed
/// projection, chained handoff artifact, and display reconciliation.
#[tokio::test]
async fn v2_open_claim_handoff_complete_happy_path() -> TestResult {
    let world = V2World::new("wpb2-happy", &[]).await?;
    let tracker: &dyn Tracker = &world.tracker;
    let agent = AgentId::new(world.me.id.clone())?;

    let issue = tracker.create_issue(draft("build it", "the spec")).await?;
    assert_eq!(issue.state, IssueState::new("todo")?);
    assert_eq!(issue.description, "the spec");
    assert_eq!(
        issue
            .signature_provenance
            .as_ref()
            .and_then(|p| p.verified_signer()),
        Some(world.me.id.as_str()),
        "fold-admitted open events carry REAL verified provenance"
    );

    let candidates = tracker.fetch_candidates(&poll_ctx()?).await?;
    assert_eq!(candidates.len(), 1);

    let claim = tracker.claim(&issue.id, &agent).await?;
    let after_claim = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(after_claim[0].state, IssueState::new("in_progress")?);
    assert_eq!(
        after_claim[0].claim.as_ref().map(|c| c.by.as_str()),
        Some(world.me.id.as_str())
    );

    tracker.heartbeat(&claim).await?;

    let handoff = Handoff::new("did the thing")
        .with_file("src/lib.rs")
        .with_validation(ValidationResult {
            command: "cargo test".to_owned(),
            status: ValidationStatus::Passed,
            exit_code: Some(0),
        })
        .with_follow_up("polish docs");
    tracker.handoff(&claim, handoff).await?;

    let done = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(
        done[0].state,
        IssueState::new("review")?,
        "completed-with-handoff reads as review (v1 parity)"
    );
    let projected = done[0]
        .handoff
        .as_ref()
        .ok_or_else(|| err("handoff missing from projection"))?;
    assert_eq!(projected.summary, "did the thing");
    assert_eq!(projected.files_changed, vec!["src/lib.rs".to_owned()]);
    assert_eq!(projected.validation.len(), 1);
    assert_eq!(projected.validation[0].status, ValidationStatus::Passed);
    assert_eq!(projected.follow_up, vec!["polish docs".to_owned()]);
    assert!(tracker.fetch_candidates(&poll_ctx()?).await?.is_empty());

    // Both chained records exist durably: ho-* and the completing ev-*.
    let topic = event_store_topic(&world.list_uuid, &world.me.id);
    assert_eq!(
        world.daemon.count_keys_with_prefix(&topic, "ho-").await,
        1,
        "exactly one durable handoff record"
    );
    Ok(())
}

/// Blocked/requeue path driving the C6 gate through the trait: only an
/// `awaiting_approval` block is requeue-able, and requeue makes the issue
/// claimable again.
#[tokio::test]
async fn v2_block_requeue_path_drives_c6_gate() -> TestResult {
    let world = V2World::new("wpb2-requeue", &[]).await?;
    let tracker: &dyn Tracker = &world.tracker;
    let agent = AgentId::new(world.me.id.clone())?;

    let issue = tracker
        .create_issue(draft("gated", "needs consent"))
        .await?;
    let claim = tracker.claim(&issue.id, &agent).await?;
    tracker
        .block(
            &claim,
            ReleaseReason::new(ReleaseReasonCode::AwaitingApproval, "parked for approval"),
        )
        .await?;
    let blocked = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(blocked[0].state, IssueState::new("blocked")?);
    assert!(tracker.fetch_candidates(&poll_ctx()?).await?.is_empty());

    tracker
        .requeue_blocked(
            &issue.id,
            ReleaseReason::new(ReleaseReasonCode::AwaitingApproval, "operator approved"),
        )
        .await?;
    let requeued = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(requeued[0].state, IssueState::new("todo")?);

    // Re-claim works with a fresh fence.
    let claim2 = tracker.claim(&issue.id, &agent).await?;

    // A NON-awaiting_approval block is terminal: requeue refuses (C6).
    tracker
        .block(
            &claim2,
            ReleaseReason::new(ReleaseReasonCode::RetryExhausted, "gave up"),
        )
        .await?;
    let refused = tracker
        .requeue_blocked(
            &issue.id,
            ReleaseReason::new(ReleaseReasonCode::AwaitingApproval, "nice try"),
        )
        .await;
    assert!(
        refused.is_err(),
        "non-awaiting_approval blocks must never be requeue-able"
    );
    Ok(())
}

/// Concurrent claims resolve to ONE deterministic winner; the trait caller
/// that lost gets an ERROR, never a claim it does not hold.
#[tokio::test]
async fn v2_claim_race_has_one_deterministic_winner() -> TestResult {
    let peer = Author::generate()?;
    let world = V2World::new("wpb2-race", &[&peer]).await?;
    let tracker: &dyn Tracker = &world.tracker;
    let agent = AgentId::new(world.me.id.clone())?;

    let issue = tracker.create_issue(draft("contested", "spec")).await?;

    // Stage a peer claim that becomes visible only when OUR claim event is
    // written (partition heal at the worst moment). Same lamport as ours
    // will be assigned (max+1 = 2): the fold breaks the tie by
    // (lamport, author, event_hash) — deterministically.
    let peer_claim = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: world.list_uuid.clone(),
        genesis_manifest_hash: world.genesis_hash.clone(),
        roster_epoch: 0,
        issue_id: issue.id.as_str().to_owned(),
        actor: peer.id.clone(),
        lamport: 2,
        author_seq: 1,
        prev_own_event_hash: world.genesis_hash.clone(),
        kind: TransitionKind::Claim {
            claim_nonce: "peer-nonce".to_owned(),
        },
    };
    let payload = peer_claim.to_signed_bytes().map_err(err)?;
    let peer_claim_hash = sha256_hex(&payload);
    let envelope = peer.sign_envelope(TRANSITION_CONTEXT_V2, &payload)?;
    let peer_topic = event_store_topic(&world.list_uuid, &peer.id);
    world
        .daemon
        .stage(
            "ev-",
            vec![(
                peer_topic,
                event_key(issue.id.as_str(), &peer_claim_hash),
                envelope.encode().map_err(err)?,
            )],
        )
        .await;

    let claim_outcome = tracker.claim(&issue.id, &agent).await;
    let folded = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    let winner = folded[0].claim.as_ref().map(|c| c.by.as_str().to_owned());
    match claim_outcome {
        Ok(_) => {
            assert_eq!(
                winner.as_deref(),
                Some(world.me.id.as_str()),
                "claim() returned Ok, so the fold must agree we won"
            );
        }
        Err(e) => {
            assert!(
                e.to_string().contains("lost the deterministic fold race"),
                "loser gets a loud race error, got: {e}"
            );
            assert_eq!(
                winner.as_deref(),
                Some(peer.id.as_str()),
                "claim() errored, so the fold must show the peer holding it"
            );
        }
    }
    // Determinism: a second read agrees with the first.
    let again = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(
        again[0].claim.as_ref().map(|c| c.by.as_str().to_owned()),
        winner
    );
    Ok(())
}

/// The v1 approval bridge: `store_approval` appends a chained v2 record
/// carrying the verbatim v1 event; `load_approval_state` round-trips it,
/// signature envelope included. Foreign approvers are refused.
#[tokio::test]
async fn v2_store_approval_round_trips_v1_record() -> TestResult {
    let world = V2World::new("wpb2-approval", &[]).await?;
    let tracker: &dyn Tracker = &world.tracker;

    let issue = tracker.create_issue(draft("needs consent", "spec")).await?;
    let projected = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    let event = ApprovalEvent {
        issue_id: issue.id.clone(),
        content_hash: content_hash(&projected[0]),
        signer_agent_id: AgentId::new(world.me.id.clone())?,
        verdict: ApprovalVerdict::Approve,
        approved_at: "2026-07-16T00:00:00Z".to_owned(),
        approver_agent_id: AgentId::new(world.me.id.clone())?,
        claim_id: None,
        signature: Some(SignatureEnvelope::new(
            "ml-dsa-65",
            "x0x-symphony-approval-v1",
            "cGs=",
            "c2ln",
            sha256_hex(b"payload"),
            world.me.id.clone(),
        )),
    };
    tracker.store_approval(&event).await?;

    let state = tracker.load_approval_state(&issue.id).await?;
    assert_eq!(state.events.len(), 1);
    assert_eq!(
        state.events[0], event,
        "verbatim v1 round-trip, signature included"
    );
    assert!(state.consumed.is_empty());

    // A durable chained ap-* record exists in the author's own store.
    let topic = event_store_topic(&world.list_uuid, &world.me.id);
    assert_eq!(world.daemon.count_keys_with_prefix(&topic, "ap-").await, 1);

    // Foreign approver: cannot mint a record into OUR store.
    let foreign = Author::generate()?;
    let mut foreign_event = event.clone();
    foreign_event.approver_agent_id = AgentId::new(foreign.id.clone())?;
    let refused = tracker.store_approval(&foreign_event).await;
    assert!(
        refused.is_err(),
        "v2 approvals are author-signed; a foreign approver's record must be refused"
    );

    // Stale content: approval bound to different content is refused.
    let mut wrong_content = event.clone();
    wrong_content.content_hash = x0x_symphony_core::ContentHash::new(sha256_hex(b"different"))
        .map_err(|e| err(format!("{e}")))?;
    assert!(tracker.store_approval(&wrong_content).await.is_err());
    Ok(())
}

/// Consume-then-confirm through the trait: exactly-once on the happy path,
/// and a HARD ERROR (zero dispatch) when a divergent claim heals in
/// between — the fold winner, not the local append, is the authority.
#[tokio::test]
async fn v2_store_consumed_exactly_once_and_fails_closed() -> TestResult {
    let peer = Author::generate()?;
    let world = V2World::new("wpb2-consume", &[&peer]).await?;
    let tracker: &dyn Tracker = &world.tracker;
    let agent = AgentId::new(world.me.id.clone())?;

    let issue = tracker.create_issue(draft("consented", "spec")).await?;
    let claim = tracker.claim(&issue.id, &agent).await?;
    let projected = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    let approval = ApprovalEvent {
        issue_id: issue.id.clone(),
        content_hash: content_hash(&projected[0]),
        signer_agent_id: AgentId::new(world.me.id.clone())?,
        verdict: ApprovalVerdict::Approve,
        approved_at: "2026-07-16T00:00:00Z".to_owned(),
        approver_agent_id: AgentId::new(world.me.id.clone())?,
        claim_id: None,
        signature: None,
    };
    tracker.store_approval(&approval).await?;

    let consumed = x0x_symphony_core::ApprovalConsumed::new(
        issue.id.clone(),
        content_hash(&projected[0]),
        AgentId::new(world.me.id.clone())?,
        "nonce-1",
        "2026-07-16T00:00:01Z",
        SignatureEnvelope::new(
            "ml-dsa-65",
            "x0x-symphony-approval-consumed-v1",
            "cGs=",
            "c2ln",
            sha256_hex(b"consumed"),
            world.me.id.clone(),
        ),
    );
    tracker.store_consumed(&consumed).await?;
    let state = tracker.load_approval_state(&issue.id).await?;
    assert_eq!(state.consumed.len(), 1, "effective consume round-trips");

    // Second consumption: the approval is spent — refuse loudly.
    let second = tracker.store_consumed(&consumed).await;
    assert!(
        second.is_err(),
        "spent approvals must never consume twice: {second:?}"
    );
    let _ = claim;
    Ok(())
}

/// Divergent-claim heal between append and confirm: `store_consumed` must
/// fail closed (error, zero executions) when the healed fold shows the
/// peer holding the winning claim.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn v2_store_consumed_aborts_when_divergent_claim_heals() -> TestResult {
    let peer = Author::generate()?;
    let world = V2World::new("wpb2-heal", &[&peer]).await?;
    let tracker: &dyn Tracker = &world.tracker;
    let agent = AgentId::new(world.me.id.clone())?;

    let issue = tracker
        .create_issue(draft("contested-consume", "spec"))
        .await?;

    // Peer decoy approval (lamport 2, seq 1) raises the lamport horizon so
    // OUR claim lands at lamport 3 — making the staged peer claim
    // (lamport 2, seq 2) deterministically order BEFORE ours after heal.
    let decoy = ApprovalEventV2 {
        schema: V2_SCHEMA,
        kind: "dispatch_approval".to_owned(),
        list_uuid: world.list_uuid.clone(),
        genesis_manifest_hash: world.genesis_hash.clone(),
        roster_epoch: 0,
        issue_id: "decoy-issue".to_owned(),
        open_event_hash: sha256_hex(b"decoy"),
        actor: peer.id.clone(),
        lamport: 2,
        author_seq: 1,
        prev_own_event_hash: world.genesis_hash.clone(),
        verdict: ApprovalVerdictV2::Approve,
        entropy: "decoy-entropy".to_owned(),
        approved_at: 1,
        v1_record_json: String::new(),
    };
    let decoy_payload = decoy.to_signed_bytes().map_err(err)?;
    let decoy_hash = sha256_hex(&decoy_payload);
    let decoy_env = peer.sign_envelope(APPROVAL_CONTEXT_V2, &decoy_payload)?;
    let peer_topic = event_store_topic(&world.list_uuid, &peer.id);
    world
        .daemon
        .seed(
            &peer_topic,
            &approval_key("decoy-issue", &decoy_hash),
            decoy_env.encode().map_err(err)?,
        )
        .await;

    // Our claim: folds at lamport 3 (open=1, decoy=2).
    let claim = tracker.claim(&issue.id, &agent).await?;

    let projected = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    let approval = ApprovalEvent {
        issue_id: issue.id.clone(),
        content_hash: content_hash(&projected[0]),
        signer_agent_id: AgentId::new(world.me.id.clone())?,
        verdict: ApprovalVerdict::Approve,
        approved_at: "2026-07-16T00:00:00Z".to_owned(),
        approver_agent_id: AgentId::new(world.me.id.clone())?,
        claim_id: None,
        signature: None,
    };
    tracker.store_approval(&approval).await?;

    // Stage the peer's earlier-ordered claim (lamport 2, seq 2) to heal in
    // exactly when our consume record is written.
    let peer_claim = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: world.list_uuid.clone(),
        genesis_manifest_hash: world.genesis_hash.clone(),
        roster_epoch: 0,
        issue_id: issue.id.as_str().to_owned(),
        actor: peer.id.clone(),
        lamport: 2,
        author_seq: 2,
        prev_own_event_hash: decoy_hash,
        kind: TransitionKind::Claim {
            claim_nonce: "peer-heal-nonce".to_owned(),
        },
    };
    let payload = peer_claim.to_signed_bytes().map_err(err)?;
    let peer_claim_hash = sha256_hex(&payload);
    let envelope = peer.sign_envelope(TRANSITION_CONTEXT_V2, &payload)?;
    world
        .daemon
        .stage(
            "cs-",
            vec![(
                event_store_topic(&world.list_uuid, &peer.id),
                event_key(issue.id.as_str(), &peer_claim_hash),
                envelope.encode().map_err(err)?,
            )],
        )
        .await;

    let consumed = x0x_symphony_core::ApprovalConsumed::new(
        issue.id.clone(),
        content_hash(&projected[0]),
        AgentId::new(world.me.id.clone())?,
        "nonce-heal",
        "2026-07-16T00:00:01Z",
        SignatureEnvelope::new(
            "ml-dsa-65",
            "x0x-symphony-approval-consumed-v1",
            "cGs=",
            "c2ln",
            sha256_hex(b"consumed"),
            world.me.id.clone(),
        ),
    );
    let outcome = tracker.store_consumed(&consumed).await;
    assert!(
        outcome.is_err(),
        "healed divergent claim must abort consumption (zero executions), got Ok"
    );
    // The durable consume record exists (spent-toward-zero, WP-B) but the
    // v1 projection shows NO effective consumption — the fold refused it.
    let topic = event_store_topic(&world.list_uuid, &world.me.id);
    assert_eq!(world.daemon.count_keys_with_prefix(&topic, "cs-").await, 1);
    let state = tracker.load_approval_state(&issue.id).await?;
    assert!(
        state.consumed.is_empty(),
        "a losing consume never projects as an effective consumption"
    );
    let _ = claim;
    Ok(())
}

// ---------------------------------------------------------------------------
// Parity scenarios: written once against `&dyn Tracker`, run on BOTH the
// v1 tracker (in-memory x0xd double) and the v2 tracker (in-memory store
// double). Issue seeding differs per backend (v1 issue creation requires
// the shard/worker-view machinery, covered by the v1 unit suite); the
// orchestration surface under test is identical.
// ---------------------------------------------------------------------------

async fn scenario_claim_heartbeat_release_reclaim(
    tracker: &dyn Tracker,
    agent: &AgentId,
    issue_id: &IssueId,
) -> TestResult {
    let start = tracker.fetch_by_ids(std::slice::from_ref(issue_id)).await?;
    assert_eq!(start[0].state, IssueState::new("todo")?);

    let claim = tracker.claim(issue_id, agent).await?;
    let claimed = tracker.fetch_by_ids(std::slice::from_ref(issue_id)).await?;
    assert_eq!(claimed[0].state, IssueState::new("in_progress")?);

    // Double-claim of a held issue is refused on both backends.
    assert!(tracker.claim(issue_id, agent).await.is_err());

    tracker.heartbeat(&claim).await?;

    tracker
        .release(
            &claim,
            ReleaseReason::new(ReleaseReasonCode::RunnerFailed, "exit 1"),
        )
        .await?;
    let released = tracker.fetch_by_ids(std::slice::from_ref(issue_id)).await?;
    assert_eq!(released[0].state, IssueState::new("todo")?);

    // Reclaim works after release.
    let claim2 = tracker.claim(issue_id, agent).await?;
    tracker
        .release(
            &claim2,
            ReleaseReason::new(ReleaseReasonCode::OperatorCancelled, "stop"),
        )
        .await?;
    Ok(())
}

async fn scenario_block_requeue_awaiting_approval(
    tracker: &dyn Tracker,
    agent: &AgentId,
    issue_id: &IssueId,
) -> TestResult {
    let claim = tracker.claim(issue_id, agent).await?;
    tracker
        .block(
            &claim,
            ReleaseReason::new(ReleaseReasonCode::AwaitingApproval, "parked"),
        )
        .await?;
    let blocked = tracker.fetch_by_ids(std::slice::from_ref(issue_id)).await?;
    assert_eq!(blocked[0].state, IssueState::new("blocked")?);

    tracker
        .requeue_blocked(
            issue_id,
            ReleaseReason::new(ReleaseReasonCode::AwaitingApproval, "approved"),
        )
        .await?;
    let requeued = tracker.fetch_by_ids(std::slice::from_ref(issue_id)).await?;
    assert_eq!(requeued[0].state, IssueState::new("todo")?);

    // Non-awaiting_approval blocks are terminal on both backends.
    let claim2 = tracker.claim(issue_id, agent).await?;
    tracker
        .block(
            &claim2,
            ReleaseReason::new(ReleaseReasonCode::RetryExhausted, "budget spent"),
        )
        .await?;
    assert!(tracker
        .requeue_blocked(
            issue_id,
            ReleaseReason::new(ReleaseReasonCode::AwaitingApproval, "no"),
        )
        .await
        .is_err());
    Ok(())
}

async fn scenario_handoff_reads_as_review(
    tracker: &dyn Tracker,
    agent: &AgentId,
    issue_id: &IssueId,
) -> TestResult {
    let claim = tracker.claim(issue_id, agent).await?;
    tracker
        .handoff(&claim, Handoff::new("shipped").with_file("main.rs"))
        .await?;
    let done = tracker.fetch_by_ids(std::slice::from_ref(issue_id)).await?;
    assert_eq!(done[0].state, IssueState::new("review")?);
    let handoff = done[0]
        .handoff
        .as_ref()
        .ok_or_else(|| err("handoff missing"))?;
    assert_eq!(handoff.summary, "shipped");
    // fetch_claimed no longer reports it as actively claimed on v2; v1
    // keeps a completed claim blob — both must agree the issue is not a
    // dispatch candidate anymore.
    let candidates = tracker
        .fetch_candidates(&PollContext::new(
            vec![IssueState::new("todo")?],
            vec![IssueState::new("done")?, IssueState::new("review")?],
        ))
        .await?;
    assert!(candidates.iter().all(|i| &i.id != issue_id));
    Ok(())
}

/// Build a v1 tracker over the in-memory double with one seeded issue.
async fn v1_world(issue_title: &str) -> TestResult<(X0xCrdtTracker, AgentId, IssueId)> {
    let daemon = Arc::new(InMemoryX0xd::default());
    let agent = AgentId::new("agent-a")?;
    let list_id = "list-a";
    X0xdApi::create_task_list(daemon.as_ref(), list_id, list_id).await?;
    daemon
        .kv_stores
        .lock()
        .await
        .insert(format!("symphony-{list_id}"));
    let task_id = X0xdApi::add_task(
        daemon.as_ref(),
        list_id,
        AddTaskDraft::new(issue_title).with_description("spec"),
    )
    .await?;
    let tracker = X0xCrdtTracker::from_client(
        "http://mock.invalid",
        list_id,
        agent.clone(),
        daemon as Arc<dyn X0xdApi>,
    );
    Ok((tracker, agent, IssueId::new(task_id)?))
}

/// Build a v2 tracker world with one issue created through the trait.
async fn v2_world_with_issue(list_uuid: &str) -> TestResult<(V2World, AgentId, IssueId)> {
    let world = V2World::new(list_uuid, &[]).await?;
    let agent = AgentId::new(world.me.id.clone())?;
    let issue = world
        .tracker
        .create_issue(draft("parity issue", "spec"))
        .await?;
    let id = issue.id;
    Ok((world, agent, id))
}

#[tokio::test]
async fn parity_claim_heartbeat_release_reclaim() -> TestResult {
    let (v1, agent1, issue1) = v1_world("parity issue").await?;
    scenario_claim_heartbeat_release_reclaim(&v1, &agent1, &issue1).await?;

    let (v2, agent2, issue2) = v2_world_with_issue("wpb2-parity-claim").await?;
    scenario_claim_heartbeat_release_reclaim(&v2.tracker, &agent2, &issue2).await?;
    Ok(())
}

#[tokio::test]
async fn parity_block_requeue_awaiting_approval_only() -> TestResult {
    let (v1, agent1, issue1) = v1_world("parity issue").await?;
    scenario_block_requeue_awaiting_approval(&v1, &agent1, &issue1).await?;

    let (v2, agent2, issue2) = v2_world_with_issue("wpb2-parity-requeue").await?;
    scenario_block_requeue_awaiting_approval(&v2.tracker, &agent2, &issue2).await?;
    Ok(())
}

#[tokio::test]
async fn parity_handoff_reads_as_review() -> TestResult {
    let (v1, agent1, issue1) = v1_world("parity issue").await?;
    scenario_handoff_reads_as_review(&v1, &agent1, &issue1).await?;

    let (v2, agent2, issue2) = v2_world_with_issue("wpb2-parity-handoff").await?;
    scenario_handoff_reads_as_review(&v2.tracker, &agent2, &issue2).await?;
    Ok(())
}

/// Codex blocker 1 regression: a heartbeat-store write failure AFTER the
/// fold-winning claim is durably confirmed must NOT fail the claim —
/// heartbeats are non-authoritative liveness hints (spec §2.6).
#[tokio::test]
async fn claim_survives_heartbeat_write_failure() -> TestResult {
    let world = V2World::new("wpb2-hbfail", &[]).await?;
    let tracker: &dyn Tracker = &world.tracker;
    let agent = AgentId::new(world.me.id.clone())?;
    let issue = tracker.create_issue(draft("hb-fragile", "spec")).await?;

    *world.daemon.fail_heartbeat_puts.lock().await = true;
    let claim = tracker
        .claim(&issue.id, &agent)
        .await
        .map_err(|e| err(format!("claim must survive a heartbeat failure, got: {e}")))?;
    assert_eq!(claim.by, agent);
    let folded = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(
        folded[0].state,
        IssueState::new("in_progress")?,
        "the durable claim stands even though the heartbeat write failed"
    );
    // The failure only cost the liveness hint; explicit heartbeat() still
    // reports the store error (its ONLY job is the heartbeat write).
    assert!(tracker.heartbeat(&claim).await.is_err());
    *world.daemon.fail_heartbeat_puts.lock().await = false;
    tracker.heartbeat(&claim).await?;
    Ok(())
}

/// Codex blocker 2 regression: an author admitted by a roster UPDATE (not
/// the genesis roster) must have its store joined and its events visible
/// through the PRODUCTION tracker read path (`fold_view` join fixpoint).
#[tokio::test]
async fn roster_added_member_events_visible_via_tracker_read_path() -> TestResult {
    let world = V2World::new("wpb2-rosteradd", &[]).await?;
    let tracker: &dyn Tracker = &world.tracker;

    // Creator publishes roster epoch 1 adding a brand-new member.
    let peer = Author::generate()?;
    let manager = V2StoreManager::new(
        world.daemon.clone(),
        Arc::new(LocalSigner {
            author: world.me.clone(),
        }),
        StorePolicyMode::AppendOnly,
    );
    let own = manager.ensure_own_store(&world.list_uuid).await?;
    manager
        .publish_roster_update(
            &own,
            &world.genesis_hash,
            1,
            &world.genesis_hash,
            vec![world.me.id.clone(), peer.id.clone()],
        )
        .await?;

    // The peer's store exists with card-self + an Open event, but is NOT
    // pre-anchored: only the tracker's own join may make it readable.
    let peer_topic = event_store_topic(&world.list_uuid, &peer.id);
    world
        .daemon
        .seed(&peer_topic, CARD_SELF_KEY, peer.pk.clone())
        .await;
    let open = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: world.list_uuid.clone(),
        genesis_manifest_hash: world.genesis_hash.clone(),
        roster_epoch: 1,
        issue_id: "peer-issue".to_owned(),
        actor: peer.id.clone(),
        lamport: 5,
        author_seq: 1,
        prev_own_event_hash: world.genesis_hash.clone(),
        kind: TransitionKind::open("from the roster-added member", "spec"),
    };
    let payload = open.to_signed_bytes().map_err(err)?;
    let open_hash = sha256_hex(&payload);
    let envelope = peer.sign_envelope(TRANSITION_CONTEXT_V2, &payload)?;
    world
        .daemon
        .seed(
            &peer_topic,
            &event_key("peer-issue", &open_hash),
            envelope.encode().map_err(err)?,
        )
        .await;

    // Production read path: list_issues → fold_view → join fixpoint.
    let issues = tracker.list_issues().await?;
    assert!(
        issues.iter().any(|i| i.id.as_str() == "peer-issue"),
        "roster-added member's issue must be visible via the tracker read path; got {:?}",
        issues
            .iter()
            .map(|i| i.id.as_str().to_owned())
            .collect::<Vec<_>>()
    );
    let joins = world.daemon.joins.lock().await.clone();
    assert!(
        joins.iter().any(|t| t == &peer_topic),
        "the tracker must have JOINED the roster-added member's store, joins: {joins:?}"
    );
    Ok(())
}

/// Codex round-3 item 2: a member store whose daemon-reported anchor is
/// PRESENT but WRONG (owner mismatch) fails the whole list read
/// (fail-closed), while a member whose store is genuinely ABSENT (no
/// listing at all — normal replication lag) is skipped and the list still
/// folds.
#[tokio::test]
async fn member_anchor_mismatch_fails_read_but_absent_member_is_skipped() -> TestResult {
    let peer = Author::generate()?;
    let ghost = Author::generate()?;
    let world = V2World::new("wpb2-anchor", &[&peer, &ghost]).await?;
    let tracker: &dyn Tracker = &world.tracker;

    // Baseline sanity: `ghost` is in the roster but has NO store listing —
    // that is replication lag, not an integrity violation: reads succeed.
    let issue = tracker.create_issue(draft("anchored", "spec")).await?;
    assert_eq!(
        tracker
            .fetch_by_ids(std::slice::from_ref(&issue.id))
            .await?
            .len(),
        1,
        "absent member store must not block the list read"
    );

    // Now corrupt peer's anchor: listing present, WRONG owner.
    let peer_topic = event_store_topic(&world.list_uuid, &peer.id);
    world
        .daemon
        .anchor(&peer_topic, &ghost.id, "append_only")
        .await;
    let refused = tracker.list_issues().await;
    assert!(
        matches!(&refused, Err(e) if e.to_string().contains("anchor")),
        "an owner-mismatched member store must fail the read, got {refused:?}"
    );
    Ok(())
}

/// Codex round-3 item 1: the read path enforces the record budget before
/// fetching values — an over-budget stream refuses the read outright.
#[tokio::test]
async fn read_budget_violation_refuses_the_read() -> TestResult {
    use x0x_symphony_tracker_x0x_crdt::v2::FoldLimits;
    let world = V2World::new("wpb2-readbudget", &[]).await?;
    let tracker: &dyn Tracker = &world.tracker;
    for i in 0..3 {
        tracker
            .create_issue(draft(&format!("issue {i}"), "spec"))
            .await?;
    }
    // A manager with a tiny record budget must refuse the same stream.
    let tight = V2StoreManager::new(
        world.daemon.clone(),
        Arc::new(LocalSigner {
            author: world.me.clone(),
        }),
        StorePolicyMode::AppendOnly,
    )
    .with_limits(FoldLimits {
        max_records_per_stream: 2,
        ..FoldLimits::default()
    });
    let refused = tight.read_fold_input(&world.list_uuid, &world.me.id).await;
    assert!(
        matches!(&refused, Err(e) if e.to_string().contains("budget")),
        "over-budget stream must refuse the read, got {refused:?}"
    );
    Ok(())
}
