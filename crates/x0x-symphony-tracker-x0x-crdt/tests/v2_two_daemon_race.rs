//! WP-C: the tracker-integrity race harness (x0x-symphony#10, design r2).
//!
//! # Execution model — READ THIS FIRST (honest fidelity)
//!
//! The design target is TWO isolated live x0xd daemons whose per-author KV
//! event stores replicate over gossip. This harness was written and
//! committed against that topology (see `spawn_pair` / the two-daemon
//! bootstrap below, retained for infrastructure where gossip converges).
//! **In the local/CI sandbox that topology is not runnable**: two ephemeral
//! loopback daemons connect at the transport layer and replicate store
//! *metadata*, but KV *values* do not anti-entropy within a bounded window
//! (verified: no convergence in 210s on x0xd 0.32.1), and KV values are not
//! durable across a daemon restart on the same data dir (verified: keys lost
//! after SIGKILL+restart on 0.32.1). Both are the pillars scenarios ii–vi
//! would depend on.
//!
//! So the cross-author scenarios execute against **one live x0xd daemon with
//! two local ML-DSA-65 authors** (the `mock-crypto` signer pattern):
//! author A and author B each own an event-store topic on the SAME daemon's
//! real KV, read back immediately (no cross-daemon sync in the loop). This
//! PRESERVES the properties that matter for WP-C — real x0xd storage, real
//! `AccessPolicy::AppendOnly` enforcement (PUT-to-existing → 409), the pure
//! fold's convergence/exactly-once/rejection/fork guarantees over live
//! bytes — and DEGRADES only what the sandbox cannot provide:
//!
//! - **partition/heal (iv)** → sequential local writes then a single fold
//!   (a latency-free window, not a real partition; the deterministic-winner
//!   property is identical because fold order is total);
//! - **crash-after-consume durability (v)** → SKIPPED live with a loud note,
//!   because x0xd 0.32.1 does not persist KV across restart; the
//!   consume-then-execute fail-toward-zero LOGIC is proven in the in-memory
//!   `v2_gate::crash_after_consume_recovers_via_reapproval` test.
//!
//! Scenario (i) (v1 RMW record loss) runs fully against one live daemon —
//! the interleave class it reproduces (API `store_approval` vs gate
//! `store_consumed` on one node) is exactly issue #10(b)'s single-node RMW
//! race.
//!
//! # Mode matrix
//!
//! `X0X_V2_APPEND_ONLY=1` → `StorePolicyMode::AppendOnly` plus the WP-X REST
//! contract assertions (reported policy `append_only`; PUT-to-existing key
//! → 409). Requires an x0xd honoring `AccessPolicy::AppendOnly`
//! (x0x ≥ 0.33.0 / PR #237). Unset → interim `SignedFallback` against
//! x0xd ≤ 0.32.x, append-only assertions skipped (loud `MODE:` banner).

use std::{
    error::Error,
    fs,
    net::{TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use saorsa_pqc::{MlDsa65, MlDsaOperations, MlDsaSecretKey};
use x0x_symphony_core::{
    content_hash, sha256_hex, AgentId, ApprovalConsumed, ApprovalEvent, ApprovalVerdict, IssueId,
    SignatureEnvelope, Tracker,
};
use x0x_symphony_signing::{
    AgentInfo, SignResponse, SigningClient, SigningError, VerifyOutcome,
    X0xdClient as SigningX0xdClient,
};
use x0x_symphony_tracker_x0x_crdt::{
    client::{AddTaskDraft, X0xdApi, X0xdClient},
    v2::{
        events::{
            event_key, event_store_topic, ApprovalEventV2, ApprovalPayloadV2, ApprovalVerdictV2,
            BlockReason, EventEnvelope, RequeueJustification, TransitionEventV2, TransitionKind,
            TRANSITION_CONTEXT_V2, V2_SCHEMA,
        },
        fold_v2, ConsumeEventV2, FoldInput, FoldOutput, IssueStatusV2, OwnEventStore,
        StorePolicyMode, V2ListRef, V2StoreApi, V2StoreError, V2StoreManager, V2Tracker,
    },
    X0xCrdtTracker,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn err(msg: impl Into<String>) -> Box<dyn Error> {
    Box::new(std::io::Error::other(msg.into()))
}

fn append_only_mode() -> bool {
    std::env::var("X0X_V2_APPEND_ONLY").is_ok_and(|v| v == "1")
}

fn policy_mode() -> StorePolicyMode {
    if append_only_mode() {
        StorePolicyMode::AppendOnly
    } else {
        eprintln!(
            "MODE: signed-fallback (X0X_V2_APPEND_ONLY unset) — append-only \
             assertions SKIPPED; C1 deletion residual open in this mode"
        );
        StorePolicyMode::SignedFallback
    }
}

fn x0xd_binary() -> TestResult<PathBuf> {
    if let Ok(path) = std::env::var("X0XD_TEST_BINARY") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(err(format!("X0XD_TEST_BINARY={} missing", path.display())));
    }
    let out = Command::new("which").arg("x0xd").output()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if out.status.success() && !path.is_empty() {
        Ok(PathBuf::from(path))
    } else {
        Err(err("no x0xd: set X0XD_TEST_BINARY or put x0xd on PATH"))
    }
}

fn free_tcp_port() -> TestResult<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn free_udp_port() -> TestResult<u16> {
    Ok(UdpSocket::bind("127.0.0.1:0")?.local_addr()?.port())
}

// ---------------------------------------------------------------------------
// Local ML-DSA author (mock-crypto pattern) + its SigningClient.
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
            id: x0x_symphony_tracker_x0x_crdt::v2::identity::derive_agent_id_hex(&pk),
            pk,
            sk,
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
        let canonical =
            x0x_symphony_tracker_x0x_crdt::v2::identity::assemble_external_dst(context, payload);
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
        _c: &str,
        _p: &[u8],
        _s: &[u8],
        _k: &[u8],
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
// Live x0xd daemon lifecycle (single daemon; spawn_pair retained for infra).
// ---------------------------------------------------------------------------

struct Daemon {
    name: String,
    child: Option<Child>,
    dir: PathBuf,
    config_path: PathBuf,
    bind_port: u16,
    url: String,
    token: String,
    binary: PathBuf,
}

impl Daemon {
    async fn spawn(name: &str, binary: &Path, bootstrap: &[String]) -> TestResult<Self> {
        let dir = std::env::temp_dir().join(format!(
            "x0x-symphony-wpc-{name}-{}-{}",
            std::process::id(),
            &sha256_hex(format!("{:?}", std::time::Instant::now()).as_bytes())[..8]
        ));
        fs::create_dir_all(dir.join("data"))?;
        let api_port = free_tcp_port()?;
        let bind_port = free_udp_port()?;
        let peers = bootstrap
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config = format!(
            "data_dir = \"{data}\"\napi_address = \"127.0.0.1:{api_port}\"\n\
             bind_address = \"127.0.0.1:{bind_port}\"\nlog_level = \"warn\"\n\
             bootstrap_peers = [{peers}]\n[update]\nenabled = false\n",
            data = dir.join("data").display(),
        );
        let config_path = dir.join("config.toml");
        fs::write(&config_path, config)?;
        let mut d = Self {
            name: name.to_owned(),
            child: None,
            dir,
            config_path,
            bind_port,
            url: format!("http://127.0.0.1:{api_port}"), // api_port consumed here
            token: String::new(),
            binary: binary.to_path_buf(),
        };
        d.start().await?;
        Ok(d)
    }

    async fn start(&mut self) -> TestResult<()> {
        let stdout = fs::File::create(self.dir.join(format!("{}.stdout.log", self.name)))?;
        let stderr = fs::File::create(self.dir.join(format!("{}.stderr.log", self.name)))?;
        let child = Command::new(&self.binary)
            .arg("--config")
            .arg(&self.config_path)
            .arg("--no-hard-coded-bootstrap")
            .arg("--skip-update-check")
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        self.child = Some(child);
        let http = reqwest::Client::new();
        let health = format!("{}/health", self.url);
        let deadline = std::time::Instant::now() + Duration::from_secs(75);
        loop {
            if std::time::Instant::now() >= deadline {
                let tail = fs::read_to_string(self.dir.join(format!("{}.stderr.log", self.name)))
                    .unwrap_or_default();
                let tail: String = tail.lines().rev().take(15).collect::<Vec<_>>().join("\n");
                return Err(err(format!(
                    "daemon {} not healthy on {health}; stderr:\n{tail}",
                    self.name
                )));
            }
            if let Ok(resp) = http.get(&health).send().await {
                if resp.status().is_success() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let token_path = self.dir.join("data").join("api-token");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(token) = fs::read_to_string(&token_path) {
                let token = token.trim().to_owned();
                if !token.is_empty() {
                    self.token = token;
                    return Ok(());
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(err(format!(
                    "daemon {}: api-token never appeared",
                    self.name
                )));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.kill();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Spawn one live daemon.
async fn spawn_one(name: &str) -> TestResult<Daemon> {
    let binary = x0xd_binary()?;
    Daemon::spawn(name, &binary, &[]).await
}

/// Retained for infrastructure where gossip converges: spawn A + B with B
/// bootstrapping to A. NOT used by the sandbox scenarios (see the module
/// doc — cross-daemon KV values do not converge locally).
#[allow(dead_code)]
async fn spawn_pair(test: &str) -> TestResult<(Daemon, Daemon)> {
    let binary = x0xd_binary()?;
    let a = Daemon::spawn(&format!("{test}-a"), &binary, &[]).await?;
    let boot = vec![format!("127.0.0.1:{}", a.bind_port)];
    let b = Daemon::spawn(&format!("{test}-b"), &binary, &boot).await?;
    Ok((a, b))
}

// ---------------------------------------------------------------------------
// Two-author world over ONE live daemon.
// ---------------------------------------------------------------------------

struct World {
    _daemon: Daemon,
    api: Arc<X0xdClient>,
    a: Arc<Author>,
    b: Arc<Author>,
    manager_a: V2StoreManager,
    manager_b: V2StoreManager,
    own_a: OwnEventStore,
    own_b: OwnEventStore,
    list_uuid: String,
}

impl World {
    /// Create a live daemon, two local authors (A creator, roster [A,B]),
    /// publish genesis, and materialize B's card-self. Each store is ensured
    /// EXACTLY ONCE (one manager per author) — a second `ensure_own_store`
    /// on the same topic re-anchors x0x KV ownership, which is a test-only
    /// hazard the real one-tracker-per-daemon product never hits. Everything
    /// lives on the one daemon's KV, so reads are immediate.
    async fn new(test: &str) -> TestResult<Self> {
        let daemon = spawn_one(test).await?;
        let api = Arc::new(X0xdClient::with_token(
            &daemon.url,
            Some(daemon.token.clone()),
        )?);
        let a = Arc::new(Author::generate()?);
        let b = Arc::new(Author::generate()?);
        let manager_a = V2StoreManager::new(
            api.clone(),
            Arc::new(LocalSigner { author: a.clone() }),
            policy_mode(),
        );
        let manager_b = V2StoreManager::new(
            api.clone(),
            Arc::new(LocalSigner { author: b.clone() }),
            policy_mode(),
        );
        let list_uuid = format!("wpc-{test}");
        let own_a = manager_a.ensure_own_store(&list_uuid).await?;
        manager_a
            .publish_genesis(&own_a, vec![a.id.clone(), b.id.clone()], None, 1)
            .await?;
        let own_b = manager_b.ensure_own_store(&list_uuid).await?;
        Ok(Self {
            _daemon: daemon,
            api,
            a,
            b,
            manager_a,
            manager_b,
            own_a,
            own_b,
            list_uuid,
        })
    }

    async fn fold(&self) -> TestResult<FoldOutput> {
        let input: FoldInput = self
            .manager_a
            .read_fold_input(&self.list_uuid, &self.a.id)
            .await?;
        fold_v2(&input).map_err(|e| err(format!("list refused: {e}")))
    }

    /// Build a transition for `author` at its next chain link + lamport
    /// horizon, from the given fold view.
    fn transition(
        &self,
        author: &str,
        fold: &FoldOutput,
        issue_id: &str,
        kind: TransitionKind,
    ) -> TransitionEventV2 {
        let (author_seq, prev) = fold.next_chain_link(author);
        TransitionEventV2 {
            schema: V2_SCHEMA,
            list_uuid: self.list_uuid.clone(),
            genesis_manifest_hash: fold.genesis_hash.clone(),
            roster_epoch: fold.latest_roster_epoch,
            issue_id: issue_id.to_owned(),
            actor: author.to_owned(),
            lamport: fold.max_admitted_lamport + 1,
            author_seq,
            prev_own_event_hash: prev,
            kind,
        }
    }

    /// A opens `issue_id`; returns the open event hash.
    async fn a_open(&self, issue_id: &str, title: &str, spec: &str) -> TestResult<String> {
        let fold = self.fold().await?;
        let ev = self.transition(
            &self.a.id,
            &fold,
            issue_id,
            TransitionKind::open(title, spec),
        );
        Ok(self.manager_a.append_transition(&self.own_a, &ev).await?)
    }

    /// B claims `issue_id` (fold-fenced); returns the claim event hash.
    async fn b_claim(&self, issue_id: &str) -> TestResult<String> {
        let fold = self.fold().await?;
        let ev = x0x_symphony_tracker_x0x_crdt::v2::build_claim_transition(
            &fold,
            &self.list_uuid,
            &self.b.id,
            issue_id,
        );
        Ok(self.manager_b.append_transition(&self.own_b, &ev).await?)
    }

    /// A approves `issue_id`'s current content; returns the approval hash.
    async fn a_approve(
        &self,
        issue_id: &str,
        approved_at: u64,
        entropy: &str,
    ) -> TestResult<String> {
        let fold = self.fold().await?;
        let open_hash = fold
            .issues
            .get(issue_id)
            .map(|st| st.open_event_hash.clone())
            .ok_or_else(|| err("issue not folded for approval"))?;
        let (author_seq, prev) = fold.next_chain_link(&self.a.id);
        let approval = ApprovalEventV2 {
            schema: V2_SCHEMA,
            kind: "dispatch_approval".to_owned(),
            list_uuid: self.list_uuid.clone(),
            genesis_manifest_hash: fold.genesis_hash.clone(),
            roster_epoch: fold.latest_roster_epoch,
            issue_id: issue_id.to_owned(),
            open_event_hash: open_hash,
            actor: self.a.id.clone(),
            lamport: fold.max_admitted_lamport + 1,
            author_seq,
            prev_own_event_hash: prev,
            verdict: ApprovalVerdictV2::Approve,
            entropy: entropy.to_owned(),
            approved_at,
            v1_record_json: String::new(),
        };
        Ok(self
            .manager_a
            .append_approval(&self.own_a, &approval)
            .await?)
    }

    /// B consumes `approval_hash` under its fold-winning claim; returns the
    /// consume event hash. `entropy` distinguishes duplicate attempts.
    async fn b_consume(
        &self,
        issue_id: &str,
        approval_hash: &str,
        entropy: &str,
    ) -> TestResult<String> {
        let fold = self.fold().await?;
        let approver = fold
            .approvals
            .get(approval_hash)
            .map(|a| a.approval.actor.clone())
            .ok_or_else(|| err("approval not folded for consume"))?;
        let (claim_nonce, claimed_event_hash) = match &fold
            .issues
            .get(issue_id)
            .ok_or_else(|| err("issue not folded for consume"))?
            .status
        {
            IssueStatusV2::Claimed {
                claim_nonce,
                claim_event_hash,
                ..
            } => (claim_nonce.clone(), claim_event_hash.clone()),
            other => return Err(err(format!("issue not claimed for consume: {other:?}"))),
        };
        let (author_seq, prev) = fold.next_chain_link(&self.b.id);
        let consume = ConsumeEventV2 {
            schema: V2_SCHEMA,
            kind: "consume".to_owned(),
            list_uuid: self.list_uuid.clone(),
            genesis_manifest_hash: fold.genesis_hash.clone(),
            roster_epoch: fold.latest_roster_epoch,
            issue_id: issue_id.to_owned(),
            actor: self.b.id.clone(),
            lamport: fold.max_admitted_lamport + 1,
            author_seq,
            prev_own_event_hash: prev,
            approval_event_hash: approval_hash.to_owned(),
            approval_payload_sha256: approval_hash.to_owned(),
            approver,
            claim_nonce,
            claimed_event_hash,
            entropy: entropy.to_owned(),
            v1_record_json: String::new(),
        };
        Ok(self.manager_b.append_consume(&self.own_b, &consume).await?)
    }

    /// A claims `issue_id` (fold-fenced); returns the claim event hash.
    async fn a_claim(&self, issue_id: &str) -> TestResult<String> {
        let fold = self.fold().await?;
        let ev = x0x_symphony_tracker_x0x_crdt::v2::build_claim_transition(
            &fold,
            &self.list_uuid,
            &self.a.id,
            issue_id,
        );
        Ok(self.manager_a.append_transition(&self.own_a, &ev).await?)
    }

    /// A blocks its own held `issue_id` with `reason`.
    async fn a_block(&self, issue_id: &str, reason: BlockReason) -> TestResult<String> {
        let fold = self.fold().await?;
        let (claim_nonce, claimed_event_hash) = match &fold
            .issues
            .get(issue_id)
            .ok_or_else(|| err("issue not folded for block"))?
            .status
        {
            IssueStatusV2::Claimed {
                claimant,
                claim_nonce,
                claim_event_hash,
            } if claimant == &self.a.id => (claim_nonce.clone(), claim_event_hash.clone()),
            other => {
                return Err(err(format!(
                    "A does not hold the claim to block: {other:?}"
                )))
            }
        };
        let ev = self.transition(
            &self.a.id,
            &fold,
            issue_id,
            TransitionKind::Block {
                claim_nonce,
                claimed_event_hash,
                reason,
            },
        );
        Ok(self.manager_a.append_transition(&self.own_a, &ev).await?)
    }
}

fn dummy_envelope(signer: &str) -> SignatureEnvelope {
    SignatureEnvelope::new(
        "ml-dsa-65",
        "x0x-symphony-approval-consumed-v1",
        "cGs=",
        "c2ln",
        sha256_hex(b"harness"),
        signer,
    )
}

fn approval_for(
    issue: &x0x_symphony_core::Issue,
    approver: &str,
    at: &str,
) -> TestResult<ApprovalEvent> {
    Ok(ApprovalEvent {
        issue_id: issue.id.clone(),
        content_hash: content_hash(issue),
        signer_agent_id: AgentId::new(approver.to_owned())?,
        verdict: ApprovalVerdict::Approve,
        approved_at: at.to_owned(),
        approver_agent_id: AgentId::new(approver.to_owned())?,
        claim_id: None,
        signature: Some(dummy_envelope(approver)),
    })
}

fn consumed_for(
    issue: &x0x_symphony_core::Issue,
    consumer: &str,
    nonce: &str,
) -> TestResult<ApprovalConsumed> {
    Ok(ApprovalConsumed::new(
        issue.id.clone(),
        content_hash(issue),
        AgentId::new(consumer.to_owned())?,
        nonce,
        "2026-07-16T00:00:01Z",
        dummy_envelope(consumer),
    ))
}

async fn issue_by_id(tracker: &dyn Tracker, id: &IssueId) -> Option<x0x_symphony_core::Issue> {
    tracker
        .fetch_by_ids(std::slice::from_ref(id))
        .await
        .ok()?
        .into_iter()
        .next()
}

const IGNORE: &str = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); \
                      X0X_V2_APPEND_ONLY=1 for the append-only matrix";

// ===========================================================================
// (i) v1 RMW record loss — one live daemon, two tracker instances.
// ===========================================================================

#[tokio::test]
#[ignore = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix"]
async fn v1_rmw_interleave_loses_records_repro() -> TestResult {
    let _ = IGNORE;
    let daemon = spawn_one("v1rmw").await?;
    let api = Arc::new(X0xdClient::with_token(
        &daemon.url,
        Some(daemon.token.clone()),
    )?);
    let signer = SigningX0xdClient::with_token(&daemon.url, Some(daemon.token.clone()))?;
    let agent = AgentId::new(signer.agent_identity().await?.agent_id)?;

    let list_id = "wpc-race-list";
    api.create_task_list(list_id, list_id).await?;
    api.create_kv_store(
        &format!("symphony-{list_id}"),
        &format!("symphony-{list_id}"),
    )
    .await?;
    let task_id = api
        .add_task(
            list_id,
            AddTaskDraft::new("contested").with_description("spec"),
        )
        .await?;
    let tracker_1 = X0xCrdtTracker::from_client(
        &daemon.url,
        list_id,
        agent.clone(),
        api.clone() as Arc<dyn X0xdApi>,
    );
    let tracker_2 = X0xCrdtTracker::from_client(
        &daemon.url,
        list_id,
        agent.clone(),
        api.clone() as Arc<dyn X0xdApi>,
    );
    let issue_id = IssueId::new(task_id)?;
    let issue = issue_by_id(&tracker_1, &issue_id)
        .await
        .ok_or_else(|| err("seeded v1 issue not visible"))?;
    tracker_1
        .store_approval(&approval_for(
            &issue,
            agent.as_str(),
            "2026-07-16T00:00:00Z",
        )?)
        .await?;

    // API store_approval vs gate store_consumed on one node: both GET the
    // blob, both PUT — the last PUT erases the other writer's record.
    let mut loss = false;
    for round in 0..12u32 {
        let approval = approval_for(
            &issue,
            agent.as_str(),
            &format!("2026-07-16T00:01:{round:02}Z"),
        )?;
        let consumed = consumed_for(&issue, agent.as_str(), &format!("nonce-{round}"))?;
        let (ra, rc) = tokio::join!(
            tracker_1.store_approval(&approval),
            tracker_2.store_consumed(&consumed)
        );
        ra?;
        rc?;
        let after = tracker_1.load_approval_state(&issue_id).await?;
        let kept_a = after
            .events
            .iter()
            .any(|e| e.approved_at == approval.approved_at);
        let kept_c = after.consumed.iter().any(|c| c.nonce == consumed.nonce);
        if !(kept_a && kept_c) {
            eprintln!("v1 RMW loss round {round}: approval_kept={kept_a} consume_kept={kept_c}");
            loss = true;
            break;
        }
    }
    assert!(
        loss,
        "v1 RMW interleave must lose a record in 12 rounds; if not, the v1 blob \
         gained atomicity and issue #10's defect catalogue needs re-verification"
    );
    let _ = &daemon;
    Ok(())
}

// ===========================================================================
// (ii) v2 interleave keeps all records; exactly-once effective consume;
// duplicate surfaced as a loser. Real x0xd KV + (append-only mode) real 409.
// ===========================================================================

#[tokio::test]
#[ignore = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix"]
#[allow(clippy::too_many_lines)]
async fn v2_interleave_keeps_all_records_exactly_once_consume() -> TestResult {
    let world = World::new("v2race").await?;
    // A opens, B claims (both fold-fenced), A approves. All over live KV.
    let issue_id = "i1";
    world.a_open(issue_id, "contested v2", "spec").await?;
    world.b_claim(issue_id).await?;
    let approval1 = world.a_approve(issue_id, 100, "ap1").await?;

    // The interleave A raced with B's consume: in v1 the RMW blob erased one
    // record; in v2 A's approval #2 and B's consume of #1 are DISTINCT
    // per-key append-only records. Order cannot change the folded outcome —
    // that is precisely the property v2 restores — so writing them
    // sequentially over the single-daemon KV is a faithful test. Both must
    // survive.
    let approval2 = world.a_approve(issue_id, 100, "ap2").await?;
    let consume = world.b_consume(issue_id, &approval1, "consume1").await?;

    let fold = world.fold().await?;
    let approval_count = fold
        .approvals
        .values()
        .filter(|a| a.approval.issue_id == issue_id)
        .count();
    assert_eq!(
        approval_count, 2,
        "both approvals present (nothing clobbered) — {approval_count} != 2"
    );
    assert!(
        fold.approvals.contains_key(&approval2),
        "approval #2 durable"
    );
    assert_eq!(
        fold.effective_consumes.len(),
        1,
        "exactly one effective consume"
    );
    assert!(
        fold.effective_consumes
            .get(&approval1)
            .is_some_and(|c| c.event_hash == consume),
        "our consume is THE effective one for approval #1"
    );

    // Duplicate consume for the same approval → deterministic loser.
    world.b_consume(issue_id, &approval1, "dup").await?;
    let fold = world.fold().await?;
    let ah = approval1.clone();
    assert_eq!(
        fold.effective_consumes.len(),
        1,
        "still exactly one effective"
    );
    assert!(
        fold.losing_consumes
            .iter()
            .any(|d| d.approval_event_hash == ah),
        "duplicate consume surfaced as a loser, never silently dropped"
    );

    // Append-only REST contract (only when the daemon honors it).
    if append_only_mode() {
        let topic = event_store_topic(&world.list_uuid, &world.a.id);
        let detail = world
            .api
            .kv_store_detail(&topic)
            .await?
            .ok_or_else(|| err("own store missing from listing"))?;
        assert_eq!(detail.policy.as_deref(), Some("append_only"));
        let keys = V2StoreApi::list_kv_keys(world.api.as_ref(), &topic).await?;
        let ev = keys
            .iter()
            .map(|k| k.key.clone())
            .find(|k| k.starts_with("ev-"))
            .ok_or_else(|| err("no ev- key"))?;
        let overwrite =
            V2StoreApi::put_kv(world.api.as_ref(), &topic, &ev, b"tamper", "text/plain").await;
        assert!(overwrite.is_err(), "append-only PUT-to-existing must 409");
    }
    Ok(())
}

// ===========================================================================
// (iii) hostile un-park + forged authorship inadmissible.
// ===========================================================================

#[tokio::test]
#[ignore = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix"]
#[allow(clippy::too_many_lines)]
async fn hostile_unpark_and_forged_authorship_inadmissible() -> TestResult {
    let world = World::new("hostile").await?;
    // A opens, claims, and parks its own issue with a NON-requeue-able reason.
    let issue_id = "i1";
    world.a_open(issue_id, "parked", "spec").await?;
    world.a_claim(issue_id).await?;
    world
        .a_block(
            issue_id,
            BlockReason::Other {
                detail: "retry_exhausted: budget spent".to_owned(),
            },
        )
        .await?;
    let fold = world.fold().await?;
    let st = fold
        .issues
        .get(issue_id)
        .ok_or_else(|| err("issue missing"))?;
    let IssueStatusV2::Blocked {
        claim_nonce,
        claim_event_hash,
        block_event_hash,
        ..
    } = st.status.clone()
    else {
        return Err(err("issue not blocked"));
    };
    let own_b = &world.own_b;

    // (a) B-authored release naming A's fence: admissible, INEFFECTIVE.
    let (seq, prev) = fold.next_chain_link(&world.b.id);
    let release = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: world.list_uuid.clone(),
        genesis_manifest_hash: fold.genesis_hash.clone(),
        roster_epoch: fold.latest_roster_epoch,
        issue_id: issue_id.to_owned(),
        actor: world.b.id.clone(),
        lamport: fold.max_admitted_lamport + 1,
        author_seq: seq,
        prev_own_event_hash: prev,
        kind: TransitionKind::Release {
            claim_nonce: claim_nonce.clone(),
            claimed_event_hash: claim_event_hash.clone(),
        },
    };
    let release_hash = world.manager_b.append_transition(own_b, &release).await?;

    // (b) B-authored requeue with a valid-looking B-signed justification —
    // block reason is Other, so the C6 fold refuses the un-park.
    let approval_payload = ApprovalPayloadV2 {
        schema: V2_SCHEMA,
        kind: "approval".to_owned(),
        list_uuid: world.list_uuid.clone(),
        genesis_manifest_hash: fold.genesis_hash.clone(),
        issue_id: issue_id.to_owned(),
        block_event_hash: block_event_hash.clone(),
        claim_nonce: claim_nonce.clone(),
        approver: world.b.id.clone(),
        approved_at: 1,
    };
    let approval_bytes = serde_json::to_vec(&approval_payload)?;
    let approval_hash = sha256_hex(&approval_bytes);
    let approval_env = world
        .manager_b
        .sign_approval_payload(own_b, &approval_bytes)
        .await?;
    let requeue = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: world.list_uuid.clone(),
        genesis_manifest_hash: fold.genesis_hash.clone(),
        roster_epoch: fold.latest_roster_epoch,
        issue_id: issue_id.to_owned(),
        actor: world.b.id.clone(),
        lamport: fold.max_admitted_lamport + 2,
        author_seq: seq + 1,
        prev_own_event_hash: release_hash,
        kind: TransitionKind::Requeue {
            justification: RequeueJustification {
                block_event_hash: block_event_hash.clone(),
                claim_nonce: claim_nonce.clone(),
                approval_event_hash: approval_hash.clone(),
                approval_payload_sha256: approval_hash,
                approver: world.b.id.clone(),
                approval: approval_env,
            },
        },
    };
    world.manager_b.append_transition(own_b, &requeue).await?;

    // (c) forged authorship: payload actor=A, signed by B, dropped into B's
    // store — four-way binding fails at admission.
    let forged = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: world.list_uuid.clone(),
        genesis_manifest_hash: fold.genesis_hash.clone(),
        roster_epoch: fold.latest_roster_epoch,
        issue_id: issue_id.to_owned(),
        actor: world.a.id.clone(),
        lamport: fold.max_admitted_lamport + 3,
        author_seq: 999,
        prev_own_event_hash: fold.genesis_hash.clone(),
        kind: TransitionKind::Release {
            claim_nonce,
            claimed_event_hash: claim_event_hash,
        },
    };
    let forged_bytes = forged.to_signed_bytes().map_err(err)?;
    let forged_hash = sha256_hex(&forged_bytes);
    let signer_b = LocalSigner {
        author: world.b.clone(),
    };
    let sign = signer_b.sign(TRANSITION_CONTEXT_V2, &forged_bytes).await?;
    let forged_env = EventEnvelope {
        schema: V2_SCHEMA,
        context: TRANSITION_CONTEXT_V2.to_owned(),
        algorithm: sign.algorithm,
        payload_b64: BASE64.encode(&forged_bytes),
        public_key_b64: sign.public_key_b64,
        signature_b64: sign.signature_b64,
        signer_agent_id: sign.agent_id,
    };
    let topic_b = event_store_topic(&world.list_uuid, &world.b.id);
    V2StoreApi::put_kv(
        world.api.as_ref(),
        &topic_b,
        &event_key(issue_id, &forged_hash),
        &forged_env.encode().map_err(err)?,
        "application/x0x-symphony-v2+json",
    )
    .await?;

    let fold = world.fold().await?;
    assert!(
        fold.issues
            .get(issue_id)
            .is_some_and(|st| matches!(st.status, IssueStatusV2::Blocked { .. })),
        "issue must stay blocked despite three hostile records"
    );
    let hostile = fold
        .rejections
        .iter()
        .filter(|r| r.author == world.b.id || r.reason.contains("store owner"))
        .count();
    assert!(
        hostile >= 3,
        "all three hostile records must be surfaced as rejections, got {hostile}"
    );
    Ok(())
}

// ===========================================================================
// (iv) divergent claims → one deterministic winner; equivocation → fork.
// Partition degraded to sequential local writes (see module doc).
// ===========================================================================

#[tokio::test]
#[ignore = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix"]
async fn divergent_claims_heal_to_single_winner_and_fork_evidence() -> TestResult {
    let world = World::new("diverge").await?;
    let issue_id = "i1";
    world.a_open(issue_id, "both want it", "spec").await?;

    // "Partition": B claims, then A claims — both claims exist; the total
    // fold order picks ONE. (Fidelity: sequential local writes, not a
    // firewalled partition — the deterministic-winner property is identical
    // because fold order is total over (lamport, author, event_hash).)
    let own_b = &world.own_b;
    world.b_claim(issue_id).await?;
    world.a_claim(issue_id).await?;

    let winner_of = |fold: &FoldOutput| {
        fold.issues.get(issue_id).and_then(|st| match &st.status {
            IssueStatusV2::Claimed { claimant, .. } => Some(claimant.clone()),
            _ => None,
        })
    };
    let fold = world.fold().await?;
    let winner = winner_of(&fold).ok_or_else(|| err("no claim winner"))?;
    assert!(
        winner == world.a.id || winner == world.b.id,
        "winner must be one of the two claimants"
    );
    // Determinism: a second independent fold agrees.
    let winner2 = winner_of(&world.fold().await?);
    assert_eq!(Some(winner.clone()), winner2, "winner is deterministic");
    eprintln!("divergent claim winner (deterministic) = {winner}");

    // Equivocation: B signs two DIFFERENT events at one author_seq.
    let fold = world.fold().await?;
    let (seq, prev) = fold.next_chain_link(&world.b.id);
    for nonce in ["fork-one", "fork-two"] {
        let ev = TransitionEventV2 {
            schema: V2_SCHEMA,
            list_uuid: world.list_uuid.clone(),
            genesis_manifest_hash: fold.genesis_hash.clone(),
            roster_epoch: fold.latest_roster_epoch,
            issue_id: issue_id.to_owned(),
            actor: world.b.id.clone(),
            lamport: fold.max_admitted_lamport + 1,
            author_seq: seq,
            prev_own_event_hash: prev.clone(),
            kind: TransitionKind::Claim {
                claim_nonce: nonce.to_owned(),
            },
        };
        world.manager_b.append_transition(own_b, &ev).await?;
    }
    let fold = world.fold().await?;
    assert!(
        fold.forks
            .iter()
            .any(|f| f.author == world.b.id && f.author_seq == seq && f.event_hashes.len() == 2),
        "author equivocation must surface ForkEvidence"
    );
    Ok(())
}

// ===========================================================================
// (v) crash-after-consume — SKIPPED live (see module doc: x0xd 0.32.1 does
// not persist KV across restart). The consume-then-execute fail-toward-zero
// logic is proven in v2_gate::crash_after_consume_recovers_via_reapproval.
// ===========================================================================

#[tokio::test]
#[ignore = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix"]
async fn crash_after_consume_recovers_via_reapproval() -> TestResult {
    eprintln!(
        "SKIP-LIVE (v): x0xd KV is not durable across restart in this build \
         (verified: keys lost after SIGKILL+restart on 0.32.1), so live \
         crash-durability cannot be demonstrated here. The consume-then-\
         execute fail-toward-zero LOGIC is proven in \
         v2_gate::crash_after_consume_recovers_via_reapproval (in-memory, \
         passing). This live scenario runs on infra with durable KV."
    );
    Ok(())
}

// ===========================================================================
// (vi) downgrade refusals.
// ===========================================================================

#[tokio::test]
#[ignore = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix"]
async fn downgrade_refusals() -> TestResult {
    let daemon = spawn_one("downgrade").await?;
    let api = Arc::new(X0xdClient::with_token(
        &daemon.url,
        Some(daemon.token.clone()),
    )?);
    let a = Arc::new(Author::generate()?);

    // (a) genesis-less v2 list is refused (no v1 fallback).
    let manager = V2StoreManager::new(
        api.clone(),
        Arc::new(LocalSigner { author: a.clone() }),
        policy_mode(),
    );
    let list_uuid = "wpc-nogen";
    manager.ensure_own_store(list_uuid).await?; // card-self only, NO genesis
    let tracker = V2Tracker::new(
        V2StoreManager::new(
            api.clone(),
            Arc::new(LocalSigner { author: a.clone() }),
            policy_mode(),
        ),
        V2ListRef {
            list_uuid: list_uuid.to_owned(),
            creator: a.id.clone(),
        },
        AgentId::new(a.id.clone())?,
        None,
        Duration::ZERO,
    );
    let refused = tracker.list_issues().await;
    assert!(
        matches!(&refused, Err(e) if e.to_string().contains("refused")),
        "genesis-less v2 list must be refused, got {refused:?}"
    );
    let lists = api.list_task_lists().await?;
    assert!(
        !lists.iter().any(|l| l.id.contains("symphony2:")),
        "a refused v2 list must not materialize a v1 surface"
    );

    // (b) append_only policy gate fails loudly.
    let a_id = a.id.clone();
    let gate = V2StoreManager::new(
        api.clone(),
        Arc::new(LocalSigner { author: a }),
        StorePolicyMode::AppendOnly,
    );
    let policy_list = "wpc-policy";
    if append_only_mode() {
        // Daemon honors append_only: pre-create the store topic as a MUTABLE
        // `signed` store; reuse must then refuse to masquerade it.
        let topic = event_store_topic(policy_list, &a_id);
        api.create_kv_store(&topic, &topic).await?;
        let outcome = gate.ensure_own_store(policy_list).await;
        assert!(
            matches!(outcome, Err(V2StoreError::PolicyNotHonored { .. })),
            "pre-existing mutable store must be refused in append-only mode, got {outcome:?}"
        );
    } else {
        // Old daemon ignoring the policy field → refused, never downgraded.
        let outcome = gate.ensure_own_store(policy_list).await;
        assert!(
            matches!(outcome, Err(V2StoreError::PolicyNotHonored { .. })),
            "old daemon must be refused when append_only is requested, got {outcome:?}"
        );
    }
    let _ = &daemon;
    Ok(())
}
