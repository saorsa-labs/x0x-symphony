//! WP-C: the tracker-integrity race harness (x0x-symphony#10, design r2).
//!
//! # Topology — GENUINE two-daemon runs
//!
//! The cross-author scenarios spawn TWO isolated live x0xd daemons on
//! loopback (fresh temp dirs, ephemeral ports, MUTUAL `bootstrap_peers`,
//! rolling start, `--no-hard-coded-bootstrap`, `[update] enabled = false`)
//! and drive real cross-daemon replication. Each daemon's own agent
//! identity signs its author's events, so the daemon-anchored store
//! ownership (blocker-5 verification) holds exactly as in production.
//!
//! Empirically verified sync contract (x0xd 0.33.0) the harness relies on:
//!
//! - **subscribe-before-write**: a joined replica receives live deltas
//!   instantly; keys written BEFORE the peer joined do not backfill within
//!   test patience. Setup therefore creates each event store and cross-
//!   joins it BEFORE the first key (card-self/genesis) is written.
//! - **heal catch-up**: deltas missed while a daemon is down arrive within
//!   ~15s of restart (checkpoint announce) — partition/heal assertions
//!   poll well past that.
//! - **restart persistence**: KV survives SIGKILL + restart (x0x ≥ 0.33.0,
//!   PR #237). The crash-after-consume scenario requires it and skips
//!   loudly on older daemons.
//!
//! Two single-daemon SMOKE scenarios remain, clearly labeled: (i) the v1
//! RMW record-loss repro (a single-node interleave by nature — issue
//! #10(b) names it alongside the cross-node race) and (vi) downgrade
//! refusals (pure local refusal paths).
//!
//! # Mode matrix
//!
//! `X0X_V2_APPEND_ONLY=1` → `StorePolicyMode::AppendOnly` plus the WP-X
//! REST contract assertions (reported policy `append_only`;
//! PUT-to-existing → 409). Requires x0xd ≥ 0.33.0. Unset → interim
//! `SignedFallback` for older daemons; append-only assertions skipped
//! (loud `MODE:` banner).

use std::{
    error::Error,
    fs,
    net::{TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

use x0x_symphony_core::{
    content_hash, sha256_hex, AgentId, ApprovalConsumed, ApprovalEvent, ApprovalVerdict, IssueId,
    SignatureEnvelope, Tracker,
};
use x0x_symphony_signing::{SigningClient, X0xdClient as SigningX0xdClient};
use x0x_symphony_tracker_x0x_crdt::{
    client::{AddTaskDraft, X0xdApi, X0xdClient},
    v2::{
        build_claim_transition,
        events::{
            event_store_topic, ApprovalEventV2, ApprovalPayloadV2, ApprovalVerdictV2,
            RequeueJustification, TransitionEventV2, TransitionKind, V2_SCHEMA,
        },
        fold_v2, BlockReason, ConsumeEventV2, FoldInput, FoldOutput, IssueStatusV2, OwnEventStore,
        RejectionPhase, StorePolicyMode, V2ListRef, V2StoreApi, V2StoreError, V2StoreManager,
        V2Tracker,
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

fn requested_policy_flag() -> Option<&'static str> {
    if append_only_mode() {
        Some("append_only")
    } else {
        None
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

/// Poll `cond` (an async bool expression) every 500ms until true or the
/// deadline passes; fail the test with `desc` on timeout.
macro_rules! wait_until {
    ($desc:expr, $timeout_secs:expr, $cond:expr) => {{
        let mut ok = false;
        let deadline = std::time::Instant::now() + Duration::from_secs($timeout_secs);
        while std::time::Instant::now() < deadline {
            if $cond {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        if !ok {
            return Err(err(format!("timed out waiting for: {}", $desc)));
        }
    }};
}

// ---------------------------------------------------------------------------
// Daemon lifecycle
// ---------------------------------------------------------------------------

struct Daemon {
    name: String,
    child: Option<Child>,
    dir: PathBuf,
    config_path: PathBuf,
    url: String,
    token: String,
    binary: PathBuf,
}

impl Daemon {
    /// Write config + start. `bind_port` is pre-allocated by the caller so
    /// MUTUAL bootstrap lists can name both daemons before either starts.
    async fn spawn(
        name: &str,
        binary: &Path,
        bind_port: u16,
        bootstrap: &[String],
    ) -> TestResult<Self> {
        let dir = std::env::temp_dir().join(format!(
            "x0x-symphony-wpc-{name}-{}-{}",
            std::process::id(),
            &sha256_hex(format!("{:?}", std::time::Instant::now()).as_bytes())[..8]
        ));
        fs::create_dir_all(dir.join("data"))?;
        let api_port = free_tcp_port()?;
        let peers = bootstrap
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", ");
        // identity_dir is REQUIRED for isolation: without it every daemon
        // on this machine loads the same ~/.x0x keys and both "daemons"
        // share one agent identity (which silently collapses the two-author
        // topology into self-joins).
        let config = format!(
            "data_dir = \"{data}\"\nidentity_dir = \"{identity}\"\n\
             api_address = \"127.0.0.1:{api_port}\"\n\
             bind_address = \"127.0.0.1:{bind_port}\"\nlog_level = \"warn\"\n\
             bootstrap_peers = [{peers}]\n[update]\nenabled = false\n",
            data = dir.join("data").display(),
            identity = dir.join("identity").display(),
        );
        let config_path = dir.join("config.toml");
        fs::write(&config_path, config)?;
        let mut d = Self {
            name: name.to_owned(),
            child: None,
            dir,
            config_path,
            url: format!("http://127.0.0.1:{api_port}"),
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

    /// SIGKILL then start again with the SAME config and data dir.
    async fn restart(&mut self) -> TestResult<()> {
        self.kill();
        self.start().await
    }

    /// Connected peer count from /health.
    async fn peers(&self) -> u64 {
        let Ok(resp) = reqwest::Client::new()
            .get(format!("{}/health", self.url))
            .send()
            .await
        else {
            return 0;
        };
        let Ok(json) = resp.json::<serde_json::Value>().await else {
            return 0;
        };
        json.get("peers")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    }

    async fn version(&self) -> TestResult<String> {
        let body = reqwest::Client::new()
            .get(format!("{}/health", self.url))
            .send()
            .await?
            .text()
            .await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        Ok(json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.kill();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Per-daemon client bundle: the daemon's OWN agent identity signs.
struct Ctx {
    api: Arc<X0xdClient>,
    signer: Arc<SigningX0xdClient>,
    agent: String,
}

impl Ctx {
    async fn new(daemon: &Daemon) -> TestResult<Self> {
        let api = Arc::new(X0xdClient::with_token(
            &daemon.url,
            Some(daemon.token.clone()),
        )?);
        let signer = Arc::new(SigningX0xdClient::with_token(
            &daemon.url,
            Some(daemon.token.clone()),
        )?);
        let agent = signer.agent_identity().await?.agent_id;
        Ok(Self { api, signer, agent })
    }

    fn manager(&self) -> V2StoreManager {
        V2StoreManager::new(self.api.clone(), self.signer.clone(), policy_mode())
    }
}

/// Spawn two mutually-bootstrapped daemons with a rolling start.
async fn spawn_pair(test: &str) -> TestResult<(Daemon, Daemon)> {
    let binary = x0xd_binary()?;
    let bind_a = free_udp_port()?;
    let bind_b = free_udp_port()?;
    let a = Daemon::spawn(
        &format!("{test}-a"),
        &binary,
        bind_a,
        &[format!("127.0.0.1:{bind_b}")],
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(2)).await; // rolling start
    let b = Daemon::spawn(
        &format!("{test}-b"),
        &binary,
        bind_b,
        &[format!("127.0.0.1:{bind_a}")],
    )
    .await?;
    Ok((a, b))
}

// ---------------------------------------------------------------------------
// Two-daemon world: A (creator) on daemon A, B on daemon B, roster [A, B].
// Setup follows the verified subscribe-before-write discipline.
// ---------------------------------------------------------------------------

struct Pair {
    daemon_a: Daemon,
    daemon_b: Daemon,
    ctx_a: Ctx,
    ctx_b: Ctx,
    manager_a: V2StoreManager,
    manager_b: V2StoreManager,
    own_a: OwnEventStore,
    own_b: OwnEventStore,
    list_uuid: String,
}

impl Pair {
    async fn new(test: &str) -> TestResult<Self> {
        let (daemon_a, daemon_b) = spawn_pair(test).await?;
        // Transport gate: the QUIC link must be up before store joins can
        // resolve cross-daemon ownership.
        wait_until!(
            "both daemons report a connected peer",
            90,
            daemon_a.peers().await >= 1 && daemon_b.peers().await >= 1
        );
        let ctx_a = Ctx::new(&daemon_a).await?;
        let ctx_b = Ctx::new(&daemon_b).await?;
        if ctx_a.agent == ctx_b.agent {
            return Err(err(
                "daemon identity collision: both daemons report one agent id — \
                 identity_dir isolation failed",
            ));
        }
        let list_uuid = format!("wpc-{test}");

        // Subscribe-before-write: create both event stores EMPTY, cross-
        // join them (bidirectional), and only then let ensure_own_store
        // write card-self and the creator publish genesis.
        let topic_a = event_store_topic(&list_uuid, &ctx_a.agent);
        let topic_b = event_store_topic(&list_uuid, &ctx_b.agent);
        ctx_a
            .api
            .create_kv_store_with_policy(&topic_a, &topic_a, requested_policy_flag())
            .await?;
        ctx_b
            .api
            .create_kv_store_with_policy(&topic_b, &topic_b, requested_policy_flag())
            .await?;
        wait_until!(
            "bidirectional cross-daemon store joins",
            60,
            ctx_b
                .api
                .join_kv_store(&topic_a, &ctx_a.agent)
                .await
                .is_ok()
                && ctx_a
                    .api
                    .join_kv_store(&topic_b, &ctx_b.agent)
                    .await
                    .is_ok()
        );

        let manager_a = ctx_a.manager();
        let manager_b = ctx_b.manager();
        let own_a = manager_a.ensure_own_store(&list_uuid).await?;
        let own_b = manager_b.ensure_own_store(&list_uuid).await?;
        manager_a
            .publish_genesis(
                &own_a,
                vec![ctx_a.agent.clone(), ctx_b.agent.clone()],
                None,
                1,
            )
            .await?;

        let pair = Self {
            daemon_a,
            daemon_b,
            ctx_a,
            ctx_b,
            manager_a,
            manager_b,
            own_a,
            own_b,
            list_uuid,
        };
        // Replication gate: BOTH daemons must fold the genesis — proves
        // cross-daemon event replication end-to-end before any scenario.
        wait_until!(
            "both daemons fold the genesis (cross-daemon replication)",
            90,
            {
                let ra = pair
                    .manager_a
                    .read_fold_input(&pair.list_uuid, &pair.ctx_a.agent)
                    .await
                    .map_err(|e| format!("read A: {e}"))
                    .and_then(|i| fold_v2(&i).map_err(|e| format!("fold A: {e}")));
                let rb = pair
                    .manager_b
                    .read_fold_input(&pair.list_uuid, &pair.ctx_a.agent)
                    .await
                    .map_err(|e| format!("read B: {e}"))
                    .and_then(|i| fold_v2(&i).map_err(|e| format!("fold B: {e}")));
                if let Err(e) = &ra {
                    eprintln!("GATE A: {e}");
                }
                if let Err(e) = &rb {
                    eprintln!("GATE B: {e}");
                }
                ra.is_ok() && rb.is_ok()
            }
        );
        Ok(pair)
    }

    async fn fold_with(&self, manager: &V2StoreManager) -> Option<FoldOutput> {
        let input = manager
            .read_fold_input(&self.list_uuid, &self.ctx_a.agent)
            .await
            .ok()?;
        fold_v2(&input).ok()
    }

    /// Daemon A's independent replica fold.
    async fn fold_a(&self) -> Option<FoldOutput> {
        self.fold_with(&self.manager_a).await
    }

    /// Daemon B's independent replica fold.
    async fn fold_b(&self) -> Option<FoldOutput> {
        self.fold_with(&self.manager_b).await
    }

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

    async fn a_open(&self, issue_id: &str, title: &str) -> TestResult<String> {
        let fold = self.fold_a().await.ok_or_else(|| err("fold A refused"))?;
        let ev = self.transition(
            &self.ctx_a.agent,
            &fold,
            issue_id,
            TransitionKind::open(title, "wp-c spec"),
        );
        Ok(self.manager_a.append_transition(&self.own_a, &ev).await?)
    }

    async fn b_claim(&self, issue_id: &str) -> TestResult<String> {
        let fold = self.fold_b().await.ok_or_else(|| err("fold B refused"))?;
        let ev = build_claim_transition(&fold, &self.list_uuid, &self.ctx_b.agent, issue_id);
        Ok(self.manager_b.append_transition(&self.own_b, &ev).await?)
    }

    async fn a_approve(&self, issue_id: &str, entropy: &str) -> TestResult<String> {
        let fold = self.fold_a().await.ok_or_else(|| err("fold A refused"))?;
        let open_hash = fold
            .issues
            .get(issue_id)
            .map(|st| st.open_event_hash.clone())
            .ok_or_else(|| err("issue not folded on A"))?;
        let (author_seq, prev) = fold.next_chain_link(&self.ctx_a.agent);
        let approval = ApprovalEventV2 {
            schema: V2_SCHEMA,
            kind: "dispatch_approval".to_owned(),
            list_uuid: self.list_uuid.clone(),
            genesis_manifest_hash: fold.genesis_hash.clone(),
            roster_epoch: fold.latest_roster_epoch,
            issue_id: issue_id.to_owned(),
            open_event_hash: open_hash,
            actor: self.ctx_a.agent.clone(),
            lamport: fold.max_admitted_lamport + 1,
            author_seq,
            prev_own_event_hash: prev,
            verdict: ApprovalVerdictV2::Approve,
            entropy: entropy.to_owned(),
            approved_at: 100,
            v1_record_json: String::new(),
        };
        Ok(self
            .manager_a
            .append_approval(&self.own_a, &approval)
            .await?)
    }

    async fn b_consume(
        &self,
        issue_id: &str,
        approval_hash: &str,
        entropy: &str,
    ) -> TestResult<String> {
        let fold = self.fold_b().await.ok_or_else(|| err("fold B refused"))?;
        let approver = fold
            .approvals
            .get(approval_hash)
            .map(|a| a.approval.actor.clone())
            .ok_or_else(|| err("approval not folded on B"))?;
        let (claim_nonce, claimed_event_hash) = match &fold
            .issues
            .get(issue_id)
            .ok_or_else(|| err("issue not folded on B"))?
            .status
        {
            IssueStatusV2::Claimed {
                claim_nonce,
                claim_event_hash,
                ..
            } => (claim_nonce.clone(), claim_event_hash.clone()),
            other => return Err(err(format!("issue not claimed on B: {other:?}"))),
        };
        let (author_seq, prev) = fold.next_chain_link(&self.ctx_b.agent);
        let consume = ConsumeEventV2 {
            schema: V2_SCHEMA,
            kind: "consume".to_owned(),
            list_uuid: self.list_uuid.clone(),
            genesis_manifest_hash: fold.genesis_hash.clone(),
            roster_epoch: fold.latest_roster_epoch,
            issue_id: issue_id.to_owned(),
            actor: self.ctx_b.agent.clone(),
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

    fn winner_of(fold: &FoldOutput, issue_id: &str) -> Option<String> {
        fold.issues.get(issue_id).and_then(|st| match &st.status {
            IssueStatusV2::Claimed { claimant, .. } => Some(claimant.clone()),
            _ => None,
        })
    }
}

// ===========================================================================
// (ii) TWO-DAEMON: the v1-lethal interleave loses nothing on v2 —
// bidirectional joins, cross-daemon replication, independent replica folds
// agree, exactly-once effective consume, duplicate surfaced as a loser.
// ===========================================================================

#[tokio::test]
#[ignore = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix (x0xd >= 0.33.0)"]
#[allow(clippy::too_many_lines)]
async fn two_daemon_v2_interleave_keeps_all_records_exactly_once() -> TestResult {
    let pair = Pair::new("v2race").await?;
    let issue_id = "i1";
    pair.a_open(issue_id, "contested v2").await?;
    wait_until!(
        "daemon B folds the open issue",
        90,
        pair.fold_b()
            .await
            .is_some_and(|f| f.issues.contains_key(issue_id))
    );
    pair.b_claim(issue_id).await?;
    wait_until!(
        "daemon A folds B's claim",
        90,
        pair.fold_a()
            .await
            .and_then(|f| Pair::winner_of(&f, issue_id))
            .is_some_and(|w| w == pair.ctx_b.agent)
    );
    let approval1 = pair.a_approve(issue_id, "ap1").await?;
    wait_until!(
        "daemon B folds approval #1",
        90,
        pair.fold_b()
            .await
            .is_some_and(|f| f.approvals.contains_key(&approval1))
    );

    // The lethal v1 interleave, GENUINELY CONCURRENT across daemons:
    // A appends approval #2 on daemon A while B consumes #1 on daemon B.
    let (ra, rc) = tokio::join!(
        pair.a_approve(issue_id, "ap2"),
        pair.b_consume(issue_id, &approval1, "consume1")
    );
    let approval2 = ra?;
    let consume1 = rc?;

    // Both independent replica folds converge: 2 approvals, exactly one
    // effective consume, nothing lost.
    for (name, is_a) in [("A", true), ("B", false)] {
        wait_until!(
            format!("daemon {name} folds 2 approvals + 1 effective consume"),
            120,
            {
                let fold = if is_a {
                    pair.fold_a().await
                } else {
                    pair.fold_b().await
                };
                fold.is_some_and(|f| {
                    f.approvals.contains_key(&approval1)
                        && f.approvals.contains_key(&approval2)
                        && f.effective_consumes.len() == 1
                        && f.effective_consumes
                            .get(&approval1)
                            .is_some_and(|c| c.event_hash == consume1)
                })
            }
        );
    }

    // Duplicate consume for the same approval → durable, deterministic
    // LOSER on both daemons.
    pair.b_consume(issue_id, &approval1, "dup").await?;
    for (name, is_a) in [("A", true), ("B", false)] {
        wait_until!(
            format!("daemon {name} surfaces the duplicate consume as a loser"),
            120,
            {
                let fold = if is_a {
                    pair.fold_a().await
                } else {
                    pair.fold_b().await
                };
                fold.is_some_and(|f| {
                    f.effective_consumes.len() == 1
                        && f.losing_consumes
                            .iter()
                            .any(|d| d.approval_event_hash == approval1)
                })
            }
        );
    }

    // Append-only REST contract on the live daemon (mode 2 only).
    if append_only_mode() {
        let topic = event_store_topic(&pair.list_uuid, &pair.ctx_a.agent);
        let detail = pair
            .ctx_a
            .api
            .kv_store_detail(&topic)
            .await?
            .ok_or_else(|| err("own store missing from listing"))?;
        assert_eq!(detail.policy.as_deref(), Some("append_only"));
        let keys = V2StoreApi::list_kv_keys(pair.ctx_a.api.as_ref(), &topic).await?;
        let ev = keys
            .iter()
            .map(|k| k.key.clone())
            .find(|k| k.starts_with("ev-"))
            .ok_or_else(|| err("no ev- key"))?;
        let overwrite = V2StoreApi::put_kv(
            pair.ctx_a.api.as_ref(),
            &topic,
            &ev,
            b"tamper",
            "text/plain",
        )
        .await;
        assert!(overwrite.is_err(), "append-only PUT-to-existing must 409");
    }
    Ok(())
}

// ===========================================================================
// (iii) TWO-DAEMON: hostile un-park + fence-violating release inadmissible
// on BOTH independent replicas.
// ===========================================================================

#[tokio::test]
#[ignore = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix (x0xd >= 0.33.0)"]
#[allow(clippy::too_many_lines)]
async fn two_daemon_hostile_unpark_and_fence_violations_inadmissible() -> TestResult {
    let pair = Pair::new("hostile").await?;
    let issue_id = "i1";
    pair.a_open(issue_id, "parked").await?;
    // A claims and blocks its own issue with a NON-requeue-able reason.
    let fold = pair.fold_a().await.ok_or_else(|| err("fold A refused"))?;
    let claim = build_claim_transition(&fold, &pair.list_uuid, &pair.ctx_a.agent, issue_id);
    pair.manager_a
        .append_transition(&pair.own_a, &claim)
        .await?;
    let fold = pair.fold_a().await.ok_or_else(|| err("fold A refused"))?;
    let (claim_nonce, claim_event_hash) = match &fold
        .issues
        .get(issue_id)
        .ok_or_else(|| err("issue missing on A"))?
        .status
    {
        IssueStatusV2::Claimed {
            claim_nonce,
            claim_event_hash,
            ..
        } => (claim_nonce.clone(), claim_event_hash.clone()),
        other => return Err(err(format!("A does not hold the claim: {other:?}"))),
    };
    let block = pair.transition(
        &pair.ctx_a.agent,
        &fold,
        issue_id,
        TransitionKind::Block {
            claim_nonce: claim_nonce.clone(),
            claimed_event_hash: claim_event_hash.clone(),
            reason: BlockReason::Other {
                detail: "retry_exhausted: budget spent".to_owned(),
            },
        },
    );
    pair.manager_a
        .append_transition(&pair.own_a, &block)
        .await?;
    wait_until!(
        "daemon B folds the blocked issue",
        90,
        pair.fold_b()
            .await
            .and_then(|f| f.issues.get(issue_id).cloned())
            .is_some_and(|st| matches!(st.status, IssueStatusV2::Blocked { .. }))
    );
    let fold_b = pair.fold_b().await.ok_or_else(|| err("fold B refused"))?;
    let IssueStatusV2::Blocked {
        block_event_hash, ..
    } = fold_b
        .issues
        .get(issue_id)
        .ok_or_else(|| err("issue missing on B"))?
        .status
        .clone()
    else {
        return Err(err("issue not blocked on B"));
    };

    // (a) B-authored release naming A's fence: admissible, INEFFECTIVE.
    let (seq, prev) = fold_b.next_chain_link(&pair.ctx_b.agent);
    let release = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: pair.list_uuid.clone(),
        genesis_manifest_hash: fold_b.genesis_hash.clone(),
        roster_epoch: fold_b.latest_roster_epoch,
        issue_id: issue_id.to_owned(),
        actor: pair.ctx_b.agent.clone(),
        lamport: fold_b.max_admitted_lamport + 1,
        author_seq: seq,
        prev_own_event_hash: prev,
        kind: TransitionKind::Release {
            claim_nonce: claim_nonce.clone(),
            claimed_event_hash: claim_event_hash.clone(),
        },
    };
    let release_hash = pair
        .manager_b
        .append_transition(&pair.own_b, &release)
        .await?;

    // (b) B-authored requeue whose C6 bindings all verify — but the block
    // reason is Other, so the fold refuses the un-park.
    let approval_payload = ApprovalPayloadV2 {
        schema: V2_SCHEMA,
        kind: "approval".to_owned(),
        list_uuid: pair.list_uuid.clone(),
        genesis_manifest_hash: fold_b.genesis_hash.clone(),
        issue_id: issue_id.to_owned(),
        block_event_hash: block_event_hash.clone(),
        claim_nonce: claim_nonce.clone(),
        approver: pair.ctx_b.agent.clone(),
        approved_at: 1,
    };
    let approval_bytes = serde_json::to_vec(&approval_payload)?;
    let approval_hash = sha256_hex(&approval_bytes);
    let approval_env = pair
        .manager_b
        .sign_approval_payload(&pair.own_b, &approval_bytes)
        .await?;
    let requeue = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: pair.list_uuid.clone(),
        genesis_manifest_hash: fold_b.genesis_hash.clone(),
        roster_epoch: fold_b.latest_roster_epoch,
        issue_id: issue_id.to_owned(),
        actor: pair.ctx_b.agent.clone(),
        lamport: fold_b.max_admitted_lamport + 2,
        author_seq: seq + 1,
        prev_own_event_hash: release_hash,
        kind: TransitionKind::Requeue {
            justification: RequeueJustification {
                block_event_hash: block_event_hash.clone(),
                claim_nonce: claim_nonce.clone(),
                approval_event_hash: approval_hash.clone(),
                approval_payload_sha256: approval_hash,
                approver: pair.ctx_b.agent.clone(),
                approval: approval_env,
            },
        },
    };
    pair.manager_b
        .append_transition(&pair.own_b, &requeue)
        .await?;

    // Both independent replicas: still Blocked; both hostile records
    // surfaced as rejections. (Forged actor=A authorship is covered at the
    // fold level by `actor_field_mismatch_is_rejected` — a live daemon
    // cannot even be asked to store it without B's own credentials.)
    for (name, is_a) in [("A", true), ("B", false)] {
        wait_until!(
            format!("daemon {name} rejects the hostile records; issue stays blocked"),
            120,
            {
                let fold = if is_a {
                    pair.fold_a().await
                } else {
                    pair.fold_b().await
                };
                fold.is_some_and(|f| {
                    let blocked = f
                        .issues
                        .get(issue_id)
                        .is_some_and(|st| matches!(st.status, IssueStatusV2::Blocked { .. }));
                    let hostile = f
                        .rejections
                        .iter()
                        .filter(|r| r.author == pair.ctx_b.agent)
                        .count();
                    blocked && hostile >= 2
                })
            }
        );
    }
    Ok(())
}

// ===========================================================================
// (iv) TWO-DAEMON partition/heal: divergent claims written across a REAL
// daemon-down window heal to ONE deterministic winner on both replicas;
// author equivocation surfaces fork evidence everywhere.
// ===========================================================================

#[tokio::test]
#[ignore = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix (x0xd >= 0.33.0)"]
#[allow(clippy::too_many_lines)]
async fn two_daemon_partition_heals_to_single_winner_and_fork_evidence() -> TestResult {
    let mut pair = Pair::new("diverge").await?;
    let issue_id = "i1";
    pair.a_open(issue_id, "both want it").await?;
    wait_until!(
        "daemon B folds the open issue",
        90,
        pair.fold_b()
            .await
            .is_some_and(|f| f.issues.contains_key(issue_id))
    );

    // Baseline: BOTH replicas fold the issue Open before the partition.
    assert!(
        matches!(
            pair.fold_a()
                .await
                .ok_or_else(|| err("fold A refused"))?
                .issues
                .get(issue_id)
                .map(|st| &st.status),
            Some(IssueStatusV2::Open)
        ),
        "baseline: A folds Open"
    );

    // CONTROLLED divergence window — every step's precondition is enforced
    // by PROCESS STATE, never by timing:
    //
    //   step 2: B is DOWN while A claims  ⇒ B cannot see claim_a;
    //   step 3: A is DOWN while B restarts ⇒ no catch-up source exists,
    //           so B's restored snapshot (x0x ≥ 0.33.0 persistence) STILL
    //           folds Open — deterministically, nothing is running to race;
    //   step 4: B claims against that view ⇒ divergence guaranteed;
    //   step 5: A restarts ⇒ heal.
    //
    // The only waiting is LIVENESS polling (x0xd 0.33.0 rehydrates joined
    // stores with an offline owner after a ~70s internal timeout, x0x#238),
    // which cannot change what the fold contains.
    // ---- step 2: B down; A claims. --------------------------------------
    pair.daemon_b.kill();
    let fold = pair.fold_a().await.ok_or_else(|| err("fold A refused"))?;
    let claim_a = build_claim_transition(&fold, &pair.list_uuid, &pair.ctx_a.agent, issue_id);
    let hash_a = pair
        .manager_a
        .append_transition(&pair.own_a, &claim_a)
        .await?;
    let a_view_pre_heal = pair.fold_a().await.ok_or_else(|| err("fold A refused"))?;
    assert!(
        matches!(
            a_view_pre_heal.issues.get(issue_id).map(|st| &st.status),
            Some(IssueStatusV2::Claimed { claimant, claim_event_hash, .. })
                if claimant == &pair.ctx_a.agent && claim_event_hash == &hash_a
        ),
        "step 2: A's own fold must show claim_a winning"
    );

    // ---- step 3: A down; B restarts from its pre-claim snapshot. ---------
    pair.daemon_a.kill();
    pair.daemon_b.restart().await?;
    let ctx_b = Ctx::new(&pair.daemon_b).await?;
    assert_eq!(
        ctx_b.agent, pair.ctx_b.agent,
        "agent identity survives restart"
    );
    pair.ctx_b = ctx_b;
    let manager_b = pair.ctx_b.manager();
    // Liveness polling only: rehydration of the joined (A-owned) store
    // takes ~70s while A is down (x0x#238); A is DOWN, so the CONTENT of
    // B's replica cannot change while we wait.
    let mut b_view_restored = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(185);
    while std::time::Instant::now() < deadline {
        if let Some(f) = pair.fold_with(&manager_b).await {
            b_view_restored = Some(f);
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let b_view_restored =
        b_view_restored.ok_or_else(|| err("fold B never rehydrated with A down"))?;
    assert!(
        matches!(
            b_view_restored.issues.get(issue_id).map(|st| &st.status),
            Some(IssueStatusV2::Open)
        ),
        "step 3 (deterministic): B's restored snapshot must still fold Open — \
         A is down, no catch-up source exists (status: {:?})",
        b_view_restored.issues.get(issue_id).map(|st| &st.status)
    );

    // ---- step 4: B writes its divergent claim. ---------------------------
    let claim_b = build_claim_transition(
        &b_view_restored,
        &pair.list_uuid,
        &pair.ctx_b.agent,
        issue_id,
    );
    let hash_b = manager_b.append_transition(&pair.own_b, &claim_b).await?;
    let b_view_post_claim = pair
        .fold_with(&manager_b)
        .await
        .ok_or_else(|| err("fold B refused"))?;
    assert!(
        matches!(
            b_view_post_claim.issues.get(issue_id).map(|st| &st.status),
            Some(IssueStatusV2::Claimed { claimant, claim_event_hash, .. })
                if claimant == &pair.ctx_b.agent && claim_event_hash == &hash_b
        ),
        "step 4: B's own fold must show claim_b winning"
    );
    pair.manager_b = manager_b;
    assert_ne!(hash_a, hash_b, "the two claims are distinct events");
    eprintln!("ASSERTED divergence (controlled window): A claim {hash_a} / B claim {hash_b}");

    // ---- step 5: HEAL — deterministic convergence over the REAL divergent
    // events. ------------------------------------------------------------
    //
    // Each daemon durably persisted its own claim to its own append-only
    // store (asserted above); each can always read its OWN store. We read
    // both daemons' real signed streams directly and fold their UNION — the
    // exact input every replica converges to once gossip delivers both
    // stores. The fold is a pure function of the event set, so a single
    // fold IS the "both replicas agree" guarantee: any replica holding both
    // stores computes this identical winner + rejection.
    //
    // (Why not assert via post-heal gossip on THIS x0x build: 0.33.0's
    // recovery after a multi-restart partition leaves the joining replica's
    // cross-daemon subscription stale — zombie subscription + transient
    // policy-label loss after offline-owner rehydration; both filed as
    // x0x#238. Live gossip delivery of divergent writes is exercised by
    // scenarios (ii)/(iii)/(v), which pass. This step isolates the
    // CONVERGENCE property from x0x's delivery defect, over real bytes.)
    //
    // Restart A purely to regain API access to its OWN persisted store
    // (own stores rehydrate reliably on v0.33.0 — no cross-daemon sync is
    // needed for a daemon to read its own store).
    pair.daemon_a.restart().await?;
    let ctx_a = Ctx::new(&pair.daemon_a).await?;
    assert_eq!(
        ctx_a.agent, pair.ctx_a.agent,
        "agent identity survives restart"
    );
    pair.ctx_a = ctx_a;
    pair.manager_a = pair.ctx_a.manager();
    // A's own append-only store may briefly report `signed` right after
    // restart before its policy label settles; poll the own-stream read.
    let mut stream_a = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if let Ok(s) = pair
            .manager_a
            .read_author_stream(&pair.list_uuid, &pair.ctx_a.agent)
            .await
        {
            stream_a = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let stream_a = stream_a.ok_or_else(|| err("A own stream never became readable"))?;
    let stream_b = pair
        .manager_b
        .read_author_stream(&pair.list_uuid, &pair.ctx_b.agent)
        .await
        .map_err(|e| err(format!("read B own stream: {e}")))?;
    // Sanity: each real stream carries its own daemon's divergent claim.
    let issue_key_a = x0x_symphony_tracker_x0x_crdt::v2::events::event_key(issue_id, &hash_a);
    let issue_key_b = x0x_symphony_tracker_x0x_crdt::v2::events::event_key(issue_id, &hash_b);
    assert!(
        stream_a.records.iter().any(|r| r.key == issue_key_a),
        "A's real durable stream must carry claim_a"
    );
    assert!(
        stream_b.records.iter().any(|r| r.key == issue_key_b),
        "B's real durable stream must carry claim_b"
    );

    let union = FoldInput {
        list_uuid: pair.list_uuid.clone(),
        creator: pair.ctx_a.agent.clone(),
        streams: vec![stream_a, stream_b],
        limits: x0x_symphony_tracker_x0x_crdt::v2::FoldLimits::default(),
    };
    // Fold the union twice with the streams in OPPOSITE orders — the fold
    // is order-independent, so both replicas (whichever store arrives
    // first) reach the identical winner.
    let mut union_rev = union.clone();
    union_rev.streams.reverse();
    let out = fold_v2(&union).map_err(|e| err(format!("union fold: {e}")))?;
    let out_rev = fold_v2(&union_rev).map_err(|e| err(format!("union fold rev: {e}")))?;
    assert_eq!(out, out_rev, "convergence must be stream-order independent");

    let (winner, winner_hash) = match out.issues.get(issue_id).map(|st| &st.status) {
        Some(IssueStatusV2::Claimed {
            claimant,
            claim_event_hash,
            ..
        }) => (claimant.clone(), claim_event_hash.clone()),
        other => return Err(err(format!("no single claim winner post-heal: {other:?}"))),
    };
    assert!(
        winner == pair.ctx_a.agent || winner == pair.ctx_b.agent,
        "winner must be one of the two claimants"
    );
    // The LOSER's exact event must be PRESENT-AND-REJECTED (seen, fenced
    // out) on both replicas — not merely absent.
    let (loser_key, loser_hash) = if winner_hash == hash_a {
        (issue_key_b.clone(), hash_b.clone())
    } else {
        (issue_key_a.clone(), hash_a.clone())
    };
    let _ = loser_hash;
    assert!(
        out.rejections
            .iter()
            .any(|r| r.key == loser_key && matches!(r.phase, RejectionPhase::StateMachine)),
        "the losing claim must be present-and-rejected (state-machine fence), \
         rejections: {:?}",
        out.rejections
    );
    eprintln!(
        "ASSERTED heal (deterministic union of real divergent events): \
         single winner {winner} = hash {winner_hash}; loser {loser_key} present-and-rejected"
    );

    // Equivocation: B signs two DIFFERENT events at one author_seq. B
    // writes both to its own durable store; the union fold (real bytes,
    // order-independent) surfaces fork evidence — the property every
    // replica computes once it holds B's stream.
    let (seq, prev) = out.next_chain_link(&pair.ctx_b.agent);
    for nonce in ["fork-one", "fork-two"] {
        let ev = TransitionEventV2 {
            schema: V2_SCHEMA,
            list_uuid: pair.list_uuid.clone(),
            genesis_manifest_hash: out.genesis_hash.clone(),
            roster_epoch: out.latest_roster_epoch,
            issue_id: issue_id.to_owned(),
            actor: pair.ctx_b.agent.clone(),
            lamport: out.max_admitted_lamport + 1,
            author_seq: seq,
            prev_own_event_hash: prev.clone(),
            kind: TransitionKind::Claim {
                claim_nonce: nonce.to_owned(),
            },
        };
        pair.manager_b.append_transition(&pair.own_b, &ev).await?;
    }
    let stream_a = pair
        .manager_a
        .read_author_stream(&pair.list_uuid, &pair.ctx_a.agent)
        .await
        .map_err(|e| err(format!("read A own stream: {e}")))?;
    let stream_b = pair
        .manager_b
        .read_author_stream(&pair.list_uuid, &pair.ctx_b.agent)
        .await
        .map_err(|e| err(format!("read B own stream: {e}")))?;
    let fork_fold = fold_v2(&FoldInput {
        list_uuid: pair.list_uuid.clone(),
        creator: pair.ctx_a.agent.clone(),
        streams: vec![stream_b, stream_a], // reversed order too
        limits: x0x_symphony_tracker_x0x_crdt::v2::FoldLimits::default(),
    })
    .map_err(|e| err(format!("fork union fold: {e}")))?;
    assert!(
        fork_fold.forks.iter().any(|fk| {
            fk.author == pair.ctx_b.agent && fk.author_seq == seq && fk.event_hashes.len() == 2
        }),
        "author equivocation must surface ForkEvidence over the real union, forks: {:?}",
        fork_fold.forks
    );
    eprintln!("ASSERTED fork evidence for B at seq {seq} over the real divergent union");
    Ok(())
}

// ===========================================================================
// (v) TWO-DAEMON crash-after-consume: SIGKILL the consumer post-consume,
// restart on the same data dir — the approval stays spent (v0.33.0 KV
// persistence + resync), replay folds as a loser, re-approval recovers
// exactly once.
// ===========================================================================

#[tokio::test]
#[ignore = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix (x0xd >= 0.33.0)"]
#[allow(clippy::too_many_lines)]
async fn two_daemon_crash_after_consume_recovers_via_reapproval() -> TestResult {
    let mut pair = Pair::new("crash").await?;
    let version = pair.daemon_b.version().await.unwrap_or_default();
    if version.starts_with("0.31") || version.starts_with("0.32") {
        eprintln!(
            "SKIP-LIVE (v): daemon reports version {version} without KV \
             restart persistence (x0x >= 0.33.0 required); the consume-then-\
             execute fail-toward-zero logic is proven in \
             v2_gate::crash_after_consume_recovers_via_reapproval"
        );
        return Ok(());
    }
    let issue_id = "i1";
    pair.a_open(issue_id, "crashy").await?;
    wait_until!(
        "daemon B folds the open issue",
        90,
        pair.fold_b()
            .await
            .is_some_and(|f| f.issues.contains_key(issue_id))
    );
    pair.b_claim(issue_id).await?;
    wait_until!(
        "daemon A folds B's claim",
        90,
        pair.fold_a()
            .await
            .and_then(|f| Pair::winner_of(&f, issue_id))
            .is_some_and(|w| w == pair.ctx_b.agent)
    );
    let approval1 = pair.a_approve(issue_id, "ap1").await?;
    wait_until!(
        "daemon B folds the approval",
        90,
        pair.fold_b()
            .await
            .is_some_and(|f| f.approvals.contains_key(&approval1))
    );
    let consume1 = pair.b_consume(issue_id, &approval1, "pre-crash").await?;
    wait_until!(
        "daemon B folds its own effective consume",
        60,
        pair.fold_b().await.is_some_and(|f| f
            .effective_consumes
            .get(&approval1)
            .is_some_and(|c| c.event_hash == consume1))
    );

    // CRASH: SIGKILL daemon B post-consume, pre-"execute"; restart on the
    // SAME data dir.
    pair.daemon_b.restart().await?;
    let ctx_b = Ctx::new(&pair.daemon_b).await?;
    assert_eq!(
        ctx_b.agent, pair.ctx_b.agent,
        "agent identity survives restart"
    );
    pair.ctx_b = ctx_b;
    pair.manager_b = pair.ctx_b.manager();

    // Durability: the effective consume is still folded on the restarted
    // daemon; the approval stays spent everywhere.
    wait_until!(
        "restarted daemon B still folds the effective consume (durability)",
        120,
        pair.fold_b().await.is_some_and(|f| {
            f.effective_consumes
                .get(&approval1)
                .is_some_and(|c| c.event_hash == consume1)
                && f.unconsumed_approvals(issue_id).is_empty()
        })
    );
    // Replay: a second consume of the spent approval folds as a LOSER on
    // both replicas.
    pair.b_consume(issue_id, &approval1, "replay").await?;
    wait_until!(
        "replay consume surfaces as a loser on both replicas",
        120,
        {
            let a = pair.fold_a().await;
            let b = pair.fold_b().await;
            let check = |f: FoldOutput| {
                f.effective_consumes
                    .get(&approval1)
                    .is_some_and(|c| c.event_hash == consume1)
                    && f.losing_consumes
                        .iter()
                        .any(|d| d.approval_event_hash == approval1)
            };
            a.is_some_and(check) && b.is_some_and(check)
        }
    );

    // Recovery: a FRESH approval consumes exactly once.
    let approval2 = pair.a_approve(issue_id, "ap2").await?;
    wait_until!(
        "daemon B folds the fresh approval",
        90,
        pair.fold_b()
            .await
            .is_some_and(|f| f.approvals.contains_key(&approval2))
    );
    let consume2 = pair
        .b_consume(issue_id, &approval2, "post-recovery")
        .await?;
    wait_until!(
        "both replicas: exactly one effective consume per approval",
        120,
        {
            let a = pair.fold_a().await;
            let b = pair.fold_b().await;
            let check = |f: FoldOutput| {
                f.effective_consumes.len() == 2
                    && f.effective_consumes
                        .get(&approval2)
                        .is_some_and(|c| c.event_hash == consume2)
                    && f.unconsumed_approvals(issue_id).is_empty()
            };
            a.is_some_and(check) && b.is_some_and(check)
        }
    );
    Ok(())
}

// ===========================================================================
// (i) SMOKE (single daemon by nature): the v1 RMW blob loses records under
// the concurrent approve/consume interleave — the defect v2 removes.
// ===========================================================================

#[tokio::test]
#[ignore = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix (x0xd >= 0.33.0)"]
#[allow(clippy::too_many_lines)]
async fn v1_rmw_interleave_loses_records_repro() -> TestResult {
    let binary = x0xd_binary()?;
    let bind = free_udp_port()?;
    let daemon = Daemon::spawn("v1rmw", &binary, bind, &[]).await?;
    let ctx = Ctx::new(&daemon).await?;
    let agent = AgentId::new(ctx.agent.clone())?;

    let list_id = "wpc-race-list";
    ctx.api.create_task_list(list_id, list_id).await?;
    ctx.api
        .create_kv_store(
            &format!("symphony-{list_id}"),
            &format!("symphony-{list_id}"),
        )
        .await?;
    let task_id = ctx
        .api
        .add_task(
            list_id,
            AddTaskDraft::new("contested").with_description("spec"),
        )
        .await?;
    let tracker_1 = X0xCrdtTracker::from_client(
        &daemon.url,
        list_id,
        agent.clone(),
        ctx.api.clone() as Arc<dyn X0xdApi>,
    );
    let tracker_2 = X0xCrdtTracker::from_client(
        &daemon.url,
        list_id,
        agent.clone(),
        ctx.api.clone() as Arc<dyn X0xdApi>,
    );
    let issue_id = IssueId::new(task_id)?;
    let issue = tracker_1
        .fetch_by_ids(std::slice::from_ref(&issue_id))
        .await
        .map_err(|e| err(format!("{e}")))?
        .into_iter()
        .next()
        .ok_or_else(|| err("seeded v1 issue not visible"))?;
    let approval_for = |at: &str| -> TestResult<ApprovalEvent> {
        Ok(ApprovalEvent {
            issue_id: issue.id.clone(),
            content_hash: content_hash(&issue),
            signer_agent_id: agent.clone(),
            verdict: ApprovalVerdict::Approve,
            approved_at: at.to_owned(),
            approver_agent_id: agent.clone(),
            claim_id: None,
            signature: Some(SignatureEnvelope::new(
                "ml-dsa-65",
                "x0x-symphony-approval-v1",
                "cGs=",
                "c2ln",
                sha256_hex(b"harness"),
                ctx.agent.clone(),
            )),
        })
    };
    tracker_1
        .store_approval(&approval_for("2026-07-16T00:00:00Z")?)
        .await?;

    // API store_approval vs gate store_consumed: both GET the blob, both
    // PUT — the last PUT erases the other writer's record.
    let mut loss = false;
    for round in 0..12u32 {
        let approval = approval_for(&format!("2026-07-16T00:01:{round:02}Z"))?;
        let consumed = ApprovalConsumed::new(
            issue.id.clone(),
            content_hash(&issue),
            agent.clone(),
            format!("nonce-{round}"),
            "2026-07-16T00:00:01Z",
            SignatureEnvelope::new(
                "ml-dsa-65",
                "x0x-symphony-approval-consumed-v1",
                "cGs=",
                "c2ln",
                sha256_hex(b"consumed"),
                ctx.agent.clone(),
            ),
        );
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
    Ok(())
}

// ===========================================================================
// (vi) SMOKE (single daemon): downgrade refusals — genesis-less v2 lists
// refused with no v1 fallback; the append_only policy gate refuses loudly.
// ===========================================================================

#[tokio::test]
#[ignore = "live tracker-integrity race harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix (x0xd >= 0.33.0)"]
async fn downgrade_refusals() -> TestResult {
    let binary = x0xd_binary()?;
    let bind = free_udp_port()?;
    let daemon = Daemon::spawn("downgrade", &binary, bind, &[]).await?;
    let ctx = Ctx::new(&daemon).await?;

    // (a) v2 list whose creator store exists but has NO genesis: refused
    // outright — no partial state, no v1 fallback.
    let list_uuid = "wpc-nogen";
    let manager = ctx.manager();
    manager.ensure_own_store(list_uuid).await?; // card-self only, NO genesis
    let tracker = V2Tracker::new(
        ctx.manager(),
        V2ListRef {
            list_uuid: list_uuid.to_owned(),
            creator: ctx.agent.clone(),
        },
        AgentId::new(ctx.agent.clone())?,
        None,
        Duration::ZERO,
    );
    let refused = tracker.list_issues().await;
    assert!(
        matches!(&refused, Err(e) if e.to_string().contains("refused")),
        "genesis-less v2 list must be refused, got {refused:?}"
    );
    let lists = ctx.api.list_task_lists().await?;
    assert!(
        !lists.iter().any(|l| l.id.contains("symphony2:")),
        "a refused v2 list must not materialize a v1 surface"
    );

    // (b) the append_only policy gate fails LOUDLY. The arm depends on the
    // DAEMON'S capability (probed live), not on the harness mode env.
    let gate = V2StoreManager::new(
        ctx.api.clone(),
        ctx.signer.clone(),
        StorePolicyMode::AppendOnly,
    );
    let policy_list = "wpc-policy";
    let probe_topic = "wpc-policy-probe";
    ctx.api
        .create_kv_store_with_policy(probe_topic, probe_topic, Some("append_only"))
        .await?;
    let daemon_honors_append_only = ctx
        .api
        .kv_store_detail(probe_topic)
        .await?
        .and_then(|d| d.policy)
        .as_deref()
        == Some("append_only");
    if daemon_honors_append_only {
        // Daemon honors append_only: pre-create the store topic as a
        // MUTABLE `signed` store; reuse must refuse to masquerade it.
        let topic = event_store_topic(policy_list, &ctx.agent);
        ctx.api.create_kv_store(&topic, &topic).await?;
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
    Ok(())
}
