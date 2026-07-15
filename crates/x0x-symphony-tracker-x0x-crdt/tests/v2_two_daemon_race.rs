//! WP-C: the two-daemon race harness (x0x-symphony#10, design r2).
//!
//! Spawns TWO isolated x0xd daemons on loopback (fresh temp dirs, ephemeral
//! ports, `--no-hard-coded-bootstrap`, `[update] enabled = false`) and
//! drives the v1 and v2 trackers across them to prove, live:
//!
//! (i)   the v1 RMW consumption blob LOSES records under concurrent
//!       writers (the defect v2 fixes — asserted, not fixed);
//! (ii)  the same interleave on v2 loses NOTHING: per-key append-only
//!       records, exactly-once effective consume, losers surfaced;
//! (iii) hostile un-park and forged authorship are inadmissible;
//! (iv)  divergent claims heal to ONE deterministic winner; equivocation
//!       yields fork evidence on both daemons;
//! (v)   crash-after-consume keeps the approval spent across a restart and
//!       recovers via re-approval;
//! (vi)  downgrade refusals: genesis-less v2 lists are refused, and the
//!       `append_only` policy gate fails loudly when not honored.
//!
//! Mode matrix: `X0X_V2_APPEND_ONLY=1` runs the v2 stores with
//! `StorePolicyMode::AppendOnly` and asserts the WP-X REST contract
//! (PUT-to-existing → 409, reported policy `append_only`) — requires an
//! x0xd with x0x `AccessPolicy::AppendOnly` (x0x ≥ 0.33.0 / PR #237).
//! Unset, the harness runs the interim `SignedFallback` mode against
//! x0xd ≤ 0.32.x and skips the append-only-specific assertions.

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
    content_hash, sha256_hex, AgentId, ApprovalConsumed, ApprovalEvent, ApprovalVerdict,
    IssueDraft, IssueId, ReleaseReason, ReleaseReasonCode, SignatureEnvelope, Tracker,
};
use x0x_symphony_signing::{SigningClient, X0xdClient as SigningX0xdClient};
use x0x_symphony_tracker_x0x_crdt::{
    client::{X0xdApi, X0xdClient},
    v2::{
        events::{
            event_key, event_store_topic, ApprovalPayloadV2, EventEnvelope, RequeueJustification,
            TransitionEventV2, TransitionKind, TRANSITION_CONTEXT_V2, V2_SCHEMA,
        },
        fold_v2, FoldOutput, IssueStatusV2, StorePolicyMode, V2ListRef, V2StoreApi, V2StoreError,
        V2StoreManager, V2Tracker,
    },
    X0xCrdtTracker,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

const IGNORE_REASON: &str = "live two-daemon harness: set X0XD_TEST_BINARY (or PATH x0xd); \
                             X0X_V2_APPEND_ONLY=1 for the append-only matrix";

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
        return Err(err(format!(
            "X0XD_TEST_BINARY={} does not exist",
            path.display()
        )));
    }
    let out = Command::new("which").arg("x0xd").output()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if out.status.success() && !path.is_empty() {
        Ok(PathBuf::from(path))
    } else {
        Err(err(
            "no x0xd binary: set X0XD_TEST_BINARY or put x0xd on PATH",
        ))
    }
}

fn free_tcp_port() -> TestResult<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn free_udp_port() -> TestResult<u16> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    Ok(socket.local_addr()?.port())
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
            sha256_hex(format!("{:?}", std::time::Instant::now()).as_bytes())
                .chars()
                .take(8)
                .collect::<String>()
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
        let mut daemon = Self {
            name: name.to_owned(),
            child: None,
            dir,
            config_path,
            bind_port,
            url: format!("http://127.0.0.1:{api_port}"),
            token: String::new(),
            binary: binary.to_path_buf(),
        };
        daemon.start().await?;
        Ok(daemon)
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
        // Readiness: /health is public.
        let http = reqwest::Client::new();
        let health = format!("{}/health", self.url);
        let deadline = std::time::Instant::now() + Duration::from_secs(75);
        loop {
            if std::time::Instant::now() >= deadline {
                let tail = fs::read_to_string(self.dir.join(format!("{}.stderr.log", self.name)))
                    .unwrap_or_default();
                let tail: String = tail.lines().rev().take(15).collect::<Vec<_>>().join("\n");
                return Err(err(format!(
                    "daemon {} never became healthy on {health}; stderr tail:\n{tail}",
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
        // Token: written to <data_dir>/api-token at startup.
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
                    "daemon {}: api-token never appeared at {}",
                    self.name,
                    token_path.display()
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
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.kill();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Per-daemon client bundle.
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

    fn tracker(&self, list_uuid: &str, creator: &str) -> TestResult<V2Tracker> {
        Ok(V2Tracker::new(
            self.manager(),
            V2ListRef {
                list_uuid: list_uuid.to_owned(),
                creator: creator.to_owned(),
            },
            AgentId::new(self.agent.clone())?,
            None,
            Duration::from_secs(1),
        ))
    }
}

async fn spawn_pair(test: &str) -> TestResult<(Daemon, Daemon)> {
    let binary = x0xd_binary()?;
    let a = Daemon::spawn(&format!("{test}-a"), &binary, &[]).await?;
    let b_bootstrap = vec![format!("127.0.0.1:{}", a.bind_port)];
    let b = Daemon::spawn(&format!("{test}-b"), &binary, &b_bootstrap).await?;
    Ok((a, b))
}

/// Fold one daemon's view of a v2 list. `Ok(None)` = refused/unreadable.
async fn fold_of(ctx: &Ctx, list_uuid: &str, creator: &str) -> Option<FoldOutput> {
    let manager = ctx.manager();
    let input = manager.read_fold_input(list_uuid, creator).await.ok()?;
    fold_v2(&input).ok()
}

/// Set up a two-member v2 list: A is creator, roster [A, B]; both trackers
/// have run `ensure_surfaces` and BOTH daemons fold the genesis.
async fn v2_two_member_list(
    ctx_a: &Ctx,
    ctx_b: &Ctx,
    list_uuid: &str,
) -> TestResult<(V2Tracker, V2Tracker)> {
    let manager_a = ctx_a.manager();
    let own_a = manager_a.ensure_own_store(list_uuid).await?;
    manager_a
        .publish_genesis(
            &own_a,
            vec![ctx_a.agent.clone(), ctx_b.agent.clone()],
            None,
            1,
        )
        .await?;
    let tracker_a = ctx_a.tracker(list_uuid, &ctx_a.agent)?;
    tracker_a.ensure_surfaces().await?;
    let tracker_b = ctx_b.tracker(list_uuid, &ctx_a.agent)?;
    tracker_b.ensure_surfaces().await?;
    wait_until!(
        format!("daemon B folds the genesis of {list_uuid}"),
        60,
        fold_of(ctx_b, list_uuid, &ctx_a.agent).await.is_some()
    );
    Ok((tracker_a, tracker_b))
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
    approved_at: &str,
) -> TestResult<ApprovalEvent> {
    Ok(ApprovalEvent {
        issue_id: issue.id.clone(),
        content_hash: content_hash(issue),
        signer_agent_id: AgentId::new(approver.to_owned())?,
        verdict: ApprovalVerdict::Approve,
        approved_at: approved_at.to_owned(),
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

fn draft(title: &str) -> IssueDraft {
    IssueDraft {
        title: title.to_owned(),
        description: Some("wp-c spec".to_owned()),
        priority: None,
        labels: Vec::new(),
    }
}

async fn issue_by_id(tracker: &dyn Tracker, id: &IssueId) -> Option<x0x_symphony_core::Issue> {
    tracker
        .fetch_by_ids(std::slice::from_ref(id))
        .await
        .ok()?
        .into_iter()
        .next()
}

// ---------------------------------------------------------------------------
// (i) v1 defect repro: concurrent RMW writers lose approval/consumption
// records. This test DOCUMENTS the v0.1 defect that v2 removes.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live two-daemon harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix"]
async fn v1_rmw_interleave_loses_records_repro() -> TestResult {
    let _ = IGNORE_REASON;
    let (daemon_a, _daemon_b) = spawn_pair("v1rmw").await?;
    let ctx_a = Ctx::new(&daemon_a).await?;

    // VARIANT NOTE (honest): the v1 sidecar KvStore is owner-signed, so a
    // remote daemon's writes to it are not the interesting path — the RMW
    // interleave defect lives entirely in X0xCrdtTracker's read-modify-
    // write over HTTP. Two tracker instances against daemon A interleave
    // exactly the same way two orchestrator processes on one node (API
    // store_approval vs gate store_consumed) do, which is the concurrency
    // class issue #10(b) names alongside the cross-node race.
    let list_id = "wpc-race-list";
    ctx_a.api.create_task_list(list_id, list_id).await?;
    ctx_a
        .api
        .create_kv_store(
            &format!("symphony-{list_id}"),
            &format!("symphony-{list_id}"),
        )
        .await?;
    let task_id = ctx_a
        .api
        .add_task(
            list_id,
            x0x_symphony_tracker_x0x_crdt::client::AddTaskDraft::new("contested")
                .with_description("spec"),
        )
        .await?;
    let agent = AgentId::new(ctx_a.agent.clone())?;
    let tracker_1 = X0xCrdtTracker::from_client(
        &daemon_a.url,
        list_id,
        agent.clone(),
        ctx_a.api.clone() as Arc<dyn X0xdApi>,
    );
    let tracker_2 = X0xCrdtTracker::from_client(
        &daemon_a.url,
        list_id,
        agent.clone(),
        ctx_a.api.clone() as Arc<dyn X0xdApi>,
    );
    let issue_id = IssueId::new(task_id)?;
    let issue = issue_by_id(&tracker_1, &issue_id)
        .await
        .ok_or_else(|| err("seeded v1 issue not visible"))?;

    // Seed approval #1 so both writers start from the same non-empty blob.
    tracker_1
        .store_approval(&approval_for(&issue, &ctx_a.agent, "2026-07-16T00:00:00Z")?)
        .await?;

    // The race: concurrent store_approval (writer 1) vs store_consumed
    // (writer 2). Each does GET blob → mutate → PUT blob. When both GETs
    // happen before either PUT, the last PUT silently erases the other
    // writer's record. Retry until the interleave lands (it usually lands
    // on the first attempt; serialized attempts are rolled back by
    // checking and reseeding is unnecessary because a serialized attempt
    // keeps BOTH records and we simply try the next pair).
    let mut loss_observed = false;
    for round in 0..10u32 {
        let approval = approval_for(
            &issue,
            &ctx_a.agent,
            &format!("2026-07-16T00:01:{round:02}Z"),
        )?;
        let consumed = consumed_for(&issue, &ctx_a.agent, &format!("nonce-{round}"))?;
        let before = tracker_1.load_approval_state(&issue_id).await?;
        let (ra, rc) = tokio::join!(
            tracker_1.store_approval(&approval),
            tracker_2.store_consumed(&consumed)
        );
        ra?;
        rc?;
        let after = tracker_1.load_approval_state(&issue_id).await?;
        let has_approval = after
            .events
            .iter()
            .any(|e| e.approved_at == approval.approved_at);
        let has_consumed = after.consumed.iter().any(|c| c.nonce == consumed.nonce);
        if !(has_approval && has_consumed) {
            eprintln!(
                "v1 RMW loss on round {round}: approval kept={has_approval}, \
                 consumption kept={has_consumed} (events {} -> {}, consumed {} -> {})",
                before.events.len(),
                after.events.len(),
                before.consumed.len(),
                after.consumed.len()
            );
            loss_observed = true;
            break;
        }
    }
    assert!(
        loss_observed,
        "expected the v1 RMW interleave to lose at least one record in 10 rounds — \
         if this ever fails, the v1 blob store gained atomicity and issue #10's \
         defect catalogue needs re-verification"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// (ii) v2: same interleave shape — nothing is lost, exactly one effective
// consume, losers are diagnostics.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live two-daemon harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix"]
#[allow(clippy::too_many_lines)]
async fn v2_interleave_keeps_all_records_exactly_once_consume() -> TestResult {
    let (daemon_a, daemon_b) = spawn_pair("v2race").await?;
    let ctx_a = Ctx::new(&daemon_a).await?;
    let ctx_b = Ctx::new(&daemon_b).await?;
    let list_uuid = "wpc-v2-race";
    let (tracker_a, tracker_b) = v2_two_member_list(&ctx_a, &ctx_b, list_uuid).await?;

    let issue = tracker_a.create_issue(draft("contested v2")).await?;
    wait_until!(
        "daemon B sees the open issue",
        60,
        issue_by_id(&tracker_b, &issue.id).await.is_some()
    );
    let agent_b = AgentId::new(ctx_b.agent.clone())?;
    tracker_b.claim(&issue.id, &agent_b).await?;
    wait_until!(
        "daemon A sees B's claim",
        60,
        fold_of(&ctx_a, list_uuid, &ctx_a.agent)
            .await
            .and_then(|f| f.issues.get(issue.id.as_str()).cloned())
            .is_some_and(|st| matches!(st.status, IssueStatusV2::Claimed { ref claimant, .. } if claimant == &ctx_b.agent))
    );

    // Approval #1 from A; wait until B folds it (its consume needs it).
    let projected_a = issue_by_id(&tracker_a, &issue.id)
        .await
        .ok_or_else(|| err("issue vanished on A"))?;
    tracker_a
        .store_approval(&approval_for(
            &projected_a,
            &ctx_a.agent,
            "2026-07-16T00:00:00Z",
        )?)
        .await?;
    wait_until!(
        "daemon B folds approval #1",
        60,
        fold_of(&ctx_b, list_uuid, &ctx_a.agent)
            .await
            .is_some_and(|f| f
                .approvals
                .values()
                .filter(|a| a.approval.issue_id == issue.id.as_str())
                .count()
                == 1)
    );

    // The interleave: A appends approval #2 while B consumes. In v1 this
    // exact shape silently erased one record; in v2 both are per-key
    // append-only records that can never clobber each other.
    let projected_b = issue_by_id(&tracker_b, &issue.id)
        .await
        .ok_or_else(|| err("issue vanished on B"))?;
    let approval2 = approval_for(&projected_a, &ctx_a.agent, "2026-07-16T00:02:00Z")?;
    let consumed = consumed_for(&projected_b, &ctx_b.agent, "wpc-consume")?;
    let (ra, rc) = tokio::join!(
        tracker_a.store_approval(&approval2),
        tracker_b.store_consumed(&consumed)
    );
    ra?;
    rc?;

    // Convergence: BOTH daemons fold 2 approvals + exactly 1 effective
    // consume. Nothing lost, exactly-once effective.
    for (name, ctx) in [("A", &ctx_a), ("B", &ctx_b)] {
        wait_until!(
            format!("daemon {name} folds 2 approvals + 1 effective consume"),
            60,
            fold_of(ctx, list_uuid, &ctx_a.agent)
                .await
                .is_some_and(|f| {
                    let approval_count = f
                        .approvals
                        .values()
                        .filter(|a| a.approval.issue_id == issue.id.as_str())
                        .count();
                    approval_count == 2 && f.effective_consumes.len() == 1
                })
        );
    }

    // Duplicate consume for the SAME approval: appended durably, resolved
    // as a LOSER in fold order, surfaced in losing_consumes on both sides.
    let manager_b = ctx_b.manager();
    let own_b = manager_b.ensure_own_store(list_uuid).await?;
    let fold_b = fold_of(&ctx_b, list_uuid, &ctx_a.agent)
        .await
        .ok_or_else(|| err("fold b unavailable"))?;
    let (consumed_approval_hash, effective) = fold_b
        .effective_consumes
        .iter()
        .next()
        .map(|(k, v)| (k.clone(), v.consume.clone()))
        .ok_or_else(|| err("no effective consume on B"))?;
    let (author_seq, prev_own_event_hash) = fold_b.next_chain_link(&ctx_b.agent);
    let duplicate = x0x_symphony_tracker_x0x_crdt::v2::ConsumeEventV2 {
        schema: V2_SCHEMA,
        kind: "consume".to_owned(),
        list_uuid: list_uuid.to_owned(),
        genesis_manifest_hash: fold_b.genesis_hash.clone(),
        roster_epoch: fold_b.latest_roster_epoch,
        issue_id: issue.id.as_str().to_owned(),
        actor: ctx_b.agent.clone(),
        lamport: fold_b.max_admitted_lamport + 1,
        author_seq,
        prev_own_event_hash,
        approval_event_hash: consumed_approval_hash.clone(),
        approval_payload_sha256: consumed_approval_hash.clone(),
        approver: effective.approver.clone(),
        claim_nonce: effective.claim_nonce.clone(),
        claimed_event_hash: effective.claimed_event_hash.clone(),
        entropy: "duplicate-entropy".to_owned(),
        v1_record_json: String::new(),
    };
    manager_b.append_consume(&own_b, &duplicate).await?;
    for (name, ctx) in [("A", &ctx_a), ("B", &ctx_b)] {
        wait_until!(
            format!("daemon {name} surfaces the duplicate consume as a loser"),
            60,
            fold_of(ctx, list_uuid, &ctx_a.agent)
                .await
                .is_some_and(|f| {
                    f.effective_consumes.len() == 1
                        && f.losing_consumes
                            .iter()
                            .any(|d| d.approval_event_hash == consumed_approval_hash)
                })
        );
    }

    // Append-only matrix (WP-X contract), only when the daemon honors it.
    if append_only_mode() {
        let topic = event_store_topic(list_uuid, &ctx_a.agent);
        let detail = ctx_a
            .api
            .kv_store_detail(&topic)
            .await?
            .ok_or_else(|| err("own store missing from listing"))?;
        assert_eq!(
            detail.policy.as_deref(),
            Some("append_only"),
            "daemon must report the append_only policy"
        );
        let keys = V2StoreApi::list_kv_keys(ctx_a.api.as_ref(), &topic).await?;
        let ev_key = keys
            .iter()
            .map(|k| k.key.clone())
            .find(|k| k.starts_with("ev-"))
            .ok_or_else(|| err("no ev- key in creator store"))?;
        let overwrite =
            V2StoreApi::put_kv(ctx_a.api.as_ref(), &topic, &ev_key, b"tamper", "text/plain").await;
        assert!(
            overwrite.is_err(),
            "PUT to an existing append-only key must be refused (409), got Ok"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// (iii) hostile un-park + forged authorship are inadmissible.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live two-daemon harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix"]
#[allow(clippy::too_many_lines)]
async fn hostile_unpark_and_forged_authorship_inadmissible() -> TestResult {
    let (daemon_a, daemon_b) = spawn_pair("hostile").await?;
    let ctx_a = Ctx::new(&daemon_a).await?;
    let ctx_b = Ctx::new(&daemon_b).await?;
    let list_uuid = "wpc-hostile";
    let (tracker_a, tracker_b) = v2_two_member_list(&ctx_a, &ctx_b, list_uuid).await?;
    let _ = &tracker_b;

    // A opens, claims, and parks its own issue with a NON-requeue-able
    // reason (RetryExhausted → BlockReason::Other).
    let issue = tracker_a.create_issue(draft("parked")).await?;
    let agent_a = AgentId::new(ctx_a.agent.clone())?;
    let claim = tracker_a.claim(&issue.id, &agent_a).await?;
    tracker_a
        .block(
            &claim,
            ReleaseReason::new(ReleaseReasonCode::RetryExhausted, "budget spent"),
        )
        .await?;
    wait_until!(
        "daemon B folds the blocked issue",
        60,
        fold_of(&ctx_b, list_uuid, &ctx_a.agent)
            .await
            .and_then(|f| f.issues.get(issue.id.as_str()).cloned())
            .is_some_and(|st| matches!(st.status, IssueStatusV2::Blocked { .. }))
    );
    let fold_b = fold_of(&ctx_b, list_uuid, &ctx_a.agent)
        .await
        .ok_or_else(|| err("fold b unavailable"))?;
    let st = fold_b
        .issues
        .get(issue.id.as_str())
        .ok_or_else(|| err("issue missing on B"))?;
    let IssueStatusV2::Blocked {
        claim_nonce,
        claim_event_hash,
        block_event_hash,
        ..
    } = st.status.clone()
    else {
        return Err(err("issue not blocked on B"));
    };

    let manager_b = ctx_b.manager();
    let own_b = manager_b.ensure_own_store(list_uuid).await?;

    // (a) B-authored Release naming A's fence: admissible (B signed its own
    // event) but INEFFECTIVE — B is not the claimant of the parked claim.
    let (seq, prev) = fold_b.next_chain_link(&ctx_b.agent);
    let release = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: list_uuid.to_owned(),
        genesis_manifest_hash: fold_b.genesis_hash.clone(),
        roster_epoch: fold_b.latest_roster_epoch,
        issue_id: issue.id.as_str().to_owned(),
        actor: ctx_b.agent.clone(),
        lamport: fold_b.max_admitted_lamport + 1,
        author_seq: seq,
        prev_own_event_hash: prev,
        kind: TransitionKind::Release {
            claim_nonce: claim_nonce.clone(),
            claimed_event_hash: claim_event_hash.clone(),
        },
    };
    let release_hash = manager_b.append_transition(&own_b, &release).await?;

    // (b) B-authored Requeue with a B-signed justification binding the real
    // block hash + nonce: every C6 binding verifies, but the block reason
    // is Other — the fold refuses the un-park.
    let approval_payload = ApprovalPayloadV2 {
        schema: V2_SCHEMA,
        kind: "approval".to_owned(),
        list_uuid: list_uuid.to_owned(),
        genesis_manifest_hash: fold_b.genesis_hash.clone(),
        issue_id: issue.id.as_str().to_owned(),
        block_event_hash: block_event_hash.clone(),
        claim_nonce: claim_nonce.clone(),
        approver: ctx_b.agent.clone(),
        approved_at: 1,
    };
    let approval_bytes = serde_json::to_vec(&approval_payload)?;
    let approval_hash = sha256_hex(&approval_bytes);
    let approval_env = manager_b
        .sign_approval_payload(&own_b, &approval_bytes)
        .await?;
    let requeue = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: list_uuid.to_owned(),
        genesis_manifest_hash: fold_b.genesis_hash.clone(),
        roster_epoch: fold_b.latest_roster_epoch,
        issue_id: issue.id.as_str().to_owned(),
        actor: ctx_b.agent.clone(),
        lamport: fold_b.max_admitted_lamport + 2,
        author_seq: seq + 1,
        prev_own_event_hash: release_hash,
        kind: TransitionKind::Requeue {
            justification: RequeueJustification {
                block_event_hash: block_event_hash.clone(),
                claim_nonce: claim_nonce.clone(),
                approval_event_hash: approval_hash.clone(),
                approval_payload_sha256: approval_hash,
                approver: ctx_b.agent.clone(),
                approval: approval_env,
            },
        },
    };
    manager_b.append_transition(&own_b, &requeue).await?;

    // (c) forged authorship: a payload naming actor=A, signed by B, dropped
    // straight into B's store — the four-way binding fails at admission.
    let forged = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: list_uuid.to_owned(),
        genesis_manifest_hash: fold_b.genesis_hash.clone(),
        roster_epoch: fold_b.latest_roster_epoch,
        issue_id: issue.id.as_str().to_owned(),
        actor: ctx_a.agent.clone(),
        lamport: fold_b.max_admitted_lamport + 3,
        author_seq: 999,
        prev_own_event_hash: fold_b.genesis_hash.clone(),
        kind: TransitionKind::Release {
            claim_nonce,
            claimed_event_hash: claim_event_hash,
        },
    };
    let forged_bytes = forged.to_signed_bytes().map_err(err)?;
    let forged_hash = sha256_hex(&forged_bytes);
    let sign = ctx_b
        .signer
        .sign(TRANSITION_CONTEXT_V2, &forged_bytes)
        .await?;
    let forged_env = EventEnvelope {
        schema: V2_SCHEMA,
        context: TRANSITION_CONTEXT_V2.to_owned(),
        algorithm: sign.algorithm,
        payload_b64: base64_std(&forged_bytes),
        public_key_b64: sign.public_key_b64,
        signature_b64: sign.signature_b64,
        signer_agent_id: sign.agent_id,
    };
    let topic_b = event_store_topic(list_uuid, &ctx_b.agent);
    V2StoreApi::put_kv(
        ctx_b.api.as_ref(),
        &topic_b,
        &event_key(issue.id.as_str(), &forged_hash),
        &forged_env.encode().map_err(err)?,
        "application/x0x-symphony-v2+json",
    )
    .await?;

    // Both daemons: issue STAYS blocked; all three hostile records are
    // surfaced as rejections, never silently applied.
    for (name, ctx) in [("A", &ctx_a), ("B", &ctx_b)] {
        wait_until!(
            format!("daemon {name} rejects all three hostile records"),
            60,
            fold_of(ctx, list_uuid, &ctx_a.agent)
                .await
                .is_some_and(|f| {
                    let still_blocked = f
                        .issues
                        .get(issue.id.as_str())
                        .is_some_and(|st| matches!(st.status, IssueStatusV2::Blocked { .. }));
                    let hostile_rejections = f
                        .rejections
                        .iter()
                        .filter(|r| r.author == ctx_b.agent || r.reason.contains("store owner"))
                        .count();
                    still_blocked && hostile_rejections >= 3
                })
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// (iv) divergent claims heal to a single deterministic winner; equivocation
// yields fork evidence everywhere.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live two-daemon harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix"]
async fn divergent_claims_heal_to_single_winner_and_fork_evidence() -> TestResult {
    let (daemon_a, daemon_b) = spawn_pair("diverge").await?;
    let ctx_a = Ctx::new(&daemon_a).await?;
    let ctx_b = Ctx::new(&daemon_b).await?;
    let list_uuid = "wpc-diverge";
    let (tracker_a, tracker_b) = v2_two_member_list(&ctx_a, &ctx_b, list_uuid).await?;

    let issue = tracker_a.create_issue(draft("both want it")).await?;
    wait_until!(
        "daemon B sees the open issue",
        60,
        issue_by_id(&tracker_b, &issue.id).await.is_some()
    );

    // FIDELITY NOTE: this races the two claims inside the live gossip
    // propagation window — the honest approximation of a partition. A
    // firewall-enforced partition is out of scope here; the deterministic
    // winner property is identical (total fold order), only the window
    // width differs.
    let agent_a = AgentId::new(ctx_a.agent.clone())?;
    let agent_b = AgentId::new(ctx_b.agent.clone())?;
    let (claim_a, claim_b) = tokio::join!(
        tracker_a.claim(&issue.id, &agent_a),
        tracker_b.claim(&issue.id, &agent_b)
    );
    eprintln!(
        "divergent-claim outcomes: A={:?} B={:?} (both-Ok = the documented live window)",
        claim_a.as_ref().map(|_| "Ok"),
        claim_b.as_ref().map(|_| "Ok")
    );

    // After heal: both daemons agree on ONE winner.
    let winner_of = |f: FoldOutput| {
        f.issues
            .get(issue.id.as_str())
            .and_then(|st| match &st.status {
                IssueStatusV2::Claimed { claimant, .. } => Some(claimant.clone()),
                _ => None,
            })
    };
    wait_until!("both daemons agree on one claim winner", 90, {
        let fa = fold_of(&ctx_a, list_uuid, &ctx_a.agent)
            .await
            .and_then(winner_of);
        let fb = fold_of(&ctx_b, list_uuid, &ctx_a.agent)
            .await
            .and_then(winner_of);
        fa.is_some() && fa == fb
    });
    let winner = fold_of(&ctx_a, list_uuid, &ctx_a.agent)
        .await
        .and_then(winner_of)
        .ok_or_else(|| err("no winner after heal"))?;
    assert!(
        winner == ctx_a.agent || winner == ctx_b.agent,
        "winner must be one of the two claimants"
    );

    // Equivocation: B signs TWO different events with one author_seq. Both
    // are durable (different content addresses); the fold surfaces fork
    // evidence on BOTH daemons and admits neither.
    let manager_b = ctx_b.manager();
    let own_b = manager_b.ensure_own_store(list_uuid).await?;
    let fold_b = fold_of(&ctx_b, list_uuid, &ctx_a.agent)
        .await
        .ok_or_else(|| err("fold b unavailable"))?;
    let (seq, prev) = fold_b.next_chain_link(&ctx_b.agent);
    for nonce in ["fork-one", "fork-two"] {
        let ev = TransitionEventV2 {
            schema: V2_SCHEMA,
            list_uuid: list_uuid.to_owned(),
            genesis_manifest_hash: fold_b.genesis_hash.clone(),
            roster_epoch: fold_b.latest_roster_epoch,
            issue_id: issue.id.as_str().to_owned(),
            actor: ctx_b.agent.clone(),
            lamport: fold_b.max_admitted_lamport + 1,
            author_seq: seq,
            prev_own_event_hash: prev.clone(),
            kind: TransitionKind::Claim {
                claim_nonce: nonce.to_owned(),
            },
        };
        manager_b.append_transition(&own_b, &ev).await?;
    }
    for (name, ctx) in [("A", &ctx_a), ("B", &ctx_b)] {
        wait_until!(
            format!("daemon {name} surfaces B's fork evidence"),
            60,
            fold_of(ctx, list_uuid, &ctx_a.agent)
                .await
                .is_some_and(|f| f.forks.iter().any(|fk| fk.author == ctx_b.agent
                    && fk.author_seq == seq
                    && fk.event_hashes.len() == 2))
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// (v) crash-after-consume: durable spend, zero executions, re-approval
// recovers.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live two-daemon harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix"]
#[allow(clippy::too_many_lines)]
async fn crash_after_consume_recovers_via_reapproval() -> TestResult {
    let (daemon_a, mut daemon_b) = spawn_pair("crash").await?;
    let ctx_a = Ctx::new(&daemon_a).await?;
    let ctx_b = Ctx::new(&daemon_b).await?;
    let list_uuid = "wpc-crash";
    let (tracker_a, tracker_b) = v2_two_member_list(&ctx_a, &ctx_b, list_uuid).await?;

    let issue = tracker_a.create_issue(draft("crashy")).await?;
    wait_until!(
        "daemon B sees the open issue",
        60,
        issue_by_id(&tracker_b, &issue.id).await.is_some()
    );
    let agent_b = AgentId::new(ctx_b.agent.clone())?;
    tracker_b.claim(&issue.id, &agent_b).await?;
    let projected = issue_by_id(&tracker_a, &issue.id)
        .await
        .ok_or_else(|| err("issue vanished on A"))?;
    tracker_a
        .store_approval(&approval_for(
            &projected,
            &ctx_a.agent,
            "2026-07-16T00:00:00Z",
        )?)
        .await?;
    wait_until!(
        "daemon B folds the approval",
        60,
        fold_of(&ctx_b, list_uuid, &ctx_a.agent)
            .await
            .is_some_and(|f| !f.approvals.is_empty())
    );
    let projected_b = issue_by_id(&tracker_b, &issue.id)
        .await
        .ok_or_else(|| err("issue vanished on B"))?;
    tracker_b
        .store_consumed(&consumed_for(&projected_b, &ctx_b.agent, "pre-crash")?)
        .await?;

    // CRASH: SIGKILL daemon B post-consume, pre-"execute".
    daemon_b.restart().await?;
    let ctx_b = Ctx::new(&daemon_b).await?;
    assert_eq!(
        ctx_b.agent,
        agent_b.as_str(),
        "agent identity must survive restart"
    );
    let tracker_b = ctx_b.tracker(list_uuid, &ctx_a.agent)?;
    tracker_b.ensure_surfaces().await?;

    // Durability (local disk or anti-entropy resync from A): the effective
    // consume is still there; the approval stays spent.
    wait_until!(
        "restarted daemon B folds the effective consume",
        90,
        fold_of(&ctx_b, list_uuid, &ctx_a.agent)
            .await
            .is_some_and(|f| f.effective_consumes.len() == 1
                && f.unconsumed_approvals(issue.id.as_str()).is_empty())
    );
    let projected_b = issue_by_id(&tracker_b, &issue.id)
        .await
        .ok_or_else(|| err("issue vanished on restarted B"))?;
    let replay = tracker_b
        .store_consumed(&consumed_for(&projected_b, &ctx_b.agent, "replay")?)
        .await;
    assert!(
        replay.is_err(),
        "spent approval must not be consumable again after the crash"
    );

    // Recovery: a FRESH approval from A consumes exactly once.
    let projected_a = issue_by_id(&tracker_a, &issue.id)
        .await
        .ok_or_else(|| err("issue vanished on A"))?;
    tracker_a
        .store_approval(&approval_for(
            &projected_a,
            &ctx_a.agent,
            "2026-07-16T00:05:00Z",
        )?)
        .await?;
    wait_until!(
        "daemon B folds the fresh approval",
        60,
        fold_of(&ctx_b, list_uuid, &ctx_a.agent)
            .await
            .is_some_and(|f| !f.unconsumed_approvals(issue.id.as_str()).is_empty())
    );
    tracker_b
        .store_consumed(&consumed_for(&projected_b, &ctx_b.agent, "post-recovery")?)
        .await?;
    let fold_b = fold_of(&ctx_b, list_uuid, &ctx_a.agent)
        .await
        .ok_or_else(|| err("fold b unavailable"))?;
    assert_eq!(
        fold_b.effective_consumes.len(),
        2,
        "each approval consumed at most once (one pre-crash, one post-recovery)"
    );
    assert!(fold_b.unconsumed_approvals(issue.id.as_str()).is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// (vi) downgrade refusals.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live two-daemon harness: set X0XD_TEST_BINARY (or PATH x0xd); X0X_V2_APPEND_ONLY=1 for the append-only matrix"]
async fn downgrade_refusals() -> TestResult {
    let (daemon_a, daemon_b) = spawn_pair("downgrade").await?;
    let ctx_a = Ctx::new(&daemon_a).await?;
    let ctx_b = Ctx::new(&daemon_b).await?;

    // (a) v2 list whose creator store exists but has NO genesis: refused
    // outright on the reader — no partial state, no v1 fallback.
    let list_uuid = "wpc-nogen";
    let manager_a = ctx_a.manager();
    manager_a.ensure_own_store(list_uuid).await?; // card-self only, NO genesis
    let tracker_b = ctx_b.tracker(list_uuid, &ctx_a.agent)?;
    tracker_b.ensure_surfaces().await?;
    wait_until!(
        "daemon B refuses the genesis-less v2 list",
        60,
        matches!(
            tracker_b.list_issues().await,
            Err(e) if e.to_string().contains("refused")
        )
    );
    // No v1 fallback surface was created for the v2 ref.
    let lists = ctx_b.api.list_task_lists().await?;
    assert!(
        !lists.iter().any(|l| l.id.contains("symphony2:")),
        "a refused v2 list must not materialize any v1 surface"
    );

    // (b) the append-only policy gate fails LOUDLY.
    let policy_list = "wpc-policy";
    let manager_gate = V2StoreManager::new(
        ctx_a.api.clone(),
        ctx_a.signer.clone(),
        StorePolicyMode::AppendOnly,
    );
    if append_only_mode() {
        // Daemon honors append_only: pre-create the would-be own store as a
        // MUTABLE signed store; reuse must refuse it.
        let topic = event_store_topic(policy_list, &ctx_a.agent);
        ctx_a.api.create_kv_store(&topic, &topic).await?;
        let outcome = manager_gate.ensure_own_store(policy_list).await;
        assert!(
            matches!(outcome, Err(V2StoreError::PolicyNotHonored { .. })),
            "a pre-existing mutable store must be refused in append-only mode, got {outcome:?}"
        );
    } else {
        // Daemon predates AccessPolicy::AppendOnly: requesting it must be
        // refused, never silently downgraded to a mutable store.
        let outcome = manager_gate.ensure_own_store(policy_list).await;
        assert!(
            matches!(outcome, Err(V2StoreError::PolicyNotHonored { .. })),
            "an old daemon ignoring the policy field must be refused, got {outcome:?}"
        );
    }
    Ok(())
}

fn base64_std(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(bytes)
}
