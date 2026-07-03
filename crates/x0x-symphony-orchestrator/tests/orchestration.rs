//! Integration tests for the x0x-symphony-orchestrator (XSY-0006 / WP-4).
//!
//! Exercises the orchestrator against in-memory stub implementations of the
//! core `Tracker`, `Runner`, and `Workspace` traits, covering the WP-4
//! acceptance criteria:
//!   - end-to-end smoke: `todo` -> claimed(`in_progress`) -> run -> `review`;
//!   - retry exhaustion -> `blocked` (structured `blocked_reason`);
//!   - shutdown mid-run -> claim released with `shutdown`, workspace preserved;
//!   - mocked-clock reconciliation: fresh self-claim resumes, stale releases;
//!   - concurrency cap: two eligible issues, cap 1 -> only one claimed.

#![cfg(test)]

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::stream;
use tempfile::TempDir;
use x0x_symphony_core::{
    content_hash, AgentId, ApprovalConsumed, ApprovalEvent, ApprovalState, ApprovalVerdict, Claim,
    EventStream, Handoff, Hook, HookEnv, HookOutcome, HookStatus, Issue, IssueId, IssueState,
    LifecycleHooks, PollContext, Prompt, ReleaseReason, ReleaseReasonCode, Result as CoreResult,
    Runner, RunnerCapabilities, RunnerEvent, RunnerEventKind, SessionContext, SessionHandle,
    SessionId, Shard, SignatureEnvelope, SignatureProvenance, Tracker, TurnOutcome, TurnStatus,
    UsageReport, ValidationStatus, Workspace, WorkspaceHandle, APPROVAL_CONSUMED_CONTEXT,
    APPROVAL_CONTEXT, SIGN_ALGORITHM,
};
use x0x_symphony_orchestrator::{
    dispatch::Resolution, is_fresh_self, retry::RetryPolicy, Clock, Config, ManualClock,
    NetworkDispatchPolicy, Orchestrator, SystemClock, TrustClient, TrustLevel,
};
use x0x_symphony_workspace::{Config as WorkspaceConfig, Manager};

fn make_issue(id: &str, state: &str) -> Result<Issue, Box<dyn Error>> {
    Ok(Issue::new(
        IssueId::new(id)?,
        id,
        "test issue",
        IssueState::new(state)?,
        "2026-07-02T00:00:00Z",
    )?)
}

fn network_issue(id: &str, labels: &[&str], signer: &str) -> Result<Issue, Box<dyn Error>> {
    network_issue_with_provenance(id, labels, Some(SignatureProvenance::verified(signer)))
}

fn unsigned_network_issue(id: &str, labels: &[&str]) -> Result<Issue, Box<dyn Error>> {
    network_issue_with_provenance(id, labels, None)
}

fn network_issue_with_provenance(
    id: &str,
    labels: &[&str],
    provenance: Option<SignatureProvenance>,
) -> Result<Issue, Box<dyn Error>> {
    let mut issue = make_issue(id, "todo")?;
    issue.labels = labels.iter().map(|label| (*label).to_owned()).collect();
    issue.extra.insert(
        "issue_source".to_owned(),
        serde_json::Value::String("network_sourced".to_owned()),
    );
    issue.signature_provenance = provenance;
    Ok(issue)
}

/// Like [`network_issue_with_provenance`] but the source marker deliberately
/// claims `local`. Used to prove the dispatch gate is self-enforcing: an issue
/// carrying network provenance must be gated even when the marker is absent or
/// claims local (defends against a tampered/missing marker).
fn local_marker_with_provenance(
    id: &str,
    labels: &[&str],
    provenance: Option<SignatureProvenance>,
) -> Result<Issue, Box<dyn Error>> {
    let mut issue = make_issue(id, "todo")?;
    issue.labels = labels.iter().map(|label| (*label).to_owned()).collect();
    issue.extra.insert(
        "issue_source".to_owned(),
        serde_json::Value::String("local".to_owned()),
    );
    issue.signature_provenance = provenance;
    Ok(issue)
}

fn local_issue_with_labels(id: &str, labels: &[&str]) -> Result<Issue, Box<dyn Error>> {
    let mut issue = make_issue(id, "todo")?;
    issue.labels = labels.iter().map(|label| (*label).to_owned()).collect();
    Ok(issue)
}

fn agent() -> Result<AgentId, Box<dyn Error>> {
    Ok(AgentId::new("agent-a")?)
}

fn state(name: &str) -> Result<IssueState, Box<dyn Error>> {
    Ok(IssueState::new(name)?)
}

fn parse_ts(value: &str) -> Result<DateTime<Utc>, Box<dyn Error>> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn claimed_issue(id: &str, agent: &AgentId, ts: String) -> Result<Issue, Box<dyn Error>> {
    let mut issue = make_issue(id, "in_progress")?;
    issue.claim = Some(
        Claim::new(
            Some(issue.id.clone()),
            agent.clone(),
            ts.clone(),
            x0x_symphony_core::ShardRole::ManualM1,
        )
        .with_heartbeat(ts),
    );
    Ok(issue)
}

fn sharded_issue(
    id: &str,
    state_name: &str,
    primary: &AgentId,
    backups: Vec<AgentId>,
    claim_ttl_ms: u64,
) -> Result<Issue, Box<dyn Error>> {
    let mut issue = make_issue(id, state_name)?;
    issue.shard = Some(Shard::new(primary.clone(), backups, claim_ttl_ms, 1));
    Ok(issue)
}

fn sharded_claimed_issue(
    id: &str,
    claimant: &AgentId,
    role: x0x_symphony_core::ShardRole,
    ts: String,
    shard: Shard,
) -> Result<Issue, Box<dyn Error>> {
    let mut issue = make_issue(id, "in_progress")?;
    issue.shard = Some(shard);
    issue.claim = Some(
        Claim::new(Some(issue.id.clone()), claimant.clone(), ts.clone(), role).with_heartbeat(ts),
    );
    Ok(issue)
}

// ---------- stub workspace ----------

#[derive(Default)]
struct StubWorkspace {
    root: PathBuf,
    created: Mutex<Vec<PathBuf>>,
    destroyed: Mutex<Vec<PathBuf>>,
    /// When true, `create` fails — used to exercise the budget-slot guard on the
    /// `?` error path of `run_claim`.
    create_fails: bool,
}

#[async_trait]
impl Workspace for StubWorkspace {
    fn root(&self) -> &Path {
        &self.root
    }
    async fn create(&self, issue: &Issue) -> CoreResult<WorkspaceHandle> {
        if self.create_fails {
            return Err(x0x_symphony_core::SymphonyError::Tracker(
                "stub create failed".into(),
            ));
        }
        let path = self.root.join(issue.identifier.as_str());
        std::fs::create_dir_all(&path)
            .map_err(|e| x0x_symphony_core::SymphonyError::Tracker(e.to_string()))?;
        if let Ok(mut created) = self.created.lock() {
            created.push(path.clone());
        }
        Ok(WorkspaceHandle::new(issue.id.clone(), path, true))
    }
    async fn run_hook(&self, _hook: &Hook, _env: &HookEnv) -> CoreResult<HookOutcome> {
        Ok(HookOutcome::new(HookStatus::Succeeded))
    }
    async fn destroy(&self, handle: WorkspaceHandle) -> CoreResult<()> {
        if let Ok(mut destroyed) = self.destroyed.lock() {
            destroyed.push(handle.path);
        }
        Ok(())
    }
}

// ---------- stub runner ----------

#[derive(Clone, Copy)]
enum RunBehavior {
    Succeed,
    Fail,
    Hang,
    /// Succeeds after sleeping for the given duration (exercises the heartbeat path).
    SucceedAfter(std::time::Duration),
}

struct StubRunner {
    behavior: RunBehavior,
}

impl StubRunner {
    const fn succeeding() -> Self {
        Self {
            behavior: RunBehavior::Succeed,
        }
    }
    const fn failing() -> Self {
        Self {
            behavior: RunBehavior::Fail,
        }
    }
    const fn hanging() -> Self {
        Self {
            behavior: RunBehavior::Hang,
        }
    }
    fn succeeding_after(delay: std::time::Duration) -> Self {
        Self {
            behavior: RunBehavior::SucceedAfter(delay),
        }
    }
}

#[async_trait]
impl Runner for StubRunner {
    fn name(&self) -> &'static str {
        "stub"
    }
    fn capabilities(&self) -> &RunnerCapabilities {
        static CAPS: std::sync::OnceLock<RunnerCapabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| RunnerCapabilities::new("stub"))
    }
    async fn start_session(&self, ctx: SessionContext) -> CoreResult<SessionHandle> {
        let label = ctx
            .workspace_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("x");
        Ok(SessionHandle::new(
            SessionId::new(format!("session-{label}")),
            ctx.workspace_path,
            "now",
        ))
    }
    async fn run_turn(
        &self,
        _sess: &mut SessionHandle,
        _prompt: Prompt,
    ) -> CoreResult<TurnOutcome> {
        match self.behavior {
            RunBehavior::Succeed => Ok(TurnOutcome::new(TurnStatus::Succeeded, UsageReport::new())),
            RunBehavior::Fail => Ok(TurnOutcome::new(TurnStatus::Failed, UsageReport::new())),
            RunBehavior::SucceedAfter(delay) => {
                tokio::time::sleep(delay).await;
                Ok(TurnOutcome::new(TurnStatus::Succeeded, UsageReport::new()))
            }
            RunBehavior::Hang => {
                // Never completes in tests; preempted by graceful shutdown.
                std::future::pending::<()>().await;
                unreachable!("pending never returns")
            }
        }
    }
    fn stream_events(&self, _sess: &SessionHandle) -> EventStream {
        Box::pin(stream::empty::<RunnerEvent>())
    }
    async fn stop_session(&self, _sess: SessionHandle) -> CoreResult<UsageReport> {
        Ok(UsageReport::new())
    }
}

#[derive(Default)]
struct ExecutionSpy {
    workspace_create: Mutex<u32>,
    workspace_hook: Mutex<u32>,
    runner_start: Mutex<u32>,
    runner_turn: Mutex<u32>,
}

impl ExecutionSpy {
    fn record(counter: &Mutex<u32>) {
        if let Ok(mut value) = counter.lock() {
            *value = value.saturating_add(1);
        }
    }

    fn counts(&self) -> (u32, u32, u32, u32) {
        (
            self.workspace_create.lock().map_or(0, |value| *value),
            self.workspace_hook.lock().map_or(0, |value| *value),
            self.runner_start.lock().map_or(0, |value| *value),
            self.runner_turn.lock().map_or(0, |value| *value),
        )
    }
}

struct SpyWorkspace {
    root: PathBuf,
    spy: Arc<ExecutionSpy>,
}

#[async_trait]
impl Workspace for SpyWorkspace {
    fn root(&self) -> &Path {
        &self.root
    }

    async fn create(&self, issue: &Issue) -> CoreResult<WorkspaceHandle> {
        ExecutionSpy::record(&self.spy.workspace_create);
        let path = self.root.join(issue.identifier.as_str());
        std::fs::create_dir_all(&path)
            .map_err(|e| x0x_symphony_core::SymphonyError::Tracker(e.to_string()))?;
        Ok(WorkspaceHandle::new(issue.id.clone(), path, true))
    }

    async fn run_hook(&self, _hook: &Hook, _env: &HookEnv) -> CoreResult<HookOutcome> {
        ExecutionSpy::record(&self.spy.workspace_hook);
        Ok(HookOutcome::new(HookStatus::Succeeded))
    }

    async fn destroy(&self, _handle: WorkspaceHandle) -> CoreResult<()> {
        Ok(())
    }
}

struct SpyRunner {
    spy: Arc<ExecutionSpy>,
}

#[async_trait]
impl Runner for SpyRunner {
    fn name(&self) -> &'static str {
        "spy"
    }

    fn capabilities(&self) -> &RunnerCapabilities {
        static CAPS: std::sync::OnceLock<RunnerCapabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| RunnerCapabilities::new("spy"))
    }

    async fn start_session(&self, ctx: SessionContext) -> CoreResult<SessionHandle> {
        ExecutionSpy::record(&self.spy.runner_start);
        Ok(SessionHandle::new(
            SessionId::new("spy-session"),
            ctx.workspace_path,
            "now",
        ))
    }

    async fn run_turn(
        &self,
        _sess: &mut SessionHandle,
        _prompt: Prompt,
    ) -> CoreResult<TurnOutcome> {
        ExecutionSpy::record(&self.spy.runner_turn);
        Ok(TurnOutcome::new(TurnStatus::Succeeded, UsageReport::new()))
    }

    fn stream_events(&self, _sess: &SessionHandle) -> EventStream {
        Box::pin(stream::empty::<RunnerEvent>())
    }

    async fn stop_session(&self, _sess: SessionHandle) -> CoreResult<UsageReport> {
        Ok(UsageReport::new())
    }
}

struct EventfulRunner {
    status: TurnStatus,
    events: Vec<RunnerEvent>,
    artifact: Option<(String, Vec<u8>)>,
}

impl EventfulRunner {
    fn success(events: Vec<RunnerEvent>) -> Self {
        Self {
            status: TurnStatus::Succeeded,
            events,
            artifact: None,
        }
    }

    fn failure(events: Vec<RunnerEvent>) -> Self {
        Self {
            status: TurnStatus::Failed,
            events,
            artifact: None,
        }
    }

    fn with_artifact(mut self, name: &str, bytes: &[u8]) -> Self {
        self.artifact = Some((name.to_owned(), bytes.to_vec()));
        self
    }
}

#[async_trait]
impl Runner for EventfulRunner {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn capabilities(&self) -> &RunnerCapabilities {
        static CAPS: std::sync::OnceLock<RunnerCapabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| RunnerCapabilities::new("stub"))
    }

    async fn start_session(&self, ctx: SessionContext) -> CoreResult<SessionHandle> {
        if let Some((name, bytes)) = &self.artifact {
            std::fs::write(ctx.workspace_path.join(name), bytes)
                .map_err(|source| x0x_symphony_core::SymphonyError::Runner(source.to_string()))?;
        }
        Ok(SessionHandle::new(
            SessionId::new("eventful-session"),
            ctx.workspace_path,
            "now",
        ))
    }

    async fn run_turn(
        &self,
        _sess: &mut SessionHandle,
        _prompt: Prompt,
    ) -> CoreResult<TurnOutcome> {
        Ok(
            TurnOutcome::new(self.status.clone(), UsageReport::new()).with_summary(
                match self.status {
                    TurnStatus::Succeeded => "exit_code=0",
                    TurnStatus::Failed => "exit_code=7",
                    TurnStatus::TimedOut => "turn timed out",
                    TurnStatus::Cancelled => "turn cancelled",
                },
            ),
        )
    }

    fn stream_events(&self, _sess: &SessionHandle) -> EventStream {
        Box::pin(stream::iter(self.events.clone()))
    }

    async fn stop_session(&self, _sess: SessionHandle) -> CoreResult<UsageReport> {
        Ok(UsageReport::new())
    }
}

struct GitChangingRunner;

#[async_trait]
impl Runner for GitChangingRunner {
    fn name(&self) -> &'static str {
        "git-changing"
    }

    fn capabilities(&self) -> &RunnerCapabilities {
        static CAPS: std::sync::OnceLock<RunnerCapabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| RunnerCapabilities::new("git-changing"))
    }

    async fn start_session(&self, ctx: SessionContext) -> CoreResult<SessionHandle> {
        init_tracked_git_repo(&ctx.workspace_path)?;
        std::fs::write(ctx.workspace_path.join("tracked.txt"), b"changed\n")
            .map_err(|source| x0x_symphony_core::SymphonyError::Runner(source.to_string()))?;
        Ok(SessionHandle::new(
            SessionId::new("git-changing-session"),
            ctx.workspace_path,
            "now",
        ))
    }

    async fn run_turn(
        &self,
        _sess: &mut SessionHandle,
        _prompt: Prompt,
    ) -> CoreResult<TurnOutcome> {
        Ok(TurnOutcome::new(TurnStatus::Succeeded, UsageReport::new()))
    }

    fn stream_events(&self, _sess: &SessionHandle) -> EventStream {
        Box::pin(stream::empty::<RunnerEvent>())
    }

    async fn stop_session(&self, _sess: SessionHandle) -> CoreResult<UsageReport> {
        Ok(UsageReport::new())
    }
}

fn init_tracked_git_repo(path: &Path) -> CoreResult<()> {
    run_git(path, &["init"])?;
    run_git(path, &["config", "user.email", "runner@example.invalid"])?;
    run_git(path, &["config", "user.name", "Test Runner"])?;
    std::fs::write(path.join("tracked.txt"), b"base\n")
        .map_err(|source| x0x_symphony_core::SymphonyError::Runner(source.to_string()))?;
    run_git(path, &["add", "tracked.txt"])?;
    run_git(path, &["commit", "-m", "initial"])
}

fn run_git(path: &Path, args: &[&str]) -> CoreResult<()> {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|source| x0x_symphony_core::SymphonyError::Runner(source.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(x0x_symphony_core::SymphonyError::Runner(format!(
            "git {:?} failed with exit code {:?}",
            args,
            status.code()
        )))
    }
}

// ---------- stub tracker ----------

#[derive(Default)]
struct StubTracker {
    issues: Mutex<Vec<Issue>>,
    releases: Mutex<Vec<(IssueId, ReleaseReasonCode)>>,
    handoffs: Mutex<Vec<Handoff>>,
    approvals: Mutex<ApprovalState>,
    abandons: Mutex<Vec<(IssueId, AgentId)>>,
    /// Number of times `heartbeat` was called (proves the periodic task fires).
    heartbeats: Mutex<u32>,
}

impl StubTracker {
    fn with(issues: Vec<Issue>) -> Self {
        Self {
            issues: Mutex::new(issues),
            ..Self::default()
        }
    }
}

#[derive(Default)]
struct MockTrustClient {
    levels: BTreeMap<String, TrustLevel>,
    calls: Mutex<Vec<String>>,
}

impl MockTrustClient {
    fn with_levels<I, S>(levels: I) -> Self
    where
        I: IntoIterator<Item = (S, TrustLevel)>,
        S: Into<String>,
    {
        Self {
            levels: levels
                .into_iter()
                .map(|(agent, level)| (agent.into(), level))
                .collect(),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<String> {
        guard(&self.calls).clone()
    }
}

#[async_trait]
impl TrustClient for MockTrustClient {
    async fn trust_level(&self, agent_id: &str) -> x0x_symphony_orchestrator::Result<TrustLevel> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(agent_id.to_owned());
        }
        Ok(self
            .levels
            .get(agent_id)
            .copied()
            .unwrap_or(TrustLevel::Unknown))
    }
}

fn lock<T>(m: &Mutex<T>) -> CoreResult<std::sync::MutexGuard<'_, T>> {
    m.lock()
        .map_err(|e| x0x_symphony_core::SymphonyError::Tracker(format!("poisoned: {e}")))
}

/// Recover a mutex guard, treating poison as recovered (tests never poison).
fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn set_state(issue: &mut Issue, name: &str) -> CoreResult<()> {
    issue.state = IssueState::new(name)
        .map_err(|e| x0x_symphony_core::SymphonyError::Tracker(e.to_string()))?;
    Ok(())
}

fn shard_role_for(issue: &Issue, agent_id: &AgentId) -> x0x_symphony_core::ShardRole {
    let Some(shard) = issue.shard.as_ref() else {
        return x0x_symphony_core::ShardRole::ManualM1;
    };
    if shard.primary.eq(agent_id) {
        return x0x_symphony_core::ShardRole::Primary;
    }
    shard
        .backups
        .iter()
        .position(|backup| backup == agent_id)
        .map_or(
            x0x_symphony_core::ShardRole::ManualM1,
            x0x_symphony_core::ShardRole::Backup,
        )
}

#[async_trait]
impl x0x_symphony_core::Tracker for StubTracker {
    async fn fetch_candidates(&self, ctx: &PollContext) -> CoreResult<Vec<Issue>> {
        let active: BTreeSet<IssueState> = ctx.active_states.iter().cloned().collect();
        Ok(lock(&self.issues)?
            .iter()
            .filter(|i| active.contains(&i.state))
            .cloned()
            .collect())
    }
    async fn fetch_by_ids(&self, ids: &[IssueId]) -> CoreResult<Vec<Issue>> {
        Ok(lock(&self.issues)?
            .iter()
            .filter(|i| ids.contains(&i.id))
            .cloned()
            .collect())
    }
    async fn fetch_claimed(&self, agent_id: Option<&AgentId>) -> CoreResult<Vec<Issue>> {
        Ok(lock(&self.issues)?
            .iter()
            .filter(|i| i.claim.is_some())
            .filter(|i| agent_id.is_none_or(|a| i.claim.as_ref().is_some_and(|c| &c.by == a)))
            .cloned()
            .collect())
    }
    async fn claim(&self, id: &IssueId, agent_id: &AgentId) -> CoreResult<Claim> {
        let mut issues = lock(&self.issues)?;
        let issue = issues
            .iter_mut()
            .find(|i| &i.id == id)
            .ok_or_else(|| x0x_symphony_core::SymphonyError::Tracker("not found".into()))?;
        if issue.claim.is_some() {
            return Err(x0x_symphony_core::SymphonyError::Tracker(
                "already claimed".into(),
            ));
        }
        let now = now_iso();
        let shard_role = shard_role_for(issue, agent_id);
        let claim = Claim::new(Some(id.clone()), agent_id.clone(), now.clone(), shard_role);
        set_state(&mut *issue, "in_progress")?;
        issue.claim = Some(claim.clone());
        Ok(claim)
    }
    async fn heartbeat(&self, claim: &Claim) -> CoreResult<()> {
        let mut issues = lock(&self.issues)?;
        if let Some(id) = &claim.issue_id {
            if let Some(issue) = issues.iter_mut().find(|i| &i.id == id) {
                if let Some(c) = issue.claim.as_mut() {
                    c.heartbeat_at = now_iso();
                }
            }
        }
        drop(issues);
        *lock(&self.heartbeats)? += 1;
        Ok(())
    }
    async fn release(&self, claim: &Claim, reason: ReleaseReason) -> CoreResult<()> {
        let mut issues = lock(&self.issues)?;
        if let Some(id) = &claim.issue_id {
            if let Some(issue) = issues.iter_mut().find(|i| {
                &i.id == id
                    && i.claim
                        .as_ref()
                        .is_some_and(|current| current.by.eq(&claim.by))
            }) {
                issue.claim = None;
                set_state(&mut *issue, "todo")?;
            }
            let code = reason.code.clone();
            if code == ReleaseReasonCode::Conflict {
                lock(&self.abandons)?.push((id.clone(), claim.by.clone()));
            }
            lock(&self.releases)?.push((id.clone(), code));
        }
        Ok(())
    }
    async fn handoff(&self, claim: &Claim, handoff: Handoff) -> CoreResult<()> {
        let mut issues = lock(&self.issues)?;
        if let Some(id) = &claim.issue_id {
            if let Some(issue) = issues.iter_mut().find(|i| &i.id == id) {
                issue.claim = None;
                issue.handoff = Some(handoff.clone());
                set_state(&mut *issue, "review")?;
            }
        }
        drop(issues);
        lock(&self.handoffs)?.push(handoff);
        Ok(())
    }
    async fn block(&self, claim: &Claim, reason: ReleaseReason) -> CoreResult<()> {
        let mut issues = lock(&self.issues)?;
        if let Some(id) = &claim.issue_id {
            if let Some(issue) = issues.iter_mut().find(|i| &i.id == id) {
                issue.claim = None;
                set_state(&mut *issue, "blocked")?;
                issue.extra.insert(
                    "blocked_reason".to_string(),
                    serde_json::to_value(&reason).unwrap_or(serde_json::Value::Null),
                );
            }
            lock(&self.releases)?.push((id.clone(), reason.code));
        }
        Ok(())
    }

    async fn load_approval_state(&self, issue_id: &IssueId) -> CoreResult<ApprovalState> {
        let approvals = lock(&self.approvals)?;
        Ok(ApprovalState {
            events: approvals
                .events
                .iter()
                .filter(|event| &event.issue_id == issue_id)
                .cloned()
                .collect(),
            consumed: approvals
                .consumed
                .iter()
                .filter(|event| &event.issue_id == issue_id)
                .cloned()
                .collect(),
        })
    }

    async fn store_approval(&self, event: &ApprovalEvent) -> CoreResult<()> {
        lock(&self.approvals)?.events.push(event.clone());
        Ok(())
    }

    async fn store_consumed(&self, event: &ApprovalConsumed) -> CoreResult<()> {
        lock(&self.approvals)?.consumed.push(event.clone());
        Ok(())
    }
}

fn now_iso() -> String {
    // Millis precision so sub-second TTLs (used by the heartbeat test) compare
    // accurately against the injected clock in `is_fresh_self`.
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

// ---------- builders ----------

fn config_with(retry: RetryPolicy, concurrency: usize) -> Result<Config, Box<dyn Error>> {
    config_with_hooks(
        retry,
        concurrency,
        LifecycleHooks::default(),
        vec![state("done")?, state("cancelled")?],
    )
}

fn config_with_hooks(
    retry: RetryPolicy,
    concurrency: usize,
    hooks: LifecycleHooks,
    terminal_states: Vec<IssueState>,
) -> Result<Config, Box<dyn Error>> {
    config_with_hooks_and_proofs(
        retry,
        concurrency,
        hooks,
        terminal_states,
        default_test_proofs_dir(),
    )
}

fn config_with_hooks_and_proofs(
    retry: RetryPolicy,
    concurrency: usize,
    hooks: LifecycleHooks,
    terminal_states: Vec<IssueState>,
    proofs_dir: PathBuf,
) -> Result<Config, Box<dyn Error>> {
    Ok(Config::builder(agent()?)
        .active_states(vec![state("todo")?])
        .terminal_states(terminal_states)
        .global_concurrency(concurrency)
        .retry(retry)
        .hooks(hooks)
        .proofs_dir(proofs_dir)
        .build())
}

fn trust_config(required_trust: TrustLevel, proofs_dir: PathBuf) -> Result<Config, Box<dyn Error>> {
    network_config(required_trust, NetworkDispatchPolicy::Auto, proofs_dir)
}

fn network_config(
    required_trust: TrustLevel,
    policy: NetworkDispatchPolicy,
    proofs_dir: PathBuf,
) -> Result<Config, Box<dyn Error>> {
    Ok(Config::builder(agent()?)
        .active_states(vec![state("todo")?])
        .terminal_states(vec![state("done")?, state("cancelled")?])
        .global_concurrency(1)
        .retry(fast_retry(1))
        .required_trust(required_trust)
        .network_dispatch(policy)
        .proofs_dir(proofs_dir)
        .build())
}

fn default_test_proofs_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "x0x-symphony-orchestrator-tests-{}",
        std::process::id()
    ))
}

fn record_hook_script(log: &Path) -> String {
    format!(
        "printf '%s|%s|%s|%s|%s\\n' \"$HOOK_PHASE\" \"$PWD\" \"$ISSUE_ID\" \"$AGENT_ID\" \"$CLAIM_ID\" >> '{}'",
        log.display()
    )
}

fn read_hook_log(log: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    if !log.exists() {
        return Ok(Vec::new());
    }
    Ok(std::fs::read_to_string(log)?
        .lines()
        .map(ToOwned::to_owned)
        .collect())
}

fn proof_dir_from_handoff(root: &Path, handoff: &Handoff) -> Result<PathBuf, Box<dyn Error>> {
    let relative = handoff
        .proofs_dir
        .as_deref()
        .ok_or("handoff should link proofs_dir")?;
    let suffix = relative
        .strip_prefix("proofs/")
        .ok_or("proofs_dir should be relative to proofs root")?;
    Ok(root.join(suffix))
}

fn only_proof_run(root: &Path, issue_id: &str) -> Result<PathBuf, Box<dyn Error>> {
    let issue_dir = root.join(issue_id);
    let mut entries = std::fs::read_dir(issue_dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort();
    if entries.len() != 1 {
        return Err(format!("expected one proof run, got {}", entries.len()).into());
    }
    Ok(entries.remove(0))
}

fn manifest(path: &Path) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(serde_json::from_str(&std::fs::read_to_string(
        path.join("manifest.json"),
    )?)?)
}

fn fast_retry(max_attempts: u32) -> RetryPolicy {
    RetryPolicy::new(
        std::time::Duration::from_millis(1),
        std::time::Duration::from_millis(5),
        max_attempts,
    )
}

fn orc<T, R, W>(
    tracker: Arc<T>,
    runner: Arc<R>,
    workspace: Arc<W>,
    clock: Arc<dyn Clock>,
    config: Config,
) -> Orchestrator<T, R, W>
where
    T: x0x_symphony_core::Tracker,
    R: Runner,
    W: Workspace,
{
    Orchestrator::new(tracker, runner, workspace, clock, config)
}

fn orc_with_trust<T, R, W>(
    tracker: Arc<T>,
    runner: Arc<R>,
    workspace: Arc<W>,
    clock: Arc<dyn Clock>,
    config: Config,
    trust_client: Arc<dyn TrustClient>,
) -> Orchestrator<T, R, W>
where
    T: x0x_symphony_core::Tracker,
    R: Runner,
    W: Workspace,
{
    Orchestrator::new_with_trust_client(tracker, runner, workspace, clock, config, trust_client)
}

fn sysclock() -> Arc<dyn Clock> {
    Arc::new(SystemClock) as Arc<dyn Clock>
}

fn manual_clock(at: &str) -> Result<Arc<dyn Clock>, Box<dyn Error>> {
    Ok(Arc::new(ManualClock::new(parse_ts(at)?)) as Arc<dyn Clock>)
}

fn workspace_manager(tmp: &TempDir) -> Result<Arc<Manager>, Box<dyn Error>> {
    Ok(Arc::new(Manager::new(WorkspaceConfig::new(
        tmp.path().join("workspaces"),
    ))?))
}

fn create_workspace_dir(manager: &Manager, issue_id: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = manager.issue_path(issue_id)?;
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn orphan_config() -> Result<Config, Box<dyn Error>> {
    config_with_hooks(
        RetryPolicy::default(),
        1,
        LifecycleHooks::default(),
        vec![state("done")?, state("cancelled")?, state("duplicate")?],
    )
}

async fn run_spy_dispatch(
    issue: Issue,
    config: Config,
    trust: Arc<MockTrustClient>,
) -> Result<
    (
        Option<Resolution>,
        Arc<ExecutionSpy>,
        Arc<StubTracker>,
        Arc<MockTrustClient>,
    ),
    Box<dyn Error>,
> {
    run_spy_dispatch_with_approval_state(issue, config, trust, ApprovalState::default()).await
}

async fn run_spy_dispatch_with_approval_state(
    issue: Issue,
    config: Config,
    trust: Arc<MockTrustClient>,
    approval_state: ApprovalState,
) -> Result<
    (
        Option<Resolution>,
        Arc<ExecutionSpy>,
        Arc<StubTracker>,
        Arc<MockTrustClient>,
    ),
    Box<dyn Error>,
> {
    let tracker = Arc::new(StubTracker::with(vec![issue]));
    *lock(&tracker.approvals)? = approval_state;
    run_spy_dispatch_with_tracker(tracker, config, trust).await
}

async fn run_spy_dispatch_with_tracker(
    tracker: Arc<StubTracker>,
    config: Config,
    trust: Arc<MockTrustClient>,
) -> Result<
    (
        Option<Resolution>,
        Arc<ExecutionSpy>,
        Arc<StubTracker>,
        Arc<MockTrustClient>,
    ),
    Box<dyn Error>,
> {
    let tmp = TempDir::new()?;
    let spy = Arc::new(ExecutionSpy::default());
    let runner = Arc::new(SpyRunner {
        spy: Arc::clone(&spy),
    });
    let workspace = Arc::new(SpyWorkspace {
        root: tmp.path().join("workspaces"),
        spy: Arc::clone(&spy),
    });
    let trust_client: Arc<dyn TrustClient> = trust.clone();
    let orc = orc_with_trust(
        Arc::clone(&tracker),
        runner,
        workspace,
        sysclock(),
        config,
        trust_client,
    );

    let resolution = orc.run_once().await?;
    Ok((resolution, spy, tracker, trust))
}

fn assert_no_execution_calls(spy: &ExecutionSpy) {
    assert_eq!(spy.counts(), (0, 0, 0, 0));
}

fn assert_blocked_with_code(
    tracker: &StubTracker,
    issue_id: &str,
    code: &ReleaseReasonCode,
) -> Result<(), Box<dyn Error>> {
    assert!(guard(&tracker.releases)
        .iter()
        .any(|(id, release_code)| id.as_str() == issue_id && release_code == code));
    let issues = guard(&tracker.issues);
    let issue = issues
        .iter()
        .find(|issue| issue.id.as_str() == issue_id)
        .ok_or("issue should remain in tracker")?;
    assert_eq!(issue.state, state("blocked")?);
    let blocked_code = issue
        .extra
        .get("blocked_reason")
        .and_then(|value| value.get("code"))
        .and_then(|value| value.as_str())
        .ok_or("blocked reason code should be recorded")?;
    assert_eq!(blocked_code, code.as_str());
    Ok(())
}

fn signed_approval_event(
    issue: &Issue,
    signer: &str,
    verdict: ApprovalVerdict,
    approved_at: &str,
) -> Result<ApprovalEvent, Box<dyn Error>> {
    let signer = AgentId::new(signer)?;
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

fn signed_consumed_event(
    event: &ApprovalEvent,
    nonce: &str,
    consumed_at: &str,
) -> Result<ApprovalConsumed, Box<dyn Error>> {
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
    Ok(consumed)
}

async fn store_approval(
    tracker: &StubTracker,
    event: &ApprovalEvent,
) -> Result<(), Box<dyn Error>> {
    Tracker::store_approval(tracker, event).await?;
    Ok(())
}

fn assert_consumed_count(tracker: &StubTracker, expected: usize) {
    let approvals = guard(&tracker.approvals);
    assert_eq!(approvals.consumed.len(), expected);
    for consumed in &approvals.consumed {
        assert!(consumed.signature_envelope_is_consistent());
    }
}

// ---------- tests ----------

#[tokio::test]
async fn unsigned_network_issue_never_dispatched() -> Result<(), Box<dyn Error>> {
    let issue = unsigned_network_issue("XSY-GATE-UNSIGNED", &["feature"])?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Auto,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::default());

    let (resolution, spy, tracker, trust) = run_spy_dispatch(issue, config, trust).await?;

    assert_eq!(resolution, Some(Resolution::Blocked));
    assert_no_execution_calls(&spy);
    assert!(trust.calls().is_empty());
    assert_blocked_with_code(
        &tracker,
        "XSY-GATE-UNSIGNED",
        &ReleaseReasonCode::MissingVerifiedSignature,
    )?;
    Ok(())
}

#[tokio::test]
async fn invalid_signature_never_dispatched() -> Result<(), Box<dyn Error>> {
    let issue = network_issue_with_provenance(
        "XSY-GATE-INVALID",
        &["feature"],
        Some(SignatureProvenance::invalid("signature mismatch")),
    )?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Auto,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::default());

    let (resolution, spy, tracker, trust) = run_spy_dispatch(issue, config, trust).await?;

    assert_eq!(resolution, Some(Resolution::Blocked));
    assert_no_execution_calls(&spy);
    assert!(trust.calls().is_empty());
    assert_blocked_with_code(
        &tracker,
        "XSY-GATE-INVALID",
        &ReleaseReasonCode::InvalidSignature,
    )?;
    Ok(())
}

#[tokio::test]
async fn verify_transport_error_refused_not_silently_dropped() -> Result<(), Box<dyn Error>> {
    let issue = network_issue_with_provenance(
        "XSY-GATE-TRANSPORT",
        &["feature"],
        Some(SignatureProvenance::transport_error("x0xd unavailable")),
    )?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Auto,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::default());

    let (resolution, spy, tracker, trust) = run_spy_dispatch(issue, config, trust).await?;

    assert_eq!(resolution, Some(Resolution::Blocked));
    assert_no_execution_calls(&spy);
    assert!(trust.calls().is_empty());
    assert_blocked_with_code(
        &tracker,
        "XSY-GATE-TRANSPORT",
        &ReleaseReasonCode::VerifyTransportError,
    )?;
    Ok(())
}

#[tokio::test]
async fn untrusted_signer_never_dispatched() -> Result<(), Box<dyn Error>> {
    for (issue_id, signer, level, code) in [
        (
            "XSY-GATE-UNKNOWN",
            "unknown-signer",
            TrustLevel::Unknown,
            ReleaseReasonCode::UnknownSigner,
        ),
        (
            "XSY-GATE-KNOWN",
            "known-signer",
            TrustLevel::Known,
            ReleaseReasonCode::UntrustedSigner,
        ),
    ] {
        let issue = network_issue(issue_id, &["feature"], signer)?;
        let config = network_config(
            TrustLevel::Trusted,
            NetworkDispatchPolicy::Auto,
            default_test_proofs_dir(),
        )?;
        let trust = Arc::new(MockTrustClient::with_levels([(signer, level)]));

        let (resolution, spy, tracker, trust) = run_spy_dispatch(issue, config, trust).await?;

        assert_eq!(resolution, Some(Resolution::Blocked));
        assert_no_execution_calls(&spy);
        assert_eq!(trust.calls(), vec![signer.to_owned()]);
        assert_blocked_with_code(&tracker, issue_id, &code)?;
    }
    Ok(())
}

#[tokio::test]
async fn blocked_signer_never_dispatched() -> Result<(), Box<dyn Error>> {
    let issue = network_issue("XSY-GATE-BLOCKED", &["feature"], "blocked-signer")?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Auto,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::with_levels([(
        "blocked-signer",
        TrustLevel::Blocked,
    )]));

    let (resolution, spy, tracker, trust) = run_spy_dispatch(issue, config, trust).await?;

    assert_eq!(resolution, Some(Resolution::Blocked));
    assert_no_execution_calls(&spy);
    assert_eq!(trust.calls(), vec!["blocked-signer".to_owned()]);
    assert_blocked_with_code(
        &tracker,
        "XSY-GATE-BLOCKED",
        &ReleaseReasonCode::BlockedSigner,
    )?;
    Ok(())
}

#[tokio::test]
async fn default_off_refuses_all_network_dispatch() -> Result<(), Box<dyn Error>> {
    let issue = network_issue("XSY-GATE-DEFAULT-OFF", &["feature"], "trusted-signer")?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Off,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::with_levels([(
        "trusted-signer",
        TrustLevel::Trusted,
    )]));

    let (resolution, spy, tracker, trust) = run_spy_dispatch(issue, config, trust).await?;

    assert_eq!(resolution, Some(Resolution::Blocked));
    assert_no_execution_calls(&spy);
    assert!(trust.calls().is_empty());
    assert_blocked_with_code(
        &tracker,
        "XSY-GATE-DEFAULT-OFF",
        &ReleaseReasonCode::NetworkDispatchDisabled,
    )?;
    Ok(())
}

#[tokio::test]
async fn approve_mode_refuses_without_execution() -> Result<(), Box<dyn Error>> {
    let issue = network_issue("XSY-GATE-APPROVE", &["feature"], "trusted-signer")?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Approve,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::with_levels([(
        "trusted-signer",
        TrustLevel::Trusted,
    )]));

    let (resolution, spy, tracker, trust) = run_spy_dispatch(issue, config, trust).await?;

    assert_eq!(resolution, Some(Resolution::PendingApproval));
    assert_no_execution_calls(&spy);
    assert_eq!(trust.calls(), vec!["trusted-signer".to_owned()]);
    assert_blocked_with_code(
        &tracker,
        "XSY-GATE-APPROVE",
        &ReleaseReasonCode::AwaitingApproval,
    )?;
    Ok(())
}

#[tokio::test]
async fn approve_with_valid_approval_dispatches() -> Result<(), Box<dyn Error>> {
    let issue = network_issue("XSY-APPROVE-VALID", &["feature"], "trusted-signer")?;
    let approval = signed_approval_event(
        &issue,
        "trusted-signer",
        ApprovalVerdict::Approve,
        &now_iso(),
    )?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Approve,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::with_levels([(
        "trusted-signer",
        TrustLevel::Trusted,
    )]));

    let (resolution, spy, tracker, trust) = run_spy_dispatch_with_approval_state(
        issue,
        config,
        trust,
        ApprovalState {
            events: vec![approval],
            consumed: Vec::new(),
        },
    )
    .await?;

    assert_eq!(resolution, Some(Resolution::Completed));
    assert_eq!(spy.counts(), (1, 0, 1, 1));
    assert_eq!(trust.calls(), vec!["trusted-signer".to_owned()]);
    assert_eq!(guard(&tracker.handoffs).len(), 1);
    assert_consumed_count(&tracker, 1);
    Ok(())
}

#[tokio::test]
async fn approve_missing_approval_enters_pending() -> Result<(), Box<dyn Error>> {
    let issue = network_issue("XSY-APPROVE-MISSING", &["feature"], "trusted-signer")?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Approve,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::with_levels([(
        "trusted-signer",
        TrustLevel::Trusted,
    )]));

    let (resolution, spy, tracker, trust) = run_spy_dispatch(issue, config, trust).await?;

    assert_eq!(resolution, Some(Resolution::PendingApproval));
    assert_no_execution_calls(&spy);
    assert_eq!(trust.calls(), vec!["trusted-signer".to_owned()]);
    assert_consumed_count(&tracker, 0);
    assert_blocked_with_code(
        &tracker,
        "XSY-APPROVE-MISSING",
        &ReleaseReasonCode::AwaitingApproval,
    )?;
    Ok(())
}

#[tokio::test]
async fn approve_expired_approval_re_pending() -> Result<(), Box<dyn Error>> {
    let issue = network_issue("XSY-APPROVE-EXPIRED", &["feature"], "trusted-signer")?;
    let approval = signed_approval_event(
        &issue,
        "trusted-signer",
        ApprovalVerdict::Approve,
        "2000-01-01T00:00:00Z",
    )?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Approve,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::with_levels([(
        "trusted-signer",
        TrustLevel::Trusted,
    )]));

    let (resolution, spy, tracker, _trust) = run_spy_dispatch_with_approval_state(
        issue,
        config,
        trust,
        ApprovalState {
            events: vec![approval],
            consumed: Vec::new(),
        },
    )
    .await?;

    assert_eq!(resolution, Some(Resolution::PendingApproval));
    assert_no_execution_calls(&spy);
    assert_consumed_count(&tracker, 0);
    assert_blocked_with_code(
        &tracker,
        "XSY-APPROVE-EXPIRED",
        &ReleaseReasonCode::AwaitingApproval,
    )?;
    Ok(())
}

#[tokio::test]
async fn approve_consumed_approval_re_pending() -> Result<(), Box<dyn Error>> {
    let issue = network_issue("XSY-APPROVE-CONSUMED", &["feature"], "trusted-signer")?;
    let approval = signed_approval_event(
        &issue,
        "trusted-signer",
        ApprovalVerdict::Approve,
        &now_iso(),
    )?;
    let consumed = signed_consumed_event(&approval, "nonce-1", &now_iso())?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Approve,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::with_levels([(
        "trusted-signer",
        TrustLevel::Trusted,
    )]));

    let (resolution, spy, tracker, _trust) = run_spy_dispatch_with_approval_state(
        issue,
        config,
        trust,
        ApprovalState {
            events: vec![approval],
            consumed: vec![consumed],
        },
    )
    .await?;

    assert_eq!(resolution, Some(Resolution::PendingApproval));
    assert_no_execution_calls(&spy);
    assert_consumed_count(&tracker, 1);
    assert_blocked_with_code(
        &tracker,
        "XSY-APPROVE-CONSUMED",
        &ReleaseReasonCode::AwaitingApproval,
    )?;
    Ok(())
}

#[tokio::test]
async fn approve_payload_mismatch_re_pending() -> Result<(), Box<dyn Error>> {
    let original = network_issue("XSY-APPROVE-MISMATCH", &["feature"], "trusted-signer")?;
    let approval = signed_approval_event(
        &original,
        "trusted-signer",
        ApprovalVerdict::Approve,
        &now_iso(),
    )?;
    let mut changed = original;
    changed.description = "changed payload after approval".to_owned();
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Approve,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::with_levels([(
        "trusted-signer",
        TrustLevel::Trusted,
    )]));

    let (resolution, spy, tracker, _trust) = run_spy_dispatch_with_approval_state(
        changed,
        config,
        trust,
        ApprovalState {
            events: vec![approval],
            consumed: Vec::new(),
        },
    )
    .await?;

    assert_eq!(resolution, Some(Resolution::PendingApproval));
    assert_no_execution_calls(&spy);
    assert_consumed_count(&tracker, 0);
    assert_blocked_with_code(
        &tracker,
        "XSY-APPROVE-MISMATCH",
        &ReleaseReasonCode::AwaitingApproval,
    )?;
    Ok(())
}

#[tokio::test]
async fn approve_denial_blocks_dispatch() -> Result<(), Box<dyn Error>> {
    let issue = network_issue("XSY-APPROVE-DENIED", &["feature"], "trusted-signer")?;
    let approval = signed_approval_event(
        &issue,
        "trusted-signer",
        ApprovalVerdict::Approve,
        &now_iso(),
    )?;
    let denial =
        signed_approval_event(&issue, "trusted-signer", ApprovalVerdict::Deny, &now_iso())?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Approve,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::with_levels([(
        "trusted-signer",
        TrustLevel::Trusted,
    )]));

    let (resolution, spy, tracker, _trust) = run_spy_dispatch_with_approval_state(
        issue,
        config,
        trust,
        ApprovalState {
            events: vec![approval, denial],
            consumed: Vec::new(),
        },
    )
    .await?;

    assert_eq!(resolution, Some(Resolution::PendingApproval));
    assert_no_execution_calls(&spy);
    assert_consumed_count(&tracker, 0);
    assert_blocked_with_code(
        &tracker,
        "XSY-APPROVE-DENIED",
        &ReleaseReasonCode::AwaitingApproval,
    )?;
    Ok(())
}

#[tokio::test]
async fn approve_sig_failure_refuses_not_pending() -> Result<(), Box<dyn Error>> {
    let issue = unsigned_network_issue("XSY-APPROVE-SIGFAIL", &["feature"])?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Approve,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::default());

    let (resolution, spy, tracker, trust) = run_spy_dispatch(issue, config, trust).await?;

    assert_eq!(resolution, Some(Resolution::Blocked));
    assert_no_execution_calls(&spy);
    assert!(trust.calls().is_empty());
    assert_consumed_count(&tracker, 0);
    assert_blocked_with_code(
        &tracker,
        "XSY-APPROVE-SIGFAIL",
        &ReleaseReasonCode::MissingVerifiedSignature,
    )?;
    Ok(())
}

#[tokio::test]
async fn resumed_claim_with_valid_approval_executes() -> Result<(), Box<dyn Error>> {
    let issue = network_issue("XSY-APPROVE-RESUME", &["feature"], "trusted-signer")?;
    let approval = signed_approval_event(
        &issue,
        "trusted-signer",
        ApprovalVerdict::Approve,
        &now_iso(),
    )?;
    let tracker = Arc::new(StubTracker::with(vec![issue.clone()]));
    store_approval(&tracker, &approval).await?;

    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Approve,
        default_test_proofs_dir(),
    )?;
    let trust1 = Arc::new(MockTrustClient::with_levels([(
        "trusted-signer",
        TrustLevel::Trusted,
    )]));
    let (res1, spy1, tracker, _trust1) =
        run_spy_dispatch_with_tracker(Arc::clone(&tracker), config.clone(), trust1).await?;

    assert_eq!(res1, Some(Resolution::Completed));
    assert_eq!(spy1.counts(), (1, 0, 1, 1));
    assert_consumed_count(&tracker, 1);

    {
        let mut issues = lock(&tracker.issues)?;
        let issue = issues
            .iter_mut()
            .find(|candidate| candidate.id.as_str() == "XSY-APPROVE-RESUME")
            .ok_or("issue should remain in tracker")?;
        issue.claim = None;
        issue.handoff = None;
        set_state(&mut *issue, "todo")?;
    }

    let trust2 = Arc::new(MockTrustClient::with_levels([(
        "trusted-signer",
        TrustLevel::Trusted,
    )]));
    let (res2, spy2, tracker, _trust2) =
        run_spy_dispatch_with_tracker(Arc::clone(&tracker), config, trust2).await?;

    assert_eq!(res2, Some(Resolution::PendingApproval));
    assert_no_execution_calls(&spy2);
    assert_consumed_count(&tracker, 1);
    assert_blocked_with_code(
        &tracker,
        "XSY-APPROVE-RESUME",
        &ReleaseReasonCode::AwaitingApproval,
    )?;
    Ok(())
}

#[tokio::test]
async fn verified_trusted_enabled_dispatches() -> Result<(), Box<dyn Error>> {
    let issue = network_issue("XSY-GATE-POSITIVE", &["feature"], "trusted-signer")?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Auto,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::with_levels([(
        "trusted-signer",
        TrustLevel::Trusted,
    )]));

    let (resolution, spy, tracker, trust) = run_spy_dispatch(issue, config, trust).await?;

    assert_eq!(resolution, Some(Resolution::Completed));
    assert_eq!(spy.counts(), (1, 0, 1, 1));
    assert_eq!(trust.calls(), vec!["trusted-signer".to_owned()]);
    assert_eq!(guard(&tracker.handoffs).len(), 1);
    assert!(guard(&tracker.releases).is_empty());
    Ok(())
}

#[tokio::test]
async fn provenance_with_local_marker_still_gated() -> Result<(), Box<dyn Error>> {
    // Self-enforcing gate: an issue whose marker claims `local` but carries
    // network signature provenance must NOT slip past the gate. The old
    // fail-open classification (marker == Local => bypass) would dispatch this;
    // the hardened gate treats provenance presence as network-sourced and
    // refuses because network dispatch is disabled (M3 default).
    let issue = local_marker_with_provenance(
        "XSY-GATE-TAMPER",
        &["feature"],
        Some(SignatureProvenance::verified("agent-tamper")),
    )?;
    let config = network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Off,
        default_test_proofs_dir(),
    )?;
    let trust = Arc::new(MockTrustClient::default());

    let (resolution, spy, tracker, trust) = run_spy_dispatch(issue, config, trust).await?;

    assert_eq!(resolution, Some(Resolution::Blocked));
    assert_no_execution_calls(&spy);
    assert!(
        trust.calls().is_empty(),
        "disabled dispatch must never query trust"
    );
    assert_blocked_with_code(
        &tracker,
        "XSY-GATE-TAMPER",
        &ReleaseReasonCode::NetworkDispatchDisabled,
    )?;
    Ok(())
}

#[tokio::test]
async fn resumed_network_claim_is_re_gated_not_trusted_from_prior_state(
) -> Result<(), Box<dyn Error>> {
    // After a restart, a network-sourced issue is re-gated on every run_claim
    // — it is never trusted from a prior pass. Two independent orchestrator
    // lifecycles (fresh state = restart) both refuse the same unsigned network
    // issue with zero execution calls.
    let issue = unsigned_network_issue("XSY-GATE-RESUME", &["feature"])?;

    // First lifecycle: blocked, zero execution.
    let (res1, spy1, tracker1, _) = run_spy_dispatch(
        issue.clone(),
        network_config_trusted_enabled()?,
        Arc::new(MockTrustClient::default()),
    )
    .await?;
    assert_eq!(res1, Some(Resolution::Blocked));
    assert_no_execution_calls(&spy1);
    assert_blocked_with_code(
        &tracker1,
        "XSY-GATE-RESUME",
        &ReleaseReasonCode::MissingVerifiedSignature,
    )?;

    // Restart: fresh orchestrator, same network issue — re-gated, not trusted.
    let (res2, spy2, tracker2, _) = run_spy_dispatch(
        issue,
        network_config_trusted_enabled()?,
        Arc::new(MockTrustClient::default()),
    )
    .await?;
    assert_eq!(res2, Some(Resolution::Blocked));
    assert_no_execution_calls(&spy2);
    assert_blocked_with_code(
        &tracker2,
        "XSY-GATE-RESUME",
        &ReleaseReasonCode::MissingVerifiedSignature,
    )?;
    Ok(())
}

fn network_config_trusted_enabled() -> Result<Config, Box<dyn Error>> {
    network_config(
        TrustLevel::Trusted,
        NetworkDispatchPolicy::Auto,
        default_test_proofs_dir(),
    )
}

#[tokio::test]
async fn trust_gate_rejects_non_trusted_on_security_sensitive() -> Result<(), Box<dyn Error>> {
    for (level, suffix, expected_code) in [
        (
            TrustLevel::Unknown,
            "unknown",
            ReleaseReasonCode::UnknownSigner,
        ),
        (
            TrustLevel::Known,
            "known",
            ReleaseReasonCode::UntrustedSigner,
        ),
    ] {
        let tmp = TempDir::new()?;
        let signer = format!("signer-{suffix}");
        let issue_id = format!("XSY-TG-{suffix}");
        let tracker = Arc::new(StubTracker::with(vec![network_issue(
            &issue_id,
            &["security-sensitive"],
            &signer,
        )?]));
        let runner = Arc::new(StubRunner::succeeding());
        let workspace = Arc::new(StubWorkspace {
            root: tmp.path().join("workspaces"),
            ..StubWorkspace::default()
        });
        let trust = Arc::new(MockTrustClient::with_levels([(signer.clone(), level)]));
        let trust_client: Arc<dyn TrustClient> = trust.clone();
        let orc = orc_with_trust(
            Arc::clone(&tracker),
            runner,
            Arc::clone(&workspace),
            sysclock(),
            trust_config(TrustLevel::Trusted, tmp.path().join("proofs"))?,
            trust_client,
        );

        let resolution = orc.run_once().await?;

        assert_eq!(resolution, Some(Resolution::Blocked));
        assert_eq!(trust.calls(), vec![signer.clone()]);
        assert!(guard(&workspace.created).is_empty());
        assert!(guard(&tracker.handoffs).is_empty());
        assert!(guard(&tracker.releases)
            .iter()
            .any(|(id, code)| id.as_str() == issue_id && code == &expected_code));
        let issues = guard(&tracker.issues);
        let issue = issues
            .iter()
            .find(|issue| issue.id.as_str() == issue_id)
            .ok_or("blocked issue should remain in tracker")?;
        assert_eq!(issue.state, state("blocked")?);
    }
    Ok(())
}

#[tokio::test]
async fn trust_gate_allows_trusted_on_security_sensitive() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(vec![network_issue(
        "XSY-TG-TRUSTED",
        &["security-sensitive"],
        "trusted-signer",
    )?]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let trust = Arc::new(MockTrustClient::with_levels([(
        "trusted-signer",
        TrustLevel::Trusted,
    )]));
    let trust_client: Arc<dyn TrustClient> = trust.clone();
    let orc = orc_with_trust(
        Arc::clone(&tracker),
        runner,
        Arc::clone(&workspace),
        sysclock(),
        trust_config(TrustLevel::Trusted, tmp.path().join("proofs"))?,
        trust_client,
    );

    let resolution = orc.run_once().await?;

    assert_eq!(resolution, Some(Resolution::Completed));
    assert_eq!(trust.calls(), vec!["trusted-signer".to_owned()]);
    assert_eq!(guard(&tracker.handoffs).len(), 1);
    assert_eq!(guard(&workspace.created).len(), 1);
    let issues = guard(&tracker.issues);
    let issue = issues
        .iter()
        .find(|issue| issue.id.as_str() == "XSY-TG-TRUSTED")
        .ok_or("trusted issue should remain in tracker")?;
    assert_eq!(issue.state, state("review")?);
    Ok(())
}

#[tokio::test]
async fn trust_gate_skips_local_issues() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let mut issue = local_issue_with_labels("XSY-TG-LOCAL", &["security-sensitive"])?;
    issue.extra.insert(
        "signer_agent_id".to_owned(),
        serde_json::Value::String("blocked-local-signer".to_owned()),
    );
    let tracker = Arc::new(StubTracker::with(vec![issue]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let trust = Arc::new(MockTrustClient::with_levels([(
        "blocked-local-signer",
        TrustLevel::Blocked,
    )]));
    let trust_client: Arc<dyn TrustClient> = trust.clone();
    let orc = orc_with_trust(
        Arc::clone(&tracker),
        runner,
        Arc::clone(&workspace),
        sysclock(),
        trust_config(TrustLevel::Trusted, tmp.path().join("proofs"))?,
        trust_client,
    );

    let resolution = orc.run_once().await?;

    assert_eq!(resolution, Some(Resolution::Completed));
    assert!(trust.calls().is_empty());
    assert_eq!(guard(&tracker.handoffs).len(), 1);
    assert_eq!(guard(&workspace.created).len(), 1);
    Ok(())
}

#[tokio::test]
async fn dispatch_gate_rejects_untrusted_non_sensitive_tasks() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(vec![network_issue(
        "XSY-TG-NON-SENSITIVE",
        &["feature"],
        "unknown-signer",
    )?]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let trust = Arc::new(MockTrustClient::with_levels([(
        "unknown-signer",
        TrustLevel::Unknown,
    )]));
    let trust_client: Arc<dyn TrustClient> = trust.clone();
    let orc = orc_with_trust(
        Arc::clone(&tracker),
        runner,
        Arc::clone(&workspace),
        sysclock(),
        trust_config(TrustLevel::Trusted, tmp.path().join("proofs"))?,
        trust_client,
    );

    let resolution = orc.run_once().await?;

    assert_eq!(resolution, Some(Resolution::Blocked));
    assert_eq!(trust.calls(), vec!["unknown-signer".to_owned()]);
    assert!(guard(&workspace.created).is_empty());
    assert!(guard(&tracker.handoffs).is_empty());
    assert!(guard(&tracker.releases).iter().any(|(id, code)| {
        id.as_str() == "XSY-TG-NON-SENSITIVE" && code == &ReleaseReasonCode::UnknownSigner
    }));
    Ok(())
}

#[tokio::test]
async fn trust_gate_blocked_always_rejected() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(vec![network_issue(
        "XSY-TG-BLOCKED",
        &["feature"],
        "blocked-signer",
    )?]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let trust = Arc::new(MockTrustClient::with_levels([(
        "blocked-signer",
        TrustLevel::Blocked,
    )]));
    let trust_client: Arc<dyn TrustClient> = trust.clone();
    let orc = orc_with_trust(
        Arc::clone(&tracker),
        runner,
        Arc::clone(&workspace),
        sysclock(),
        trust_config(TrustLevel::Trusted, tmp.path().join("proofs"))?,
        trust_client,
    );

    let resolution = orc.run_once().await?;

    assert_eq!(resolution, Some(Resolution::Blocked));
    assert_eq!(trust.calls(), vec!["blocked-signer".to_owned()]);
    assert!(guard(&workspace.created).is_empty());
    assert!(guard(&tracker.releases)
        .iter()
        .any(|(id, code)| id.as_str() == "XSY-TG-BLOCKED"
            && code == &ReleaseReasonCode::BlockedSigner));
    Ok(())
}

#[tokio::test]
async fn trust_gate_mock_client_covers_all_four_levels() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let cases = [
        (
            "XSY-TG-MATRIX-BLOCKED",
            "signer-blocked",
            TrustLevel::Blocked,
        ),
        (
            "XSY-TG-MATRIX-UNKNOWN",
            "signer-unknown",
            TrustLevel::Unknown,
        ),
        ("XSY-TG-MATRIX-KNOWN", "signer-known", TrustLevel::Known),
        (
            "XSY-TG-MATRIX-TRUSTED",
            "signer-trusted",
            TrustLevel::Trusted,
        ),
    ];
    let issues = cases
        .iter()
        .map(|(id, signer, _level)| network_issue(id, &["security-sensitive"], signer))
        .collect::<Result<Vec<_>, _>>()?;
    let tracker = Arc::new(StubTracker::with(issues));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let trust = Arc::new(MockTrustClient::with_levels(
        cases
            .iter()
            .map(|(_id, signer, level)| ((*signer).to_owned(), *level)),
    ));
    let trust_client: Arc<dyn TrustClient> = trust.clone();
    let orc = orc_with_trust(
        Arc::clone(&tracker),
        runner,
        Arc::clone(&workspace),
        sysclock(),
        trust_config(TrustLevel::Known, tmp.path().join("proofs"))?,
        trust_client,
    );

    for _case in cases {
        let _resolution = orc.run_once().await?;
    }

    assert_eq!(
        trust.calls(),
        vec![
            "signer-blocked".to_owned(),
            "signer-unknown".to_owned(),
            "signer-known".to_owned(),
            "signer-trusted".to_owned(),
        ]
    );
    assert_eq!(guard(&tracker.handoffs).len(), 2);
    assert_eq!(guard(&workspace.created).len(), 2);
    let releases = guard(&tracker.releases);
    assert_eq!(releases.len(), 2);
    assert!(releases.iter().any(|(id, code)| {
        id.as_str() == "XSY-TG-MATRIX-BLOCKED" && code == &ReleaseReasonCode::BlockedSigner
    }));
    assert!(releases.iter().any(|(id, code)| {
        id.as_str() == "XSY-TG-MATRIX-UNKNOWN" && code == &ReleaseReasonCode::UnknownSigner
    }));
    let issues = guard(&tracker.issues);
    for (id, _signer, level) in cases {
        let issue = issues
            .iter()
            .find(|issue| issue.id.as_str() == id)
            .ok_or("matrix issue should remain in tracker")?;
        if level >= TrustLevel::Known && level != TrustLevel::Blocked {
            assert_eq!(issue.state, state("review")?);
        } else {
            assert_eq!(issue.state, state("blocked")?);
        }
    }
    Ok(())
}

#[tokio::test]
async fn orphan_sweep_quarantines_done_and_tracker_missing_workspaces() -> Result<(), Box<dyn Error>>
{
    let tmp = TempDir::new()?;
    let workspace = workspace_manager(&tmp)?;
    let done_path = create_workspace_dir(&workspace, "XSY-9701")?;
    let missing_path = create_workspace_dir(&workspace, "XSY-9702")?;
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9701", "done")?]));
    let runner = Arc::new(StubRunner::succeeding());
    let orc = orc(
        Arc::clone(&tracker),
        Arc::clone(&runner),
        Arc::clone(&workspace),
        manual_clock("2026-07-02T12:34:56Z")?,
        orphan_config()?,
    );

    let summary = orc.sweep_orphans().await?;

    assert_eq!(summary.preserved_count(), 0);
    assert_eq!(summary.quarantined_count(), 2);
    assert_eq!(summary.refused_count(), 0);
    assert!(!done_path.exists());
    assert!(!missing_path.exists());
    assert!(workspace
        .canonical_root()
        .join(".orphaned")
        .join("20260702T123456Z")
        .join("XSY-9701")
        .is_dir());
    assert!(workspace
        .canonical_root()
        .join(".orphaned")
        .join("20260702T123456Z")
        .join("XSY-9702")
        .is_dir());
    Ok(())
}

#[tokio::test]
async fn orphan_sweep_preserves_non_terminal_workspace_without_live_claim(
) -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let workspace = workspace_manager(&tmp)?;
    let todo_path = create_workspace_dir(&workspace, "XSY-9703")?;
    let review_path = create_workspace_dir(&workspace, "XSY-9704")?;
    let tracker = Arc::new(StubTracker::with(vec![
        make_issue("XSY-9703", "todo")?,
        make_issue("XSY-9704", "review")?,
    ]));
    let runner = Arc::new(StubRunner::succeeding());
    let orc = orc(
        Arc::clone(&tracker),
        Arc::clone(&runner),
        Arc::clone(&workspace),
        manual_clock("2026-07-02T12:34:56Z")?,
        orphan_config()?,
    );

    let summary = orc.sweep_orphans().await?;

    assert_eq!(summary.preserved_count(), 2);
    assert_eq!(summary.quarantined_count(), 0);
    assert_eq!(summary.refused_count(), 0);
    assert!(todo_path.is_dir());
    assert!(review_path.is_dir());
    assert!(!workspace.canonical_root().join(".orphaned").exists());
    Ok(())
}

#[tokio::test]
async fn orphan_sweep_preserves_live_self_claim_workspace() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let workspace = workspace_manager(&tmp)?;
    let live_path = create_workspace_dir(&workspace, "XSY-9705")?;
    let owner = agent()?;
    let tracker = Arc::new(StubTracker::with(vec![claimed_issue(
        "XSY-9705",
        &owner,
        "2026-07-02T12:34:56Z".to_owned(),
    )?]));
    let runner = Arc::new(StubRunner::succeeding());
    let orc = orc(
        Arc::clone(&tracker),
        Arc::clone(&runner),
        Arc::clone(&workspace),
        manual_clock("2026-07-02T12:34:56Z")?,
        orphan_config()?,
    );

    let summary = orc.sweep_orphans().await?;

    assert_eq!(summary.preserved_count(), 1);
    assert_eq!(summary.quarantined_count(), 0);
    assert_eq!(summary.refused_count(), 0);
    assert!(live_path.is_dir());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn orphan_sweep_refuses_symlink_escape_without_moving_it() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let workspace = workspace_manager(&tmp)?;
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside)?;
    let symlink_path = workspace.canonical_root().join("XSY-9706");
    std::os::unix::fs::symlink(&outside, &symlink_path)?;
    let invalid_name_path = workspace.canonical_root().join("XSY-..-9706");
    std::fs::create_dir_all(&invalid_name_path)?;
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9706", "done")?]));
    let runner = Arc::new(StubRunner::succeeding());
    let orc = orc(
        Arc::clone(&tracker),
        Arc::clone(&runner),
        Arc::clone(&workspace),
        manual_clock("2026-07-02T12:34:56Z")?,
        orphan_config()?,
    );

    let summary = orc.sweep_orphans().await?;

    assert_eq!(summary.preserved_count(), 0);
    assert_eq!(summary.quarantined_count(), 0);
    assert_eq!(summary.refused_count(), 2);
    assert!(std::fs::symlink_metadata(&symlink_path)?
        .file_type()
        .is_symlink());
    assert!(invalid_name_path.is_dir());
    assert!(outside.is_dir());
    assert!(!workspace.canonical_root().join(".orphaned").exists());
    Ok(())
}

#[tokio::test]
async fn orphan_sweep_is_idempotent_after_quarantine() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let workspace = workspace_manager(&tmp)?;
    let orphan_path = create_workspace_dir(&workspace, "XSY-9707")?;
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9707", "done")?]));
    let runner = Arc::new(StubRunner::succeeding());
    let orc = orc(
        Arc::clone(&tracker),
        Arc::clone(&runner),
        Arc::clone(&workspace),
        manual_clock("2026-07-02T12:34:56Z")?,
        orphan_config()?,
    );

    let first = orc.sweep_orphans().await?;
    let second = orc.sweep_orphans().await?;

    assert_eq!(first.quarantined_count(), 1);
    assert_eq!(second.preserved_count(), 0);
    assert_eq!(second.quarantined_count(), 0);
    assert_eq!(second.refused_count(), 0);
    assert!(!orphan_path.exists());
    assert!(workspace
        .canonical_root()
        .join(".orphaned")
        .join("20260702T123456Z")
        .join("XSY-9707")
        .is_dir());
    Ok(())
}

#[tokio::test]
async fn end_to_end_smoke_todo_to_review() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9001", "todo")?]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().to_path_buf(),
        ..StubWorkspace::default()
    });
    let orc = orc(
        Arc::clone(&tracker),
        Arc::clone(&runner),
        Arc::clone(&workspace),
        sysclock(),
        config_with(RetryPolicy::default(), 1)?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;
    assert_eq!(resolution, Resolution::Completed);

    let issues = lock(&tracker.issues)?.clone();
    assert_eq!(issues[0].state, state("review")?);
    // Workspace created but never destroyed (review is not a terminal cleanup state).
    assert_eq!(guard(&workspace.created).clone().len(), 1);
    assert!(guard(&workspace.destroyed).clone().is_empty());
    Ok(())
}

#[tokio::test]
async fn proofs_subtree_and_handoff_link_written_on_success() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let proofs_root = tmp.path().join("proofs");
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9501", "todo")?]));
    let runner = Arc::new(EventfulRunner::success(vec![
        RunnerEvent::new(RunnerEventKind::Stdout).with_message("hello stdout\n"),
        RunnerEvent::new(RunnerEventKind::Stderr).with_message("hello stderr\n"),
    ]));
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        sysclock(),
        config_with_hooks_and_proofs(
            fast_retry(1),
            1,
            LifecycleHooks::default(),
            vec![state("done")?, state("cancelled")?],
            proofs_root.clone(),
        )?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;

    assert_eq!(resolution, Resolution::Completed);
    let handoff = lock(&tracker.handoffs)?
        .first()
        .cloned()
        .ok_or("handoff recorded")?;
    let run_dir = proof_dir_from_handoff(&proofs_root, &handoff)?;
    assert!(run_dir.join("manifest.json").is_file());
    assert!(run_dir.join("stdout.log").is_file());
    assert!(run_dir.join("stderr.log").is_file());
    assert_eq!(
        std::fs::read_to_string(run_dir.join("stdout.log"))?,
        "hello stdout\n"
    );
    assert_eq!(
        std::fs::read_to_string(run_dir.join("stderr.log"))?,
        "hello stderr\n"
    );
    let manifest = manifest(&run_dir)?;
    assert_eq!(manifest["issue_id"], "XSY-9501");
    assert_eq!(manifest["agent_id"], "agent-a");
    assert_eq!(manifest["runner_kind"], "stub");
    assert_eq!(manifest["preset"], serde_json::Value::Null);
    assert_eq!(manifest["command"], "stub");
    assert_eq!(manifest["args"].as_array().ok_or("args array")?.len(), 0);
    assert_eq!(
        manifest["env_allowlist"]
            .as_array()
            .ok_or("env_allowlist array")?
            .len(),
        0
    );
    assert_eq!(manifest["exit_code"], 0);
    assert!(manifest["duration_ms"].as_u64().is_some());
    assert!(manifest["started_at"].as_str().is_some());
    assert!(manifest["ended_at"].as_str().is_some());
    assert_eq!(manifest["hooks"].as_array().ok_or("hooks array")?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn handoff_files_changed_are_read_from_git_diff() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9510", "todo")?]));
    let runner = Arc::new(GitChangingRunner);
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        sysclock(),
        config_with(fast_retry(1), 1)?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;

    assert_eq!(resolution, Resolution::Completed);
    let handoff = lock(&tracker.handoffs)?
        .first()
        .cloned()
        .ok_or("handoff recorded")?;
    assert_eq!(handoff.files_changed, ["tracked.txt"]);
    Ok(())
}

#[tokio::test]
async fn handoff_no_git_repo_uses_empty_files_changed() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9511", "todo")?]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        sysclock(),
        config_with(fast_retry(1), 1)?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;

    assert_eq!(resolution, Resolution::Completed);
    let handoff = lock(&tracker.handoffs)?
        .first()
        .cloned()
        .ok_or("handoff recorded")?;
    assert!(handoff.files_changed.is_empty());
    Ok(())
}

#[tokio::test]
async fn handoff_validation_records_configured_command_statuses() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9512", "todo")?]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let config = Config::builder(agent()?)
        .active_states(vec![state("todo")?])
        .terminal_states(vec![state("done")?, state("cancelled")?])
        .global_concurrency(1)
        .retry(fast_retry(1))
        .validation_commands(["exit 0", "exit 7"])
        .proofs_dir(default_test_proofs_dir())
        .build();
    let orc = orc(Arc::clone(&tracker), runner, workspace, sysclock(), config);

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;

    assert_eq!(resolution, Resolution::Completed);
    let handoff = lock(&tracker.handoffs)?
        .first()
        .cloned()
        .ok_or("handoff recorded")?;
    assert_eq!(handoff.validation.len(), 2);
    assert_eq!(handoff.validation[0].command, "exit 0");
    assert_eq!(handoff.validation[0].status, ValidationStatus::Passed);
    assert_eq!(handoff.validation[0].exit_code, Some(0));
    assert_eq!(handoff.validation[1].command, "exit 7");
    assert_eq!(handoff.validation[1].status, ValidationStatus::Failed);
    assert_eq!(handoff.validation[1].exit_code, Some(7));
    Ok(())
}

#[tokio::test]
async fn handoff_validation_can_come_from_issue_metadata() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let mut issue = make_issue("XSY-9513", "todo")?;
    issue
        .extra
        .insert("validation".to_owned(), serde_json::json!(["exit 0"]));
    let tracker = Arc::new(StubTracker::with(vec![issue]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        sysclock(),
        config_with(fast_retry(1), 1)?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;

    assert_eq!(resolution, Resolution::Completed);
    let handoff = lock(&tracker.handoffs)?
        .first()
        .cloned()
        .ok_or("handoff recorded")?;
    assert_eq!(handoff.validation.len(), 1);
    assert_eq!(handoff.validation[0].command, "exit 0");
    assert_eq!(handoff.validation[0].status, ValidationStatus::Passed);
    Ok(())
}

#[tokio::test]
async fn proofs_written_on_failed_dispatch() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let proofs_root = tmp.path().join("proofs");
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9502", "todo")?]));
    let runner = Arc::new(EventfulRunner::failure(vec![
        RunnerEvent::new(RunnerEventKind::Stdout).with_message("partial stdout\n"),
        RunnerEvent::new(RunnerEventKind::Stderr).with_message("partial stderr\n"),
    ]));
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        sysclock(),
        config_with_hooks_and_proofs(
            fast_retry(1),
            1,
            LifecycleHooks::default(),
            vec![state("done")?, state("cancelled")?],
            proofs_root.clone(),
        )?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;

    assert_eq!(resolution, Resolution::Blocked);
    let run_dir = only_proof_run(&proofs_root, "XSY-9502")?;
    assert_eq!(
        std::fs::read_to_string(run_dir.join("stdout.log"))?,
        "partial stdout\n"
    );
    assert_eq!(
        std::fs::read_to_string(run_dir.join("stderr.log"))?,
        "partial stderr\n"
    );
    let manifest = manifest(&run_dir)?;
    assert_eq!(manifest["issue_id"], "XSY-9502");
    assert_ne!(manifest["exit_code"], 0);
    Ok(())
}

#[tokio::test]
async fn malicious_issue_id_refuses_proof_dir_creation() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let malicious_id = IssueId::new("../evil")?;
    let mut issue = Issue::new(
        malicious_id.clone(),
        "../evil",
        "malicious issue",
        IssueState::new("in_progress")?,
        "2026-07-02T00:00:00Z",
    )?;
    let owner = agent()?;
    let claim = Claim::new(
        Some(malicious_id),
        owner.clone(),
        now_iso(),
        x0x_symphony_core::ShardRole::ManualM1,
    );
    issue.claim = Some(claim.clone());
    let tracker = Arc::new(StubTracker::with(vec![issue]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let orc = orc(
        tracker,
        runner,
        workspace,
        sysclock(),
        config_with_hooks_and_proofs(
            fast_retry(1),
            1,
            LifecycleHooks::default(),
            vec![state("done")?, state("cancelled")?],
            tmp.path().join("proofs"),
        )?,
    );

    let result = orc.run_claim(claim).await;

    assert!(matches!(
        result,
        Err(x0x_symphony_orchestrator::Error::ProofContainment { .. })
    ));
    assert!(!tmp.path().join("evil").exists());
    Ok(())
}

#[tokio::test]
async fn runner_artifact_event_is_persisted() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let proofs_root = tmp.path().join("proofs");
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9503", "todo")?]));
    let runner = Arc::new(
        EventfulRunner::success(vec![
            RunnerEvent::new(RunnerEventKind::Artifact).with_message("artifact-source.bin")
        ])
        .with_artifact("artifact-source.bin", b"artifact bytes"),
    );
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let orc = orc(
        tracker,
        runner,
        workspace,
        sysclock(),
        config_with_hooks_and_proofs(
            fast_retry(1),
            1,
            LifecycleHooks::default(),
            vec![state("done")?, state("cancelled")?],
            proofs_root.clone(),
        )?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;

    assert_eq!(resolution, Resolution::Completed);
    let run_dir = only_proof_run(&proofs_root, "XSY-9503")?;
    assert_eq!(
        std::fs::read(run_dir.join("artifact-0001.bin"))?,
        b"artifact bytes"
    );
    Ok(())
}

#[tokio::test]
async fn lifecycle_hooks_fire_in_order_in_workspace_dir() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let log = tmp.path().join("hooks.log");
    let script = record_hook_script(&log);
    let hooks = LifecycleHooks::new(1_000)
        .with_after_create(script.clone())
        .with_before_run(script.clone())
        .with_after_run(script.clone())
        .with_before_remove(script);
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9401", "todo")?]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(Manager::new(WorkspaceConfig::new(
        tmp.path().join("workspaces"),
    ))?);
    let expected_dir = workspace.canonical_root().join("XSY-9401");
    let orc = orc(
        Arc::clone(&tracker),
        Arc::clone(&runner),
        Arc::clone(&workspace),
        sysclock(),
        config_with_hooks(fast_retry(1), 1, hooks, vec![state("review")?])?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;
    assert_eq!(resolution, Resolution::Completed);

    let lines = read_hook_log(&log)?;
    let records = lines
        .iter()
        .map(|line| line.split('|').collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let phases = records
        .iter()
        .map(|parts| parts.first().copied().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(
        phases,
        vec!["after_create", "before_run", "after_run", "before_remove"]
    );
    let expected_dir_text = expected_dir.to_string_lossy();
    for parts in &records {
        assert_eq!(parts.get(1).copied(), Some(expected_dir_text.as_ref()));
        assert_eq!(parts.get(2).copied(), Some("XSY-9401"));
        assert_eq!(parts.get(3).copied(), Some("agent-a"));
        assert!(
            parts
                .get(4)
                .is_some_and(|claim_id| claim_id.contains("XSY-9401")),
            "CLAIM_ID should identify the claim: {parts:?}"
        );
    }
    assert!(
        !expected_dir.exists(),
        "terminal cleanup should remove workspace"
    );
    Ok(())
}

#[tokio::test]
async fn before_remove_does_not_fire_on_shutdown_release() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let log = tmp.path().join("before-remove.log");
    let hooks = LifecycleHooks::new(1_000).with_before_remove(record_hook_script(&log));
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9402", "todo")?]));
    let runner = Arc::new(StubRunner::hanging());
    let workspace = Arc::new(Manager::new(WorkspaceConfig::new(
        tmp.path().join("workspaces"),
    ))?);
    let expected_dir = workspace.canonical_root().join("XSY-9402");
    let orc = Arc::new(orc(
        Arc::clone(&tracker),
        runner,
        Arc::clone(&workspace),
        sysclock(),
        config_with_hooks(fast_retry(1), 1, hooks, vec![state("review")?])?,
    ));

    let claim = orc.claim_next().await?.ok_or("should claim XSY-9402")?;
    let run_orc = Arc::clone(&orc);
    let run_task = tokio::spawn(async move { run_orc.run_claim(claim).await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let signaled = orc.shutdown().await;
    assert_eq!(signaled, 1);

    let resolution = run_task.await?;
    assert_eq!(resolution?, Resolution::ShutdownReleased);
    assert!(read_hook_log(&log)?.is_empty());
    assert!(
        expected_dir.exists(),
        "shutdown release must preserve workspace"
    );
    Ok(())
}

#[tokio::test]
async fn after_create_failure_blocks_and_releases_claim() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let hooks = LifecycleHooks::new(1_000).with_after_create("exit 7");
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9403", "todo")?]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(Manager::new(WorkspaceConfig::new(
        tmp.path().join("workspaces"),
    ))?);
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        sysclock(),
        config_with_hooks(fast_retry(1), 1, hooks, vec![state("done")?])?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;
    assert_eq!(resolution, Resolution::Blocked);

    let issues = lock(&tracker.issues)?.clone();
    assert_eq!(issues[0].state, state("blocked")?);
    assert!(
        issues[0].claim.is_none(),
        "blocked issue should release claim"
    );
    let reason = issues[0]
        .extra
        .get("blocked_reason")
        .and_then(|value| value.get("message"))
        .and_then(|value| value.as_str())
        .ok_or("blocked reason message")?;
    assert!(reason.contains("after_create hook failed"));
    Ok(())
}

#[tokio::test]
async fn before_run_failure_blocks_and_releases_claim() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let hooks = LifecycleHooks::new(1_000).with_before_run("exit 9");
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9406", "todo")?]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(Manager::new(WorkspaceConfig::new(
        tmp.path().join("workspaces"),
    ))?);
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        sysclock(),
        config_with_hooks(fast_retry(1), 1, hooks, vec![state("done")?])?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;
    assert_eq!(resolution, Resolution::Blocked);

    let issues = lock(&tracker.issues)?.clone();
    assert_eq!(issues[0].state, state("blocked")?);
    assert!(
        issues[0].claim.is_none(),
        "blocked issue should release claim"
    );
    let reason = issues[0]
        .extra
        .get("blocked_reason")
        .and_then(|value| value.get("message"))
        .and_then(|value| value.as_str())
        .ok_or("blocked reason message")?;
    assert!(reason.contains("before_run hook failed"));
    Ok(())
}

#[tokio::test]
async fn after_run_failure_preserves_successful_runner_output() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let hooks = LifecycleHooks::new(1_000).with_after_run("exit 2");
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9407", "todo")?]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(Manager::new(WorkspaceConfig::new(
        tmp.path().join("workspaces"),
    ))?);
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        sysclock(),
        config_with_hooks(fast_retry(1), 1, hooks, vec![state("done")?])?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;
    assert_eq!(resolution, Resolution::Completed);

    let issues = lock(&tracker.issues)?.clone();
    assert_eq!(issues[0].state, state("review")?);
    assert!(issues[0].claim.is_none());
    Ok(())
}

#[tokio::test]
async fn hook_timeout_blocks_without_waiting_for_script() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let hooks = LifecycleHooks::new(50).with_after_create("sleep 5");
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9404", "todo")?]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(Manager::new(WorkspaceConfig::new(
        tmp.path().join("workspaces"),
    ))?);
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        sysclock(),
        config_with_hooks(fast_retry(1), 1, hooks, vec![state("done")?])?,
    );

    let started = std::time::Instant::now();
    let resolution = orc.run_once().await?.ok_or("an issue should run")?;
    let elapsed = started.elapsed();

    assert_eq!(resolution, Resolution::Blocked);
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "hook timeout should stop the sleeping script quickly, elapsed {elapsed:?}"
    );
    let issues = lock(&tracker.issues)?.clone();
    assert_eq!(issues[0].state, state("blocked")?);
    Ok(())
}

#[tokio::test]
async fn empty_and_absent_hook_scripts_are_noops() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let log = tmp.path().join("hooks.log");
    let script = record_hook_script(&log);
    let hooks = LifecycleHooks::new(1_000)
        .with_after_create("")
        .with_before_run(script.clone())
        .with_after_run(script);
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9405", "todo")?]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(Manager::new(WorkspaceConfig::new(
        tmp.path().join("workspaces"),
    ))?);
    let expected_dir = workspace.canonical_root().join("XSY-9405");
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        Arc::clone(&workspace),
        sysclock(),
        config_with_hooks(fast_retry(1), 1, hooks, vec![state("done")?])?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;
    assert_eq!(resolution, Resolution::Completed);

    let phases = read_hook_log(&log)?
        .iter()
        .map(|line| line.split('|').next().unwrap_or_default().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(phases, vec!["before_run", "after_run"]);
    assert!(
        expected_dir.exists(),
        "non-terminal review should preserve workspace"
    );
    Ok(())
}

#[tokio::test]
async fn retry_exhaustion_moves_issue_to_blocked() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9002", "todo")?]));
    let runner = Arc::new(StubRunner::failing());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().to_path_buf(),
        ..StubWorkspace::default()
    });
    let orc = orc(
        Arc::clone(&tracker),
        Arc::clone(&runner),
        Arc::clone(&workspace),
        sysclock(),
        config_with(fast_retry(2), 1)?,
    );

    let resolution = orc.run_once().await?.ok_or("an issue should run")?;
    assert_eq!(resolution, Resolution::Blocked);

    let issues = lock(&tracker.issues)?.clone();
    assert_eq!(issues[0].state, state("blocked")?);
    let reason = issues[0]
        .extra
        .get("blocked_reason")
        .ok_or("blocked_reason recorded")?;
    let code = reason
        .get("code")
        .and_then(|v| v.as_str())
        .ok_or("code field")?;
    assert_eq!(code, "retry_exhausted");
    Ok(())
}

#[tokio::test]
async fn shutdown_mid_run_releases_claim_and_preserves_workspace() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9003", "todo")?]));
    let runner = Arc::new(StubRunner::hanging());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().to_path_buf(),
        ..StubWorkspace::default()
    });
    let orc = Arc::new(orc(
        Arc::clone(&tracker),
        runner,
        Arc::clone(&workspace),
        sysclock(),
        config_with(RetryPolicy::default(), 1)?,
    ));

    // Claim, then run in a task. The hanging runner never returns, so the run
    // stays in flight until shutdown preempts it.
    let claim = orc.claim_next().await?.ok_or("should claim XSY-9003")?;
    let run_orc = Arc::clone(&orc);
    let run_task = tokio::spawn(async move { run_orc.run_claim(claim).await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let signaled = orc.shutdown().await;
    assert_eq!(signaled, 1, "one in-flight run should have been signaled");

    let resolution = run_task.await?;
    assert_eq!(resolution?, Resolution::ShutdownReleased);

    let releases = lock(&tracker.releases)?.clone();
    assert!(
        releases
            .iter()
            .any(|(_, code)| *code == ReleaseReasonCode::Shutdown),
        "expected a shutdown release, got {releases:?}"
    );
    assert_eq!(guard(&workspace.created).clone().len(), 1);
    assert!(
        guard(&workspace.destroyed).clone().is_empty(),
        "workspace must be preserved on shutdown"
    );
    Ok(())
}

#[tokio::test]
async fn concurrency_cap_one_claims_only_one_of_two() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(vec![
        make_issue("XSY-9004", "todo")?,
        make_issue("XSY-9005", "todo")?,
    ]));
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().to_path_buf(),
        ..StubWorkspace::default()
    });
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        Arc::clone(&workspace),
        sysclock(),
        config_with(RetryPolicy::default(), 1)?,
    );

    let first = orc.claim_next().await?.ok_or("should claim one issue")?;
    let second = orc.claim_next().await?;
    assert!(
        second.is_none(),
        "global cap=1 should forbid a second claim"
    );

    let _ = orc.run_claim(first).await?;
    let todo = state("todo")?;
    let issues = lock(&tracker.issues)?.clone();
    let still_pending = issues
        .iter()
        .find(|i| i.state == todo)
        .ok_or("one issue remains todo")?;
    assert!(still_pending.claim.is_none());
    Ok(())
}

#[tokio::test]
async fn reconcile_releases_stale_and_keeps_fresh_self_claims() -> Result<(), Box<dyn Error>> {
    let owner = agent()?;
    let clock = Arc::new(ManualClock::new(parse_ts("2026-07-02T12:00:00Z")?)) as Arc<dyn Clock>;
    let ttl = chrono::Duration::minutes(30);
    let now = clock.now();
    let fresh_ts =
        (now - chrono::Duration::minutes(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let stale_ts = (now - ttl - chrono::Duration::minutes(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let other = AgentId::new("agent-b")?;
    let tracker = Arc::new(StubTracker::with(vec![
        claimed_issue("XSY-9101", &owner, fresh_ts.clone())?,
        claimed_issue("XSY-9102", &owner, stale_ts)?,
        {
            let mut i = make_issue("XSY-9103", "in_progress")?;
            i.claim = Some(
                Claim::new(
                    Some(i.id.clone()),
                    other.clone(),
                    fresh_ts.clone(),
                    x0x_symphony_core::ShardRole::ManualM1,
                )
                .with_heartbeat(fresh_ts),
            );
            i
        },
    ]));

    let runner = Arc::new(StubRunner::succeeding());
    let tmp = TempDir::new()?;
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().to_path_buf(),
        ..StubWorkspace::default()
    });
    let orc = orc(
        tracker.clone(),
        runner,
        workspace,
        clock,
        config_with(RetryPolicy::default(), 1)?,
    );

    let summary = orc.reconcile().await?;
    assert_eq!(summary.resumed, 1, "fresh self claim resumes");
    assert_eq!(summary.released, 1, "stale self claim releases");

    let releases = lock(&tracker.releases)?.clone();
    assert!(
        releases
            .iter()
            .any(|(id, code)| id.as_str() == "XSY-9102"
                && *code == ReleaseReasonCode::ExpiredHeartbeat),
        "stale claim should be released with expired_heartbeat, got {releases:?}"
    );
    // The foreign claim must be untouched: still claimed by agent-b, still in_progress.
    let issues = lock(&tracker.issues)?.clone();
    let foreign = issues
        .iter()
        .find(|i| i.id.as_str() == "XSY-9103")
        .ok_or("foreign issue present")?;
    assert_eq!(foreign.state, state("in_progress")?);
    assert_eq!(
        foreign.claim.as_ref().ok_or("foreign claim present")?.by,
        other
    );
    Ok(())
}

#[tokio::test]
async fn reconcile_backup_takes_over_stale_primary() -> Result<(), Box<dyn Error>> {
    let backup = agent()?;
    let primary = AgentId::new("agent-b")?;
    let now = parse_ts("2026-07-02T12:00:00Z")?;
    let clock = Arc::new(ManualClock::new(now)) as Arc<dyn Clock>;
    let ttl_ms = 60_000;
    let stale_ts = (now - chrono::Duration::milliseconds(61_000))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let shard = Shard::new(primary.clone(), vec![backup.clone()], ttl_ms, 1);
    let tracker = Arc::new(StubTracker::with(vec![sharded_claimed_issue(
        "XSY-9104",
        &primary,
        x0x_symphony_core::ShardRole::Primary,
        stale_ts,
        shard,
    )?]));
    let runner = Arc::new(StubRunner::succeeding());
    let tmp = TempDir::new()?;
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().to_path_buf(),
        ..StubWorkspace::default()
    });
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        clock,
        config_with(RetryPolicy::default(), 1)?,
    );

    let summary = orc.reconcile().await?;

    assert_eq!(
        summary.taken_over, 1,
        "backup should claim stale primary work"
    );
    let releases = lock(&tracker.releases)?.clone();
    assert!(
        releases
            .iter()
            .any(|(id, code)| id.as_str() == "XSY-9104"
                && *code == ReleaseReasonCode::ExpiredHeartbeat),
        "stale primary should be released with expired_heartbeat, got {releases:?}"
    );
    let issues = lock(&tracker.issues)?.clone();
    let issue = issues
        .iter()
        .find(|issue| issue.id.as_str() == "XSY-9104")
        .ok_or("takeover issue present")?;
    assert_eq!(issue.state, state("in_progress")?);
    let claim = issue.claim.as_ref().ok_or("backup claim present")?;
    assert_eq!(claim.by, backup);
    assert_eq!(claim.shard_role, x0x_symphony_core::ShardRole::Backup(0));
    Ok(())
}

#[tokio::test]
async fn reconcile_conflict_abandons_higher_index_self_claim() -> Result<(), Box<dyn Error>> {
    let backup = agent()?;
    let primary = AgentId::new("agent-b")?;
    let now = parse_ts("2026-07-02T12:00:00Z")?;
    let fresh_ts =
        (now - chrono::Duration::seconds(10)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let shard = Shard::new(primary.clone(), vec![backup.clone()], 60_000, 1);
    let tracker = Arc::new(StubTracker::with(vec![
        sharded_claimed_issue(
            "XSY-9105",
            &primary,
            x0x_symphony_core::ShardRole::Primary,
            fresh_ts.clone(),
            shard.clone(),
        )?,
        sharded_claimed_issue(
            "XSY-9105",
            &backup,
            x0x_symphony_core::ShardRole::Backup(0),
            fresh_ts,
            shard,
        )?,
    ]));
    let runner = Arc::new(StubRunner::succeeding());
    let tmp = TempDir::new()?;
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().to_path_buf(),
        ..StubWorkspace::default()
    });
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        Arc::new(ManualClock::new(now)) as Arc<dyn Clock>,
        config_with(RetryPolicy::default(), 1)?,
    );

    let summary = orc.reconcile().await?;

    assert_eq!(summary.conflicts_abandoned, 1);
    let abandons = lock(&tracker.abandons)?.clone();
    assert_eq!(abandons, vec![(IssueId::new("XSY-9105")?, backup.clone())]);
    let releases = lock(&tracker.releases)?.clone();
    assert!(
        releases
            .iter()
            .any(|(id, code)| id.as_str() == "XSY-9105" && *code == ReleaseReasonCode::Conflict),
        "higher-index loser should release with conflict, got {releases:?}"
    );
    let issues = lock(&tracker.issues)?.clone();
    let winner = issues
        .iter()
        .find(|issue| {
            issue
                .claim
                .as_ref()
                .is_some_and(|claim| claim.by.eq(&primary))
        })
        .ok_or("primary winner remains claimed")?;
    assert_eq!(winner.state, state("in_progress")?);
    let loser = issues
        .iter()
        .find(|issue| issue.claim.is_none() && issue.id.as_str() == "XSY-9105")
        .ok_or("backup loser abandoned")?;
    assert_eq!(loser.state, state("todo")?);
    Ok(())
}

fn dual_claim_issues(
    issue_id: &str,
    primary: &AgentId,
    backup: &AgentId,
    now: DateTime<Utc>,
) -> Result<Vec<Issue>, Box<dyn Error>> {
    let fresh_ts =
        (now - chrono::Duration::seconds(10)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let shard = Shard::new(primary.clone(), vec![backup.clone()], 60_000, 1);
    let winner = sharded_claimed_issue(
        issue_id,
        primary,
        x0x_symphony_core::ShardRole::Primary,
        fresh_ts.clone(),
        shard.clone(),
    )?;
    let loser = sharded_claimed_issue(
        issue_id,
        backup,
        x0x_symphony_core::ShardRole::Backup(0),
        fresh_ts,
        shard,
    )?;
    Ok(vec![winner, loser])
}

fn assert_abandon_marker(
    root: &Path,
    issue_id: &str,
    directory_name: &str,
    primary: &AgentId,
    backup: &AgentId,
) -> Result<(), Box<dyn Error>> {
    let issue_dir = root.join(issue_id);
    let mut entries = std::fs::read_dir(&issue_dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort();
    assert_eq!(entries.len(), 1);
    let marker_dir = entries.first().ok_or("abandon proof directory present")?;
    let marker_name = marker_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("abandon proof directory has UTF-8 name")?;
    assert_eq!(marker_name, directory_name);
    let marker: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(marker_dir.join("abandon.json"))?)?;
    assert_eq!(
        abandon_agent(&marker, "abandoned_claim"),
        Some(backup.as_str())
    );
    assert_eq!(abandon_reason_code(&marker), Some("conflict"));
    assert_eq!(
        marker
            .get("winning_agent_id")
            .and_then(serde_json::Value::as_str),
        Some(primary.as_str())
    );
    Ok(())
}

fn abandon_agent<'a>(value: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .and_then(|nested| nested.get("by"))
        .and_then(serde_json::Value::as_str)
}

fn abandon_reason_code(value: &serde_json::Value) -> Option<&str> {
    value
        .get("reason")
        .and_then(|nested| nested.get("code"))
        .and_then(serde_json::Value::as_str)
}

#[tokio::test]
async fn startup_reconcile_conflict_abandon_persists_tracker_and_proof_marker(
) -> Result<(), Box<dyn Error>> {
    let backup = agent()?;
    let primary = AgentId::new("agent-b")?;
    let now = parse_ts("2026-07-02T12:00:00Z")?;
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(dual_claim_issues(
        "XSY-9110", &primary, &backup, now,
    )?));

    let artifacts_root = tmp.path().join("proofs");
    let runner = Arc::new(StubRunner::succeeding());
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().join("workspaces"),
        ..StubWorkspace::default()
    });
    let orc = orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        Arc::new(ManualClock::new(now)) as Arc<dyn Clock>,
        config_with_hooks_and_proofs(
            RetryPolicy::default(),
            1,
            LifecycleHooks::default(),
            vec![state("done")?, state("cancelled")?],
            artifacts_root.clone(),
        )?,
    );

    let summary = orc.reconcile().await?;

    assert_eq!(summary.conflicts_abandoned, 1);
    assert_eq!(
        lock(&tracker.abandons)?.clone(),
        vec![(IssueId::new("XSY-9110")?, backup.clone())]
    );
    assert_abandon_marker(
        &artifacts_root,
        "XSY-9110",
        "2026-07-02T120000Z-abandoned",
        &primary,
        &backup,
    )?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn heartbeat_keeps_claim_fresh_during_long_run() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(vec![make_issue("XSY-9201", "todo")?]));
    // Run (500 ms) outlasts the claim TTL (200 ms); without a periodic heartbeat
    // the claim would go stale long before completion.
    let runner = Arc::new(StubRunner::succeeding_after(
        std::time::Duration::from_millis(500),
    ));
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().to_path_buf(),
        ..StubWorkspace::default()
    });
    let ttl = chrono::Duration::milliseconds(200); // -> heartbeat interval 50 ms
    let config = Config::builder(agent()?)
        .active_states(vec![state("todo")?])
        .terminal_states(vec![state("done")?, state("cancelled")?])
        .global_concurrency(1)
        .retry(RetryPolicy::default())
        .proofs_dir(tmp.path().join("proofs"))
        .claim_ttl(ttl)
        .build();
    let clock = sysclock();
    let orc = Arc::new(orc(
        Arc::clone(&tracker),
        Arc::clone(&runner),
        Arc::clone(&workspace),
        Arc::clone(&clock),
        config,
    ));

    // Drive the run in a task so we can inspect the claim mid-flight.
    let orc_run = Arc::clone(&orc);
    let run_task = tokio::spawn(async move { orc_run.run_once().await });

    // Mid-run: enough elapsed paused Tokio time for several 50 ms heartbeats.
    tokio::task::yield_now().await;
    for _ in 0..6 {
        tokio::time::advance(std::time::Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
    }

    let heartbeats = *lock(&tracker.heartbeats)?;
    assert!(
        heartbeats >= 2,
        "periodic heartbeat must fire during a long run; saw {heartbeats}"
    );

    // The claim must still be fresh (the heartbeat task refreshed it).
    let owner = agent()?;
    let issues = lock(&tracker.issues)?.clone();
    let in_flight = issues
        .iter()
        .find(|i| i.id.as_str() == "XSY-9201")
        .ok_or("issue present")?;
    let claim = in_flight.claim.as_ref().ok_or("claim still held mid-run")?;
    assert!(
        is_fresh_self(claim, &owner, clock.as_ref(), ttl)?,
        "claim must remain fresh while the heartbeat task runs"
    );

    tokio::time::advance(std::time::Duration::from_millis(300)).await;
    tokio::task::yield_now().await;
    let resolution = run_task.await??.ok_or("an issue should run")?;
    assert_eq!(resolution, Resolution::Completed);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn heartbeat_interval_uses_shard_claim_ttl() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let owner = agent()?;
    let issue = sharded_issue("XSY-9202", "todo", &owner, Vec::new(), 400)?;
    let tracker = Arc::new(StubTracker::with(vec![issue]));
    let runner = Arc::new(StubRunner::succeeding_after(
        std::time::Duration::from_millis(500),
    ));
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().to_path_buf(),
        ..StubWorkspace::default()
    });
    let config = Config::builder(owner)
        .active_states(vec![state("todo")?])
        .terminal_states(vec![state("done")?, state("cancelled")?])
        .global_concurrency(1)
        .retry(RetryPolicy::default())
        .proofs_dir(tmp.path().join("proofs"))
        // If the heartbeat task used this default TTL, the interval would be 1 s.
        .claim_ttl(chrono::Duration::seconds(4))
        .build();
    let orc = Arc::new(orc(
        Arc::clone(&tracker),
        runner,
        workspace,
        sysclock(),
        config,
    ));

    let orc_run = Arc::clone(&orc);
    let run_task = tokio::spawn(async move { orc_run.run_once().await });
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_millis(100)).await;
    tokio::task::yield_now().await;

    let heartbeats = *lock(&tracker.heartbeats)?;
    assert!(
        heartbeats >= 2,
        "shard ttl 400 ms should refresh every 100 ms; saw {heartbeats}"
    );

    tokio::time::advance(std::time::Duration::from_millis(400)).await;
    tokio::task::yield_now().await;
    let resolution = run_task.await??.ok_or("an issue should run")?;
    assert_eq!(resolution, Resolution::Completed);
    Ok(())
}

#[tokio::test]
async fn budget_slot_released_on_workspace_create_error() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let tracker = Arc::new(StubTracker::with(vec![
        make_issue("XSY-9301", "todo")?,
        make_issue("XSY-9302", "todo")?,
    ]));
    let runner = Arc::new(StubRunner::succeeding());
    // Workspace whose create() always fails, forcing the `?` error path.
    let workspace = Arc::new(StubWorkspace {
        root: tmp.path().to_path_buf(),
        create_fails: true,
        ..StubWorkspace::default()
    });
    let orc = orc(
        Arc::clone(&tracker),
        Arc::clone(&runner),
        Arc::clone(&workspace),
        sysclock(),
        config_with(RetryPolicy::default(), 1)?,
    );

    // Claim the first issue; this acquires the single budget slot.
    let first = orc.claim_next().await?.ok_or("should claim first issue")?;
    // run_claim fails inside at workspace.create(); the HeldClaim guard must
    // free the slot on this `?` error path.
    let result = orc.run_claim(first).await;
    assert!(
        result.is_err(),
        "workspace.create failure must surface as an error"
    );

    // Slot must now be free: a second claim succeeds (cap=1 would block a leak).
    let second = orc.claim_next().await?;
    assert!(
        second.is_some(),
        "budget slot must be released on the error path"
    );
    Ok(())
}
