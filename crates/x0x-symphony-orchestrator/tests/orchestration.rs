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
    collections::BTreeSet,
    error::Error,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::stream;
use tempfile::TempDir;
use x0x_symphony_core::{
    AgentId, Claim, EventStream, Handoff, Hook, HookEnv, HookOutcome, HookStatus, Issue, IssueId,
    IssueState, LifecycleHooks, PollContext, Prompt, ReleaseReason, ReleaseReasonCode,
    Result as CoreResult, Runner, RunnerCapabilities, RunnerEvent, RunnerEventKind, SessionContext,
    SessionHandle, SessionId, TurnOutcome, TurnStatus, UsageReport, ValidationStatus, Workspace,
    WorkspaceHandle,
};
use x0x_symphony_orchestrator::{
    dispatch::Resolution, is_fresh_self, retry::RetryPolicy, Clock, Config, ManualClock,
    Orchestrator, SystemClock,
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
        let claim = Claim::new(
            Some(id.clone()),
            agent_id.clone(),
            now.clone(),
            x0x_symphony_core::ShardRole::ManualM1,
        );
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
            if let Some(issue) = issues.iter_mut().find(|i| &i.id == id) {
                issue.claim = None;
                set_state(&mut *issue, "todo")?;
            }
            lock(&self.releases)?.push((id.clone(), reason.code));
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

// ---------- tests ----------

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

    // Mid-run: enough elapsed time for several 50 ms heartbeats.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

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
