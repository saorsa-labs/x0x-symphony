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
    IssueState, PollContext, Prompt, ReleaseReason, ReleaseReasonCode, Result as CoreResult,
    Runner, RunnerCapabilities, RunnerEvent, SessionContext, SessionHandle, SessionId, TurnOutcome,
    TurnStatus, UsageReport, Workspace, WorkspaceHandle,
};
use x0x_symphony_orchestrator::{
    dispatch::Resolution, is_fresh_self, retry::RetryPolicy, Clock, Config, ManualClock,
    Orchestrator, SystemClock,
};

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

// ---------- stub tracker ----------

#[derive(Default)]
struct StubTracker {
    issues: Mutex<Vec<Issue>>,
    releases: Mutex<Vec<(IssueId, ReleaseReasonCode)>>,
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
    async fn handoff(&self, claim: &Claim, _handoff: Handoff) -> CoreResult<()> {
        let mut issues = lock(&self.issues)?;
        if let Some(id) = &claim.issue_id {
            if let Some(issue) = issues.iter_mut().find(|i| &i.id == id) {
                issue.claim = None;
                set_state(&mut *issue, "review")?;
            }
        }
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
    Ok(Config::builder(agent()?)
        .active_states(vec![state("todo")?])
        .terminal_states(vec![state("done")?, state("cancelled")?])
        .global_concurrency(concurrency)
        .retry(retry)
        .build())
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

// ---------- tests ----------

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
