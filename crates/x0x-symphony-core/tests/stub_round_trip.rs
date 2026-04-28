use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use futures_util::stream;
use tokio::sync::Mutex;
use x0x_symphony_core::{
    AgentId, Claim, EventStream, Handoff, Hook, HookEnv, HookOutcome, HookStatus, Issue, IssueId,
    IssueState, PollContext, Prompt, ReleaseReason, Result, Runner, RunnerCapabilities,
    RunnerEvent, SessionContext, SessionHandle, SessionId, ShardRole, Tracker, TurnOutcome,
    TurnStatus, UsageReport, ValidationResult, ValidationStatus, Workspace, WorkspaceHandle,
};

#[derive(Clone)]
struct MemoryTracker {
    issue: Arc<Mutex<Issue>>,
}

impl MemoryTracker {
    fn new(issue: Issue) -> Self {
        Self {
            issue: Arc::new(Mutex::new(issue)),
        }
    }
}

#[async_trait]
impl Tracker for MemoryTracker {
    async fn fetch_candidates(&self, ctx: &PollContext) -> Result<Vec<Issue>> {
        let issue = self.issue.lock().await.clone();
        let active = ctx.active_states.iter().any(|state| state == &issue.state);
        if active {
            Ok(vec![issue])
        } else {
            Ok(Vec::new())
        }
    }

    async fn fetch_by_ids(&self, ids: &[IssueId]) -> Result<Vec<Issue>> {
        let issue = self.issue.lock().await.clone();
        if ids.iter().any(|id| id == &issue.id) {
            Ok(vec![issue])
        } else {
            Ok(Vec::new())
        }
    }

    async fn claim(&self, id: &IssueId, agent_id: &AgentId) -> Result<Claim> {
        let mut issue = self.issue.lock().await;
        if &issue.id != id {
            return Err(x0x_symphony_core::SymphonyError::Tracker(
                "unknown issue".to_owned(),
            ));
        }
        let claim = Claim::new(
            Some(id.clone()),
            agent_id.clone(),
            "2026-04-28T10:00:00Z",
            ShardRole::ManualM1,
        );
        issue.state = IssueState::new("in_progress")?;
        issue.claim = Some(claim.clone());
        Ok(claim)
    }

    async fn heartbeat(&self, claim: &Claim) -> Result<()> {
        let mut issue = self.issue.lock().await;
        issue.claim = Some(claim.clone().with_heartbeat("2026-04-28T10:01:00Z"));
        Ok(())
    }

    async fn release(&self, _claim: &Claim, _reason: ReleaseReason) -> Result<()> {
        let mut issue = self.issue.lock().await;
        issue.state = IssueState::new("todo")?;
        issue.claim = None;
        Ok(())
    }

    async fn handoff(&self, _claim: &Claim, handoff: Handoff) -> Result<()> {
        let mut issue = self.issue.lock().await;
        issue.state = IssueState::new("review")?;
        issue.handoff = Some(handoff);
        Ok(())
    }
}

struct NoopRunner {
    capabilities: RunnerCapabilities,
}

impl NoopRunner {
    fn new() -> Self {
        Self {
            capabilities: RunnerCapabilities::new("stub-shell"),
        }
    }
}

#[async_trait]
impl Runner for NoopRunner {
    fn name(&self) -> &'static str {
        "stub-shell"
    }

    fn capabilities(&self) -> &RunnerCapabilities {
        &self.capabilities
    }

    async fn start_session(&self, ctx: SessionContext) -> Result<SessionHandle> {
        Ok(SessionHandle::new(
            SessionId::new("session-1"),
            ctx.workspace_path,
            "2026-04-28T10:00:00Z",
        ))
    }

    async fn run_turn(&self, _sess: &mut SessionHandle, prompt: Prompt) -> Result<TurnOutcome> {
        Ok(TurnOutcome::new(
            TurnStatus::Succeeded,
            UsageReport::new().with_duration_ms(prompt.as_str().len() as u64),
        )
        .with_summary("stub completed"))
    }

    fn stream_events(&self, _sess: &SessionHandle) -> EventStream {
        Box::pin(stream::empty::<RunnerEvent>())
    }

    async fn stop_session(&self, _sess: SessionHandle) -> Result<UsageReport> {
        Ok(UsageReport::new().with_duration_ms(1))
    }
}

struct NoopWorkspace {
    root: PathBuf,
}

impl NoopWorkspace {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

#[async_trait]
impl Workspace for NoopWorkspace {
    fn root(&self) -> &Path {
        &self.root
    }

    async fn create(&self, issue: &Issue) -> Result<WorkspaceHandle> {
        Ok(WorkspaceHandle::new(
            issue.id.clone(),
            self.root.join(issue.identifier.as_str()),
            true,
        ))
    }

    async fn run_hook(&self, _hook: &Hook, _env: &HookEnv) -> Result<HookOutcome> {
        Ok(HookOutcome::new(HookStatus::Succeeded).with_exit_code(0))
    }

    async fn destroy(&self, _handle: WorkspaceHandle) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn stub_traits_support_round_trip() -> Result<()> {
    let issue = Issue::new(
        IssueId::new("XSY-0002")?,
        "XSY-0002",
        "Define core traits",
        IssueState::new("todo")?,
        "2026-04-28T00:00:00Z",
    )?;
    let tracker = MemoryTracker::new(issue);
    let runner = NoopRunner::new();
    let workspace = NoopWorkspace::new(PathBuf::from("/tmp/x0x-symphony-test"));
    let agent = AgentId::new("agent-a")?;

    let poll = PollContext::new(
        vec![IssueState::new("todo")?],
        vec![IssueState::new("done")?],
    )
    .with_agent_id(agent.clone());
    let candidates = tracker.fetch_candidates(&poll).await?;
    assert_eq!(candidates.len(), 1);

    let claim = tracker.claim(&candidates[0].id, &agent).await?;
    tracker.heartbeat(&claim).await?;

    let handle = workspace.create(&candidates[0]).await?;
    let hook = Hook::new(x0x_symphony_core::HookName::BeforeRun, "true", 1_000);
    let hook_outcome = workspace.run_hook(&hook, &HookEnv::new()).await?;
    assert!(hook_outcome.status.is_success());

    let ctx = SessionContext::new(candidates[0].clone(), handle.path.clone());
    let mut session = runner.start_session(ctx).await?;
    let turn = runner
        .run_turn(&mut session, Prompt::new("implement core traits"))
        .await?;
    assert!(turn.status.is_terminal_success());
    let usage = runner.stop_session(session).await?;
    assert_eq!(usage.duration_ms, Some(1));

    let handoff = Handoff::new("stub completed")
        .with_file("crates/x0x-symphony-core/src/lib.rs")
        .with_validation(ValidationResult::new(
            "stub round trip",
            ValidationStatus::Passed,
        ));
    tracker.handoff(&claim, handoff).await?;

    let reviewed = tracker.fetch_by_ids(&[candidates[0].id.clone()]).await?;
    assert_eq!(reviewed.len(), 1);
    assert_eq!(reviewed[0].state, IssueState::new("review")?);
    assert!(reviewed[0].handoff.is_some());
    Ok(())
}
