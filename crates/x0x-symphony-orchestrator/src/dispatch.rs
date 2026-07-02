//! Dispatch helpers: eligibility gate and the per-issue run/retry flow.
//!
//! [`claimable_for`] decides which polled candidates this agent may take right
//! now (free, or already owned-and-fresh). [`Orchestrator::run_claim`] runs a
//! claimed issue through the retry loop, handing off on success and blocking on
//! exhaustion. Graceful shutdown cancels an in-flight run, releases the claim
//! with `shutdown`, and preserves the workspace.
//!
//! Ownership contract: the caller of `run_claim` first acquires a budget slot
//! and registers the claim as in-flight (done by [`Orchestrator::claim_next`]
//! and the resume path). `run_claim` releases that slot on every exit path.

use std::{sync::Arc, time::Duration};

use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::warn;
use x0x_symphony_core::{
    Claim, Handoff, HookEnv, HookName, HookOutcome, HookStatus, Issue, IssueId, Prompt,
    ReleaseReason, ReleaseReasonCode, Runner, SessionContext, Tracker, TurnStatus, Workspace,
    WorkspaceHandle,
};

use crate::{clock::Clock, error::Result, reconcile::is_fresh_self, Orchestrator};
// `Error` is referenced only via `Error::NotEligible` / `Error::PoisonedState`;
// re-exported through `error` for the variants below.
use crate::error::Error;

/// Why a polled candidate may (or may not) be taken by this agent now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Claimable {
    /// No active claim — anyone may claim.
    Free,
    /// Claimed by this agent and still within the TTL — resume it.
    FreshSelf,
}

/// Classify a polled candidate's claim state from this agent's perspective.
///
/// Returns `Ok(None)` when the issue is claimed by someone else, or owned by
/// this agent but stale (it must be reconciled, not dispatched fresh).
///
/// # Errors
///
/// Propagates [`Error::BadHeartbeat`] when a present claim's heartbeat cannot
/// be parsed.
pub fn claimable_for(
    issue: &Issue,
    owner: &x0x_symphony_core::AgentId,
    clock: &dyn Clock,
    ttl: chrono::Duration,
) -> Result<Option<Claimable>> {
    match &issue.claim {
        None => Ok(Some(Claimable::Free)),
        Some(claim) => {
            if is_fresh_self(claim, owner, clock, ttl)? {
                Ok(Some(Claimable::FreshSelf))
            } else {
                Ok(None)
            }
        }
    }
}

/// RAII owner of a held claim's cleanup while [`Orchestrator::run_claim`] runs.
///
/// It guarantees that the concurrency-budget slot acquired by `claim_next` is
/// freed on **every** exit path — success, block, shutdown, or `?` error — by
/// releasing it in `Drop`, and that the background heartbeat task is aborted at
/// the transition point ([`Self::cancel_heartbeat`]) rather than only on drop.
/// This is the single source of truth for slot release inside `run_claim`;
/// there are no manual `release_slot` calls in that method.
struct HeldClaim<'a, T, R, W> {
    orch: &'a Orchestrator<T, R, W>,
    claim: &'a x0x_symphony_core::Claim,
    heartbeat: Option<JoinHandle<()>>,
}

impl<'a, T, R, W> HeldClaim<'a, T, R, W> {
    fn new(orch: &'a Orchestrator<T, R, W>, claim: &'a x0x_symphony_core::Claim) -> Self {
        Self {
            orch,
            claim,
            heartbeat: None,
        }
    }

    /// Spawn a background task that refreshes the claim's heartbeat at `interval`
    /// for as long as the run is in flight. It is cancelled either at a
    /// transition via [`Self::cancel_heartbeat`] or when this guard drops.
    ///
    /// The task captures only an `Arc<T>` clone of the tracker and an owned
    /// clone of the claim, so the spawned future is `Send` whenever `T` is.
    fn spawn_heartbeat(
        &mut self,
        tracker: Arc<T>,
        claim: x0x_symphony_core::Claim,
        interval: Duration,
    ) where
        T: Tracker + Send + Sync + 'static,
    {
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                // Heartbeats are best-effort: a failure must not abort the run.
                let _ = tracker.heartbeat(&claim).await;
            }
        });
        self.heartbeat = Some(handle);
    }

    /// Abort the heartbeat task at a transition (handoff/block/shutdown) so it
    /// does not fire on an already-released claim before the guard itself drops.
    fn cancel_heartbeat(&mut self) {
        if let Some(handle) = self.heartbeat.take() {
            handle.abort();
        }
    }
}

impl<T, R, W> Drop for HeldClaim<'_, T, R, W> {
    fn drop(&mut self) {
        // Abort first, then release the slot, so a still-running heartbeat can
        // never observe a half-released claim.
        self.cancel_heartbeat();
        self.orch.release_slot(self.claim);
    }
}

/// Outcome of running a single claimed issue to resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution {
    /// The runner succeeded and the issue was handed off to `review`.
    Completed,
    /// The retry budget was exhausted and the issue was moved to `blocked`.
    Blocked,
    /// Graceful shutdown cancelled the run; the claim was released with
    /// `shutdown` and the workspace was preserved.
    ShutdownReleased,
}

/// Carries a runner session through `select!` so shutdown can preempt it.
struct RunTurnOutcome {
    status: TurnStatus,
    session: x0x_symphony_core::SessionHandle,
}

/// Lets `select!` await `run_turn` while keeping the session handle for the
/// later `stop_session`. The core `Runner` trait takes the session by value, so
/// we wrap the call and thread the handle back out.
///
/// `#[allow(async_fn_in_trait)]`: this is a private helper trait whose async
/// future is awaited locally inside `run_claim`'s `select!` and is never spawned
/// or sent across threads, so the lint's `Send`-bound concern does not apply.
/// Declared and signed off in the XSY-0006 audit follow-up.
#[allow(async_fn_in_trait)]
trait RunTurnExt {
    /// Run one prompt turn, returning the status and the (still-open) session.
    ///
    /// # Errors
    /// Propagates runner errors.
    async fn run_turn_prompt(
        &self,
        session: x0x_symphony_core::SessionHandle,
        prompt: Prompt,
    ) -> Result<RunTurnOutcome>;
}

impl<R: Runner> RunTurnExt for R {
    async fn run_turn_prompt(
        &self,
        mut session: x0x_symphony_core::SessionHandle,
        prompt: Prompt,
    ) -> Result<RunTurnOutcome> {
        let outcome = self.run_turn(&mut session, prompt).await?;
        Ok(RunTurnOutcome {
            status: outcome.status,
            session,
        })
    }
}

fn describe_hook_outcome(outcome: &HookOutcome) -> String {
    let status = match &outcome.status {
        HookStatus::Succeeded => "succeeded",
        HookStatus::Failed => "failed",
        HookStatus::TimedOut => "timed_out",
    };
    match outcome.exit_code {
        Some(code) => format!("status={status}, exit_code={code}"),
        None => format!("status={status}"),
    }
}

fn claim_env_id(claim: &Claim) -> String {
    match &claim.issue_id {
        Some(issue_id) => format!("{}:{}:{}", issue_id.as_str(), claim.by.as_str(), claim.at),
        None => format!("{}:{}", claim.by.as_str(), claim.at),
    }
}

impl<T, R, W> Orchestrator<T, R, W>
where
    // `T` is shared with the background heartbeat task spawned below; `R`/`W`
    // are driven only on the calling task and need no extra bounds.
    T: x0x_symphony_core::Tracker + Send + Sync + 'static,
    R: Runner,
    W: Workspace,
{
    /// Run one claimed issue through the retry loop to resolution.
    ///
    /// The claim is held across retries and the workspace is reused across
    /// attempts. A background heartbeat task refreshes the claim at
    /// [`crate::Config::heartbeat_interval`] (one quarter of the claim TTL) for
    /// as long as the run is in flight, so a run that outlasts the TTL keeps its
    /// claim fresh. On success the issue is handed off to `review`; on exhaustion
    /// it is moved to `blocked`; on shutdown the run is cancelled and the claim
    /// released with `shutdown`. Workspaces are destroyed only when the state
    /// reached by the dispatch transition is configured as terminal; retry and
    /// shutdown releases preserve the workspace for resumption.
    ///
    /// # Ownership contract
    ///
    /// The caller first acquires a budget slot and registers the claim as
    /// in-flight (done by [`Orchestrator::claim_next`] and the resume path). The
    /// internal `HeldClaim` guard created here owns slot release and heartbeat
    /// cancellation, so the slot is freed on **every** exit path, including the
    /// `?` error paths below.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when a tracker/runner/workspace call fails for reasons
    /// other than the run itself failing.
    pub async fn run_claim(&self, claim: x0x_symphony_core::Claim) -> Result<Resolution> {
        // Guard: owns the budget slot + heartbeat task; releases on EVERY exit.
        let mut guard = HeldClaim::new(self, &claim);
        guard.spawn_heartbeat(
            Arc::clone(&self.tracker),
            claim.clone(),
            self.config.heartbeat_interval(),
        );

        let issue = self.fetch_claim_issue(&claim).await?;
        let handle = self.workspace.create(&issue).await?;
        let workspace_path = handle.path.clone();

        if self
            .block_if_hook_failed(&mut guard, &claim, &handle, HookName::AfterCreate)
            .await?
        {
            self.cleanup_if_terminal(&claim, &handle, "blocked").await?;
            return Ok(Resolution::Blocked);
        }

        let max_attempts = self.config.retry.max_attempts();
        let mut attempts = 0_u32;
        loop {
            attempts += 1;
            if self
                .block_if_hook_failed(&mut guard, &claim, &handle, HookName::BeforeRun)
                .await?
            {
                self.cleanup_if_terminal(&claim, &handle, "blocked").await?;
                return Ok(Resolution::Blocked);
            }

            let session = self
                .runner
                .start_session(SessionContext::new(issue.clone(), workspace_path.clone()))
                .await?;
            let prompt = Prompt::new(issue.description.clone());
            // The run-turn branch takes ownership; clone first so the shutdown
            // branch still owns a handle to stop the same runner-side session.
            let run_session = session.clone();
            let outcome = tokio::select! {
                biased;
                () = self.shutdown_signaled() => {
                    let _ = self.runner.stop_session(session).await;
                    guard.cancel_heartbeat();
                    self.tracker
                        .release(
                            &claim,
                            ReleaseReason::new(ReleaseReasonCode::Shutdown, "graceful shutdown"),
                        )
                        .await?;
                    return Ok(Resolution::ShutdownReleased);
                }
                outcome = self.runner.run_turn_prompt(run_session, prompt) => outcome?,
            };
            let _ = self.runner.stop_session(outcome.session).await;

            self.warn_after_run_hook_failure(&claim, &handle).await;

            match outcome.status {
                TurnStatus::Succeeded => {
                    let handoff = Handoff::new(format!(
                        "runner '{}' succeeded after {attempts} attempt(s)",
                        self.runner.name()
                    ))
                    .with_file(workspace_path.to_string_lossy().into_owned());
                    guard.cancel_heartbeat();
                    self.tracker.handoff(&claim, handoff).await?;
                    self.cleanup_if_terminal(&claim, &handle, "review").await?;
                    return Ok(Resolution::Completed);
                }
                TurnStatus::Failed | TurnStatus::TimedOut | TurnStatus::Cancelled
                    if attempts >= max_attempts =>
                {
                    guard.cancel_heartbeat();
                    self.tracker
                        .block(
                            &claim,
                            ReleaseReason::new(
                                ReleaseReasonCode::RetryExhausted,
                                format!(
                                    "runner '{}' failed after {attempts} attempt(s)",
                                    self.runner.name()
                                ),
                            ),
                        )
                        .await?;
                    self.cleanup_if_terminal(&claim, &handle, "blocked").await?;
                    return Ok(Resolution::Blocked);
                }
                TurnStatus::Failed | TurnStatus::TimedOut | TurnStatus::Cancelled => {
                    // Retry: back off, then loop. The claim stays in_progress
                    // and the heartbeat task keeps it fresh.
                    sleep(self.config.retry.backoff_after(attempts)).await;
                }
            }
        }
    }

    async fn block_if_hook_failed(
        &self,
        guard: &mut HeldClaim<'_, T, R, W>,
        claim: &Claim,
        handle: &WorkspaceHandle,
        phase: HookName,
    ) -> Result<bool> {
        let phase_name = phase.as_str();
        match self.run_hook_phase(claim, handle, phase).await {
            Ok(None) => Ok(false),
            Ok(Some(outcome)) if outcome.status.is_success() => Ok(false),
            Ok(Some(outcome)) => {
                self.block_for_hook_failure(
                    guard,
                    claim,
                    phase_name,
                    describe_hook_outcome(&outcome),
                )
                .await?;
                Ok(true)
            }
            Err(error) => {
                self.block_for_hook_failure(guard, claim, phase_name, error.to_string())
                    .await?;
                Ok(true)
            }
        }
    }

    async fn block_for_hook_failure(
        &self,
        guard: &mut HeldClaim<'_, T, R, W>,
        claim: &Claim,
        phase_name: &str,
        detail: String,
    ) -> Result<()> {
        guard.cancel_heartbeat();
        self.tracker
            .block(
                claim,
                ReleaseReason::new(
                    ReleaseReasonCode::Other,
                    format!("{phase_name} hook failed: {detail}"),
                ),
            )
            .await?;
        Ok(())
    }

    async fn warn_after_run_hook_failure(&self, claim: &Claim, handle: &WorkspaceHandle) {
        match self.run_hook_phase(claim, handle, HookName::AfterRun).await {
            Ok(
                None
                | Some(HookOutcome {
                    status: HookStatus::Succeeded,
                    ..
                }),
            ) => {}
            Ok(Some(outcome)) => {
                warn!(
                    issue_id = handle.issue_id.as_str(),
                    detail = %describe_hook_outcome(&outcome),
                    "after_run hook failed; preserving runner outcome"
                );
            }
            Err(error) => {
                warn!(
                    issue_id = handle.issue_id.as_str(),
                    error = %error,
                    "after_run hook errored; preserving runner outcome"
                );
            }
        }
    }

    async fn cleanup_if_terminal(
        &self,
        claim: &Claim,
        handle: &WorkspaceHandle,
        state_name: &str,
    ) -> Result<()> {
        if !self
            .config
            .terminal_states
            .iter()
            .any(|state| state.as_str() == state_name)
        {
            return Ok(());
        }

        if self.before_remove_allows_cleanup(claim, handle).await {
            self.workspace.destroy(handle.clone()).await?;
        }
        Ok(())
    }

    async fn before_remove_allows_cleanup(&self, claim: &Claim, handle: &WorkspaceHandle) -> bool {
        match self
            .run_hook_phase(claim, handle, HookName::BeforeRemove)
            .await
        {
            Ok(
                None
                | Some(HookOutcome {
                    status: HookStatus::Succeeded,
                    ..
                }),
            ) => true,
            Ok(Some(outcome)) => {
                warn!(
                    issue_id = handle.issue_id.as_str(),
                    detail = %describe_hook_outcome(&outcome),
                    "before_remove hook failed; preserving workspace"
                );
                false
            }
            Err(error) => {
                warn!(
                    issue_id = handle.issue_id.as_str(),
                    error = %error,
                    "before_remove hook errored; preserving workspace"
                );
                false
            }
        }
    }

    async fn run_hook_phase(
        &self,
        claim: &Claim,
        handle: &WorkspaceHandle,
        phase: HookName,
    ) -> Result<Option<HookOutcome>> {
        let Some(hook) = self.config.hooks.hook(phase) else {
            return Ok(None);
        };
        let env = self.hook_env(claim, handle, hook.name.as_str());
        let outcome = self.workspace.run_hook_in(handle, &hook, &env).await?;
        Ok(Some(outcome))
    }

    fn hook_env(&self, claim: &Claim, handle: &WorkspaceHandle, phase_name: &str) -> HookEnv {
        HookEnv::new()
            .with_var("ISSUE_ID", handle.issue_id.as_str())
            .with_var("AGENT_ID", self.config.agent_id.as_str())
            .with_var("WORKSPACE_DIR", handle.path.to_string_lossy().into_owned())
            .with_var("CLAIM_ID", claim_env_id(claim))
            .with_var("HOOK_PHASE", phase_name)
    }

    /// Fetch the current issue record behind a claim.
    async fn fetch_claim_issue(&self, claim: &x0x_symphony_core::Claim) -> Result<Issue> {
        let id = claim.issue_id.clone().ok_or_else(|| Error::NotEligible {
            id: "(no issue)".to_owned(),
            reason: "claim carries no issue id".into(),
        })?;
        let issues = self.tracker.fetch_by_ids(std::slice::from_ref(&id)).await?;
        issues.into_iter().next().ok_or_else(|| Error::NotEligible {
            id: id.to_string(),
            reason: "issue behind claim not found".into(),
        })
    }

    /// Freshly claim a `todo` issue for this agent.
    pub(crate) async fn claim_issue(&self, id: &IssueId) -> Result<x0x_symphony_core::Claim> {
        self.tracker
            .claim(id, &self.config.agent_id)
            .await
            .map_err(Into::into)
    }
}
