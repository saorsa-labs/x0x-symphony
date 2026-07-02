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

use std::{path::Path, process::Stdio, sync::Arc, time::Duration};

use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tracing::warn;
use x0x_symphony_core::{
    Claim, Handoff, HookEnv, HookName, HookOutcome, HookStatus, Issue, IssueId, Prompt,
    ReleaseReason, ReleaseReasonCode, Runner, SessionContext, Tracker, TurnStatus,
    ValidationResult, ValidationStatus, Workspace, WorkspaceHandle,
};

use crate::{
    clock::Clock,
    error::{Error, Result},
    proofs::{join_event_writer, ProofRun},
    reconcile::is_fresh_self,
    Orchestrator,
};

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
    summary: Option<String>,
    session: x0x_symphony_core::SessionHandle,
}

/// Result of racing one runner turn against a shutdown signal.
enum RunSelection {
    /// Shutdown won the race and still owns the runner session.
    Shutdown(x0x_symphony_core::SessionHandle),
    /// The runner turn completed or errored.
    Turn(Result<RunTurnOutcome>),
}

/// Completed runner turn data needed after session cleanup.
struct CompletedTurn {
    status: TurnStatus,
    summary: Option<String>,
}

/// Outcome of one dispatch attempt.
enum AttemptOutcome {
    /// Shutdown won the race and the claim was released.
    ShutdownReleased,
    /// The runner turn completed and can be classified by the retry loop.
    Completed(CompletedTurn),
}

/// Lets `select!` await `run_turn` while keeping the session handle for the
/// later `stop_session`. The core `Runner` trait takes the session by value, so
/// we wrap the call and thread the handle back out.
///
/// The `allow(async_fn_in_trait)` attribute below documents a private helper
/// trait whose async future is awaited locally inside `run_claim`'s `select!` and is never spawned
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
            summary: outcome.summary,
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

fn hook_status_name(status: &HookStatus) -> &'static str {
    match status {
        HookStatus::Succeeded => "succeeded",
        HookStatus::Failed => "failed",
        HookStatus::TimedOut => "timed_out",
    }
}

fn turn_exit_code(status: &TurnStatus, summary: Option<&str>) -> i32 {
    match status {
        TurnStatus::Succeeded => parse_exit_code(summary).unwrap_or(0),
        TurnStatus::Failed | TurnStatus::TimedOut | TurnStatus::Cancelled => {
            parse_exit_code(summary)
                .filter(|code| *code != 0)
                .unwrap_or(1)
        }
    }
}

fn parse_exit_code(summary: Option<&str>) -> Option<i32> {
    let summary = summary?;
    for part in summary.split(|ch: char| ch.is_whitespace() || ch == ',' || ch == ';') {
        if let Some(raw) = part.strip_prefix("exit_code=") {
            if let Ok(value) = raw.parse::<i32>() {
                return Some(value);
            }
        }
    }
    None
}

const GIT_DIFF_TIMEOUT: Duration = Duration::from_secs(10);

async fn changed_files_from_git_diff(workspace_path: &Path) -> Vec<String> {
    let output = timeout(
        GIT_DIFF_TIMEOUT,
        Command::new("git")
            .arg("-C")
            .arg(workspace_path)
            .arg("diff")
            .arg("--name-only")
            .output(),
    )
    .await;

    let output = match output {
        Ok(Ok(output)) => output,
        Ok(Err(source)) => {
            warn!(
                workspace = %workspace_path.display(),
                error = %source,
                "git diff --name-only failed; handoff files_changed left empty"
            );
            return Vec::new();
        }
        Err(_) => {
            warn!(
                workspace = %workspace_path.display(),
                timeout_ms = GIT_DIFF_TIMEOUT.as_millis(),
                "git diff --name-only timed out; handoff files_changed left empty"
            );
            return Vec::new();
        }
    };

    if !output.status.success() {
        warn!(
            workspace = %workspace_path.display(),
            exit_code = ?output.status.code(),
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "git diff --name-only returned non-zero; handoff files_changed left empty"
        );
        return Vec::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

async fn run_validation_commands(
    workspace_path: &Path,
    commands: &[String],
) -> Vec<ValidationResult> {
    let mut results = Vec::with_capacity(commands.len());
    for command in commands
        .iter()
        .map(|command| command.trim())
        .filter(|command| !command.is_empty())
    {
        results.push(run_validation_command(workspace_path, command).await);
    }
    results
}

async fn run_validation_command(workspace_path: &Path, command: &str) -> ValidationResult {
    let mut process = shell_command(command);
    process.current_dir(workspace_path);
    process.stdin(Stdio::null());
    process.stdout(Stdio::null());
    process.stderr(Stdio::null());

    match process.status().await {
        Ok(status) => {
            let validation_status = if status.success() {
                ValidationStatus::Passed
            } else {
                ValidationStatus::Failed
            };
            let mut result = ValidationResult::new(command, validation_status);
            if let Some(code) = status.code() {
                result = result.with_exit_code(code);
            }
            result
        }
        Err(source) => {
            warn!(
                workspace = %workspace_path.display(),
                command = %command,
                error = %source,
                "validation command failed to start; recording failed validation"
            );
            ValidationResult::new(command, ValidationStatus::Failed)
        }
    }
}

fn shell_command(command: &str) -> Command {
    let mut process = platform_shell();
    process.arg(command);
    process
}

#[cfg(windows)]
fn platform_shell() -> Command {
    let mut process = Command::new("cmd");
    process.arg("/C");
    process
}

#[cfg(not(windows))]
fn platform_shell() -> Command {
    let mut process = Command::new("sh");
    process.arg("-c");
    process
}

fn configured_validation_commands(configured: &[String], issue: &Issue) -> Vec<String> {
    if !configured.is_empty() {
        return configured.to_vec();
    }
    let issue_validation = issue_extra_string_list(issue, "validation");
    if !issue_validation.is_empty() {
        return issue_validation;
    }
    issue_extra_string_list(issue, "acceptance")
        .into_iter()
        .filter_map(|entry| acceptance_validation_command(&entry))
        .collect()
}

fn acceptance_validation_command(entry: &str) -> Option<String> {
    for prefix in ["validation:", "validation command:", "command:"] {
        let Some(command) = entry.strip_prefix(prefix) else {
            continue;
        };
        let trimmed = command.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    None
}

fn issue_extra_string_list(issue: &Issue, key: &str) -> Vec<String> {
    let Some(value) = issue.extra.get(key) else {
        return Vec::new();
    };
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn follow_ups_from_summary(summary: Option<&str>) -> Vec<String> {
    let Some(summary) = summary else {
        return Vec::new();
    };
    summary
        .lines()
        .filter_map(|line| follow_up_line(line.trim()))
        .collect()
}

fn follow_up_line(line: &str) -> Option<String> {
    for prefix in ["follow_up:", "follow-up:", "follow_up="] {
        let Some(note) = line.strip_prefix(prefix) else {
            continue;
        };
        let trimmed = note.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    None
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
    /// one quarter of the issue's claim TTL for
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
        let issue = self.fetch_claim_issue(&claim).await?;
        guard.spawn_heartbeat(
            Arc::clone(&self.tracker),
            claim.clone(),
            self.issue_heartbeat_interval(&issue),
        );
        let mut proof = ProofRun::start(
            &self.config.proofs_dir,
            &issue,
            &self.config.agent_id,
            self.runner.name(),
            self.runner.capabilities(),
            self.clock.now(),
        )?;
        let handle = self.workspace.create(&issue).await?;
        let workspace_path = handle.path.clone();

        if self
            .block_if_hook_failed(
                &mut guard,
                &claim,
                &handle,
                HookName::AfterCreate,
                &mut proof,
            )
            .await?
        {
            self.cleanup_if_terminal(&claim, &handle, "blocked", &mut proof)
                .await?;
            proof.finish(1, self.clock.now())?;
            return Ok(Resolution::Blocked);
        }

        let max_attempts = self.config.retry.max_attempts();
        let mut attempts = 0_u32;
        loop {
            attempts += 1;
            if self
                .block_if_hook_failed(&mut guard, &claim, &handle, HookName::BeforeRun, &mut proof)
                .await?
            {
                self.cleanup_if_terminal(&claim, &handle, "blocked", &mut proof)
                    .await?;
                proof.finish(1, self.clock.now())?;
                return Ok(Resolution::Blocked);
            }

            let outcome = match self
                .run_attempt(&claim, &mut guard, &issue, &workspace_path, &mut proof)
                .await?
            {
                AttemptOutcome::ShutdownReleased => return Ok(Resolution::ShutdownReleased),
                AttemptOutcome::Completed(outcome) => outcome,
            };

            self.warn_after_run_hook_failure(&claim, &handle, &mut proof)
                .await;
            let exit_code = turn_exit_code(&outcome.status, outcome.summary.as_deref());

            match outcome.status {
                TurnStatus::Succeeded => {
                    let handoff = self
                        .build_success_handoff(&issue, &workspace_path, &proof, attempts, &outcome)
                        .await;
                    guard.cancel_heartbeat();
                    self.tracker.handoff(&claim, handoff).await?;
                    self.cleanup_if_terminal(&claim, &handle, "review", &mut proof)
                        .await?;
                    proof.finish(exit_code, self.clock.now())?;
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
                    self.cleanup_if_terminal(&claim, &handle, "blocked", &mut proof)
                        .await?;
                    proof.finish(exit_code, self.clock.now())?;
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

    async fn build_success_handoff(
        &self,
        issue: &Issue,
        workspace_path: &Path,
        proof: &ProofRun,
        attempts: u32,
        outcome: &CompletedTurn,
    ) -> Handoff {
        let validation_commands =
            configured_validation_commands(&self.config.validation_commands, issue);
        let validation = run_validation_commands(workspace_path, &validation_commands).await;
        let files_changed = changed_files_from_git_diff(workspace_path).await;
        let follow_ups = follow_ups_from_summary(outcome.summary.as_deref());
        let mut handoff = Handoff::new(format!(
            "runner '{}' succeeded after {attempts} attempt(s)",
            self.runner.name()
        ))
        .with_files_changed(files_changed)
        .with_follow_ups(follow_ups)
        .with_proofs_dir(proof.relative_dir().to_owned());
        for result in validation {
            handoff = handoff.with_validation(result);
        }
        handoff
    }

    async fn run_attempt(
        &self,
        claim: &Claim,
        guard: &mut HeldClaim<'_, T, R, W>,
        issue: &Issue,
        workspace_path: &std::path::Path,
        proof: &mut ProofRun,
    ) -> Result<AttemptOutcome> {
        let session = self
            .runner
            .start_session(SessionContext::new(
                issue.clone(),
                workspace_path.to_path_buf(),
            ))
            .await?;
        let event_writer = proof.spawn_event_writer(
            self.runner.stream_events(&session),
            workspace_path.to_path_buf(),
        );
        let prompt = Prompt::new(issue.description.clone());
        // The run-turn branch takes ownership; clone first so the shutdown
        // branch still owns a handle to stop the same runner-side session. A
        // second clone lets us clean up if the runner errors without returning
        // its session handle.
        let run_session = session.clone();
        let stop_on_error = session.clone();
        let selected = tokio::select! {
            biased;
            () = self.shutdown_signaled() => RunSelection::Shutdown(session),
            outcome = self.runner.run_turn_prompt(run_session, prompt) => {
                RunSelection::Turn(outcome)
            }
        };
        let outcome = match selected {
            RunSelection::Shutdown(session) => {
                let _ = self.runner.stop_session(session).await;
                join_event_writer(event_writer).await?;
                guard.cancel_heartbeat();
                self.tracker
                    .release(
                        claim,
                        ReleaseReason::new(ReleaseReasonCode::Shutdown, "graceful shutdown"),
                    )
                    .await?;
                proof.finish(1, self.clock.now())?;
                return Ok(AttemptOutcome::ShutdownReleased);
            }
            RunSelection::Turn(Ok(outcome)) => outcome,
            RunSelection::Turn(Err(error)) => {
                let _ = self.runner.stop_session(stop_on_error).await;
                join_event_writer(event_writer).await?;
                return Err(error);
            }
        };
        let _ = self.runner.stop_session(outcome.session).await;
        join_event_writer(event_writer).await?;
        Ok(AttemptOutcome::Completed(CompletedTurn {
            status: outcome.status,
            summary: outcome.summary,
        }))
    }

    async fn block_if_hook_failed(
        &self,
        guard: &mut HeldClaim<'_, T, R, W>,
        claim: &Claim,
        handle: &WorkspaceHandle,
        phase: HookName,
        proof: &mut ProofRun,
    ) -> Result<bool> {
        let phase_name = phase.as_str();
        match self.run_hook_phase(claim, handle, phase).await {
            Ok(None) => Ok(false),
            Ok(Some(outcome)) if outcome.status.is_success() => {
                proof.record_hook(phase_name, hook_status_name(&outcome.status));
                Ok(false)
            }
            Ok(Some(outcome)) => {
                proof.record_hook(phase_name, hook_status_name(&outcome.status));
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
                proof.record_hook(phase_name, "errored");
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

    async fn warn_after_run_hook_failure(
        &self,
        claim: &Claim,
        handle: &WorkspaceHandle,
        proof: &mut ProofRun,
    ) {
        match self.run_hook_phase(claim, handle, HookName::AfterRun).await {
            Ok(None) => {}
            Ok(Some(outcome)) if outcome.status.is_success() => {
                proof.record_hook(
                    HookName::AfterRun.as_str(),
                    hook_status_name(&outcome.status),
                );
            }
            Ok(Some(outcome)) => {
                proof.record_hook(
                    HookName::AfterRun.as_str(),
                    hook_status_name(&outcome.status),
                );
                warn!(
                    issue_id = handle.issue_id.as_str(),
                    detail = %describe_hook_outcome(&outcome),
                    "after_run hook failed; preserving runner outcome"
                );
            }
            Err(error) => {
                proof.record_hook(HookName::AfterRun.as_str(), "errored");
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
        proof: &mut ProofRun,
    ) -> Result<()> {
        if !self
            .config
            .terminal_states
            .iter()
            .any(|state| state.as_str() == state_name)
        {
            return Ok(());
        }

        if self
            .before_remove_allows_cleanup(claim, handle, proof)
            .await
        {
            self.workspace.destroy(handle.clone()).await?;
        }
        Ok(())
    }

    async fn before_remove_allows_cleanup(
        &self,
        claim: &Claim,
        handle: &WorkspaceHandle,
        proof: &mut ProofRun,
    ) -> bool {
        match self
            .run_hook_phase(claim, handle, HookName::BeforeRemove)
            .await
        {
            Ok(None) => true,
            Ok(Some(outcome)) if outcome.status.is_success() => {
                proof.record_hook(
                    HookName::BeforeRemove.as_str(),
                    hook_status_name(&outcome.status),
                );
                true
            }
            Ok(Some(outcome)) => {
                proof.record_hook(
                    HookName::BeforeRemove.as_str(),
                    hook_status_name(&outcome.status),
                );
                warn!(
                    issue_id = handle.issue_id.as_str(),
                    detail = %describe_hook_outcome(&outcome),
                    "before_remove hook failed; preserving workspace"
                );
                false
            }
            Err(error) => {
                proof.record_hook(HookName::BeforeRemove.as_str(), "errored");
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
