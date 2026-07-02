//! Dispatch orchestrator for x0x-symphony.
//!
//! Ties the [`Tracker`], [`Runner`], and [`Workspace`] traits together:
//!
//! - polls the tracker at a configured interval;
//! - gates eligibility on active state, live-resolved blockers, and claim
//!   freshness (free, or self-owned-and-fresh);
//! - respects a global concurrency cap and optional per-state caps;
//! - retries failed runs with exponential backoff (base 5 s, capped) and a
//!   max-attempts cap, moving an issue to `blocked` on exhaustion;
//! - reconciles on startup: fresh self-owned claims resume, stale ones release;
//! - heartbeats held claims at `claim_ttl / 4`;
//! - shuts down gracefully on a signal: stop claiming, let in-flight runs
//!   release their claims with `shutdown`, and preserve workspaces.
//!
//! See `docs/plan/2026-07-m1-execution-plan.md` WP-4 (XSY-0006).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod clock;
pub mod concurrency;
pub mod dispatch;
pub mod error;
pub mod reconcile;
pub mod retry;

pub use clock::{Clock, ManualClock, SystemClock};
pub use concurrency::Budget;
pub use dispatch::{claimable_for, Claimable, Resolution};
pub use error::{Error, Result};
pub use reconcile::{classify, is_fresh_self, parse_heartbeat, ClaimStance, ReconcileSummary};
pub use retry::RetryPolicy;

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use tokio::sync::Notify;
use x0x_symphony_core::{
    AgentId, Claim, IssueId, IssueState, LifecycleHooks, PollContext, ReleaseReason,
    ReleaseReasonCode, Runner, Tracker, Workspace,
};

use crate::concurrency::Budget as BudgetImpl;

/// Internal mutable orchestrator state.
struct State {
    budget: BudgetImpl,
    in_flight: BTreeMap<IssueId, InFlight>,
}

/// A currently-running claim plus the state whose budget slot it holds.
#[derive(Clone, Debug)]
struct InFlight {
    /// Workflow state of the in-flight issue (used to release the right budget slot).
    state: IssueState,
}

/// Orchestrator wiring a tracker, runner, workspace, clock, and config.
pub struct Orchestrator<T, R, W> {
    tracker: Arc<T>,
    runner: Arc<R>,
    workspace: Arc<W>,
    clock: Arc<dyn Clock>,
    config: Config,
    state: Mutex<State>,
    shutdown_notify: Notify,
    shutdown_flag: AtomicBool,
}

/// Immutable orchestrator configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Identity of the agent driving this orchestrator.
    pub agent_id: AgentId,
    /// States eligible for dispatch (typically `["todo"]`).
    pub active_states: Vec<IssueState>,
    /// States considered terminal for blocker resolution.
    pub terminal_states: Vec<IssueState>,
    /// Poll-loop interval.
    pub polling_interval: Duration,
    /// Maximum concurrent in-flight runs.
    pub global_concurrency: usize,
    /// Optional per-state concurrency caps.
    pub per_state_concurrency: BTreeMap<IssueState, usize>,
    /// Retry policy (backoff + attempts cap).
    pub retry: RetryPolicy,
    /// Lifecycle hook scripts and timeout.
    pub hooks: LifecycleHooks,
    /// Claim heartbeat TTL; a claim older than this is stale.
    pub claim_ttl: chrono::Duration,
    /// Maximum time to wait for in-flight runs to release on shutdown.
    pub shutdown_grace: Duration,
}

impl Config {
    /// Builder seeded with M1 defaults (retry base 5 s/cap 5 min/3 attempts,
    /// 30-minute claim TTL, 1-minute shutdown grace, single agent). Active and
    /// terminal states default to empty; callers must set them before the
    /// orchestrator will dispatch anything.
    #[must_use]
    pub fn builder(agent_id: AgentId) -> ConfigBuilder {
        ConfigBuilder {
            agent_id,
            active_states: Vec::new(),
            terminal_states: Vec::new(),
            polling_interval: Duration::from_secs(5),
            global_concurrency: 1,
            per_state_concurrency: BTreeMap::new(),
            retry: RetryPolicy::default(),
            hooks: LifecycleHooks::default(),
            claim_ttl: chrono::Duration::minutes(30),
            shutdown_grace: Duration::from_mins(1),
        }
    }

    /// Heartbeat interval: one quarter of the claim TTL, never zero.
    #[must_use]
    pub fn heartbeat_interval(&self) -> Duration {
        let quarter_ms = self.claim_ttl.num_milliseconds().max(0) / 4;
        Duration::from_millis(u64::try_from(quarter_ms).unwrap_or(0).max(1))
    }

    fn poll_context(&self) -> PollContext {
        PollContext::new(self.active_states.clone(), self.terminal_states.clone())
            .with_agent_id(self.agent_id.clone())
    }
}

/// Builder for [`Config`].
#[derive(Clone, Debug)]
pub struct ConfigBuilder {
    agent_id: AgentId,
    active_states: Vec<IssueState>,
    terminal_states: Vec<IssueState>,
    polling_interval: Duration,
    global_concurrency: usize,
    per_state_concurrency: BTreeMap<IssueState, usize>,
    retry: RetryPolicy,
    hooks: LifecycleHooks,
    claim_ttl: chrono::Duration,
    shutdown_grace: Duration,
}

impl ConfigBuilder {
    /// Override the dispatchable active states.
    #[must_use]
    pub fn active_states(mut self, states: Vec<IssueState>) -> Self {
        self.active_states = states;
        self
    }
    /// Override the terminal states.
    #[must_use]
    pub fn terminal_states(mut self, states: Vec<IssueState>) -> Self {
        self.terminal_states = states;
        self
    }
    /// Override the poll interval.
    #[must_use]
    pub fn polling_interval(mut self, interval: Duration) -> Self {
        self.polling_interval = interval;
        self
    }
    /// Override the global concurrency cap.
    #[must_use]
    pub fn global_concurrency(mut self, cap: usize) -> Self {
        self.global_concurrency = cap.max(1);
        self
    }
    /// Add per-state concurrency caps.
    #[must_use]
    pub fn per_state_concurrency(mut self, caps: BTreeMap<IssueState, usize>) -> Self {
        self.per_state_concurrency = caps;
        self
    }
    /// Override the retry policy.
    #[must_use]
    pub fn retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }
    /// Override lifecycle hook scripts and timeout.
    #[must_use]
    pub fn hooks(mut self, hooks: LifecycleHooks) -> Self {
        self.hooks = hooks;
        self
    }
    /// Override the claim TTL.
    #[must_use]
    pub fn claim_ttl(mut self, ttl: chrono::Duration) -> Self {
        self.claim_ttl = ttl;
        self
    }
    /// Override the shutdown grace period.
    #[must_use]
    pub fn shutdown_grace(mut self, grace: Duration) -> Self {
        self.shutdown_grace = grace;
        self
    }
    /// Finalize the configuration.
    #[must_use]
    pub fn build(self) -> Config {
        Config {
            agent_id: self.agent_id,
            active_states: self.active_states,
            terminal_states: self.terminal_states,
            polling_interval: self.polling_interval,
            global_concurrency: self.global_concurrency,
            per_state_concurrency: self.per_state_concurrency,
            retry: self.retry,
            hooks: self.hooks,
            claim_ttl: self.claim_ttl,
            shutdown_grace: self.shutdown_grace,
        }
    }
}

impl<T, R, W> Orchestrator<T, R, W> {
    /// Construct an orchestrator over the given dependencies.
    #[must_use]
    pub fn new(
        tracker: Arc<T>,
        runner: Arc<R>,
        workspace: Arc<W>,
        clock: Arc<dyn Clock>,
        config: Config,
    ) -> Self {
        let budget = BudgetImpl::new(
            config.global_concurrency,
            config.per_state_concurrency.clone(),
        );
        Self {
            tracker,
            runner,
            workspace,
            clock,
            config,
            state: Mutex::new(State {
                budget,
                in_flight: BTreeMap::new(),
            }),
            shutdown_notify: Notify::new(),
            shutdown_flag: AtomicBool::new(false),
        }
    }

    /// Claim TTL as a `chrono::Duration`.
    fn ttl(&self) -> chrono::Duration {
        self.config.claim_ttl
    }

    /// `true` once shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown_flag.load(Ordering::Acquire)
    }

    /// Future that completes when shutdown is requested. Polled inside
    /// `select!` to preempt a run.
    async fn shutdown_signaled(&self) {
        if self.shutdown_flag.load(Ordering::Acquire) {
            return;
        }
        self.shutdown_notify.notified().await;
        // The notify is best-effort; the flag is authoritative.
    }

    /// Free the budget slot and in-flight registration for `claim`.
    fn release_slot(&self, claim: &Claim) {
        let id = match &claim.issue_id {
            Some(id) => id.clone(),
            None => return,
        };
        if let Ok(mut state) = self.state.lock() {
            if let Some(entry) = state.in_flight.remove(&id) {
                state.budget.release(&entry.state);
            }
        }
    }
}

impl<T, R, W> Orchestrator<T, R, W>
where
    // `T` must be shareable across the heartbeat task spawned by `run_claim`;
    // `R`/`W` are driven only on the calling task and need no extra bounds.
    T: Tracker + Send + Sync + 'static,
    R: Runner,
    W: Workspace,
{
    /// Claim one eligible issue under the concurrency budget.
    ///
    /// Polls the tracker, finds the highest-priority candidate that is free (or
    /// self-owned-and-fresh) and for which a budget slot is available, claims
    /// it, and registers it as in-flight. Returns `Ok(None)` when nothing is
    /// claimable right now (budget full, or no eligible issues).
    ///
    /// # Errors
    /// Propagates tracker or heartbeat-parse errors.
    pub async fn claim_next(&self) -> Result<Option<Claim>> {
        if self.is_shutdown() {
            return Ok(None);
        }
        let candidates = self
            .tracker
            .fetch_candidates(&self.config.poll_context())
            .await?;
        for issue in candidates {
            let Some(_claimable) = dispatch::claimable_for(
                &issue,
                &self.config.agent_id,
                self.clock.as_ref(),
                self.ttl(),
            )?
            else {
                continue;
            };
            // Reserve a budget slot before claiming so the cap holds.
            let acquired = {
                let Ok(mut state) = self.state.lock() else {
                    continue;
                };
                state.budget.try_acquire(&issue.state)
            };
            if !acquired {
                // Global or per-state cap exhausted; stop claiming more.
                break;
            }
            match self.claim_issue(&issue.id).await {
                Ok(claim) => {
                    if let Ok(mut state) = self.state.lock() {
                        state.in_flight.insert(
                            issue.id.clone(),
                            InFlight {
                                state: issue.state.clone(),
                            },
                        );
                    }
                    return Ok(Some(claim));
                }
                Err(_claim_failed) => {
                    // Someone else claimed it between poll and claim; release
                    // the slot and try the next candidate.
                    if let Ok(mut state) = self.state.lock() {
                        state.budget.release(&issue.state);
                    }
                }
            }
        }
        Ok(None)
    }

    /// One full cycle: claim one issue and run it to resolution.
    ///
    /// Returns `Ok(None)` when nothing was claimable.
    ///
    /// # Errors
    /// Propagates dispatch errors.
    pub async fn run_once(&self) -> Result<Option<Resolution>> {
        let Some(claim) = self.claim_next().await? else {
            return Ok(None);
        };
        let resolution = self.run_claim(claim).await?;
        Ok(Some(resolution))
    }

    /// Startup reconciliation.
    ///
    /// Releases stale self-owned claims with `expired_heartbeat`; counts fresh
    /// self-owned claims as resumable and foreign claims as observed. Does not
    /// touch foreign claims. Fresh self-owned claims are kept (`in_progress`) so a
    /// subsequent [`Self::run`] can resume them.
    ///
    /// # Errors
    /// Propagates tracker or heartbeat-parse errors.
    pub async fn reconcile(&self) -> Result<ReconcileSummary> {
        let claimed = self
            .tracker
            .fetch_claimed(Some(&self.config.agent_id))
            .await?;
        let now: DateTime<Utc> = self.clock.now();
        let ttl = self.ttl();
        let mut summary = ReconcileSummary::default();
        for issue in claimed {
            let Some(claim) = &issue.claim else { continue };
            match reconcile::classify(claim, &self.config.agent_id, now, ttl)? {
                ClaimStance::FreshSelf => summary.resumed += 1,
                ClaimStance::StaleSelf => {
                    self.tracker
                        .release(
                            claim,
                            ReleaseReason::new(
                                ReleaseReasonCode::ExpiredHeartbeat,
                                "stale claim on startup",
                            ),
                        )
                        .await?;
                    summary.released += 1;
                }
                // fetch_claimed(Some(self)) only returns this agent's claims, so
                // a foreign classification should not occur; if it does, leave
                // the claim untouched rather than acting on another agent's work.
                ClaimStance::Foreign => {}
            }
        }
        Ok(summary)
    }

    /// Request graceful shutdown.
    ///
    /// Signals in-flight runs to self-release their claims with `shutdown`
    /// (workspaces preserved), then waits up to `shutdown_grace` for them to
    /// drain. Returns the number of in-flight runs that were signaled.
    pub async fn shutdown(&self) -> usize {
        let signaled = {
            let Ok(state) = self.state.lock() else {
                return 0;
            };
            self.shutdown_flag.store(true, Ordering::Release);
            state.in_flight.len()
        };
        self.shutdown_notify.notify_waiters();
        let deadline = tokio::time::Instant::now() + self.config.shutdown_grace;
        loop {
            let remaining = {
                let Ok(state) = self.state.lock() else { break };
                state.in_flight.len()
            };
            if remaining == 0 || tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        signaled
    }

    /// Long-running daemon loop.
    ///
    /// Reconciles once at startup, then repeatedly claims and runs issues while
    /// spawning a heartbeat task for held claims, until shutdown is requested.
    /// On shutdown it stops claiming and lets in-flight runs release cleanly.
    ///
    /// # Errors
    /// Propagates the first non-recoverable tracker/runner error.
    pub async fn run(&self) -> Result<()> {
        let _ = self.reconcile().await;
        loop {
            if self.is_shutdown() {
                self.shutdown().await;
                return Ok(());
            }
            while let Some(claim) = self.claim_next().await? {
                // Run claimed work to completion. A production daemon would spawn
                // these concurrently up to the budget; for M1 a bounded sequential
                // drain keeps the claim lifecycle straightforward and testable.
                self.run_claim(claim).await?;
            }
            tokio::select! {
                biased;
                () = self.shutdown_signaled() => {
                    self.shutdown().await;
                    return Ok(());
                }
                () = tokio::time::sleep(self.config.polling_interval) => {}
            }
        }
    }
}
