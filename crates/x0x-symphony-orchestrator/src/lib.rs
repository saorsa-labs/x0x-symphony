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
pub mod orphans;
mod proofs;
pub mod reconcile;
pub mod retry;
pub mod trust_gate;

pub use clock::{Clock, ManualClock, SystemClock};
pub use concurrency::Budget;
pub use dispatch::{claimable_for, Claimable, Resolution};

/// Capacity for best-effort dispatch observability events.
pub const DISPATCH_EVENT_CHANNEL_CAPACITY: usize = 64;

/// Passive observability events emitted by the dispatch gate.
#[derive(Clone, Debug)]
pub enum DispatchEvent {
    /// A network-sourced dispatch reached `PendingApproval` and needs operator consent.
    ApprovalRequested {
        /// Issue awaiting operator approval.
        issue_id: IssueId,
        /// Verified network signer whose issue payload is awaiting consent.
        signer_agent_id: AgentId,
    },
    /// A previously-stored approval expired and the issue re-gated.
    ApprovalExpired {
        /// Issue whose stored approval expired.
        issue_id: IssueId,
    },
}

pub use error::{Error, Result};
pub use orphans::{OrphanSweepSummary, QuarantinedOrphan, RefusedOrphan};
pub use reconcile::{classify, is_fresh_self, parse_heartbeat, ClaimStance, ReconcileSummary};
pub use retry::RetryPolicy;
pub use trust_gate::{NetworkDispatchPolicy, TrustClient, TrustLevel, X0xdTrustClient};

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use tokio::sync::{broadcast, Notify};
use x0x_symphony_core::{
    AgentId, Claim, Issue, IssueId, IssueState, LifecycleHooks, PollContext, ReleaseReason,
    ReleaseReasonCode, Runner, ShardRole, Tracker, Workspace,
};
use x0x_symphony_signing::{SigningClient, TrustedKeyResolver};

use crate::trust_gate::UnknownTrustClient;

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
    trust_client: Arc<dyn TrustClient>,
    signing_client: Option<Arc<dyn SigningClient>>,
    key_resolver: Option<Arc<dyn TrustedKeyResolver>>,
    events_tx: Option<broadcast::Sender<DispatchEvent>>,
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
    /// Root directory where dispatch proof artefacts are written.
    pub proofs_dir: PathBuf,
    /// Validation commands recorded in successful handoffs.
    pub validation_commands: Vec<String>,
    /// Claim heartbeat TTL; a claim older than this is stale.
    pub claim_ttl: chrono::Duration,
    /// Minimum trust level required for network-sourced issue dispatch.
    pub required_trust: TrustLevel,
    /// Policy for network-sourced dispatch after source classification.
    pub network_dispatch: NetworkDispatchPolicy,
    /// Time approval records remain valid once the approval lifecycle lands.
    pub approval_ttl: Duration,
    /// Optional fire-and-forget webhook for approval requests.
    pub approval_webhook_url: Option<String>,
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
            proofs_dir: PathBuf::from("proofs"),
            validation_commands: Vec::new(),
            claim_ttl: chrono::Duration::minutes(30),
            required_trust: TrustLevel::Trusted,
            network_dispatch: NetworkDispatchPolicy::Off,
            approval_ttl: Duration::from_hours(24),
            approval_webhook_url: None,
            shutdown_grace: Duration::from_mins(1),
        }
    }

    /// Return a copy configured to write proofs under `proofs_dir`.
    #[must_use]
    pub fn with_proofs_dir(mut self, proofs_dir: impl Into<PathBuf>) -> Self {
        self.proofs_dir = proofs_dir.into();
        self
    }

    /// Heartbeat interval for manual claims: one quarter of the default claim TTL, never zero.
    #[must_use]
    pub fn heartbeat_interval(&self) -> Duration {
        reconcile::heartbeat_interval_for_ttl(self.claim_ttl)
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
    proofs_dir: PathBuf,
    validation_commands: Vec<String>,
    claim_ttl: chrono::Duration,
    required_trust: TrustLevel,
    network_dispatch: NetworkDispatchPolicy,
    approval_ttl: Duration,
    approval_webhook_url: Option<String>,
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
    /// Override the proof artefact root.
    #[must_use]
    pub fn proofs_dir(mut self, proofs_dir: impl Into<PathBuf>) -> Self {
        self.proofs_dir = proofs_dir.into();
        self
    }
    /// Override validation commands recorded in successful handoffs.
    #[must_use]
    pub fn validation_commands<I, S>(mut self, commands: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.validation_commands = commands.into_iter().map(Into::into).collect();
        self
    }
    /// Override the claim TTL.
    #[must_use]
    pub fn claim_ttl(mut self, ttl: chrono::Duration) -> Self {
        self.claim_ttl = ttl;
        self
    }
    /// Override the required trust threshold for network-sourced issues.
    #[must_use]
    pub fn required_trust(mut self, required_trust: TrustLevel) -> Self {
        self.required_trust = required_trust;
        self
    }
    /// Override the network-sourced dispatch policy.
    #[must_use]
    pub fn network_dispatch(mut self, policy: NetworkDispatchPolicy) -> Self {
        self.network_dispatch = policy;
        self
    }
    /// Override the approval time-to-live used by the approval lifecycle.
    #[must_use]
    pub fn approval_ttl(mut self, ttl: Duration) -> Self {
        self.approval_ttl = ttl;
        self
    }
    /// Override the optional approval request webhook URL.
    #[must_use]
    pub fn approval_webhook_url(mut self, url: Option<String>) -> Self {
        self.approval_webhook_url = url;
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
            proofs_dir: self.proofs_dir,
            validation_commands: self.validation_commands,
            claim_ttl: self.claim_ttl,
            required_trust: self.required_trust,
            network_dispatch: self.network_dispatch,
            approval_ttl: self.approval_ttl,
            approval_webhook_url: self.approval_webhook_url,
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
        Self::new_with_trust_client(
            tracker,
            runner,
            workspace,
            clock,
            config,
            Arc::new(UnknownTrustClient),
        )
    }

    /// Construct an orchestrator with an explicit trust client.
    #[must_use]
    pub fn new_with_trust_client(
        tracker: Arc<T>,
        runner: Arc<R>,
        workspace: Arc<W>,
        clock: Arc<dyn Clock>,
        config: Config,
        trust_client: Arc<dyn TrustClient>,
    ) -> Self {
        Self::new_with_signing(
            tracker,
            runner,
            workspace,
            clock,
            config,
            trust_client,
            None,
            None,
        )
    }

    /// Construct an orchestrator with explicit trust and optional signing clients.
    ///
    /// When both signing clients are present, the approval gate
    /// cryptographically verifies approval and denial signatures before treating
    /// them as executable operator consent. In `Approve` mode, passing `None`
    /// for either client fails closed before any task execution can start.
    // XSY-0055 intentionally mirrors the existing constructor parameters and
    // adds two optional security clients without breaking call sites.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new_with_signing(
        tracker: Arc<T>,
        runner: Arc<R>,
        workspace: Arc<W>,
        clock: Arc<dyn Clock>,
        config: Config,
        trust_client: Arc<dyn TrustClient>,
        signing_client: Option<Arc<dyn SigningClient>>,
        key_resolver: Option<Arc<dyn TrustedKeyResolver>>,
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
            trust_client,
            signing_client,
            key_resolver,
            events_tx: None,
            config,
            state: Mutex::new(State {
                budget,
                in_flight: BTreeMap::new(),
            }),
            shutdown_notify: Notify::new(),
            shutdown_flag: AtomicBool::new(false),
        }
    }

    /// Return a copy that emits dispatch observability events on `tx`.
    #[must_use]
    pub fn with_event_tx(mut self, tx: broadcast::Sender<DispatchEvent>) -> Self {
        self.events_tx = Some(tx);
        self
    }

    /// Subscribe to dispatch observability events when an event sink is configured.
    #[must_use]
    pub fn subscribe(&self) -> Option<broadcast::Receiver<DispatchEvent>> {
        self.events_tx.as_ref().map(broadcast::Sender::subscribe)
    }

    /// Best-effort dispatch observability event emission.
    pub(crate) fn emit(&self, event: DispatchEvent) {
        if let Some(tx) = &self.events_tx {
            let _send_result = tx.send(event);
        }
    }

    /// Default claim TTL as a `chrono::Duration`.
    fn ttl(&self) -> chrono::Duration {
        self.config.claim_ttl
    }

    /// Claim TTL for `issue`, using the frozen shard TTL when present.
    fn issue_ttl(&self, issue: &Issue) -> chrono::Duration {
        reconcile::issue_claim_ttl(issue, self.ttl())
    }

    /// Heartbeat refresh interval for `issue`, using the frozen shard TTL when present.
    fn issue_heartbeat_interval(&self, issue: &Issue) -> Duration {
        reconcile::issue_heartbeat_interval(issue, self.ttl())
    }

    /// Return the current number of in-flight dispatches.
    #[must_use]
    pub fn current_load(&self) -> u32 {
        let Ok(state) = self.state.lock() else {
            return 0;
        };
        u32::try_from(state.in_flight.len()).unwrap_or(u32::MAX)
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
                self.issue_ttl(&issue),
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
    /// Releases stale self-owned claims with `expired_heartbeat`, counts fresh
    /// self-owned claims as resumable, lets this agent take over from a stale
    /// primary when it is in the backup slate, and abandons this agent's losing
    /// side of a duplicate-claim conflict according to ADR-0002 lower-index
    /// precedence. Fresh self-owned claims are kept (`in_progress`) so a
    /// subsequent [`Self::run`] can resume them.
    ///
    /// # Errors
    /// Propagates tracker or heartbeat-parse errors.
    pub async fn reconcile(&self) -> Result<ReconcileSummary> {
        let claimed = self.tracker.fetch_claimed(None).await?;
        let now = self.clock.now();
        let mut by_issue: BTreeMap<IssueId, Vec<Issue>> = BTreeMap::new();
        for issue in claimed {
            if issue.claim.is_some() {
                by_issue.entry(issue.id.clone()).or_default().push(issue);
            }
        }

        let mut summary = ReconcileSummary::default();
        for (_id, issues) in by_issue {
            if self.reconcile_conflict(&issues, &mut summary, now).await? {
                continue;
            }
            let Some(issue) = issues.first() else {
                continue;
            };
            let Some(claim) = &issue.claim else { continue };
            match reconcile::classify(claim, &self.config.agent_id, now, self.issue_ttl(issue))? {
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
                ClaimStance::Foreign
                    if self.should_take_over_stale_primary(issue, claim, now)? =>
                {
                    self.tracker
                        .release(
                            claim,
                            ReleaseReason::new(
                                ReleaseReasonCode::ExpiredHeartbeat,
                                "stale primary heartbeat; backup taking over",
                            ),
                        )
                        .await?;
                    self.tracker.claim(&issue.id, &self.config.agent_id).await?;
                    summary.taken_over += 1;
                }
                ClaimStance::Foreign => {}
            }
        }
        Ok(summary)
    }

    async fn reconcile_conflict(
        &self,
        issues: &[Issue],
        summary: &mut ReconcileSummary,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool> {
        let claims = issues
            .iter()
            .filter_map(|issue| issue.claim.as_ref())
            .collect::<Vec<_>>();
        if claims.len() <= 1 {
            return Ok(false);
        }
        let Some(winner) = reconcile::winning_conflict_claim(claims.iter().copied()) else {
            return Ok(true);
        };
        let proof_directory = proofs::ProofDirectory::new(&self.config.proofs_dir);
        for issue in issues {
            let Some(claim) = issue.claim.as_ref() else {
                continue;
            };
            if claim != winner && claim.by.eq(&self.config.agent_id) {
                let reason = ReleaseReason::new(
                    ReleaseReasonCode::Conflict,
                    format!(
                        "duplicate claim abandoned; winner {} has shard rank {}",
                        winner.by,
                        winner.shard_role.rank()
                    ),
                );
                self.tracker.release(claim, reason.clone()).await?;
                proof_directory.write_abandoned(issue, claim, &reason, winner, now)?;
                summary.conflicts_abandoned += 1;
            }
        }
        Ok(true)
    }

    fn should_take_over_stale_primary(
        &self,
        issue: &Issue,
        claim: &Claim,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool> {
        let Some(shard) = issue.shard.as_ref() else {
            return Ok(false);
        };
        if !shard.primary.eq(&claim.by) || claim.shard_role != ShardRole::Primary {
            return Ok(false);
        }
        let Some(self_role @ ShardRole::Backup(_)) =
            reconcile::agent_shard_role(issue, &self.config.agent_id)
        else {
            return Ok(false);
        };
        if claim.shard_role.rank() >= self_role.rank() {
            return Ok(false);
        }
        reconcile::is_heartbeat_stale(claim, now, self.issue_ttl(issue))
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
