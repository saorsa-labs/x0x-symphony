//! WP-B2: the v2 `Tracker` surface.
//!
//! [`V2Tracker`] maps `x0x_symphony_core::Tracker` — the exact trait the
//! orchestrator consumes — onto the tracker-integrity v2 model. Two
//! invariants govern every method (spec §2.6):
//!
//! - **every mutation is a signed chained event** appended to the local
//!   author's own append-only event store (the sole mutable companion is
//!   the existing `symphony2-hb-*` heartbeat store);
//! - **every read is fold output** — no blob reads, no cached state.
//!
//! The `TaskList` mirror (spec §2.7) is a non-authoritative display
//! projection: created on open, checkbox reconciled by the fold-winning
//! claimant only, and any disagreement always resolves toward fold state.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
use tracing::{debug, error, warn};

use x0x_symphony_core::{
    content_hash, sha256_hex, AgentId, ApprovalConsumed, ApprovalEvent, ApprovalState,
    ApprovalVerdict, Claim, Handoff, Issue, IssueDraft, IssueId, IssueState, PollContext,
    ReleaseReason, ReleaseReasonCode, ShardRole, SignatureProvenance, SymphonyError, Tracker,
    ValidationResult, VerificationNotice, VerificationNoticeKind,
};

use super::events::{
    ApprovalEventV2, ApprovalPayloadV2, ApprovalVerdictV2, BlockReason, ConsumeEventV2,
    HandoffEventV2, HandoffValidationV2, RequeueJustification, TransitionEventV2, TransitionKind,
    V2ListRef, V2_SCHEMA,
};
use super::fold::{fold_v2, FoldOutput, IssueStateV2, IssueStatusV2};
use super::store::{OwnEventStore, V2StoreError, V2StoreManager};
use crate::client::{AddTaskDraft, TaskAction, X0xdApi};

/// Timestamp used when no heartbeat data exists for a projection — folded
/// state never depends on clocks, so projection times are display metadata
/// only (spec §2.6).
const EPOCH_RFC3339: &str = "1970-01-01T00:00:00Z";

/// Marker prefix embedded in display-task descriptions so the display item
/// for an issue can be found again (spec §2.7 — display only, never
/// authoritative).
const DISPLAY_MARKER: &str = "[x0x-symphony-v2 issue ";

fn terr(msg: impl Into<String>) -> SymphonyError {
    SymphonyError::Tracker(msg.into())
}

fn store_err(e: &V2StoreError) -> SymphonyError {
    SymphonyError::Tracker(format!("v2 store: {e}"))
}

fn now_utc() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn now_secs() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or(0)
}

/// The v2 tracker engine. Constructed directly in tests/harnesses, or
/// internally by `X0xCrdtTracker` when the configured list id addresses the
/// `symphony2:` namespace.
pub struct V2Tracker {
    manager: V2StoreManager,
    /// v1 `TaskList` surface used ONLY for the display projection (§2.7).
    display: Option<Arc<dyn X0xdApi>>,
    list_ref: V2ListRef,
    agent_id: AgentId,
    own: tokio::sync::OnceCell<OwnEventStore>,
    display_list: tokio::sync::OnceCell<String>,
    joined: tokio::sync::Mutex<BTreeSet<String>>,
    /// Settle delay before the confirming re-read in `store_consumed`
    /// (an optimization narrowing the live-partition window, NOT a safety
    /// bound — spec §2.5).
    settle: Duration,
}

impl std::fmt::Debug for V2Tracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V2Tracker")
            .field("list_ref", &self.list_ref.to_ref_string())
            .field("agent_id", &self.agent_id)
            .field("has_display", &self.display.is_some())
            .field("settle", &self.settle)
            .finish_non_exhaustive()
    }
}

impl V2Tracker {
    /// Construct a v2 tracker engine.
    #[must_use]
    pub fn new(
        manager: V2StoreManager,
        list_ref: V2ListRef,
        agent_id: AgentId,
        display: Option<Arc<dyn X0xdApi>>,
        settle: Duration,
    ) -> Self {
        Self {
            manager,
            display,
            list_ref,
            agent_id,
            own: tokio::sync::OnceCell::new(),
            display_list: tokio::sync::OnceCell::new(),
            joined: tokio::sync::Mutex::new(BTreeSet::new()),
            settle,
        }
    }

    /// The v2 list reference this tracker serves.
    #[must_use]
    pub const fn list_ref(&self) -> &V2ListRef {
        &self.list_ref
    }

    async fn own(&self) -> x0x_symphony_core::Result<&OwnEventStore> {
        self.own
            .get_or_try_init(|| async {
                let own = self
                    .manager
                    .ensure_own_store(&self.list_ref.list_uuid)
                    .await
                    .map_err(|e| store_err(&e))?;
                if own.agent_id != self.agent_id.as_str() {
                    return Err(terr(format!(
                        "x0xd signs as agent {} but this tracker is configured for {}",
                        own.agent_id, self.agent_id
                    )));
                }
                Ok(own)
            })
            .await
    }

    /// Bootstrap the list surfaces (spec §2.6): bind the local author store
    /// (WP-X policy gate applies), self-publish genesis when we are the
    /// creator and none exists, join roster peer stores, and ensure the
    /// display `TaskList`.
    ///
    /// # Errors
    ///
    /// Returns tracker errors for store-policy violations and, when the
    /// local agent is the creator, genesis publication failures. A missing
    /// peer genesis (creator elsewhere, not yet replicated) is NOT an error
    /// here — folds refuse the list until it arrives.
    pub async fn ensure_surfaces(&self) -> x0x_symphony_core::Result<()> {
        let own = self.own().await?;
        if self.list_ref.creator == own.agent_id {
            // Creator: publish a self-roster genesis when none exists yet.
            let input = self
                .manager
                .read_fold_input(&self.list_ref.list_uuid, &self.list_ref.creator)
                .await
                .map_err(|e| store_err(&e))?;
            if fold_v2(&input).is_err() {
                self.manager
                    .publish_genesis(own, vec![own.agent_id.clone()], None, now_secs())
                    .await
                    .map_err(|e| store_err(&e))?;
            }
        } else {
            // Member: join the creator's store so the genesis can replicate.
            if let Err(e) = self
                .manager
                .join_peer_store(&self.list_ref.list_uuid, &self.list_ref.creator)
                .await
            {
                warn!(error = %e, "v2 creator store join failed; list stays refused until it succeeds");
            }
        }
        // Fold once (tolerating refusal) to join any visible roster peers.
        match self.fold_view().await {
            Ok(_) => {}
            Err(e) => debug!(error = %e, "v2 list not foldable yet during ensure_surfaces"),
        }
        self.ensure_display_list().await;
        Ok(())
    }

    /// Read + fold the list, joining roster members' stores to a FIXPOINT:
    /// roster UPDATES can admit members whose stores this reader has never
    /// joined, so after each fold the current roster is diffed against the
    /// joined set, new members are joined (event + heartbeat stores), and
    /// the list is re-read + re-folded until no new member appears. The
    /// loop is bounded — each pass must join at least one new member to
    /// continue, and rosters are small; the cap is surfaced loudly.
    async fn fold_view(&self) -> x0x_symphony_core::Result<FoldOutput> {
        const MAX_JOIN_PASSES: usize = 8;
        let mut out = self.read_and_fold().await?;
        for _pass in 0..MAX_JOIN_PASSES {
            if !self.join_new_members(&out).await? {
                return Ok(out);
            }
            out = self.read_and_fold().await?;
        }
        // A view that converged exactly on the final allowed pass is
        // complete — serve it. Only a STILL-growing roster is refused.
        if !self.join_new_members(&out).await? {
            return Ok(out);
        }
        // Fail-closed: a view that never reached the join fixpoint is
        // PARTIAL and must not be served as truth.
        Err(terr(format!(
            "v2 roster join fixpoint not reached in {MAX_JOIN_PASSES} passes \
             for {}; refusing the partial view",
            self.list_ref.to_ref_string()
        )))
    }

    async fn read_and_fold(&self) -> x0x_symphony_core::Result<FoldOutput> {
        let input = self
            .manager
            .read_fold_input(&self.list_ref.list_uuid, &self.list_ref.creator)
            .await
            .map_err(|e| store_err(&e))?;
        let out = fold_v2(&input).map_err(|refusal| terr(format!("v2 list refused: {refusal}")))?;
        // Fork evidence is self-authenticating proof of equivocation —
        // surfaced loudly on every fold, never swallowed.
        for fork in &out.forks {
            error!(
                list = %self.list_ref.to_ref_string(),
                author = %fork.author,
                author_seq = fork.author_seq,
                event_hashes = ?fork.event_hashes,
                "v2 fold surfaced author equivocation (fork evidence); the \
                 forked suffix is inadmissible"
            );
        }
        Ok(out)
    }

    /// Join stores of roster members (genesis ∪ current epoch) not yet
    /// joined. Returns true when at least one NEW member store was joined
    /// (⇒ the caller should re-read and re-fold).
    /// Error classification (spec §2.6): a member store the daemon has NO
    /// listing for is ABSENT (normal replication lag — skipped with a
    /// per-member notice, retried next fold); a listing that is PRESENT
    /// but reports the wrong owner or policy is an integrity violation and
    /// FAILS the whole view (fail-closed).
    async fn join_new_members(&self, out: &FoldOutput) -> x0x_symphony_core::Result<bool> {
        let own_id = self.agent_id.as_str();
        let mut joined = self.joined.lock().await;
        let mut joined_any = false;
        let members = out.genesis.roster.iter().chain(out.current_roster.iter());
        for member in members {
            if member == own_id || joined.contains(member) {
                continue;
            }
            match self
                .manager
                .join_peer_store(&self.list_ref.list_uuid, member)
                .await
            {
                Ok(_) => {
                    joined.insert(member.clone());
                    joined_any = true;
                }
                Err(
                    e @ (V2StoreError::AnchorMismatch { .. }
                    | V2StoreError::PolicyNotHonored { .. }),
                ) => {
                    // Listing present but WRONG: integrity violation.
                    return Err(terr(format!(
                        "v2 member {member} store failed anchor verification: {e}"
                    )));
                }
                Err(e) => {
                    // Absent / transport lag: per-member notice, retried on
                    // the next fold.
                    debug!(member = %member, error = %e, "v2 peer event store not joinable yet");
                    continue;
                }
            }
            if let Err(e) = self
                .manager
                .join_peer_heartbeats(&self.list_ref.list_uuid, member)
                .await
            {
                // Heartbeat companions are excluded from the anchor
                // guarantee (non-authoritative, never fold inputs).
                debug!(member = %member, error = %e, "v2 peer heartbeat-store join failed");
            }
        }
        Ok(joined_any)
    }

    /// Project one folded issue into the v1 `Issue` surface (spec §2.6).
    async fn project_issue(
        &self,
        out: &FoldOutput,
        st: &IssueStateV2,
    ) -> x0x_symphony_core::Result<Issue> {
        let handoffs = out.handoffs.get(&st.issue_id);
        let state = match &st.status {
            IssueStatusV2::Open => IssueState::new("todo")?,
            IssueStatusV2::Claimed { .. } => IssueState::new("in_progress")?,
            IssueStatusV2::Blocked { .. } => IssueState::new("blocked")?,
            IssueStatusV2::Done { .. } => {
                if handoffs.is_some_and(|h| !h.is_empty()) {
                    IssueState::new("review")?
                } else {
                    IssueState::new("done")?
                }
            }
        };
        let mut issue = Issue::new(
            IssueId::new(st.issue_id.clone())?,
            st.issue_id.clone(),
            st.title.clone(),
            state,
            EPOCH_RFC3339,
        )?;
        issue.description.clone_from(&st.spec);
        // The fold admitted the Open event only after full ML-DSA
        // verification — provenance is real, not asserted.
        issue.signature_provenance = Some(SignatureProvenance::verified(st.opened_by.clone()));
        // Fork evidence involving this issue's opener or current claimant
        // is attached as a read-path notice (spec: forks are diagnostics,
        // never silent).
        let involved: Vec<&str> = match &st.status {
            IssueStatusV2::Claimed { claimant, .. } | IssueStatusV2::Blocked { claimant, .. } => {
                vec![st.opened_by.as_str(), claimant.as_str()]
            }
            _ => vec![st.opened_by.as_str()],
        };
        for fork in &out.forks {
            if involved.contains(&fork.author.as_str()) {
                issue.verification_notices.push(VerificationNotice {
                    kind: VerificationNoticeKind::ForkEvidence,
                    claimant: AgentId::new(fork.author.clone()).ok(),
                    reason: format!(
                        "author {} equivocated at chain seq {} ({} conflicting signed events); \
                         the forked suffix is inadmissible",
                        fork.author,
                        fork.author_seq,
                        fork.event_hashes.len()
                    ),
                });
            }
        }
        if let IssueStatusV2::Claimed { claimant, .. } = &st.status {
            let heartbeat = self
                .manager
                .read_heartbeat(&self.list_ref.list_uuid, claimant, &st.issue_id)
                .await
                .unwrap_or_else(|| EPOCH_RFC3339.to_owned());
            let mut claim = Claim::new(
                Some(issue.id.clone()),
                AgentId::new(claimant.clone())?,
                heartbeat.clone(),
                ShardRole::ManualM1,
            );
            claim = claim.with_heartbeat(heartbeat.clone());
            issue.updated_at = heartbeat;
            issue.claim = Some(claim);
        }
        if let Some(records) = handoffs {
            if let Some(last) = records.last() {
                issue.handoff = Some(project_handoff(&issue.id, &last.handoff));
            }
        }
        Ok(issue)
    }

    async fn project_all(&self, out: &FoldOutput) -> x0x_symphony_core::Result<Vec<Issue>> {
        let mut issues = Vec::with_capacity(out.issues.len());
        for st in out.issues.values() {
            issues.push(self.project_issue(out, st).await?);
        }
        Ok(issues)
    }

    fn require_local_agent(&self, agent: &AgentId, what: &str) -> x0x_symphony_core::Result<()> {
        if agent == &self.agent_id {
            Ok(())
        } else {
            Err(terr(format!(
                "v2 {what} must be authored by the local agent {} (got {agent}); \
                 v2 records are author-signed and live in the author's own store",
                self.agent_id
            )))
        }
    }

    /// The fold-winning claim fence for `issue_id`, required to be held by
    /// the LOCAL agent. Returns `(claim_nonce, claim_event_hash)`.
    fn require_own_fence(
        &self,
        out: &FoldOutput,
        issue_id: &str,
    ) -> x0x_symphony_core::Result<(String, String)> {
        let issue = out.issues.get(issue_id).ok_or_else(|| {
            terr(format!(
                "issue {issue_id} does not exist in the folded list"
            ))
        })?;
        match &issue.status {
            IssueStatusV2::Claimed {
                claimant,
                claim_nonce,
                claim_event_hash,
            } if claimant == self.agent_id.as_str() => {
                Ok((claim_nonce.clone(), claim_event_hash.clone()))
            }
            other => Err(terr(format!(
                "local agent does not hold the fold-winning claim on {issue_id} (status: {other:?})"
            ))),
        }
    }

    fn transition(
        &self,
        out: &FoldOutput,
        issue_id: &str,
        kind: TransitionKind,
    ) -> TransitionEventV2 {
        let (author_seq, prev_own_event_hash) = out.next_chain_link(self.agent_id.as_str());
        TransitionEventV2 {
            schema: V2_SCHEMA,
            list_uuid: self.list_ref.list_uuid.clone(),
            genesis_manifest_hash: out.genesis_hash.clone(),
            roster_epoch: out.latest_roster_epoch,
            issue_id: issue_id.to_owned(),
            actor: self.agent_id.to_string(),
            lamport: out.max_admitted_lamport.saturating_add(1),
            author_seq,
            prev_own_event_hash,
            kind,
        }
    }

    // ---- Display projection (spec §2.7): best effort, never authoritative

    async fn ensure_display_list(&self) -> Option<&str> {
        let display = self.display.as_ref()?;
        let topic = format!("symphony2-display-{}", self.list_ref.list_uuid);
        let id = self
            .display_list
            .get_or_try_init(|| async {
                match display.create_task_list(&topic, &topic).await {
                    Ok(id) => Ok::<String, ()>(id),
                    Err(create_err) => {
                        // Likely already exists — find it by topic.
                        match display.list_task_lists().await {
                            Ok(lists) => lists
                                .into_iter()
                                .find(|l| l.topic == topic)
                                .map(|l| l.id)
                                .ok_or_else(|| {
                                    warn!(error = %create_err, "v2 display TaskList unavailable");
                                }),
                            Err(list_err) => {
                                warn!(error = %list_err, "v2 display TaskList listing failed");
                                Err(())
                            }
                        }
                    }
                }
            })
            .await;
        match id {
            Ok(id) => Some(id.as_str()),
            Err(()) => None,
        }
    }

    async fn display_add_issue(&self, issue_id: &str, title: &str, spec: &str) {
        let Some(display) = self.display.clone() else {
            return;
        };
        let Some(list) = self.ensure_display_list().await else {
            return;
        };
        let draft = AddTaskDraft::new(title)
            .with_description(format!("{DISPLAY_MARKER}{issue_id}]\n\n{spec}"));
        if let Err(e) = display.add_task(list, draft).await {
            warn!(issue = %issue_id, error = %e, "v2 display task creation failed (display only)");
        }
    }

    /// Reconcile the display checkbox — invoked only after the underlying
    /// chained event is durable AND we are the fold-winning claimant.
    async fn display_reconcile(&self, issue_id: &str, action: TaskAction) {
        let Some(display) = self.display.clone() else {
            return;
        };
        let Some(list) = self.ensure_display_list().await else {
            return;
        };
        let marker = format!("{DISPLAY_MARKER}{issue_id}]");
        let task_id = match display.list_tasks(list).await {
            Ok(tasks) => tasks
                .into_iter()
                .find(|t| t.description.starts_with(&marker))
                .map(|t| t.id),
            Err(e) => {
                warn!(issue = %issue_id, error = %e, "v2 display task lookup failed (display only)");
                None
            }
        };
        let Some(task_id) = task_id else { return };
        if let Err(e) = display.update_task(list, &task_id, action).await {
            warn!(issue = %issue_id, error = %e, "v2 display checkbox update failed (display only)");
        }
    }
}

/// Rebuild a v1 `Handoff` from a recorded v2 handoff event.
fn project_handoff(issue_id: &IssueId, ev: &HandoffEventV2) -> Handoff {
    let mut handoff = Handoff::new(ev.summary.clone())
        .with_files_changed(ev.files_changed.clone())
        .with_follow_ups(ev.follow_up.clone())
        .with_issue_id(issue_id.clone())
        .with_signer_agent_id(ev.actor.clone());
    if let Some(proofs_dir) = &ev.proofs_dir {
        handoff = handoff.with_proofs_dir(proofs_dir.clone());
    }
    for v in &ev.validation {
        match validation_from_v2(v) {
            Ok(result) => handoff = handoff.with_validation(result),
            Err(e) => {
                warn!(
                    error = %e,
                    "v2 handoff validation entry did not project; dropped from display"
                );
            }
        }
    }
    handoff
}

fn validation_from_v2(v: &HandoffValidationV2) -> Result<ValidationResult, String> {
    // ValidationStatus is a snake_case serde enum; round-trip through JSON
    // so this projection cannot drift from core's spelling.
    let status = serde_json::from_value(serde_json::Value::String(v.status.clone()))
        .map_err(|e| format!("unknown validation status {}: {e}", v.status))?;
    Ok(ValidationResult {
        command: v.command.clone(),
        status,
        exit_code: v.exit_code,
    })
}

fn validation_to_v2(v: &ValidationResult) -> HandoffValidationV2 {
    let status = match serde_json::to_value(&v.status) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "failed".to_owned(),
    };
    HandoffValidationV2 {
        command: v.command.clone(),
        status,
        exit_code: v.exit_code,
    }
}

#[async_trait]
impl Tracker for V2Tracker {
    async fn list_issues(&self) -> x0x_symphony_core::Result<Vec<Issue>> {
        let out = self.fold_view().await?;
        self.project_all(&out).await
    }

    async fn create_issue(&self, draft: IssueDraft) -> x0x_symphony_core::Result<Issue> {
        let own = self.own().await?;
        let out = self.fold_view().await?;
        // Fresh, collision-resistant issue id (no uuid dependency needed).
        let issue_id = format!(
            "i{}",
            &sha256_hex(
                format!(
                    "{}:{}:{}:{}",
                    own.agent_id,
                    now_utc(),
                    draft.title,
                    out.max_admitted_lamport
                )
                .as_bytes()
            )[..32]
        );
        let description = draft
            .description
            .as_deref()
            .filter(|d| !d.trim().is_empty())
            .unwrap_or("")
            .to_owned();
        if draft.priority.is_some() || !draft.labels.is_empty() {
            debug!(issue = %issue_id, "v2 issues do not persist priority/labels; dropped");
        }
        let event = self.transition(
            &out,
            &issue_id,
            TransitionKind::open(draft.title.clone(), description.clone()),
        );
        self.manager
            .append_transition(own, &event)
            .await
            .map_err(|e| store_err(&e))?;
        self.display_add_issue(&issue_id, &draft.title, &description)
            .await;
        let confirm = self.fold_view().await?;
        let st = confirm
            .issues
            .get(&issue_id)
            .ok_or_else(|| terr(format!("created issue {issue_id} did not fold back")))?;
        self.project_issue(&confirm, st).await
    }

    async fn fetch_candidates(&self, ctx: &PollContext) -> x0x_symphony_core::Result<Vec<Issue>> {
        let issues = self.list_issues().await?;
        let mut candidates: Vec<Issue> = issues
            .into_iter()
            .filter(|issue| ctx.active_states.iter().any(|state| state == &issue.state))
            .collect();
        // v2 issues carry no blockers and no priority; order by id for
        // determinism (v1 parity: priority-then-id with priority absent).
        candidates.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(candidates)
    }

    async fn fetch_by_ids(&self, ids: &[IssueId]) -> x0x_symphony_core::Result<Vec<Issue>> {
        let requested: BTreeSet<&IssueId> = ids.iter().collect();
        let issues = self.list_issues().await?;
        Ok(issues
            .into_iter()
            .filter(|issue| requested.contains(&issue.id))
            .collect())
    }

    async fn claim(&self, id: &IssueId, agent_id: &AgentId) -> x0x_symphony_core::Result<Claim> {
        self.require_local_agent(agent_id, "claim")?;
        let own = self.own().await?;
        let out = self.fold_view().await?;
        let issue = out
            .issues
            .get(id.as_str())
            .ok_or_else(|| terr(format!("issue {id} does not exist in the folded list")))?;
        if issue.status != IssueStatusV2::Open {
            return Err(terr(format!(
                "issue {id} is not claimable (status: {:?})",
                issue.status
            )));
        }
        let event = super::gate::build_claim_transition(
            &out,
            &self.list_ref.list_uuid,
            self.agent_id.as_str(),
            id.as_str(),
        );
        let our_hash = self
            .manager
            .append_transition(own, &event)
            .await
            .map_err(|e| store_err(&e))?;
        // Confirming re-fold: the fold, not the append, decides the winner.
        let confirm = self.fold_view().await?;
        let confirmed = confirm
            .issues
            .get(id.as_str())
            .ok_or_else(|| terr(format!("issue {id} vanished from the folded list")))?;
        match &confirmed.status {
            IssueStatusV2::Claimed {
                claimant,
                claim_event_hash,
                ..
            } if claimant == self.agent_id.as_str() && claim_event_hash == &our_hash => {}
            other => {
                return Err(terr(format!(
                    "claim on {id} lost the deterministic fold race (status now: {other:?})"
                )));
            }
        }
        // The fold-winning claim is already durable and confirmed above.
        // Heartbeats are non-authoritative liveness hints (spec §2.6) — a
        // failed initial heartbeat write must NOT un-win the claim.
        let at = now_utc();
        if let Err(e) = self.manager.put_heartbeat(own, id.as_str(), &at).await {
            warn!(
                issue = %id,
                error = %e,
                "initial heartbeat write failed after a confirmed claim; \
                 claim stands (heartbeats are non-authoritative)"
            );
        }
        self.display_reconcile(id.as_str(), TaskAction::Claim).await;
        Ok(Claim::new(
            Some(id.clone()),
            agent_id.clone(),
            at,
            ShardRole::ManualM1,
        ))
    }

    async fn heartbeat(&self, claim: &Claim) -> x0x_symphony_core::Result<()> {
        self.require_local_agent(&claim.by, "heartbeat")?;
        let issue_id = claim_issue_id(claim)?;
        let own = self.own().await?;
        let out = self.fold_view().await?;
        self.require_own_fence(&out, issue_id.as_str())?;
        self.manager
            .put_heartbeat(own, issue_id.as_str(), &now_utc())
            .await
            .map_err(|e| store_err(&e))
    }

    async fn release(&self, claim: &Claim, reason: ReleaseReason) -> x0x_symphony_core::Result<()> {
        self.require_local_agent(&claim.by, "release")?;
        let issue_id = claim_issue_id(claim)?;
        let own = self.own().await?;
        let out = self.fold_view().await?;
        let (claim_nonce, claimed_event_hash) = self.require_own_fence(&out, issue_id.as_str())?;
        // The v1 release reason is local diagnostics only — never a fold
        // input (spec §2.6).
        debug!(issue = %issue_id, code = %reason.code.as_str(), "v2 release");
        let event = self.transition(
            &out,
            issue_id.as_str(),
            TransitionKind::Release {
                claim_nonce,
                claimed_event_hash,
            },
        );
        self.manager
            .append_transition(own, &event)
            .await
            .map_err(|e| store_err(&e))?;
        Ok(())
    }

    async fn handoff(&self, claim: &Claim, handoff: Handoff) -> x0x_symphony_core::Result<()> {
        self.require_local_agent(&claim.by, "handoff")?;
        let issue_id = claim_issue_id(claim)?;
        let own = self.own().await?;
        let out = self.fold_view().await?;
        let (claim_nonce, claimed_event_hash) = self.require_own_fence(&out, issue_id.as_str())?;
        let (author_seq, prev_own_event_hash) = out.next_chain_link(self.agent_id.as_str());
        let handoff_event = HandoffEventV2 {
            schema: V2_SCHEMA,
            kind: "handoff".to_owned(),
            list_uuid: self.list_ref.list_uuid.clone(),
            genesis_manifest_hash: out.genesis_hash.clone(),
            roster_epoch: out.latest_roster_epoch,
            issue_id: issue_id.as_str().to_owned(),
            actor: self.agent_id.to_string(),
            lamport: out.max_admitted_lamport.saturating_add(1),
            author_seq,
            prev_own_event_hash,
            claim_nonce: claim_nonce.clone(),
            claimed_event_hash: claimed_event_hash.clone(),
            summary: handoff.summary.clone(),
            files_changed: handoff.files_changed.clone(),
            validation: handoff.validation.iter().map(validation_to_v2).collect(),
            follow_up: handoff.follow_up.clone(),
            proofs_dir: handoff.proofs_dir.clone(),
        };
        let handoff_hash = self
            .manager
            .append_handoff(own, &handoff_event)
            .await
            .map_err(|e| store_err(&e))?;
        // Complete is the NEXT chained event; a crash in between leaves a
        // fenced handoff on a still-claimed issue (spec §2.6).
        let complete = TransitionEventV2 {
            schema: V2_SCHEMA,
            list_uuid: self.list_ref.list_uuid.clone(),
            genesis_manifest_hash: out.genesis_hash.clone(),
            roster_epoch: out.latest_roster_epoch,
            issue_id: issue_id.as_str().to_owned(),
            actor: self.agent_id.to_string(),
            lamport: out.max_admitted_lamport.saturating_add(2),
            author_seq: author_seq.saturating_add(1),
            prev_own_event_hash: handoff_hash,
            kind: TransitionKind::Complete {
                claim_nonce,
                claimed_event_hash,
            },
        };
        self.manager
            .append_transition(own, &complete)
            .await
            .map_err(|e| store_err(&e))?;
        self.display_reconcile(issue_id.as_str(), TaskAction::Complete)
            .await;
        Ok(())
    }

    async fn fetch_claimed(
        &self,
        agent_id: Option<&AgentId>,
    ) -> x0x_symphony_core::Result<Vec<Issue>> {
        let issues = self.list_issues().await?;
        Ok(issues
            .into_iter()
            .filter(|issue| issue.claim.is_some())
            .filter(|issue| {
                agent_id.is_none_or(|agent| {
                    issue.claim.as_ref().is_some_and(|claim| &claim.by == agent)
                })
            })
            .collect())
    }

    async fn block(&self, claim: &Claim, reason: ReleaseReason) -> x0x_symphony_core::Result<()> {
        self.require_local_agent(&claim.by, "block")?;
        let issue_id = claim_issue_id(claim)?;
        let own = self.own().await?;
        let out = self.fold_view().await?;
        let (claim_nonce, claimed_event_hash) = self.require_own_fence(&out, issue_id.as_str())?;
        let block_reason = if reason.code == ReleaseReasonCode::AwaitingApproval {
            BlockReason::AwaitingApproval
        } else {
            BlockReason::Other {
                detail: format!("{}: {}", reason.code.as_str(), reason.message),
            }
        };
        let event = self.transition(
            &out,
            issue_id.as_str(),
            TransitionKind::Block {
                claim_nonce,
                claimed_event_hash,
                reason: block_reason,
            },
        );
        self.manager
            .append_transition(own, &event)
            .await
            .map_err(|e| store_err(&e))?;
        Ok(())
    }

    async fn requeue_blocked(
        &self,
        issue_id: &IssueId,
        reason: ReleaseReason,
    ) -> x0x_symphony_core::Result<()> {
        // v1 parity: the requeue capability exists solely to resume
        // approval-parked work.
        if reason.code != ReleaseReasonCode::AwaitingApproval {
            debug!(code = %reason.code.as_str(), "v2 requeue reason is diagnostics only");
        }
        let own = self.own().await?;
        let out = self.fold_view().await?;
        let issue = out.issues.get(issue_id.as_str()).ok_or_else(|| {
            terr(format!(
                "issue {issue_id} does not exist in the folded list"
            ))
        })?;
        let IssueStatusV2::Blocked {
            claim_nonce,
            block_event_hash,
            reason: block_reason,
            ..
        } = &issue.status
        else {
            return Err(terr(format!(
                "issue {issue_id} is not blocked (status: {:?})",
                issue.status
            )));
        };
        if *block_reason != BlockReason::AwaitingApproval {
            return Err(terr(format!(
                "issue {issue_id} is blocked with a non-awaiting_approval reason; \
                 refusing requeue (design r2 C6 — admin repair is a new issue)"
            )));
        }
        // The LOCAL agent is the approver: sign the C6 justification
        // approval binding the current block and parked nonce.
        let approval = ApprovalPayloadV2 {
            schema: V2_SCHEMA,
            kind: "approval".to_owned(),
            list_uuid: self.list_ref.list_uuid.clone(),
            genesis_manifest_hash: out.genesis_hash.clone(),
            issue_id: issue_id.as_str().to_owned(),
            block_event_hash: block_event_hash.clone(),
            claim_nonce: claim_nonce.clone(),
            approver: self.agent_id.to_string(),
            approved_at: now_secs(),
        };
        let approval_payload = serde_json::to_vec(&approval)
            .map_err(|e| terr(format!("requeue approval encode failed: {e}")))?;
        let approval_hash = sha256_hex(&approval_payload);
        let approval_envelope = self
            .manager
            .sign_approval_payload(own, &approval_payload)
            .await
            .map_err(|e| store_err(&e))?;
        let event = self.transition(
            &out,
            issue_id.as_str(),
            TransitionKind::Requeue {
                justification: RequeueJustification {
                    block_event_hash: block_event_hash.clone(),
                    claim_nonce: claim_nonce.clone(),
                    approval_event_hash: approval_hash.clone(),
                    approval_payload_sha256: approval_hash,
                    approver: self.agent_id.to_string(),
                    approval: approval_envelope,
                },
            },
        );
        self.manager
            .append_transition(own, &event)
            .await
            .map_err(|e| store_err(&e))?;
        Ok(())
    }

    async fn load_approval_state(
        &self,
        issue_id: &IssueId,
    ) -> x0x_symphony_core::Result<ApprovalState> {
        let out = self.fold_view().await?;
        let mut state = ApprovalState::default();
        for admitted in out.approvals.values() {
            if admitted.approval.issue_id != issue_id.as_str() {
                continue;
            }
            if admitted.approval.v1_record_json.is_empty() {
                // Spec §2.6: carrier-less records project to nothing on the
                // v1 surface; the fold remains the authority.
                debug!(issue = %issue_id, "v2 approval without v1 carrier skipped in projection");
                continue;
            }
            match serde_json::from_str::<ApprovalEvent>(&admitted.approval.v1_record_json) {
                Ok(event) => state.events.push(event),
                Err(e) => warn!(issue = %issue_id, error = %e, "v2 approval carrier did not parse"),
            }
        }
        for consume in out.effective_consumes.values() {
            if consume.consume.issue_id != issue_id.as_str() {
                continue;
            }
            if consume.consume.v1_record_json.is_empty() {
                continue;
            }
            match serde_json::from_str::<ApprovalConsumed>(&consume.consume.v1_record_json) {
                Ok(record) => state.consumed.push(record),
                Err(e) => warn!(issue = %issue_id, error = %e, "v2 consume carrier did not parse"),
            }
        }
        Ok(state)
    }

    async fn store_approval(&self, event: &ApprovalEvent) -> x0x_symphony_core::Result<()> {
        self.require_local_agent(&event.approver_agent_id, "approval")?;
        let own = self.own().await?;
        let out = self.fold_view().await?;
        let st = out.issues.get(event.issue_id.as_str()).ok_or_else(|| {
            terr(format!(
                "issue {} does not exist in the folded list",
                event.issue_id
            ))
        })?;
        // Cross-check the v1 content binding against the projection of the
        // exact content the v2 open event carries.
        let projected = self.project_issue(&out, st).await?;
        if content_hash(&projected) != event.content_hash {
            return Err(terr(format!(
                "approval content hash {} does not match the issue's current content; \
                 refusing to bind a stale approval",
                event.content_hash
            )));
        }
        let approved_at = chrono::DateTime::parse_from_rfc3339(&event.approved_at)
            .map(|t| u64::try_from(t.timestamp()).unwrap_or(0))
            .map_err(|e| terr(format!("approval approved_at did not parse: {e}")))?;
        let verdict = match event.verdict {
            ApprovalVerdict::Approve => ApprovalVerdictV2::Approve,
            ApprovalVerdict::Deny => ApprovalVerdictV2::Deny,
        };
        let v1_record_json = serde_json::to_string(event)
            .map_err(|e| terr(format!("v1 approval carrier encode failed: {e}")))?;
        let (author_seq, prev_own_event_hash) = out.next_chain_link(self.agent_id.as_str());
        let approval = ApprovalEventV2 {
            schema: V2_SCHEMA,
            kind: "dispatch_approval".to_owned(),
            list_uuid: self.list_ref.list_uuid.clone(),
            genesis_manifest_hash: out.genesis_hash.clone(),
            roster_epoch: out.latest_roster_epoch,
            issue_id: event.issue_id.as_str().to_owned(),
            open_event_hash: st.open_event_hash.clone(),
            actor: self.agent_id.to_string(),
            lamport: out.max_admitted_lamport.saturating_add(1),
            author_seq,
            prev_own_event_hash,
            verdict,
            entropy: sha256_hex(
                format!(
                    "{}:{author_seq}:{}:{approved_at}:approval-bridge",
                    self.agent_id, event.issue_id
                )
                .as_bytes(),
            ),
            approved_at,
            v1_record_json,
        };
        self.manager
            .append_approval(own, &approval)
            .await
            .map_err(|e| store_err(&e))?;
        Ok(())
    }

    async fn store_consumed(&self, event: &ApprovalConsumed) -> x0x_symphony_core::Result<()> {
        let own = self.own().await?;
        let out = self.fold_view().await?;
        let st = out.issues.get(event.issue_id.as_str()).ok_or_else(|| {
            terr(format!(
                "issue {} does not exist in the folded list",
                event.issue_id
            ))
        })?;
        let (claim_nonce, claimed_event_hash) =
            self.require_own_fence(&out, event.issue_id.as_str())?;
        let projected = self.project_issue(&out, st).await?;
        if content_hash(&projected) != event.content_hash {
            return Err(terr(
                "consumption content hash does not match the issue's current content".to_owned(),
            ));
        }
        // First unconsumed approve-verdict approval in fold order — the
        // deterministic candidate the WP-B gate would take.
        let candidate = out
            .unconsumed_approvals(event.issue_id.as_str())
            .into_iter()
            .next()
            .ok_or_else(|| {
                terr(format!(
                    "no unconsumed approval exists for issue {}; refusing consumption",
                    event.issue_id
                ))
            })?;
        let approval_event_hash = candidate.event_hash.clone();
        let approver = candidate.approval.actor.clone();
        let v1_record_json = serde_json::to_string(event)
            .map_err(|e| terr(format!("v1 consumed carrier encode failed: {e}")))?;
        let (author_seq, prev_own_event_hash) = out.next_chain_link(self.agent_id.as_str());
        let consume = ConsumeEventV2 {
            schema: V2_SCHEMA,
            kind: "consume".to_owned(),
            list_uuid: self.list_ref.list_uuid.clone(),
            genesis_manifest_hash: out.genesis_hash.clone(),
            roster_epoch: out.latest_roster_epoch,
            issue_id: event.issue_id.as_str().to_owned(),
            actor: self.agent_id.to_string(),
            lamport: out.max_admitted_lamport.saturating_add(1),
            author_seq,
            prev_own_event_hash,
            approval_event_hash: approval_event_hash.clone(),
            approval_payload_sha256: approval_event_hash.clone(),
            approver,
            claim_nonce,
            claimed_event_hash,
            entropy: sha256_hex(
                format!(
                    "{}:{author_seq}:{}:consume-bridge",
                    self.agent_id, event.nonce
                )
                .as_bytes(),
            ),
            v1_record_json,
        };
        let our_hash = self
            .manager
            .append_consume(own, &consume)
            .await
            .map_err(|e| store_err(&e))?;
        // Consume-then-confirm (spec §2.6): the settle re-read narrows the
        // live-partition window; the deterministic fold winner is the
        // safety property. A lost race is an ERROR — the orchestrator must
        // not dispatch.
        if !self.settle.is_zero() {
            tokio::time::sleep(self.settle).await;
        }
        let confirm = self.fold_view().await?;
        match confirm.effective_consumes.get(&approval_event_hash) {
            Some(winner) if winner.event_hash == our_hash => Ok(()),
            Some(winner) => Err(terr(format!(
                "approval {approval_event_hash} was consumed by a competing fold-ordered \
                 consume from {}; refusing dispatch (zero local executions)",
                winner.consume.actor
            ))),
            None => {
                let reason = confirm
                    .losing_consumes
                    .iter()
                    .find(|d| d.event_hash == our_hash)
                    .map_or_else(
                        || "consume did not take effect".to_owned(),
                        |d| d.reason.clone(),
                    );
                Err(terr(format!(
                    "consumption of approval {approval_event_hash} was not effective: {reason}"
                )))
            }
        }
    }
}

fn claim_issue_id(claim: &Claim) -> x0x_symphony_core::Result<IssueId> {
    claim
        .issue_id
        .clone()
        .ok_or_else(|| terr("claim is missing issue_id".to_owned()))
}
