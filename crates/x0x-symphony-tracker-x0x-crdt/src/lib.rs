//! x0xd `TaskList` CRDT Tracker adapter for x0x-symphony.
//!
//! This crate implements [`x0x_symphony_core::Tracker`] against x0xd's REST API
//! without linking the x0x Rust crates. ADR-0004 chooses x0x `TaskList` CRDTs as
//! the permanent Symphony backbone: the public `TaskEntry` fields carry the small
//! issue surface (`id`, title, description, checkbox state, assignee, priority)
//! and Symphony-specific metadata that x0xd cannot patch directly is stored in
//! the paired `KvStore` `symphony-<list-id>`.
//!
//! Mapping summary:
//!
//! - Task id, title, description, and priority map directly to [`Issue`].
//! - x0xd checkbox states map to `todo` (`empty`), `in_progress`
//!   (`claimed:<agent>`), and `done` (`done:<agent>`).
//! - Active claim metadata lives at `claim-<task-id>` in the `KvStore`. Claiming
//!   calls `PATCH /task-lists/:id/tasks/:tid` with `action: "claim"`, then
//!   writes the signed/unsigned claim blob.
//! - Heartbeats update only the claim blob's `heartbeat_at`; x0xd has no
//!   heartbeat PATCH action.
//! - Handoffs live at `handoff-<task-id>`, after which the adapter calls
//!   `PATCH ... {"action":"complete"}`. A completed task with a handoff blob
//!   is exposed as Symphony state `review`, not human-closed `done`.
//! - Release and block transitions update the claim blob because x0xd exposes
//!   no unclaim or general metadata PATCH endpoint.
//!
//! The crate intentionally is not wired into the daemon binary yet; XSY-0024
//! switches the active tracker after this adapter is reviewed.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod client;
pub mod mapping;

use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{SecondsFormat, Utc};
use thiserror::Error;
use tracing::warn;
use x0x_symphony_core::{
    sha256_hex, AgentId, Claim, Handoff, Issue, IssueId, IssueState, PollContext, ReleaseReason,
    ShardRole, SignatureEnvelope, SymphonyError, Tracker, CLAIM_CONTEXT, HANDOFF_CONTEXT,
    SIGN_ALGORITHM,
};
use x0x_symphony_tracker_git_jsonl::signing::{
    SignResponse, SigningClient, SigningPolicy, TrustedKeyResolver, VerifyOutcome,
};

use crate::{
    client::{TaskAction, X0xdApi, X0xdClient},
    mapping::{
        claim_key, decode_claim_blob, decode_handoff_blob, encode_claim_blob, encode_handoff_blob,
        handoff_key, issue_from_task, store_id_for_list, ClaimBlob, ClaimBlobStatus, HandoffBlob,
        SYMPHONY_JSON_CONTENT_TYPE,
    },
};

/// Result alias used by the x0x CRDT tracker adapter.
pub type Result<T> = std::result::Result<T, TrackerError>;

/// Structured errors produced by the x0x CRDT tracker adapter.
#[derive(Debug, Error)]
pub enum TrackerError {
    /// x0xd client operation failed.
    #[error(transparent)]
    Client(#[from] client::ClientError),

    /// `TaskEntry`/`KvStore` mapping failed.
    #[error(transparent)]
    Mapping(#[from] mapping::MappingError),

    /// Core domain validation failed.
    #[error(transparent)]
    Core(#[from] SymphonyError),

    /// The issue identifier was not present in the `TaskList`.
    #[error("issue {id} not found")]
    IssueNotFound {
        /// Missing issue identifier.
        id: IssueId,
    },

    /// The requested issue cannot be claimed in its current state.
    #[error("issue {id} is not claimable: {reason}")]
    ClaimRejected {
        /// Issue that rejected the claim.
        id: IssueId,
        /// Human-readable rejection reason.
        reason: String,
    },

    /// The claim supplied to a transition is incomplete or stale.
    #[error("invalid claim: {reason}")]
    InvalidClaim {
        /// Human-readable claim validation failure.
        reason: String,
    },

    /// Signing or verification failed.
    #[error("signing error: {0}")]
    Signing(String),
}

impl From<TrackerError> for SymphonyError {
    fn from(error: TrackerError) -> Self {
        match error {
            TrackerError::Core(source) => source,
            other => Self::Tracker(other.to_string()),
        }
    }
}

#[derive(Clone)]
struct SigningRuntime {
    policy: SigningPolicy,
    client: Option<Arc<dyn SigningClient>>,
    resolver: Option<Arc<dyn TrustedKeyResolver>>,
}

impl SigningRuntime {
    const fn disabled() -> Self {
        Self {
            policy: SigningPolicy::Disabled,
            client: None,
            resolver: None,
        }
    }

    fn required(client: Arc<dyn SigningClient>, resolver: Arc<dyn TrustedKeyResolver>) -> Self {
        Self {
            policy: SigningPolicy::Required,
            client: Some(client),
            resolver: Some(resolver),
        }
    }

    fn new(
        policy: SigningPolicy,
        client: Option<Arc<dyn SigningClient>>,
        resolver: Option<Arc<dyn TrustedKeyResolver>>,
    ) -> Self {
        Self {
            policy,
            client,
            resolver,
        }
    }

    fn client(&self) -> Result<&dyn SigningClient> {
        self.client
            .as_deref()
            .ok_or_else(|| TrackerError::Signing("signing client is not configured".to_owned()))
    }

    fn resolver(&self) -> Result<&dyn TrustedKeyResolver> {
        self.resolver.as_deref().ok_or_else(|| {
            TrackerError::Signing("trusted key resolver is not configured".to_owned())
        })
    }
}

/// Builder for [`X0xCrdtTracker`].
#[derive(Clone)]
pub struct X0xCrdtTrackerBuilder {
    base_url: String,
    list_id: String,
    agent_id: AgentId,
    client: Option<Arc<dyn X0xdApi>>,
    signing: SigningRuntime,
}

impl X0xCrdtTrackerBuilder {
    /// Create a builder for one x0xd `TaskList` and local agent identity.
    #[must_use]
    pub fn new(base_url: impl Into<String>, list_id: impl Into<String>, agent_id: AgentId) -> Self {
        Self {
            base_url: base_url.into(),
            list_id: list_id.into(),
            agent_id,
            client: None,
            signing: SigningRuntime::disabled(),
        }
    }

    /// Inject a custom API implementation, usually a test mock.
    #[must_use]
    pub fn client(mut self, client: Arc<dyn X0xdApi>) -> Self {
        self.client = Some(client);
        self
    }

    /// Enable required signing with injected client and trusted-key resolver.
    #[must_use]
    pub fn required_signing(
        mut self,
        client: Arc<dyn SigningClient>,
        resolver: Arc<dyn TrustedKeyResolver>,
    ) -> Self {
        self.signing = SigningRuntime::required(client, resolver);
        self
    }

    /// Set an explicit signing policy and optional signing dependencies.
    #[must_use]
    pub fn signing(
        mut self,
        policy: SigningPolicy,
        client: Option<Arc<dyn SigningClient>>,
        resolver: Option<Arc<dyn TrustedKeyResolver>>,
    ) -> Self {
        self.signing = SigningRuntime::new(policy, client, resolver);
        self
    }

    /// Build the tracker adapter.
    ///
    /// # Errors
    ///
    /// Returns [`TrackerError::Client`] when the default reqwest client cannot
    /// be constructed.
    pub fn build(self) -> Result<X0xCrdtTracker> {
        let client = match self.client {
            Some(client) => client,
            None => Arc::new(X0xdClient::new(&self.base_url)?),
        };
        Ok(X0xCrdtTracker::from_client_parts(
            self.base_url,
            self.list_id,
            self.agent_id,
            client,
            self.signing,
        ))
    }
}

impl std::fmt::Debug for X0xCrdtTrackerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X0xCrdtTrackerBuilder")
            .field("base_url", &self.base_url)
            .field("list_id", &self.list_id)
            .field("agent_id", &self.agent_id)
            .field("has_custom_client", &self.client.is_some())
            .field("signing_policy", &self.signing.policy)
            .finish_non_exhaustive()
    }
}

/// Tracker adapter backed by x0xd `TaskList` and `KvStore` REST endpoints.
#[derive(Clone)]
pub struct X0xCrdtTracker {
    base_url: String,
    list_id: String,
    store_id: String,
    agent_id: AgentId,
    client: Arc<dyn X0xdApi>,
    signing: SigningRuntime,
}

impl std::fmt::Debug for X0xCrdtTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X0xCrdtTracker")
            .field("base_url", &self.base_url)
            .field("list_id", &self.list_id)
            .field("store_id", &self.store_id)
            .field("agent_id", &self.agent_id)
            .field("signing_policy", &self.signing.policy)
            .finish_non_exhaustive()
    }
}

impl X0xCrdtTracker {
    /// Construct a tracker using a reqwest-backed x0xd client.
    ///
    /// # Errors
    ///
    /// Returns [`TrackerError::Client`] when the reqwest client cannot be constructed.
    pub fn new(
        base_url: impl Into<String>,
        list_id: impl Into<String>,
        agent_id: AgentId,
    ) -> Result<Self> {
        Self::builder(base_url, list_id, agent_id).build()
    }

    /// Create a tracker builder.
    #[must_use]
    pub fn builder(
        base_url: impl Into<String>,
        list_id: impl Into<String>,
        agent_id: AgentId,
    ) -> X0xCrdtTrackerBuilder {
        X0xCrdtTrackerBuilder::new(base_url, list_id, agent_id)
    }

    /// Construct a tracker around an injected API implementation.
    #[must_use]
    pub fn from_client(
        base_url: impl Into<String>,
        list_id: impl Into<String>,
        agent_id: AgentId,
        client: Arc<dyn X0xdApi>,
    ) -> Self {
        Self::from_client_parts(
            base_url.into(),
            list_id.into(),
            agent_id,
            client,
            SigningRuntime::disabled(),
        )
    }

    /// Return the configured x0xd base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Return the x0xd `TaskList` id used by this tracker.
    #[must_use]
    pub fn list_id(&self) -> &str {
        &self.list_id
    }

    /// Return the x0xd `KvStore` id used for Symphony metadata sidecars.
    #[must_use]
    pub fn store_id(&self) -> &str {
        &self.store_id
    }

    /// Return the local agent id this tracker is allowed to claim as.
    #[must_use]
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    fn from_client_parts(
        base_url: String,
        list_id: String,
        agent_id: AgentId,
        client: Arc<dyn X0xdApi>,
        signing: SigningRuntime,
    ) -> Self {
        let store_id = store_id_for_list(&list_id);
        Self {
            base_url,
            list_id,
            store_id,
            agent_id,
            client,
            signing,
        }
    }

    async fn list_issues(&self) -> Result<Vec<Issue>> {
        let tasks = self.client.list_tasks(&self.list_id).await?;
        let mut issues = Vec::with_capacity(tasks.len());
        for task in tasks {
            let claim_blob = self.claim_blob_for_task(&task.id).await?;
            let handoff_blob = self.handoff_blob_for_task(&task.id).await?;
            issues.push(issue_from_task(
                &task,
                claim_blob.as_ref(),
                handoff_blob.as_ref(),
            )?);
        }
        Ok(self.filter_verified_issues(issues).await)
    }

    async fn claim_blob_for_task(&self, task_id: &str) -> Result<Option<ClaimBlob>> {
        let key = claim_key(task_id);
        self.client
            .get_kv(&self.store_id, &key)
            .await?
            .map(|value| decode_claim_blob(&value.value).map_err(Into::into))
            .transpose()
    }

    async fn handoff_blob_for_task(&self, task_id: &str) -> Result<Option<HandoffBlob>> {
        let key = handoff_key(task_id);
        self.client
            .get_kv(&self.store_id, &key)
            .await?
            .map(|value| decode_handoff_blob(&value.value).map_err(Into::into))
            .transpose()
    }

    async fn put_claim_blob(&self, task_id: &str, blob: &ClaimBlob) -> Result<()> {
        let key = claim_key(task_id);
        let encoded = encode_claim_blob(blob)?;
        self.client
            .put_kv(&self.store_id, &key, &encoded, SYMPHONY_JSON_CONTENT_TYPE)
            .await?;
        Ok(())
    }

    async fn put_handoff_blob(&self, task_id: &str, blob: &HandoffBlob) -> Result<()> {
        let key = handoff_key(task_id);
        let encoded = encode_handoff_blob(blob)?;
        self.client
            .put_kv(&self.store_id, &key, &encoded, SYMPHONY_JSON_CONTENT_TYPE)
            .await?;
        Ok(())
    }

    async fn fetch_issue(&self, id: &IssueId) -> Result<Issue> {
        self.list_issues()
            .await?
            .into_iter()
            .find(|issue| &issue.id == id)
            .ok_or_else(|| TrackerError::IssueNotFound { id: id.clone() })
    }

    fn ensure_agent_matches(&self, id: &IssueId, agent_id: &AgentId) -> Result<()> {
        if agent_id == &self.agent_id {
            Ok(())
        } else {
            Err(TrackerError::ClaimRejected {
                id: id.clone(),
                reason: format!(
                    "x0xd claims as local agent {}, not requested agent {agent_id}",
                    self.agent_id
                ),
            })
        }
    }

    fn ensure_issue_claimable(issue: &Issue, id: &IssueId) -> Result<()> {
        if issue.claim.is_some() {
            return Err(TrackerError::ClaimRejected {
                id: id.clone(),
                reason: "issue already has an active claim".to_owned(),
            });
        }
        if issue.state.as_str() != "todo" {
            return Err(TrackerError::ClaimRejected {
                id: id.clone(),
                reason: format!("state is {}", issue.state.as_str()),
            });
        }
        Ok(())
    }

    async fn current_active_claim(&self, id: &IssueId) -> Result<Claim> {
        let blob = self
            .claim_blob_for_task(id.as_str())
            .await?
            .ok_or_else(|| TrackerError::InvalidClaim {
                reason: format!("issue {id} has no claim blob"),
            })?;
        if blob.status == ClaimBlobStatus::Active {
            Ok(blob.claim)
        } else {
            Err(TrackerError::InvalidClaim {
                reason: format!("issue {id} claim status is {:?}", blob.status),
            })
        }
    }

    async fn ensure_current_claim_owner(&self, claim: &Claim) -> Result<IssueId> {
        let id = claim_issue_id(claim)?;
        let current = self.current_active_claim(&id).await?;
        if current.by == claim.by {
            Ok(id)
        } else {
            Err(TrackerError::InvalidClaim {
                reason: format!("issue {id} is claimed by {}, not {}", current.by, claim.by),
            })
        }
    }

    async fn sign_claim(&self, mut claim: Claim) -> Result<Claim> {
        let payload = claim.signing_payload_bytes().map_err(TrackerError::from)?;
        let response = self
            .signing
            .client()?
            .sign(CLAIM_CONTEXT, &payload)
            .await
            .map_err(signing_error)?;
        let envelope = envelope_from_sign_response(response, CLAIM_CONTEXT, &payload, &claim.by)?;
        claim.signature = Some(envelope);
        Ok(claim)
    }

    async fn sign_handoff(&self, mut handoff: Handoff, signer: &AgentId) -> Result<Handoff> {
        let payload = handoff
            .signing_payload_bytes()
            .map_err(TrackerError::from)?;
        let response = self
            .signing
            .client()?
            .sign(HANDOFF_CONTEXT, &payload)
            .await
            .map_err(signing_error)?;
        let envelope = envelope_from_sign_response(response, HANDOFF_CONTEXT, &payload, signer)?;
        handoff.signature = Some(envelope);
        Ok(handoff)
    }

    async fn filter_verified_issues(&self, issues: Vec<Issue>) -> Vec<Issue> {
        if self.signing.policy == SigningPolicy::Disabled {
            return issues;
        }
        let mut verified = Vec::with_capacity(issues.len());
        for issue in issues {
            if self.verify_issue(&issue).await {
                verified.push(issue);
            }
        }
        verified
    }

    async fn verify_issue(&self, issue: &Issue) -> bool {
        if let Err(error) = self.verify_issue_result(issue).await {
            warn!(issue_id = %issue.id, error = %error, "dropping issue with invalid signature");
            false
        } else {
            true
        }
    }

    async fn verify_issue_result(&self, issue: &Issue) -> Result<()> {
        if let Some(claim) = &issue.claim {
            self.verify_claim(issue, claim).await?;
        }
        if let Some(handoff) = &issue.handoff {
            self.verify_handoff(issue, handoff).await?;
        }
        Ok(())
    }

    async fn verify_claim(&self, issue: &Issue, claim: &Claim) -> Result<()> {
        if claim.issue_id.as_ref() != Some(&issue.id) {
            return Err(TrackerError::Signing(format!(
                "claim issue_id does not match parent issue {}",
                issue.id
            )));
        }
        let envelope = claim.signature.as_ref().ok_or_else(|| {
            TrackerError::Signing(format!("claim for issue {} is unsigned", issue.id))
        })?;
        if envelope.signer_agent_id != claim.by.to_string() {
            return Err(TrackerError::Signing(format!(
                "claim owner {} does not match signer {}",
                claim.by, envelope.signer_agent_id
            )));
        }
        let payload = claim.signing_payload_bytes().map_err(TrackerError::from)?;
        self.verify_envelope(envelope, CLAIM_CONTEXT, &payload)
            .await
    }

    async fn verify_handoff(&self, issue: &Issue, handoff: &Handoff) -> Result<()> {
        let envelope = handoff.signature.as_ref().ok_or_else(|| {
            TrackerError::Signing(format!("handoff for issue {} is unsigned", issue.id))
        })?;
        if handoff.issue_id.as_ref() != Some(&issue.id) {
            return Err(TrackerError::Signing(format!(
                "handoff issue_id does not match parent issue {}",
                issue.id
            )));
        }
        let signer_agent_id = handoff.signer_agent_id.as_ref().ok_or_else(|| {
            TrackerError::Signing(format!(
                "handoff for issue {} is missing signer_agent_id",
                issue.id
            ))
        })?;
        if signer_agent_id != &envelope.signer_agent_id {
            return Err(TrackerError::Signing(format!(
                "handoff signer binding {signer_agent_id} does not match envelope signer {}",
                envelope.signer_agent_id
            )));
        }
        let payload = handoff
            .signing_payload_bytes()
            .map_err(TrackerError::from)?;
        self.verify_envelope(envelope, HANDOFF_CONTEXT, &payload)
            .await
    }

    async fn verify_envelope(
        &self,
        envelope: &SignatureEnvelope,
        target_context: &str,
        payload: &[u8],
    ) -> Result<()> {
        if envelope.algorithm != SIGN_ALGORITHM {
            return Err(TrackerError::Signing(format!(
                "unsupported signing algorithm {}",
                envelope.algorithm
            )));
        }
        if envelope.context != target_context {
            return Err(TrackerError::Signing(format!(
                "signature context {} does not match {target_context}",
                envelope.context
            )));
        }
        let actual_digest = sha256_hex(payload);
        if envelope.payload_sha256 != actual_digest {
            return Err(TrackerError::Signing(format!(
                "payload digest {} does not match {actual_digest}",
                envelope.payload_sha256
            )));
        }
        let envelope_key = BASE64
            .decode(&envelope.public_key_b64)
            .map_err(|source| TrackerError::Signing(format!("invalid public_key_b64: {source}")))?;
        let trusted_key = self
            .signing
            .resolver()?
            .resolve(&envelope.signer_agent_id)
            .await
            .map_err(signing_error)?;
        if envelope_key != trusted_key {
            return Err(TrackerError::Signing(format!(
                "envelope public key does not belong to signer {}",
                envelope.signer_agent_id
            )));
        }
        let signature = BASE64
            .decode(&envelope.signature_b64)
            .map_err(|source| TrackerError::Signing(format!("invalid signature_b64: {source}")))?;
        let outcome = self
            .signing
            .client()?
            .verify(target_context, payload, &signature, &envelope_key)
            .await
            .map_err(signing_error)?;
        match outcome {
            VerifyOutcome::Valid => Ok(()),
            VerifyOutcome::Invalid(reason) => Err(TrackerError::Signing(format!(
                "x0xd verify rejected signature: {reason}"
            ))),
            VerifyOutcome::TransportError(reason) => Err(TrackerError::Signing(format!(
                "x0xd verify transport error (validity unknown): {reason}"
            ))),
        }
    }
}

#[async_trait]
impl Tracker for X0xCrdtTracker {
    async fn fetch_candidates(&self, ctx: &PollContext) -> x0x_symphony_core::Result<Vec<Issue>> {
        let issues = self.list_issues().await.map_err(SymphonyError::from)?;
        let terminal_states: BTreeSet<IssueState> = ctx.terminal_states.iter().cloned().collect();
        let mut candidates = issues
            .iter()
            .filter(|issue| ctx.active_states.iter().any(|state| state == &issue.state))
            .filter(|issue| blockers_are_terminal(issue, &issues, &terminal_states))
            .cloned()
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            priority_sort_key(left)
                .cmp(&priority_sort_key(right))
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(candidates)
    }

    async fn fetch_by_ids(&self, ids: &[IssueId]) -> x0x_symphony_core::Result<Vec<Issue>> {
        let requested = ids.iter().collect::<BTreeSet<_>>();
        let issues = self.list_issues().await.map_err(SymphonyError::from)?;
        Ok(issues
            .into_iter()
            .filter(|issue| requested.contains(&issue.id))
            .collect())
    }

    async fn claim(&self, id: &IssueId, agent_id: &AgentId) -> x0x_symphony_core::Result<Claim> {
        self.ensure_agent_matches(id, agent_id)
            .map_err(SymphonyError::from)?;
        let issue = self.fetch_issue(id).await.map_err(SymphonyError::from)?;
        Self::ensure_issue_claimable(&issue, id).map_err(SymphonyError::from)?;
        let claim = Claim::new(
            Some(id.clone()),
            agent_id.clone(),
            now_utc(),
            ShardRole::ManualM1,
        );
        let claim = if self.signing.policy == SigningPolicy::Disabled {
            claim
        } else {
            self.sign_claim(claim).await.map_err(SymphonyError::from)?
        };
        self.client
            .update_task(&self.list_id, id.as_str(), TaskAction::Claim)
            .await
            .map_err(TrackerError::from)
            .map_err(SymphonyError::from)?;
        self.put_claim_blob(id.as_str(), &ClaimBlob::active(claim.clone(), now_utc()))
            .await
            .map_err(SymphonyError::from)?;
        Ok(claim)
    }

    async fn heartbeat(&self, claim: &Claim) -> x0x_symphony_core::Result<()> {
        let id = self
            .ensure_current_claim_owner(claim)
            .await
            .map_err(SymphonyError::from)?;
        let refreshed = claim.clone().with_heartbeat(now_utc());
        self.put_claim_blob(
            id.as_str(),
            &ClaimBlob::active(refreshed.clone(), refreshed.heartbeat_at.clone()),
        )
        .await
        .map_err(SymphonyError::from)
    }

    async fn release(&self, claim: &Claim, reason: ReleaseReason) -> x0x_symphony_core::Result<()> {
        let id = self
            .ensure_current_claim_owner(claim)
            .await
            .map_err(SymphonyError::from)?;
        self.put_claim_blob(
            id.as_str(),
            &ClaimBlob::released(claim.clone(), reason, now_utc()),
        )
        .await
        .map_err(SymphonyError::from)
    }

    async fn handoff(&self, claim: &Claim, handoff: Handoff) -> x0x_symphony_core::Result<()> {
        let id = self
            .ensure_current_claim_owner(claim)
            .await
            .map_err(SymphonyError::from)?;
        let prepared = if self.signing.policy == SigningPolicy::Disabled {
            handoff
        } else {
            let mut handoff = handoff
                .with_issue_id(id.clone())
                .with_signer_agent_id(claim.by.to_string());
            handoff.signature = None;
            self.sign_handoff(handoff, &claim.by)
                .await
                .map_err(SymphonyError::from)?
        };
        self.put_handoff_blob(id.as_str(), &HandoffBlob::new(prepared, now_utc()))
            .await
            .map_err(SymphonyError::from)?;
        self.client
            .update_task(&self.list_id, id.as_str(), TaskAction::Complete)
            .await
            .map_err(TrackerError::from)
            .map_err(SymphonyError::from)?;
        self.put_claim_blob(id.as_str(), &ClaimBlob::completed(claim.clone(), now_utc()))
            .await
            .map_err(SymphonyError::from)
    }

    async fn fetch_claimed(
        &self,
        agent_id: Option<&AgentId>,
    ) -> x0x_symphony_core::Result<Vec<Issue>> {
        let issues = self.list_issues().await.map_err(SymphonyError::from)?;
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
        let id = self
            .ensure_current_claim_owner(claim)
            .await
            .map_err(SymphonyError::from)?;
        self.put_claim_blob(
            id.as_str(),
            &ClaimBlob::blocked(claim.clone(), reason, now_utc()),
        )
        .await
        .map_err(SymphonyError::from)
    }
}

fn blockers_are_terminal(
    issue: &Issue,
    issues: &[Issue],
    terminal_states: &BTreeSet<IssueState>,
) -> bool {
    issue.blocked_by.iter().all(|blocker| {
        issues
            .iter()
            .find(|candidate| candidate.id == blocker.id)
            .is_some_and(|candidate| terminal_states.contains(&candidate.state))
    })
}

const fn priority_sort_key(issue: &Issue) -> u8 {
    match issue.priority {
        Some(priority) => priority,
        None => u8::MAX,
    }
}

fn claim_issue_id(claim: &Claim) -> Result<IssueId> {
    claim
        .issue_id
        .clone()
        .ok_or_else(|| TrackerError::InvalidClaim {
            reason: "claim is missing issue_id".to_owned(),
        })
}

fn envelope_from_sign_response(
    response: SignResponse,
    target_context: &str,
    payload: &[u8],
    target_signer: &AgentId,
) -> Result<SignatureEnvelope> {
    if response.algorithm != SIGN_ALGORITHM {
        return Err(TrackerError::Signing(format!(
            "sign response algorithm {} did not match {SIGN_ALGORITHM}",
            response.algorithm
        )));
    }
    if response.context != target_context {
        return Err(TrackerError::Signing(format!(
            "sign response context {} did not match {target_context}",
            response.context
        )));
    }
    if response.agent_id != target_signer.to_string() {
        return Err(TrackerError::Signing(format!(
            "sign response agent {} did not match claim owner {}",
            response.agent_id, target_signer
        )));
    }
    Ok(SignatureEnvelope::new(
        response.algorithm,
        response.context,
        response.public_key_b64,
        response.signature_b64,
        sha256_hex(payload),
        response.agent_id,
    ))
}

fn signing_error(error: impl std::fmt::Display) -> TrackerError {
    TrackerError::Signing(error.to_string())
}

fn now_utc() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, error::Error};

    use async_trait::async_trait;
    use tokio::sync::Mutex;
    use x0x_symphony_core::{ReleaseReasonCode, ValidationResult, ValidationStatus};

    use super::*;
    use crate::{
        client::{
            AddTaskDraft, EventStream, KvKeyEntry, KvValue, TaskEntry, TaskListEntry, X0xdEvent,
        },
        mapping::{decode_claim_blob, decode_handoff_blob},
    };

    type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

    const ISSUE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ISSUE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const AGENT_A: &str = "agent-a";
    const AGENT_B: &str = "agent-b";

    #[derive(Default)]
    struct MockApi {
        state: Mutex<MockState>,
    }

    #[derive(Default)]
    struct MockState {
        tasks: Vec<TaskEntry>,
        kv: BTreeMap<(String, String), Vec<u8>>,
        actions: Vec<(String, String, TaskAction)>,
        puts: Vec<(String, String, Vec<u8>)>,
    }

    impl MockApi {
        async fn with_tasks(tasks: Vec<TaskEntry>) -> Arc<Self> {
            let api = Arc::new(Self::default());
            api.state.lock().await.tasks = tasks;
            api
        }

        async fn seed_claim(&self, task_id: &str, claim: Claim) -> TestResult {
            let blob = ClaimBlob::active(claim, "2026-07-03T01:00:00Z");
            let key = claim_key(task_id);
            self.state.lock().await.kv.insert(
                (store_id_for_list("list-a"), key),
                encode_claim_blob(&blob)?,
            );
            Ok(())
        }

        async fn action_count(&self, action: TaskAction) -> usize {
            self.state
                .lock()
                .await
                .actions
                .iter()
                .filter(|(_, _, recorded)| recorded == &action)
                .count()
        }

        async fn claim_blob(&self, task_id: &str) -> TestResult<ClaimBlob> {
            let key = (store_id_for_list("list-a"), claim_key(task_id));
            let state = self.state.lock().await;
            let bytes = state
                .kv
                .get(&key)
                .ok_or_else(|| std::io::Error::other("missing claim blob"))?;
            Ok(decode_claim_blob(bytes)?)
        }

        async fn handoff_blob(&self, task_id: &str) -> TestResult<HandoffBlob> {
            let key = (store_id_for_list("list-a"), handoff_key(task_id));
            let state = self.state.lock().await;
            let bytes = state
                .kv
                .get(&key)
                .ok_or_else(|| std::io::Error::other("missing handoff blob"))?;
            Ok(decode_handoff_blob(bytes)?)
        }
    }

    #[async_trait]
    impl X0xdApi for MockApi {
        async fn list_task_lists(&self) -> client::Result<Vec<TaskListEntry>> {
            Ok(vec![TaskListEntry {
                id: "list-a".to_owned(),
                topic: "list-a".to_owned(),
            }])
        }

        async fn create_task_list(&self, _name: &str, topic: &str) -> client::Result<String> {
            Ok(topic.to_owned())
        }

        async fn list_tasks(&self, _list_id: &str) -> client::Result<Vec<TaskEntry>> {
            Ok(self.state.lock().await.tasks.clone())
        }

        async fn add_task(&self, _list_id: &str, draft: AddTaskDraft) -> client::Result<String> {
            let id = ISSUE_A.to_owned();
            self.state.lock().await.tasks.push(TaskEntry {
                id: id.clone(),
                title: draft.title,
                description: draft.description.unwrap_or_default(),
                state: "empty".to_owned(),
                assignee: None,
                priority: 3,
            });
            Ok(id)
        }

        async fn update_task(
            &self,
            list_id: &str,
            task_id: &str,
            action: TaskAction,
        ) -> client::Result<()> {
            let mut state = self.state.lock().await;
            state
                .actions
                .push((list_id.to_owned(), task_id.to_owned(), action));
            for task in &mut state.tasks {
                if task.id == task_id {
                    match action {
                        TaskAction::Claim => {
                            task.state = format!("claimed:{AGENT_A}");
                            task.assignee = Some(AGENT_A.to_owned());
                        }
                        TaskAction::Complete => {
                            task.state = format!("done:{AGENT_A}");
                        }
                    }
                }
            }
            Ok(())
        }

        async fn list_kv_stores(&self) -> client::Result<Vec<TaskListEntry>> {
            Ok(vec![TaskListEntry {
                id: store_id_for_list("list-a"),
                topic: store_id_for_list("list-a"),
            }])
        }

        async fn create_kv_store(&self, _name: &str, topic: &str) -> client::Result<String> {
            Ok(topic.to_owned())
        }

        async fn list_kv_keys(&self, store_id: &str) -> client::Result<Vec<KvKeyEntry>> {
            let keys = self
                .state
                .lock()
                .await
                .kv
                .keys()
                .filter(|(store, _)| store == store_id)
                .map(|(_, key)| KvKeyEntry {
                    key: key.clone(),
                    content_type: Some(SYMPHONY_JSON_CONTENT_TYPE.to_owned()),
                    content_hash: None,
                    size: 0,
                    updated_at: None,
                })
                .collect();
            Ok(keys)
        }

        async fn put_kv(
            &self,
            store_id: &str,
            key: &str,
            value: &[u8],
            _content_type: &str,
        ) -> client::Result<()> {
            let mut state = self.state.lock().await;
            state
                .kv
                .insert((store_id.to_owned(), key.to_owned()), value.to_vec());
            state
                .puts
                .push((store_id.to_owned(), key.to_owned(), value.to_vec()));
            Ok(())
        }

        async fn get_kv(&self, store_id: &str, key: &str) -> client::Result<Option<KvValue>> {
            Ok(self
                .state
                .lock()
                .await
                .kv
                .get(&(store_id.to_owned(), key.to_owned()))
                .map(|value| KvValue {
                    key: key.to_owned(),
                    value: value.clone(),
                    content_type: Some(SYMPHONY_JSON_CONTENT_TYPE.to_owned()),
                    content_hash: None,
                    created_at: None,
                    updated_at: None,
                }))
        }

        async fn subscribe_events(&self) -> client::Result<EventStream> {
            let stream = futures_util::stream::iter([Ok(X0xdEvent {
                event_type: Some("message".to_owned()),
                data: "event: message".to_owned(),
            })]);
            Ok(Box::pin(stream))
        }
    }

    fn task(id: &str, title: &str, state: &str, priority: u8) -> TaskEntry {
        TaskEntry {
            id: id.to_owned(),
            title: title.to_owned(),
            description: String::new(),
            state: state.to_owned(),
            assignee: None,
            priority,
        }
    }

    fn tracker(api: Arc<MockApi>) -> TestResult<X0xCrdtTracker> {
        Ok(X0xCrdtTracker::from_client(
            "mock://x0xd",
            "list-a",
            AgentId::new(AGENT_A)?,
            api,
        ))
    }

    fn claim_for(task_id: &str, agent: &str) -> TestResult<Claim> {
        Ok(Claim::new(
            Some(IssueId::new(task_id)?),
            AgentId::new(agent)?,
            "2026-07-03T01:00:00Z",
            ShardRole::ManualM1,
        ))
    }

    #[tokio::test]
    async fn fetch_candidates_filters_active_states_and_sorts() -> TestResult {
        let api = MockApi::with_tasks(vec![
            task(ISSUE_A, "normal", "empty", 3),
            task(ISSUE_B, "urgent", "empty", 1),
        ])
        .await;
        let tracker = tracker(api)?;
        let ctx = PollContext::new(
            vec![IssueState::new("todo")?],
            vec![IssueState::new("done")?],
        );

        let candidates = tracker.fetch_candidates(&ctx).await?;

        let ids = candidates
            .iter()
            .map(|issue| issue.id.to_string())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec![ISSUE_B.to_owned(), ISSUE_A.to_owned()]);
        Ok(())
    }

    #[tokio::test]
    async fn fetch_by_ids_returns_requested_tasks_only() -> TestResult {
        let api = MockApi::with_tasks(vec![
            task(ISSUE_A, "a", "empty", 3),
            task(ISSUE_B, "b", "empty", 3),
        ])
        .await;
        let tracker = tracker(api)?;

        let fetched = tracker.fetch_by_ids(&[IssueId::new(ISSUE_B)?]).await?;

        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].id, IssueId::new(ISSUE_B)?);
        Ok(())
    }

    #[tokio::test]
    async fn claim_patches_task_and_writes_active_claim_blob() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "claim", "empty", 3)]).await;
        let tracker = tracker(api.clone())?;
        let agent = AgentId::new(AGENT_A)?;

        let claim = tracker.claim(&IssueId::new(ISSUE_A)?, &agent).await?;

        assert_eq!(claim.by, agent);
        assert_eq!(api.action_count(TaskAction::Claim).await, 1);
        let blob = api.claim_blob(ISSUE_A).await?;
        assert_eq!(blob.status, ClaimBlobStatus::Active);
        assert_eq!(blob.claim.by, AgentId::new(AGENT_A)?);
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_updates_claim_blob_heartbeat() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "heartbeat", "claimed:agent-a", 3)]).await;
        let claim = claim_for(ISSUE_A, AGENT_A)?;
        api.seed_claim(ISSUE_A, claim.clone()).await?;
        let tracker = tracker(api.clone())?;

        tracker.heartbeat(&claim).await?;

        let blob = api.claim_blob(ISSUE_A).await?;
        assert_eq!(blob.status, ClaimBlobStatus::Active);
        assert_ne!(blob.claim.heartbeat_at, claim.heartbeat_at);
        Ok(())
    }

    #[tokio::test]
    async fn release_writes_released_blob_and_fetches_as_todo() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "release", "claimed:agent-a", 3)]).await;
        let claim = claim_for(ISSUE_A, AGENT_A)?;
        api.seed_claim(ISSUE_A, claim.clone()).await?;
        let tracker = tracker(api.clone())?;

        tracker
            .release(
                &claim,
                ReleaseReason::new(ReleaseReasonCode::OperatorCancelled, "test release"),
            )
            .await?;

        let blob = api.claim_blob(ISSUE_A).await?;
        assert_eq!(blob.status, ClaimBlobStatus::Released);
        let fetched = tracker.fetch_by_ids(&[IssueId::new(ISSUE_A)?]).await?;
        assert_eq!(fetched[0].state, IssueState::new("todo")?);
        assert!(fetched[0].claim.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn handoff_writes_handoff_blob_and_completes_task() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "handoff", "claimed:agent-a", 3)]).await;
        let claim = claim_for(ISSUE_A, AGENT_A)?;
        api.seed_claim(ISSUE_A, claim.clone()).await?;
        let tracker = tracker(api.clone())?;
        let handoff = Handoff::new("ready")
            .with_file("src/lib.rs")
            .with_validation(ValidationResult::new("just test", ValidationStatus::Passed));

        tracker.handoff(&claim, handoff).await?;

        assert_eq!(api.action_count(TaskAction::Complete).await, 1);
        let handoff_blob = api.handoff_blob(ISSUE_A).await?;
        assert_eq!(handoff_blob.handoff.summary, "ready");
        let claim_blob = api.claim_blob(ISSUE_A).await?;
        assert_eq!(claim_blob.status, ClaimBlobStatus::Completed);
        let fetched = tracker.fetch_by_ids(&[IssueId::new(ISSUE_A)?]).await?;
        assert_eq!(fetched[0].state, IssueState::new("review")?);
        assert!(fetched[0].claim.is_none());
        assert!(fetched[0].handoff.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn fetch_claimed_returns_active_claims_and_filters_owner() -> TestResult {
        let api = MockApi::with_tasks(vec![
            task(ISSUE_A, "a", "claimed:agent-a", 3),
            task(ISSUE_B, "b", "claimed:agent-b", 3),
        ])
        .await;
        api.seed_claim(ISSUE_A, claim_for(ISSUE_A, AGENT_A)?)
            .await?;
        api.seed_claim(ISSUE_B, claim_for(ISSUE_B, AGENT_B)?)
            .await?;
        let tracker = tracker(api)?;

        let all = tracker.fetch_claimed(None).await?;
        let mine = tracker.fetch_claimed(Some(&AgentId::new(AGENT_A)?)).await?;

        assert_eq!(all.len(), 2);
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].id, IssueId::new(ISSUE_A)?);
        Ok(())
    }

    #[tokio::test]
    async fn block_writes_blocked_blob_and_fetches_as_blocked() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "block", "claimed:agent-a", 3)]).await;
        let claim = claim_for(ISSUE_A, AGENT_A)?;
        api.seed_claim(ISSUE_A, claim.clone()).await?;
        let tracker = tracker(api.clone())?;

        tracker
            .block(
                &claim,
                ReleaseReason::new(ReleaseReasonCode::RetryExhausted, "retry cap reached"),
            )
            .await?;

        let blob = api.claim_blob(ISSUE_A).await?;
        assert_eq!(blob.status, ClaimBlobStatus::Blocked);
        let fetched = tracker.fetch_by_ids(&[IssueId::new(ISSUE_A)?]).await?;
        assert_eq!(fetched[0].state, IssueState::new("blocked")?);
        assert!(fetched[0].claim.is_none());
        assert!(fetched[0].extra.contains_key("blocked_reason"));
        Ok(())
    }
}
