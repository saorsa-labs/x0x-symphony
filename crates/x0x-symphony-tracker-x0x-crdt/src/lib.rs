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
//! - When configured with `tracker.group`, the adapter first resolves the value
//!   against x0xd's named-group table, or joins via `POST /groups/join` when the
//!   value is an invite link/token. The x0xd `TaskList` topic is then scoped to
//!   `x0x.group.<group_id>.symphony.<list-id>` and the metadata `KvStore` remains
//!   the deterministic `symphony-<scoped-list-id>` sidecar. Symphony performs no
//!   MLS cryptography; x0xd remains responsible for group membership and any
//!   encrypted task-list enforcement. If x0xd hides or forbids the scoped list,
//!   `fetch_candidates` observes zero visible tasks.
//!
//! This is the M3 runtime tracker used by `x0x-symphonyd`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod client;
pub mod mapping;

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{SecondsFormat, Utc};
use reqwest::StatusCode;
use thiserror::Error;
use tracing::{info, warn};
use x0x_symphony_core::{
    sha256_hex, shard, AgentId, ApprovalConsumed, ApprovalEvent, ApprovalState, Claim, Handoff,
    Issue, IssueDraft, IssueId, IssueState, PollContext, ReleaseReason, ShardRole,
    SignatureEnvelope, SignatureProvenance, SymphonyError, Tracker, VerificationNotice,
    VerificationNoticeKind, WorkerCard, CLAIM_CONTEXT, HANDOFF_CONTEXT, ISSUE_PROVENANCE_CONTEXT,
    SIGN_ALGORITHM, WORKER_CARD_CONTEXT, WORKER_CARD_SCHEMA_VERSION,
};
use x0x_symphony_signing::{
    SignResponse, SigningClient, SigningPolicy, TrustedKeyResolver, VerifyOutcome,
};

use crate::{
    client::{AddTaskDraft, ClientError, TaskAction, X0xdApi, X0xdClient},
    mapping::{
        approval_key, claim_key, decode_approval_blob, decode_claim_blob, decode_handoff_blob,
        decode_provenance_blob, decode_shard_blob, encode_approval_blob, encode_claim_blob,
        encode_handoff_blob, encode_provenance_blob, encode_shard_blob, handoff_key,
        issue_from_task, provenance_key, shard_key, store_id_for_list, ApprovalBlob, ClaimBlob,
        ClaimBlobStatus, HandoffBlob, ProvenanceBlob, ShardBlob, SYMPHONY_JSON_CONTENT_TYPE,
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

    /// The configured MLS/named group could not be resolved locally or joined.
    #[error("tracker.group {group} could not be resolved: {reason}")]
    GroupResolution {
        /// Group name, id, or invite configured by the operator.
        group: String,
        /// Human-readable resolution failure.
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

    /// Signature validity is unknown because verification transport failed.
    #[error("signature verification transport error: {reason}")]
    VerifyTransport {
        /// Verification dependency or transport failure.
        reason: String,
    },
}

impl From<TrackerError> for SymphonyError {
    fn from(error: TrackerError) -> Self {
        match error {
            TrackerError::Core(source) => source,
            other => Self::Tracker(other.to_string()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResourceScope {
    list_id: String,
    store_id: String,
    group_scoped: bool,
}

impl ResourceScope {
    fn unscoped(list_id: &str) -> Self {
        Self {
            list_id: list_id.to_owned(),
            store_id: store_id_for_list(list_id),
            group_scoped: false,
        }
    }

    fn grouped(base_list_id: &str, group_id: &str) -> Self {
        let list_id = group_scoped_list_id(group_id, base_list_id);
        Self {
            store_id: store_id_for_list(&list_id),
            list_id,
            group_scoped: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedGroup {
    group_id: String,
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

#[derive(Clone)]
struct IssueCreationRuntime {
    worker_view: Option<Arc<dyn WorkerViewProvider>>,
    replication_factor: usize,
}

impl IssueCreationRuntime {
    fn new(worker_view: Option<Arc<dyn WorkerViewProvider>>, replication_factor: usize) -> Self {
        Self {
            worker_view,
            replication_factor: replication_factor.max(1),
        }
    }

    const fn unsupported() -> Self {
        Self {
            worker_view: None,
            replication_factor: shard::DEFAULT_REPLICATION_FACTOR,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct VerifyCacheKey {
    issue_id: IssueId,
    context: String,
    payload_sha256: String,
    signature_b64: String,
    public_key_b64: String,
    signer_agent_id: String,
}

/// Atomic live worker-view snapshot used for shard assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerViewSnapshot {
    /// Verified worker cards visible at one point in time.
    pub cards: Vec<WorkerCard>,
    /// Monotonic epoch of the worker view that produced `cards`.
    pub view_epoch: u64,
}

/// Source of live worker-card snapshots for issue creation.
#[async_trait]
pub trait WorkerViewProvider: Send + Sync {
    /// Return one atomic snapshot of the current live worker view.
    async fn snapshot(&self) -> WorkerViewSnapshot;
}

/// Builder for [`X0xCrdtTracker`].
#[derive(Clone)]
pub struct X0xCrdtTrackerBuilder {
    base_url: String,
    list_id: String,
    agent_id: AgentId,
    client: Option<Arc<dyn X0xdApi>>,
    signing: SigningRuntime,
    group: Option<String>,
    worker_view: Option<Arc<dyn WorkerViewProvider>>,
    replication_factor: usize,
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
            group: None,
            worker_view: None,
            replication_factor: shard::DEFAULT_REPLICATION_FACTOR,
        }
    }

    /// Scope this tracker to an x0xd named/MLS group.
    ///
    /// The value may be a locally-known group id, a locally-known group name,
    /// or an x0xd invite link/token. Invite values are passed to x0xd's
    /// `POST /groups/join` on first use; group ids/names must already resolve
    /// in x0xd's local named-group table.
    #[must_use]
    pub fn group(mut self, group: impl Into<String>) -> Self {
        let group = group.into();
        self.group = (!group.trim().is_empty()).then_some(group);
        self
    }

    /// Inject a custom API implementation, usually a test mock.
    #[must_use]
    pub fn client(mut self, client: Arc<dyn X0xdApi>) -> Self {
        self.client = Some(client);
        self
    }

    /// Inject the live worker view used for symphony-owned issue creation.
    #[must_use]
    pub fn worker_view(mut self, provider: Arc<dyn WorkerViewProvider>) -> Self {
        self.worker_view = Some(provider);
        self
    }

    /// Set the shard owner count for newly created issues.
    #[must_use]
    pub fn replication_factor(mut self, replication_factor: usize) -> Self {
        self.replication_factor = replication_factor.max(1);
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
            self.group,
            IssueCreationRuntime::new(self.worker_view, self.replication_factor),
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
            .field("group", &self.group)
            .field("has_worker_view", &self.worker_view.is_some())
            .field("replication_factor", &self.replication_factor)
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
    group: Option<String>,
    creation: IssueCreationRuntime,
    resolved_scope: Arc<tokio::sync::Mutex<Option<ResourceScope>>>,
    verify_cache: Arc<Mutex<HashMap<VerifyCacheKey, VerifyOutcome>>>,
}

impl std::fmt::Debug for X0xCrdtTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X0xCrdtTracker")
            .field("base_url", &self.base_url)
            .field("list_id", &self.list_id)
            .field("store_id", &self.store_id)
            .field("agent_id", &self.agent_id)
            .field("signing_policy", &self.signing.policy)
            .field("group", &self.group)
            .field("has_worker_view", &self.creation.worker_view.is_some())
            .field("replication_factor", &self.creation.replication_factor)
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
            None,
            IssueCreationRuntime::unsupported(),
        )
    }

    /// Return the configured x0xd base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Return the configured x0xd `TaskList` id before optional group scoping.
    #[must_use]
    pub fn list_id(&self) -> &str {
        &self.list_id
    }

    /// Return the configured x0xd `KvStore` sidecar id before optional group scoping.
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
        group: Option<String>,
        creation: IssueCreationRuntime,
    ) -> Self {
        let store_id = store_id_for_list(&list_id);
        Self {
            base_url,
            list_id,
            store_id,
            agent_id,
            client,
            signing,
            group,
            creation,
            resolved_scope: Arc::new(tokio::sync::Mutex::new(None)),
            verify_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn resource_scope(&self) -> Result<ResourceScope> {
        let Some(group) = self.group.as_deref() else {
            return Ok(ResourceScope::unscoped(&self.list_id));
        };
        if let Some(scope) = self.resolved_scope.lock().await.clone() {
            return Ok(scope);
        }
        let resolved = self.resolve_or_join_group(group).await?;
        let scope = ResourceScope::grouped(&self.list_id, &resolved.group_id);
        let mut cached = self.resolved_scope.lock().await;
        if cached.is_none() {
            *cached = Some(scope);
        }
        cached.clone().ok_or_else(|| TrackerError::GroupResolution {
            group: group.to_owned(),
            reason: "resolved scope cache was unexpectedly empty".to_owned(),
        })
    }

    async fn resolve_or_join_group(&self, group: &str) -> Result<ResolvedGroup> {
        let groups = self.client.list_named_groups().await?;
        if let Some(entry) = groups
            .iter()
            .find(|entry| entry.group_id == group || entry.name == group)
        {
            let details = self.client.get_named_group(&entry.group_id).await?;
            return Ok(ResolvedGroup {
                group_id: details.group_id,
            });
        }
        if looks_like_group_invite(group) {
            let joined = self
                .client
                .join_group(group, Some(self.agent_id.as_str()))
                .await?;
            return Ok(ResolvedGroup {
                group_id: joined.group_id,
            });
        }
        Err(TrackerError::GroupResolution {
            group: group.to_owned(),
            reason: "not found in x0xd /groups and not an invite link/token".to_owned(),
        })
    }

    /// List all issues visible in the configured x0xd `TaskList`.
    ///
    /// # Errors
    ///
    /// Returns [`TrackerError`] when x0xd cannot be read, the TaskList/KvStore
    /// data cannot be mapped, or required signature verification has unknown
    /// validity because x0xd transport failed.
    pub async fn list_issues(&self) -> Result<Vec<Issue>> {
        let scope = self.resource_scope().await?;
        let tasks = match self.client.list_tasks(&scope.list_id).await {
            Ok(tasks) => tasks,
            Err(ClientError::Http { status, body })
                if scope.group_scoped
                    && (status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND) =>
            {
                warn!(
                    list_id = %scope.list_id,
                    status = %status,
                    body = %body,
                    "x0xd denied or hid group-scoped task list; treating as zero visible tasks"
                );
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        };
        let mut issues = Vec::with_capacity(tasks.len());
        for task in tasks {
            let claim_blob = self.claim_blob_for_task(&task.id).await?;
            let handoff_blob = self.handoff_blob_for_task(&task.id).await?;
            let shard_blob = self.shard_blob_for_task(&task.id).await?;
            issues.push(issue_from_task(
                &task,
                claim_blob.as_ref(),
                handoff_blob.as_ref(),
                shard_blob.as_ref(),
            )?);
        }
        self.filter_verified_issues(issues).await
    }

    async fn claim_blob_for_task(&self, task_id: &str) -> Result<Option<ClaimBlob>> {
        let scope = self.resource_scope().await?;
        let key = claim_key(task_id);
        self.client
            .get_kv(&scope.store_id, &key)
            .await?
            .map(|value| decode_claim_blob(&value.value).map_err(Into::into))
            .transpose()
    }

    async fn handoff_blob_for_task(&self, task_id: &str) -> Result<Option<HandoffBlob>> {
        let scope = self.resource_scope().await?;
        let key = handoff_key(task_id);
        self.client
            .get_kv(&scope.store_id, &key)
            .await?
            .map(|value| decode_handoff_blob(&value.value).map_err(Into::into))
            .transpose()
    }

    async fn shard_blob_for_task(&self, task_id: &str) -> Result<Option<ShardBlob>> {
        let scope = self.resource_scope().await?;
        let key = shard_key(task_id);
        self.client
            .get_kv(&scope.store_id, &key)
            .await?
            .map(|value| decode_shard_blob(&value.value).map_err(Into::into))
            .transpose()
    }

    async fn approval_blob_for_issue(&self, issue_id: &IssueId) -> Result<Option<ApprovalBlob>> {
        let scope = self.resource_scope().await?;
        let key = approval_key(issue_id);
        self.client
            .get_kv(&scope.store_id, &key)
            .await?
            .map(|value| decode_approval_blob(&value.value).map_err(Into::into))
            .transpose()
    }

    async fn put_approval_blob(&self, issue_id: &IssueId, blob: &ApprovalBlob) -> Result<()> {
        let scope = self.resource_scope().await?;
        let key = approval_key(issue_id);
        let encoded = encode_approval_blob(blob)?;
        self.client
            .put_kv(&scope.store_id, &key, &encoded, SYMPHONY_JSON_CONTENT_TYPE)
            .await?;
        Ok(())
    }

    async fn put_claim_blob(&self, task_id: &str, blob: &ClaimBlob) -> Result<()> {
        let scope = self.resource_scope().await?;
        let key = claim_key(task_id);
        let encoded = encode_claim_blob(blob)?;
        self.client
            .put_kv(&scope.store_id, &key, &encoded, SYMPHONY_JSON_CONTENT_TYPE)
            .await?;
        Ok(())
    }

    async fn put_handoff_blob(&self, task_id: &str, blob: &HandoffBlob) -> Result<()> {
        let scope = self.resource_scope().await?;
        let key = handoff_key(task_id);
        let encoded = encode_handoff_blob(blob)?;
        self.client
            .put_kv(&scope.store_id, &key, &encoded, SYMPHONY_JSON_CONTENT_TYPE)
            .await?;
        Ok(())
    }

    async fn put_shard_blob(&self, task_id: &str, blob: &ShardBlob) -> Result<()> {
        let scope = self.resource_scope().await?;
        let key = shard_key(task_id);
        let encoded = encode_shard_blob(blob)?;
        self.client
            .put_kv(&scope.store_id, &key, &encoded, SYMPHONY_JSON_CONTENT_TYPE)
            .await?;
        Ok(())
    }

    async fn provenance_blob_for_task(&self, task_id: &str) -> Result<Option<ProvenanceBlob>> {
        let scope = self.resource_scope().await?;
        let key = provenance_key(task_id);
        self.client
            .get_kv(&scope.store_id, &key)
            .await?
            .map(|value| decode_provenance_blob(&value.value).map_err(Into::into))
            .transpose()
    }

    async fn put_provenance_blob(&self, task_id: &str, blob: &ProvenanceBlob) -> Result<()> {
        let scope = self.resource_scope().await?;
        let key = provenance_key(task_id);
        let encoded = encode_provenance_blob(blob)?;
        self.client
            .put_kv(&scope.store_id, &key, &encoded, SYMPHONY_JSON_CONTENT_TYPE)
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

    /// Ensure the configured `TaskList` and companion `KvStore` exist in x0xd.
    ///
    /// Creates both surfaces if missing. Idempotent: surfaces that already
    /// exist are left untouched. Respects group-scoped list and store ids
    /// when a group is configured.
    ///
    /// # Errors
    ///
    /// Returns [`TrackerError::Client`] when x0xd listing or creation fails.
    pub async fn ensure_surfaces(&self) -> Result<()> {
        let scope = self.resource_scope().await?;
        let task_lists = self.client.list_task_lists().await?;
        if !task_lists.iter().any(|entry| entry.id == scope.list_id) {
            info!(
                list_id = %scope.list_id,
                group_scoped = scope.group_scoped,
                "creating missing x0xd TaskList for symphony tracker"
            );
            self.client
                .create_task_list(&scope.list_id, &scope.list_id)
                .await?;
        }
        let stores = self.client.list_kv_stores().await?;
        if !stores.iter().any(|entry| entry.id == scope.store_id) {
            info!(
                store_id = %scope.store_id,
                "creating missing x0xd KvStore sidecar for symphony tracker"
            );
            self.client
                .create_kv_store(&scope.store_id, &scope.store_id)
                .await?;
        }
        Ok(())
    }

    async fn create_issue_with_shard(&self, draft: IssueDraft) -> Result<Issue> {
        if draft.title.trim().is_empty() {
            return Err(SymphonyError::validation("issue.title", "must not be empty").into());
        }
        let _ = draft_priority_as_u8(draft.priority)?;
        let provider = self.creation.worker_view.as_ref().ok_or_else(|| {
            SymphonyError::unsupported("this tracker does not own issue creation")
        })?;
        let snapshot = provider.snapshot().await;
        let now = now_utc();
        let workers = live_verified_worker_ids(&snapshot.cards, &now);
        if workers.is_empty() {
            return Err(SymphonyError::unsupported(
                "cannot assign shard: live worker view is empty; start at least one trusted worker",
            )
            .into());
        }

        let description = effective_description(draft.description.as_ref());
        let mut add_task = AddTaskDraft::new(draft.title.clone());
        if !description.is_empty() {
            add_task = add_task.with_description(description.clone());
        }
        let scope = self.resource_scope().await?;
        let task_id = self.client.add_task(&scope.list_id, add_task).await?;
        let issue_id = IssueId::new(task_id.clone())?;
        let shard = shard::assign_with_metadata(
            &issue_id,
            &workers,
            self.creation.replication_factor,
            shard::DEFAULT_CLAIM_TTL_MS,
            snapshot.view_epoch,
        )
        .ok_or_else(|| {
            SymphonyError::unsupported(
                "cannot assign shard: live worker view is empty; start at least one trusted worker",
            )
        })?;
        let mut sidecar_result = self
            .put_shard_blob(
                &task_id,
                &ShardBlob::new(shard, snapshot.view_epoch, now_utc()),
            )
            .await;
        if sidecar_result.is_ok() && self.signing.policy == SigningPolicy::Required {
            sidecar_result = self
                .sign_and_put_provenance(&task_id, &draft.title, &description)
                .await;
        }
        if let Err(error) = sidecar_result {
            warn!(
                task_id = %task_id,
                error = %error,
                "sidecar blob write failed; marking task terminal to avoid zombie"
            );
            if let Err(cleanup_error) = self
                .client
                .update_task(&scope.list_id, &task_id, TaskAction::Complete)
                .await
            {
                warn!(
                    task_id = %task_id,
                    error = %cleanup_error,
                    "failed to mark zombie task terminal; bare task remains in TaskList"
                );
            }
            return Err(error);
        }
        self.fetch_issue(&issue_id).await
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

    async fn sign_and_put_provenance(
        &self,
        task_id: &str,
        title: &str,
        description: &str,
    ) -> Result<()> {
        let payload = issue_provenance_payload(task_id, title, description);
        let response = self
            .signing
            .client()?
            .sign(ISSUE_PROVENANCE_CONTEXT, &payload)
            .await
            .map_err(signing_error)?;
        let envelope = envelope_from_sign_response(
            response,
            ISSUE_PROVENANCE_CONTEXT,
            &payload,
            &self.agent_id,
        )?;
        let blob = ProvenanceBlob::new(envelope);
        self.put_provenance_blob(task_id, &blob).await
    }

    async fn filter_verified_issues(&self, issues: Vec<Issue>) -> Result<Vec<Issue>> {
        if self.signing.policy == SigningPolicy::Disabled {
            return Ok(issues);
        }
        let mut verified = Vec::with_capacity(issues.len());
        for mut issue in issues {
            if let Some(claim) = issue.claim.clone() {
                match self.verify_claim(&issue, &claim).await {
                    Ok(()) => {}
                    Err(TrackerError::VerifyTransport { reason }) => {
                        return Err(TrackerError::VerifyTransport {
                            reason: format!("issue {}: {reason}", issue.id),
                        });
                    }
                    Err(error) => {
                        let reason = error.to_string();
                        warn!(
                            issue_id = %issue.id,
                            claimant = %claim.by,
                            error = %reason,
                            "stripping invalid claim from issue"
                        );
                        strip_bad_claim(&mut issue, &claim, reason)?;
                    }
                }
            }
            let handoff_ok = if let Some(handoff) = &issue.handoff {
                match self.verify_handoff(&issue, handoff).await {
                    Ok(()) => true,
                    Err(TrackerError::VerifyTransport { reason }) => {
                        return Err(TrackerError::VerifyTransport {
                            reason: format!("issue {}: {reason}", issue.id),
                        });
                    }
                    Err(error) => {
                        warn!(issue_id = %issue.id, error = %error, "dropping issue with invalid handoff signature");
                        false
                    }
                }
            } else {
                true
            };
            if handoff_ok {
                match self.verify_issue_provenance(&issue).await {
                    Ok(Some(signer)) => {
                        issue.signature_provenance = Some(SignatureProvenance::verified(signer));
                    }
                    Ok(None) => {}
                    Err(TrackerError::VerifyTransport { reason }) => {
                        return Err(TrackerError::VerifyTransport {
                            reason: format!("issue {}: {reason}", issue.id),
                        });
                    }
                    Err(error) => {
                        warn!(
                            issue_id = %issue.id,
                            error = %error,
                            "issue provenance verification failed; leaving unsigned"
                        );
                    }
                }
                verified.push(issue);
            }
        }
        Ok(verified)
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
        self.verify_envelope(&issue.id, envelope, CLAIM_CONTEXT, &payload)
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
        self.verify_envelope(&issue.id, envelope, HANDOFF_CONTEXT, &payload)
            .await
    }

    /// Verify issue creation provenance and return the verified signer id.
    ///
    /// Returns `Ok(None)` when no provenance blob is stored for this issue.
    async fn verify_issue_provenance(&self, issue: &Issue) -> Result<Option<String>> {
        let Some(blob) = self.provenance_blob_for_task(issue.id.as_str()).await? else {
            return Ok(None);
        };
        let payload = issue_provenance_payload(issue.id.as_str(), &issue.title, &issue.description);
        self.verify_envelope(
            &issue.id,
            &blob.envelope,
            ISSUE_PROVENANCE_CONTEXT,
            &payload,
        )
        .await?;
        Ok(Some(blob.envelope.signer_agent_id))
    }

    async fn verify_envelope(
        &self,
        issue_id: &IssueId,
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
        let cache_key = VerifyCacheKey {
            issue_id: issue_id.clone(),
            context: target_context.to_owned(),
            payload_sha256: actual_digest,
            signature_b64: envelope.signature_b64.clone(),
            public_key_b64: envelope.public_key_b64.clone(),
            signer_agent_id: envelope.signer_agent_id.clone(),
        };
        if let Some(outcome) = self.cached_verify_outcome(&cache_key) {
            return verify_outcome_to_result(outcome);
        }
        let outcome = self
            .signing
            .client()?
            .verify(target_context, payload, &signature, &envelope_key)
            .await
            .map_err(signing_error)?;
        if !matches!(outcome, VerifyOutcome::TransportError(_)) {
            self.cache_verify_outcome(cache_key, outcome.clone());
        }
        verify_outcome_to_result(outcome)
    }

    fn cached_verify_outcome(&self, key: &VerifyCacheKey) -> Option<VerifyOutcome> {
        let cache = self.verify_cache.lock().ok()?;
        cache.get(key).cloned()
    }

    fn cache_verify_outcome(&self, key: VerifyCacheKey, outcome: VerifyOutcome) {
        if let Ok(mut cache) = self.verify_cache.lock() {
            cache.insert(key, outcome);
        }
    }
}

fn strip_bad_claim(issue: &mut Issue, claim: &Claim, reason: String) -> Result<()> {
    issue.claim = None;
    if issue.state.as_str() == "in_progress" {
        issue.state = IssueState::new("todo")?;
    }
    issue.verification_notices.push(VerificationNotice {
        kind: VerificationNoticeKind::BadClaim,
        claimant: Some(claim.by.clone()),
        reason,
    });
    Ok(())
}

fn verify_outcome_to_result(outcome: VerifyOutcome) -> Result<()> {
    match outcome {
        VerifyOutcome::Valid => Ok(()),
        VerifyOutcome::Invalid(reason) => Err(TrackerError::Signing(format!(
            "x0xd verify rejected signature: {reason}"
        ))),
        VerifyOutcome::TransportError(reason) => Err(TrackerError::VerifyTransport { reason }),
    }
}

#[async_trait]
impl Tracker for X0xCrdtTracker {
    async fn list_issues(&self) -> x0x_symphony_core::Result<Vec<Issue>> {
        X0xCrdtTracker::list_issues(self)
            .await
            .map_err(SymphonyError::from)
    }

    async fn create_issue(&self, draft: IssueDraft) -> x0x_symphony_core::Result<Issue> {
        self.create_issue_with_shard(draft)
            .await
            .map_err(SymphonyError::from)
    }

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
        let scope = self.resource_scope().await.map_err(SymphonyError::from)?;
        self.client
            .update_task(&scope.list_id, id.as_str(), TaskAction::Claim)
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
        let scope = self.resource_scope().await.map_err(SymphonyError::from)?;
        self.client
            .update_task(&scope.list_id, id.as_str(), TaskAction::Complete)
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

    async fn requeue_blocked(
        &self,
        issue_id: &IssueId,
        reason: ReleaseReason,
    ) -> x0x_symphony_core::Result<()> {
        let blob = self
            .claim_blob_for_task(issue_id.as_str())
            .await
            .map_err(SymphonyError::from)?
            .ok_or_else(|| TrackerError::InvalidClaim {
                reason: format!("issue {issue_id} has no claim blob"),
            })
            .map_err(SymphonyError::from)?;
        if blob.status != ClaimBlobStatus::Blocked {
            return Err(SymphonyError::from(TrackerError::InvalidClaim {
                reason: format!(
                    "issue {issue_id} claim status is {:?}, not Blocked",
                    blob.status
                ),
            }));
        }
        // Releasing the blocked claim reconstructs the issue as `todo`, which
        // returns it to the orchestrator's candidate scan.
        self.put_claim_blob(
            issue_id.as_str(),
            &ClaimBlob::released(blob.claim, reason, now_utc()),
        )
        .await
        .map_err(SymphonyError::from)
    }

    async fn load_approval_state(
        &self,
        issue_id: &IssueId,
    ) -> x0x_symphony_core::Result<ApprovalState> {
        let Some(blob) = self
            .approval_blob_for_issue(issue_id)
            .await
            .map_err(SymphonyError::from)?
        else {
            return Ok(ApprovalState::default());
        };
        Ok(ApprovalState {
            events: blob.events,
            consumed: blob.consumed,
        })
    }

    async fn store_approval(&self, event: &ApprovalEvent) -> x0x_symphony_core::Result<()> {
        let mut blob = match self
            .approval_blob_for_issue(&event.issue_id)
            .await
            .map_err(SymphonyError::from)?
        {
            Some(blob) => blob,
            None => ApprovalBlob::new(event.issue_id.clone(), now_utc()),
        };
        blob.events.push(event.clone());
        blob.updated_at = now_utc();
        self.put_approval_blob(&event.issue_id, &blob)
            .await
            .map_err(SymphonyError::from)
    }

    async fn store_consumed(&self, event: &ApprovalConsumed) -> x0x_symphony_core::Result<()> {
        let mut blob = match self
            .approval_blob_for_issue(&event.issue_id)
            .await
            .map_err(SymphonyError::from)?
        {
            Some(blob) => blob,
            None => ApprovalBlob::new(event.issue_id.clone(), now_utc()),
        };
        blob.consumed.push(event.clone());
        blob.updated_at = now_utc();
        self.put_approval_blob(&event.issue_id, &blob)
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

fn group_scoped_list_id(group_id: &str, list_id: &str) -> String {
    format!("x0x.group.{group_id}.symphony.{list_id}")
}

fn looks_like_group_invite(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("x0x://invite/")
        || (trimmed.len() > 80 && !trimmed.chars().any(char::is_whitespace))
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

fn draft_priority_as_u8(priority: Option<i32>) -> Result<Option<u8>> {
    priority
        .map(|value| {
            u8::try_from(value).map_err(|_error| {
                SymphonyError::validation("issue.priority", "must be between 0 and 255").into()
            })
        })
        .transpose()
}

/// Build the deterministic signing payload for issue creation provenance.
///
/// The payload is a canonical JSON object with sorted keys: `description`,
/// `issue_id`, and `title`. The exact same fields are reconstructed on read
/// from the assembled [`Issue`] so the stored signature verifies.
fn issue_provenance_payload(task_id: &str, title: &str, description: &str) -> Vec<u8> {
    use std::collections::BTreeMap;
    let mut payload: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    payload.insert(
        "description",
        serde_json::Value::String(description.to_owned()),
    );
    payload.insert("issue_id", serde_json::Value::String(task_id.to_owned()));
    payload.insert("title", serde_json::Value::String(title.to_owned()));
    // Serializing a map of String JSON values cannot fail in practice.
    serde_json::to_vec(&payload).unwrap_or_default()
}

/// Return the description value that will be stored on the x0xd task entry.
///
/// Whitespace-only descriptions are normalised to empty so the signing payload
/// matches what `issue_from_task` reads back.
fn effective_description(description: Option<&String>) -> String {
    description
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_default()
}

fn live_verified_worker_ids(cards: &[WorkerCard], now: &str) -> Vec<AgentId> {
    cards
        .iter()
        .filter(|card| card.schema_version == WORKER_CARD_SCHEMA_VERSION)
        .filter(|card| !card.is_expired(now))
        .filter(|card| worker_card_has_verified_signature_marker(card))
        .map(|card| card.agent_id.clone())
        .collect()
}

fn worker_card_has_verified_signature_marker(card: &WorkerCard) -> bool {
    card.signature.as_ref().is_some_and(|signature| {
        signature.algorithm == SIGN_ALGORITHM
            && signature.context == WORKER_CARD_CONTEXT
            && signature.signer_agent_id == card.agent_id.as_str()
            && card
                .signing_payload_sha256()
                .is_ok_and(|digest| digest == signature.payload_sha256)
    })
}

fn now_utc() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, error::Error};

    use async_trait::async_trait;
    use tokio::sync::Mutex;
    use x0x_symphony_core::{
        ReleaseReasonCode, ValidationResult, ValidationStatus, VerificationNoticeKind,
    };

    use super::*;
    use crate::{
        client::{
            EventStream, JoinedGroup, KvKeyEntry, KvValue, NamedGroupDetails, NamedGroupEntry,
            NamedGroupMember, TaskEntry, TaskListEntry, X0xdEvent,
        },
        mapping::{decode_claim_blob, decode_handoff_blob, decode_shard_blob, SHARD_BLOB_KIND},
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
        groups: Vec<NamedGroupDetails>,
        joins: Vec<String>,
        list_task_calls: Vec<String>,
        hidden_list_ids: Vec<String>,
        /// When true, `list_task_lists`/`list_kv_stores` return empty to
        /// simulate missing surfaces.
        surfaces_missing: bool,
        /// Topics passed to `create_task_list`.
        created_lists: Vec<String>,
        /// Topics passed to `create_kv_store`.
        created_stores: Vec<String>,
        /// When true, `put_kv` returns a synthetic HTTP 500.
        put_kv_failing: bool,
    }

    impl MockApi {
        async fn with_tasks(tasks: Vec<TaskEntry>) -> Arc<Self> {
            let api = Arc::new(Self::default());
            api.state.lock().await.tasks = tasks;
            api
        }

        async fn add_group(&self, group_id: &str, name: &str) {
            self.state.lock().await.groups.push(NamedGroupDetails {
                group_id: group_id.to_owned(),
                name: name.to_owned(),
                members: vec![NamedGroupMember {
                    agent_id: AGENT_A.to_owned(),
                    state: Some("active".to_owned()),
                }],
            });
        }

        async fn join_count(&self) -> usize {
            self.state.lock().await.joins.len()
        }

        async fn list_task_calls(&self) -> Vec<String> {
            self.state.lock().await.list_task_calls.clone()
        }

        async fn hide_task_list(&self, list_id: &str) {
            self.state
                .lock()
                .await
                .hidden_list_ids
                .push(list_id.to_owned());
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

        async fn seed_handoff(&self, task_id: &str, handoff: Handoff) -> TestResult {
            let blob = HandoffBlob::new(handoff, "2026-07-03T02:00:00Z");
            let key = handoff_key(task_id);
            self.state.lock().await.kv.insert(
                (store_id_for_list("list-a"), key),
                encode_handoff_blob(&blob)?,
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

        async fn shard_blob(&self, task_id: &str) -> TestResult<ShardBlob> {
            let key = (store_id_for_list("list-a"), shard_key(task_id));
            let state = self.state.lock().await;
            let bytes = state
                .kv
                .get(&key)
                .ok_or_else(|| std::io::Error::other("missing shard blob"))?;
            Ok(decode_shard_blob(bytes)?)
        }

        async fn task_count(&self) -> usize {
            self.state.lock().await.tasks.len()
        }

        async fn put_count(&self) -> usize {
            self.state.lock().await.puts.len()
        }

        async fn set_surfaces_missing(&self, missing: bool) {
            self.state.lock().await.surfaces_missing = missing;
        }

        async fn set_put_kv_failing(&self, failing: bool) {
            self.state.lock().await.put_kv_failing = failing;
        }

        async fn created_lists(&self) -> Vec<String> {
            self.state.lock().await.created_lists.clone()
        }

        async fn created_stores(&self) -> Vec<String> {
            self.state.lock().await.created_stores.clone()
        }
    }

    #[async_trait]
    impl X0xdApi for MockApi {
        async fn list_task_lists(&self) -> client::Result<Vec<TaskListEntry>> {
            let state = self.state.lock().await;
            if state.surfaces_missing {
                return Ok(Vec::new());
            }
            Ok(vec![TaskListEntry {
                id: "list-a".to_owned(),
                topic: "list-a".to_owned(),
            }])
        }

        async fn create_task_list(&self, _name: &str, topic: &str) -> client::Result<String> {
            self.state.lock().await.created_lists.push(topic.to_owned());
            Ok(topic.to_owned())
        }

        async fn list_named_groups(&self) -> client::Result<Vec<NamedGroupEntry>> {
            Ok(self
                .state
                .lock()
                .await
                .groups
                .iter()
                .map(|group| NamedGroupEntry {
                    group_id: group.group_id.clone(),
                    name: group.name.clone(),
                })
                .collect())
        }

        async fn get_named_group(&self, group_id: &str) -> client::Result<NamedGroupDetails> {
            self.state
                .lock()
                .await
                .groups
                .iter()
                .find(|group| group.group_id == group_id)
                .cloned()
                .ok_or_else(|| ClientError::Http {
                    status: StatusCode::NOT_FOUND,
                    body: "group not found".to_owned(),
                })
        }

        async fn join_group(
            &self,
            invite: &str,
            _display_name: Option<&str>,
        ) -> client::Result<JoinedGroup> {
            let mut state = self.state.lock().await;
            state.joins.push(invite.to_owned());
            let group = NamedGroupDetails {
                group_id: "group-a".to_owned(),
                name: "joined group".to_owned(),
                members: vec![NamedGroupMember {
                    agent_id: AGENT_A.to_owned(),
                    state: Some("active".to_owned()),
                }],
            };
            state.groups.push(group.clone());
            Ok(JoinedGroup {
                group_id: group.group_id,
                group_name: Some(group.name),
            })
        }

        async fn list_tasks(&self, list_id: &str) -> client::Result<Vec<TaskEntry>> {
            let mut state = self.state.lock().await;
            state.list_task_calls.push(list_id.to_owned());
            if state.hidden_list_ids.iter().any(|hidden| hidden == list_id) {
                return Err(ClientError::Http {
                    status: StatusCode::NOT_FOUND,
                    body: "hidden by group membership".to_owned(),
                });
            }
            Ok(state.tasks.clone())
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
            let state = self.state.lock().await;
            if state.surfaces_missing {
                return Ok(Vec::new());
            }
            Ok(vec![TaskListEntry {
                id: store_id_for_list("list-a"),
                topic: store_id_for_list("list-a"),
            }])
        }

        async fn create_kv_store(&self, _name: &str, topic: &str) -> client::Result<String> {
            self.state
                .lock()
                .await
                .created_stores
                .push(topic.to_owned());
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
            if state.put_kv_failing {
                return Err(ClientError::Http {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    body: "store not found".to_owned(),
                });
            }
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

    #[derive(Default)]
    struct MockWorkerView {
        snapshots: Mutex<Vec<WorkerViewSnapshot>>,
        calls: Mutex<usize>,
    }

    impl MockWorkerView {
        fn new(snapshots: Vec<WorkerViewSnapshot>) -> Arc<Self> {
            Arc::new(Self {
                snapshots: Mutex::new(snapshots),
                calls: Mutex::new(0),
            })
        }

        async fn calls(&self) -> usize {
            *self.calls.lock().await
        }
    }

    #[async_trait]
    impl WorkerViewProvider for MockWorkerView {
        async fn snapshot(&self) -> WorkerViewSnapshot {
            let mut calls = self.calls.lock().await;
            *calls = calls.saturating_add(1);
            drop(calls);
            let mut snapshots = self.snapshots.lock().await;
            if snapshots.is_empty() {
                WorkerViewSnapshot {
                    cards: Vec::new(),
                    view_epoch: 0,
                }
            } else {
                snapshots.remove(0)
            }
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

    fn grouped_tracker(api: Arc<MockApi>, group: &str) -> TestResult<X0xCrdtTracker> {
        Ok(
            X0xCrdtTracker::builder("mock://x0xd", "list-a", AgentId::new(AGENT_A)?)
                .client(api)
                .group(group)
                .build()?,
        )
    }

    fn tracker_with_worker_view(
        api: Arc<MockApi>,
        provider: Arc<dyn WorkerViewProvider>,
    ) -> TestResult<X0xCrdtTracker> {
        Ok(
            X0xCrdtTracker::builder("mock://x0xd", "list-a", AgentId::new(AGENT_A)?)
                .client(api)
                .worker_view(provider)
                .replication_factor(shard::DEFAULT_REPLICATION_FACTOR)
                .build()?,
        )
    }

    fn required_tracker(
        api: Arc<MockApi>,
        signing: Arc<MockSigning>,
    ) -> TestResult<X0xCrdtTracker> {
        let signing_client: Arc<dyn SigningClient> = signing.clone();
        let resolver: Arc<dyn TrustedKeyResolver> = signing;
        Ok(
            X0xCrdtTracker::builder("mock://x0xd", "list-a", AgentId::new(AGENT_A)?)
                .client(api)
                .required_signing(signing_client, resolver)
                .build()?,
        )
    }

    fn claim_for(task_id: &str, agent: &str) -> TestResult<Claim> {
        Ok(Claim::new(
            Some(IssueId::new(task_id)?),
            AgentId::new(agent)?,
            "2026-07-03T01:00:00Z",
            ShardRole::ManualM1,
        ))
    }

    fn worker_card(agent: &str) -> TestResult<WorkerCard> {
        let agent_id = AgentId::new(agent)?;
        let mut card = WorkerCard {
            schema_version: WORKER_CARD_SCHEMA_VERSION,
            agent_id: agent_id.clone(),
            issued_at: "2099-07-03T12:00:00Z".to_owned(),
            ttl_seconds: 60,
            capabilities: vec!["rust".to_owned()],
            sandbox_levels: vec!["repo-write".to_owned()],
            runner_presets: vec!["shell".to_owned()],
            current_load: 0,
            max_load: 2,
            platform: x0x_symphony_core::PlatformInfo {
                os: "linux".to_owned(),
                arch: "x86_64".to_owned(),
                version: "0.0.0".to_owned(),
            },
            signature: None,
        };
        let payload_sha256 = card.signing_payload_sha256()?;
        card.signature = Some(SignatureEnvelope::new(
            SIGN_ALGORITHM,
            WORKER_CARD_CONTEXT,
            BASE64.encode(format!("{agent}-public-key")),
            BASE64.encode(format!("{agent}-signature")),
            payload_sha256,
            agent_id.to_string(),
        ));
        Ok(card)
    }

    fn worker_snapshot(agents: &[&str], view_epoch: u64) -> TestResult<WorkerViewSnapshot> {
        Ok(WorkerViewSnapshot {
            cards: agents
                .iter()
                .map(|agent| worker_card(agent))
                .collect::<TestResult<Vec<_>>>()?,
            view_epoch,
        })
    }

    fn issue_draft(title: &str) -> IssueDraft {
        IssueDraft {
            title: title.to_owned(),
            description: Some("created by test".to_owned()),
            priority: Some(2),
            labels: vec!["x0x-symphony".to_owned()],
        }
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
    async fn create_issue_assigns_live_worker_shard_and_writes_sidecar() -> TestResult {
        let api = MockApi::with_tasks(Vec::new()).await;
        let provider = MockWorkerView::new(vec![worker_snapshot(
            &["agent-a", "agent-b", "agent-c", "agent-d"],
            42,
        )?]);
        let tracker = tracker_with_worker_view(api.clone(), provider)?;

        let issue = tracker.create_issue(issue_draft("Live shard")).await?;

        let workers = ["agent-a", "agent-b", "agent-c", "agent-d"]
            .iter()
            .map(|agent| AgentId::new(*agent))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let expected = shard::assign_with_metadata(
            &IssueId::new(ISSUE_A)?,
            &workers,
            shard::DEFAULT_REPLICATION_FACTOR,
            shard::DEFAULT_CLAIM_TTL_MS,
            42,
        )
        .ok_or_else(|| std::io::Error::other("expected non-empty worker assignment"))?;
        assert_eq!(issue.id, IssueId::new(ISSUE_A)?);
        assert_eq!(issue.shard.as_ref(), Some(&expected));
        let blob = api.shard_blob(ISSUE_A).await?;
        assert_eq!(blob.kind, SHARD_BLOB_KIND);
        assert_eq!(blob.created_view_epoch, 42);
        assert_eq!(blob.shard, expected);
        Ok(())
    }

    #[tokio::test]
    async fn create_issue_empty_worker_view_fails_without_creating_task() -> TestResult {
        let api = MockApi::with_tasks(Vec::new()).await;
        let provider = MockWorkerView::new(vec![WorkerViewSnapshot {
            cards: Vec::new(),
            view_epoch: 7,
        }]);
        let tracker = tracker_with_worker_view(api.clone(), provider)?;

        let result = tracker.create_issue(issue_draft("No workers")).await;

        let Err(error) = result else {
            return Err(std::io::Error::other("empty view should fail").into());
        };
        assert!(error.to_string().contains("live worker view is empty"));
        assert_eq!(api.task_count().await, 0);
        assert_eq!(api.put_count().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn create_issue_uses_one_worker_snapshot_during_view_churn() -> TestResult {
        let api = MockApi::with_tasks(Vec::new()).await;
        let provider = MockWorkerView::new(vec![
            worker_snapshot(&["agent-a", "agent-b", "agent-c"], 11)?,
            worker_snapshot(&["agent-d", "agent-e", "agent-f"], 12)?,
        ]);
        let tracker = tracker_with_worker_view(api.clone(), provider.clone())?;

        let issue = tracker.create_issue(issue_draft("Stable snapshot")).await?;

        assert_eq!(provider.calls().await, 1);
        assert_eq!(
            issue.shard.as_ref().map(|shard| shard.created_view_epoch),
            Some(11)
        );
        let blob = api.shard_blob(ISSUE_A).await?;
        assert_eq!(blob.created_view_epoch, 11);
        Ok(())
    }

    fn required_tracker_with_workers(
        api: Arc<MockApi>,
        signing: Arc<MockSigning>,
        provider: Arc<MockWorkerView>,
    ) -> TestResult<X0xCrdtTracker> {
        let signing_client: Arc<dyn SigningClient> = signing.clone();
        let resolver: Arc<dyn TrustedKeyResolver> = signing;
        Ok(
            X0xCrdtTracker::builder("mock://x0xd", "list-a", AgentId::new(AGENT_A)?)
                .client(api)
                .worker_view(provider)
                .replication_factor(shard::DEFAULT_REPLICATION_FACTOR)
                .required_signing(signing_client, resolver)
                .build()?,
        )
    }

    fn valid_signing() -> Arc<MockSigning> {
        Arc::new(MockSigning {
            verify_outcome: VerifyOutcome::Valid,
            public_key: b"trusted-key".to_vec(),
        })
    }

    /// Locally-created issues MUST carry verified signature provenance when
    /// signing is Required, so the dispatch gate treats them as cryptographically
    /// attested rather than blocking them as unsigned network-sourced issues.
    #[tokio::test]
    async fn create_issue_with_required_signing_attaches_verified_provenance() -> TestResult {
        let api = MockApi::with_tasks(Vec::new()).await;
        let provider = MockWorkerView::new(vec![worker_snapshot(
            &["agent-a", "agent-b", "agent-c"],
            1,
        )?]);
        let tracker = required_tracker_with_workers(api, valid_signing(), provider)?;

        let issue = tracker.create_issue(issue_draft("Provenance test")).await?;

        // The returned issue carries verified provenance from the read-back path.
        assert_eq!(
            issue.signature_provenance,
            Some(SignatureProvenance::verified(AGENT_A))
        );

        // Re-reading confirms the provenance is stable across fetches.
        let reloaded = tracker.list_issues().await?;
        assert_eq!(reloaded.len(), 1);
        assert_eq!(
            reloaded[0].signature_provenance,
            Some(SignatureProvenance::verified(AGENT_A))
        );
        Ok(())
    }

    /// Issues without a provenance blob (arrived from the network or created
    /// before provenance support) MUST have no verified provenance under
    /// Required signing. The dispatch gate will then refuse them as unsigned.
    #[tokio::test]
    async fn unsigned_issue_has_no_provenance_under_required_signing() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "unsigned", "empty", 3)]).await;
        let provider = MockWorkerView::new(vec![worker_snapshot(
            &["agent-a", "agent-b", "agent-c"],
            1,
        )?]);
        let tracker = required_tracker_with_workers(api, valid_signing(), provider)?;

        let issues = tracker.list_issues().await?;
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].signature_provenance.is_none(),
            "unsigned issue must not gain provenance"
        );
        Ok(())
    }

    #[tokio::test]
    async fn fetch_candidates_does_not_assign_missing_shards_on_read_path() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "unsharded", "empty", 3)]).await;
        let provider = MockWorkerView::new(vec![worker_snapshot(
            &["agent-a", "agent-b", "agent-c"],
            99,
        )?]);
        let tracker = tracker_with_worker_view(api.clone(), provider)?;
        let ctx = PollContext::new(
            vec![IssueState::new("todo")?],
            vec![IssueState::new("done")?],
        );

        let candidates = tracker.fetch_candidates(&ctx).await?;

        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].shard.is_none());
        assert_eq!(api.put_count().await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn group_invite_is_joined_on_first_fetch_and_scopes_task_list() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "grouped", "empty", 3)]).await;
        let tracker = grouped_tracker(api.clone(), "x0x://invite/test-token")?;
        let ctx = PollContext::new(
            vec![IssueState::new("todo")?],
            vec![IssueState::new("done")?],
        );

        let candidates = tracker.fetch_candidates(&ctx).await?;

        assert_eq!(api.join_count().await, 1);
        assert_eq!(
            api.list_task_calls().await,
            vec![group_scoped_list_id("group-a", "list-a")]
        );
        assert_eq!(candidates.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn group_name_resolves_without_rejoining() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "grouped", "empty", 3)]).await;
        api.add_group("group-b", "project-alpha").await;
        let tracker = grouped_tracker(api.clone(), "project-alpha")?;
        let ctx = PollContext::new(
            vec![IssueState::new("todo")?],
            vec![IssueState::new("done")?],
        );

        let candidates = tracker.fetch_candidates(&ctx).await?;

        assert_eq!(api.join_count().await, 0);
        assert_eq!(
            api.list_task_calls().await,
            vec![group_scoped_list_id("group-b", "list-a")]
        );
        assert_eq!(candidates.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn group_hidden_task_list_returns_zero_candidates() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "hidden", "empty", 3)]).await;
        api.add_group("group-c", "project-charlie").await;
        api.hide_task_list(&group_scoped_list_id("group-c", "list-a"))
            .await;
        let tracker = grouped_tracker(api, "project-charlie")?;
        let ctx = PollContext::new(
            vec![IssueState::new("todo")?],
            vec![IssueState::new("done")?],
        );

        let candidates = tracker.fetch_candidates(&ctx).await?;

        assert!(candidates.is_empty());
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

    #[derive(Clone)]
    struct MockSigning {
        verify_outcome: VerifyOutcome,
        public_key: Vec<u8>,
    }

    #[async_trait]
    impl SigningClient for MockSigning {
        async fn sign(
            &self,
            context: &str,
            _payload: &[u8],
        ) -> x0x_symphony_signing::Result<SignResponse> {
            Ok(SignResponse {
                agent_id: AGENT_A.to_owned(),
                public_key_b64: BASE64.encode(&self.public_key),
                signature_b64: BASE64.encode(b"mock-signature"),
                algorithm: SIGN_ALGORITHM.to_owned(),
                context: context.to_owned(),
            })
        }

        async fn verify(
            &self,
            _context: &str,
            _payload: &[u8],
            _signature: &[u8],
            _public_key: &[u8],
        ) -> x0x_symphony_signing::Result<VerifyOutcome> {
            Ok(self.verify_outcome.clone())
        }

        async fn agent_identity(
            &self,
        ) -> x0x_symphony_signing::Result<x0x_symphony_signing::AgentInfo> {
            Ok(x0x_symphony_signing::AgentInfo {
                agent_id: AGENT_A.to_owned(),
            })
        }
    }

    #[async_trait]
    impl TrustedKeyResolver for MockSigning {
        async fn resolve(&self, _agent_id: &str) -> x0x_symphony_signing::Result<Vec<u8>> {
            Ok(self.public_key.clone())
        }
    }

    fn signed_claim_for(task_id: &str, agent: &str, public_key: &[u8]) -> TestResult<Claim> {
        let mut claim = claim_for(task_id, agent)?;
        let payload = claim.signing_payload_bytes()?;
        claim.signature = Some(SignatureEnvelope::new(
            SIGN_ALGORITHM,
            CLAIM_CONTEXT,
            BASE64.encode(public_key),
            BASE64.encode(b"signature"),
            sha256_hex(&payload),
            agent,
        ));
        Ok(claim)
    }

    fn signed_handoff_for(task_id: &str, agent: &str, public_key: &[u8]) -> TestResult<Handoff> {
        let mut handoff = Handoff::new("ready")
            .with_issue_id(IssueId::new(task_id)?)
            .with_signer_agent_id(agent);
        let payload = handoff.signing_payload_bytes()?;
        handoff.signature = Some(SignatureEnvelope::new(
            SIGN_ALGORITHM,
            HANDOFF_CONTEXT,
            BASE64.encode(public_key),
            BASE64.encode(b"signature"),
            sha256_hex(&payload),
            agent,
        ));
        Ok(handoff)
    }

    fn assert_bad_claim_notice(issue: &Issue, reason: &str) -> TestResult {
        assert_eq!(issue.verification_notices.len(), 1);
        let notice = &issue.verification_notices[0];
        assert_eq!(notice.kind, VerificationNoticeKind::BadClaim);
        assert_eq!(notice.claimant, Some(AgentId::new(AGENT_A)?));
        assert!(
            notice.reason.contains(reason),
            "notice reason {:?} did not contain {reason:?}",
            notice.reason
        );
        Ok(())
    }

    #[tokio::test]
    async fn bad_signature_claim_strips_claim_and_keeps_issue_visible() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "forged", "claimed:agent-a", 3)]).await;
        let public_key = b"trusted-key".to_vec();
        api.seed_claim(ISSUE_A, signed_claim_for(ISSUE_A, AGENT_A, &public_key)?)
            .await?;
        let tracker = required_tracker(
            api,
            Arc::new(MockSigning {
                verify_outcome: VerifyOutcome::Invalid("forged claim".to_owned()),
                public_key,
            }),
        )?;
        let ctx = PollContext::new(
            vec![IssueState::new("todo")?],
            vec![IssueState::new("done")?],
        );

        let candidates = tracker.fetch_candidates(&ctx).await?;
        let fetched = tracker.fetch_by_ids(&[IssueId::new(ISSUE_A)?]).await?;

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id, IssueId::new(ISSUE_A)?);
        assert_eq!(candidates[0].state, IssueState::new("todo")?);
        assert!(candidates[0].claim.is_none());
        assert_bad_claim_notice(&candidates[0], "forged claim")?;
        assert_eq!(fetched.len(), 1);
        assert!(fetched[0].claim.is_none());
        assert_eq!(fetched[0].state, IssueState::new("todo")?);
        assert_bad_claim_notice(&fetched[0], "forged claim")?;
        Ok(())
    }

    #[tokio::test]
    async fn unsigned_claim_strips_claim_and_keeps_issue_visible() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "unsigned", "claimed:agent-a", 3)]).await;
        api.seed_claim(ISSUE_A, claim_for(ISSUE_A, AGENT_A)?)
            .await?;
        let tracker = required_tracker(
            api,
            Arc::new(MockSigning {
                verify_outcome: VerifyOutcome::Valid,
                public_key: b"trusted-key".to_vec(),
            }),
        )?;
        let ctx = PollContext::new(
            vec![IssueState::new("todo")?],
            vec![IssueState::new("done")?],
        );

        let candidates = tracker.fetch_candidates(&ctx).await?;
        let fetched = tracker.fetch_by_ids(&[IssueId::new(ISSUE_A)?]).await?;

        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].claim.is_none());
        assert_eq!(candidates[0].state, IssueState::new("todo")?);
        assert_bad_claim_notice(&candidates[0], "unsigned")?;
        assert_eq!(fetched.len(), 1);
        assert!(fetched[0].claim.is_none());
        assert_eq!(fetched[0].state, IssueState::new("todo")?);
        assert_bad_claim_notice(&fetched[0], "unsigned")?;
        Ok(())
    }

    #[tokio::test]
    async fn valid_claim_remains_unchanged() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "valid", "claimed:agent-a", 3)]).await;
        let public_key = b"trusted-key".to_vec();
        api.seed_claim(ISSUE_A, signed_claim_for(ISSUE_A, AGENT_A, &public_key)?)
            .await?;
        let tracker = required_tracker(
            api,
            Arc::new(MockSigning {
                verify_outcome: VerifyOutcome::Valid,
                public_key,
            }),
        )?;

        let fetched = tracker.fetch_by_ids(&[IssueId::new(ISSUE_A)?]).await?;

        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].state, IssueState::new("in_progress")?);
        assert_eq!(
            fetched[0].claim.as_ref().map(|claim| &claim.by),
            Some(&AgentId::new(AGENT_A)?)
        );
        assert!(fetched[0].verification_notices.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn invalid_handoff_still_drops_issue() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "handoff", "done:agent-a", 3)]).await;
        let public_key = b"trusted-key".to_vec();
        api.seed_handoff(ISSUE_A, signed_handoff_for(ISSUE_A, AGENT_A, &public_key)?)
            .await?;
        let tracker = required_tracker(
            api,
            Arc::new(MockSigning {
                verify_outcome: VerifyOutcome::Invalid("forged handoff".to_owned()),
                public_key,
            }),
        )?;

        let fetched = tracker.fetch_by_ids(&[IssueId::new(ISSUE_A)?]).await?;

        assert!(fetched.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn disabled_signing_keeps_everything() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "disabled", "claimed:agent-a", 3)]).await;
        api.seed_claim(ISSUE_A, claim_for(ISSUE_A, AGENT_A)?)
            .await?;
        let tracker = tracker(api)?;

        let fetched = tracker.fetch_by_ids(&[IssueId::new(ISSUE_A)?]).await?;

        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].state, IssueState::new("in_progress")?);
        assert!(fetched[0].claim.is_some());
        assert!(fetched[0].verification_notices.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn verify_transport_error_surfaces_from_required_signing() -> TestResult {
        let api = MockApi::with_tasks(vec![task(ISSUE_A, "signed", "claimed:agent-a", 3)]).await;
        let public_key = b"trusted-key".to_vec();
        let claim = signed_claim_for(ISSUE_A, AGENT_A, &public_key)?;
        api.seed_claim(ISSUE_A, claim).await?;
        let signing = Arc::new(MockSigning {
            verify_outcome: VerifyOutcome::TransportError("x0xd unavailable".to_owned()),
            public_key,
        });
        let signing_client: Arc<dyn SigningClient> = signing.clone();
        let resolver: Arc<dyn TrustedKeyResolver> = signing;
        let tracker = X0xCrdtTracker::builder("mock://x0xd", "list-a", AgentId::new(AGENT_A)?)
            .client(api)
            .required_signing(signing_client, resolver)
            .build()?;

        let result = tracker.fetch_by_ids(&[IssueId::new(ISSUE_A)?]).await;
        let Err(error) = result else {
            return Err(std::io::Error::other("verify transport failure must surface").into());
        };

        assert!(
            error
                .to_string()
                .contains("signature verification transport error"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn ensure_surfaces_creates_missing_surfaces() -> TestResult {
        let api = MockApi::with_tasks(Vec::new()).await;
        api.set_surfaces_missing(true).await;
        let tracker = tracker(api.clone())?;

        tracker.ensure_surfaces().await?;

        let created_lists = api.created_lists().await;
        let created_stores = api.created_stores().await;
        assert_eq!(created_lists, vec!["list-a".to_owned()]);
        assert_eq!(created_stores, vec![store_id_for_list("list-a")]);
        Ok(())
    }

    #[tokio::test]
    async fn ensure_surfaces_idempotent_when_surfaces_exist() -> TestResult {
        let api = MockApi::with_tasks(Vec::new()).await;
        let tracker = tracker(api.clone())?;

        tracker.ensure_surfaces().await?;

        // Default mock already lists list-a and symphony-list-a, so nothing
        // should have been created.
        assert!(api.created_lists().await.is_empty());
        assert!(api.created_stores().await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn create_issue_marks_task_terminal_on_shard_write_failure() -> TestResult {
        let api = MockApi::with_tasks(Vec::new()).await;
        api.set_put_kv_failing(true).await;
        let provider = MockWorkerView::new(vec![worker_snapshot(
            &["agent-a", "agent-b", "agent-c"],
            1,
        )?]);
        let tracker = tracker_with_worker_view(api.clone(), provider)?;

        let result = tracker.create_issue(issue_draft("Zombie test")).await;
        assert!(
            result.is_err(),
            "create_issue should fail when put_kv fails"
        );

        // The bare task was added but should have been marked terminal.
        let completes = api.action_count(TaskAction::Complete).await;
        assert_eq!(
            completes, 1,
            "task should have been completed (marked terminal) to avoid zombie"
        );
        Ok(())
    }
}
