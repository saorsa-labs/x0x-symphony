//! Axum HTTP API for the local x0x-symphony daemon.

use std::{
    convert::Infallible,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    extract::{OriginalUri, Path as AxumPath, Query, State},
    http::{
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
        HeaderMap, Method, Request, StatusCode,
    },
    middleware,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use futures_util::{stream, Stream};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::{sync::broadcast, time};
use x0x_symphony_core::{
    approval_decision, constant_time_eq, content_hash, sha256_hex, AgentId, ApprovalDecision,
    ApprovalEvent, ApprovalState, ApprovalVerdict, Claim, Handoff, Issue, IssueDraft, IssueId,
    IssueSource, ReleaseReason, ReleaseReasonCode, SignatureEnvelope, SignatureProvenance, Tracker,
    VerificationNotice, WorkerCard, APPROVAL_CONTEXT, SIGN_ALGORITHM,
};
use x0x_symphony_signing::SigningClient;
use x0x_symphony_tracker_x0x_crdt::WorkerViewProvider;

const AUTH_ERROR: &str = "missing or invalid Authorization: Bearer token";
const EVENT_CHANNEL_CAPACITY: usize = 64;
const HEARTBEAT_SECS: u64 = 3;
const DEFAULT_APPROVAL_TTL: Duration = Duration::from_hours(24);

/// Marker trait for a daemon orchestrator handle stored in [`AppState`].
pub trait OrchestratorHandle: Send + Sync {}

impl<T> OrchestratorHandle for T where T: Send + Sync {}

/// Shared Axum application state.
#[derive(Clone)]
pub struct AppState {
    tracker: Arc<dyn Tracker>,
    proofs_dir: PathBuf,
    agent_id: AgentId,
    orchestrator: Option<Arc<dyn OrchestratorHandle>>,
    api_token: String,
    signing_client: Option<Arc<dyn SigningClient>>,
    worker_discovery: Option<Arc<dyn WorkerViewProvider>>,
    approval_ttl: Duration,
    events_tx: broadcast::Sender<EventNotice>,
}

/// Task row returned by `/symphony/tasks`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Task {
    /// Stable issue id.
    pub id: String,
    /// Human-readable issue identifier.
    pub identifier: String,
    /// Issue title.
    pub title: String,
    /// Current workflow state.
    pub state: String,
    /// Optional priority; lower runs first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    /// Issue labels.
    pub labels: Vec<String>,
    /// Current claim owner when the issue is claimed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_by: Option<String>,
    /// Non-serialized tracker verification notices surfaced for operators.
    #[serde(default)]
    pub verification_notices: Vec<VerificationNotice>,
}

/// Active claim row returned by `/symphony/status`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimInfo {
    /// Issue id.
    pub id: String,
    /// Issue identifier.
    pub identifier: String,
    /// Issue state.
    pub state: String,
    /// Claim owner.
    pub by: String,
    /// Last heartbeat timestamp.
    pub heartbeat_at: String,
}

/// Status response returned by `/symphony/status`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Status {
    /// Agent id configured for this daemon.
    pub agent_id: String,
    /// Number of issues by state.
    pub counts: std::collections::BTreeMap<String, usize>,
    /// Issues that currently have active claims.
    pub active_claims: Vec<ClaimInfo>,
    /// Whether this API state carries an orchestrator handle.
    pub orchestrator_attached: bool,
}

/// Worker view returned by `/symphony/workers`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Workers {
    /// Current non-expired, verified worker cards visible to the daemon.
    pub workers: Vec<WorkerCard>,
    /// Monotonic epoch of the worker view that produced `workers`.
    pub view_epoch: u64,
    /// Operator note when worker discovery is not configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct TaskDetail {
    #[serde(flatten)]
    issue: Issue,
    verification_notices: Vec<VerificationNotice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature_provenance: Option<PendingApprovalProvenance>,
    approval_summary: ApprovalSummary,
}

/// Route metadata returned by `/symphony/routes`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RouteInfo {
    /// HTTP method.
    pub method: String,
    /// Route path.
    pub path: String,
}

/// Routes response returned by `/symphony/routes`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Routes {
    /// Available routes in deterministic order.
    pub routes: Vec<RouteInfo>,
}

/// Proof listing returned by `/symphony/proofs`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProofList {
    /// Proof names relative to the repository `proofs/` directory.
    pub proofs: Vec<String>,
}

/// Proof content returned by `/symphony/proofs/{name}`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Proof {
    /// Proof name relative to the repository `proofs/` directory.
    pub name: String,
    /// UTF-8 proof content.
    pub content: String,
}

/// JSON payload accepted by `/symphony/handoff/{id}`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HandoffRequest {
    /// Handoff summary message.
    pub message: String,
    /// Optional changed file path to record in the handoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

/// JSON response returned by `/symphony/claim/{id}`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimResponse {
    /// Claimed issue id.
    pub id: String,
    /// Claim owner.
    pub by: String,
}

/// JSON response returned by `/symphony/handoff/{id}`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HandoffResponse {
    /// Issue id receiving the handoff.
    pub id: String,
    /// Whether the handoff was recorded.
    pub recorded: bool,
}

/// One issue awaiting operator approval for network-sourced dispatch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingApproval {
    /// Issue id whose current payload requires approval.
    pub issue_id: String,
    /// Issue title displayed to the operator.
    pub title: String,
    /// Current workflow state.
    pub state: String,
    /// Current canonical content hash bound by approval events.
    pub content_hash: String,
    /// Verified network signer whose issue payload is awaiting consent.
    pub signer_agent_id: String,
    /// Source signature provenance attached by the tracker, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<PendingApprovalProvenance>,
    /// Summary of stored approval, denial, and consumption records.
    pub approval_summary: ApprovalSummary,
}

/// Stored approval-record counts returned with a pending approval row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApprovalSummary {
    /// Number of approval or denial events stored for the issue.
    pub events: usize,
    /// Number of approval-consumption records stored for the issue.
    pub consumed: usize,
    /// Whether any stored event is a denial.
    pub has_deny: bool,
}

/// Serializable view of source signature provenance for approval consumers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PendingApprovalProvenance {
    /// A source signature was verified and binds the issue to this signer.
    Verified {
        /// x0x agent id whose ML-DSA-65 signature verified.
        signer_agent_id: String,
    },
    /// A source signature was present but failed verification.
    Invalid {
        /// Verification failure detail suitable for operator display.
        reason: String,
    },
    /// Verification could not complete because the verifier transport failed.
    TransportError {
        /// Transport failure detail suitable for operator display.
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct SubmitApprovalRequest {
    pub(crate) verdict: ApprovalVerdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expected_content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expected_signer_agent_id: Option<String>,
}

/// Errors returned by API handlers.
#[derive(Debug, Error)]
pub enum Error {
    /// A filesystem read failed.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path being accessed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A core tracker operation failed.
    #[error("tracker error: {0}")]
    Tracker(String),
    /// The request payload or path was invalid.
    #[error("bad request: {0}")]
    BadRequest(String),
    /// A proof was not found.
    #[error("proof not found: {0}")]
    NotFound(String),
    /// A request conflicted with the current issue view.
    #[error("conflict: {0}")]
    Conflict(String),
    /// Approval signing is not available for this daemon.
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
    /// Approval signing failed.
    #[error("signing error: {0}")]
    Signing(String),
    /// A bind address was not loopback.
    #[error("bind address must be loopback; got {0}")]
    NonLoopbackBind(SocketAddr),
    /// A bind address could not be parsed.
    #[error("invalid bind address {value}: {source}")]
    InvalidBind {
        /// Address text supplied by the operator.
        value: String,
        /// Underlying parser error.
        #[source]
        source: std::net::AddrParseError,
    },
}

/// One notice emitted on the daemon's Server-Sent Events bus.
#[derive(Clone, Debug)]
pub struct EventNotice {
    /// SSE event name.
    pub kind: &'static str,
    /// SSE data payload.
    pub data: String,
}

impl EventNotice {
    /// Construct an SSE event notice.
    #[must_use]
    pub fn new(kind: &'static str, data: impl Into<String>) -> Self {
        Self {
            kind,
            data: data.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct TasksQuery {
    state: Option<String>,
}

impl AppState {
    /// Construct application state for the daemon API.
    #[must_use]
    pub fn new(
        tracker: Arc<dyn Tracker>,
        agent_id: AgentId,
        api_token: String,
        orchestrator: Option<Arc<dyn OrchestratorHandle>>,
    ) -> Self {
        let (events_tx, _events_rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            tracker,
            proofs_dir: PathBuf::from("proofs"),
            agent_id,
            orchestrator,
            api_token,
            signing_client: None,
            worker_discovery: None,
            approval_ttl: DEFAULT_APPROVAL_TTL,
            events_tx,
        }
    }

    /// Return a copy that serves proof artefacts from `proofs_dir`.
    #[must_use]
    pub fn with_proofs_dir(mut self, proofs_dir: PathBuf) -> Self {
        self.proofs_dir = proofs_dir;
        self
    }

    /// Return a copy that signs approval decisions with `client` when configured.
    #[must_use]
    pub fn with_signing_client(mut self, client: Option<Arc<dyn SigningClient>>) -> Self {
        self.signing_client = client;
        self
    }

    /// Return a copy that exposes live worker-discovery snapshots when configured.
    #[must_use]
    pub fn with_worker_discovery(
        mut self,
        worker_discovery: Option<Arc<dyn WorkerViewProvider>>,
    ) -> Self {
        self.worker_discovery = worker_discovery;
        self
    }

    /// Return a copy that evaluates pending approvals with `ttl`.
    #[must_use]
    pub fn with_approval_ttl(mut self, ttl: Duration) -> Self {
        self.approval_ttl = ttl;
        self
    }

    fn proofs_root(&self) -> PathBuf {
        self.proofs_dir.clone()
    }

    /// Return a clone of the application SSE event sender.
    #[must_use]
    pub fn events_sender(&self) -> broadcast::Sender<EventNotice> {
        self.events_tx.clone()
    }

    fn notify_task_changed(&self, id: &str) {
        let _send_result = self
            .events_tx
            .send(EventNotice::new("task_changed", id.to_owned()));
    }

    fn notify_approval(&self, event: &ApprovalEvent) {
        let notice = match event.verdict {
            ApprovalVerdict::Approve => EventNotice::new(
                "approval_granted",
                json!({
                    "issue_id": event.issue_id.as_str(),
                    "approver_agent_id": event.approver_agent_id.as_str(),
                    "content_hash": event.content_hash.as_str(),
                })
                .to_string(),
            ),
            ApprovalVerdict::Deny => EventNotice::new(
                "approval_denied",
                json!({
                    "issue_id": event.issue_id.as_str(),
                    "approver_agent_id": event.approver_agent_id.as_str(),
                })
                .to_string(),
            ),
        };
        let _send_result = self.events_tx.send(notice);
    }
}

/// Build the daemon HTTP router.
pub fn build_router(state: AppState) -> Router {
    let auth_layer = middleware::from_fn_with_state(state.clone(), auth_middleware);
    let proof_routes = Router::new()
        .route("/{issue_id}/{ts}/manifest.json", get(show_proof_manifest))
        .route("/{issue_id}/{ts}/stdout.log", get(show_proof_stdout))
        .route("/{issue_id}/{ts}/stderr.log", get(show_proof_stderr))
        .fallback(show_proof_fallback);
    Router::new()
        .route("/health", get(health))
        .route("/symphony/tasks", get(tasks))
        .route("/symphony/tasks/{id}", get(task_detail))
        .route("/symphony/status", get(status))
        .route("/symphony/workers", get(workers))
        .route("/symphony/events", get(events))
        .route("/symphony/approvals/pending", get(approvals_pending))
        .route("/symphony/approvals/{id}", post(submit_approval))
        .route("/symphony/issues", post(create_issue))
        .route("/symphony/claim/{id}", post(claim_issue))
        .route("/symphony/handoff/{id}", post(handoff_issue))
        .route("/symphony/routes", get(routes))
        .route("/symphony/proofs", get(list_proofs))
        .nest("/symphony/proofs", proof_routes)
        .layer(auth_layer)
        .with_state(state)
}

/// Validate a daemon bind address and require a literal loopback IP.
///
/// # Errors
///
/// Returns [`Error::InvalidBind`] for malformed addresses and
/// [`Error::NonLoopbackBind`] for non-loopback addresses such as `0.0.0.0`.
pub fn validate_loopback_bind(value: &str) -> Result<SocketAddr, Error> {
    let addr = value
        .parse::<SocketAddr>()
        .map_err(|source| Error::InvalidBind {
            value: value.to_owned(),
            source,
        })?;
    if addr.ip().is_loopback() {
        Ok(addr)
    } else {
        Err(Error::NonLoopbackBind(addr))
    }
}

/// Bearer-token authentication middleware.
///
/// `/health` and `OPTIONS` are exempt. `/symphony/events` may authenticate via
/// `?token=` for `EventSource` clients; all other `/symphony/*` routes require an
/// `Authorization: Bearer <token>` header.
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: middleware::Next,
) -> Response {
    if request.method() == Method::OPTIONS || request.uri().path() == "/health" {
        return next.run(request).await;
    }

    if bearer_header_matches(&request, &state.api_token)
        || query_token_matches(&request, &state.api_token)
    {
        return next.run(request).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": AUTH_ERROR })),
    )
        .into_response()
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

async fn tasks(
    State(state): State<AppState>,
    Query(query): Query<TasksQuery>,
) -> Result<Json<Vec<Task>>, Error> {
    let mut tasks = state
        .tracker
        .list_issues()
        .await
        .map_err(|error| Error::Tracker(error.to_string()))?
        .into_iter()
        .filter(|issue| {
            query
                .state
                .as_ref()
                .is_none_or(|state_filter| issue.state.as_str() == state_filter)
        })
        .map(task_from_issue)
        .collect::<Vec<_>>();
    tasks.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(Json(tasks))
}

async fn task_detail(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<TaskDetail>, Error> {
    let issue_id =
        IssueId::new(id.clone()).map_err(|error| Error::BadRequest(error.to_string()))?;
    let issues = state
        .tracker
        .fetch_by_ids(std::slice::from_ref(&issue_id))
        .await
        .map_err(|error| Error::Tracker(error.to_string()))?;
    let issue = issues
        .into_iter()
        .next()
        .ok_or_else(|| Error::NotFound(id.clone()))?;
    let signature_provenance = issue
        .signature_provenance
        .as_ref()
        .map(PendingApprovalProvenance::from);
    let verification_notices = issue.verification_notices.clone();
    let approval_state = state
        .tracker
        .load_approval_state(&issue_id)
        .await
        .map_err(|error| Error::Tracker(error.to_string()))?;
    Ok(Json(TaskDetail {
        issue,
        verification_notices,
        signature_provenance,
        approval_summary: approval_summary(&approval_state),
    }))
}

async fn status(State(state): State<AppState>) -> Result<Json<Status>, Error> {
    let issues = state
        .tracker
        .list_issues()
        .await
        .map_err(|error| Error::Tracker(error.to_string()))?;
    Ok(Json(status_from_issues(&state, &issues)))
}

async fn workers(State(state): State<AppState>) -> Json<Workers> {
    let Some(worker_discovery) = &state.worker_discovery else {
        return Json(Workers {
            workers: Vec::new(),
            view_epoch: 0,
            note: Some("worker discovery is not configured".to_owned()),
        });
    };
    let snapshot = worker_discovery.snapshot().await;
    let mut workers = snapshot.cards;
    workers.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
    Json(Workers {
        workers,
        view_epoch: snapshot.view_epoch,
        note: None,
    })
}

async fn events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let event_rx = state.events_tx.subscribe();
    let interval = time::interval(Duration::from_secs(HEARTBEAT_SECS));
    let stream = stream::unfold(
        (event_rx, interval),
        |(mut event_rx, mut interval)| async move {
            let event = tokio::select! {
                notice_result = event_rx.recv() => match notice_result {
                    Ok(notice) => Event::default().event(notice.kind).data(notice.data),
                    Err(broadcast::error::RecvError::Lagged(_)) => Event::default().event("heartbeat").data("lagged"),
                    Err(broadcast::error::RecvError::Closed) => Event::default().event("heartbeat").data("closed"),
                },
                _ = interval.tick() => Event::default().event("heartbeat").data("ok"),
            };
            Some((Ok(event), (event_rx, interval)))
        },
    );
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn create_issue(
    State(state): State<AppState>,
    Json(draft): Json<IssueDraft>,
) -> Result<Json<Issue>, Error> {
    let issue = state
        .tracker
        .create_issue(draft)
        .await
        .map_err(|error| Error::Tracker(error.to_string()))?;
    state.notify_task_changed(issue.id.as_str());
    Ok(Json(issue))
}

async fn claim_issue(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<ClaimResponse>, Error> {
    let issue_id =
        IssueId::new(id.clone()).map_err(|error| Error::BadRequest(error.to_string()))?;
    let claim = state
        .tracker
        .claim(&issue_id, &state.agent_id)
        .await
        .map_err(|error| Error::Tracker(error.to_string()))?;
    state.notify_task_changed(issue_id.as_str());
    Ok(Json(ClaimResponse {
        id,
        by: claim.by.to_string(),
    }))
}

async fn handoff_issue(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<HandoffRequest>,
) -> Result<Json<HandoffResponse>, Error> {
    if request.message.trim().is_empty() {
        return Err(Error::BadRequest(
            "handoff message must not be empty".to_owned(),
        ));
    }
    let issue_id =
        IssueId::new(id.clone()).map_err(|error| Error::BadRequest(error.to_string()))?;
    let issues = state
        .tracker
        .fetch_by_ids(std::slice::from_ref(&issue_id))
        .await
        .map_err(|error| Error::Tracker(error.to_string()))?;
    let issue = issues
        .into_iter()
        .next()
        .ok_or_else(|| Error::NotFound(id.clone()))?;
    let claim = issue
        .claim
        .ok_or_else(|| Error::BadRequest(format!("issue {id} has no active claim")))?;
    let mut handoff = Handoff::new(request.message);
    if let Some(file) = request.file {
        handoff = handoff.with_file(file);
    }
    state
        .tracker
        .handoff(&claim, handoff)
        .await
        .map_err(|error| Error::Tracker(error.to_string()))?;
    state.notify_task_changed(issue_id.as_str());
    Ok(Json(HandoffResponse { id, recorded: true }))
}

async fn approvals_pending(
    State(state): State<AppState>,
) -> Result<Json<Vec<PendingApproval>>, Error> {
    let issues = state
        .tracker
        .list_issues()
        .await
        .map_err(|error| Error::Tracker(error.to_string()))?;
    let now = now_utc();
    let mut pending = Vec::new();
    for issue in issues {
        if !is_active_approval_state(&issue) {
            continue;
        }
        let Some(network_signer) = verified_network_signer_for_pending(&issue) else {
            continue;
        };
        let approval_state = state
            .tracker
            .load_approval_state(&issue.id)
            .await
            .map_err(|error| Error::Tracker(error.to_string()))?;
        let decision = approval_decision(
            &approval_state.events,
            &issue,
            &network_signer,
            &now,
            state.approval_ttl,
            &approval_state.consumed,
        );
        // `Approved` while still parked means a prior approval's requeue was
        // lost (e.g. daemon crash between approval store and requeue). Keep
        // the issue visible so the operator can approve again — submit_approval
        // is idempotent in this state and re-runs the requeue. Auto-requeueing
        // from here is deliberately avoided: this scan does not
        // cryptographically verify approvals; the dispatch gate does.
        let surface = decision == ApprovalDecision::Pending
            || (decision == ApprovalDecision::Approved && is_blocked_awaiting_approval(&issue));
        if surface {
            pending.push(pending_approval_from_issue(
                &issue,
                &network_signer,
                &approval_state,
            ));
        }
    }
    pending.sort_by(|left, right| left.issue_id.cmp(&right.issue_id));
    Ok(Json(pending))
}

async fn submit_approval(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<SubmitApprovalRequest>,
) -> Result<Json<ApprovalEvent>, Error> {
    let signing_client = state
        .signing_client
        .as_ref()
        .ok_or_else(|| Error::ServiceUnavailable("approval signing not configured".to_owned()))?;
    let issue_id =
        IssueId::new(id.clone()).map_err(|error| Error::BadRequest(error.to_string()))?;
    let issues = state
        .tracker
        .fetch_by_ids(std::slice::from_ref(&issue_id))
        .await
        .map_err(|error| Error::Tracker(error.to_string()))?;
    let issue = issues
        .into_iter()
        .next()
        .ok_or_else(|| Error::NotFound(id.clone()))?;
    let current_hash = content_hash(&issue);
    let network_signer = require_verified_network_signer(&issue)?;
    if let Some(expected_hash) = request.expected_content_hash.as_deref() {
        if expected_hash != current_hash.as_str() {
            return Err(Error::Conflict(format!(
                "issue payload changed: expected content hash {expected_hash}, current {}",
                current_hash.as_str()
            )));
        }
    }
    if let Some(expected_signer) = request.expected_signer_agent_id.as_deref() {
        if expected_signer != network_signer.as_str() {
            return Err(Error::Conflict(format!(
                "issue signer changed: expected {expected_signer}, current {}",
                network_signer.as_str()
            )));
        }
    }

    let approved_at = now_utc();
    let event = match request.verdict {
        ApprovalVerdict::Approve => ApprovalEvent::approve(
            issue_id.clone(),
            current_hash,
            network_signer,
            approved_at,
            state.agent_id.clone(),
            None,
        ),
        ApprovalVerdict::Deny => ApprovalEvent::deny(
            issue_id.clone(),
            current_hash,
            network_signer,
            approved_at,
            state.agent_id.clone(),
            None,
        ),
    };
    let signed = sign_approval_event(signing_client.as_ref(), event).await?;
    state
        .tracker
        .store_approval(&signed)
        .await
        .map_err(|error| Error::Tracker(error.to_string()))?;
    // An approved issue that the dispatch gate parked as blocked/awaiting_approval
    // must return to `todo` so the orchestrator re-claims it; the gate then finds
    // the stored approval, consumes it, and dispatches exactly once. The approval
    // event above is already durable, so a requeue failure is retryable by
    // re-approving (duplicate approve events are harmless).
    if request.verdict == ApprovalVerdict::Approve && is_blocked_awaiting_approval(&issue) {
        let requeue_result = state
            .tracker
            .requeue_blocked(
                &issue_id,
                ReleaseReason::new(
                    ReleaseReasonCode::Other,
                    "approval granted; requeued for dispatch",
                ),
            )
            .await;
        if let Err(error) = requeue_result {
            // Concurrent approves race on the requeue: exactly one converts
            // the blocked claim. If another call (or a crash-recovery retry)
            // already returned the issue to `todo`, this approval is still
            // fully recorded — treat the request as successful.
            let refetched = state
                .tracker
                .fetch_by_ids(std::slice::from_ref(&issue_id))
                .await
                .map_err(|fetch_error| Error::Tracker(fetch_error.to_string()))?;
            let still_parked = refetched.first().is_none_or(is_blocked_awaiting_approval);
            if still_parked {
                return Err(Error::Tracker(error.to_string()));
            }
        }
    }
    state.notify_approval(&signed);
    state.notify_task_changed(issue_id.as_str());
    Ok(Json(signed))
}

async fn routes() -> Json<Routes> {
    Json(Routes {
        routes: route_infos(),
    })
}

async fn list_proofs(State(state): State<AppState>) -> Result<Json<ProofList>, Error> {
    let root = state.proofs_root();
    let mut proofs = Vec::new();
    let mut entries = match tokio::fs::read_dir(&root).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Json(ProofList { proofs }));
        }
        Err(source) => return Err(Error::Io { path: root, source }),
    };
    loop {
        match entries.next_entry().await {
            Ok(Some(entry)) => proofs.push(entry.file_name().to_string_lossy().into_owned()),
            Ok(None) => break,
            Err(source) => {
                return Err(Error::Io {
                    path: root.clone(),
                    source,
                });
            }
        }
    }
    proofs.sort();
    Ok(Json(ProofList { proofs }))
}

async fn show_proof_fallback(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Proof>, Error> {
    let name = uri
        .path()
        .strip_prefix("/symphony/proofs/")
        .ok_or_else(|| Error::NotFound(uri.path().to_owned()))?;
    show_proof_by_name(state, name.to_owned()).await
}

async fn show_proof_by_name(state: AppState, name: String) -> Result<Json<Proof>, Error> {
    let root = state.proofs_root();
    let path = safe_proof_path(&root, &name)?;
    let content = read_proof_to_string(&path, &name).await?;
    Ok(Json(Proof { name, content }))
}

async fn show_proof_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((issue_id, ts)): AxumPath<(String, String)>,
) -> Result<Response, Error> {
    show_proof_artifact(
        state,
        &headers,
        &issue_id,
        &ts,
        "manifest.json",
        "application/json",
    )
    .await
}

async fn show_proof_stdout(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((issue_id, ts)): AxumPath<(String, String)>,
) -> Result<Response, Error> {
    show_proof_artifact(
        state,
        &headers,
        &issue_id,
        &ts,
        "stdout.log",
        "text/plain; charset=utf-8",
    )
    .await
}

async fn show_proof_stderr(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((issue_id, ts)): AxumPath<(String, String)>,
) -> Result<Response, Error> {
    show_proof_artifact(
        state,
        &headers,
        &issue_id,
        &ts,
        "stderr.log",
        "text/plain; charset=utf-8",
    )
    .await
}

async fn show_proof_artifact(
    state: AppState,
    headers: &HeaderMap,
    issue_id: &str,
    ts: &str,
    file_name: &'static str,
    content_type: &'static str,
) -> Result<Response, Error> {
    let root = state.proofs_root();
    let path = safe_proof_artifact_path(&root, issue_id, ts, file_name)?;
    let name = format!("{issue_id}/{ts}/{file_name}");
    if accepts_json(headers) {
        return show_proof_by_name(state, name)
            .await
            .map(IntoResponse::into_response);
    }
    let content = read_proof_to_string(&path, &name).await?;
    Ok(([(CONTENT_TYPE, content_type)], content).into_response())
}

fn accepts_json(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|part| part.starts_with("application/json"))
        })
}

async fn read_proof_to_string(path: &Path, name: &str) -> Result<String, Error> {
    tokio::fs::read_to_string(path).await.map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            Error::NotFound(name.to_owned())
        } else {
            Error::Io {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

/// Sign an approval or denial event exactly as the dispatch gate verifies it.
///
/// The payload is [`ApprovalEvent::signing_payload_bytes`] signed under
/// [`APPROVAL_CONTEXT`], and the returned event carries a [`SignatureEnvelope`]
/// whose digest covers those exact bytes.
///
/// # Errors
///
/// Returns [`Error::Signing`] if the event payload cannot be serialized, x0xd
/// signing fails, or x0xd returns an algorithm, context, or signer that does not
/// match the approval event being signed.
pub async fn sign_approval_event(
    client: &dyn SigningClient,
    mut event: ApprovalEvent,
) -> Result<ApprovalEvent, Error> {
    let payload = event
        .signing_payload_bytes()
        .map_err(|error| Error::Signing(error.to_string()))?;
    let response = client
        .sign(APPROVAL_CONTEXT, &payload)
        .await
        .map_err(|error| Error::Signing(error.to_string()))?;
    if response.algorithm != SIGN_ALGORITHM {
        return Err(Error::Signing(format!(
            "sign response algorithm {} did not match {SIGN_ALGORITHM}",
            response.algorithm
        )));
    }
    if response.context != APPROVAL_CONTEXT {
        return Err(Error::Signing(format!(
            "sign response context {} did not match {APPROVAL_CONTEXT}",
            response.context
        )));
    }
    if response.agent_id != event.approver_agent_id.as_str() {
        return Err(Error::Signing(format!(
            "sign response agent {} did not match approver {}",
            response.agent_id,
            event.approver_agent_id.as_str()
        )));
    }
    event.signature = Some(SignatureEnvelope::new(
        response.algorithm,
        response.context,
        response.public_key_b64,
        response.signature_b64,
        sha256_hex(&payload),
        response.agent_id,
    ));
    Ok(event)
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match self {
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::BadRequest(_) | Self::InvalidBind { .. } | Self::NonLoopbackBind(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::Io { .. } | Self::Tracker(_) | Self::Signing(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let body = Json(json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}

fn bearer_header_matches(request: &Request<axum::body::Body>, target: &str) -> bool {
    request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| constant_time_eq(token.as_bytes(), target.as_bytes()))
}

fn query_token_matches(request: &Request<axum::body::Body>, target: &str) -> bool {
    if request.uri().path() != "/symphony/events" {
        return false;
    }
    request.uri().query().is_some_and(|query| {
        query
            .split('&')
            .filter_map(|pair| pair.strip_prefix("token="))
            .any(|token| constant_time_eq(token.as_bytes(), target.as_bytes()))
    })
}

fn task_from_issue(issue: Issue) -> Task {
    Task {
        id: issue.id.to_string(),
        identifier: issue.identifier,
        title: issue.title,
        state: issue.state.to_string(),
        priority: issue.priority,
        labels: issue.labels,
        claim_by: issue.claim.map(|claim| claim.by.to_string()),
        verification_notices: issue.verification_notices,
    }
}

fn status_from_issues(state: &AppState, issues: &[Issue]) -> Status {
    let mut counts = std::collections::BTreeMap::new();
    let mut active_claims = Vec::new();
    for issue in issues {
        let count = counts.entry(issue.state.to_string()).or_insert(0_usize);
        *count = count.saturating_add(1);
        if let Some(claim) = &issue.claim {
            active_claims.push(claim_info_from_issue(issue, claim));
        }
    }
    active_claims.sort_by(|left, right| left.id.cmp(&right.id));
    Status {
        agent_id: state.agent_id.to_string(),
        counts,
        active_claims,
        orchestrator_attached: state.orchestrator.is_some(),
    }
}

fn claim_info_from_issue(issue: &Issue, claim: &Claim) -> ClaimInfo {
    ClaimInfo {
        id: issue.id.to_string(),
        identifier: issue.identifier.clone(),
        state: issue.state.to_string(),
        by: claim.by.to_string(),
        heartbeat_at: claim.heartbeat_at.clone(),
    }
}

fn pending_approval_from_issue(
    issue: &Issue,
    signer: &AgentId,
    approval_state: &ApprovalState,
) -> PendingApproval {
    PendingApproval {
        issue_id: issue.id.to_string(),
        title: issue.title.clone(),
        state: issue.state.to_string(),
        content_hash: content_hash(issue).to_string(),
        signer_agent_id: signer.to_string(),
        provenance: issue
            .signature_provenance
            .as_ref()
            .map(PendingApprovalProvenance::from),
        approval_summary: approval_summary(approval_state),
    }
}

fn approval_summary(approval_state: &ApprovalState) -> ApprovalSummary {
    ApprovalSummary {
        events: approval_state.events.len(),
        consumed: approval_state.consumed.len(),
        has_deny: approval_state.events.iter().any(ApprovalEvent::is_denial),
    }
}

fn is_active_approval_state(issue: &Issue) -> bool {
    matches!(issue.state.as_str(), "todo" | "in_progress") || is_blocked_awaiting_approval(issue)
}

/// The dispatch gate parks approval-gated issues as `blocked` with reason code
/// `awaiting_approval`. Those issues must stay visible in the pending-approval
/// scan — the act of awaiting approval must not remove an issue from the very
/// list the operator approves from.
fn is_blocked_awaiting_approval(issue: &Issue) -> bool {
    issue.state.as_str() == "blocked"
        && issue
            .extra
            .get("blocked_reason")
            .and_then(|reason| reason.get("code"))
            .and_then(serde_json::Value::as_str)
            == Some("awaiting_approval")
}

fn verified_network_signer_for_pending(issue: &Issue) -> Option<AgentId> {
    if !is_network_sourced(issue) {
        return None;
    }
    match &issue.signature_provenance {
        Some(SignatureProvenance::Verified { signer_agent_id })
            if !signer_agent_id.trim().is_empty() =>
        {
            AgentId::new(signer_agent_id.trim().to_owned()).ok()
        }
        Some(
            SignatureProvenance::Verified { .. }
            | SignatureProvenance::Invalid { .. }
            | SignatureProvenance::TransportError { .. },
        )
        | None => None,
    }
}

fn require_verified_network_signer(issue: &Issue) -> Result<AgentId, Error> {
    if !is_network_sourced(issue) {
        return Err(Error::Conflict(
            "issue is not network-sourced; approval not applicable".to_owned(),
        ));
    }
    match &issue.signature_provenance {
        Some(SignatureProvenance::Verified { signer_agent_id })
            if !signer_agent_id.trim().is_empty() =>
        {
            AgentId::new(signer_agent_id.trim().to_owned())
                .map_err(|error| Error::Conflict(error.to_string()))
        }
        Some(SignatureProvenance::Verified { .. }) | None => Err(Error::Conflict(
            "network-sourced issue lacks verified ML-DSA-65 signature provenance".to_owned(),
        )),
        Some(SignatureProvenance::Invalid { reason }) => Err(Error::Conflict(format!(
            "network-sourced issue signature is invalid: {reason}"
        ))),
        Some(SignatureProvenance::TransportError { reason }) => Err(Error::Conflict(format!(
            "network-sourced issue signature verification transport failed: {reason}"
        ))),
    }
}

fn is_network_sourced(issue: &Issue) -> bool {
    IssueSource::from_issue(issue) == IssueSource::NetworkSourced
        || issue.signature_provenance.is_some()
}

fn now_utc() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

impl From<&SignatureProvenance> for PendingApprovalProvenance {
    fn from(value: &SignatureProvenance) -> Self {
        match value {
            SignatureProvenance::Verified { signer_agent_id } => Self::Verified {
                signer_agent_id: signer_agent_id.clone(),
            },
            SignatureProvenance::Invalid { reason } => Self::Invalid {
                reason: reason.clone(),
            },
            SignatureProvenance::TransportError { reason } => Self::TransportError {
                reason: reason.clone(),
            },
        }
    }
}

fn route_infos() -> Vec<RouteInfo> {
    [
        ("GET", "/health"),
        ("GET", "/symphony/approvals/pending"),
        ("GET", "/symphony/events"),
        ("GET", "/symphony/proofs"),
        ("GET", "/symphony/proofs/{issue_id}/{ts}/manifest.json"),
        ("GET", "/symphony/proofs/{issue_id}/{ts}/stdout.log"),
        ("GET", "/symphony/proofs/{issue_id}/{ts}/stderr.log"),
        ("GET", "/symphony/proofs/{*name}"),
        ("GET", "/symphony/routes"),
        ("GET", "/symphony/status"),
        ("GET", "/symphony/tasks"),
        ("GET", "/symphony/tasks/{id}"),
        ("GET", "/symphony/workers"),
        ("POST", "/symphony/approvals/{id}"),
        ("POST", "/symphony/claim/{id}"),
        ("POST", "/symphony/handoff/{id}"),
        ("POST", "/symphony/issues"),
    ]
    .into_iter()
    .map(|(method, path)| RouteInfo {
        method: method.to_owned(),
        path: path.to_owned(),
    })
    .collect()
}

fn safe_proof_path(root: &Path, name: &str) -> Result<PathBuf, Error> {
    let candidate = Path::new(name);
    if candidate.is_absolute() {
        return Err(Error::BadRequest("proof name must be relative".to_owned()));
    }
    let mut path = root.to_path_buf();
    for component in candidate.components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::BadRequest(
                    "proof name must stay inside proofs directory".to_owned(),
                ));
            }
        }
    }
    if path == root {
        return Err(Error::BadRequest("proof name must not be empty".to_owned()));
    }
    Ok(path)
}

fn safe_proof_artifact_path(
    root: &Path,
    issue_id: &str,
    ts: &str,
    file_name: &'static str,
) -> Result<PathBuf, Error> {
    let issue_id = safe_proof_segment("issue_id", issue_id)?;
    let ts = safe_proof_segment("ts", ts)?;
    Ok(root.join(issue_id).join(ts).join(file_name))
}

fn safe_proof_segment<'a>(label: &str, value: &'a str) -> Result<&'a str, Error> {
    if value.trim().is_empty() {
        return Err(Error::BadRequest(format!(
            "proof {label} must not be empty"
        )));
    }
    if value.contains('/') || value.contains('\\') {
        return Err(Error::BadRequest(format!(
            "proof {label} must be a single path segment"
        )));
    }
    let candidate = Path::new(value);
    if candidate.is_absolute() {
        return Err(Error::BadRequest(format!("proof {label} must be relative")));
    }
    let mut components = candidate.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(value),
        _ => Err(Error::BadRequest(format!(
            "proof {label} must stay inside proofs directory"
        ))),
    }
}
