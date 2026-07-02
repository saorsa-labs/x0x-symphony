//! Axum HTTP API for the local x0x-symphony daemon.

use std::{
    convert::Infallible,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{header::AUTHORIZATION, Method, Request, StatusCode},
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
use tokio::{
    sync::broadcast,
    time::{self, Duration},
};
use x0x_symphony_core::{AgentId, Claim, Handoff, Issue, IssueId, Tracker};
use x0x_symphony_tracker_git_jsonl::{parse_issue_line, JsonlTracker};

const AUTH_ERROR: &str = "missing or invalid Authorization: Bearer token";
const EVENT_CHANNEL_CAPACITY: usize = 64;
const HEARTBEAT_SECS: u64 = 3;

/// Marker trait for a daemon orchestrator handle stored in [`AppState`].
pub trait OrchestratorHandle: Send + Sync {}

impl<T> OrchestratorHandle for T where T: Send + Sync {}

/// Shared Axum application state.
#[derive(Clone)]
pub struct AppState {
    tracker_path: PathBuf,
    agent_id: AgentId,
    orchestrator: Option<Arc<dyn OrchestratorHandle>>,
    api_token: String,
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
    /// JSONL parsing failed.
    #[error("issue database parse error: {0}")]
    IssueParse(String),
    /// A core tracker operation failed.
    #[error("tracker error: {0}")]
    Tracker(String),
    /// The request payload or path was invalid.
    #[error("bad request: {0}")]
    BadRequest(String),
    /// A proof was not found.
    #[error("proof not found: {0}")]
    NotFound(String),
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

#[derive(Clone, Debug)]
struct EventNotice {
    kind: &'static str,
    data: String,
}

#[derive(Debug, Deserialize)]
struct TasksQuery {
    state: Option<String>,
}

impl AppState {
    /// Construct application state for the daemon API.
    #[must_use]
    pub fn new(
        tracker_path: PathBuf,
        agent_id: AgentId,
        api_token: String,
        orchestrator: Option<Arc<dyn OrchestratorHandle>>,
    ) -> Self {
        let (events_tx, _events_rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            tracker_path,
            agent_id,
            orchestrator,
            api_token,
            events_tx,
        }
    }

    fn tracker(&self) -> JsonlTracker {
        let repo_root = repo_root_from_issues_path(&self.tracker_path);
        JsonlTracker::builder(repo_root)
            .issues_path(self.tracker_path.clone())
            .build()
    }

    fn proofs_root(&self) -> PathBuf {
        repo_root_from_issues_path(&self.tracker_path).join("proofs")
    }

    fn notify_task_changed(&self, id: &str) {
        let _send_result = self.events_tx.send(EventNotice {
            kind: "task_changed",
            data: id.to_owned(),
        });
    }
}

/// Build the daemon HTTP router.
pub fn build_router(state: AppState) -> Router {
    let auth_layer = middleware::from_fn_with_state(state.clone(), auth_middleware);
    Router::new()
        .route("/health", get(health))
        .route("/symphony/tasks", get(tasks))
        .route("/symphony/status", get(status))
        .route("/symphony/events", get(events))
        .route("/symphony/claim/{id}", post(claim_issue))
        .route("/symphony/handoff/{id}", post(handoff_issue))
        .route("/symphony/routes", get(routes))
        .route("/symphony/proofs", get(list_proofs))
        .route("/symphony/proofs/{*name}", get(show_proof))
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
    let mut tasks = issues_from_path(&state.tracker_path)
        .await?
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

async fn status(State(state): State<AppState>) -> Result<Json<Status>, Error> {
    let issues = issues_from_path(&state.tracker_path).await?;
    Ok(Json(status_from_issues(&state, &issues)))
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

async fn claim_issue(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<ClaimResponse>, Error> {
    let issue_id =
        IssueId::new(id.clone()).map_err(|error| Error::BadRequest(error.to_string()))?;
    let claim = state
        .tracker()
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
    let tracker = state.tracker();
    let issues = tracker
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
    tracker
        .handoff(&claim, handoff)
        .await
        .map_err(|error| Error::Tracker(error.to_string()))?;
    state.notify_task_changed(issue_id.as_str());
    Ok(Json(HandoffResponse { id, recorded: true }))
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

async fn show_proof(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<Proof>, Error> {
    let root = state.proofs_root();
    let path = safe_proof_path(&root, &name)?;
    let content = tokio::fs::read_to_string(&path).await.map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            Error::NotFound(name.clone())
        } else {
            Error::Io {
                path: path.clone(),
                source,
            }
        }
    })?;
    Ok(Json(Proof { name, content }))
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match self {
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::BadRequest(_) | Self::InvalidBind { .. } | Self::NonLoopbackBind(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::Io { .. } | Self::IssueParse(_) | Self::Tracker(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let body = Json(json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}

fn bearer_header_matches(request: &Request<axum::body::Body>, expected: &str) -> bool {
    request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| token == expected)
}

fn query_token_matches(request: &Request<axum::body::Body>, expected: &str) -> bool {
    if request.uri().path() != "/symphony/events" {
        return false;
    }
    request.uri().query().is_some_and(|query| {
        query
            .split('&')
            .filter_map(|pair| pair.strip_prefix("token="))
            .any(|token| token == expected)
    })
}

async fn issues_from_path(path: &Path) -> Result<Vec<Issue>, Error> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut issues = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_number = index.saturating_add(1);
        let issue = parse_issue_line(line_number, line)
            .map_err(|error| Error::IssueParse(error.to_string()))?;
        issues.push(issue);
    }
    issues.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(issues)
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

fn route_infos() -> Vec<RouteInfo> {
    [
        ("GET", "/health"),
        ("GET", "/symphony/events"),
        ("GET", "/symphony/proofs"),
        ("GET", "/symphony/proofs/{name}"),
        ("GET", "/symphony/routes"),
        ("GET", "/symphony/status"),
        ("GET", "/symphony/tasks"),
        ("POST", "/symphony/claim/{id}"),
        ("POST", "/symphony/handoff/{id}"),
    ]
    .into_iter()
    .map(|(method, path)| RouteInfo {
        method: method.to_owned(),
        path: path.to_owned(),
    })
    .collect()
}

fn repo_root_from_issues_path(path: &Path) -> PathBuf {
    let Some(parent) = path.parent() else {
        return PathBuf::from(".");
    };
    if parent.file_name().and_then(|name| name.to_str()) == Some("issues") {
        if let Some(root) = parent.parent() {
            return root.to_path_buf();
        }
    }
    parent.to_path_buf()
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
