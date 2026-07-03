use std::{collections::BTreeMap, error::Error, sync::Arc};

use async_trait::async_trait;
use reqwest::StatusCode;
use serde_json::Value;
use tempfile::TempDir;
use tokio::{net::TcpListener, task::JoinHandle};
use x0x_symphony_bin::api::{build_router, AppState};
use x0x_symphony_core::{
    AgentId, ApprovalState, Claim, Handoff, Issue, IssueDraft, IssueId, IssueState, PlatformInfo,
    PollContext, ReleaseReason, Result as CoreResult, SignatureProvenance, Tracker, WorkerCard,
    WORKER_CARD_SCHEMA_VERSION,
};
use x0x_symphony_tracker_x0x_crdt::{WorkerViewProvider, WorkerViewSnapshot};

const API_TOKEN: &str = "secret-token";

struct TestServer {
    base_url: String,
    task: JoinHandle<()>,
    _proofs_dir: Option<TempDir>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct ObservabilityTracker {
    issues: Vec<Issue>,
    approvals: BTreeMap<IssueId, ApprovalState>,
}

impl ObservabilityTracker {
    fn new(issues: Vec<Issue>) -> Self {
        Self {
            issues,
            approvals: BTreeMap::new(),
        }
    }
}

#[async_trait]
impl Tracker for ObservabilityTracker {
    async fn list_issues(&self) -> CoreResult<Vec<Issue>> {
        Ok(self.issues.clone())
    }

    async fn fetch_candidates(&self, _ctx: &PollContext) -> CoreResult<Vec<Issue>> {
        Ok(self.issues.clone())
    }

    async fn fetch_by_ids(&self, ids: &[IssueId]) -> CoreResult<Vec<Issue>> {
        Ok(self
            .issues
            .iter()
            .filter(|issue| ids.iter().any(|id| id == &issue.id))
            .cloned()
            .collect())
    }

    async fn claim(&self, _id: &IssueId, _agent_id: &AgentId) -> CoreResult<Claim> {
        Err(x0x_symphony_core::SymphonyError::Tracker(
            "observability tracker cannot claim".to_owned(),
        ))
    }

    async fn heartbeat(&self, _claim: &Claim) -> CoreResult<()> {
        Ok(())
    }

    async fn release(&self, _claim: &Claim, _reason: ReleaseReason) -> CoreResult<()> {
        Ok(())
    }

    async fn handoff(&self, _claim: &Claim, _handoff: Handoff) -> CoreResult<()> {
        Ok(())
    }

    async fn create_issue(&self, _draft: IssueDraft) -> CoreResult<Issue> {
        Err(x0x_symphony_core::SymphonyError::Tracker(
            "observability tracker cannot create".to_owned(),
        ))
    }

    async fn load_approval_state(&self, issue_id: &IssueId) -> CoreResult<ApprovalState> {
        Ok(self.approvals.get(issue_id).cloned().unwrap_or_default())
    }
}

struct MockWorkerViewProvider {
    snapshot: WorkerViewSnapshot,
}

#[async_trait]
impl WorkerViewProvider for MockWorkerViewProvider {
    async fn snapshot(&self) -> WorkerViewSnapshot {
        self.snapshot.clone()
    }
}

#[tokio::test]
async fn task_detail_returns_issue_and_404_when_absent() -> Result<(), Box<dyn Error>> {
    let mut issue = issue("XSY-OBS-1", "Observed task")?;
    issue.priority = Some(2);
    issue.labels = vec!["observability".to_owned()];
    issue.signature_provenance = Some(SignatureProvenance::verified("network-signer"));
    let server = spawn_server(AppState::new(
        Arc::new(ObservabilityTracker::new(vec![issue])),
        AgentId::new("symphonyd")?,
        API_TOKEN.to_owned(),
        None,
    ))
    .await?;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/symphony/tasks/XSY-OBS-1", server.base_url))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.json::<Value>().await?;
    assert_eq!(body["id"], "XSY-OBS-1");
    assert_eq!(body["state"], "todo");
    assert_eq!(body["priority"], 2);
    assert_eq!(body["labels"], serde_json::json!(["observability"]));
    assert_eq!(body["signature_provenance"]["kind"], "verified");
    assert_eq!(body["approval_summary"]["events"], 0);

    let missing = client
        .get(format!("{}/symphony/tasks/XSY-MISSING", server.base_url))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn workers_returns_empty_without_discovery_and_cards_when_wired() -> Result<(), Box<dyn Error>>
{
    let empty_server = spawn_server(AppState::new(
        Arc::new(ObservabilityTracker::new(Vec::new())),
        AgentId::new("symphonyd")?,
        API_TOKEN.to_owned(),
        None,
    ))
    .await?;
    let client = reqwest::Client::new();

    let empty_response = client
        .get(format!("{}/symphony/workers", empty_server.base_url))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    assert_eq!(empty_response.status(), StatusCode::OK);
    let empty_body = empty_response.json::<Value>().await?;
    assert_eq!(empty_body["workers"], serde_json::json!([]));
    assert_eq!(empty_body["view_epoch"], 0);
    assert!(empty_body.get("note").is_some());

    let worker = worker_card("worker-a")?;
    let provider: Arc<dyn WorkerViewProvider> = Arc::new(MockWorkerViewProvider {
        snapshot: WorkerViewSnapshot {
            cards: vec![worker],
            view_epoch: 42,
        },
    });
    let populated_state = AppState::new(
        Arc::new(ObservabilityTracker::new(Vec::new())),
        AgentId::new("symphonyd")?,
        API_TOKEN.to_owned(),
        None,
    )
    .with_worker_discovery(Some(provider));
    let populated_server = spawn_server(populated_state).await?;

    let populated_response = client
        .get(format!("{}/symphony/workers", populated_server.base_url))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    assert_eq!(populated_response.status(), StatusCode::OK);
    let populated_body = populated_response.json::<Value>().await?;
    assert_eq!(populated_body["view_epoch"], 42);
    assert_eq!(populated_body["workers"][0]["agent_id"], "worker-a");
    assert_eq!(
        populated_body["workers"][0]["capabilities"],
        serde_json::json!(["rust"])
    );
    Ok(())
}

#[tokio::test]
async fn granular_proof_routes_return_artifacts_and_reject_traversal() -> Result<(), Box<dyn Error>>
{
    let proofs_dir = TempDir::new()?;
    let artifact_dir = proofs_dir
        .path()
        .join("XSY-OBS-1")
        .join("2026-07-03T00-00-00Z");
    std::fs::create_dir_all(&artifact_dir)?;
    std::fs::write(artifact_dir.join("manifest.json"), "{\"ok\":true}\n")?;
    std::fs::write(artifact_dir.join("stdout.log"), "stdout\n")?;
    std::fs::write(artifact_dir.join("stderr.log"), "stderr\n")?;

    let server = spawn_server_with_proofs(proofs_dir).await?;
    let client = reqwest::Client::new();

    let manifest = client
        .get(format!(
            "{}/symphony/proofs/XSY-OBS-1/2026-07-03T00-00-00Z/manifest.json",
            server.base_url
        ))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    assert_eq!(manifest.status(), StatusCode::OK);
    assert_eq!(
        manifest.headers()[reqwest::header::CONTENT_TYPE],
        "application/json"
    );
    assert_eq!(manifest.text().await?, "{\"ok\":true}\n");

    let stdout = client
        .get(format!(
            "{}/symphony/proofs/XSY-OBS-1/2026-07-03T00-00-00Z/stdout.log",
            server.base_url
        ))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    assert_eq!(stdout.status(), StatusCode::OK);
    assert!(stdout.headers()[reqwest::header::CONTENT_TYPE]
        .to_str()?
        .starts_with("text/plain"));
    assert_eq!(stdout.text().await?, "stdout\n");

    let catchall_json = client
        .get(format!(
            "{}/symphony/proofs/XSY-OBS-1/2026-07-03T00-00-00Z/stdout.log",
            server.base_url
        ))
        .bearer_auth(API_TOKEN)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await?;
    assert_eq!(catchall_json.status(), StatusCode::OK);
    let catchall_body = catchall_json.json::<Value>().await?;
    assert_eq!(catchall_body["content"], "stdout\n");

    let stderr = client
        .get(format!(
            "{}/symphony/proofs/XSY-OBS-1/2026-07-03T00-00-00Z/stderr.log",
            server.base_url
        ))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    assert_eq!(stderr.status(), StatusCode::OK);
    assert_eq!(stderr.text().await?, "stderr\n");

    let missing = client
        .get(format!(
            "{}/symphony/proofs/XSY-OBS-1/missing-ts/stdout.log",
            server.base_url
        ))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let traversal = client
        .get(format!(
            "{}/symphony/proofs/%2e%2e/2026-07-03T00-00-00Z/manifest.json",
            server.base_url
        ))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    assert!(matches!(
        traversal.status(),
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND
    ));
    Ok(())
}

#[tokio::test]
async fn new_observability_routes_require_bearer_token() -> Result<(), Box<dyn Error>> {
    let server = spawn_server_with_proofs(TempDir::new()?).await?;
    let client = reqwest::Client::new();
    let paths = [
        "/symphony/tasks/XSY-OBS-1",
        "/symphony/workers",
        "/symphony/proofs/XSY-OBS-1/2026-07-03T00-00-00Z/manifest.json",
        "/symphony/proofs/XSY-OBS-1/2026-07-03T00-00-00Z/stdout.log",
        "/symphony/proofs/XSY-OBS-1/2026-07-03T00-00-00Z/stderr.log",
    ];

    for path in paths {
        let response = client
            .get(format!("{}{}", server.base_url, path))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    Ok(())
}

async fn spawn_server(state: AppState) -> Result<TestServer, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = build_router(state);
    let task = tokio::spawn(async move {
        let result = axum::serve(listener, app).await;
        if let Err(_error) = result {}
    });
    Ok(TestServer {
        base_url: format!("http://{addr}"),
        task,
        _proofs_dir: None,
    })
}

async fn spawn_server_with_proofs(proofs_dir: TempDir) -> Result<TestServer, Box<dyn Error>> {
    let state = AppState::new(
        Arc::new(ObservabilityTracker::new(Vec::new())),
        AgentId::new("symphonyd")?,
        API_TOKEN.to_owned(),
        None,
    )
    .with_proofs_dir(proofs_dir.path().to_path_buf());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = build_router(state);
    let task = tokio::spawn(async move {
        let result = axum::serve(listener, app).await;
        if let Err(_error) = result {}
    });
    Ok(TestServer {
        base_url: format!("http://{addr}"),
        task,
        _proofs_dir: Some(proofs_dir),
    })
}

fn issue(id: &str, title: &str) -> Result<Issue, Box<dyn Error>> {
    Ok(Issue::new(
        IssueId::new(id)?,
        id,
        title,
        IssueState::new("todo")?,
        "2026-07-03T00:00:00Z",
    )?)
}

fn worker_card(agent_id: &str) -> Result<WorkerCard, Box<dyn Error>> {
    Ok(WorkerCard {
        schema_version: WORKER_CARD_SCHEMA_VERSION,
        agent_id: AgentId::new(agent_id)?,
        issued_at: "2026-07-03T00:00:00Z".to_owned(),
        ttl_seconds: 60,
        capabilities: vec!["rust".to_owned()],
        sandbox_levels: vec!["repo-write".to_owned()],
        runner_presets: vec!["claude_code".to_owned()],
        current_load: 1,
        max_load: 3,
        platform: PlatformInfo {
            os: "linux".to_owned(),
            arch: "x86_64".to_owned(),
            version: "0.1.0".to_owned(),
        },
        signature: None,
    })
}
