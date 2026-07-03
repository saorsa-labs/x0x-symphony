use std::{error::Error, sync::Arc};

use async_trait::async_trait;
use reqwest::StatusCode;
use serde_json::Value;
use tokio::{net::TcpListener, task::JoinHandle};
use x0x_symphony_bin::api::{build_router, AppState};
use x0x_symphony_core::{
    AgentId, Claim, Handoff, Issue, IssueId, IssueState, PollContext, ReleaseReason,
    Result as CoreResult, Tracker,
};

struct TestServer {
    base_url: String,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct StaticTracker {
    issues: Vec<Issue>,
}

#[async_trait]
impl Tracker for StaticTracker {
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
            "static tracker cannot claim".to_owned(),
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
}

#[tokio::test]
async fn symphony_routes_require_bearer_token() -> Result<(), Box<dyn Error>> {
    let issue = Issue::new(
        IssueId::new("XSY-0001")?,
        "XSY-0001",
        "Auth test",
        IssueState::new("todo")?,
        "2026-07-02T00:00:00Z",
    )?;

    let tracker: Arc<dyn Tracker> = Arc::new(StaticTracker {
        issues: vec![issue],
    });
    let state = AppState::new(
        tracker,
        AgentId::new("symphonyd")?,
        "secret-token".to_owned(),
        None,
    );
    let server = spawn_server(state).await?;
    let client = reqwest::Client::new();

    let missing = client
        .get(format!("{}/symphony/status", server.base_url))
        .send()
        .await?;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let body = missing.json::<Value>().await?;
    assert_eq!(
        body,
        serde_json::json!({"error": "missing or invalid Authorization: Bearer token"})
    );

    let ok = client
        .get(format!("{}/symphony/status", server.base_url))
        .bearer_auth("secret-token")
        .send()
        .await?;
    assert_eq!(ok.status(), StatusCode::OK);
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
    })
}
