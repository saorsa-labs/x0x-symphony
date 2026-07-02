use std::error::Error;

use reqwest::StatusCode;
use serde_json::Value;
use tokio::{net::TcpListener, task::JoinHandle};
use x0x_symphony_bin::api::{build_router, AppState};
use x0x_symphony_core::{AgentId, Issue, IssueId, IssueState};
use x0x_symphony_tracker_git_jsonl::serialize_issue;

struct TestServer {
    base_url: String,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn symphony_routes_require_bearer_token() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let issues_dir = dir.path().join("issues");
    std::fs::create_dir_all(&issues_dir)?;
    let issues_path = issues_dir.join("issues.jsonl");
    let issue = Issue::new(
        IssueId::new("XSY-0001")?,
        "XSY-0001",
        "Auth test",
        IssueState::new("todo")?,
        "2026-07-02T00:00:00Z",
    )?;
    std::fs::write(&issues_path, format!("{}\n", serialize_issue(&issue)?))?;

    let state = AppState::new(
        issues_path,
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
