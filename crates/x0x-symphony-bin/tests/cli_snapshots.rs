use std::error::Error;

use axum::{routing::get, Json, Router};
use clap::Parser;
use serde_json::json;
use tokio::{net::TcpListener, task::JoinHandle};
use x0x_symphony_bin::cli::{self, CommandLine};

struct StubDaemon {
    server: String,
    task: JoinHandle<()>,
}

impl Drop for StubDaemon {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn tasks_snapshot() -> Result<(), Box<dyn Error>> {
    let daemon = spawn_stub_daemon().await?;
    let stdout = run_cli(&[
        "x0x-symphony",
        "--server",
        &daemon.server,
        "--token",
        "stub-token",
        "tasks",
    ])
    .await?;
    assert_eq!(
        stdout,
        "tasks:\n- XSY-0001 [todo] p2 Write daemon\n- XSY-0002 [review] p- Review CLI\n"
    );
    Ok(())
}

#[tokio::test]
async fn status_snapshot() -> Result<(), Box<dyn Error>> {
    let daemon = spawn_stub_daemon().await?;
    let stdout = run_cli(&[
        "x0x-symphony",
        "--server",
        &daemon.server,
        "--token",
        "stub-token",
        "status",
    ])
    .await?;
    assert_eq!(
        stdout,
        concat!(
            "status:\n",
            "agent: symphonyd\n",
            "orchestrator_attached: true\n",
            "counts:\n",
            "- review: 1\n",
            "- todo: 1\n",
            "active_claims:\n",
            "- XSY-0001 [in_progress] by worker-a heartbeat 2026-07-02T00:00:00Z\n",
        )
    );
    Ok(())
}

#[tokio::test]
async fn routes_snapshot() -> Result<(), Box<dyn Error>> {
    let daemon = spawn_stub_daemon().await?;
    let stdout = run_cli(&[
        "x0x-symphony",
        "--server",
        &daemon.server,
        "--token",
        "stub-token",
        "routes",
    ])
    .await?;
    assert_eq!(
        stdout,
        "routes:\n- GET /health\n- GET /symphony/status\n- GET /symphony/tasks\n"
    );
    Ok(())
}

#[tokio::test]
async fn proofs_list_snapshot() -> Result<(), Box<dyn Error>> {
    let daemon = spawn_stub_daemon().await?;
    let stdout = run_cli(&[
        "x0x-symphony",
        "--server",
        &daemon.server,
        "--token",
        "stub-token",
        "proofs",
        "list",
    ])
    .await?;
    assert_eq!(
        stdout,
        "proofs:\n- XSY-0001/run.txt\n- XSY-0002/report.txt\n"
    );
    Ok(())
}

#[tokio::test]
async fn issue_new_reports_jsonl_removal() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let workflow_path = dir.path().join("WORKFLOW.md");
    std::fs::write(
        &workflow_path,
        workflow_with_sharding("/tmp/xsy-workspaces"),
    )?;
    let config_arg = workflow_path.to_string_lossy().into_owned();

    let command_line = CommandLine::try_parse_from([
        "x0x-symphony",
        "issue",
        "new",
        "--config",
        &config_arg,
        "--title",
        "Shard me",
        "--priority",
        "2",
        "--label",
        "x0x-symphony",
    ])?;
    let output = cli::run(command_line).await?;

    assert_eq!(output.exit_code, 1);
    assert_eq!(output.stdout, "");
    assert_eq!(
        output.stderr,
        "x0x-symphony issue new used the removed M1-M2 JSONL tracker; create tasks in x0xd TaskList for M3 (daemon/API task creation is M4 work)\n"
    );
    Ok(())
}

#[tokio::test]
async fn config_show_snapshot() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let workflow_path = dir.path().join("WORKFLOW.md");
    std::fs::write(&workflow_path, valid_workflow("/tmp/xsy-workspaces"))?;
    let config_arg = workflow_path.to_string_lossy().into_owned();
    let stdout = run_cli(&["x0x-symphony", "config", "show", "--config", &config_arg]).await?;
    assert_eq!(
        stdout,
        concat!(
            "{\n",
            "  \"agent\": {\n",
            "    \"max_concurrent_agents\": 1,\n",
            "    \"max_concurrent_agents_by_state\": {\n",
            "      \"todo\": 1\n",
            "    },\n",
            "    \"max_retry_backoff_ms\": 1000,\n",
            "    \"max_turns\": 2\n",
            "  },\n",
            "  \"hooks\": {\n",
            "    \"after_create\": \"true\",\n",
            "    \"after_run\": \"true\",\n",
            "    \"before_remove\": \"true\",\n",
            "    \"before_run\": \"true\",\n",
            "    \"timeout_ms\": 1\n",
            "  },\n",
            "  \"polling\": {\n",
            "    \"interval_ms\": 1\n",
            "  },\n",
            "  \"runner\": {\n",
            "    \"command\": \"echo\",\n",
            "    \"kind\": \"shell\"\n",
            "  },\n",
            "  \"tracker\": {\n",
            "    \"kind\": \"x0x_crdt\",\n",
            "    \"list_id\": \"x0x-symphony\"\n",
            "  },\n",
            "  \"workspace\": {\n",
            "    \"root\": \"/tmp/xsy-workspaces\"\n",
            "  }\n",
            "}\n",
        )
    );
    Ok(())
}

async fn spawn_stub_daemon() -> Result<StubDaemon, Box<dyn Error>> {
    let app = Router::new()
        .route("/symphony/tasks", get(stub_tasks))
        .route("/symphony/status", get(stub_status))
        .route("/symphony/routes", get(stub_routes))
        .route("/symphony/proofs", get(stub_proofs));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let result = axum::serve(listener, app).await;
        if let Err(_error) = result {}
    });
    Ok(StubDaemon {
        server: format!("http://{addr}"),
        task,
    })
}

async fn run_cli(args: &[&str]) -> Result<String, Box<dyn Error>> {
    let command_line = CommandLine::try_parse_from(args)?;
    let output = cli::run(command_line).await?;
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stderr, "");
    Ok(output.stdout)
}

async fn stub_tasks() -> Json<serde_json::Value> {
    Json(json!([
        {
            "id": "XSY-0001",
            "identifier": "XSY-0001",
            "title": "Write daemon",
            "state": "todo",
            "priority": 2,
            "labels": ["x0x-symphony"]
        },
        {
            "id": "XSY-0002",
            "identifier": "XSY-0002",
            "title": "Review CLI",
            "state": "review",
            "labels": []
        }
    ]))
}

async fn stub_status() -> Json<serde_json::Value> {
    Json(json!({
        "agent_id": "symphonyd",
        "counts": {"review": 1, "todo": 1},
        "active_claims": [
            {
                "id": "XSY-0001",
                "identifier": "XSY-0001",
                "state": "in_progress",
                "by": "worker-a",
                "heartbeat_at": "2026-07-02T00:00:00Z"
            }
        ],
        "orchestrator_attached": true
    }))
}

async fn stub_routes() -> Json<serde_json::Value> {
    Json(json!({
        "routes": [
            {"method": "GET", "path": "/health"},
            {"method": "GET", "path": "/symphony/status"},
            {"method": "GET", "path": "/symphony/tasks"}
        ]
    }))
}

async fn stub_proofs() -> Json<serde_json::Value> {
    Json(json!({"proofs": ["XSY-0001/run.txt", "XSY-0002/report.txt"]}))
}

fn workflow_with_sharding(root: &str) -> String {
    valid_workflow(root).replace(
        "polling:\n  interval_ms: 1\n",
        concat!(
            "sharding:\n",
            "  workers: [\"agent-a\", \"agent-b\", \"agent-c\"]\n",
            "  replication_factor: 3\n",
            "polling:\n",
            "  interval_ms: 1\n",
        ),
    )
}

fn valid_workflow(root: &str) -> String {
    format!(
        concat!(
            "---\n",
            "tracker:\n",
            "  kind: x0x_crdt\n",
            "  list_id: x0x-symphony\n",
            "polling:\n",
            "  interval_ms: 1\n",
            "workspace:\n",
            "  root: {}\n",
            "hooks:\n",
            "  timeout_ms: 1\n",
            "  after_create: \"true\"\n",
            "  before_run: \"true\"\n",
            "  after_run: \"true\"\n",
            "  before_remove: \"true\"\n",
            "agent:\n",
            "  max_concurrent_agents: 1\n",
            "  max_concurrent_agents_by_state:\n",
            "    todo: 1\n",
            "  max_turns: 2\n",
            "  max_retry_backoff_ms: 1000\n",
            "runner:\n",
            "  kind: shell\n",
            "  command: echo\n",
            "---\n",
            "Prompt\n",
        ),
        root
    )
}
