use std::error::Error;

use axum::{
    extract::Path,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::{error::ErrorKind, Parser};
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
async fn approvals_list_snapshot() -> Result<(), Box<dyn Error>> {
    let daemon = spawn_stub_daemon().await?;
    let stdout = run_cli(&[
        "x0x-symphony",
        "--server",
        &daemon.server,
        "--token",
        "stub-token",
        "approvals",
        "list",
    ])
    .await?;
    assert_eq!(
        stdout,
        "approvals:\n- XSY-0003 [todo] signer network-signer hash abcdef123456 Review network task\n"
    );
    Ok(())
}

#[tokio::test]
async fn approvals_approve_snapshot() -> Result<(), Box<dyn Error>> {
    let daemon = spawn_stub_daemon().await?;
    let stdout = run_cli(&[
        "x0x-symphony",
        "--server",
        &daemon.server,
        "--token",
        "stub-token",
        "approvals",
        "approve",
        "XSY-0003",
        "--expected-hash",
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "--expected-signer",
        "network-signer",
    ])
    .await?;
    assert_eq!(stdout, "XSY-0003 approved\n");
    Ok(())
}

#[tokio::test]
async fn approvals_deny_snapshot() -> Result<(), Box<dyn Error>> {
    let daemon = spawn_stub_daemon().await?;
    let stdout = run_cli(&[
        "x0x-symphony",
        "--server",
        &daemon.server,
        "--token",
        "stub-token",
        "approvals",
        "deny",
        "XSY-0003",
    ])
    .await?;
    assert_eq!(stdout, "XSY-0003 denied\n");
    Ok(())
}

#[tokio::test]
async fn approvals_conflict_is_operator_friendly() -> Result<(), Box<dyn Error>> {
    let daemon = spawn_stub_daemon().await?;
    let output = run_cli_output(&[
        "x0x-symphony",
        "--server",
        &daemon.server,
        "--token",
        "stub-token",
        "approvals",
        "approve",
        "XSY-CONFLICT",
        "--expected-hash",
        "stale",
    ])
    .await?;
    assert_eq!(output.exit_code, 1);
    assert_eq!(output.stdout, "");
    assert_eq!(
        output.stderr,
        "issue payload changed since you viewed it; re-check and retry\n"
    );
    Ok(())
}

#[test]
fn approvals_help_snapshots() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        render_help(&["approvals"])?,
        concat!(
            "Inspect and act on network-sourced task approvals\n\n",
            "Usage: x0x-symphony approvals <COMMAND>\n\n",
            "Commands:\n",
            "  list     List network-sourced issues awaiting an approval decision\n",
            "  approve  Approve a network-sourced issue for execution\n",
            "  deny     Deny a network-sourced issue (terminal until payload changes)\n",
            "  help     Print this message or the help of the given subcommand(s)\n\n",
            "Options:\n",
            "  -h, --help  Print help\n",
        )
    );
    assert_eq!(
        render_help(&["approvals", "list"])?,
        concat!(
            "List network-sourced issues awaiting an approval decision\n\n",
            "Usage: x0x-symphony approvals list\n\n",
            "Options:\n",
            "  -h, --help  Print help\n",
        )
    );
    assert_eq!(
        render_help(&["approvals", "approve"])?,
        concat!(
            "Approve a network-sourced issue for execution\n\n",
            "Usage: x0x-symphony approvals approve [OPTIONS] <ID>\n\n",
            "Arguments:\n",
            "  <ID>  Issue id to approve\n\n",
            "Options:\n",
            "      --expected-hash <EXPECTED_HASH>\n",
            "          Optional expected content hash; POST fails with 409 if it no longer matches (stale-UI protection)\n",
            "      --expected-signer <EXPECTED_SIGNER>\n",
            "          Optional expected network signer agent id; POST fails with 409 on mismatch\n",
            "  -h, --help\n",
            "          Print help\n",
        )
    );
    assert_eq!(
        render_help(&["approvals", "deny"])?,
        concat!(
            "Deny a network-sourced issue (terminal until payload changes)\n\n",
            "Usage: x0x-symphony approvals deny [OPTIONS] <ID>\n\n",
            "Arguments:\n",
            "  <ID>  Issue id to deny\n\n",
            "Options:\n",
            "      --expected-hash <EXPECTED_HASH>\n",
            "          Optional expected content hash; POST fails with 409 if it no longer matches (stale-UI protection)\n",
            "      --expected-signer <EXPECTED_SIGNER>\n",
            "          Optional expected network signer agent id; POST fails with 409 on mismatch\n",
            "  -h, --help\n",
            "          Print help\n",
        )
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
async fn issue_new_dispatches_to_daemon_create_issue() -> Result<(), Box<dyn Error>> {
    let daemon = spawn_stub_daemon().await?;
    let stdout = run_cli(&[
        "x0x-symphony",
        "--server",
        &daemon.server,
        "--token",
        "stub-token",
        "issue",
        "new",
        "--title",
        "Shard me",
        "--description",
        "body",
        "--priority",
        "2",
        "--label",
        "x0x-symphony",
    ])
    .await?;

    assert_eq!(stdout, "created TASK-NEW\n");
    Ok(())
}

#[test]
fn issue_new_help_renders() -> Result<(), Box<dyn Error>> {
    let help = render_help(&["issue", "new"])?;
    assert!(help.contains("Create an issue through the daemon tracker"));
    assert!(help.contains("--title <TITLE>"));
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
        .route("/symphony/approvals/pending", get(stub_pending_approvals))
        .route("/symphony/approvals/{id}", post(stub_submit_approval))
        .route("/symphony/issues", post(stub_create_issue))
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
    let output = run_cli_output(args).await?;
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stderr, "");
    Ok(output.stdout)
}

async fn run_cli_output(args: &[&str]) -> Result<cli::Output, Box<dyn Error>> {
    let command_line = CommandLine::try_parse_from(args)?;
    cli::run(command_line).await.map_err(Into::into)
}

fn render_help(path: &[&str]) -> Result<String, Box<dyn Error>> {
    let mut args = Vec::with_capacity(path.len().saturating_add(2));
    args.push("x0x-symphony");
    args.extend_from_slice(path);
    args.push("--help");
    match CommandLine::try_parse_from(args) {
        Ok(_) => Err(std::io::Error::other("help parse unexpectedly succeeded").into()),
        Err(error) if error.kind() == ErrorKind::DisplayHelp => Ok(error.to_string()),
        Err(error) => Err(error.into()),
    }
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

async fn stub_pending_approvals() -> Json<serde_json::Value> {
    Json(json!([
        {
            "issue_id": "XSY-0003",
            "title": "Review network task",
            "state": "todo",
            "content_hash": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "signer_agent_id": "network-signer",
            "provenance": {"kind": "verified", "signer_agent_id": "network-signer"},
            "approval_summary": {"events": 0, "consumed": 0, "has_deny": false}
        }
    ]))
}

async fn stub_submit_approval(
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    if id == "XSY-CONFLICT" {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "conflict: issue payload changed: expected content hash stale, current abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            })),
        );
    }
    let verdict = body
        .get("verdict")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("approve");
    (
        StatusCode::OK,
        Json(json!({
            "issue_id": id,
            "content_hash": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "signer_agent_id": "network-signer",
            "verdict": verdict,
            "approved_at": "2026-07-03T00:00:00Z",
            "approver_agent_id": "operator"
        })),
    )
}

async fn stub_create_issue(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    Json(json!({
        "schema_version": 1,
        "id": "TASK-NEW",
        "identifier": "TASK-NEW",
        "title": body.get("title").and_then(serde_json::Value::as_str).unwrap_or("Untitled"),
        "description": body.get("description").and_then(serde_json::Value::as_str).unwrap_or(""),
        "priority": body.get("priority").and_then(serde_json::Value::as_i64),
        "state": "todo",
        "branch_name": null,
        "url": null,
        "labels": body.get("labels").and_then(serde_json::Value::as_array).cloned().unwrap_or_default(),
        "blocked_by": [],
        "created_at": "2026-07-03T00:00:00Z",
        "updated_at": "2026-07-03T00:00:00Z"
    }))
}

async fn stub_proofs() -> Json<serde_json::Value> {
    Json(json!({"proofs": ["XSY-0001/run.txt", "XSY-0002/report.txt"]}))
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
