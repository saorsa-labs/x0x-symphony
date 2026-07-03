use std::{error::Error, path::PathBuf};

use clap::Parser;
use x0x_symphony_bin::{
    cli::{self, CommandLine},
    config::WorkflowConfig,
};
use x0x_symphony_core::AgentId;
use x0x_symphony_orchestrator::TrustLevel;

#[tokio::test]
async fn repository_workflow_passes_config_check() -> Result<(), Box<dyn Error>> {
    let workflow = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("WORKFLOW.md");
    let workflow_arg = workflow.to_string_lossy().into_owned();
    let output = run_cli(&["x0x-symphony", "config", "check", "--config", &workflow_arg]).await?;
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, "config ok\n");
    assert_eq!(output.stderr, "");
    Ok(())
}

#[tokio::test]
async fn workflow_with_runner_sandbox_passes_config_check() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let workflow_path = dir.path().join("WORKFLOW.md");
    std::fs::write(&workflow_path, workflow_with_sandbox())?;
    let workflow_arg = workflow_path.to_string_lossy().into_owned();

    let output = run_cli(&["x0x-symphony", "config", "check", "--config", &workflow_arg]).await?;

    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, "config ok\n");
    assert_eq!(output.stderr, "");
    Ok(())
}

#[test]
fn security_config_maps_to_orchestrator_config() -> Result<(), Box<dyn Error>> {
    let mut workflow = workflow_missing("none");
    workflow = workflow.replace(
        "agent:\n",
        "security:\n  required_trust: known\n  network_dispatch_enabled: true\n\nagent:\n",
    );

    let config = WorkflowConfig::from_markdown(&workflow)?;
    let orchestrator = config.to_orchestrator_config(AgentId::new("agent-a")?)?;

    assert_eq!(config.security.required_trust, TrustLevel::Known);
    assert!(config.security.network_dispatch_enabled);
    assert_eq!(orchestrator.required_trust, TrustLevel::Known);
    assert!(orchestrator.network_dispatch_enabled);
    Ok(())
}

#[test]
fn network_dispatch_defaults_off() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_missing("none");

    let config = WorkflowConfig::from_markdown(&workflow)?;
    let orchestrator = config.to_orchestrator_config(AgentId::new("agent-a")?)?;

    assert!(!config.security.network_dispatch_enabled);
    assert!(!orchestrator.network_dispatch_enabled);
    Ok(())
}

#[test]
fn tracker_group_is_optional_and_preserved() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_missing("none").replace(
        "tracker:\n  kind: x0x_crdt\n  list_id: x0x-symphony\n",
        concat!(
            "tracker:\n",
            "  kind: x0x_crdt\n",
            "  list_id: x0x-symphony\n",
            "  group: private-project\n",
        ),
    );

    let config = WorkflowConfig::from_markdown(&workflow)?;

    assert_eq!(config.tracker.group.as_deref(), Some("private-project"));
    Ok(())
}

#[tokio::test]
async fn missing_required_blocks_fail_config_check() -> Result<(), Box<dyn Error>> {
    for block in [
        "tracker",
        "polling",
        "workspace",
        "hooks",
        "agent",
        "runner",
    ] {
        let dir = tempfile::tempdir()?;
        let workflow_path = dir.path().join("WORKFLOW.md");
        std::fs::write(&workflow_path, workflow_missing(block))?;
        let workflow_arg = workflow_path.to_string_lossy().into_owned();
        let output =
            run_cli(&["x0x-symphony", "config", "check", "--config", &workflow_arg]).await?;
        assert_eq!(output.exit_code, 1);
        assert_eq!(output.stdout, "");
        assert!(
            output
                .stderr
                .contains(&format!("error: missing required key `{block}`")),
            "stderr was: {}",
            output.stderr
        );
    }
    Ok(())
}

async fn run_cli(args: &[&str]) -> Result<cli::Output, Box<dyn Error>> {
    let command_line = CommandLine::try_parse_from(args)?;
    cli::run(command_line).await.map_err(Into::into)
}

fn workflow_with_sandbox() -> String {
    let mut content = workflow_missing("none");
    content = content.replace(
        "runner:\n  kind: shell\n  command: echo\n",
        concat!(
            "runner:\n",
            "  kind: shell\n",
            "  command: echo\n",
            "  sandbox:\n",
            "    profile: repo-write\n",
            "    backend: none\n",
            "    on_unavailable: warn\n",
            "    egress_allow: [\"api.example.test\"]\n",
        ),
    );
    content
}

fn workflow_missing(block: &str) -> String {
    let mut content = String::from("---\n");
    if block != "tracker" {
        content.push_str("tracker:\n  kind: x0x_crdt\n  list_id: x0x-symphony\n");
    }
    if block != "polling" {
        content.push_str("polling:\n  interval_ms: 1\n");
    }
    if block != "workspace" {
        content.push_str("workspace:\n  root: /tmp/xsy-workspaces\n");
    }
    if block != "hooks" {
        content.push_str(concat!(
            "hooks:\n",
            "  timeout_ms: 1\n",
            "  after_create: \"true\"\n",
            "  before_run: \"true\"\n",
            "  after_run: \"true\"\n",
            "  before_remove: \"true\"\n",
        ));
    }
    if block != "agent" {
        content.push_str(concat!(
            "agent:\n",
            "  max_concurrent_agents: 1\n",
            "  max_concurrent_agents_by_state:\n",
            "    todo: 1\n",
            "  max_turns: 2\n",
            "  max_retry_backoff_ms: 1000\n",
        ));
    }
    if block != "runner" {
        content.push_str("runner:\n  kind: shell\n  command: echo\n");
    }
    content.push_str("---\nPrompt\n");
    content
}
