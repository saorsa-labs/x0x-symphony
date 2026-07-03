use std::{error::Error, path::PathBuf, time::Duration};

use clap::Parser;
use x0x_symphony_bin::{
    cli::{self, CommandLine},
    config::{Error as ConfigError, WorkflowConfig},
};
use x0x_symphony_core::AgentId;
use x0x_symphony_orchestrator::{NetworkDispatchPolicy, TrustLevel};

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
    let workflow = workflow_with_security(concat!(
        "  required_trust: known\n",
        "  network_dispatch: approve\n",
        "  approval_ttl: 2h\n",
        "  approval_webhook_url: https://approvals.example.test/hook\n",
    ));

    let config = WorkflowConfig::from_markdown(&workflow)?;
    let orchestrator = config.to_orchestrator_config(AgentId::new("agent-a")?)?;

    assert_eq!(config.security.required_trust, TrustLevel::Known);
    assert_eq!(
        config.security.network_dispatch,
        NetworkDispatchPolicy::Approve
    );
    assert_eq!(config.security.approval_ttl, Duration::from_hours(2));
    assert_eq!(
        config.security.approval_webhook_url.as_deref(),
        Some("https://approvals.example.test/hook")
    );
    assert_eq!(orchestrator.required_trust, TrustLevel::Known);
    assert_eq!(
        orchestrator.network_dispatch,
        NetworkDispatchPolicy::Approve
    );
    assert_eq!(orchestrator.approval_ttl, Duration::from_hours(2));
    assert_eq!(
        orchestrator.approval_webhook_url.as_deref(),
        Some("https://approvals.example.test/hook")
    );
    Ok(())
}

#[test]
fn network_dispatch_defaults_off() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_missing("none");

    let config = WorkflowConfig::from_markdown(&workflow)?;
    let orchestrator = config.to_orchestrator_config(AgentId::new("agent-a")?)?;

    assert_eq!(config.security.network_dispatch, NetworkDispatchPolicy::Off);
    assert_eq!(config.security.approval_ttl, Duration::from_hours(24));
    assert_eq!(config.security.approval_webhook_url, None);
    assert_eq!(orchestrator.network_dispatch, NetworkDispatchPolicy::Off);
    assert_eq!(orchestrator.approval_ttl, Duration::from_hours(24));
    assert_eq!(orchestrator.approval_webhook_url, None);
    Ok(())
}

#[test]
fn workers_config_defaults_to_publish_enabled_with_sixty_second_ttl() -> Result<(), Box<dyn Error>>
{
    let workflow = workflow_missing("none");

    let config = WorkflowConfig::from_markdown(&workflow)?;

    assert!(config.workers.publish_enabled);
    assert_eq!(config.workers.ttl_seconds, 60);
    assert!(config.workers.capabilities.is_empty());
    assert!(config.workers.sandbox_levels.is_empty());
    assert!(config.workers.runner_presets.is_empty());
    Ok(())
}

#[test]
fn workers_config_overrides_parse() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_missing("none").replace(
        "agent:\n",
        concat!(
            "workers:\n",
            "  publish_enabled: false\n",
            "  ttl_seconds: 120\n",
            "  capabilities: [\"rust\", \"docs\"]\n",
            "  sandbox_levels: [\"repo-write\"]\n",
            "  runner_presets: [\"claude_code\"]\n\n",
            "agent:\n",
        ),
    );

    let config = WorkflowConfig::from_markdown(&workflow)?;

    assert!(!config.workers.publish_enabled);
    assert_eq!(config.workers.ttl_seconds, 120);
    assert_eq!(config.workers.capabilities, ["rust", "docs"]);
    assert_eq!(config.workers.sandbox_levels, ["repo-write"]);
    assert_eq!(config.workers.runner_presets, ["claude_code"]);
    Ok(())
}

#[test]
fn workers_ttl_must_be_positive() -> Result<(), Box<dyn Error>> {
    let workflow =
        workflow_missing("none").replace("agent:\n", "workers:\n  ttl_seconds: 0\n\nagent:\n");

    let problems = invalid_workflow_problems(&workflow)?;

    assert!(
        problems
            .iter()
            .any(|problem| problem == "workers.ttl_seconds must be >= 1"),
        "problems were: {problems:?}"
    );
    Ok(())
}

#[test]
fn network_dispatch_policy_values_parse() -> Result<(), Box<dyn Error>> {
    for (raw, expected) in [
        ("off", NetworkDispatchPolicy::Off),
        ("approve", NetworkDispatchPolicy::Approve),
        ("auto", NetworkDispatchPolicy::Auto),
    ] {
        let ack = if expected == NetworkDispatchPolicy::Auto {
            "  network_dispatch_auto_ack: true\n"
        } else {
            ""
        };
        let workflow = workflow_with_security(&format!("  network_dispatch: {raw}\n{ack}"));

        let config = WorkflowConfig::from_markdown(&workflow)?;

        assert_eq!(config.security.network_dispatch, expected);
    }
    Ok(())
}

#[test]
fn unknown_network_dispatch_policy_aborts_config_load() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_with_security("  network_dispatch: maybe\n");

    let problems = invalid_workflow_problems(&workflow)?;

    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("security.network_dispatch")),
        "problems were: {problems:?}"
    );
    Ok(())
}

#[test]
fn legacy_network_dispatch_enabled_true_maps_to_approve() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_with_security("  network_dispatch_enabled: true\n");

    let config = WorkflowConfig::from_markdown(&workflow)?;

    assert_eq!(
        config.security.network_dispatch,
        NetworkDispatchPolicy::Approve
    );
    Ok(())
}

#[test]
fn legacy_network_dispatch_enabled_false_maps_to_off() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_with_security("  network_dispatch_enabled: false\n");

    let config = WorkflowConfig::from_markdown(&workflow)?;

    assert_eq!(config.security.network_dispatch, NetworkDispatchPolicy::Off);
    Ok(())
}

#[test]
fn auto_network_dispatch_without_ack_aborts_config_load() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_with_security("  network_dispatch: auto\n");

    let problems = invalid_workflow_problems(&workflow)?;

    assert!(
        problems.iter().any(|problem| problem
            == "security.network_dispatch=auto requires network_dispatch_auto_ack=true"),
        "problems were: {problems:?}"
    );
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

fn invalid_workflow_problems(workflow: &str) -> Result<Vec<String>, Box<dyn Error>> {
    match WorkflowConfig::from_markdown(workflow) {
        Ok(_) => Err("workflow config should have failed validation".into()),
        Err(ConfigError::Invalid { problems }) => Ok(problems),
        Err(error) => Err(error.into()),
    }
}

fn workflow_with_security(security_body: &str) -> String {
    workflow_missing("none").replace("agent:\n", &format!("security:\n{security_body}\nagent:\n"))
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
