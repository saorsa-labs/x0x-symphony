use std::{
    error::Error,
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use clap::Parser;
use x0x_symphony_bin::{
    cli::{self, CommandLine},
    config::{Error as ConfigError, WorkflowConfig},
};
use x0x_symphony_core::AgentId;
use x0x_symphony_orchestrator::{NetworkDispatchPolicy, TrustLevel};

#[derive(Clone, Default)]
struct SharedWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
}

struct SharedWriterGuard {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for SharedWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut bytes = self
            .bytes
            .lock()
            .map_err(|_error| io::Error::other("trace buffer lock poisoned"))?;
        bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for SharedWriter {
    type Writer = SharedWriterGuard;

    fn make_writer(&'writer self) -> Self::Writer {
        SharedWriterGuard {
            bytes: Arc::clone(&self.bytes),
        }
    }
}

fn logs_from_writer(writer: &SharedWriter) -> Result<String, Box<dyn Error>> {
    let bytes = writer
        .bytes
        .lock()
        .map_err(|_error| io::Error::other("trace buffer lock poisoned"))?
        .clone();
    String::from_utf8(bytes).map_err(Into::into)
}

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
    let workflow = with_required_signing(&workflow_with_security(concat!(
        "  required_trust: known\n",
        "  network_dispatch: approve\n",
        "  approval_ttl: 2h\n",
        "  approval_webhook_url: https://approvals.example.test/hook\n",
    )));

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
fn retention_defaults_to_thirty_days_and_hourly_reaper() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_missing("none");

    let config = WorkflowConfig::from_markdown(&workflow)?;
    let orchestrator = config.to_orchestrator_config(AgentId::new("agent-a")?)?;

    assert_eq!(config.retention.proofs_days, 30);
    assert_eq!(config.retention.reap_interval_secs, 3_600);
    assert_eq!(orchestrator.retention.proofs_days, 30);
    assert_eq!(
        orchestrator.retention.reap_interval,
        Duration::from_hours(1)
    );
    Ok(())
}

#[test]
fn retention_overrides_parse() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_with_retention("  proofs_days: 7\n  reap_interval_secs: 120\n");

    let config = WorkflowConfig::from_markdown(&workflow)?;
    let orchestrator = config.to_orchestrator_config(AgentId::new("agent-a")?)?;

    assert_eq!(config.retention.proofs_days, 7);
    assert_eq!(config.retention.reap_interval_secs, 120);
    assert_eq!(orchestrator.retention.proofs_days, 7);
    assert_eq!(orchestrator.retention.reap_interval, Duration::from_mins(2));
    Ok(())
}

#[test]
fn retention_proofs_days_rejects_zero() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_with_retention("  proofs_days: 0\n");

    let problems = invalid_workflow_problems(&workflow)?;

    assert!(
        problems
            .iter()
            .any(|problem| problem == "retention.proofs_days must be >= 1"),
        "problems were: {problems:?}"
    );
    Ok(())
}

#[test]
fn retention_reap_interval_rejects_under_sixty_seconds() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_with_retention("  reap_interval_secs: 59\n");

    let problems = invalid_workflow_problems(&workflow)?;

    assert!(
        problems
            .iter()
            .any(|problem| problem == "retention.reap_interval_secs must be >= 60"),
        "problems were: {problems:?}"
    );
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
fn sharding_workers_emit_deprecation_warn() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_missing("none").replace(
        "polling:\n  interval_ms: 1\n",
        concat!(
            "sharding:\n",
            "  workers: [\"agent-a\", \"agent-b\"]\n",
            "  replication_factor: 2\n",
            "polling:\n",
            "  interval_ms: 1\n",
        ),
    );
    let writer = SharedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(writer.clone())
        .without_time()
        .finish();

    let config =
        tracing::subscriber::with_default(subscriber, || WorkflowConfig::from_markdown(&workflow))?;

    assert_eq!(config.sharding.workers.len(), 2);
    assert!(logs_from_writer(&writer)?.contains("sharding.workers is deprecated"));
    Ok(())
}

#[test]
fn legacy_codex_block_fails_config_load_with_structured_error() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_with_legacy_codex_block();

    let problems = invalid_workflow_problems(&workflow)?;

    assert_eq!(problems.len(), 1, "problems were: {problems:?}");
    let problem = &problems[0];
    assert!(
        problem.contains("`codex:` top-level block was removed in XSY-0031"),
        "problem was: {problem}"
    );
    assert!(
        problem.contains("`runner: {kind: shell, preset: codex}`"),
        "problem was: {problem}"
    );
    assert!(
        problem.contains("docs/symphony/operator.md#migrating-from-the-legacy-codex-block"),
        "problem was: {problem}"
    );
    Ok(())
}

#[tokio::test]
async fn legacy_codex_block_config_check_fails_with_structured_error() -> Result<(), Box<dyn Error>>
{
    let dir = tempfile::tempdir()?;
    let workflow_path = dir.path().join("WORKFLOW.md");
    std::fs::write(&workflow_path, workflow_with_legacy_codex_block())?;
    let workflow_arg = workflow_path.to_string_lossy().into_owned();

    let output = run_cli(&["x0x-symphony", "config", "check", "--config", &workflow_arg]).await?;

    assert_eq!(output.exit_code, 1);
    assert_eq!(output.stdout, "");
    assert!(
        output
            .stderr
            .contains("error: `codex:` top-level block was removed in XSY-0031"),
        "stderr was: {}",
        output.stderr
    );
    assert!(
        output
            .stderr
            .contains("`runner: {kind: shell, preset: codex}`"),
        "stderr was: {}",
        output.stderr
    );
    assert!(
        output
            .stderr
            .contains("docs/symphony/operator.md#migrating-from-the-legacy-codex-block"),
        "stderr was: {}",
        output.stderr
    );
    assert!(!output.stderr.contains("warning:"));
    assert!(!output.stderr.contains("deprecated"));
    Ok(())
}

#[tokio::test]
async fn workflow_without_legacy_codex_block_has_no_codex_warning() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let workflow_path = dir.path().join("WORKFLOW.md");
    std::fs::write(&workflow_path, workflow_missing("none"))?;
    let workflow_arg = workflow_path.to_string_lossy().into_owned();

    let config = WorkflowConfig::from_markdown(&workflow_missing("none"))?;
    let output = run_cli(&["x0x-symphony", "config", "check", "--config", &workflow_arg]).await?;

    assert!(config.warnings.is_empty());
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, "config ok\n");
    assert_eq!(output.stderr, "");
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
        let mut workflow = workflow_with_security(&format!("  network_dispatch: {raw}\n{ack}"));
        if expected == NetworkDispatchPolicy::Approve {
            // approve without signing.policy=required is rejected outright.
            workflow = with_required_signing(&workflow);
        }

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
    let workflow = with_required_signing(&workflow_with_security(
        "  network_dispatch_enabled: true\n",
    ));

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

/// Issue #6 defect 3: `network_dispatch: approve` with tracker signing
/// disabled is an unrecoverable trap — locally created issues can never carry
/// verified provenance, so nothing could ever be approved or dispatched. The
/// pairing must be rejected at config load, mirroring the auto+auto_ack gate.
#[test]
fn approve_without_required_signing_aborts_config_load() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_with_security("  network_dispatch: approve\n");

    let problems = invalid_workflow_problems(&workflow)?;

    assert!(
        problems.iter().any(|problem| problem
            .starts_with("security.network_dispatch=approve requires signing.policy=required")),
        "problems were: {problems:?}"
    );
    Ok(())
}

#[test]
fn approve_with_required_signing_loads() -> Result<(), Box<dyn Error>> {
    let workflow = with_required_signing(&workflow_with_security("  network_dispatch: approve\n"));

    let config = WorkflowConfig::from_markdown(&workflow)?;

    assert_eq!(
        config.security.network_dispatch,
        NetworkDispatchPolicy::Approve
    );
    assert!(config.warnings.is_empty());
    Ok(())
}

/// Explicit `network_dispatch: off` without required signing leaves local
/// issues undispatchable (they carry no self-signed provenance); the config
/// must warn loudly instead of trapping the operator silently.
#[test]
fn explicit_off_without_required_signing_warns() -> Result<(), Box<dyn Error>> {
    let workflow = workflow_with_security("  network_dispatch: off\n");

    let config = WorkflowConfig::from_markdown(&workflow)?;

    assert!(
        config
            .warnings
            .iter()
            .any(|warning| warning.contains("network_dispatch=off")
                && warning.contains("signing.policy=required")),
        "warnings were: {:?}",
        config.warnings
    );
    Ok(())
}

/// A minimal config with no `security:` block keeps the quiet default —
/// the off/signing pairing warning is only for explicitly configured security.
#[test]
fn default_security_without_block_does_not_warn() -> Result<(), Box<dyn Error>> {
    let config = WorkflowConfig::from_markdown(&workflow_missing("none"))?;

    assert_eq!(config.security.network_dispatch, NetworkDispatchPolicy::Off);
    assert!(config.warnings.is_empty());
    Ok(())
}

fn with_required_signing(workflow: &str) -> String {
    workflow.replace("agent:\n", "signing:\n  policy: required\nagent:\n")
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

fn workflow_with_retention(retention_body: &str) -> String {
    workflow_missing("none").replace(
        "agent:\n",
        &format!("retention:\n{retention_body}\nagent:\n"),
    )
}

fn workflow_with_legacy_codex_block() -> String {
    workflow_missing("none").replace(
        "runner:\n  kind: shell\n",
        concat!(
            "codex:\n",
            "  app_server: true\n\n",
            "runner:\n",
            "  kind: shell\n",
        ),
    )
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
