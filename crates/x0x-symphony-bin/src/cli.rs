//! Clap definitions and deterministic CLI command dispatch.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use reqwest::StatusCode;
use thiserror::Error;
use x0x_symphony_core::IssueDraft;

use crate::{client, config::WorkflowConfig};

/// Result alias for CLI dispatch.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level `x0x-symphony` command line.
#[derive(Clone, Debug, Parser)]
#[command(name = "x0x-symphony")]
#[command(about = "Control a local x0x-symphony daemon")]
#[command(subcommand_required = true, arg_required_else_help = true)]
pub struct CommandLine {
    /// Server URL. Defaults to `http://127.0.0.1:<daemon.port>`.
    #[arg(long)]
    server: Option<String>,
    /// Daemon data directory containing `daemon.port` and `api-token`.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Bearer token. Defaults to reading `api-token`.
    #[arg(long)]
    token: Option<String>,
    /// Bearer token file. Defaults to `<data-dir>/api-token`.
    #[arg(long)]
    token_file: Option<PathBuf>,
    /// Command to execute.
    #[command(subcommand)]
    command: Commands,
}

/// Top-level CLI subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum Commands {
    /// List tasks, optionally filtered by state.
    Tasks {
        /// State filter, such as `todo` or `review`.
        #[arg(long)]
        state: Option<String>,
    },
    /// Claim a task by id.
    Claim {
        /// Issue id to claim.
        id: String,
    },
    /// Record a handoff for a claimed task.
    Handoff {
        /// Issue id to hand off.
        id: String,
        /// Handoff message.
        #[arg(long)]
        message: String,
        /// Optional changed file to record.
        #[arg(long)]
        file: Option<String>,
    },
    /// Show daemon status.
    Status,
    /// Inspect and act on network-sourced task approvals.
    Approvals {
        /// Approval subcommand.
        #[command(subcommand)]
        command: ApprovalsCommand,
    },
    /// Inspect proof artefacts.
    Proofs {
        /// Proof subcommand.
        #[command(subcommand)]
        command: ProofsCommand,
    },
    /// Create or inspect issues in the configured tracker.
    Issue {
        /// Issue subcommand.
        #[command(subcommand)]
        command: IssueCommand,
    },
    /// Inspect or validate workflow configuration.
    Config {
        /// Config subcommand.
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// List daemon HTTP routes.
    Routes,
}

/// Approval-related subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum ApprovalsCommand {
    /// List network-sourced issues awaiting an approval decision.
    List,
    /// Approve a network-sourced issue for execution.
    Approve {
        /// Issue id to approve.
        id: String,
        /// Optional expected content hash; POST fails with 409 if it no longer matches (stale-UI protection).
        #[arg(long)]
        expected_hash: Option<String>,
        /// Optional expected network signer agent id; POST fails with 409 on mismatch.
        #[arg(long)]
        expected_signer: Option<String>,
    },
    /// Deny a network-sourced issue (terminal until payload changes).
    Deny {
        /// Issue id to deny.
        id: String,
        /// Optional expected content hash; POST fails with 409 if it no longer matches (stale-UI protection).
        #[arg(long)]
        expected_hash: Option<String>,
        /// Optional expected network signer agent id; POST fails with 409 on mismatch.
        #[arg(long)]
        expected_signer: Option<String>,
    },
}

/// Proof-related subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum ProofsCommand {
    /// List proof artefacts known to the daemon.
    List,
    /// Show one proof artefact.
    Show {
        /// Proof name relative to the daemon proofs root.
        name: String,
    },
}

/// Issue-related subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum IssueCommand {
    /// Create an issue through the daemon tracker.
    New {
        /// Deprecated; daemon workflow controls tracker and sharding settings.
        #[arg(long, default_value = "WORKFLOW.md")]
        config: PathBuf,
        /// Issue title.
        #[arg(long)]
        title: String,
        /// Markdown-capable issue description.
        #[arg(long, default_value = "")]
        description: String,
        /// Dispatch priority where lower values run earlier.
        #[arg(long)]
        priority: Option<u8>,
        /// Label to attach; may be supplied more than once.
        #[arg(long = "label")]
        labels: Vec<String>,
    },
}

/// Workflow configuration subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print parsed workflow frontmatter as deterministic JSON.
    Show {
        /// Workflow file path.
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate workflow frontmatter.
    Check {
        /// Workflow file path.
        #[arg(long)]
        config: PathBuf,
    },
}

/// Deterministic command output plus process exit code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Output {
    /// Text to write to stdout.
    pub stdout: String,
    /// Text to write to stderr.
    pub stderr: String,
    /// Process exit code.
    pub exit_code: u8,
}

/// Errors produced by CLI dispatch.
#[derive(Debug, Error)]
pub enum Error {
    /// HTTP client setup or request failed.
    #[error(transparent)]
    Client(#[from] client::Error),
    /// Workflow configuration loading failed.
    #[error(transparent)]
    Config(#[from] crate::config::Error),
}

impl Output {
    /// Build a successful output value.
    #[must_use]
    pub fn success(stdout: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: 0,
        }
    }

    /// Build a failing output value.
    #[must_use]
    pub fn failure(stderr: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: stderr.into(),
            exit_code: 1,
        }
    }
}

/// Dispatch one parsed CLI invocation.
///
/// # Errors
///
/// Returns [`enum@Error`] for daemon client errors and surprising config show errors.
pub async fn run(command_line: CommandLine) -> Result<Output> {
    match &command_line.command {
        Commands::Config { command } => run_config(command),
        command => run_daemon_command(&command_line, command).await,
    }
}

async fn run_daemon_command(command_line: &CommandLine, command: &Commands) -> Result<Output> {
    let client = client_options(command_line).into_client().await?;
    match command {
        Commands::Tasks { state } => {
            let tasks = client.tasks(state.as_deref()).await?;
            Ok(Output::success(format_tasks(&tasks)))
        }
        Commands::Claim { id } => {
            let claim = client.claim(id).await?;
            Ok(Output::success(format!(
                "claimed {} by {}\n",
                claim.id, claim.by
            )))
        }
        Commands::Handoff { id, message, file } => {
            let response = client.handoff(id, message.clone(), file.clone()).await?;
            let line = if response.recorded {
                format!("handoff recorded for {}\n", response.id)
            } else {
                format!("handoff not recorded for {}\n", response.id)
            };
            Ok(Output::success(line))
        }
        Commands::Status => {
            let status = client.status().await?;
            Ok(Output::success(format_status(&status)))
        }
        Commands::Approvals { command } => match command {
            ApprovalsCommand::List => {
                let pending = client.approvals_pending().await?;
                Ok(Output::success(format_pending_approvals(&pending)))
            }
            ApprovalsCommand::Approve {
                id,
                expected_hash,
                expected_signer,
            } => match client
                .approve(id, expected_hash.as_deref(), expected_signer.as_deref())
                .await
            {
                Ok(event) => Ok(Output::success(format!("{} approved\n", event.issue_id))),
                Err(error) => approval_error_output(error),
            },
            ApprovalsCommand::Deny {
                id,
                expected_hash,
                expected_signer,
            } => match client
                .deny(id, expected_hash.as_deref(), expected_signer.as_deref())
                .await
            {
                Ok(event) => Ok(Output::success(format!("{} denied\n", event.issue_id))),
                Err(error) => approval_error_output(error),
            },
        },
        Commands::Proofs { command } => match command {
            ProofsCommand::List => {
                let proofs = client.proofs().await?;
                Ok(Output::success(format_proofs(&proofs.proofs)))
            }
            ProofsCommand::Show { name } => {
                let proof = client.proof(name).await?;
                Ok(Output::success(ensure_trailing_newline(proof.content)))
            }
        },
        Commands::Routes => {
            let routes = client.routes().await?;
            Ok(Output::success(format_routes(&routes.routes)))
        }
        Commands::Issue { command } => run_issue(&client, command).await,
        Commands::Config { .. } => Ok(Output::failure(
            "internal error: local command reached daemon dispatch\n",
        )),
    }
}

fn approval_error_output(error: client::Error) -> Result<Output> {
    match error {
        client::Error::Http { status, body } if status == StatusCode::CONFLICT => {
            Ok(Output::failure(format_approval_conflict(&body)))
        }
        other => Err(other.into()),
    }
}

async fn run_issue(client: &client::SymphonyClient, command: &IssueCommand) -> Result<Output> {
    match command {
        IssueCommand::New {
            config: _,
            title,
            description,
            priority,
            labels,
        } => {
            let draft = IssueDraft {
                title: title.clone(),
                description: (!description.trim().is_empty()).then_some(description.clone()),
                priority: priority.map(i32::from),
                labels: labels.clone(),
            };
            let issue = client.create_issue(&draft).await?;
            Ok(Output::success(format!("created {}\n", issue.identifier)))
        }
    }
}

fn run_config(command: &ConfigCommand) -> Result<Output> {
    match command {
        ConfigCommand::Show { config } => {
            let workflow = WorkflowConfig::load(config)?;
            Ok(Output::success(format!(
                "{}\n",
                workflow.pretty_config_json()?
            )))
        }
        ConfigCommand::Check { config } => match WorkflowConfig::load(config) {
            Ok(_) => Ok(Output::success("config ok\n")),
            Err(crate::config::Error::Invalid { problems }) => {
                Ok(Output::failure(format_validation_errors(&problems)))
            }
            Err(error) => Ok(Output::failure(format!("{error}\n"))),
        },
    }
}

fn client_options(command_line: &CommandLine) -> client::Options {
    client::Options {
        server: command_line.server.clone(),
        data_dir: command_line.data_dir.clone(),
        token: command_line.token.clone(),
        token_file: command_line.token_file.clone(),
    }
}

fn format_tasks(tasks: &[crate::api::Task]) -> String {
    let mut lines = Vec::with_capacity(tasks.len().saturating_add(1));
    lines.push("tasks:".to_owned());
    for task in tasks {
        let priority = task
            .priority
            .map_or_else(|| "p-".to_owned(), |value| format!("p{value}"));
        lines.push(format!(
            "- {} [{}] {} {}",
            task.identifier, task.state, priority, task.title
        ));
    }
    join_lines(&lines)
}

fn format_pending_approvals(pending: &[crate::api::PendingApproval]) -> String {
    let mut lines = Vec::with_capacity(pending.len().saturating_add(1));
    lines.push("approvals:".to_owned());
    if pending.is_empty() {
        lines.push("- none".to_owned());
    } else {
        for approval in pending {
            lines.push(format!(
                "- {} [{}] signer {} hash {} {}",
                approval.issue_id,
                approval.state,
                approval.signer_agent_id,
                short_hash(&approval.content_hash),
                approval.title
            ));
        }
    }
    join_lines(&lines)
}

fn short_hash(content_hash: &str) -> String {
    content_hash.chars().take(12).collect()
}

fn format_status(status: &crate::api::Status) -> String {
    let mut lines = vec![
        "status:".to_owned(),
        format!("agent: {}", status.agent_id),
        format!("orchestrator_attached: {}", status.orchestrator_attached),
        "counts:".to_owned(),
    ];
    if status.counts.is_empty() {
        lines.push("- none: 0".to_owned());
    } else {
        for (state, count) in &status.counts {
            lines.push(format!("- {state}: {count}"));
        }
    }
    lines.push("active_claims:".to_owned());
    if status.active_claims.is_empty() {
        lines.push("- none".to_owned());
    } else {
        for claim in &status.active_claims {
            lines.push(format!(
                "- {} [{}] by {} heartbeat {}",
                claim.identifier, claim.state, claim.by, claim.heartbeat_at
            ));
        }
    }
    join_lines(&lines)
}

fn format_routes(routes: &[crate::api::RouteInfo]) -> String {
    let mut lines = Vec::with_capacity(routes.len().saturating_add(1));
    lines.push("routes:".to_owned());
    for route in routes {
        lines.push(format!("- {} {}", route.method, route.path));
    }
    join_lines(&lines)
}

fn format_proofs(proofs: &[String]) -> String {
    let mut lines = Vec::with_capacity(proofs.len().saturating_add(1));
    lines.push("proofs:".to_owned());
    if proofs.is_empty() {
        lines.push("- none".to_owned());
    } else {
        for proof in proofs {
            lines.push(format!("- {proof}"));
        }
    }
    join_lines(&lines)
}

fn format_validation_errors(problems: &[String]) -> String {
    let lines = problems
        .iter()
        .map(|problem| format!("error: {problem}"))
        .collect::<Vec<_>>();
    join_lines(&lines)
}

fn format_approval_conflict(body: &str) -> String {
    let detail = match daemon_error_detail(body) {
        Some(detail) => detail,
        None => body.trim().to_owned(),
    };
    let is_stale_view =
        detail.contains("issue payload changed") || detail.contains("issue signer changed");
    if is_stale_view || detail.is_empty() {
        "issue payload changed since you viewed it; re-check and retry\n".to_owned()
    } else if let Some(stripped) = detail.strip_prefix("conflict: ") {
        format!("approval conflict: {stripped}\n")
    } else {
        format!("approval conflict: {detail}\n")
    }
}

fn daemon_error_detail(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|error| error.as_str())
                .map(str::to_owned)
        })
}

fn join_lines(lines: &[String]) -> String {
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

fn ensure_trailing_newline(mut content: String) -> String {
    if !content.ends_with('\n') {
        content.push('\n');
    }
    content
}
