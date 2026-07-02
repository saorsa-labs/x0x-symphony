use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::Parser;
use tokio::net::TcpListener;
use tracing::{error, info};
use x0x_symphony_bin::{api, auth, config};
use x0x_symphony_core::AgentId;
use x0x_symphony_orchestrator::{Orchestrator, SystemClock};
use x0x_symphony_runner_shell::{RunnerSpec, ShellRunner};
use x0x_symphony_tracker_git_jsonl::JsonlTracker;
use x0x_symphony_workspace::{Config as WorkspaceConfig, Manager};

#[derive(Debug, Parser)]
#[command(name = "x0x-symphonyd")]
#[command(about = "Run the local x0x-symphony daemon")]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long, default_value = "~/.x0x-symphony")]
    data_dir: String,
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: String,
    #[arg(long, default_value = "symphonyd")]
    agent_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let args = Args::parse();
    run(args).await
}

async fn run(args: Args) -> anyhow::Result<()> {
    let bind_addr = api::validate_loopback_bind(&args.bind)?;
    let data_dir = config::expand_tilde_path(&args.data_dir, "data-dir")?;
    let workflow = config::WorkflowConfig::load(&args.config)?;
    let tracker_paths = workflow.tracker_paths(&args.config)?;
    let api_token = auth::load_or_generate_api_token(&data_dir).await?;
    let agent_id = AgentId::new(args.agent_id.clone())?;

    let tracker = Arc::new(
        JsonlTracker::builder(tracker_paths.repo_root.clone())
            .issues_path(tracker_paths.issues_path.clone())
            .build(),
    );
    let runner_spec = RunnerSpec::from_workflow_config(&workflow.definition.config)
        .context("runner configuration did not resolve")?;
    let runner = Arc::new(ShellRunner::new(runner_spec).context("failed to build shell runner")?);
    let workspace = Arc::new(
        Manager::new(WorkspaceConfig::new(workflow.workspace.root.clone()))
            .context("failed to initialize workspace manager")?,
    );
    let orchestrator_config = workflow.to_orchestrator_config(agent_id.clone())?;
    let orchestrator = Arc::new(Orchestrator::new(
        tracker,
        runner,
        workspace,
        Arc::new(SystemClock),
        orchestrator_config,
    ));

    let _ = orchestrator.reconcile().await;
    let sweep = orchestrator
        .sweep_orphans()
        .await
        .context("orphan workspace sweep failed")?;
    info!(
        preserved = sweep.preserved_count(),
        quarantined = sweep.quarantined_count(),
        refused = sweep.refused_count(),
        "orphan workspace sweep finished before poll loop"
    );

    let orchestrator_handle: Arc<dyn api::OrchestratorHandle> = orchestrator.clone();
    let app_state = api::AppState::new(
        tracker_paths.issues_path.clone(),
        agent_id,
        api_token,
        Some(orchestrator_handle),
    );
    let app = api::build_router(app_state);
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;
    let actual_addr = listener.local_addr().context("failed to read local addr")?;
    let port_file = data_dir.join("daemon.port");
    tokio::fs::write(&port_file, format!("{}\n", actual_addr.port()))
        .await
        .with_context(|| format!("failed to write {}", port_file.display()))?;
    info!(
        bind = %actual_addr,
        port_file = %port_file.display(),
        tracker = %tracker_paths.issues_path.display(),
        "x0x-symphonyd started"
    );

    let shutdown_orchestrator = orchestrator.clone();
    let shutdown = async move {
        wait_for_shutdown_signal().await;
        let signaled = shutdown_orchestrator.shutdown().await;
        info!(signaled, "orchestrator shutdown requested");
    };
    let server = axum::serve(listener, app).with_graceful_shutdown(shutdown);

    tokio::select! {
        result = orchestrator.run() => {
            result.context("orchestrator failed")?;
        }
        result = server => {
            result.context("HTTP server failed")?;
        }
    }
    Ok(())
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .finish();
    let _set_result = tracing::subscriber::set_global_default(subscriber);
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let ctrl_c = async {
            if let Err(source) = tokio::signal::ctrl_c().await {
                error!(%source, "failed to install ctrl-c handler");
            }
        };
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    () = ctrl_c => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(source) => {
                error!(%source, "failed to install SIGTERM handler; waiting for ctrl-c only");
                ctrl_c.await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(source) = tokio::signal::ctrl_c().await {
            error!(%source, "failed to install ctrl-c handler");
        }
    }
}
