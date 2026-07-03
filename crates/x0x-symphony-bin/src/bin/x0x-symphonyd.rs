use std::{
    env,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use serde_json::json;
use tokio::{net::TcpListener, sync::broadcast};
use tracing::{error, info, warn};
use x0x_symphony_bin::{api, auth, config, workers};
use x0x_symphony_core::AgentId;
use x0x_symphony_orchestrator::{
    DispatchEvent, Orchestrator, SystemClock, TrustClient, X0xdTrustClient,
    DISPATCH_EVENT_CHANNEL_CAPACITY,
};
use x0x_symphony_runner_shell::{RunnerSpec, ShellRunner};
use x0x_symphony_signing::{SigningClient, SigningPolicy, TrustedKeyResolver, X0xdClient};
use x0x_symphony_tracker_x0x_crdt::X0xCrdtTracker;
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
    let workflow_root = workflow_root(&args.config);
    let proofs_dir = workflow_root.join("proofs");
    if args.agent_id != "symphonyd" {
        info!(
            requested_agent_id = %args.agent_id,
            "--agent-id is ignored by the M3 x0x_crdt tracker; using x0xd /agent identity"
        );
    }
    let api_token = auth::load_or_generate_api_token(&data_dir).await?;
    let (tracker, agent_id, signing_client) = build_tracker(&workflow).await?;
    let runner_spec = RunnerSpec::from_workflow_config(&workflow.definition.config)
        .context("runner configuration did not resolve")?;
    let local_worker_card = local_worker_card_template(&workflow, &runner_spec, agent_id.clone());
    let runner =
        Arc::new(ShellRunner::new(runner_spec.clone()).context("failed to build shell runner")?);
    let workspace = Arc::new(
        Manager::new(WorkspaceConfig::new(workflow.workspace.root.clone()))
            .context("failed to initialize workspace manager")?,
    );
    let orchestrator_config = workflow
        .to_orchestrator_config(agent_id.clone())?
        .with_proofs_dir(proofs_dir.clone());
    let trust_client: Arc<dyn TrustClient> = Arc::new(
        X0xdTrustClient::new(&workflow.signing.x0xd_url)
            .context("failed to configure x0xd trust client")?,
    );
    let api_signing_client: Arc<dyn SigningClient> = signing_client.clone();
    let approval_signing_client: Arc<dyn SigningClient> = signing_client.clone();
    let worker_signing_client = signing_client.clone();
    let approval_key_resolver: Arc<dyn TrustedKeyResolver> = signing_client;
    let (dispatch_events_tx, _) = broadcast::channel(DISPATCH_EVENT_CHANNEL_CAPACITY);
    let orchestrator = Arc::new(
        Orchestrator::new_with_signing(
            tracker.clone(),
            runner,
            workspace,
            Arc::new(SystemClock),
            orchestrator_config,
            trust_client,
            Some(approval_signing_client),
            Some(approval_key_resolver),
        )
        .with_event_tx(dispatch_events_tx),
    );
    let _worker_discovery_handle = spawn_worker_discovery(
        &workflow,
        agent_id.clone(),
        worker_signing_client,
        local_worker_card,
        orchestrator.clone(),
    )
    .await?;

    run_startup_maintenance(&orchestrator).await?;

    let orchestrator_handle: Arc<dyn api::OrchestratorHandle> = orchestrator.clone();
    let api_tracker: Arc<dyn x0x_symphony_core::Tracker> = tracker.clone();
    let app_state = api::AppState::new(api_tracker, agent_id, api_token, Some(orchestrator_handle))
        .with_proofs_dir(proofs_dir)
        .with_signing_client(Some(api_signing_client))
        .with_approval_ttl(workflow.security.approval_ttl);
    if let Some(dispatch_events_rx) = orchestrator.subscribe() {
        spawn_dispatch_event_forwarder(dispatch_events_rx, app_state.events_sender());
    }
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
        tracker_kind = %workflow.tracker.kind,
        task_list = %workflow.tracker.list_id,
        x0xd_url = %workflow.signing.x0xd_url,
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

/// Construct the x0x CRDT tracker, returning the x0xd-resolved agent identity.
async fn build_tracker(
    workflow: &config::WorkflowConfig,
) -> anyhow::Result<(Arc<X0xCrdtTracker>, AgentId, Arc<X0xdClient>)> {
    let signing_client = Arc::new(
        X0xdClient::new(&workflow.signing.x0xd_url)
            .context("failed to configure x0xd signing client")?,
    );
    let identity = signing_client
        .agent_identity()
        .await
        .context("failed to read x0xd agent identity")?;
    let agent_id = AgentId::new(identity.agent_id)?;
    let mut tracker_builder = X0xCrdtTracker::builder(
        &workflow.signing.x0xd_url,
        &workflow.tracker.list_id,
        agent_id.clone(),
    );
    if let Some(group) = &workflow.tracker.group {
        tracker_builder = tracker_builder.group(group.clone());
    }
    if workflow.signing.policy == SigningPolicy::Required {
        let signing: Arc<dyn SigningClient> = signing_client.clone();
        let resolver: Arc<dyn TrustedKeyResolver> = signing_client.clone();
        tracker_builder = tracker_builder.required_signing(signing, resolver);
    }
    let tracker = tracker_builder
        .build()
        .context("failed to configure x0x CRDT tracker")?;
    Ok((Arc::new(tracker), agent_id, signing_client))
}

async fn run_startup_maintenance(
    orchestrator: &Orchestrator<X0xCrdtTracker, ShellRunner, Manager>,
) -> anyhow::Result<()> {
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
    Ok(())
}

async fn spawn_worker_discovery(
    workflow: &config::WorkflowConfig,
    agent_id: AgentId,
    signing_client: Arc<X0xdClient>,
    local_worker_card: x0x_symphony_core::WorkerCard,
    orchestrator: Arc<Orchestrator<X0xCrdtTracker, ShellRunner, Manager>>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let worker_signing_client: Arc<dyn SigningClient> = signing_client.clone();
    let worker_key_resolver: Arc<dyn TrustedKeyResolver> = signing_client;
    let worker_discovery = Arc::new(
        workers::WorkerDiscovery::new(
            agent_id,
            worker_signing_client,
            worker_key_resolver,
            workflow.signing.x0xd_url.clone(),
            x0xd_api_token(),
            local_worker_card,
            workflow.workers.publish_enabled,
        )
        .context("failed to configure worker gossip discovery")?,
    );
    spawn_worker_load_updater(Arc::clone(&worker_discovery), orchestrator);
    Ok(worker_discovery.run().await)
}

fn spawn_worker_load_updater(
    worker_discovery: Arc<workers::WorkerDiscovery>,
    orchestrator: Arc<Orchestrator<X0xCrdtTracker, ShellRunner, Manager>>,
) {
    let _load_updater = tokio::spawn(async move {
        loop {
            worker_discovery.set_current_load(orchestrator.current_load());
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

fn local_worker_card_template(
    workflow: &config::WorkflowConfig,
    runner_spec: &RunnerSpec,
    agent_id: AgentId,
) -> x0x_symphony_core::WorkerCard {
    let capabilities = configured_or_default_capabilities(workflow, runner_spec);
    let sandbox_levels = configured_or_default_sandbox_levels(workflow, runner_spec);
    let runner_presets = configured_or_default_runner_presets(workflow, runner_spec);
    let max_load = u32::try_from(workflow.agent.max_concurrent_agents).unwrap_or(u32::MAX);
    workers::local_worker_card_template(
        agent_id,
        workflow.workers.ttl_seconds,
        capabilities,
        sandbox_levels,
        runner_presets,
        max_load,
    )
}

fn configured_or_default_capabilities(
    workflow: &config::WorkflowConfig,
    runner_spec: &RunnerSpec,
) -> Vec<String> {
    if !workflow.workers.capabilities.is_empty() {
        return workflow.workers.capabilities.clone();
    }
    let mut capabilities = vec!["shell".to_owned()];
    if let Some(preset) = runner_spec.preset {
        push_unique(&mut capabilities, preset.as_str());
    }
    capabilities
}

fn configured_or_default_sandbox_levels(
    workflow: &config::WorkflowConfig,
    runner_spec: &RunnerSpec,
) -> Vec<String> {
    if !workflow.workers.sandbox_levels.is_empty() {
        return workflow.workers.sandbox_levels.clone();
    }
    runner_spec.sandbox.as_ref().map_or_else(
        || vec!["unsandboxed".to_owned()],
        |sandbox| vec![sandbox.profile.as_kebab().to_owned()],
    )
}

fn configured_or_default_runner_presets(
    workflow: &config::WorkflowConfig,
    runner_spec: &RunnerSpec,
) -> Vec<String> {
    if !workflow.workers.runner_presets.is_empty() {
        return workflow.workers.runner_presets.clone();
    }
    runner_spec.preset.map_or_else(
        || vec!["shell".to_owned()],
        |preset| vec![preset.as_str().to_owned()],
    )
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn x0xd_api_token() -> Option<String> {
    env::var("X0X_API_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn workflow_root(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn spawn_dispatch_event_forwarder(
    mut dispatch_events_rx: broadcast::Receiver<DispatchEvent>,
    events_tx: broadcast::Sender<api::EventNotice>,
) {
    let _forwarder = tokio::spawn(async move {
        loop {
            match dispatch_events_rx.recv().await {
                Ok(event) => {
                    let notice = dispatch_event_notice(event);
                    let _send_result = events_tx.send(notice);
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "dispatch event forwarder lagged");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

fn dispatch_event_notice(event: DispatchEvent) -> api::EventNotice {
    match event {
        DispatchEvent::ApprovalRequested {
            issue_id,
            signer_agent_id,
        } => api::EventNotice::new(
            "approval_requested",
            json!({
                "issue_id": issue_id.as_str(),
                "signer_agent_id": signer_agent_id.as_str(),
            })
            .to_string(),
        ),
        DispatchEvent::ApprovalExpired { issue_id } => api::EventNotice::new(
            "approval_expired",
            json!({ "issue_id": issue_id.as_str() }).to_string(),
        ),
    }
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
