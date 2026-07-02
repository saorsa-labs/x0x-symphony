//! Proof artefact writer for orchestrator dispatch runs.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::StreamExt;
use serde::Serialize;
use tokio::task::JoinHandle;
use x0x_symphony_core::{
    AgentId, Claim, EventStream, Issue, ReleaseReason, RunnerCapabilities, RunnerEventKind,
};
use x0x_symphony_workspace::containment::{
    canonicalize_root, sanitize_issue_identifier, validate_existing_workspace_path,
};

use crate::{Error, Result};

const STDOUT_LOG: &str = "stdout.log";
const STDERR_LOG: &str = "stderr.log";
const MANIFEST_JSON: &str = "manifest.json";

#[derive(Clone, Debug, Serialize)]
struct ProofManifest {
    issue_id: String,
    agent_id: String,
    hostname: String,
    runner_kind: String,
    preset: Option<String>,
    command: String,
    args: Vec<String>,
    env_allowlist: Vec<String>,
    exit_code: i32,
    duration_ms: u64,
    started_at: String,
    ended_at: String,
    hooks: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct AbandonManifest {
    issue_id: String,
    recorded_at: String,
    abandoned_claim: Claim,
    reason: ReleaseReason,
    winning_agent_id: String,
}

#[derive(Clone, Debug)]
struct RunnerManifestMetadata {
    runner_kind: String,
    preset: Option<String>,
    command: String,
    args: Vec<String>,
    env_allowlist: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct ProofDirectory<'a> {
    root: &'a Path,
}

impl<'a> ProofDirectory<'a> {
    pub(crate) const fn new(root: &'a Path) -> Self {
        Self { root }
    }

    pub(crate) fn write_abandoned(
        &self,
        issue: &Issue,
        abandoned_claim: &Claim,
        reason: &ReleaseReason,
        winning_claim: &Claim,
        recorded_at: DateTime<Utc>,
    ) -> Result<String> {
        let canonical_root = prepare_root(self.root)?;
        let issue_segment = sanitize_segment(issue.id.as_str())?;
        let issue_dir = ensure_child_dir(&canonical_root, issue_segment.as_str())?;
        let base_timestamp = format!("{}-abandoned", timestamp_segment(recorded_at));
        let (abandon_dir, abandon_segment) = create_unique_run_dir(&issue_dir, &base_timestamp)?;
        let manifest = AbandonManifest {
            issue_id: issue.id.to_string(),
            recorded_at: recorded_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            abandoned_claim: abandoned_claim.clone(),
            reason: reason.clone(),
            winning_agent_id: winning_claim.by.to_string(),
        };
        write_json_file(&abandon_dir.join("abandon.json"), &manifest)?;
        Ok(format!("proofs/{issue_segment}/{abandon_segment}"))
    }
}

#[derive(Debug)]
pub(crate) struct ProofRun {
    issue_id: String,
    agent_id: String,
    dir: PathBuf,
    relative_dir: String,
    started_at: DateTime<Utc>,
    started_instant: Instant,
    runner: RunnerManifestMetadata,
    hooks: Vec<String>,
    artifact_counter: Arc<AtomicUsize>,
}

impl ProofRun {
    pub(crate) fn start(
        proofs_root: &Path,
        issue: &Issue,
        agent_id: &AgentId,
        runner_name: &str,
        capabilities: &RunnerCapabilities,
        started_at: DateTime<Utc>,
    ) -> Result<Self> {
        let canonical_root = prepare_root(proofs_root)?;
        // M5: reaper - retention cleanup for old proof directories belongs here.
        let issue_segment = sanitize_segment(issue.id.as_str())?;
        let issue_dir = ensure_child_dir(&canonical_root, issue_segment.as_str())?;
        let base_timestamp = timestamp_segment(started_at);
        let (run_dir, run_segment) = create_unique_run_dir(&issue_dir, &base_timestamp)?;
        create_empty_log(&run_dir, STDOUT_LOG)?;
        create_empty_log(&run_dir, STDERR_LOG)?;

        let relative_dir = format!("proofs/{issue_segment}/{run_segment}");
        Ok(Self {
            issue_id: issue.id.to_string(),
            agent_id: agent_id.to_string(),
            dir: run_dir,
            relative_dir,
            started_at,
            started_instant: Instant::now(),
            runner: RunnerManifestMetadata::from_capabilities(runner_name, capabilities),
            hooks: Vec::new(),
            artifact_counter: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub(crate) fn relative_dir(&self) -> &str {
        &self.relative_dir
    }

    pub(crate) fn record_hook(&mut self, phase_name: &str, status: &str) {
        self.hooks.push(format!("{phase_name}:{status}"));
    }

    pub(crate) fn spawn_event_writer(
        &self,
        events: EventStream,
        workspace_path: PathBuf,
    ) -> JoinHandle<Result<()>> {
        let proof_dir = self.dir.clone();
        let artifact_counter = Arc::clone(&self.artifact_counter);
        tokio::spawn(async move {
            write_runner_events(events, proof_dir, workspace_path, artifact_counter).await
        })
    }

    pub(crate) fn finish(&self, exit_code: i32, ended_at: DateTime<Utc>) -> Result<()> {
        let manifest = ProofManifest {
            issue_id: self.issue_id.clone(),
            agent_id: self.agent_id.clone(),
            hostname: hostname(),
            runner_kind: self.runner.runner_kind.clone(),
            preset: self.runner.preset.clone(),
            command: self.runner.command.clone(),
            args: self.runner.args.clone(),
            env_allowlist: self.runner.env_allowlist.clone(),
            exit_code,
            duration_ms: elapsed_ms(self.started_instant),
            started_at: self.started_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            ended_at: ended_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            hooks: self.hooks.clone(),
        };
        self.write_manifest(&manifest)
    }

    fn write_manifest(&self, manifest: &ProofManifest) -> Result<()> {
        write_json_file(&self.dir.join(MANIFEST_JSON), manifest)
    }
}

impl RunnerManifestMetadata {
    fn from_capabilities(runner_name: &str, capabilities: &RunnerCapabilities) -> Self {
        let mut env_allowlist = capabilities.env_allowlist.clone();
        env_allowlist.sort();
        env_allowlist.dedup();
        Self {
            runner_kind: capabilities.runner_kind.clone(),
            preset: capabilities
                .preset
                .clone()
                .or_else(|| capabilities.labels.first().cloned()),
            command: capabilities
                .command
                .clone()
                .unwrap_or_else(|| runner_name.to_owned()),
            args: capabilities.args.clone(),
            env_allowlist,
        }
    }
}

pub(crate) async fn join_event_writer(handle: JoinHandle<Result<()>>) -> Result<()> {
    handle.await.map_err(|source| Error::ProofTask {
        message: source.to_string(),
    })?
}

async fn write_runner_events(
    mut events: EventStream,
    proof_dir: PathBuf,
    workspace_path: PathBuf,
    artifact_counter: Arc<AtomicUsize>,
) -> Result<()> {
    let stdout_path = proof_dir.join(STDOUT_LOG);
    let stderr_path = proof_dir.join(STDERR_LOG);
    let mut stdout = append_file(&stdout_path)?;
    let mut stderr = append_file(&stderr_path)?;

    while let Some(event) = events.next().await {
        match event.kind {
            RunnerEventKind::Stdout => {
                if let Some(message) = event.message {
                    write_all(&mut stdout, &stdout_path, message.as_bytes())?;
                }
            }
            RunnerEventKind::Stderr => {
                if let Some(message) = event.message {
                    write_all(&mut stderr, &stderr_path, message.as_bytes())?;
                }
            }
            RunnerEventKind::Error => {
                if let Some(message) = event.message {
                    write_all(
                        &mut stderr,
                        &stderr_path,
                        format!("[runner-error] {message}\n").as_bytes(),
                    )?;
                }
            }
            RunnerEventKind::Artifact => {
                persist_artifact_event(
                    event.message.as_deref(),
                    &workspace_path,
                    &proof_dir,
                    &artifact_counter,
                    &mut stderr,
                    &stderr_path,
                )?;
            }
            RunnerEventKind::SessionStarted | RunnerEventKind::TurnCompleted => {}
        }
    }

    stdout.flush().map_err(|source| Error::ProofIo {
        path: stdout_path.clone(),
        source,
    })?;
    stderr.flush().map_err(|source| Error::ProofIo {
        path: stderr_path.clone(),
        source,
    })
}

fn prepare_root(root: &Path) -> Result<PathBuf> {
    fs::create_dir_all(root).map_err(|source| Error::ProofIo {
        path: root.to_path_buf(),
        source,
    })?;
    canonicalize_root(root).map_err(|source| Error::ProofContainment {
        reason: source.to_string(),
    })
}

fn ensure_child_dir(root: &Path, child_name: &str) -> Result<PathBuf> {
    let child = root.join(child_name);
    match fs::symlink_metadata(&child) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(Error::ProofContainment {
                    reason: format!("proof path is not a real directory: {}", child.display()),
                });
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&child).map_err(|create_source| Error::ProofIo {
                path: child.clone(),
                source: create_source,
            })?;
        }
        Err(source) => {
            return Err(Error::ProofIo {
                path: child.clone(),
                source,
            });
        }
    }
    validate_existing_workspace_path(root, &child).map_err(|source| Error::ProofContainment {
        reason: source.to_string(),
    })
}

fn create_unique_run_dir(issue_dir: &Path, base_timestamp: &str) -> Result<(PathBuf, String)> {
    for suffix in 0..100_u32 {
        let candidate = if suffix == 0 {
            base_timestamp.to_owned()
        } else {
            format!("{base_timestamp}-{suffix:02}")
        };
        let run_segment = sanitize_segment(&candidate)?;
        let run_dir = issue_dir.join(run_segment.as_str());
        match fs::create_dir(&run_dir) {
            Ok(()) => {
                let canonical =
                    validate_existing_workspace_path(issue_dir, &run_dir).map_err(|source| {
                        Error::ProofContainment {
                            reason: source.to_string(),
                        }
                    })?;
                return Ok((canonical, run_segment.as_str().to_owned()));
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(Error::ProofIo {
                    path: run_dir,
                    source,
                });
            }
        }
    }
    Err(Error::ProofContainment {
        reason: format!("proof timestamp collision for {base_timestamp}"),
    })
}

fn create_empty_log(run_dir: &Path, file_name: &str) -> Result<()> {
    let path = run_dir.join(file_name);
    File::create(&path)
        .and_then(|file| file.sync_all())
        .map_err(|source| Error::ProofIo { path, source })
}

fn append_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| Error::ProofIo {
            path: path.to_path_buf(),
            source,
        })
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut file = File::create(path).map_err(|source| Error::ProofIo {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::to_writer_pretty(&mut file, value).map_err(|source| Error::ProofJson { source })?;
    file.write_all(b"\n").map_err(|source| Error::ProofIo {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| Error::ProofIo {
        path: path.to_path_buf(),
        source,
    })
}

fn write_all(file: &mut File, path: &Path, bytes: &[u8]) -> Result<()> {
    file.write_all(bytes).map_err(|source| Error::ProofIo {
        path: path.to_path_buf(),
        source,
    })
}

fn persist_artifact_event(
    message: Option<&str>,
    workspace_path: &Path,
    proof_dir: &Path,
    artifact_counter: &AtomicUsize,
    stderr: &mut File,
    stderr_path: &Path,
) -> Result<()> {
    let Some(message) = message.map(str::trim).filter(|value| !value.is_empty()) else {
        return write_artifact_warning(stderr, stderr_path, "artifact event missing path");
    };
    let source = artifact_source_path(workspace_path, message);
    let canonical_workspace = match fs::canonicalize(workspace_path) {
        Ok(path) => path,
        Err(source_error) => {
            return write_artifact_warning(
                stderr,
                stderr_path,
                &format!(
                    "artifact workspace is unavailable ({}): {source_error}",
                    workspace_path.display()
                ),
            );
        }
    };
    let canonical_source = match fs::canonicalize(&source) {
        Ok(path) => path,
        Err(source_error) => {
            return write_artifact_warning(
                stderr,
                stderr_path,
                &format!(
                    "artifact source is unavailable ({}): {source_error}",
                    source.display()
                ),
            );
        }
    };
    if !canonical_source.starts_with(&canonical_workspace) {
        return write_artifact_warning(
            stderr,
            stderr_path,
            &format!(
                "artifact path escaped workspace: {}",
                canonical_source.display()
            ),
        );
    }
    let metadata = match fs::metadata(&canonical_source) {
        Ok(metadata) => metadata,
        Err(source_error) => {
            return write_artifact_warning(
                stderr,
                stderr_path,
                &format!(
                    "artifact metadata failed ({}): {source_error}",
                    canonical_source.display()
                ),
            );
        }
    };
    if !metadata.is_file() {
        return write_artifact_warning(
            stderr,
            stderr_path,
            &format!(
                "artifact source is not a file: {}",
                canonical_source.display()
            ),
        );
    }

    let number = artifact_counter
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let target = proof_dir.join(format!("artifact-{number:04}.bin"));
    fs::copy(&canonical_source, &target).map_err(|source_error| Error::ProofIo {
        path: target,
        source: source_error,
    })?;
    Ok(())
}

fn write_artifact_warning(stderr: &mut File, stderr_path: &Path, message: &str) -> Result<()> {
    write_all(
        stderr,
        stderr_path,
        format!("[artifact-warning] {message}\n").as_bytes(),
    )
}

fn artifact_source_path(workspace_path: &Path, message: &str) -> PathBuf {
    let candidate = Path::new(message);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        workspace_path.join(candidate)
    }
}

fn sanitize_segment(raw: &str) -> Result<x0x_symphony_workspace::containment::SanitizedIdentifier> {
    sanitize_issue_identifier(raw).map_err(|source| Error::ProofContainment {
        reason: source.to_string(),
    })
}

fn timestamp_segment(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%dT%H%M%SZ").to_string()
}

fn elapsed_ms(started: Instant) -> u64 {
    let millis = started.elapsed().as_millis();
    u64::try_from(millis).map_or(u64::MAX, |value| value)
}

fn hostname() -> String {
    for key in ["HOSTNAME", "COMPUTERNAME"] {
        match std::env::var(key) {
            Ok(value) if !value.trim().is_empty() => return value,
            Ok(_) | Err(_) => {}
        }
    }
    "unknown".to_owned()
}
