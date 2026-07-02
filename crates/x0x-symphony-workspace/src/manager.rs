//! Workspace manager implementation.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use async_trait::async_trait;
#[cfg(unix)]
use tokio::process::Child;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    task::JoinHandle,
    time,
};
use tracing::warn;
use x0x_symphony_core::{
    Hook, HookEnv, HookOutcome, HookStatus, Issue, IssueState, Workspace, WorkspaceHandle,
};

use crate::{
    containment::{
        canonicalize_root, deterministic_path, sanitize_issue_identifier,
        validate_existing_workspace_path,
    },
    error::{Error, Result},
};

const DEFAULT_HOOK_OUTPUT_LIMIT_BYTES: usize = 64 * 1024;
const HOOK_OUTPUT_TIMEOUT_DRAIN_MS: u64 = 1_000;
const BASH_PATH: &str = "/bin/bash";

/// Workspace manager configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    root: PathBuf,
    sensitive_env_allowlist: BTreeSet<String>,
    hook_output_limit_bytes: usize,
}

impl Config {
    /// Create configuration for a workspace root.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            sensitive_env_allowlist: BTreeSet::new(),
            hook_output_limit_bytes: DEFAULT_HOOK_OUTPUT_LIMIT_BYTES,
        }
    }

    /// Return the configured root path.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return explicitly allowed sensitive hook environment names.
    #[must_use]
    pub fn sensitive_env_allowlist(&self) -> &BTreeSet<String> {
        &self.sensitive_env_allowlist
    }

    /// Return the per-stream hook output capture limit.
    #[must_use]
    pub const fn hook_output_limit_bytes(&self) -> usize {
        self.hook_output_limit_bytes
    }

    /// Add an explicit allow-list entry for one sensitive hook environment key.
    ///
    /// Keys matching `*_TOKEN`, `*_KEY`, or `*_SECRET` are denied by default.
    /// Add only the exact names that the operator has intentionally approved.
    #[must_use]
    pub fn with_sensitive_env(mut self, name: impl Into<String>) -> Self {
        self.sensitive_env_allowlist.insert(name.into());
        self
    }

    /// Override the per-stream hook output capture limit.
    #[must_use]
    pub const fn with_hook_output_limit_bytes(mut self, limit: usize) -> Self {
        self.hook_output_limit_bytes = limit;
        self
    }
}

/// Decision made by terminal-state cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupDecision {
    /// The issue state was not terminal, so the workspace was preserved.
    PreservedRetry,
    /// The workspace had already been removed.
    AlreadyAbsent,
    /// The workspace passed containment re-validation and was removed.
    Removed,
}

/// Local filesystem workspace manager.
///
/// Workspaces are direct children of a canonicalized root. The child directory
/// name is the sanitized issue identifier; unsafe identifiers are rejected
/// rather than rewritten.
#[derive(Clone, Debug)]
pub struct Manager {
    config: Config,
    root: PathBuf,
}

impl Manager {
    /// Create a workspace manager and canonicalize the root.
    ///
    /// The root directory is created when it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the root cannot be created, canonicalized, or
    /// verified as a directory.
    pub fn new(config: Config) -> Result<Self> {
        fs::create_dir_all(config.root()).map_err(|source| Error::CreateRoot {
            path: config.root().to_path_buf(),
            source,
        })?;
        let root = canonicalize_root(config.root())?;
        Ok(Self { config, root })
    }

    /// Return the canonical workspace root.
    #[must_use]
    pub fn canonical_root(&self) -> &Path {
        &self.root
    }

    /// Return the active configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Return the deterministic path for an issue identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the identifier fails containment sanitization.
    pub fn issue_path(&self, identifier: &str) -> Result<PathBuf> {
        let sanitized = sanitize_issue_identifier(identifier)?;
        Ok(deterministic_path(&self.root, &sanitized))
    }

    /// Create or reuse a workspace for an issue.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the identifier is unsafe, the existing path is not
    /// a contained direct child directory, or directory creation fails.
    pub fn create_for_issue(&self, issue: &Issue) -> Result<WorkspaceHandle> {
        let path = self.issue_path(&issue.identifier)?;
        let (created_now, canonical_path) = self.create_or_reuse_directory(&path)?;
        Ok(WorkspaceHandle::new(
            issue.id.clone(),
            canonical_path,
            created_now,
        ))
    }

    /// Re-check a workspace handle against this manager's root.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the path does not exist, is not a direct child of
    /// the root, escapes through a symlink, aliases another child, or is not a
    /// directory.
    pub fn validate_handle(&self, handle: &WorkspaceHandle) -> Result<PathBuf> {
        let canonical = validate_existing_workspace_path(&self.root, &handle.path)?;
        let metadata = fs::metadata(&canonical).map_err(|source| Error::Metadata {
            path: canonical.clone(),
            source,
        })?;
        if !metadata.is_dir() {
            return Err(Error::NotDirectory { path: canonical });
        }
        Ok(canonical)
    }

    /// Execute a hook with its working directory set to a validated workspace.
    ///
    /// The path is validated immediately before the hook starts and again after
    /// it exits, so a hook that swaps the workspace for a symlink fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] for containment failures, invalid hook environment,
    /// process spawn or wait failures, or output capture failures.
    pub async fn run_hook_in(
        &self,
        handle: &WorkspaceHandle,
        hook: &Hook,
        env: &HookEnv,
    ) -> Result<HookOutcome> {
        let workdir = self.validate_handle(handle)?;
        let outcome = self.run_hook_in_dir(&workdir, hook, env).await?;
        self.validate_handle(handle)?;
        Ok(outcome)
    }

    /// Execute a hook with its working directory set to the canonical root.
    ///
    /// This supports the core [`Workspace`] trait shape. Orchestrator code that
    /// has a [`WorkspaceHandle`] should prefer [`Manager::run_hook_in`] so hook
    /// commands run inside the per-issue workspace.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] for invalid hook environment, process spawn or wait
    /// failures, or output capture failures.
    pub async fn run_hook_at_root(&self, hook: &Hook, env: &HookEnv) -> Result<HookOutcome> {
        self.run_hook_in_dir(&self.root, hook, env).await
    }

    /// Remove a workspace after re-validating containment.
    ///
    /// Missing workspaces are treated as already absent. Existing paths must
    /// pass the same canonicalize-and-prefix checks used at creation before any
    /// removal is attempted.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the path exists but fails containment
    /// re-validation or when removal fails.
    pub fn destroy_workspace(&self, handle: WorkspaceHandle) -> Result<CleanupDecision> {
        match fs::symlink_metadata(&handle.path) {
            Ok(_metadata) => {
                let canonical = self.validate_handle(&handle)?;
                fs::remove_dir_all(&canonical).map_err(|source| Error::RemoveDir {
                    path: canonical,
                    source,
                })?;
                Ok(CleanupDecision::Removed)
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                Ok(CleanupDecision::AlreadyAbsent)
            }
            Err(source) => Err(Error::Metadata {
                path: handle.path,
                source,
            }),
        }
    }

    /// Remove a workspace only when the issue is in a terminal state.
    ///
    /// Non-terminal states preserve the workspace for retry/resume semantics.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] only when the state is terminal and the destroy path
    /// fails containment re-validation or removal.
    pub fn destroy_if_terminal(
        &self,
        handle: WorkspaceHandle,
        state: &IssueState,
        terminal_states: &[IssueState],
    ) -> Result<CleanupDecision> {
        if terminal_states
            .iter()
            .any(|terminal_state| terminal_state == state)
        {
            self.destroy_workspace(handle)
        } else {
            Ok(CleanupDecision::PreservedRetry)
        }
    }

    fn create_or_reuse_directory(&self, path: &Path) -> Result<(bool, PathBuf)> {
        match fs::symlink_metadata(path) {
            Ok(_metadata) => self
                .validate_existing_directory(path)
                .map(|canonical| (false, canonical)),
            Err(source) if source.kind() == io::ErrorKind::NotFound => match fs::create_dir(path) {
                Ok(()) => self
                    .validate_existing_directory(path)
                    .map(|canonical| (true, canonical)),
                Err(create_source) if create_source.kind() == io::ErrorKind::AlreadyExists => self
                    .validate_existing_directory(path)
                    .map(|canonical| (false, canonical)),
                Err(create_source) => Err(Error::CreateDir {
                    path: path.to_path_buf(),
                    source: create_source,
                }),
            },
            Err(source) => Err(Error::Metadata {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    fn validate_existing_directory(&self, path: &Path) -> Result<PathBuf> {
        let canonical = validate_existing_workspace_path(&self.root, path)?;
        let metadata = fs::metadata(&canonical).map_err(|source| Error::Metadata {
            path: canonical.clone(),
            source,
        })?;
        if !metadata.is_dir() {
            return Err(Error::NotDirectory { path: canonical });
        }
        Ok(canonical)
    }

    async fn run_hook_in_dir(
        &self,
        workdir: &Path,
        hook: &Hook,
        env: &HookEnv,
    ) -> Result<HookOutcome> {
        let env = self.build_hook_env(env)?;
        let hook_name = hook.name.as_str();
        let mut command = Command::new(BASH_PATH);
        command
            .arg("-e")
            .arg("-u")
            .arg("-o")
            .arg("pipefail")
            .arg("-c")
            .arg(&hook.script)
            .current_dir(workdir)
            .env_clear()
            .envs(env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // Place the hook child in its own process group so a timeout can kill
        // any grandchildren the hook forked (mirrors the runner's PG-kill).
        configure_process_group(&mut command);

        let mut child = command.spawn().map_err(|source| Error::HookSpawn {
            hook: hook_name,
            source,
        })?;
        let stdout = child.stdout.take().ok_or(Error::HookPipeMissing {
            hook: hook_name,
            stream: "stdout",
        })?;
        let stderr = child.stderr.take().ok_or(Error::HookPipeMissing {
            hook: hook_name,
            stream: "stderr",
        })?;

        let stdout_task = tokio::spawn(read_limited(stdout, self.config.hook_output_limit_bytes));
        let stderr_task = tokio::spawn(read_limited(stderr, self.config.hook_output_limit_bytes));

        let timeout = Duration::from_millis(hook.timeout_ms);
        let wait_result = time::timeout(timeout, child.wait()).await;
        let (status, timed_out) = match wait_result {
            Ok(Ok(status)) => (Some(status), false),
            Ok(Err(source)) => {
                return Err(Error::HookWait {
                    hook: hook_name,
                    source,
                });
            }
            Err(_elapsed) => {
                // Kill the whole process group, not just the direct bash
                // child, so forked grandchildren die with the hook.
                if let Err(error) = kill_process_group(&mut child) {
                    warn!(
                        hook = hook_name,
                        error = %error,
                        "failed to kill timed-out hook process group"
                    );
                }
                if let Err(source) = child.wait().await {
                    warn!(
                        hook = hook_name,
                        error = %source,
                        "failed to reap timed-out hook process"
                    );
                }
                (None, true)
            }
        };

        let stdout = finish_output_task(stdout_task, "stdout", timed_out).await?;
        let stderr = finish_output_task(stderr_task, "stderr", timed_out).await?;

        let mut outcome = if timed_out {
            HookOutcome::new(HookStatus::TimedOut)
        } else if status.is_some_and(|exit_status| exit_status.success()) {
            HookOutcome::new(HookStatus::Succeeded)
        } else {
            HookOutcome::new(HookStatus::Failed)
        };

        if let Some(exit_status) = status.and_then(|exit_status| exit_status.code()) {
            outcome = outcome.with_exit_code(exit_status);
        }
        if let Some(stdout) = stdout.into_option() {
            outcome = outcome.with_stdout(stdout);
        }
        if let Some(stderr) = stderr.into_option() {
            outcome = outcome.with_stderr(stderr);
        }

        Ok(outcome)
    }

    fn build_hook_env(&self, env: &HookEnv) -> Result<BTreeMap<String, String>> {
        let mut vars = BTreeMap::new();
        for (name, value) in &env.vars {
            validate_env_name(name)?;
            if value.as_bytes().contains(&0) {
                return Err(Error::InvalidHookEnv {
                    name: name.clone(),
                    reason: "value must not contain NUL",
                });
            }
            if is_sensitive_env_name(name) && !self.config.sensitive_env_allowlist.contains(name) {
                return Err(Error::SensitiveHookEnvDenied { name: name.clone() });
            }
            if is_dangerous_env_name(name) {
                return Err(Error::DangerousHookEnvDenied { name: name.clone() });
            }
            vars.insert(name.clone(), value.clone());
        }
        Ok(vars)
    }
}

#[async_trait]
impl Workspace for Manager {
    fn root(&self) -> &Path {
        self.canonical_root()
    }

    async fn create(&self, issue: &Issue) -> x0x_symphony_core::Result<WorkspaceHandle> {
        self.create_for_issue(issue).map_err(Error::into_core)
    }

    async fn run_hook(&self, hook: &Hook, env: &HookEnv) -> x0x_symphony_core::Result<HookOutcome> {
        self.run_hook_at_root(hook, env)
            .await
            .map_err(Error::into_core)
    }

    async fn destroy(&self, handle: WorkspaceHandle) -> x0x_symphony_core::Result<()> {
        self.destroy_workspace(handle)
            .map(|_decision| ())
            .map_err(Error::into_core)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CapturedOutput {
    text: String,
    truncated: bool,
}

impl CapturedOutput {
    fn from_bytes(bytes: &[u8], truncated: bool) -> Self {
        let mut text = String::from_utf8_lossy(bytes).into_owned();
        if truncated {
            text.push_str("\n[hook output truncated]\n");
        }
        Self { text, truncated }
    }

    fn aborted_after_timeout() -> Self {
        Self {
            text: "[hook output collection aborted after timeout]\n".to_owned(),
            truncated: true,
        }
    }

    fn into_option(self) -> Option<String> {
        if self.text.is_empty() && !self.truncated {
            None
        } else {
            Some(self.text)
        }
    }
}

async fn read_limited<R>(mut reader: R, limit: usize) -> io::Result<CapturedOutput>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 8 * 1024];

    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(output.len());
        if remaining == 0 {
            truncated = true;
            continue;
        }
        let to_copy = remaining.min(read);
        output.extend_from_slice(&buffer[..to_copy]);
        if to_copy < read {
            truncated = true;
        }
    }

    Ok(CapturedOutput::from_bytes(&output, truncated))
}

async fn finish_output_task(
    mut task: JoinHandle<io::Result<CapturedOutput>>,
    stream: &'static str,
    timed_out: bool,
) -> Result<CapturedOutput> {
    if timed_out {
        let drain_timeout = Duration::from_millis(HOOK_OUTPUT_TIMEOUT_DRAIN_MS);
        match time::timeout(drain_timeout, &mut task).await {
            Ok(join_result) => decode_output_join(join_result, stream),
            Err(_elapsed) => {
                task.abort();
                Ok(CapturedOutput::aborted_after_timeout())
            }
        }
    } else {
        decode_output_join(task.await, stream)
    }
}

fn decode_output_join(
    join_result: std::result::Result<io::Result<CapturedOutput>, tokio::task::JoinError>,
    stream: &'static str,
) -> Result<CapturedOutput> {
    match join_result {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(source)) => Err(Error::HookOutputRead { stream, source }),
        Err(join_error) => Err(Error::HookOutputJoin {
            stream,
            message: join_error.to_string(),
        }),
    }
}

fn validate_env_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidHookEnv {
            name: name.to_owned(),
            reason: "name must not be empty",
        });
    }
    if name.as_bytes().contains(&0) {
        return Err(Error::InvalidHookEnv {
            name: name.to_owned(),
            reason: "name must not contain NUL",
        });
    }

    let mut bytes = name.bytes();
    let first = bytes.next().ok_or_else(|| Error::InvalidHookEnv {
        name: name.to_owned(),
        reason: "name must not be empty",
    })?;
    if !matches!(first, b'A'..=b'Z' | b'a'..=b'z' | b'_') {
        return Err(Error::InvalidHookEnv {
            name: name.to_owned(),
            reason: "name must start with ASCII letter or underscore",
        });
    }
    if !bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')) {
        return Err(Error::InvalidHookEnv {
            name: name.to_owned(),
            reason: "name must contain only ASCII letters, digits, or underscore",
        });
    }
    Ok(())
}

fn is_sensitive_env_name(name: &str) -> bool {
    let uppercase = name.to_ascii_uppercase();
    uppercase.ends_with("_TOKEN") || uppercase.ends_with("_KEY") || uppercase.ends_with("_SECRET")
}

/// Return true when `name` is a dangerous shell/linker environment variable
/// that must never enter a hook child process regardless of the sensitive
/// allow-list.
///
/// `BASH_ENV`/`ENV` cause `bash` to execute a file on startup; `SHELLOPTS`
/// can enable unsafe options; `CDPATH` alters path resolution; `LD_PRELOAD`/
/// `LD_LIBRARY_PATH` load arbitrary shared libraries into the hook process.
/// The comparison is case-insensitive to match the resolver's behaviour.
/// See the red-team review of XSY-0005 (MEDIUM finding).
#[must_use]
fn is_dangerous_env_name(name: &str) -> bool {
    const DANGEROUS: &[&str] = &[
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "CDPATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
    ];
    DANGEROUS.contains(&name.to_ascii_uppercase().as_str())
}

/// Place the spawned hook child in its own process group so a timeout can
/// signal the entire group. No-op off Unix; mirroring the runner's PG-kill.
#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

/// Kill the hook child's process group on timeout. On Unix this signals the
/// negative process id (the whole group) so forked grandchildren die with the
/// bash child; off Unix it falls back to the direct child only. Mirrors the
/// runner's `kill_process_group`.
#[cfg(unix)]
fn kill_process_group(child: &mut Child) -> std::result::Result<(), String> {
    use nix::{
        errno::Errno,
        sys::signal::{kill, Signal},
        unistd::Pid,
    };
    let Some(child_id) = child.id() else {
        return Ok(());
    };
    let pgid = i32::try_from(child_id)
        .map_err(|error| format!("child id does not fit process id: {error}"))?;
    match kill(Pid::from_raw(-pgid), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(not(unix))]
fn kill_process_group(child: &mut Child) -> std::result::Result<(), String> {
    child.start_kill().map_err(|error| error.to_string())
}
