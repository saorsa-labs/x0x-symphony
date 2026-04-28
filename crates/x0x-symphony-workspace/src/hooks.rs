//! Hook process execution.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    task::JoinHandle,
    time,
};
use tracing::{debug, warn};
use x0x_symphony_core::{Hook, HookEnv, HookOutcome, HookStatus};

use crate::{WorkspaceManagerError, WorkspaceResult};

/// Hook environment variable that carries the canonical workspace root.
///
/// # Examples
///
/// ```
/// use x0x_symphony_workspace::WORKSPACE_ROOT_ENV;
///
/// assert_eq!(WORKSPACE_ROOT_ENV, "X0X_SYMPHONY_WORKSPACE_ROOT");
/// ```
pub const WORKSPACE_ROOT_ENV: &str = "X0X_SYMPHONY_WORKSPACE_ROOT";

/// Hook environment variable that carries the current workspace path.
///
/// # Examples
///
/// ```
/// use x0x_symphony_workspace::WORKSPACE_PATH_ENV;
///
/// assert_eq!(WORKSPACE_PATH_ENV, "X0X_SYMPHONY_WORKSPACE_PATH");
/// ```
pub const WORKSPACE_PATH_ENV: &str = "X0X_SYMPHONY_WORKSPACE_PATH";

const DEFAULT_PATH: &str = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin";
const READ_CHUNK_BYTES: usize = 8192;

/// Description of a hook process execution.
///
/// This value is useful for tests and future proof manifests. It intentionally
/// excludes environment values so secret material is not serialised by default.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use x0x_symphony_workspace::HookExecution;
///
/// let execution = HookExecution::new(PathBuf::from("/tmp/work"), 1_000);
/// assert_eq!(execution.timeout_ms, 1_000);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookExecution {
    /// Directory where the hook runs.
    pub cwd: PathBuf,
    /// Timeout applied to the hook process.
    pub timeout_ms: u64,
}

impl HookExecution {
    /// Construct hook execution metadata.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use x0x_symphony_workspace::HookExecution;
    ///
    /// let execution = HookExecution::new(PathBuf::from("/tmp/work"), 1_000);
    /// assert_eq!(execution.cwd, PathBuf::from("/tmp/work"));
    /// ```
    #[must_use]
    pub fn new(cwd: PathBuf, timeout_ms: u64) -> Self {
        Self { cwd, timeout_ms }
    }
}

pub(crate) async fn run_bash_hook(
    hook: &Hook,
    env: &HookEnv,
    cwd: &Path,
    allowed_secret_env: &BTreeSet<String>,
    output_limit_bytes: usize,
) -> WorkspaceResult<HookOutcome> {
    let env_map = validated_env(env, allowed_secret_env)?;
    debug!(hook = hook.name.as_str(), cwd = ?cwd, "starting workspace hook");

    let mut command = Command::new("bash");
    command
        .args(["-e", "-u", "-o", "pipefail", "-c", hook.script.as_str()])
        .current_dir(cwd)
        .env_clear()
        .env("PATH", DEFAULT_PATH)
        .envs(env_map)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| WorkspaceManagerError::HookSpawn(error.to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| WorkspaceManagerError::HookSpawn("stdout pipe unavailable".to_owned()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| WorkspaceManagerError::HookSpawn("stderr pipe unavailable".to_owned()))?;

    let stdout_task = tokio::spawn(read_limited(stdout, output_limit_bytes));
    let stderr_task = tokio::spawn(read_limited(stderr, output_limit_bytes));

    let status = match time::timeout(Duration::from_millis(hook.timeout_ms), child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => {
            warn!(
                hook = hook.name.as_str(),
                timeout_ms = hook.timeout_ms,
                "workspace hook timed out"
            );
            kill_child(&mut child).await?;
            let stdout = join_output(stdout_task).await?;
            let stderr = join_output(stderr_task).await?;
            return Ok(HookOutcome::new(HookStatus::TimedOut)
                .with_stdout(stdout)
                .with_stderr(stderr));
        }
    };

    let stdout = join_output(stdout_task).await?;
    let stderr = join_output(stderr_task).await?;
    let base = if status.success() {
        HookOutcome::new(HookStatus::Succeeded)
    } else {
        warn!(
            hook = hook.name.as_str(),
            exit_code = status.code(),
            "workspace hook failed"
        );
        HookOutcome::new(HookStatus::Failed)
    };
    let outcome = match status.code() {
        Some(code) => base.with_exit_code(code),
        None => base,
    };
    Ok(outcome.with_stdout(stdout).with_stderr(stderr))
}

fn validated_env(
    env: &HookEnv,
    allowed_secret_env: &BTreeSet<String>,
) -> WorkspaceResult<BTreeMap<String, String>> {
    let mut filtered = BTreeMap::new();
    for (key, value) in &env.vars {
        if is_secret_like(key) && !allowed_secret_env.contains(key) {
            return Err(WorkspaceManagerError::DeniedEnvironment(key.clone()));
        }
        filtered.insert(key.clone(), value.clone());
    }
    Ok(filtered)
}

fn is_secret_like(name: &str) -> bool {
    matches!(name, "TOKEN" | "KEY" | "SECRET")
        || name.ends_with("_TOKEN")
        || name.ends_with("_KEY")
        || name.ends_with("_SECRET")
}

async fn kill_child(child: &mut tokio::process::Child) -> WorkspaceResult<()> {
    match child.kill().await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
            warn!(error = %error, "workspace hook process exited before timeout kill completed");
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

async fn read_limited<R>(mut reader: R, limit: usize) -> std::io::Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut captured = Vec::with_capacity(limit.min(READ_CHUNK_BYTES));
    let mut buffer = [0_u8; READ_CHUNK_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(captured.len());
        let copy_len = remaining.min(read);
        if copy_len > 0 {
            captured.extend_from_slice(&buffer[..copy_len]);
        }
    }
    Ok(String::from_utf8_lossy(&captured).into_owned())
}

async fn join_output(handle: JoinHandle<std::io::Result<String>>) -> WorkspaceResult<String> {
    match handle.await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(error.into()),
        Err(error) => Err(WorkspaceManagerError::HookOutput(error.to_string())),
    }
}
