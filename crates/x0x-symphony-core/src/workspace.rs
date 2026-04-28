//! Workspace trait and hook outcome types.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{Hook, Issue, Result};

/// Environment passed to a workspace hook.
///
/// The map is an explicit allow-list; implementations must not forward the
/// process environment wholesale.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::HookEnv;
///
/// let env = HookEnv::new().with_var("RUST_LOG", "info");
/// assert_eq!(env.vars.get("RUST_LOG").map(String::as_str), Some("info"));
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct HookEnv {
    /// Allowed hook environment variables.
    pub vars: BTreeMap<String, String>,
}

impl HookEnv {
    /// Construct an empty hook environment.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::HookEnv;
    ///
    /// let env = HookEnv::new();
    /// assert!(env.vars.is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a copy with one variable added.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::HookEnv;
    ///
    /// let env = HookEnv::new().with_var("RUST_LOG", "debug");
    /// assert_eq!(env.vars.get("RUST_LOG").map(String::as_str), Some("debug"));
    /// ```
    #[must_use]
    pub fn with_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.vars.insert(key.into(), value.into());
        self
    }
}

/// Hook execution status.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::HookStatus;
///
/// assert!(HookStatus::Succeeded.is_success());
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookStatus {
    /// Hook completed successfully.
    Succeeded,
    /// Hook process returned a failing exit status.
    Failed,
    /// Hook exceeded its timeout.
    TimedOut,
}

impl HookStatus {
    /// Return true for a successful hook.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::HookStatus;
    ///
    /// assert!(HookStatus::Succeeded.is_success());
    /// assert!(!HookStatus::Failed.is_success());
    /// ```
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

/// Outcome produced by a workspace hook.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{HookOutcome, HookStatus};
///
/// let outcome = HookOutcome::new(HookStatus::Succeeded).with_exit_code(0);
/// assert_eq!(outcome.exit_code, Some(0));
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HookOutcome {
    /// Hook status.
    pub status: HookStatus,
    /// Exit code when a process completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Captured stdout, truncated by implementations as needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    /// Captured stderr, truncated by implementations as needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

impl HookOutcome {
    /// Construct a hook outcome without output or exit code.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{HookOutcome, HookStatus};
    ///
    /// let outcome = HookOutcome::new(HookStatus::Succeeded);
    /// assert!(outcome.status.is_success());
    /// ```
    #[must_use]
    pub fn new(status: HookStatus) -> Self {
        Self {
            status,
            exit_code: None,
            stdout: None,
            stderr: None,
        }
    }

    /// Return a copy with an exit code.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{HookOutcome, HookStatus};
    ///
    /// let outcome = HookOutcome::new(HookStatus::Succeeded).with_exit_code(0);
    /// assert_eq!(outcome.exit_code, Some(0));
    /// ```
    #[must_use]
    pub fn with_exit_code(mut self, exit_code: i32) -> Self {
        self.exit_code = Some(exit_code);
        self
    }

    /// Return a copy with stdout.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{HookOutcome, HookStatus};
    ///
    /// let outcome = HookOutcome::new(HookStatus::Succeeded).with_stdout("ok");
    /// assert_eq!(outcome.stdout.as_deref(), Some("ok"));
    /// ```
    #[must_use]
    pub fn with_stdout(mut self, stdout: impl Into<String>) -> Self {
        self.stdout = Some(stdout.into());
        self
    }

    /// Return a copy with stderr.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{HookOutcome, HookStatus};
    ///
    /// let outcome = HookOutcome::new(HookStatus::Failed).with_stderr("boom");
    /// assert_eq!(outcome.stderr.as_deref(), Some("boom"));
    /// ```
    #[must_use]
    pub fn with_stderr(mut self, stderr: impl Into<String>) -> Self {
        self.stderr = Some(stderr.into());
        self
    }
}

/// Handle for a prepared issue workspace.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use x0x_symphony_core::{IssueId, WorkspaceHandle};
///
/// let handle = WorkspaceHandle::new(IssueId::new("XSY-0002")?, PathBuf::from("/tmp/XSY-0002"), true);
/// assert!(handle.created_now);
/// # Ok::<(), x0x_symphony_core::SymphonyError>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceHandle {
    /// Issue identifier this workspace belongs to.
    pub issue_id: crate::IssueId,
    /// Absolute workspace path.
    pub path: PathBuf,
    /// Whether the workspace directory was created for this call.
    pub created_now: bool,
}

impl WorkspaceHandle {
    /// Construct a workspace handle.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use x0x_symphony_core::{IssueId, WorkspaceHandle};
    ///
    /// let handle = WorkspaceHandle::new(IssueId::new("XSY-0002")?, PathBuf::from("/tmp/XSY-0002"), false);
    /// assert!(!handle.created_now);
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    #[must_use]
    pub fn new(issue_id: crate::IssueId, path: PathBuf, created_now: bool) -> Self {
        Self {
            issue_id,
            path,
            created_now,
        }
    }
}

/// Workspace lifecycle abstraction used by the orchestrator.
///
/// # Examples
///
/// ```no_run
/// use async_trait::async_trait;
/// use std::path::{Path, PathBuf};
/// use x0x_symphony_core::{Hook, HookEnv, HookOutcome, HookStatus, Issue, Result, Workspace, WorkspaceHandle};
///
/// struct NoopWorkspace { root: PathBuf }
///
/// #[async_trait]
/// impl Workspace for NoopWorkspace {
///     fn root(&self) -> &Path { &self.root }
///     async fn create(&self, issue: &Issue) -> Result<WorkspaceHandle> {
///         Ok(WorkspaceHandle::new(issue.id.clone(), self.root.join(issue.identifier.as_str()), false))
///     }
///     async fn run_hook(&self, _hook: &Hook, _env: &HookEnv) -> Result<HookOutcome> {
///         Ok(HookOutcome::new(HookStatus::Succeeded))
///     }
///     async fn destroy(&self, _handle: WorkspaceHandle) -> Result<()> { Ok(()) }
/// }
/// ```
#[async_trait]
pub trait Workspace: Send + Sync {
    /// Return the configured workspace root.
    fn root(&self) -> &Path;

    /// Create or reuse a workspace for an issue.
    async fn create(&self, issue: &Issue) -> Result<WorkspaceHandle>;

    /// Execute one configured workspace hook.
    async fn run_hook(&self, hook: &Hook, env: &HookEnv) -> Result<HookOutcome>;

    /// Destroy a workspace after a terminal state transition.
    async fn destroy(&self, handle: WorkspaceHandle) -> Result<()>;
}
