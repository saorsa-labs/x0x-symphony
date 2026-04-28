#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

mod containment;
mod hooks;

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use x0x_symphony_core::{
    Hook, HookEnv, HookOutcome, Issue, IssueState, Result as CoreResult, SymphonyError, Workspace,
    WorkspaceHandle,
};

pub use containment::{sanitize_issue_identifier, workspace_path_for};
pub use hooks::{HookExecution, WORKSPACE_PATH_ENV, WORKSPACE_ROOT_ENV};

/// Result alias for workspace-manager operations.
///
/// # Examples
///
/// ```
/// use x0x_symphony_workspace::{sanitize_issue_identifier, WorkspaceResult};
///
/// fn sanitize(raw: &str) -> WorkspaceResult<String> {
///     sanitize_issue_identifier(raw)
/// }
/// # Ok::<(), x0x_symphony_workspace::WorkspaceManagerError>(())
/// ```
pub type WorkspaceResult<T> = std::result::Result<T, WorkspaceManagerError>;

/// Errors produced by the workspace manager.
///
/// # Examples
///
/// ```
/// use x0x_symphony_workspace::WorkspaceManagerError;
///
/// let error = WorkspaceManagerError::InvalidIdentifier("contains traversal".into());
/// assert!(error.to_string().contains("invalid issue identifier"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceManagerError {
    /// Issue identifier cannot be converted into a safe workspace key.
    #[error("invalid issue identifier: {0}")]
    InvalidIdentifier(String),

    /// Workspace path escaped, or could escape, the configured root.
    #[error("workspace path escapes root: root={root:?} path={path:?}")]
    RootEscape {
        /// Canonical workspace root.
        root: PathBuf,
        /// Path that failed containment validation.
        path: PathBuf,
    },

    /// A filesystem path was expected to be a directory.
    #[error("path is not a directory: {0:?}")]
    NotDirectory(PathBuf),

    /// A symbolic link was found where a real directory is required.
    #[error("symbolic link rejected: {0:?}")]
    SymlinkRejected(PathBuf),

    /// Hook environment variable was denied by the secret-name policy.
    #[error("hook environment variable denied by secret policy: {0}")]
    DeniedEnvironment(String),

    /// Hook process could not be spawned.
    #[error("hook spawn failed: {0}")]
    HookSpawn(String),

    /// Hook output reader task failed.
    #[error("hook output reader failed: {0}")]
    HookOutput(String),

    /// Filesystem or process I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<WorkspaceManagerError> for SymphonyError {
    fn from(value: WorkspaceManagerError) -> Self {
        Self::Workspace(value.to_string())
    }
}

/// Configuration for [`WorkspaceManager`].
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use x0x_symphony_workspace::WorkspaceConfig;
///
/// let config = WorkspaceConfig::new(PathBuf::from("/tmp/x0x-symphony"))
///     .with_secret_env("API_TOKEN")
///     .with_output_limit_bytes(4096);
/// assert_eq!(config.output_limit_bytes(), 4096);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceConfig {
    root: PathBuf,
    allowed_secret_env: BTreeSet<String>,
    output_limit_bytes: usize,
}

impl WorkspaceConfig {
    /// Default number of bytes captured from each hook output stream.
    pub const DEFAULT_OUTPUT_LIMIT_BYTES: usize = 16 * 1024;

    /// Construct workspace configuration for a root path.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use x0x_symphony_workspace::WorkspaceConfig;
    ///
    /// let config = WorkspaceConfig::new(PathBuf::from("/tmp/workspaces"));
    /// assert_eq!(config.root(), PathBuf::from("/tmp/workspaces").as_path());
    /// ```
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            allowed_secret_env: BTreeSet::new(),
            output_limit_bytes: Self::DEFAULT_OUTPUT_LIMIT_BYTES,
        }
    }

    /// Return the configured root path before canonicalization.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use x0x_symphony_workspace::WorkspaceConfig;
    ///
    /// let config = WorkspaceConfig::new(PathBuf::from("/tmp/workspaces"));
    /// assert_eq!(config.root(), PathBuf::from("/tmp/workspaces").as_path());
    /// ```
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return a copy that explicitly allows one secret-like environment name.
    ///
    /// Exact-name allow-listing is required for names ending in `_TOKEN`,
    /// `_KEY`, or `_SECRET`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use x0x_symphony_workspace::WorkspaceConfig;
    ///
    /// let config = WorkspaceConfig::new(PathBuf::from("/tmp/workspaces"))
    ///     .with_secret_env("API_TOKEN");
    /// assert!(config.secret_env_is_allowed("API_TOKEN"));
    /// ```
    #[must_use]
    pub fn with_secret_env(mut self, name: impl Into<String>) -> Self {
        self.allowed_secret_env.insert(name.into());
        self
    }

    /// Return a copy with hook output capture limited to `bytes` per stream.
    ///
    /// A value of zero disables output capture while still draining the child
    /// process streams.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use x0x_symphony_workspace::WorkspaceConfig;
    ///
    /// let config = WorkspaceConfig::new(PathBuf::from("/tmp/workspaces"))
    ///     .with_output_limit_bytes(8);
    /// assert_eq!(config.output_limit_bytes(), 8);
    /// ```
    #[must_use]
    pub const fn with_output_limit_bytes(mut self, bytes: usize) -> Self {
        self.output_limit_bytes = bytes;
        self
    }

    /// Return true when a secret-like environment variable is explicitly allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use x0x_symphony_workspace::WorkspaceConfig;
    ///
    /// let config = WorkspaceConfig::new(PathBuf::from("/tmp/workspaces"));
    /// assert!(!config.secret_env_is_allowed("API_TOKEN"));
    /// ```
    #[must_use]
    pub fn secret_env_is_allowed(&self, name: &str) -> bool {
        self.allowed_secret_env.contains(name)
    }

    /// Return the hook output capture limit in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use x0x_symphony_workspace::WorkspaceConfig;
    ///
    /// let config = WorkspaceConfig::new(PathBuf::from("/tmp/workspaces"));
    /// assert_eq!(config.output_limit_bytes(), WorkspaceConfig::DEFAULT_OUTPUT_LIMIT_BYTES);
    /// ```
    #[must_use]
    pub const fn output_limit_bytes(&self) -> usize {
        self.output_limit_bytes
    }
}

/// Filesystem workspace manager used by the M1 orchestrator.
///
/// The manager canonicalizes its root during construction and rejects any
/// workspace or hook path that escapes that root.
///
/// # Examples
///
/// ```
/// use x0x_symphony_workspace::{WorkspaceConfig, WorkspaceManager};
///
/// let dir = tempfile::tempdir()?;
/// let manager = WorkspaceManager::new(WorkspaceConfig::new(dir.path().join("workspaces")))?;
/// let canonical_parent = std::fs::canonicalize(dir.path())?;
/// assert!(manager.root().starts_with(canonical_parent));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct WorkspaceManager {
    config: WorkspaceConfig,
    root: PathBuf,
}

impl WorkspaceManager {
    /// Create a manager and ensure the workspace root exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the root cannot be created, is not a directory, or
    /// cannot be canonicalized.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_workspace::{WorkspaceConfig, WorkspaceManager};
    ///
    /// let dir = tempfile::tempdir()?;
    /// let manager = WorkspaceManager::new(WorkspaceConfig::new(dir.path().join("workspaces")))?;
    /// assert!(manager.root().is_absolute());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(config: WorkspaceConfig) -> WorkspaceResult<Self> {
        std::fs::create_dir_all(config.root())?;
        let metadata = std::fs::symlink_metadata(config.root())?;
        if metadata.file_type().is_symlink() {
            return Err(WorkspaceManagerError::SymlinkRejected(
                config.root().to_path_buf(),
            ));
        }
        if !metadata.is_dir() {
            return Err(WorkspaceManagerError::NotDirectory(
                config.root().to_path_buf(),
            ));
        }
        let root = std::fs::canonicalize(config.root())?;
        Ok(Self { config, root })
    }

    /// Return the canonical workspace root.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_workspace::{WorkspaceConfig, WorkspaceManager};
    ///
    /// let dir = tempfile::tempdir()?;
    /// let manager = WorkspaceManager::new(WorkspaceConfig::new(dir.path().join("workspaces")))?;
    /// assert!(manager.root().is_absolute());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return the manager configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_workspace::{WorkspaceConfig, WorkspaceManager};
    ///
    /// let dir = tempfile::tempdir()?;
    /// let manager = WorkspaceManager::new(WorkspaceConfig::new(dir.path().join("workspaces")))?;
    /// assert_eq!(manager.config().output_limit_bytes(), WorkspaceConfig::DEFAULT_OUTPUT_LIMIT_BYTES);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn config(&self) -> &WorkspaceConfig {
        &self.config
    }

    /// Create or reuse the deterministic workspace for an issue.
    ///
    /// # Errors
    ///
    /// Returns an error when the issue identifier is unsafe, an existing path is
    /// not a directory, or containment validation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{Issue, IssueId, IssueState};
    /// use x0x_symphony_workspace::{WorkspaceConfig, WorkspaceManager};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let dir = tempfile::tempdir()?;
    /// let manager = WorkspaceManager::new(WorkspaceConfig::new(dir.path().join("workspaces")))?;
    /// let issue = Issue::new(IssueId::new("XSY-0005")?, "XSY-0005", "Workspace", IssueState::new("todo")?, "now")?;
    /// let handle = manager.create_workspace(&issue).await?;
    /// assert!(handle.path.ends_with("XSY-0005"));
    /// # Ok(()) }
    /// ```
    pub async fn create_workspace(&self, issue: &Issue) -> WorkspaceResult<WorkspaceHandle> {
        let path = workspace_path_for(&self.root, issue.identifier.as_str())?;
        self.reject_symlink_path(&path).await?;
        let created_now = match tokio::fs::metadata(&path).await {
            Ok(metadata) => {
                if !metadata.is_dir() {
                    return Err(WorkspaceManagerError::NotDirectory(path));
                }
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tokio::fs::create_dir(&path).await?;
                true
            }
            Err(error) => return Err(error.into()),
        };
        self.ensure_contained_existing(&path).await?;
        Ok(WorkspaceHandle::new(issue.id.clone(), path, created_now))
    }

    /// Execute a hook inside a specific workspace.
    ///
    /// # Errors
    ///
    /// Returns an error when the workspace path escapes the root, a denied
    /// environment variable is supplied, the hook cannot be spawned, or output
    /// collection fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{Hook, HookEnv, HookName, Issue, IssueId, IssueState};
    /// use x0x_symphony_workspace::{WorkspaceConfig, WorkspaceManager};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let dir = tempfile::tempdir()?;
    /// let manager = WorkspaceManager::new(WorkspaceConfig::new(dir.path().join("workspaces")))?;
    /// let issue = Issue::new(IssueId::new("XSY-0005")?, "XSY-0005", "Workspace", IssueState::new("todo")?, "now")?;
    /// let handle = manager.create_workspace(&issue).await?;
    /// let hook = Hook::new(HookName::BeforeRun, "printf hook-ok", 1_000);
    /// let outcome = manager.run_hook_for(&handle, &hook, &HookEnv::new()).await?;
    /// assert_eq!(outcome.stdout.as_deref(), Some("hook-ok"));
    /// # Ok(()) }
    /// ```
    pub async fn run_hook_for(
        &self,
        handle: &WorkspaceHandle,
        hook: &Hook,
        env: &HookEnv,
    ) -> WorkspaceResult<HookOutcome> {
        self.ensure_contained_existing(&handle.path).await?;
        let hook_env = HookEnv::new()
            .with_var(WORKSPACE_ROOT_ENV, self.root.to_string_lossy())
            .with_var(WORKSPACE_PATH_ENV, handle.path.to_string_lossy());
        let merged = merge_env(&hook_env, env);
        hooks::run_bash_hook(
            hook,
            &merged,
            &handle.path,
            &self.config.allowed_secret_env,
            self.config.output_limit_bytes,
        )
        .await
    }

    /// Execute a hook using `X0X_SYMPHONY_WORKSPACE_PATH` from the hook env.
    ///
    /// If the variable is absent, the hook runs at the workspace root. The
    /// `run_hook_for` helper should be preferred when a [`WorkspaceHandle`] is
    /// available.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested cwd escapes the root or hook execution
    /// fails before producing a structured outcome.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{Hook, HookEnv, HookName};
    /// use x0x_symphony_workspace::{WorkspaceConfig, WorkspaceManager};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let dir = tempfile::tempdir()?;
    /// let manager = WorkspaceManager::new(WorkspaceConfig::new(dir.path().join("workspaces")))?;
    /// let hook = Hook::new(HookName::BeforeRun, "printf root-ok", 1_000);
    /// let outcome = manager.run_configured_hook(&hook, &HookEnv::new()).await?;
    /// assert_eq!(outcome.stdout.as_deref(), Some("root-ok"));
    /// # Ok(()) }
    /// ```
    pub async fn run_configured_hook(
        &self,
        hook: &Hook,
        env: &HookEnv,
    ) -> WorkspaceResult<HookOutcome> {
        let cwd = env
            .vars
            .get(WORKSPACE_PATH_ENV)
            .map_or_else(|| self.root.clone(), PathBuf::from);
        self.ensure_contained_existing(&cwd).await?;
        hooks::run_bash_hook(
            hook,
            env,
            &cwd,
            &self.config.allowed_secret_env,
            self.config.output_limit_bytes,
        )
        .await
    }

    /// Delete a workspace only when `state` is terminal.
    ///
    /// Returns `true` when a delete happened and `false` when the workspace was
    /// preserved for retry or review.
    ///
    /// # Errors
    ///
    /// Returns an error when containment validation fails or deletion fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{Issue, IssueId, IssueState};
    /// use x0x_symphony_workspace::{WorkspaceConfig, WorkspaceManager};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let dir = tempfile::tempdir()?;
    /// let manager = WorkspaceManager::new(WorkspaceConfig::new(dir.path().join("workspaces")))?;
    /// let issue = Issue::new(IssueId::new("XSY-0005")?, "XSY-0005", "Workspace", IssueState::new("todo")?, "now")?;
    /// let handle = manager.create_workspace(&issue).await?;
    /// let deleted = manager.destroy_for_state(&handle, &IssueState::new("in_progress")?, &[IssueState::new("done")?]).await?;
    /// assert!(!deleted);
    /// # Ok(()) }
    /// ```
    pub async fn destroy_for_state(
        &self,
        handle: &WorkspaceHandle,
        state: &IssueState,
        terminal_states: &[IssueState],
    ) -> WorkspaceResult<bool> {
        if !terminal_states.iter().any(|terminal| terminal == state) {
            return Ok(false);
        }
        self.destroy_workspace(handle).await?;
        Ok(true)
    }

    /// Delete a workspace after the caller has observed a terminal state.
    ///
    /// # Errors
    ///
    /// Returns an error when containment validation fails or deletion fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{Issue, IssueId, IssueState};
    /// use x0x_symphony_workspace::{WorkspaceConfig, WorkspaceManager};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let dir = tempfile::tempdir()?;
    /// let manager = WorkspaceManager::new(WorkspaceConfig::new(dir.path().join("workspaces")))?;
    /// let issue = Issue::new(IssueId::new("XSY-0005")?, "XSY-0005", "Workspace", IssueState::new("done")?, "now")?;
    /// let handle = manager.create_workspace(&issue).await?;
    /// manager.destroy_workspace(&handle).await?;
    /// assert!(!handle.path.exists());
    /// # Ok(()) }
    /// ```
    pub async fn destroy_workspace(&self, handle: &WorkspaceHandle) -> WorkspaceResult<()> {
        match tokio::fs::symlink_metadata(&handle.path).await {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(WorkspaceManagerError::SymlinkRejected(handle.path.clone()));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(WorkspaceManagerError::NotDirectory(handle.path.clone()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        self.ensure_contained_existing(&handle.path).await?;
        match tokio::fs::remove_dir_all(&handle.path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn reject_symlink_path(&self, path: &Path) -> WorkspaceResult<()> {
        match tokio::fs::symlink_metadata(path).await {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                Err(WorkspaceManagerError::SymlinkRejected(path.to_path_buf()))
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn ensure_contained_existing(&self, path: &Path) -> WorkspaceResult<()> {
        self.reject_symlink_path(path).await?;
        let canonical = tokio::fs::canonicalize(path).await?;
        if !canonical.starts_with(&self.root) {
            return Err(WorkspaceManagerError::RootEscape {
                root: self.root.clone(),
                path: canonical,
            });
        }
        Ok(())
    }
}

#[async_trait]
impl Workspace for WorkspaceManager {
    fn root(&self) -> &Path {
        self.root()
    }

    async fn create(&self, issue: &Issue) -> CoreResult<WorkspaceHandle> {
        Ok(self.create_workspace(issue).await?)
    }

    async fn run_hook(&self, hook: &Hook, env: &HookEnv) -> CoreResult<HookOutcome> {
        Ok(self.run_configured_hook(hook, env).await?)
    }

    async fn destroy(&self, handle: WorkspaceHandle) -> CoreResult<()> {
        Ok(self.destroy_workspace(&handle).await?)
    }
}

fn merge_env(base: &HookEnv, overlay: &HookEnv) -> HookEnv {
    let mut merged = base.clone();
    merged.vars.extend(overlay.vars.clone());
    merged
}
