#![forbid(unsafe_code)]
//! Host sandbox profile planning for the shell runner.
//!
//! The sandbox layer creates a per-command session, then wraps a structured
//! [`CommandPlan`] into a [`WrappedCommand`] before the runner builds
//! `tokio::process::Command`. It never attempts to inspect a built command
//! because Tokio's command type intentionally has no getters for argv, cwd, or
//! environment.

use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::process::Command;
use x0x_symphony_core::IssueSource;

#[cfg(target_os = "linux")]
pub mod linux;

/// Result alias for sandbox operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Structured failures produced by sandbox planning and probes.
#[derive(Debug, Error)]
pub enum Error {
    /// Workflow configuration is present but invalid.
    #[error("invalid runner config {field}: {message}")]
    InvalidConfig {
        /// Configuration field that failed validation.
        field: &'static str,
        /// Human-readable validation failure.
        message: String,
    },

    /// A configured sandbox backend could not be enforced.
    #[error("sandbox backend {backend} unavailable: {message}")]
    SandboxUnavailable {
        /// Effective sandbox backend name.
        backend: String,
        /// Human-readable unavailability reason.
        message: String,
    },

    /// Sandbox probe filesystem setup or cleanup failed.
    #[error("sandbox probe I/O error at {path}: {source}")]
    ProbeIo {
        /// Path involved in the probe I/O failure.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// Runtime sandbox filesystem or socket setup failed.
    #[error("sandbox I/O error at {path}: {source}")]
    SandboxIo {
        /// Path involved in the sandbox operation.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// Launcher socket protocol failed.
    #[error("sandbox launcher protocol error: {message}")]
    Protocol {
        /// Human-readable protocol failure.
        message: String,
    },

    /// Linux access-control setup failed.
    #[error("landlock setup failed: {message}")]
    Landlock {
        /// Human-readable setup failure.
        message: String,
    },

    /// Process replacement in the launcher failed.
    #[error("launcher exec failed: {source}")]
    Exec {
        /// Underlying process replacement failure.
        #[source]
        source: io::Error,
    },
}

impl Error {
    /// Construct an invalid-config error.
    #[must_use]
    pub fn invalid_config(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidConfig {
            field,
            message: message.into(),
        }
    }

    /// Construct a runtime sandbox I/O error.
    #[must_use]
    pub fn sandbox_io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::SandboxIo {
            path: path.into(),
            source,
        }
    }

    /// Construct a launcher protocol error.
    #[must_use]
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol {
            message: message.into(),
        }
    }

    /// Construct a Linux access-control setup error.
    #[must_use]
    pub fn landlock(message: impl Into<String>) -> Self {
        Self::Landlock {
            message: message.into(),
        }
    }
}

fn validate_arg(arg: &str) -> Result<()> {
    if arg.as_bytes().contains(&0) {
        return Err(Error::invalid_config(
            "runner.args",
            "must not contain NUL bytes",
        ));
    }
    Ok(())
}

const WORKSPACE_MOUNT: &str = "/workspace";
const SANDBOX_EXEC_PATH: &str = "/usr/bin/sandbox-exec";
const SRT_BINARY: &str = "srt";
const BWRAP_BINARY: &str = "bwrap";
const LANDLOCK_BINARY: &str = "landlock-restrict";
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_NOT_APPLICABLE_EXIT: i32 = 77;

/// The runner's desired command before sandboxing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPlan {
    /// Executable name or absolute path.
    pub program: String,
    /// Argument vector passed without shell interpolation.
    pub args: Vec<String>,
    /// Working directory on the host before any sandbox namespace is entered.
    pub cwd: PathBuf,
    /// Exact child environment after the runner's allow-list has been applied.
    pub env: BTreeMap<String, String>,
}

impl CommandPlan {
    /// Construct a new command plan.
    #[must_use]
    pub fn new(
        program: impl Into<String>,
        args: Vec<String>,
        cwd: PathBuf,
        env: BTreeMap<String, String>,
    ) -> Self {
        Self {
            program: program.into(),
            args,
            cwd,
            env,
        }
    }
}

/// The sandboxed command the runner spawns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedCommand {
    /// Executable name or absolute path after sandbox wrapping.
    pub program: String,
    /// Argument vector passed without shell interpolation after sandbox wrapping.
    pub args: Vec<String>,
    /// Working directory used when spawning the wrapped command.
    pub cwd: PathBuf,
    /// Environment additions the backend needs, applied over the caller's
    /// allow-list at spawn time. This is not a complete child environment;
    /// collisions deliberately let the backend override the caller.
    pub env_additions: BTreeMap<String, String>,
}

impl WrappedCommand {
    /// Return an unwrapped command view for a caller plan.
    #[must_use]
    pub fn from_plan(plan: &CommandPlan) -> Self {
        Self {
            program: plan.program.clone(),
            args: plan.args.clone(),
            cwd: plan.cwd.clone(),
            env_additions: BTreeMap::new(),
        }
    }
}

impl From<CommandPlan> for WrappedCommand {
    fn from(plan: CommandPlan) -> Self {
        Self {
            program: plan.program,
            args: plan.args,
            cwd: plan.cwd,
            env_additions: BTreeMap::new(),
        }
    }
}

/// Per-session sandbox resources and wrapping hooks for one command lifetime.
#[async_trait]
pub trait SandboxSession: Send + Sync {
    /// Produce the wrapped command for this plan after [`Sandbox::prepare`].
    ///
    /// # Errors
    ///
    /// Returns an error when the plan cannot be represented by the backend.
    async fn wrap(&self, plan: &CommandPlan) -> Result<WrappedCommand>;

    /// Observe the spawned child before any backend-specific release step.
    ///
    /// The Linux native launcher needs the parent to attach the spawned PID to
    /// its cgroup before the launcher is released through its synchronization
    /// pipe. This hook is the split point that makes that race-free attach
    /// possible. Backends that do not need it use the default no-op.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot finish child setup.
    async fn child_started(&self, _pid: u32) -> Result<()> {
        Ok(())
    }

    /// Release backend resources associated with this prepared command.
    ///
    /// # Errors
    ///
    /// Returns an error when backend cleanup fails.
    async fn shutdown(&mut self) -> Result<()>;
}

/// Lifecycle handle for unsandboxed or externally self-cleaning commands.
#[derive(Debug, Default)]
pub struct NoopSession;

#[async_trait]
impl SandboxSession for NoopSession {
    async fn wrap(&self, plan: &CommandPlan) -> Result<WrappedCommand> {
        Ok(WrappedCommand::from_plan(plan))
    }

    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Host sandbox backend selection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// Probe the best backend available on this host at sandbox construction.
    #[default]
    Auto,
    /// Linux self-reexec Landlock plus cgroup-v2 backend.
    #[serde(alias = "linux-native", alias = "linux_native")]
    Native,
    /// External sandbox-runtime (`srt`) command.
    #[serde(alias = "srt", alias = "sandbox_runtime")]
    SandboxRuntime,
    /// Linux Bubblewrap (`bwrap`) namespace wrapper.
    #[serde(alias = "bwrap")]
    Bubblewrap,
    /// Linux Landlock helper wrapper.
    Landlock,
    /// macOS `sandbox-exec` wrapper.
    #[serde(alias = "sandbox_exec")]
    SandboxExec,
    /// Explicitly leave the command unsandboxed.
    None,
}

impl Backend {
    /// Stable lowercase name for logs, docs, and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Native => "native",
            Self::SandboxRuntime => "sandbox-runtime",
            Self::Bubblewrap => "bubblewrap",
            Self::Landlock => "landlock",
            Self::SandboxExec => "sandbox-exec",
            Self::None => "none",
        }
    }
}

/// Sandbox profile declared by workflow configuration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxProfile {
    /// Workspace read-only, no network, and secrets denied.
    #[serde(alias = "read_only")]
    ReadOnly,
    /// Workspace writable, LLM/API egress only, and secrets denied.
    #[serde(alias = "repo_write")]
    #[default]
    RepoWrite,
    /// Workspace writable, network disabled, and secrets denied.
    #[serde(alias = "no_network")]
    NoNetwork,
    /// Workspace writable, unrestricted network, and secrets accessible.
    #[serde(alias = "full_dev")]
    FullDev,
    /// Workspace writable, CI/registry egress, and only CI-scoped secrets.
    #[serde(alias = "ci_only")]
    CiOnly,
}

impl SandboxProfile {
    /// Stable kebab-case profile name.
    #[must_use]
    pub const fn as_kebab(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::RepoWrite => "repo-write",
            Self::NoNetwork => "no-network",
            Self::FullDev => "full-dev",
            Self::CiOnly => "ci-only",
        }
    }

    const fn denies_network_by_default(self) -> bool {
        matches!(self, Self::ReadOnly | Self::NoNetwork)
    }

    const fn denies_secrets(self) -> bool {
        !matches!(self, Self::FullDev)
    }

    const fn workspace_read_only(self) -> bool {
        matches!(self, Self::ReadOnly)
    }
}

/// Policy used when a local-work sandbox backend cannot be enforced.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnavailablePolicy {
    /// Refuse to run the command.
    #[serde(alias = "fail_closed")]
    FailClosed,
    /// Log a warning and run the unwrapped command.
    #[default]
    Warn,
}

/// Workflow sandbox configuration resolved from `runner.sandbox`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxSpec {
    /// Sandbox profile to enforce.
    #[serde(default)]
    pub profile: SandboxProfile,
    /// Requested backend; `auto` is resolved at sandbox construction.
    #[serde(default)]
    pub backend: Backend,
    /// Local-work behavior when the requested backend is unavailable.
    #[serde(default)]
    pub on_unavailable: UnavailablePolicy,
    /// Domain allow-list for profiles that permit restricted egress.
    #[serde(default)]
    pub egress_allow: Vec<String>,
    /// Secret paths that must be hidden from non-`full-dev` profiles.
    #[serde(default = "default_secret_denies")]
    pub secrets_deny: Vec<PathBuf>,
    /// Optional CPU limit in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_seconds: Option<u64>,
    /// Optional address-space / memory ceiling in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    /// Optional descendant process ceiling for cgroup-v2 backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_max: Option<u32>,
}

impl SandboxSpec {
    /// Return whether this spec is acceptable for the given issue source.
    ///
    /// Network-sourced dispatch is always fail-closed: `on_unavailable` is a
    /// local-work convenience only and cannot permit network-sourced execution
    /// without an enforceable backend.
    #[must_use]
    pub fn enforceable_for(&self, source: IssueSource) -> bool {
        match source {
            IssueSource::Local => {
                self.backend != Backend::None || self.on_unavailable == UnavailablePolicy::Warn
            }
            IssueSource::NetworkSourced => self.backend != Backend::None,
        }
    }

    /// Validate self-contained sandbox configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when domains, paths, or resource limits are malformed.
    pub fn validate(&self) -> Result<()> {
        for domain in &self.egress_allow {
            if domain.trim().is_empty() {
                return Err(Error::invalid_config(
                    "runner.sandbox.egress_allow",
                    "domains must not be empty",
                ));
            }
            validate_arg(domain)?;
        }
        for path in &self.secrets_deny {
            if path.as_os_str().is_empty() {
                return Err(Error::invalid_config(
                    "runner.sandbox.secrets_deny",
                    "paths must not be empty",
                ));
            }
        }
        if self.cpu_seconds == Some(0) {
            return Err(Error::invalid_config(
                "runner.sandbox.cpu_seconds",
                "must be greater than zero when set",
            ));
        }
        if self.memory_bytes == Some(0) {
            return Err(Error::invalid_config(
                "runner.sandbox.memory_bytes",
                "must be greater than zero when set",
            ));
        }
        if self.pids_max == Some(0) {
            return Err(Error::invalid_config(
                "runner.sandbox.pids_max",
                "must be greater than zero when set",
            ));
        }
        Ok(())
    }

    /// Expand supported `~` prefixes in path fields in place.
    pub fn normalize_paths(&mut self) {
        self.secrets_deny = self
            .secrets_deny
            .iter()
            .map(|path| expand_tilde_path(path))
            .collect();
    }

    fn network_allowed(&self) -> bool {
        match self.profile {
            SandboxProfile::FullDev => true,
            SandboxProfile::RepoWrite | SandboxProfile::CiOnly => !self.egress_allow.is_empty(),
            SandboxProfile::ReadOnly | SandboxProfile::NoNetwork => false,
        }
    }
}

impl Default for SandboxSpec {
    fn default() -> Self {
        Self {
            profile: SandboxProfile::RepoWrite,
            backend: Backend::Auto,
            on_unavailable: UnavailablePolicy::Warn,
            egress_allow: Vec::new(),
            secrets_deny: default_secret_denies(),
            cpu_seconds: None,
            memory_bytes: None,
            pids_max: None,
        }
    }
}

/// One probe check outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeCheck {
    /// Stable check identifier.
    pub name: String,
    /// Enforcement result for this check.
    pub status: ProbeStatus,
    /// Human-readable details for diagnostics.
    pub detail: String,
}

/// Probe check status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeStatus {
    /// The backend blocked the forbidden action.
    Pass,
    /// The forbidden action succeeded or the probe failed unexpectedly.
    Fail,
    /// The check is not meaningful on this backend/profile/platform.
    NotApplicable,
}

/// Structured sandbox self-test report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeReport {
    /// Effective backend used for the probe.
    pub backend: Backend,
    /// Profile used for the probe.
    pub profile: SandboxProfile,
    /// Per-check outcomes.
    pub checks: Vec<ProbeCheck>,
}

/// Object-safe sandbox interface used by the runner.
#[async_trait]
pub trait Sandbox: Send + Sync {
    /// Set up backend resources for one command lifetime.
    ///
    /// `source` controls fail-closed behavior. The runner still hard-codes the
    /// local source today; the real source is propagated by the next native
    /// backend step without changing dispatch-gate semantics.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured backend is unavailable under a
    /// fail-closed policy.
    async fn prepare(&self, source: IssueSource) -> Result<Box<dyn SandboxSession>>;

    /// Run the backend self-test and return a structured report.
    ///
    /// # Errors
    ///
    /// Returns an error when the probe workspace cannot be created or cleaned.
    async fn probe(&self) -> Result<ProbeReport>;

    /// Borrow the effective sandbox specification.
    fn spec(&self) -> &SandboxSpec;
}

/// Sandbox implementation backed by host-provided command-line tools.
pub struct HostSandbox {
    spec: SandboxSpec,
    backend_available: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostWrapMode {
    Available,
    UnavailableWarn,
}

#[derive(Debug)]
struct HostSandboxSession {
    spec: SandboxSpec,
    mode: HostWrapMode,
}

impl HostSandbox {
    /// Construct a host sandbox, resolving `backend = auto` immediately.
    ///
    /// # Errors
    ///
    /// Returns an error when the provided sandbox spec is invalid.
    pub fn new(mut spec: SandboxSpec) -> Result<Self> {
        spec.normalize_paths();
        spec.validate()?;
        let (backend, available) = resolve_backend(spec.backend, &spec);
        spec.backend = backend;
        Ok(Self {
            spec,
            backend_available: available,
        })
    }

    #[cfg(test)]
    fn from_resolved(mut spec: SandboxSpec, backend_available: bool) -> Result<Self> {
        spec.normalize_paths();
        spec.validate()?;
        Ok(Self {
            spec,
            backend_available,
        })
    }

    fn prepare_mode(&self, source: IssueSource) -> Result<HostWrapMode> {
        if self.spec.backend != Backend::None && self.backend_available {
            return Ok(HostWrapMode::Available);
        }
        let message = if self.spec.backend == Backend::None {
            "sandbox backend resolved to none".to_owned()
        } else {
            format!("{} is unavailable", self.spec.backend.as_str())
        };
        if source == IssueSource::NetworkSourced
            || self.spec.on_unavailable == UnavailablePolicy::FailClosed
        {
            return Err(Error::SandboxUnavailable {
                backend: self.spec.backend.as_str().to_owned(),
                message,
            });
        }
        Ok(HostWrapMode::UnavailableWarn)
    }

    async fn probe_check(
        &self,
        workspace: &Path,
        name: &str,
        program: &str,
        args: Vec<String>,
    ) -> ProbeCheck {
        let mut env = BTreeMap::new();
        if let Some(path) = env::var_os("PATH").and_then(os_string_into_string) {
            env.insert("PATH".to_owned(), path);
        }
        let plan = CommandPlan::new(program, args, workspace.to_path_buf(), env);
        let mut session = match self.prepare(IssueSource::Local).await {
            Ok(session) => session,
            Err(error) => {
                return ProbeCheck {
                    name: name.to_owned(),
                    status: ProbeStatus::NotApplicable,
                    detail: format!("probe could not prepare command: {error}"),
                };
            }
        };
        let command = match session.wrap(&plan).await {
            Ok(command) => command,
            Err(error) => {
                let detail = format!("probe could not wrap command: {error}");
                if let Err(shutdown_error) = session.shutdown().await {
                    return ProbeCheck {
                        name: name.to_owned(),
                        status: ProbeStatus::Fail,
                        detail: format!(
                            "probe sandbox shutdown failed after wrap error: {shutdown_error}"
                        ),
                    };
                }
                return ProbeCheck {
                    name: name.to_owned(),
                    status: ProbeStatus::NotApplicable,
                    detail,
                };
            }
        };
        let run = run_probe_plan(&command, &plan.env, &*session).await;
        if let Err(error) = session.shutdown().await {
            return ProbeCheck {
                name: name.to_owned(),
                status: ProbeStatus::Fail,
                detail: format!("probe sandbox shutdown failed: {error}"),
            };
        }
        match run {
            ProbeRun::Blocked(detail) => ProbeCheck {
                name: name.to_owned(),
                status: ProbeStatus::Pass,
                detail,
            },
            ProbeRun::Allowed(detail) => ProbeCheck {
                name: name.to_owned(),
                status: ProbeStatus::Fail,
                detail,
            },
            ProbeRun::NotApplicable(detail) => ProbeCheck {
                name: name.to_owned(),
                status: ProbeStatus::NotApplicable,
                detail,
            },
        }
    }
}

impl HostSandboxSession {
    fn wrap_available(&self, plan: &mut WrappedCommand) {
        match self.spec.backend {
            Backend::SandboxRuntime => self.wrap_sandbox_runtime(plan),
            Backend::Bubblewrap => self.wrap_bubblewrap(plan),
            Backend::Landlock => self.wrap_landlock(plan),
            Backend::SandboxExec => self.wrap_sandbox_exec(plan),
            Backend::Native | Backend::Auto | Backend::None => {}
        }
        self.apply_resource_limits(plan);
    }

    fn wrap_sandbox_runtime(&self, plan: &mut WrappedCommand) {
        let mut args = vec![
            "run".to_owned(),
            "--profile".to_owned(),
            self.spec.profile.as_kebab().to_owned(),
            "--cwd".to_owned(),
            path_string(&plan.cwd),
            "--workspace".to_owned(),
            path_string(&plan.cwd),
        ];
        for domain in &self.spec.egress_allow {
            args.push("--egress-allow".to_owned());
            args.push(domain.clone());
        }
        if self.spec.profile.denies_secrets() {
            for path in &self.spec.secrets_deny {
                args.push("--deny-path".to_owned());
                args.push(path_string(path));
            }
        }
        args.push("--".to_owned());
        replace_with_wrapper(plan, SRT_BINARY, args);
    }

    fn wrap_bubblewrap(&self, plan: &mut WrappedCommand) {
        let mut args = bubblewrap_namespace_args(&self.spec);
        args.extend(["--ro-bind".to_owned(), "/".to_owned(), "/".to_owned()]);
        if self.spec.profile.workspace_read_only() {
            args.push("--ro-bind".to_owned());
        } else {
            args.push("--bind".to_owned());
        }
        args.push(path_string(&plan.cwd));
        args.push(WORKSPACE_MOUNT.to_owned());
        if self.spec.profile.denies_secrets() {
            for path in &self.spec.secrets_deny {
                if path.is_absolute() {
                    args.push("--tmpfs".to_owned());
                    args.push(path_string(path));
                }
            }
        }
        args.extend([
            "--tmpfs".to_owned(),
            "/tmp".to_owned(),
            "--proc".to_owned(),
            "/proc".to_owned(),
            "--dev".to_owned(),
            "/dev".to_owned(),
            "--chdir".to_owned(),
            WORKSPACE_MOUNT.to_owned(),
            "--".to_owned(),
        ]);
        replace_with_wrapper(plan, BWRAP_BINARY, args);
    }

    fn wrap_landlock(&self, plan: &mut WrappedCommand) {
        let mut args = Vec::new();
        if self.spec.profile.workspace_read_only() {
            args.push("--ro".to_owned());
        } else {
            args.push("--rw".to_owned());
        }
        args.push(path_string(&plan.cwd));
        if !self.spec.network_allowed() {
            args.push("--no-network".to_owned());
        }
        if self.spec.profile.denies_secrets() {
            for path in &self.spec.secrets_deny {
                args.push("--deny".to_owned());
                args.push(path_string(path));
            }
        }
        args.push("--".to_owned());
        replace_with_wrapper(plan, LANDLOCK_BINARY, args);
    }

    fn wrap_sandbox_exec(&self, plan: &mut WrappedCommand) {
        let profile = sandbox_exec_profile(&self.spec, &plan.cwd);
        let args = vec!["-p".to_owned(), profile];
        replace_with_wrapper(plan, SANDBOX_EXEC_PATH, args);
    }

    fn apply_resource_limits(&self, plan: &mut WrappedCommand) {
        if self.spec.cpu_seconds.is_none()
            && self.spec.memory_bytes.is_none()
            && self.spec.pids_max.is_none()
        {
            return;
        }
        apply_platform_resource_limits(&self.spec, plan);
    }
}

#[async_trait]
impl SandboxSession for HostSandboxSession {
    async fn wrap(&self, plan: &CommandPlan) -> Result<WrappedCommand> {
        let mut command = WrappedCommand::from_plan(plan);
        match self.mode {
            HostWrapMode::Available => self.wrap_available(&mut command),
            HostWrapMode::UnavailableWarn => {
                tracing::warn!(
                    backend = self.spec.backend.as_str(),
                    command = plan.program,
                    "sandbox unavailable; running local work with path containment only"
                );
            }
        }
        Ok(command)
    }

    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Sandbox for HostSandbox {
    async fn prepare(&self, source: IssueSource) -> Result<Box<dyn SandboxSession>> {
        let mode = self.prepare_mode(source)?;
        if mode == HostWrapMode::Available && self.spec.backend == Backend::Native {
            #[cfg(target_os = "linux")]
            {
                return linux::LinuxSandboxSession::prepare(self.spec.clone())
                    .map(|session| Box::new(session) as Box<dyn SandboxSession>);
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(Error::SandboxUnavailable {
                    backend: self.spec.backend.as_str().to_owned(),
                    message: "native backend is Linux-only".to_owned(),
                });
            }
        }
        Ok(Box::new(HostSandboxSession {
            spec: self.spec.clone(),
            mode,
        }))
    }

    async fn probe(&self) -> Result<ProbeReport> {
        if self.spec.backend == Backend::Native {
            #[cfg(target_os = "linux")]
            {
                return Ok(linux::native_probe_report(self.spec.profile));
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Ok(ProbeReport {
                    backend: self.spec.backend,
                    profile: self.spec.profile,
                    checks: vec![ProbeCheck {
                        name: "native-linux-only".to_owned(),
                        status: ProbeStatus::NotApplicable,
                        detail: "native backend is Linux-only".to_owned(),
                    }],
                });
            }
        }
        let root = probe_root();
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).map_err(|source| Error::ProbeIo {
            path: workspace.clone(),
            source,
        })?;

        let mut checks = Vec::new();
        let outside = root.join("outside.txt");
        checks.push(
            self.probe_check(
                &workspace,
                "write-outside-workspace",
                "/bin/sh",
                vec![
                    "-c".to_owned(),
                    "echo blocked > \"$1\"".to_owned(),
                    "sh".to_owned(),
                    path_string(&outside),
                ],
            )
            .await,
        );

        let synthetic_secret = root.join("synthetic-secret").join("id_rsa");
        if let Some(parent) = synthetic_secret.parent() {
            std::fs::create_dir_all(parent).map_err(|source| Error::ProbeIo {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        std::fs::write(&synthetic_secret, b"synthetic probe secret").map_err(|source| {
            Error::ProbeIo {
                path: synthetic_secret.clone(),
                source,
            }
        })?;
        checks.push(self.secret_probe(&workspace, &synthetic_secret).await);
        checks.push(self.pid_probe(&workspace).await);
        checks.push(self.network_probe(&workspace).await);
        cleanup_probe_root(&root)?;
        Ok(ProbeReport {
            backend: self.spec.backend,
            profile: self.spec.profile,
            checks,
        })
    }

    fn spec(&self) -> &SandboxSpec {
        &self.spec
    }
}

impl HostSandbox {
    async fn secret_probe(&self, workspace: &Path, synthetic_secret: &Path) -> ProbeCheck {
        if !self.spec.profile.denies_secrets() {
            return ProbeCheck {
                name: "secret-read".to_owned(),
                status: ProbeStatus::NotApplicable,
                detail: "profile permits secret access".to_owned(),
            };
        }
        let secret = self
            .probe_secret_candidate()
            .unwrap_or_else(|| synthetic_secret.to_path_buf());
        let mut spec = self.spec.clone();
        if !spec.secrets_deny.iter().any(|path| path == &secret) {
            spec.secrets_deny.push(secret.clone());
        }
        let sandbox = Self {
            spec,
            backend_available: self.backend_available,
        };
        sandbox
            .probe_check(
                workspace,
                "secret-read",
                "/bin/sh",
                vec![
                    "-c".to_owned(),
                    "cat \"$1\" >/dev/null".to_owned(),
                    "sh".to_owned(),
                    path_string(&secret),
                ],
            )
            .await
    }

    fn probe_secret_candidate(&self) -> Option<PathBuf> {
        if let Some(id_rsa) = home_dir().map(|home| home.join(".ssh/id_rsa")) {
            if id_rsa.is_file() {
                return Some(id_rsa);
            }
        }
        self.spec
            .secrets_deny
            .iter()
            .find(|path| path.is_file())
            .cloned()
    }

    async fn pid_probe(&self, workspace: &Path) -> ProbeCheck {
        if !cfg!(target_os = "linux") {
            return ProbeCheck {
                name: "host-pid-invisible".to_owned(),
                status: ProbeStatus::NotApplicable,
                detail: "host PID namespace check is Linux-specific".to_owned(),
            };
        }
        self.probe_check(
            workspace,
            "host-pid-invisible",
            "/bin/sh",
            vec![
                "-c".to_owned(),
                "test ! -e /proc/1/root".to_owned(),
                "sh".to_owned(),
            ],
        )
        .await
    }

    async fn network_probe(&self, workspace: &Path) -> ProbeCheck {
        if self.spec.network_allowed() && !self.spec.profile.denies_network_by_default() {
            return ProbeCheck {
                name: "non-allowlisted-network".to_owned(),
                status: ProbeStatus::NotApplicable,
                detail: "profile permits configured network egress".to_owned(),
            };
        }
        self.probe_check(
            workspace,
            "non-allowlisted-network",
            "/bin/sh",
            vec![
                "-c".to_owned(),
                concat!(
                    "command -v python3 >/dev/null 2>&1 || exit 77; ",
                    "python3 -c '",
                    "import socket; ",
                    "socket.create_connection((\"1.1.1.1\", 80), 2).close()",
                    "'"
                )
                .to_owned(),
                "sh".to_owned(),
            ],
        )
        .await
    }
}

fn bubblewrap_namespace_args(spec: &SandboxSpec) -> Vec<String> {
    if spec.network_allowed() {
        vec![
            "--die-with-parent".to_owned(),
            "--unshare-user".to_owned(),
            "--unshare-ipc".to_owned(),
            "--unshare-pid".to_owned(),
            "--unshare-uts".to_owned(),
            "--unshare-cgroup".to_owned(),
        ]
    } else {
        vec!["--die-with-parent".to_owned(), "--unshare-all".to_owned()]
    }
}

fn sandbox_exec_profile(spec: &SandboxSpec, workspace: &Path) -> String {
    let mut lines = vec![
        "(version 1)".to_owned(),
        "(deny default)".to_owned(),
        "(allow process*)".to_owned(),
        "(allow sysctl-read)".to_owned(),
        "(allow file-read*)".to_owned(),
    ];
    if spec.profile.denies_secrets() {
        for path in &spec.secrets_deny {
            lines.push(format!(
                "(deny file-read* file-write* (subpath \"{}\"))",
                escape_sbpl_string(&path_string(path))
            ));
        }
    }
    if spec.profile.workspace_read_only() {
        lines.push(format!(
            "(allow file-read* (subpath \"{}\"))",
            escape_sbpl_string(&path_string(workspace))
        ));
    } else {
        lines.push(format!(
            "(allow file-write* (subpath \"{}\"))",
            escape_sbpl_string(&path_string(workspace))
        ));
    }
    if matches!(spec.profile, SandboxProfile::FullDev) {
        lines.push("(allow file-write*)".to_owned());
    }
    if spec.network_allowed() {
        lines.push("(allow network-outbound)".to_owned());
    }
    lines.join("\n")
}

fn replace_with_wrapper(plan: &mut WrappedCommand, wrapper: &str, mut wrapper_args: Vec<String>) {
    let original_program = std::mem::replace(&mut plan.program, wrapper.to_owned());
    let original_args = std::mem::take(&mut plan.args);
    wrapper_args.push(original_program);
    wrapper_args.extend(original_args);
    plan.args = wrapper_args;
}

fn apply_platform_resource_limits(spec: &SandboxSpec, plan: &mut WrappedCommand) {
    if cfg!(target_os = "linux") {
        apply_linux_resource_limits(spec, plan);
    } else if cfg!(target_os = "macos") {
        apply_macos_resource_limits(spec, plan);
    } else {
        tracing::warn!("sandbox resource limits are not implemented on this platform");
    }
}

fn apply_linux_resource_limits(spec: &SandboxSpec, plan: &mut WrappedCommand) {
    if !command_available("systemd-run") {
        tracing::warn!("systemd-run unavailable; sandbox resource limits not applied");
        return;
    }
    let original_program = std::mem::replace(&mut plan.program, "systemd-run".to_owned());
    let original_args = std::mem::take(&mut plan.args);
    let mut args = vec![
        "--user".to_owned(),
        "--scope".to_owned(),
        "--quiet".to_owned(),
    ];
    if let Some(memory_bytes) = spec.memory_bytes {
        args.push("-p".to_owned());
        args.push(format!("MemoryMax={memory_bytes}"));
    }
    if let Some(cpu_seconds) = spec.cpu_seconds {
        args.push("-p".to_owned());
        args.push(format!("RuntimeMaxSec={cpu_seconds}"));
    }
    if let Some(pids_max) = spec.pids_max {
        args.push("-p".to_owned());
        args.push(format!("TasksMax={pids_max}"));
    }
    args.push("--".to_owned());
    args.push(original_program);
    args.extend(original_args);
    plan.args = args;
}

fn apply_macos_resource_limits(spec: &SandboxSpec, plan: &mut WrappedCommand) {
    let original_program = std::mem::replace(&mut plan.program, "/bin/sh".to_owned());
    let original_args = std::mem::take(&mut plan.args);
    let mut script = String::new();
    if let Some(cpu_seconds) = spec.cpu_seconds {
        script.push_str("ulimit -t ");
        script.push_str(&cpu_seconds.to_string());
        script.push_str("; ");
    }
    if let Some(memory_bytes) = spec.memory_bytes {
        let memory_kib = memory_bytes.saturating_add(1023) / 1024;
        script.push_str("ulimit -v ");
        script.push_str(&memory_kib.to_string());
        script.push_str("; ");
    }
    script.push_str("exec \"$@\"");
    let mut args = vec!["-c".to_owned(), script, "sh".to_owned(), original_program];
    args.extend(original_args);
    plan.args = args;
    tracing::warn!(
        "macOS sandbox resource limits use inherited per-process rlimits, not cgroup-scoped limits"
    );
}

fn resolve_backend(requested: Backend, spec: &SandboxSpec) -> (Backend, bool) {
    match requested {
        Backend::Auto => auto_backend(spec),
        Backend::Native => (Backend::Native, native_backend_available(spec)),
        Backend::SandboxRuntime => (Backend::SandboxRuntime, command_available(SRT_BINARY)),
        Backend::Bubblewrap => (Backend::Bubblewrap, command_available(BWRAP_BINARY)),
        Backend::Landlock => (Backend::Landlock, command_available(LANDLOCK_BINARY)),
        Backend::SandboxExec => (Backend::SandboxExec, command_available(SANDBOX_EXEC_PATH)),
        Backend::None => (Backend::None, false),
    }
}

fn auto_backend(spec: &SandboxSpec) -> (Backend, bool) {
    #[cfg(target_os = "linux")]
    {
        if native_backend_available(spec) {
            return (Backend::Native, true);
        }
        if command_available(BWRAP_BINARY) {
            return (Backend::Bubblewrap, true);
        }
        if command_available(LANDLOCK_BINARY) {
            return (Backend::Landlock, true);
        }
        (Backend::None, false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        if command_available(SRT_BINARY) {
            return (Backend::SandboxRuntime, true);
        }
        if cfg!(target_os = "macos") && command_available(SANDBOX_EXEC_PATH) {
            return (Backend::SandboxExec, true);
        }
        let _ = spec;
        (Backend::None, false)
    }
}

fn native_backend_available(spec: &SandboxSpec) -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::native_probe_with_network_policy(!spec.network_allowed()).is_supported()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = spec;
        false
    }
}

fn command_available(command: &str) -> bool {
    let path = Path::new(command);
    if path.components().count() > 1 {
        return path.is_file();
    }
    let Some(paths) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&paths).any(|dir| dir.join(command).is_file())
}

fn default_secret_denies() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = home_dir() {
        paths.extend([
            home.join(".ssh"),
            home.join(".x0x"),
            home.join(".aws"),
            home.join(".config/gcloud"),
            home.join(".gnupg"),
            home.join("Library/Application Support/Google/Chrome"),
            home.join("Library/Application Support/Firefox"),
            home.join(".mozilla"),
            home.join(".config/google-chrome"),
            home.join(".config/chromium"),
        ]);
    }
    paths
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
}

fn expand_tilde_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        return home_dir().unwrap_or_else(|| path.to_path_buf());
    }
    if let Some(rest) = text.strip_prefix("~/") {
        return home_dir().map_or_else(|| path.to_path_buf(), |home| home.join(rest));
    }
    path.to_path_buf()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn escape_sbpl_string(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => ['\\', '\\'].into_iter().collect::<Vec<_>>(),
            '"' => ['\\', '"'].into_iter().collect::<Vec<_>>(),
            '\n' => ['\\', 'n'].into_iter().collect::<Vec<_>>(),
            other => [other].into_iter().collect::<Vec<_>>(),
        })
        .collect()
}

fn os_string_into_string(value: OsString) -> Option<String> {
    value.into_string().ok()
}

fn probe_root() -> PathBuf {
    let mut root = env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    root.push(format!("xsy-sandbox-probe-{}-{nanos}", std::process::id()));
    root
}

fn cleanup_probe_root(root: &Path) -> Result<()> {
    match std::fs::remove_dir_all(root) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::ProbeIo {
            path: root.to_path_buf(),
            source,
        }),
    }
}

enum ProbeRun {
    Blocked(String),
    Allowed(String),
    NotApplicable(String),
}

async fn run_probe_plan(
    plan: &WrappedCommand,
    base_env: &BTreeMap<String, String>,
    session: &dyn SandboxSession,
) -> ProbeRun {
    let mut merged_env = base_env.clone();
    merged_env.extend(plan.env_additions.clone());
    let mut command = Command::new(&plan.program);
    command
        .args(&plan.args)
        .current_dir(&plan.cwd)
        .env_clear()
        .envs(merged_env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ProbeRun::NotApplicable(format!("probe command not found: {error}"));
        }
        Err(error) => return ProbeRun::Blocked(format!("probe command failed to spawn: {error}")),
    };
    let Some(pid) = child.id() else {
        if let Err(error) = child.start_kill() {
            tracing::warn!(%error, "failed to kill pid-less probe child");
        }
        return ProbeRun::Blocked("probe command spawned without a child id".to_owned());
    };
    if let Err(error) = session.child_started(pid).await {
        if let Err(kill_error) = child.start_kill() {
            tracing::warn!(%kill_error, "failed to kill probe child after child-start hook error");
        }
        return ProbeRun::Blocked(format!("probe child-start hook failed: {error}"));
    }
    match tokio::time::timeout(PROBE_TIMEOUT, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            if output.status.success() {
                ProbeRun::Allowed("forbidden action succeeded".to_owned())
            } else if output.status.code() == Some(PROBE_NOT_APPLICABLE_EXIT) {
                ProbeRun::NotApplicable("probe dependency is unavailable".to_owned())
            } else {
                ProbeRun::Blocked(exit_detail(&output))
            }
        }
        Ok(Err(error)) => ProbeRun::Blocked(format!("probe command failed while waiting: {error}")),
        Err(_elapsed) => ProbeRun::Blocked("probe command timed out".to_owned()),
    }
}

fn exit_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.trim().is_empty() {
        format!("exit status {}", output.status)
    } else {
        format!("exit status {}; stderr: {}", output.status, stderr.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> CommandPlan {
        CommandPlan::new(
            "/bin/echo",
            vec!["hello".to_owned()],
            PathBuf::from("/tmp/repo"),
            BTreeMap::new(),
        )
    }

    fn spec(profile: SandboxProfile, backend: Backend) -> SandboxSpec {
        SandboxSpec {
            profile,
            backend,
            on_unavailable: UnavailablePolicy::FailClosed,
            egress_allow: vec!["api.example.test".to_owned()],
            secrets_deny: vec![PathBuf::from("/home/me/.ssh")],
            cpu_seconds: None,
            memory_bytes: None,
            pids_max: None,
        }
    }

    fn available_sandbox(spec: SandboxSpec) -> HostSandbox {
        match HostSandbox::from_resolved(spec, true) {
            Ok(sandbox) => sandbox,
            Err(error) => unreachable!("test spec is valid: {error}"),
        }
    }

    async fn prepared_command(sandbox: &HostSandbox, plan: CommandPlan) -> Result<WrappedCommand> {
        let mut session = sandbox.prepare(IssueSource::Local).await?;
        let command = session.wrap(&plan).await?;
        session.shutdown().await?;
        Ok(command)
    }

    fn assert_profile_mapping(backend: Backend, profile: SandboxProfile, plan: &WrappedCommand) {
        match backend {
            Backend::SandboxRuntime => {
                assert_eq!(plan.program, SRT_BINARY);
                assert!(plan
                    .args
                    .windows(2)
                    .any(|window| window == ["--profile", profile.as_kebab()]));
            }
            Backend::Bubblewrap => assert_bubblewrap_profile(profile, plan),
            Backend::Landlock => assert_landlock_profile(profile, plan),
            Backend::SandboxExec => assert_sandbox_exec_profile(profile, plan),
            Backend::Native | Backend::Auto | Backend::None => {
                unreachable!("matrix uses concrete backends")
            }
        }
    }

    fn assert_bubblewrap_profile(profile: SandboxProfile, plan: &WrappedCommand) {
        assert_eq!(plan.program, BWRAP_BINARY);
        let workspace_flag = if profile.workspace_read_only() {
            "--ro-bind"
        } else {
            "--bind"
        };
        assert!(plan
            .args
            .windows(3)
            .any(|window| window == [workspace_flag, "/tmp/repo", WORKSPACE_MOUNT]));
        if matches!(
            profile,
            SandboxProfile::ReadOnly | SandboxProfile::NoNetwork
        ) {
            assert!(plan.args.iter().any(|arg| arg == "--unshare-all"));
        }
        if profile.denies_secrets() {
            assert!(plan
                .args
                .windows(2)
                .any(|window| window == ["--tmpfs", "/home/me/.ssh"]));
        }
    }

    fn assert_landlock_profile(profile: SandboxProfile, plan: &WrappedCommand) {
        assert_eq!(plan.program, LANDLOCK_BINARY);
        let workspace_flag = if profile.workspace_read_only() {
            "--ro"
        } else {
            "--rw"
        };
        assert!(plan
            .args
            .windows(2)
            .any(|window| window == [workspace_flag, "/tmp/repo"]));
        if matches!(
            profile,
            SandboxProfile::ReadOnly | SandboxProfile::NoNetwork
        ) {
            assert!(plan.args.iter().any(|arg| arg == "--no-network"));
        }
        if profile.denies_secrets() {
            assert!(plan
                .args
                .windows(2)
                .any(|window| window == ["--deny", "/home/me/.ssh"]));
        }
    }

    fn assert_sandbox_exec_profile(profile: SandboxProfile, plan: &WrappedCommand) {
        assert_eq!(plan.program, SANDBOX_EXEC_PATH);
        let profile_text = plan.args.get(1).map(String::as_str).unwrap_or_default();
        if profile.workspace_read_only() {
            assert!(profile_text.contains("(allow file-read* (subpath \"/tmp/repo\"))"));
        } else {
            assert!(profile_text.contains("(allow file-write* (subpath \"/tmp/repo\"))"));
        }
        if profile.denies_secrets() {
            assert!(profile_text.contains("/home/me/.ssh"));
        }
        if matches!(
            profile,
            SandboxProfile::RepoWrite | SandboxProfile::FullDev | SandboxProfile::CiOnly
        ) {
            assert!(profile_text.contains("network-outbound"));
        }
    }

    #[tokio::test]
    async fn profiles_map_expected_flags_for_all_backends() {
        for backend in [
            Backend::SandboxRuntime,
            Backend::Bubblewrap,
            Backend::Landlock,
            Backend::SandboxExec,
        ] {
            for profile in [
                SandboxProfile::ReadOnly,
                SandboxProfile::RepoWrite,
                SandboxProfile::NoNetwork,
                SandboxProfile::FullDev,
                SandboxProfile::CiOnly,
            ] {
                let sandbox = available_sandbox(spec(profile, backend));

                let result = prepared_command(&sandbox, plan()).await;

                assert!(result.is_ok());
                if let Ok(command) = result {
                    assert_profile_mapping(backend, profile, &command);
                }
            }
        }
    }

    #[tokio::test]
    async fn bubblewrap_read_only_maps_to_read_only_workspace_and_unshare_all() {
        let sandbox =
            HostSandbox::from_resolved(spec(SandboxProfile::ReadOnly, Backend::Bubblewrap), true);
        let Ok(sandbox) = sandbox else {
            unreachable!("test spec is valid");
        };
        let result = prepared_command(&sandbox, plan()).await;

        assert!(result.is_ok());
        if let Ok(command) = result {
            assert_eq!(command.program, BWRAP_BINARY);
            assert!(command
                .args
                .windows(3)
                .any(|window| window == ["--ro-bind", "/tmp/repo", WORKSPACE_MOUNT,]));
            assert!(command.args.iter().any(|arg| arg == "--unshare-all"));
        }
    }

    #[tokio::test]
    async fn sandbox_exec_profile_contains_workspace_write_for_repo_write() {
        let sandbox =
            HostSandbox::from_resolved(spec(SandboxProfile::RepoWrite, Backend::SandboxExec), true);
        let Ok(sandbox) = sandbox else {
            unreachable!("test spec is valid");
        };
        let result = prepared_command(&sandbox, plan()).await;

        assert!(result.is_ok());
        if let Ok(command) = result {
            assert_eq!(command.program, SANDBOX_EXEC_PATH);
            let profile = command.args.get(1).map(String::as_str).unwrap_or_default();
            assert!(profile.contains("(allow file-write* (subpath \"/tmp/repo\"))"));
            assert!(profile.contains("network-outbound"));
            assert!(profile.contains("/home/me/.ssh"));
        }
    }

    #[tokio::test]
    async fn sandbox_runtime_receives_profile_and_policy_flags() {
        let sandbox =
            HostSandbox::from_resolved(spec(SandboxProfile::CiOnly, Backend::SandboxRuntime), true);
        let Ok(sandbox) = sandbox else {
            unreachable!("test spec is valid");
        };
        let result = prepared_command(&sandbox, plan()).await;

        assert!(result.is_ok());
        if let Ok(command) = result {
            assert_eq!(command.program, SRT_BINARY);
            assert!(command
                .args
                .windows(2)
                .any(|window| window == ["--profile", "ci-only"]));
            assert!(command
                .args
                .windows(2)
                .any(|window| window == ["--egress-allow", "api.example.test"]));
        }
    }

    #[tokio::test]
    async fn landlock_receives_read_write_and_network_flags() {
        let sandbox =
            HostSandbox::from_resolved(spec(SandboxProfile::NoNetwork, Backend::Landlock), true);
        let Ok(sandbox) = sandbox else {
            unreachable!("test spec is valid");
        };
        let result = prepared_command(&sandbox, plan()).await;

        assert!(result.is_ok());
        if let Ok(command) = result {
            assert_eq!(command.program, LANDLOCK_BINARY);
            assert!(command
                .args
                .windows(2)
                .any(|window| window == ["--rw", "/tmp/repo"]));
            assert!(command.args.iter().any(|arg| arg == "--no-network"));
        }
    }

    #[tokio::test]
    async fn unavailable_fail_closed_errors() {
        let sandbox =
            HostSandbox::from_resolved(spec(SandboxProfile::RepoWrite, Backend::Bubblewrap), false);
        let Ok(sandbox) = sandbox else {
            unreachable!("test spec is valid");
        };
        let result = sandbox.prepare(IssueSource::Local).await;

        assert!(matches!(result, Err(Error::SandboxUnavailable { .. })));
    }

    #[tokio::test]
    async fn unavailable_warn_leaves_plan_unwrapped() {
        let mut spec = spec(SandboxProfile::RepoWrite, Backend::Bubblewrap);
        spec.on_unavailable = UnavailablePolicy::Warn;
        let sandbox = HostSandbox::from_resolved(spec, false);
        let Ok(sandbox) = sandbox else {
            unreachable!("test spec is valid");
        };
        let original = plan();

        let result = prepared_command(&sandbox, original.clone()).await;

        assert!(result.is_ok());
        if let Ok(command) = result {
            assert_eq!(command, WrappedCommand::from(original));
        }
    }

    #[tokio::test]
    async fn network_sourced_none_prepare_fails_closed_and_local_warn_unwrapped() {
        let mut spec = spec(SandboxProfile::RepoWrite, Backend::None);
        spec.on_unavailable = UnavailablePolicy::Warn;
        let sandbox = HostSandbox::from_resolved(spec.clone(), false);
        let Ok(sandbox) = sandbox else {
            unreachable!("test spec is valid");
        };

        let network_result = sandbox.prepare(IssueSource::NetworkSourced).await;

        assert!(matches!(
            network_result,
            Err(Error::SandboxUnavailable { .. })
        ));
        let original = plan();
        let local_result = prepared_command(&sandbox, original.clone()).await;
        assert!(local_result.is_ok());
        if let Ok(command) = local_result {
            assert_eq!(command, WrappedCommand::from(original));
        }
    }

    #[tokio::test]
    async fn network_sourced_native_unavailable_refuses_local_warns() {
        let mut spec = spec(SandboxProfile::RepoWrite, Backend::Native);
        spec.on_unavailable = UnavailablePolicy::Warn;
        let sandbox = HostSandbox::from_resolved(spec, false);
        let Ok(sandbox) = sandbox else {
            unreachable!("test spec is valid");
        };

        let network_result = sandbox.prepare(IssueSource::NetworkSourced).await;

        assert!(matches!(
            network_result,
            Err(Error::SandboxUnavailable { .. })
        ));
        let original = plan();
        let local_result = prepared_command(&sandbox, original.clone()).await;
        assert!(local_result.is_ok());
        if let Ok(command) = local_result {
            assert_eq!(command, WrappedCommand::from(original));
        }
    }

    #[tokio::test]
    async fn wrap_returns_env_additions_not_complete_env() -> Result<()> {
        let sandbox = available_sandbox(spec(SandboxProfile::RepoWrite, Backend::Bubblewrap));
        let mut caller_env = BTreeMap::new();
        caller_env.insert("CALLER_ONLY".to_owned(), "visible".to_owned());
        caller_env.insert("PATH".to_owned(), "/usr/bin".to_owned());
        let plan = CommandPlan::new(
            "/bin/echo",
            vec!["hello".to_owned()],
            PathBuf::from("/tmp/repo"),
            caller_env,
        );

        let mut session = sandbox.prepare(IssueSource::Local).await?;
        let wrapped = session.wrap(&plan).await?;

        assert_eq!(wrapped.program, BWRAP_BINARY);
        assert!(wrapped.env_additions.is_empty());
        assert!(!wrapped.env_additions.contains_key("CALLER_ONLY"));
        assert!(!wrapped.env_additions.contains_key("PATH"));
        session.shutdown().await
    }

    #[tokio::test]
    async fn absent_caller_vars_do_not_leak_via_additions() -> Result<()> {
        let mut spec = spec(SandboxProfile::RepoWrite, Backend::None);
        spec.on_unavailable = UnavailablePolicy::Warn;
        let sandbox = available_sandbox(spec);
        let mut caller_env = BTreeMap::new();
        caller_env.insert("ALLOWED_BY_CALLER".to_owned(), "kept".to_owned());
        let plan = CommandPlan::new(
            "/bin/echo",
            vec!["hello".to_owned()],
            PathBuf::from("/tmp/repo"),
            caller_env,
        );

        let mut session = sandbox.prepare(IssueSource::Local).await?;
        let wrapped = session.wrap(&plan).await?;

        assert!(wrapped.env_additions.is_empty());
        assert!(!wrapped.env_additions.contains_key("ALLOWED_BY_CALLER"));
        assert!(!wrapped.env_additions.contains_key("STRIPPED_BY_CALLER"));
        session.shutdown().await
    }

    #[tokio::test]
    async fn prepare_returns_session_and_wrap_is_separate_call() -> Result<()> {
        let sandbox = available_sandbox(spec(SandboxProfile::RepoWrite, Backend::Bubblewrap));
        let mut session = sandbox.prepare(IssueSource::Local).await?;
        let plan = plan();

        let wrapped = session.wrap(&plan).await?;

        assert_eq!(wrapped.program, BWRAP_BINARY);
        assert_eq!(wrapped.cwd, plan.cwd);
        session.shutdown().await
    }

    struct DefaultHookSession;

    #[async_trait]
    impl SandboxSession for DefaultHookSession {
        async fn wrap(&self, plan: &CommandPlan) -> Result<WrappedCommand> {
            Ok(WrappedCommand::from_plan(plan))
        }

        async fn shutdown(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn child_started_default_is_noop() -> Result<()> {
        let session = DefaultHookSession;

        session.child_started(42).await
    }

    #[test]
    fn network_sourced_none_is_not_enforceable() {
        let mut spec = spec(SandboxProfile::RepoWrite, Backend::None);
        spec.on_unavailable = UnavailablePolicy::Warn;

        assert!(spec.enforceable_for(IssueSource::Local));
        assert!(!spec.enforceable_for(IssueSource::NetworkSourced));
    }
}
