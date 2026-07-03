//! Linux native launcher and cgroup-v2 session support.

use std::{
    collections::BTreeMap,
    env,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::{fs::DirBuilderExt, net::UnixStream as StdUnixStream, process::CommandExt},
    path::{Component, Path, PathBuf},
    process::Command as StdCommand,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use landlock::{
    Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, net::UnixListener, sync::Mutex, time::timeout};

use crate::{
    Backend, CommandPlan, Error, ProbeCheck, ProbeReport, ProbeStatus, Result, SandboxProfile,
    SandboxSession, SandboxSpec, WrappedCommand,
};

const LAUNCHER_SENTINEL: &str = "--__saorsa-sandbox-launcher";
const LAUNCHER_SOCKET_FLAG: &str = "--socket";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const PROC_SELF_CGROUP: &str = "/proc/self/cgroup";
const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(5);
const CPU_PERIOD_MICROS: u64 = 100_000;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// Serialized launcher configuration sent after cgroup attachment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LauncherConfig {
    /// Absolute target executable path.
    pub program: PathBuf,
    /// Target argument vector.
    pub args: Vec<String>,
    /// Target working directory.
    pub cwd: PathBuf,
    /// Exact target environment after the runner allow-list has been applied.
    pub env: BTreeMap<String, String>,
    /// Paths granted read and execute access.
    pub read_only_paths: Vec<PathBuf>,
    /// Paths granted read, write, and execute access.
    pub read_write_paths: Vec<PathBuf>,
    /// Whether TCP bind/connect rights are denied by default.
    pub deny_network: bool,
}

impl LauncherConfig {
    /// Serialize this config for the socket protocol.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn to_json_vec(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|source| Error::Protocol {
            message: format!("failed to encode launcher config: {source}"),
        })
    }

    /// Deserialize this config from the socket protocol.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON decoding fails.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|source| Error::Protocol {
            message: format!("failed to decode launcher config: {source}"),
        })
    }

    fn from_plan(plan: &CommandPlan, spec: &SandboxSpec) -> Result<Self> {
        let cwd = canonicalize_existing(&plan.cwd, "runner.cwd")?;
        let program = resolve_target_executable(&plan.program, &cwd, &plan.env)?;
        let mut read_only_paths = system_read_exec_paths();
        push_unique_path(&mut read_only_paths, program.clone());
        let mut read_write_paths = Vec::new();
        if spec.profile.workspace_read_only() {
            push_unique_path(&mut read_only_paths, cwd.clone());
        } else {
            push_unique_path(&mut read_write_paths, cwd.clone());
        }
        Ok(Self {
            program,
            args: plan.args.clone(),
            cwd,
            env: plan.env.clone(),
            read_only_paths,
            read_write_paths,
            deny_network: !spec.network_allowed(),
        })
    }
}

/// Linux native probe result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProbe {
    /// Whether Landlock file rules can be created with ABI v1 rights.
    pub landlock_supported: bool,
    /// Landlock diagnostic detail.
    pub landlock_detail: String,
    /// Whether the current cgroup-v2 parent is delegated for leaf creation.
    pub cgroup_supported: bool,
    /// Cgroup diagnostic detail.
    pub cgroup_detail: String,
}

impl NativeProbe {
    /// Return true when both Landlock and cgroup-v2 are available.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        self.landlock_supported && self.cgroup_supported
    }
}

/// Probe Linux native backend support.
#[must_use]
pub fn native_probe() -> NativeProbe {
    native_probe_with_network_policy(false)
}

/// Probe Linux native backend support for a specific network policy.
#[must_use]
pub fn native_probe_with_network_policy(deny_network: bool) -> NativeProbe {
    let (landlock_supported, landlock_detail) = probe_landlock(deny_network);
    let (cgroup_supported, cgroup_detail) = probe_cgroup_delegation();
    NativeProbe {
        landlock_supported,
        landlock_detail,
        cgroup_supported,
        cgroup_detail,
    }
}

/// Build a report for the native backend probe.
#[must_use]
pub fn native_probe_report(profile: SandboxProfile) -> ProbeReport {
    let probe = native_probe();
    ProbeReport {
        backend: Backend::Native,
        profile,
        checks: vec![
            ProbeCheck {
                name: "landlock-abi".to_owned(),
                status: pass_if(probe.landlock_supported),
                detail: probe.landlock_detail,
            },
            ProbeCheck {
                name: "cgroup-v2-delegation".to_owned(),
                status: pass_if(probe.cgroup_supported),
                detail: probe.cgroup_detail,
            },
        ],
    }
}

/// Return whether the argv vector requests hidden launcher mode.
#[must_use]
pub fn is_launcher_invocation(argv: &[OsString]) -> bool {
    argv.get(1)
        .is_some_and(|arg| arg.as_os_str() == OsStr::new(LAUNCHER_SENTINEL))
}

/// Run the hidden launcher mode.
///
/// # Errors
///
/// Returns an error when argv parsing, socket I/O, Landlock setup, or exec fails.
pub fn launcher_main<I>(argv: I) -> Result<()>
where
    I: IntoIterator<Item = OsString>,
{
    let socket_path = parse_launcher_socket(argv)?;
    let mut stream = StdUnixStream::connect(&socket_path)
        .map_err(|source| Error::sandbox_io(socket_path.clone(), source))?;
    let mut payload = Vec::new();
    stream
        .read_to_end(&mut payload)
        .map_err(|source| Error::sandbox_io(socket_path.clone(), source))?;
    let config = LauncherConfig::from_json_slice(&payload)?;
    apply_landlock(&config)?;
    exec_target(config)
}

/// Per-command Linux native session.
#[derive(Debug)]
pub struct LinuxSandboxSession {
    spec: SandboxSpec,
    temp_dir: PathBuf,
    socket_path: PathBuf,
    listener: Mutex<Option<UnixListener>>,
    cgroup: CgroupLeaf,
    config: Mutex<Option<LauncherConfig>>,
}

impl LinuxSandboxSession {
    /// Prepare a Linux native sandbox session.
    ///
    /// # Errors
    ///
    /// Returns an error if the private socket, cgroup leaf, or configured limits cannot be created.
    pub fn prepare(spec: SandboxSpec) -> Result<Self> {
        let temp_dir = create_private_temp_dir()?;
        let socket_path = temp_dir.join("launcher.sock");
        let std_listener = std::os::unix::net::UnixListener::bind(&socket_path)
            .map_err(|source| Error::sandbox_io(socket_path.clone(), source))?;
        std_listener
            .set_nonblocking(true)
            .map_err(|source| Error::sandbox_io(socket_path.clone(), source))?;
        let listener = UnixListener::from_std(std_listener)
            .map_err(|source| Error::sandbox_io(socket_path.clone(), source))?;
        let cgroup = match CgroupLeaf::create(&spec) {
            Ok(cgroup) => cgroup,
            Err(error) => {
                cleanup_temp_dir(&temp_dir);
                return Err(error);
            }
        };
        Ok(Self {
            spec,
            temp_dir,
            socket_path,
            listener: Mutex::new(Some(listener)),
            cgroup,
            config: Mutex::new(None),
        })
    }

    async fn take_listener(&self) -> Result<UnixListener> {
        self.listener
            .lock()
            .await
            .take()
            .ok_or_else(|| Error::protocol("launcher listener was already consumed"))
    }
}

#[async_trait]
impl SandboxSession for LinuxSandboxSession {
    async fn wrap(&self, plan: &CommandPlan) -> Result<WrappedCommand> {
        let config = LauncherConfig::from_plan(plan, &self.spec)?;
        *self.config.lock().await = Some(config);
        launcher_wrapped_command(&self.socket_path, &plan.cwd)
    }

    async fn child_started(&self, pid: u32) -> Result<()> {
        if let Err(error) = self.cgroup.attach(pid) {
            let _closed = self.listener.lock().await.take();
            return Err(error);
        }
        let config = self
            .config
            .lock()
            .await
            .take()
            .ok_or_else(|| Error::protocol("launcher config was not prepared before spawn"))?;
        let payload = config.to_json_vec()?;
        let listener = self.take_listener().await?;
        let (mut stream, _addr) = timeout(PROTOCOL_TIMEOUT, listener.accept())
            .await
            .map_err(|_elapsed| Error::protocol("timed out waiting for launcher socket"))?
            .map_err(|source| Error::sandbox_io(self.socket_path.clone(), source))?;
        stream
            .write_all(&payload)
            .await
            .map_err(|source| Error::sandbox_io(self.socket_path.clone(), source))?;
        stream
            .shutdown()
            .await
            .map_err(|source| Error::sandbox_io(self.socket_path.clone(), source))
    }

    async fn shutdown(&mut self) -> Result<()> {
        let _closed = self.listener.lock().await.take();
        remove_file_if_exists(&self.socket_path);
        self.cgroup.delete_best_effort();
        cleanup_temp_dir(&self.temp_dir);
        Ok(())
    }
}

#[derive(Debug)]
struct CgroupLeaf {
    path: PathBuf,
}

impl CgroupLeaf {
    fn create(spec: &SandboxSpec) -> Result<Self> {
        let parent = current_cgroup_parent()?;
        let path = parent.join(unique_leaf_name());
        fs::create_dir(&path).map_err(|source| cgroup_error(&path, &source))?;
        let leaf = Self { path };
        if let Err(error) = leaf.apply_limits(spec) {
            leaf.delete_best_effort();
            return Err(error);
        }
        Ok(leaf)
    }

    fn apply_limits(&self, spec: &SandboxSpec) -> Result<()> {
        if let Some(pids_max) = spec.pids_max {
            write_cgroup_file(&self.path.join("pids.max"), &pids_max.to_string())?;
        }
        if let Some(memory_bytes) = spec.memory_bytes {
            write_cgroup_file(&self.path.join("memory.max"), &memory_bytes.to_string())?;
        }
        if let Some(cpu_seconds) = spec.cpu_seconds {
            let quota = cpu_seconds.saturating_mul(CPU_PERIOD_MICROS);
            write_cgroup_file(
                &self.path.join("cpu.max"),
                &format!("{quota} {CPU_PERIOD_MICROS}"),
            )?;
        }
        Ok(())
    }

    fn attach(&self, pid: u32) -> Result<()> {
        write_cgroup_file(&self.path.join("cgroup.procs"), &pid.to_string())
    }

    fn delete_best_effort(&self) {
        match fs::remove_dir(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(path = %self.path.display(), %error, "failed to remove cgroup leaf");
            }
        }
    }
}

/// Derive the cgroup-v2 parent path from `/proc/self/cgroup` content.
///
/// # Errors
///
/// Returns an error when the v2 line is absent or contains unsupported path components.
pub fn derive_cgroup_parent_from_content(root: &Path, content: &str) -> Result<PathBuf> {
    let line = content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| Error::protocol("/proc/self/cgroup does not contain a cgroup-v2 entry"))?;
    let mut path = root.to_path_buf();
    for component in Path::new(line).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => path.push(part),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(Error::protocol(
                    "cgroup path contains unsupported components",
                ));
            }
        }
    }
    Ok(path)
}

fn launcher_wrapped_command(socket_path: &Path, cwd: &Path) -> Result<WrappedCommand> {
    let launcher = env::current_exe()
        .map_err(|source| Error::sandbox_io(PathBuf::from("current_exe"), source))?;
    Ok(WrappedCommand {
        program: os_path_to_string(&launcher, "current_exe")?,
        args: vec![
            LAUNCHER_SENTINEL.to_owned(),
            LAUNCHER_SOCKET_FLAG.to_owned(),
            os_path_to_string(socket_path, "launcher.socket")?,
        ],
        cwd: cwd.to_path_buf(),
        env_additions: BTreeMap::new(),
    })
}

fn parse_launcher_socket<I>(argv: I) -> Result<PathBuf>
where
    I: IntoIterator<Item = OsString>,
{
    let argv_vec = argv.into_iter().collect::<Vec<_>>();
    if !is_launcher_invocation(&argv_vec) {
        return Err(Error::protocol("missing launcher sentinel"));
    }
    match (argv_vec.get(2), argv_vec.get(3), argv_vec.get(4)) {
        (Some(flag), Some(path), None) if flag.as_os_str() == OsStr::new(LAUNCHER_SOCKET_FLAG) => {
            Ok(PathBuf::from(path))
        }
        _ => Err(Error::protocol(
            "expected launcher argv: sentinel --socket <path>",
        )),
    }
}

fn apply_landlock(config: &LauncherConfig) -> Result<()> {
    let abi = ABI::V1;
    let read_access = AccessFs::from_read(abi);
    let write_access = AccessFs::from_all(abi);
    let mut builder = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(write_access)
        .map_err(landlock_error)?;
    if config.deny_network {
        builder = builder
            .handle_access(AccessNet::from_all(ABI::V4))
            .map_err(landlock_error)?;
    }
    let mut ruleset = builder.create().map_err(landlock_error)?;
    for path in &config.read_only_paths {
        ruleset = ruleset
            .add_rule(PathBeneath::new(path_fd(path)?, read_access))
            .map_err(landlock_error)?;
    }
    for path in &config.read_write_paths {
        ruleset = ruleset
            .add_rule(PathBeneath::new(path_fd(path)?, write_access))
            .map_err(landlock_error)?;
    }
    let status = ruleset.restrict_self().map_err(landlock_error)?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(Error::landlock("ruleset was not enforced"));
    }
    Ok(())
}

fn exec_target(config: LauncherConfig) -> Result<()> {
    let mut command = StdCommand::new(&config.program);
    command
        .args(config.args)
        .current_dir(config.cwd)
        .env_clear()
        .envs(config.env);
    Err(Error::Exec {
        source: command.exec(),
    })
}

fn probe_landlock(deny_network: bool) -> (bool, String) {
    let mut result = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1));
    if deny_network {
        result = result.and_then(|ruleset| ruleset.handle_access(AccessNet::from_all(ABI::V4)));
    }
    match result.and_then(Ruleset::create) {
        Ok(_ruleset) if deny_network => (
            true,
            "Landlock ABI v1 file rules and ABI v4 TCP rules are available".to_owned(),
        ),
        Ok(_ruleset) => (true, "Landlock ABI v1 file rules are available".to_owned()),
        Err(error) => (false, format!("Landlock probe failed: {error}")),
    }
}

fn probe_cgroup_delegation() -> (bool, String) {
    let root = Path::new(CGROUP_ROOT);
    let controllers = root.join("cgroup.controllers");
    if !controllers.is_file() {
        return (
            false,
            format!("{} is not a cgroup-v2 mount", root.display()),
        );
    }
    match probe_cgroup_leaf(root) {
        Ok(()) => (
            true,
            "cgroup-v2 leaf creation and write probe succeeded".to_owned(),
        ),
        Err(error) => (false, format!("cgroup-v2 delegation probe failed: {error}")),
    }
}

fn probe_cgroup_leaf(root: &Path) -> Result<()> {
    let content = fs::read_to_string(PROC_SELF_CGROUP)
        .map_err(|source| cgroup_error(Path::new(PROC_SELF_CGROUP), &source))?;
    let parent = derive_cgroup_parent_from_content(root, &content)?;
    let path = parent.join(unique_leaf_name());
    fs::create_dir(&path).map_err(|source| cgroup_error(&path, &source))?;
    let procs = path.join("cgroup.procs");
    let open_result = OpenOptions::new().write(true).open(&procs);
    let remove_result = fs::remove_dir(&path);
    if let Err(source) = remove_result {
        tracing::warn!(path = %path.display(), %source, "failed to remove cgroup probe leaf");
    }
    open_result
        .map(|_file| ())
        .map_err(|source| cgroup_error(&procs, &source))
}

fn current_cgroup_parent() -> Result<PathBuf> {
    let content = fs::read_to_string(PROC_SELF_CGROUP)
        .map_err(|source| cgroup_error(Path::new(PROC_SELF_CGROUP), &source))?;
    derive_cgroup_parent_from_content(Path::new(CGROUP_ROOT), &content)
}

fn write_cgroup_file(path: &Path, value: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|source| cgroup_error(path, &source))?;
    file.write_all(value.as_bytes())
        .map_err(|source| cgroup_error(path, &source))
}

fn cgroup_error(path: &Path, source: &io::Error) -> Error {
    Error::SandboxUnavailable {
        backend: Backend::Native.as_str().to_owned(),
        message: format!("cgroup-v2 operation at {} failed: {source}", path.display()),
    }
}

fn create_private_temp_dir() -> Result<PathBuf> {
    let base = env::temp_dir();
    for _attempt in 0..16 {
        let path = base.join(unique_temp_name());
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(Error::sandbox_io(path, source)),
        }
    }
    Err(Error::protocol(
        "failed to allocate a private launcher temp dir",
    ))
}

fn unique_temp_name() -> String {
    let nonce = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    format!("xsy-native-{}-{}-{nonce}", std::process::id(), now_nanos())
}

fn unique_leaf_name() -> String {
    let nonce = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    format!("symphony-{}-{}-{nonce}", std::process::id(), now_nanos())
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn cleanup_temp_dir(path: &Path) {
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "failed to remove launcher temp dir");
        }
    }
}

fn remove_file_if_exists(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "failed to remove launcher socket");
        }
    }
}

fn pass_if(value: bool) -> ProbeStatus {
    if value {
        ProbeStatus::Pass
    } else {
        ProbeStatus::Fail
    }
}

fn system_read_exec_paths() -> Vec<PathBuf> {
    [
        "/bin",
        "/usr/bin",
        "/usr/local/bin",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/dev/null",
        "/dev/zero",
        "/dev/urandom",
    ]
    .into_iter()
    .filter_map(existing_canonical_path)
    .fold(Vec::new(), |mut paths, path| {
        push_unique_path(&mut paths, path);
        paths
    })
}

fn resolve_target_executable(
    program: &str,
    cwd: &Path,
    target_env: &BTreeMap<String, String>,
) -> Result<PathBuf> {
    let candidate = Path::new(program);
    if candidate.components().count() > 1 {
        let path = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            cwd.join(candidate)
        };
        return canonicalize_existing(&path, "runner.command");
    }
    let path_value = target_env
        .get("PATH")
        .cloned()
        .or_else(|| env::var("PATH").ok())
        .ok_or_else(|| {
            Error::invalid_config("runner.command", "PATH is required for bare commands")
        })?;
    env::split_paths(OsStr::new(&path_value))
        .find_map(|dir| {
            let candidate = dir.join(program);
            existing_canonical_path(candidate)
        })
        .ok_or_else(|| {
            Error::invalid_config(
                "runner.command",
                format!("could not resolve target executable {program:?} from PATH"),
            )
        })
}

fn canonicalize_existing(path: &Path, field: &'static str) -> Result<PathBuf> {
    fs::canonicalize(path).map_err(|source| Error::InvalidConfig {
        field,
        message: format!("{} is not accessible: {source}", path.display()),
    })
}

fn existing_canonical_path(path: impl AsRef<Path>) -> Option<PathBuf> {
    fs::canonicalize(path).ok()
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

fn path_fd(path: &Path) -> Result<PathFd> {
    PathFd::new(path).map_err(landlock_error)
}

fn landlock_error(error: impl std::fmt::Display) -> Error {
    Error::landlock(error.to_string())
}

fn os_path_to_string(path: &Path, field: &'static str) -> Result<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::invalid_config(field, "path must be valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_config_json_round_trips() -> Result<()> {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_owned(), "/usr/bin".to_owned());
        let config = LauncherConfig {
            program: PathBuf::from("/bin/echo"),
            args: vec!["hello".to_owned()],
            cwd: PathBuf::from("/tmp/workspace"),
            env,
            read_only_paths: vec![PathBuf::from("/bin")],
            read_write_paths: vec![PathBuf::from("/tmp/workspace")],
            deny_network: true,
        };

        let encoded = config.to_json_vec()?;
        let decoded = LauncherConfig::from_json_slice(&encoded)?;

        assert_eq!(decoded, config);
        Ok(())
    }

    #[test]
    fn derives_cgroup_parent_from_proc_sample() -> Result<()> {
        let root = Path::new("/sys/fs/cgroup");
        let sample = "0::/user.slice/user-501.slice/session.scope\n";

        let derived = derive_cgroup_parent_from_content(root, sample)?;

        assert_eq!(
            derived,
            PathBuf::from("/sys/fs/cgroup/user.slice/user-501.slice/session.scope")
        );
        Ok(())
    }

    #[test]
    fn root_cgroup_maps_to_cgroup_mount() -> Result<()> {
        let derived = derive_cgroup_parent_from_content(Path::new("/sys/fs/cgroup"), "0::/\n")?;

        assert_eq!(derived, PathBuf::from("/sys/fs/cgroup"));
        Ok(())
    }

    #[test]
    fn launcher_invocation_uses_current_exe_and_private_sentinel() -> Result<()> {
        let socket = PathBuf::from("/tmp/socket");
        let cwd = PathBuf::from("/tmp/workspace");

        let wrapped = launcher_wrapped_command(&socket, &cwd)?;

        let current_exe = env::current_exe()
            .map_err(|source| Error::sandbox_io(PathBuf::from("current_exe"), source))?;
        assert_eq!(PathBuf::from(&wrapped.program), current_exe);
        assert_eq!(
            wrapped.args,
            vec![
                LAUNCHER_SENTINEL.to_owned(),
                LAUNCHER_SOCKET_FLAG.to_owned(),
                "/tmp/socket".to_owned(),
            ]
        );
        assert_eq!(wrapped.cwd, cwd);
        assert!(wrapped.env_additions.is_empty());
        Ok(())
    }
}
