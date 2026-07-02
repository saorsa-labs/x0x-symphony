//! `WORKFLOW.md` frontmatter parsing and validation.

use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::{Map, Value};
use thiserror::Error;
use x0x_symphony_core::{
    shard, AgentId, IssueState, LifecycleHooks, SymphonyError, WorkflowDefinition,
};
use x0x_symphony_orchestrator::{Config as OrchestratorConfig, RetryPolicy};
use x0x_symphony_runner_shell::RunnerSpec;
use x0x_symphony_tracker_git_jsonl::signing::SigningPolicy;

/// Result alias for workflow configuration operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors raised while loading or validating workflow configuration.
#[derive(Debug, Error)]
pub enum Error {
    /// The workflow file could not be read.
    #[error("failed to read workflow file {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The markdown document did not contain YAML frontmatter delimited by `---`.
    #[error("WORKFLOW.md must start with YAML frontmatter delimited by ---")]
    MissingFrontmatter,
    /// The YAML frontmatter could not be decoded.
    #[error("invalid workflow YAML: {source}")]
    Yaml {
        /// Underlying YAML decoder error.
        #[source]
        source: serde_yaml::Error,
    },
    /// The parsed YAML could not be converted to JSON values.
    #[error("failed to normalize workflow config: {source}")]
    Json {
        /// Underlying JSON conversion or formatting error.
        #[source]
        source: serde_json::Error,
    },
    /// Required keys were missing or invalid.
    #[error("workflow config validation failed")]
    Invalid {
        /// One-line validation problems suitable for `config check` output.
        problems: Vec<String>,
    },
    /// A path using `~` could not be expanded.
    #[error("cannot expand ~ in {field}: no home directory is available")]
    NoHomeDirectory {
        /// Config field being expanded.
        field: &'static str,
    },
    /// A core domain type rejected a configured value.
    #[error(transparent)]
    Core(#[from] SymphonyError),
}

/// Fully validated workflow configuration used by daemon startup.
#[derive(Clone, Debug)]
pub struct WorkflowConfig {
    /// Core workflow definition: raw JSON config plus prompt template body.
    pub definition: WorkflowDefinition,
    /// Tracker settings.
    pub tracker: TrackerConfig,
    /// Polling settings.
    pub polling: PollingConfig,
    /// Workspace settings.
    pub workspace: WorkspaceConfig,
    /// Lifecycle hook settings.
    pub hooks: HooksConfig,
    /// Agent and orchestrator settings.
    pub agent: AgentConfig,
    /// Signing settings for claim and handoff payloads.
    pub signing: SigningConfig,
    /// Static M2 sharding placeholder settings.
    pub sharding: ShardingConfig,
    /// Raw runner block used by `RunnerSpec`.
    pub runner: Value,
}

/// Tracker configuration parsed from the `tracker:` block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackerConfig {
    /// Tracker kind. M1 accepts only `git_issues`.
    pub kind: String,
    /// Path to the JSONL issue database, relative to the workflow file when not absolute.
    pub path: PathBuf,
    /// Active states configured for dispatch.
    pub active_states: Vec<String>,
    /// Terminal states used for blocker resolution.
    pub terminal_states: Vec<String>,
}

/// Poll-loop configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollingConfig {
    /// Poll interval in milliseconds.
    pub interval_ms: u64,
}

/// Workspace configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceConfig {
    /// Expanded workspace root path.
    pub root: PathBuf,
}

/// Lifecycle hook configuration parsed from the workflow file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HooksConfig {
    /// Hook timeout in milliseconds.
    pub timeout_ms: u32,
    /// Script configured for `after_create`; absent or empty means no-op.
    pub after_create: Option<String>,
    /// Script configured for `before_run`; absent or empty means no-op.
    pub before_run: Option<String>,
    /// Script configured for `after_run`; absent or empty means no-op.
    pub after_run: Option<String>,
    /// Script configured for `before_remove`; absent or empty means no-op.
    pub before_remove: Option<String>,
}

impl HooksConfig {
    /// Convert bin-level workflow hooks into core dispatch hook settings.
    #[must_use]
    pub fn to_lifecycle_hooks(&self) -> LifecycleHooks {
        LifecycleHooks {
            timeout_ms: self.timeout_ms,
            after_create: self.after_create.clone(),
            before_run: self.before_run.clone(),
            after_run: self.after_run.clone(),
            before_remove: self.before_remove.clone(),
        }
    }
}

/// Agent and orchestrator configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentConfig {
    /// Global maximum number of concurrent agents.
    pub max_concurrent_agents: usize,
    /// Per-state concurrency caps.
    pub max_concurrent_agents_by_state: BTreeMap<String, usize>,
    /// Maximum turns/attempts before retry exhaustion.
    pub max_turns: u32,
    /// Maximum retry backoff in milliseconds.
    pub max_retry_backoff_ms: u64,
}

/// Signing configuration parsed from the optional `signing:` block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningConfig {
    /// Signing policy for local JSONL claim/handoff records.
    pub policy: SigningPolicy,
    /// x0xd base URL used for `/agent/sign` and `/agent/verify`.
    pub x0xd_url: String,
}

/// Static M2 sharding configuration parsed from the optional `sharding:` block.
///
/// This is deliberately a placeholder. M2 reads a static `workers:` list from
/// `WORKFLOW.md` only so issue creation can freeze shard slates now; M4 replaces
/// this with live x0x presence-based trusted-worker discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardingConfig {
    /// Static trusted-worker roster used for XOR-distance shard assignment.
    pub workers: Vec<AgentId>,
    /// Total shard owner count: one primary plus `replication_factor - 1` backups.
    pub replication_factor: usize,
}

/// Resolved tracker filesystem paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackerPaths {
    /// Repository root passed to the JSONL tracker.
    pub repo_root: PathBuf,
    /// JSONL file path read by API list/status endpoints.
    pub issues_path: PathBuf,
}

impl WorkflowConfig {
    /// Load and validate a workflow file from disk.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] when the file cannot be read, parsed, or validated.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_markdown(&content)
    }

    /// Parse and validate a workflow markdown document.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] when frontmatter is missing, malformed, or invalid.
    pub fn from_markdown(content: &str) -> Result<Self> {
        let (yaml, prompt) = split_frontmatter(content)?;
        let yaml_value = serde_yaml::from_str::<serde_yaml::Value>(yaml)
            .map_err(|source| Error::Yaml { source })?;
        let raw = serde_json::to_value(yaml_value).map_err(|source| Error::Json { source })?;
        Self::from_raw(raw, prompt.to_owned())
    }

    /// Build a workflow config from already-normalized JSON and a prompt body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] when required keys are missing or invalid.
    pub fn from_raw(raw: Value, prompt_template: String) -> Result<Self> {
        let mut problems = Vec::new();
        let Some(root) = raw.as_object() else {
            return Err(Error::Invalid {
                problems: vec!["workflow frontmatter must be a mapping".to_owned()],
            });
        };

        let tracker = parse_tracker(root, &mut problems);
        let polling = parse_polling(root, &mut problems);
        let workspace = parse_workspace(root, &mut problems);
        let hooks = parse_hooks(root, &mut problems);
        let agent = parse_agent(root, &mut problems);
        let signing = parse_signing(root, &mut problems);
        let sharding = parse_sharding(root, &mut problems);
        let runner = parse_runner(root, &raw, &mut problems);

        if problems.is_empty() {
            if let Err(error) = RunnerSpec::from_workflow_config(&raw) {
                problems.push(format!("runner block does not resolve: {error}"));
            }
        }

        if !problems.is_empty() {
            return Err(Error::Invalid { problems });
        }

        let definition = WorkflowDefinition::new(raw, prompt_template);
        Ok(Self {
            definition,
            tracker: tracker.ok_or_else(internal_validation_gap)?,
            polling: polling.ok_or_else(internal_validation_gap)?,
            workspace: workspace.ok_or_else(internal_validation_gap)?,
            hooks: hooks.ok_or_else(internal_validation_gap)?,
            agent: agent.ok_or_else(internal_validation_gap)?,
            signing: signing.ok_or_else(internal_validation_gap)?,
            sharding: sharding.ok_or_else(internal_validation_gap)?,
            runner: runner.ok_or_else(internal_validation_gap)?,
        })
    }

    /// Pretty-print the normalized frontmatter as deterministic JSON.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Json`] if serialization fails.
    pub fn pretty_config_json(&self) -> Result<String> {
        let sorted = sort_json_value(&self.definition.config);
        serde_json::to_string_pretty(&sorted).map_err(|source| Error::Json { source })
    }

    /// Resolve the configured tracker paths relative to the workflow file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] when a relative tracker path has no parent.
    pub fn tracker_paths(&self, workflow_path: &Path) -> Result<TrackerPaths> {
        let base = match workflow_path.parent() {
            Some(parent) => parent,
            None => Path::new("."),
        };
        let issues_path = absolutize_against(base, &self.tracker.path);
        let repo_root = repo_root_from_issues_path(&issues_path)?;
        Ok(TrackerPaths {
            repo_root,
            issues_path,
        })
    }

    /// Convert validated config into orchestrator configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Core`] if a configured state or agent id is invalid.
    pub fn to_orchestrator_config(&self, agent_id: AgentId) -> Result<OrchestratorConfig> {
        let active_states = states_from_strings(&self.tracker.active_states)?;
        let terminal_states = states_from_strings(&self.tracker.terminal_states)?;
        let per_state = self
            .agent
            .max_concurrent_agents_by_state
            .iter()
            .map(|(state, cap)| Ok((IssueState::new(state.clone())?, *cap)))
            .collect::<std::result::Result<BTreeMap<_, _>, SymphonyError>>()?;
        let retry = RetryPolicy::new(
            Duration::from_secs(5),
            Duration::from_millis(self.agent.max_retry_backoff_ms),
            self.agent.max_turns,
        );
        Ok(OrchestratorConfig::builder(agent_id)
            .active_states(active_states)
            .terminal_states(terminal_states)
            .polling_interval(Duration::from_millis(self.polling.interval_ms))
            .global_concurrency(self.agent.max_concurrent_agents)
            .per_state_concurrency(per_state)
            .retry(retry)
            .hooks(self.hooks.to_lifecycle_hooks())
            .build())
    }
}

/// Expand a path that may start with `~` using the current user's home directory.
///
/// # Errors
///
/// Returns [`Error::NoHomeDirectory`] when `~` expansion is requested and no
/// home directory environment variable is available.
pub fn expand_tilde_path(input: &str, field: &'static str) -> Result<PathBuf> {
    if input == "~" {
        return home_dir().ok_or(Error::NoHomeDirectory { field });
    }
    if let Some(rest) = input.strip_prefix("~/") {
        let home = home_dir().ok_or(Error::NoHomeDirectory { field })?;
        return Ok(home.join(rest));
    }
    Ok(PathBuf::from(input))
}

fn split_frontmatter(content: &str) -> Result<(&str, &str)> {
    let Some(after_open) = content.strip_prefix("---\n") else {
        return Err(Error::MissingFrontmatter);
    };
    let Some((yaml, body)) = after_open.split_once("\n---\n") else {
        return Err(Error::MissingFrontmatter);
    };
    Ok((yaml, body))
}

fn parse_tracker(root: &Map<String, Value>, problems: &mut Vec<String>) -> Option<TrackerConfig> {
    let tracker = required_object(root, "tracker", problems)?;
    let kind = required_string(tracker, "tracker.kind", problems);
    if let Some(value) = &kind {
        if value != "git_issues" {
            problems.push("tracker.kind must be `git_issues` for M1".to_owned());
        }
    }
    let path = required_string(tracker, "tracker.path", problems).map(PathBuf::from);
    let active_states = match optional_string_list(tracker, "tracker.active_states") {
        Some(states) => states,
        None => vec!["todo".to_owned()],
    };
    let terminal_states = match optional_string_list(tracker, "tracker.terminal_states") {
        Some(states) => states,
        None => vec![
            "done".to_owned(),
            "cancelled".to_owned(),
            "duplicate".to_owned(),
        ],
    };
    Some(TrackerConfig {
        kind: kind?,
        path: path?,
        active_states,
        terminal_states,
    })
}

fn parse_polling(root: &Map<String, Value>, problems: &mut Vec<String>) -> Option<PollingConfig> {
    let polling = required_object(root, "polling", problems)?;
    let interval_ms = required_u64(polling, "polling.interval_ms", problems, 1)?;
    Some(PollingConfig { interval_ms })
}

fn parse_workspace(
    root: &Map<String, Value>,
    problems: &mut Vec<String>,
) -> Option<WorkspaceConfig> {
    let workspace = required_object(root, "workspace", problems)?;
    let root_value = required_string(workspace, "workspace.root", problems)?;
    let root = match expand_tilde_path(&root_value, "workspace.root") {
        Ok(path) => path,
        Err(error) => {
            problems.push(error.to_string());
            return None;
        }
    };
    Some(WorkspaceConfig { root })
}

fn parse_hooks(root: &Map<String, Value>, problems: &mut Vec<String>) -> Option<HooksConfig> {
    let hooks = required_object(root, "hooks", problems)?;
    let timeout_ms = required_u32(hooks, "hooks.timeout_ms", problems, 1)?;
    Some(HooksConfig {
        timeout_ms,
        after_create: optional_string(hooks, "hooks.after_create", problems),
        before_run: optional_string(hooks, "hooks.before_run", problems),
        after_run: optional_string(hooks, "hooks.after_run", problems),
        before_remove: optional_string(hooks, "hooks.before_remove", problems),
    })
}

fn parse_agent(root: &Map<String, Value>, problems: &mut Vec<String>) -> Option<AgentConfig> {
    let agent = required_object(root, "agent", problems)?;
    let max_concurrent_agents = required_usize(agent, "agent.max_concurrent_agents", problems, 1)?;
    let max_concurrent_agents_by_state =
        required_usize_map(agent, "agent.max_concurrent_agents_by_state", problems, 1)?;
    let max_turns = required_u32(agent, "agent.max_turns", problems, 1)?;
    let max_retry_backoff_ms = required_u64(agent, "agent.max_retry_backoff_ms", problems, 1)?;
    Some(AgentConfig {
        max_concurrent_agents,
        max_concurrent_agents_by_state,
        max_turns,
        max_retry_backoff_ms,
    })
}

fn parse_signing(root: &Map<String, Value>, problems: &mut Vec<String>) -> Option<SigningConfig> {
    let Some(value) = root.get("signing") else {
        return Some(SigningConfig {
            policy: SigningPolicy::Disabled,
            x0xd_url: "http://127.0.0.1:12700".to_owned(),
        });
    };
    let Some(signing) = value.as_object() else {
        problems.push("signing must be a mapping".to_owned());
        return None;
    };
    let policy = match optional_string(signing, "signing.policy", problems) {
        Some(raw) => {
            if let Some(policy) = SigningPolicy::from_config_value(&raw) {
                policy
            } else {
                problems.push("signing.policy must be `disabled` or `required`".to_owned());
                return None;
            }
        }
        None => SigningPolicy::Disabled,
    };
    let x0xd_url = match optional_string(signing, "signing.x0xd_url", problems) {
        Some(url) if !url.trim().is_empty() => url,
        Some(_) => {
            problems.push("signing.x0xd_url must not be empty".to_owned());
            return None;
        }
        None => "http://127.0.0.1:12700".to_owned(),
    };
    Some(SigningConfig { policy, x0xd_url })
}

fn parse_sharding(root: &Map<String, Value>, problems: &mut Vec<String>) -> Option<ShardingConfig> {
    let Some(value) = root.get("sharding") else {
        return Some(ShardingConfig {
            workers: Vec::new(),
            replication_factor: shard::DEFAULT_REPLICATION_FACTOR,
        });
    };
    let Some(sharding) = value.as_object() else {
        problems.push("sharding must be a mapping".to_owned());
        return None;
    };
    let workers = optional_agent_list(sharding, "sharding.workers", problems)?;
    let replication_factor = optional_usize(sharding, "sharding.replication_factor", problems, 1)
        .unwrap_or(shard::DEFAULT_REPLICATION_FACTOR);
    Some(ShardingConfig {
        workers,
        replication_factor,
    })
}

fn parse_runner(
    root: &Map<String, Value>,
    raw: &Value,
    problems: &mut Vec<String>,
) -> Option<Value> {
    let runner = required_object(root, "runner", problems)?;
    let kind = required_string(runner, "runner.kind", problems);
    if let Some(value) = &kind {
        if value != "shell" {
            problems.push("runner.kind must be `shell` for M1".to_owned());
        }
    }
    let _ = kind?;
    raw.get("runner").cloned()
}

fn required_object<'a>(
    root: &'a Map<String, Value>,
    key: &'static str,
    problems: &mut Vec<String>,
) -> Option<&'a Map<String, Value>> {
    match root.get(key) {
        Some(Value::Object(map)) => Some(map),
        Some(_) => {
            problems.push(format!("{key} must be a mapping"));
            None
        }
        None => {
            problems.push(format!("missing required key `{key}`"));
            None
        }
    }
}

fn required_string(
    map: &Map<String, Value>,
    path: &'static str,
    problems: &mut Vec<String>,
) -> Option<String> {
    let key = leaf_key(path);
    match map.get(key) {
        Some(Value::String(value)) if !value.trim().is_empty() => Some(value.clone()),
        Some(Value::String(_)) => {
            problems.push(format!("{path} must not be empty"));
            None
        }
        Some(_) => {
            problems.push(format!("{path} must be a string"));
            None
        }
        None => {
            problems.push(format!("missing required key `{path}`"));
            None
        }
    }
}

fn optional_string(
    map: &Map<String, Value>,
    path: &'static str,
    problems: &mut Vec<String>,
) -> Option<String> {
    let key = leaf_key(path);
    match map.get(key) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => {
            problems.push(format!("{path} must be a string"));
            None
        }
        None => None,
    }
}

fn required_u64(
    map: &Map<String, Value>,
    path: &'static str,
    problems: &mut Vec<String>,
    min: u64,
) -> Option<u64> {
    let key = leaf_key(path);
    match map.get(key).and_then(Value::as_u64) {
        Some(value) if value >= min => Some(value),
        Some(_) => {
            problems.push(format!("{path} must be >= {min}"));
            None
        }
        None if map.contains_key(key) => {
            problems.push(format!("{path} must be an unsigned integer"));
            None
        }
        None => {
            problems.push(format!("missing required key `{path}`"));
            None
        }
    }
}

fn required_u32(
    map: &Map<String, Value>,
    path: &'static str,
    problems: &mut Vec<String>,
    min: u32,
) -> Option<u32> {
    let value = required_u64(map, path, problems, u64::from(min))?;
    if let Ok(converted) = u32::try_from(value) {
        Some(converted)
    } else {
        problems.push(format!("{path} must fit in u32"));
        None
    }
}

fn required_usize(
    map: &Map<String, Value>,
    path: &'static str,
    problems: &mut Vec<String>,
    min: u64,
) -> Option<usize> {
    let value = required_u64(map, path, problems, min)?;
    if let Ok(converted) = usize::try_from(value) {
        Some(converted)
    } else {
        problems.push(format!("{path} must fit in usize"));
        None
    }
}

fn required_usize_map(
    map: &Map<String, Value>,
    path: &'static str,
    problems: &mut Vec<String>,
    min: u64,
) -> Option<BTreeMap<String, usize>> {
    let key = leaf_key(path);
    let Some(value) = map.get(key) else {
        problems.push(format!("missing required key `{path}`"));
        return None;
    };
    let Some(object) = value.as_object() else {
        problems.push(format!("{path} must be a mapping"));
        return None;
    };
    let mut result = BTreeMap::new();
    for (entry_key, entry_value) in object {
        if entry_key.trim().is_empty() {
            problems.push(format!("{path} keys must not be empty"));
            continue;
        }
        if let Some(raw) = entry_value.as_u64() {
            if raw < min {
                problems.push(format!("{path}.{entry_key} must be >= {min}"));
            } else if let Ok(value) = usize::try_from(raw) {
                result.insert(entry_key.clone(), value);
            } else {
                problems.push(format!("{path}.{entry_key} must fit in usize"));
            }
        } else {
            problems.push(format!("{path}.{entry_key} must be an unsigned integer"));
        }
    }
    Some(result)
}

fn optional_string_list(map: &Map<String, Value>, path: &'static str) -> Option<Vec<String>> {
    let key = leaf_key(path);
    let Some(Value::Array(values)) = map.get(key) else {
        return None;
    };
    let strings = values
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if strings.is_empty() {
        None
    } else {
        Some(strings)
    }
}

fn optional_agent_list(
    map: &Map<String, Value>,
    path: &'static str,
    problems: &mut Vec<String>,
) -> Option<Vec<AgentId>> {
    let key = leaf_key(path);
    let Some(value) = map.get(key) else {
        return Some(Vec::new());
    };
    let Some(values) = value.as_array() else {
        problems.push(format!("{path} must be a list of agent id strings"));
        return None;
    };
    let mut agents = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(raw) = value.as_str() else {
            problems.push(format!("{path}[{index}] must be a string"));
            continue;
        };
        match AgentId::new(raw.to_owned()) {
            Ok(agent) => agents.push(agent),
            Err(error) => problems.push(format!("{path}[{index}] {error}")),
        }
    }
    Some(agents)
}

fn optional_usize(
    map: &Map<String, Value>,
    path: &'static str,
    problems: &mut Vec<String>,
    min: u64,
) -> Option<usize> {
    let key = leaf_key(path);
    match map.get(key).and_then(Value::as_u64) {
        Some(value) if value >= min => {
            if let Ok(converted) = usize::try_from(value) {
                Some(converted)
            } else {
                problems.push(format!("{path} must fit in usize"));
                None
            }
        }
        Some(_) => {
            problems.push(format!("{path} must be >= {min}"));
            None
        }
        None if map.contains_key(key) => {
            problems.push(format!("{path} must be an unsigned integer"));
            None
        }
        None => None,
    }
}

fn leaf_key(path: &str) -> &str {
    path.rsplit_once('.').map_or(path, |(_, leaf)| leaf)
}

fn internal_validation_gap() -> Error {
    Error::Invalid {
        problems: vec!["internal validation gap while building workflow config".to_owned()],
    }
}

fn states_from_strings(values: &[String]) -> std::result::Result<Vec<IssueState>, SymphonyError> {
    values
        .iter()
        .map(|value| IssueState::new(value.clone()))
        .collect()
}

fn absolutize_against(base: &Path, value: &Path) -> PathBuf {
    if value.is_absolute() {
        value.to_path_buf()
    } else {
        base.join(value)
    }
}

fn repo_root_from_issues_path(path: &Path) -> Result<PathBuf> {
    let Some(parent) = path.parent() else {
        return Err(Error::Invalid {
            problems: vec!["tracker.path must have a parent directory".to_owned()],
        });
    };
    if parent.file_name().and_then(|name| name.to_str()) == Some("issues") {
        if let Some(root) = parent.parent() {
            return Ok(root.to_path_buf());
        }
    }
    Ok(parent.to_path_buf())
}

fn sort_json_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(sort_json_value).collect()),
        Value::Object(map) => {
            let mut sorted = Map::new();
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            for key in keys {
                if let Some(child) = map.get(key) {
                    sorted.insert(key.clone(), sort_json_value(child));
                }
            }
            Value::Object(sorted)
        }
        other => other.clone(),
    }
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
}
