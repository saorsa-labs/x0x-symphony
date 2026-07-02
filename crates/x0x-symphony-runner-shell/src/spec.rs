//! Runner specification resolved from workflow configuration.

use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use x0x_symphony_core::WorkflowDefinition;

use crate::{
    error::{Error, Result},
    preset::{self, PresetName},
    sandbox::SandboxSpec,
};

const DEFAULT_TURN_TIMEOUT_MS: u64 = 3_600_000;
const DEFAULT_EVENT_CAPACITY: usize = 256;
const DEFAULT_HIGH_WATER_MARK: usize = 192;

/// Overflow behavior for the bounded event channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOverflowPolicy {
    /// Drop the oldest queued event before enqueueing a new event.
    DropOldest,
}

/// Fully resolved child-process runner specification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunnerSpec {
    /// Executable name or path passed to `tokio::process::Command::new`.
    pub command: String,
    /// Argument vector passed unchanged to the child process.
    pub args: Vec<String>,
    /// Environment variables declared by workflow or preset configuration.
    pub env: BTreeMap<String, String>,
    /// Secret-like env names explicitly allowed despite the default deny-list.
    pub allow_secret_env: Vec<String>,
    /// Turn timeout in milliseconds.
    pub turn_timeout_ms: u64,
    /// Bounded event-channel capacity.
    pub event_capacity: usize,
    /// Queue occupancy at which WARN logs are emitted.
    pub event_high_water_mark: usize,
    /// Explicit bounded-channel overflow behavior.
    pub event_overflow_policy: EventOverflowPolicy,
    /// Host sandbox configuration; absent means intentionally unsandboxed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxSpec>,
    /// Preset name that produced this spec, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<PresetName>,
}

impl RunnerSpec {
    /// Construct a spec for an explicit command with conservative defaults.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] when `command` is empty.
    pub fn new(command: impl Into<String>) -> Result<Self> {
        let command = command.into();
        if command.trim().is_empty() {
            return Err(Error::invalid_config("runner.command", "must not be empty"));
        }
        Ok(Self {
            command,
            args: Vec::new(),
            env: BTreeMap::new(),
            allow_secret_env: Vec::new(),
            turn_timeout_ms: DEFAULT_TURN_TIMEOUT_MS,
            event_capacity: DEFAULT_EVENT_CAPACITY,
            event_high_water_mark: DEFAULT_HIGH_WATER_MARK,
            event_overflow_policy: EventOverflowPolicy::DropOldest,
            sandbox: None,
            preset: None,
        })
    }

    /// Resolve a runner spec from parsed `WORKFLOW.md` front-matter.
    ///
    /// # Errors
    ///
    /// Returns an error when the `runner:` block is missing, malformed, or does
    /// not resolve to a non-empty command.
    pub fn from_workflow_config(config: &Value) -> Result<Self> {
        let root: WorkflowConfig = serde_json::from_value(config.clone())?;
        let runner = root.runner.ok_or_else(|| Error::missing_config("runner"))?;
        runner.into_spec()
    }

    /// Resolve a runner spec from a core workflow definition.
    ///
    /// # Errors
    ///
    /// Returns an error when the workflow's front-matter config is invalid for
    /// the shell runner.
    pub fn from_workflow_definition(workflow: &WorkflowDefinition) -> Result<Self> {
        Self::from_workflow_config(&workflow.config)
    }

    /// Resolve a runner spec from YAML workflow front-matter.
    ///
    /// # Errors
    ///
    /// Returns an error when YAML parsing fails or the decoded config is
    /// invalid for the shell runner.
    pub fn from_workflow_yaml(yaml: &str) -> Result<Self> {
        let yaml_value: serde_yaml::Value = serde_yaml::from_str(yaml)?;
        let json_value = serde_json::to_value(yaml_value).map_err(Error::Decode)?;
        Self::from_workflow_config(&json_value)
    }

    /// Append one argv entry.
    #[must_use]
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Replace the argv vector.
    #[must_use]
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Declare one environment variable for the child process.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Allow one secret-like environment variable name explicitly.
    #[must_use]
    pub fn with_allowed_secret_env(mut self, key: impl Into<String>) -> Self {
        self.allow_secret_env.push(key.into());
        self
    }

    /// Override the turn timeout.
    #[must_use]
    pub const fn with_turn_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.turn_timeout_ms = timeout_ms;
        self
    }

    /// Override the event channel capacity.
    #[must_use]
    pub const fn with_event_capacity(mut self, capacity: usize) -> Self {
        self.event_capacity = capacity;
        self
    }

    /// Override the event high-water mark.
    #[must_use]
    pub const fn with_event_high_water_mark(mut self, high_water_mark: usize) -> Self {
        self.event_high_water_mark = high_water_mark;
        self
    }

    /// Configure a host sandbox for this runner.
    #[must_use]
    pub fn with_sandbox(mut self, sandbox: SandboxSpec) -> Self {
        self.sandbox = Some(sandbox);
        self
    }

    /// Return the configured timeout as a [`Duration`].
    #[must_use]
    pub const fn turn_timeout(&self) -> Duration {
        Duration::from_millis(self.turn_timeout_ms)
    }

    /// Validate self-contained configuration that does not depend on a session.
    ///
    /// # Errors
    ///
    /// Returns an error when the command, event channel sizing, or declared env
    /// values are invalid.
    pub fn validate(&self) -> Result<()> {
        validate_command(&self.command)?;
        if self.event_capacity == 0 {
            return Err(Error::invalid_config(
                "runner.event_capacity",
                "must be at least 1",
            ));
        }
        if self.event_high_water_mark == 0 || self.event_high_water_mark > self.event_capacity {
            return Err(Error::invalid_config(
                "runner.event_high_water_mark",
                "must be between 1 and event_capacity",
            ));
        }
        for arg in &self.args {
            validate_arg(arg)?;
        }
        for (key, value) in &self.env {
            crate::env::validate_env_key(key)?;
            crate::env::validate_env_value(value)?;
        }
        for key in &self.allow_secret_env {
            crate::env::validate_env_key(key)?;
        }
        if let Some(sandbox) = &self.sandbox {
            sandbox.validate()?;
        }
        crate::env::ensure_secret_env_allowed(self.env.keys(), &self.allow_secret_env)
    }
}

#[derive(Debug, Default, Deserialize)]
struct WorkflowConfig {
    runner: Option<RunnerWorkflowConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct RunnerWorkflowConfig {
    kind: Option<String>,
    preset: Option<PresetName>,
    command: Option<String>,
    args: Option<Vec<String>>,
    env: Option<BTreeMap<String, String>>,
    allow_secret_env: Option<Vec<String>>,
    turn_timeout_ms: Option<u64>,
    event_capacity: Option<usize>,
    event_high_water_mark: Option<usize>,
    sandbox: Option<SandboxSpec>,
    sandbox_args: Option<Vec<String>>,
    shell: Option<RunnerOverrides>,
    codex: Option<RunnerOverrides>,
    claude_code: Option<RunnerOverrides>,
    kimi: Option<RunnerOverrides>,
    glm: Option<RunnerOverrides>,
    minimax: Option<RunnerOverrides>,
    pi: Option<RunnerOverrides>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct RunnerOverrides {
    command: Option<String>,
    args: Option<Vec<String>>,
    env: Option<BTreeMap<String, String>>,
    allow_secret_env: Option<Vec<String>>,
    turn_timeout_ms: Option<u64>,
    event_capacity: Option<usize>,
    event_high_water_mark: Option<usize>,
    sandbox_args: Option<Vec<String>>,
}

impl RunnerWorkflowConfig {
    fn into_spec(self) -> Result<RunnerSpec> {
        let selected_preset = self.selected_preset()?;
        let mut spec = match selected_preset {
            Some(name) => preset::resolve(name)?,
            None => self.explicit_shell_spec()?,
        };

        if let Some(block) = self.overrides_for(selected_preset) {
            block.apply_to(&mut spec)?;
        }
        RunnerOverrides::from_top_level(&self).apply_to(&mut spec)?;
        if let Some(mut sandbox) = self.sandbox {
            sandbox.normalize_paths();
            sandbox.validate()?;
            spec.sandbox = Some(sandbox);
        }
        spec.preset = selected_preset;
        spec.validate()?;
        Ok(spec)
    }

    fn selected_preset(&self) -> Result<Option<PresetName>> {
        if self.preset.is_some() {
            return Ok(self.preset);
        }
        let Some(kind) = &self.kind else {
            return Ok(None);
        };
        if kind == "shell" {
            return Ok(None);
        }
        PresetName::parse(kind).map(Some)
    }

    fn explicit_shell_spec(&self) -> Result<RunnerSpec> {
        let Some(command) = self.command.clone() else {
            if let Some(shell) = &self.shell {
                if let Some(command) = shell.command.clone() {
                    return RunnerSpec::new(command);
                }
            }
            return Err(Error::missing_config("runner.command or runner.preset"));
        };
        RunnerSpec::new(command)
    }

    fn overrides_for(&self, preset: Option<PresetName>) -> Option<RunnerOverrides> {
        match preset {
            Some(PresetName::Codex) => self.codex.clone(),
            Some(PresetName::ClaudeCode) => self.claude_code.clone(),
            Some(PresetName::Kimi) => self.kimi.clone(),
            Some(PresetName::Glm) => self.glm.clone(),
            Some(PresetName::Minimax) => self.minimax.clone(),
            Some(PresetName::Pi) => self.pi.clone(),
            None => self.shell.clone(),
        }
    }
}

impl RunnerOverrides {
    fn from_top_level(config: &RunnerWorkflowConfig) -> Self {
        Self {
            command: config.command.clone(),
            args: config.args.clone(),
            env: config.env.clone(),
            allow_secret_env: config.allow_secret_env.clone(),
            turn_timeout_ms: config.turn_timeout_ms,
            event_capacity: config.event_capacity,
            event_high_water_mark: config.event_high_water_mark,
            sandbox_args: config.sandbox_args.clone(),
        }
    }

    fn apply_to(self, spec: &mut RunnerSpec) -> Result<()> {
        if let Some(command) = self.command {
            validate_command(&command)?;
            spec.command = command;
        }
        if let Some(args) = self.args {
            for arg in &args {
                validate_arg(arg)?;
            }
            spec.args = args;
        }
        if let Some(env) = self.env {
            for (key, value) in env {
                crate::env::validate_env_key(&key)?;
                crate::env::validate_env_value(&value)?;
                spec.env.insert(key, value);
            }
        }
        if let Some(allow_secret_env) = self.allow_secret_env {
            spec.allow_secret_env.extend(allow_secret_env);
        }
        if let Some(turn_timeout_ms) = self.turn_timeout_ms {
            spec.turn_timeout_ms = turn_timeout_ms;
        }
        if let Some(event_capacity) = self.event_capacity {
            spec.event_capacity = event_capacity;
        }
        if let Some(event_high_water_mark) = self.event_high_water_mark {
            spec.event_high_water_mark = event_high_water_mark;
        }
        if let Some(sandbox_args) = self.sandbox_args {
            for arg in &sandbox_args {
                validate_arg(arg)?;
            }
            let mut args = sandbox_args;
            args.extend(std::mem::take(&mut spec.args));
            spec.args = args;
        }
        Ok(())
    }
}

fn validate_command(command: &str) -> Result<()> {
    if command.trim().is_empty() {
        return Err(Error::invalid_config("runner.command", "must not be empty"));
    }
    if command.as_bytes().contains(&0) {
        return Err(Error::invalid_config(
            "runner.command",
            "must not contain NUL bytes",
        ));
    }
    Ok(())
}

pub(crate) fn validate_arg(arg: &str) -> Result<()> {
    if arg.as_bytes().contains(&0) {
        return Err(Error::invalid_config(
            "runner.args",
            "must not contain NUL bytes",
        ));
    }
    Ok(())
}
