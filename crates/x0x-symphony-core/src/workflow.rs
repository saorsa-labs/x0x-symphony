//! Workflow definition and hook configuration types.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Path to a selected `WORKFLOW.md` file.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use x0x_symphony_core::WorkflowPath;
///
/// let path = WorkflowPath::new(PathBuf::from("WORKFLOW.md"));
/// assert!(path.path.ends_with("WORKFLOW.md"));
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkflowPath {
    /// Filesystem path to the workflow file.
    pub path: PathBuf,
}

impl WorkflowPath {
    /// Construct a workflow path wrapper.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use x0x_symphony_core::WorkflowPath;
    ///
    /// let path = WorkflowPath::new(PathBuf::from("WORKFLOW.md"));
    /// assert_eq!(path.path, PathBuf::from("WORKFLOW.md"));
    /// ```
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

/// Parsed workflow file payload.
///
/// `config` is intentionally kept as JSON value in the core crate; concrete
/// loaders can project it into typed runtime settings without changing trait
/// signatures.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use x0x_symphony_core::WorkflowDefinition;
///
/// let workflow = WorkflowDefinition::new(json!({"tracker": {"kind": "git_issues"}}), "Prompt");
/// assert_eq!(workflow.prompt_template, "Prompt");
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    /// Parsed front-matter configuration.
    pub config: Value,
    /// Markdown prompt template body.
    pub prompt_template: String,
}

impl WorkflowDefinition {
    /// Construct a workflow definition.
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_json::json;
    /// use x0x_symphony_core::WorkflowDefinition;
    ///
    /// let workflow = WorkflowDefinition::new(json!({}), "Prompt");
    /// assert_eq!(workflow.config, json!({}));
    /// ```
    #[must_use]
    pub fn new(config: Value, prompt_template: impl Into<String>) -> Self {
        Self {
            config,
            prompt_template: prompt_template.into(),
        }
    }
}

/// Supported workspace hook names.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::HookName;
///
/// assert_eq!(HookName::BeforeRun.as_str(), "before_run");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookName {
    /// Runs once after a workspace is newly created.
    AfterCreate,
    /// Runs before each agent attempt.
    BeforeRun,
    /// Runs after each agent attempt.
    AfterRun,
    /// Runs before terminal workspace deletion.
    BeforeRemove,
}

impl HookName {
    /// Return the stable workflow spelling for this hook name.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::HookName;
    ///
    /// assert_eq!(HookName::AfterRun.as_str(), "after_run");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AfterCreate => "after_create",
            Self::BeforeRun => "before_run",
            Self::AfterRun => "after_run",
            Self::BeforeRemove => "before_remove",
        }
    }
}

/// Shell hook configured by a workflow.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{Hook, HookName};
///
/// let hook = Hook::new(HookName::BeforeRun, "just fmt-check", 60_000);
/// assert_eq!(hook.timeout_ms, 60_000);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Hook {
    /// Hook name.
    pub name: HookName,
    /// Shell script body.
    pub script: String,
    /// Hook timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Hook {
    /// Construct a hook configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{Hook, HookName};
    ///
    /// let hook = Hook::new(HookName::AfterCreate, "git status", 120_000);
    /// assert_eq!(hook.name, HookName::AfterCreate);
    /// ```
    #[must_use]
    pub fn new(name: HookName, script: impl Into<String>, timeout_ms: u64) -> Self {
        Self {
            name,
            script: script.into(),
            timeout_ms,
        }
    }
}

/// Owned lifecycle hook configuration used by dispatch.
///
/// Empty or absent scripts are treated as no-ops for that lifecycle point. The
/// timeout applies to every configured hook script.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{HookName, LifecycleHooks};
///
/// let hooks = LifecycleHooks::new(1_000).with_before_run("just fmt-check");
/// assert_eq!(hooks.hook(HookName::BeforeRun).map(|hook| hook.timeout_ms), Some(1_000));
/// assert!(hooks.hook(HookName::AfterRun).is_none());
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LifecycleHooks {
    /// Timeout applied to each hook script, in milliseconds.
    pub timeout_ms: u32,
    /// Script configured for `after_create`; `None` or empty means no-op.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_create: Option<String>,
    /// Script configured for `before_run`; `None` or empty means no-op.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_run: Option<String>,
    /// Script configured for `after_run`; `None` or empty means no-op.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_run: Option<String>,
    /// Script configured for `before_remove`; `None` or empty means no-op.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_remove: Option<String>,
}

impl Default for LifecycleHooks {
    fn default() -> Self {
        Self {
            timeout_ms: 60_000,
            after_create: None,
            before_run: None,
            after_run: None,
            before_remove: None,
        }
    }
}

impl LifecycleHooks {
    /// Construct hook configuration with no scripts and the given timeout.
    #[must_use]
    pub fn new(timeout_ms: u32) -> Self {
        Self {
            timeout_ms,
            ..Self::default()
        }
    }

    /// Return a copy with an `after_create` script.
    #[must_use]
    pub fn with_after_create(mut self, script: impl Into<String>) -> Self {
        self.after_create = Some(script.into());
        self
    }

    /// Return a copy with a `before_run` script.
    #[must_use]
    pub fn with_before_run(mut self, script: impl Into<String>) -> Self {
        self.before_run = Some(script.into());
        self
    }

    /// Return a copy with an `after_run` script.
    #[must_use]
    pub fn with_after_run(mut self, script: impl Into<String>) -> Self {
        self.after_run = Some(script.into());
        self
    }

    /// Return a copy with a `before_remove` script.
    #[must_use]
    pub fn with_before_remove(mut self, script: impl Into<String>) -> Self {
        self.before_remove = Some(script.into());
        self
    }

    /// Build a concrete hook for `name`, or `None` when that point is disabled.
    #[must_use]
    pub fn hook(&self, name: HookName) -> Option<Hook> {
        let script = match name {
            HookName::AfterCreate => self.after_create.as_deref(),
            HookName::BeforeRun => self.before_run.as_deref(),
            HookName::AfterRun => self.after_run.as_deref(),
            HookName::BeforeRemove => self.before_remove.as_deref(),
        }?;
        if script.trim().is_empty() {
            return None;
        }
        Some(Hook::new(
            name,
            script.to_owned(),
            u64::from(self.timeout_ms),
        ))
    }
}
