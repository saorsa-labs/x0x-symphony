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
