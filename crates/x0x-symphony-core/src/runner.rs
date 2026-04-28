//! Runner trait and session event types.

use std::{collections::BTreeMap, path::PathBuf, pin::Pin};

use async_trait::async_trait;
use futures_core::Stream;
use serde::{Deserialize, Serialize};

use crate::{Issue, Result};

/// Stream of structured runner events.
///
/// # Examples
///
/// ```
/// use futures_util::stream;
/// use x0x_symphony_core::{EventStream, RunnerEvent};
///
/// let events: EventStream = Box::pin(stream::empty::<RunnerEvent>());
/// drop(events);
/// ```
pub type EventStream = Pin<Box<dyn Stream<Item = RunnerEvent> + Send>>;

/// Stable runner session identifier.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::SessionId;
///
/// let id = SessionId::new("session-1");
/// assert_eq!(id.as_str(), "session-1");
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// Construct a session identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::SessionId;
    ///
    /// let id = SessionId::new("session-1");
    /// assert_eq!(id.as_str(), "session-1");
    /// ```
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the identifier as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::SessionId;
    ///
    /// let id = SessionId::new("session-1");
    /// assert_eq!(id.as_str(), "session-1");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Prompt text passed to one runner turn.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::Prompt;
///
/// let prompt = Prompt::new("Implement XSY-0002");
/// assert_eq!(prompt.as_str(), "Implement XSY-0002");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Prompt(String);

impl Prompt {
    /// Construct prompt text.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::Prompt;
    ///
    /// let prompt = Prompt::new("work");
    /// assert_eq!(prompt.as_str(), "work");
    /// ```
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow prompt text.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::Prompt;
    ///
    /// let prompt = Prompt::new("work");
    /// assert_eq!(prompt.as_str(), "work");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Capabilities advertised by a runner implementation.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::RunnerCapabilities;
///
/// let caps = RunnerCapabilities::new("shell").with_label("rust");
/// assert_eq!(caps.runner_kind, "shell");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunnerCapabilities {
    /// Runner kind, such as `shell` or `codex`.
    pub runner_kind: String,
    /// Capability labels matched against issue requirements.
    pub labels: Vec<String>,
    /// Whether the runner can produce structured events.
    pub structured_events: bool,
}

impl RunnerCapabilities {
    /// Construct a capability set for a runner kind.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::RunnerCapabilities;
    ///
    /// let caps = RunnerCapabilities::new("shell");
    /// assert!(!caps.structured_events);
    /// ```
    #[must_use]
    pub fn new(runner_kind: impl Into<String>) -> Self {
        Self {
            runner_kind: runner_kind.into(),
            labels: Vec::new(),
            structured_events: false,
        }
    }

    /// Return a copy with a capability label appended.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::RunnerCapabilities;
    ///
    /// let caps = RunnerCapabilities::new("shell").with_label("rust");
    /// assert_eq!(caps.labels, ["rust"]);
    /// ```
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.labels.push(label.into());
        self
    }

    /// Return a copy marked as structured-event capable.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::RunnerCapabilities;
    ///
    /// let caps = RunnerCapabilities::new("codex").with_structured_events();
    /// assert!(caps.structured_events);
    /// ```
    #[must_use]
    pub fn with_structured_events(mut self) -> Self {
        self.structured_events = true;
        self
    }
}

/// Context supplied when a runner session starts.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use x0x_symphony_core::{Issue, IssueId, IssueState, SessionContext};
///
/// let issue = Issue::new(IssueId::new("XSY-0002")?, "XSY-0002", "Title", IssueState::new("todo")?, "now")?;
/// let ctx = SessionContext::new(issue, PathBuf::from("/tmp/work"));
/// assert!(ctx.env_allowlist.is_empty());
/// # Ok::<(), x0x_symphony_core::SymphonyError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionContext {
    /// Issue being worked on.
    pub issue: Issue,
    /// Workspace path where the runner must execute.
    pub workspace_path: PathBuf,
    /// Environment variables explicitly allowed for the runner.
    pub env_allowlist: BTreeMap<String, String>,
}

impl SessionContext {
    /// Construct session context with an empty environment allow-list.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use x0x_symphony_core::{Issue, IssueId, IssueState, SessionContext};
    ///
    /// let issue = Issue::new(IssueId::new("XSY-0002")?, "XSY-0002", "Title", IssueState::new("todo")?, "now")?;
    /// let ctx = SessionContext::new(issue, PathBuf::from("/tmp/work"));
    /// assert_eq!(ctx.workspace_path, PathBuf::from("/tmp/work"));
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    #[must_use]
    pub fn new(issue: Issue, workspace_path: PathBuf) -> Self {
        Self {
            issue,
            workspace_path,
            env_allowlist: BTreeMap::new(),
        }
    }

    /// Return a copy with one environment variable allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use x0x_symphony_core::{Issue, IssueId, IssueState, SessionContext};
    ///
    /// let issue = Issue::new(IssueId::new("XSY-0002")?, "XSY-0002", "Title", IssueState::new("todo")?, "now")?;
    /// let ctx = SessionContext::new(issue, PathBuf::from("/tmp/work")).with_env("RUST_LOG", "info");
    /// assert_eq!(ctx.env_allowlist.get("RUST_LOG").map(String::as_str), Some("info"));
    /// # Ok::<(), x0x_symphony_core::SymphonyError>(())
    /// ```
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_allowlist.insert(key.into(), value.into());
        self
    }
}

/// Opaque handle returned by a started runner session.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use x0x_symphony_core::{SessionHandle, SessionId};
///
/// let handle = SessionHandle::new(SessionId::new("session-1"), PathBuf::from("/tmp/work"), "now");
/// assert_eq!(handle.id.as_str(), "session-1");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionHandle {
    /// Session identifier.
    pub id: SessionId,
    /// Workspace path used by the session.
    pub workspace_path: PathBuf,
    /// Session start timestamp as ISO-8601 UTC text.
    pub started_at: String,
}

impl SessionHandle {
    /// Construct a session handle.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use x0x_symphony_core::{SessionHandle, SessionId};
    ///
    /// let handle = SessionHandle::new(SessionId::new("session-1"), PathBuf::from("/tmp/work"), "now");
    /// assert_eq!(handle.started_at, "now");
    /// ```
    #[must_use]
    pub fn new(id: SessionId, workspace_path: PathBuf, started_at: impl Into<String>) -> Self {
        Self {
            id,
            workspace_path,
            started_at: started_at.into(),
        }
    }
}

/// Runner turn status.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::TurnStatus;
///
/// assert!(TurnStatus::Succeeded.is_terminal_success());
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnStatus {
    /// Turn completed successfully.
    Succeeded,
    /// Turn failed with a runner error.
    Failed,
    /// Turn timed out.
    TimedOut,
    /// Turn was cancelled.
    Cancelled,
}

impl TurnStatus {
    /// Return true for successful terminal turns.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::TurnStatus;
    ///
    /// assert!(TurnStatus::Succeeded.is_terminal_success());
    /// assert!(!TurnStatus::Failed.is_terminal_success());
    /// ```
    #[must_use]
    pub const fn is_terminal_success(&self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

/// Resource usage reported by a runner.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::UsageReport;
///
/// let usage = UsageReport::new().with_duration_ms(42);
/// assert_eq!(usage.duration_ms, Some(42));
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsageReport {
    /// Input tokens when the harness reports them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    /// Output tokens when the harness reports them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    /// Total tokens when the harness reports them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    /// Runner duration in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

impl UsageReport {
    /// Construct an empty usage report.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::UsageReport;
    ///
    /// let usage = UsageReport::new();
    /// assert!(usage.total_tokens.is_none());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a copy with duration populated.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::UsageReport;
    ///
    /// let usage = UsageReport::new().with_duration_ms(10);
    /// assert_eq!(usage.duration_ms, Some(10));
    /// ```
    #[must_use]
    pub fn with_duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }
}

/// Result of one runner turn.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{TurnOutcome, TurnStatus, UsageReport};
///
/// let outcome = TurnOutcome::new(TurnStatus::Succeeded, UsageReport::new());
/// assert!(outcome.status.is_terminal_success());
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TurnOutcome {
    /// Terminal status for the turn.
    pub status: TurnStatus,
    /// Optional human-readable summary produced by the harness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Usage reported by the harness.
    pub usage: UsageReport,
}

impl TurnOutcome {
    /// Construct a turn outcome without a summary.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{TurnOutcome, TurnStatus, UsageReport};
    ///
    /// let outcome = TurnOutcome::new(TurnStatus::Succeeded, UsageReport::new());
    /// assert!(outcome.summary.is_none());
    /// ```
    #[must_use]
    pub fn new(status: TurnStatus, usage: UsageReport) -> Self {
        Self {
            status,
            summary: None,
            usage,
        }
    }

    /// Return a copy with a summary attached.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{TurnOutcome, TurnStatus, UsageReport};
    ///
    /// let outcome = TurnOutcome::new(TurnStatus::Succeeded, UsageReport::new()).with_summary("done");
    /// assert_eq!(outcome.summary.as_deref(), Some("done"));
    /// ```
    #[must_use]
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }
}

/// Runner event category.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::RunnerEventKind;
///
/// assert_eq!(RunnerEventKind::Stdout.as_str(), "stdout");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerEventKind {
    /// Session started.
    SessionStarted,
    /// A stdout chunk was observed.
    Stdout,
    /// A stderr chunk was observed.
    Stderr,
    /// Turn completed.
    TurnCompleted,
    /// Runner emitted an artefact path.
    Artifact,
    /// Runner reported an error.
    Error,
}

impl RunnerEventKind {
    /// Return the stable JSON spelling for this event kind.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::RunnerEventKind;
    ///
    /// assert_eq!(RunnerEventKind::Error.as_str(), "error");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SessionStarted => "session_started",
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::TurnCompleted => "turn_completed",
            Self::Artifact => "artifact",
            Self::Error => "error",
        }
    }
}

/// Structured event emitted by a runner.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{RunnerEvent, RunnerEventKind};
///
/// let event = RunnerEvent::new(RunnerEventKind::Stdout).with_message("hello");
/// assert_eq!(event.message.as_deref(), Some("hello"));
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunnerEvent {
    /// Event category.
    pub kind: RunnerEventKind,
    /// Optional event message or chunk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Event timestamp as ISO-8601 UTC text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

impl RunnerEvent {
    /// Construct an event without message or timestamp.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{RunnerEvent, RunnerEventKind};
    ///
    /// let event = RunnerEvent::new(RunnerEventKind::SessionStarted);
    /// assert_eq!(event.kind, RunnerEventKind::SessionStarted);
    /// ```
    #[must_use]
    pub fn new(kind: RunnerEventKind) -> Self {
        Self {
            kind,
            message: None,
            at: None,
        }
    }

    /// Return a copy with a message.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{RunnerEvent, RunnerEventKind};
    ///
    /// let event = RunnerEvent::new(RunnerEventKind::Stdout).with_message("chunk");
    /// assert_eq!(event.message.as_deref(), Some("chunk"));
    /// ```
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Return a copy with a timestamp.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{RunnerEvent, RunnerEventKind};
    ///
    /// let event = RunnerEvent::new(RunnerEventKind::Stdout).with_timestamp("now");
    /// assert_eq!(event.at.as_deref(), Some("now"));
    /// ```
    #[must_use]
    pub fn with_timestamp(mut self, at: impl Into<String>) -> Self {
        self.at = Some(at.into());
        self
    }
}

/// Harness abstraction used by the orchestrator.
///
/// `shell` is the canonical M1 implementation; other harnesses are presets or
/// adapters over this trait.
///
/// # Examples
///
/// ```no_run
/// use async_trait::async_trait;
/// use futures_util::stream;
/// use x0x_symphony_core::{EventStream, Prompt, Result, Runner, RunnerCapabilities, RunnerEvent, SessionContext, SessionHandle, SessionId, TurnOutcome, TurnStatus, UsageReport};
///
/// struct StubRunner;
///
/// #[async_trait]
/// impl Runner for StubRunner {
///     fn name(&self) -> &'static str { "stub" }
///     fn capabilities(&self) -> &RunnerCapabilities {
///         static CAPS: std::sync::OnceLock<RunnerCapabilities> = std::sync::OnceLock::new();
///         CAPS.get_or_init(|| RunnerCapabilities::new("stub"))
///     }
///     async fn start_session(&self, ctx: SessionContext) -> Result<SessionHandle> {
///         Ok(SessionHandle::new(SessionId::new("s1"), ctx.workspace_path, "now"))
///     }
///     async fn run_turn(&self, _sess: &mut SessionHandle, _prompt: Prompt) -> Result<TurnOutcome> {
///         Ok(TurnOutcome::new(TurnStatus::Succeeded, UsageReport::new()))
///     }
///     fn stream_events(&self, _sess: &SessionHandle) -> EventStream {
///         Box::pin(stream::empty::<RunnerEvent>())
///     }
///     async fn stop_session(&self, _sess: SessionHandle) -> Result<UsageReport> {
///         Ok(UsageReport::new())
///     }
/// }
/// ```
#[async_trait]
pub trait Runner: Send + Sync {
    /// Stable runner name for logging and configuration.
    fn name(&self) -> &'static str;

    /// Capabilities advertised by this runner.
    fn capabilities(&self) -> &RunnerCapabilities;

    /// Start a session inside the supplied workspace context.
    async fn start_session(&self, ctx: SessionContext) -> Result<SessionHandle>;

    /// Run one prompt turn in an existing session.
    async fn run_turn(&self, sess: &mut SessionHandle, prompt: Prompt) -> Result<TurnOutcome>;

    /// Stream best-effort events for an existing session.
    fn stream_events(&self, sess: &SessionHandle) -> EventStream;

    /// Stop a session and return final usage.
    async fn stop_session(&self, sess: SessionHandle) -> Result<UsageReport>;
}
