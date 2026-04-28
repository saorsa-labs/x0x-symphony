//! Error types shared by all x0x-symphony core traits.

use thiserror::Error;

/// Convenient result alias for x0x-symphony library APIs.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{IssueId, Result};
///
/// fn parse_issue_id(raw: &str) -> Result<IssueId> {
///     IssueId::new(raw)
/// }
/// # Ok::<(), x0x_symphony_core::SymphonyError>(())
/// ```
pub type Result<T> = std::result::Result<T, SymphonyError>;

/// Structured error values produced by core traits and domain validation.
///
/// Adapters should map their concrete failures into one of these categories
/// before crossing the core trait boundary.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::SymphonyError;
///
/// let err = SymphonyError::validation("issue.identifier", "must not be empty");
/// assert_eq!(err.to_string(), "invalid issue.identifier: must not be empty");
/// ```
#[derive(Debug, Error)]
pub enum SymphonyError {
    /// A domain value failed validation.
    #[error("invalid {field}: {message}")]
    Validation {
        /// Field or value path that failed validation.
        field: &'static str,
        /// Human-readable reason.
        message: String,
    },

    /// Tracker adapter failure.
    #[error("tracker error: {0}")]
    Tracker(String),

    /// Runner adapter failure.
    #[error("runner error: {0}")]
    Runner(String),

    /// Workspace manager failure.
    #[error("workspace error: {0}")]
    Workspace(String),

    /// Workflow loading or rendering failure.
    #[error("workflow error: {0}")]
    Workflow(String),

    /// I/O failure surfaced by an adapter or workspace implementation.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON serialization or deserialization failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl SymphonyError {
    /// Build a validation error for a named field.
    ///
    /// # Errors
    ///
    /// This constructor does not fail; it returns a value that can be used as
    /// the error side of [`Result`].
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::SymphonyError;
    ///
    /// let err = SymphonyError::validation("agent_id", "must be configured");
    /// assert!(matches!(err, SymphonyError::Validation { .. }));
    /// ```
    #[must_use]
    pub fn validation(field: &'static str, message: impl Into<String>) -> Self {
        Self::Validation {
            field,
            message: message.into(),
        }
    }
}
