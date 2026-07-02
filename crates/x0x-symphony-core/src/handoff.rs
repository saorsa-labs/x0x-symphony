//! Handoff and validation result types.

use serde::{Deserialize, Serialize};

use crate::{IssueId, SignatureEnvelope};

/// Status for a validation command recorded in a handoff.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::ValidationStatus;
///
/// assert_eq!(ValidationStatus::Passed.as_str(), "passed");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    /// Command completed successfully.
    Passed,
    /// Command completed with a failing exit status.
    Failed,
    /// Command was intentionally skipped with a recorded reason.
    Skipped,
}

impl ValidationStatus {
    /// Return the stable JSON spelling for this status.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::ValidationStatus;
    ///
    /// assert_eq!(ValidationStatus::Failed.as_str(), "failed");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

/// Result of one validation command.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{ValidationResult, ValidationStatus};
///
/// let result = ValidationResult::new("just test", ValidationStatus::Passed).with_exit_code(0);
/// assert_eq!(result.exit_code, Some(0));
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Command or check that ran.
    pub command: String,
    /// Command status.
    pub status: ValidationStatus,
    /// Process exit code when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl ValidationResult {
    /// Construct a validation result without an exit code.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{ValidationResult, ValidationStatus};
    ///
    /// let result = ValidationResult::new("just lint", ValidationStatus::Passed);
    /// assert_eq!(result.command, "just lint");
    /// ```
    #[must_use]
    pub fn new(command: impl Into<String>, status: ValidationStatus) -> Self {
        Self {
            command: command.into(),
            status,
            exit_code: None,
        }
    }

    /// Return a copy of this validation result with an exit code attached.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{ValidationResult, ValidationStatus};
    ///
    /// let result = ValidationResult::new("just doc", ValidationStatus::Passed).with_exit_code(0);
    /// assert_eq!(result.exit_code, Some(0));
    /// ```
    #[must_use]
    pub fn with_exit_code(mut self, exit_code: i32) -> Self {
        self.exit_code = Some(exit_code);
        self
    }
}

/// Review handoff written after useful agent work completes.
///
/// # Examples
///
/// ```
/// use x0x_symphony_core::{Handoff, ValidationResult, ValidationStatus};
///
/// let handoff = Handoff::new("Implemented core traits")
///     .with_file("crates/x0x-symphony-core/src/lib.rs")
///     .with_validation(ValidationResult::new("just check", ValidationStatus::Passed));
/// assert_eq!(handoff.files_changed.len(), 1);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Handoff {
    /// Human-readable summary of what changed and why.
    pub summary: String,
    /// Relative paths changed by the work.
    pub files_changed: Vec<String>,
    /// Validation results captured before handoff.
    pub validation: Vec<ValidationResult>,
    /// Follow-up notes for humans or later agents.
    pub follow_up: Vec<String>,
    /// Optional relative path to large proof artefacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proofs_dir: Option<String>,
    /// Issue this signed handoff belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_id: Option<IssueId>,
    /// x0x agent id that must match the signature envelope signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_agent_id: Option<String>,
    /// Signature envelope over the handoff payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureEnvelope>,
}

impl Handoff {
    /// Construct a handoff with empty file, validation, and follow-up lists.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::Handoff;
    ///
    /// let handoff = Handoff::new("Ready for review");
    /// assert!(handoff.validation.is_empty());
    /// ```
    #[must_use]
    pub fn new(summary: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            files_changed: Vec::new(),
            validation: Vec::new(),
            follow_up: Vec::new(),
            proofs_dir: None,
            issue_id: None,
            signer_agent_id: None,
            signature: None,
        }
    }

    /// Return a copy with one changed file appended.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::Handoff;
    ///
    /// let handoff = Handoff::new("Ready").with_file("README.md");
    /// assert_eq!(handoff.files_changed, ["README.md"]);
    /// ```
    #[must_use]
    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.files_changed.push(file.into());
        self
    }

    /// Return a copy with multiple changed files appended.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::Handoff;
    ///
    /// let handoff = Handoff::new("Ready")
    ///     .with_files_changed(["README.md", "Cargo.toml"]);
    /// assert_eq!(handoff.files_changed, ["README.md", "Cargo.toml"]);
    /// ```
    #[must_use]
    pub fn with_files_changed<I, S>(mut self, files: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.files_changed.extend(files.into_iter().map(Into::into));
        self
    }

    /// Return a copy with one validation result appended.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::{Handoff, ValidationResult, ValidationStatus};
    ///
    /// let handoff = Handoff::new("Ready")
    ///     .with_validation(ValidationResult::new("just test", ValidationStatus::Passed));
    /// assert_eq!(handoff.validation.len(), 1);
    /// ```
    #[must_use]
    pub fn with_validation(mut self, validation: ValidationResult) -> Self {
        self.validation.push(validation);
        self
    }

    /// Return a copy with one follow-up note appended.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::Handoff;
    ///
    /// let handoff = Handoff::new("Ready").with_follow_up("Review API names");
    /// assert_eq!(handoff.follow_up.len(), 1);
    /// ```
    #[must_use]
    pub fn with_follow_up(mut self, note: impl Into<String>) -> Self {
        self.follow_up.push(note.into());
        self
    }

    /// Return a copy with multiple follow-up notes appended.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::Handoff;
    ///
    /// let handoff = Handoff::new("Ready")
    ///     .with_follow_ups(["Review API names", "Update docs"]);
    /// assert_eq!(handoff.follow_up.len(), 2);
    /// ```
    #[must_use]
    pub fn with_follow_ups<I, S>(mut self, notes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.follow_up.extend(notes.into_iter().map(Into::into));
        self
    }

    /// Return a copy with a proofs directory reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use x0x_symphony_core::Handoff;
    ///
    /// let handoff = Handoff::new("Ready").with_proofs_dir("proofs/XSY-0002/run");
    /// assert_eq!(handoff.proofs_dir.as_deref(), Some("proofs/XSY-0002/run"));
    /// ```
    #[must_use]
    pub fn with_proofs_dir(mut self, proofs_dir: impl Into<String>) -> Self {
        self.proofs_dir = Some(proofs_dir.into());
        self
    }

    /// Return a copy bound to an issue id for signing.
    #[must_use]
    pub fn with_issue_id(mut self, issue_id: IssueId) -> Self {
        self.issue_id = Some(issue_id);
        self
    }

    /// Return a copy bound to the x0x signer id for signing.
    #[must_use]
    pub fn with_signer_agent_id(mut self, signer_agent_id: impl Into<String>) -> Self {
        self.signer_agent_id = Some(signer_agent_id.into());
        self
    }
}
