//! Error types for the shell runner crate.

use std::io;

use thiserror::Error;
use x0x_symphony_core::SymphonyError;

/// Result alias for shell-runner operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Structured failures produced by the shell runner.
#[derive(Debug, Error)]
pub enum Error {
    /// Required workflow configuration is absent.
    #[error("missing runner config: {field}")]
    MissingConfig {
        /// Missing configuration field.
        field: &'static str,
    },

    /// Workflow configuration is present but invalid.
    #[error("invalid runner config {field}: {message}")]
    InvalidConfig {
        /// Configuration field that failed validation.
        field: &'static str,
        /// Human-readable validation failure.
        message: String,
    },

    /// A secret-looking environment variable was not explicitly allowed.
    #[error("environment variable {key} is denied by default; list it in allow_secret_env to pass it explicitly")]
    SecretEnvDenied {
        /// Environment variable name.
        key: String,
    },

    /// A runner session was requested but no matching session is active.
    #[error("runner session {session_id} is not active")]
    UnknownSession {
        /// Session identifier.
        session_id: String,
    },

    /// A child process could not be spawned.
    #[error("failed to spawn {command}: {source}")]
    Spawn {
        /// Command path or executable name.
        command: String,
        /// I/O failure returned by the OS.
        #[source]
        source: io::Error,
    },

    /// A required child stdio pipe was not available after spawning.
    #[error("child process for {command} did not expose {stream} pipe")]
    MissingPipe {
        /// Command path or executable name.
        command: String,
        /// Missing pipe name.
        stream: &'static str,
    },

    /// Waiting for a child process failed.
    #[error("failed while waiting for {command}: {source}")]
    Wait {
        /// Command path or executable name.
        command: String,
        /// I/O failure returned by the OS.
        #[source]
        source: io::Error,
    },

    /// Killing a timed-out child process group failed.
    #[error("failed to kill timed-out process group for {command}: {message}")]
    KillProcessGroup {
        /// Command path or executable name.
        command: String,
        /// Human-readable process-group failure.
        message: String,
    },

    /// Workflow configuration could not be decoded.
    #[error("failed to decode runner workflow config: {0}")]
    Decode(#[from] serde_json::Error),

    /// Workflow YAML could not be decoded.
    #[error("failed to decode runner workflow YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// The internal session registry could not be accessed.
    #[error("runner session registry is poisoned")]
    SessionRegistryPoisoned,
}

impl Error {
    /// Construct a missing-config error.
    #[must_use]
    pub const fn missing_config(field: &'static str) -> Self {
        Self::MissingConfig { field }
    }

    /// Construct an invalid-config error.
    #[must_use]
    pub fn invalid_config(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidConfig {
            field,
            message: message.into(),
        }
    }
}

impl From<Error> for SymphonyError {
    fn from(value: Error) -> Self {
        Self::Runner(value.to_string())
    }
}
