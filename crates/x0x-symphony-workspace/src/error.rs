//! Error types for the workspace manager crate.

use std::{io, path::PathBuf};

use thiserror::Error;
use x0x_symphony_core::SymphonyError;

use crate::containment::ContainmentError;

/// Convenient result alias for workspace manager APIs.
pub type Result<T> = std::result::Result<T, Error>;

/// Structured errors produced by the workspace manager.
#[derive(Debug, Error)]
pub enum Error {
    /// Path containment failed.
    #[error(transparent)]
    Containment(#[from] ContainmentError),

    /// A workspace path exists but is not a directory.
    #[error("workspace path is not a directory: {path}", path = .path.display())]
    NotDirectory {
        /// Rejected path.
        path: PathBuf,
    },

    /// Creating the workspace root failed.
    #[error("failed to create workspace root {path}: {source}", path = .path.display())]
    CreateRoot {
        /// Root path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// Creating an issue workspace failed.
    #[error("failed to create workspace directory {path}: {source}", path = .path.display())]
    CreateDir {
        /// Directory path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// Creating an orphan quarantine directory failed.
    #[error("failed to create orphan quarantine directory {path}: {source}", path = .path.display())]
    CreateQuarantineDir {
        /// Directory path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// Reading workspace root entries failed.
    #[error("failed to read workspace root {path}: {source}", path = .path.display())]
    ReadDir {
        /// Directory path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// Reading one workspace root entry failed.
    #[error("failed to read workspace root entry under {path}: {source}", path = .path.display())]
    ReadDirEntry {
        /// Directory being scanned.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// Reading workspace metadata failed.
    #[error("failed to read workspace metadata {path}: {source}", path = .path.display())]
    Metadata {
        /// Path being queried.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// Removing a workspace failed.
    #[error("failed to remove workspace directory {path}: {source}", path = .path.display())]
    RemoveDir {
        /// Directory path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// Moving a workspace into quarantine failed.
    #[error("failed to move workspace directory {from} to quarantine {to}: {source}", from = .from.display(), to = .to.display())]
    MoveDir {
        /// Source workspace path.
        from: PathBuf,
        /// Quarantine destination path.
        to: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// A quarantine path failed containment validation.
    #[error("invalid orphan quarantine path {path}: {reason}", path = .path.display())]
    InvalidQuarantinePath {
        /// Rejected path.
        path: PathBuf,
        /// Human-readable reason.
        reason: &'static str,
    },

    /// Hook environment key or value validation failed.
    #[error("invalid hook environment variable {name:?}: {reason}")]
    InvalidHookEnv {
        /// Rejected variable name.
        name: String,
        /// Human-readable reason.
        reason: &'static str,
    },

    /// Hook environment requested a sensitive variable without explicit opt-in.
    #[error("hook environment variable {name:?} matches the sensitive deny-list")]
    SensitiveHookEnvDenied {
        /// Rejected variable name.
        name: String,
    },

    /// Hook environment requested a dangerous shell/linker variable (e.g.
    /// `BASH_ENV`, `LD_PRELOAD`) that can execute code or load libraries into
    /// the hook process. These are never allowed, regardless of the sensitive
    /// allow-list. See the red-team review of XSY-0005.
    #[error("hook environment variable {name:?} is a dangerous shell/linker variable")]
    DangerousHookEnvDenied {
        /// Rejected variable name.
        name: String,
    },

    /// The hook process could not be spawned.
    #[error("failed to spawn hook {hook}: {source}")]
    HookSpawn {
        /// Stable hook name.
        hook: &'static str,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// The hook process could not be awaited.
    #[error("failed to wait for hook {hook}: {source}")]
    HookWait {
        /// Stable hook name.
        hook: &'static str,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// A hook pipe was not available after spawning with piped I/O.
    #[error("hook {hook} did not expose its {stream} pipe")]
    HookPipeMissing {
        /// Stable hook name.
        hook: &'static str,
        /// Missing stream name.
        stream: &'static str,
    },

    /// Reading hook output failed.
    #[error("failed to read hook {stream}: {source}")]
    HookOutputRead {
        /// Stream being read.
        stream: &'static str,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// The task reading hook output failed.
    #[error("hook {stream} reader task failed: {message}")]
    HookOutputJoin {
        /// Stream being read.
        stream: &'static str,
        /// Join failure message.
        message: String,
    },
}

impl Error {
    pub(crate) fn into_core(self) -> SymphonyError {
        SymphonyError::Workspace(self.to_string())
    }
}
