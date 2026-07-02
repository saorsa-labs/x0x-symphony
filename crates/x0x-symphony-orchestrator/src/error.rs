//! Orchestrator error type.

use std::path::PathBuf;

use thiserror::Error;
use x0x_symphony_core::SymphonyError;

/// Result alias for orchestrator operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced while dispatching and reconciling issues.
#[derive(Debug, Error)]
pub enum Error {
    /// A dependency returned a structured core error.
    #[error(transparent)]
    Core(#[from] SymphonyError),

    /// A claim heartbeat timestamp could not be parsed as RFC3339.
    ///
    /// Freshness and reconciliation rely on the heartbeat timestamp written by
    /// the tracker adapter; an unparseable value is treated as a hard failure
    /// rather than silently assuming freshness.
    #[error("unparseable heartbeat timestamp {timestamp:?}: {source}")]
    BadHeartbeat {
        /// The offending timestamp string.
        timestamp: String,
        /// Underlying parse error.
        #[source]
        source: chrono::ParseError,
    },

    /// The orchestrator was asked to do work for an issue it cannot dispatch.
    #[error("issue {id} is not eligible for dispatch: {reason}")]
    NotEligible {
        /// Issue identifier.
        id: String,
        /// Why the issue was rejected.
        reason: String,
    },

    /// A proof artefact filesystem operation failed.
    #[error("proof artefact I/O error at {path}: {source}")]
    ProofIo {
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A proof artefact path failed containment validation.
    #[error("proof artefact path rejected: {reason}")]
    ProofContainment {
        /// Human-readable containment failure.
        reason: String,
    },

    /// Serializing proof manifest JSON failed.
    #[error("proof manifest JSON serialization failed: {source}")]
    ProofJson {
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },

    /// The background proof event writer task failed to join.
    #[error("proof event writer task failed: {message}")]
    ProofTask {
        /// Join failure message.
        message: String,
    },
}
