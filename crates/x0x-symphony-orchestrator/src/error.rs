//! Orchestrator error type.

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
}
