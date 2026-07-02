//! Time abstraction for the orchestrator.
//!
//! Claim freshness, stale-claim reconciliation, and heartbeat scheduling all
//! depend on "what time is it now?". Centralising that behind a [`Clock`] trait
//! lets unit tests drive the orchestrator deterministically with a [`ManualClock`]
//! while production uses [`SystemClock`].
//!
//! Times are `chrono::DateTime<chrono::Utc>` so they round-trip against the
//! RFC3339 heartbeat timestamps written by the tracker adapters.

use std::sync::Mutex;

use chrono::{DateTime, Utc};

/// Read-only source of the current instant.
///
/// Implementations must be cheap to clone/share; the orchestrator holds one for
/// the lifetime of a run.
pub trait Clock: Send + Sync {
    /// Return the current wall-clock time.
    fn now(&self) -> DateTime<Utc>;
}

/// Wall-clock [`Clock`] backed by `chrono::Utc::now`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Controllable [`Clock`] for deterministic tests.
///
/// Holds a single instant behind a mutex; [`ManualClock::advance`] moves it
/// forward so tests can age a heartbeat past its TTL without sleeping.
#[derive(Debug)]
pub struct ManualClock {
    current: Mutex<DateTime<Utc>>,
}

impl ManualClock {
    /// Create a manual clock pinned at `at`.
    #[must_use]
    pub fn new(at: DateTime<Utc>) -> Self {
        Self {
            current: Mutex::new(at),
        }
    }

    /// Advance the clock by `duration`.
    pub fn advance(&self, duration: chrono::Duration) {
        if let Ok(mut current) = self.current.lock() {
            *current = (*current).checked_add_signed(duration).unwrap_or(*current);
        }
    }

    /// Overwrite the clock's instant.
    pub fn set(&self, at: DateTime<Utc>) {
        if let Ok(mut current) = self.current.lock() {
            *current = at;
        }
    }
}

impl Clock for ManualClock {
    fn now(&self) -> DateTime<Utc> {
        if let Ok(guard) = self.current.lock() {
            *guard
        } else {
            Utc::now()
        }
    }
}
