//! Retry policy: exponential backoff with a hard attempts cap.
//!
//! Backoff alone is insufficient — a permanently-broken issue would be retried
//! forever. [`RetryPolicy`] pairs exponential backoff (base 5 s, capped at a
//! configured maximum) with a max-attempts cap. When attempts are exhausted the
//! orchestrator asks the tracker to move the issue to `blocked` instead of
//! releasing it back to `todo` (see [`crate::dispatch`]).

use std::time::Duration;

/// Exponential-backoff retry policy with an attempts cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// First attempt's wait before a retry. The M1 execution plan fixes this at 5 s.
    base: Duration,
    /// Upper bound on a single backoff delay.
    max: Duration,
    /// Maximum number of attempts before the issue is blocked.
    max_attempts: u32,
}

impl RetryPolicy {
    /// Create a policy.
    ///
    /// `max_attempts` is clamped to at least `1`; `base` is clamped to at least
    /// one millisecond so a retry always yields the scheduler.
    #[must_use]
    pub fn new(base: Duration, max: Duration, max_attempts: u32) -> Self {
        Self {
            base: base.max(Duration::from_millis(1)),
            max,
            max_attempts: max_attempts.max(1),
        }
    }

    /// Return the base delay.
    #[must_use]
    pub const fn base(&self) -> Duration {
        self.base
    }

    /// Return the maximum delay.
    #[must_use]
    pub const fn max(&self) -> Duration {
        self.max
    }

    /// Return the maximum number of attempts.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Backoff delay to apply *after* the given attempt number (1-based) before
    /// the next attempt. Doubles each time, capped at `max`.
    #[must_use]
    pub fn backoff_after(&self, attempt: u32) -> Duration {
        // 2^(attempt-1) * base, saturating; capped at max.
        let factor = attempt.saturating_sub(1).min(31);
        let multiplier = 1_u64 << factor;
        let base_nanos = self.base.as_nanos().min(u128::from(u64::MAX));
        let raw_nanos = base_nanos.saturating_mul(u128::from(multiplier));
        let nanos = u64::try_from(raw_nanos).unwrap_or(u64::MAX);
        Duration::from_nanos(nanos).min(self.max)
    }

    /// Return `true` when `attempts_so_far` has reached the cap.
    #[must_use]
    pub fn is_exhausted(&self, attempts_so_far: u32) -> bool {
        attempts_so_far >= self.max_attempts
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        // M1 execution plan §3 WP-4: base 5 s, cap max_retry_backoff_ms.
        Self::new(Duration::from_secs(5), Duration::from_mins(5), 3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps() {
        let policy = RetryPolicy::new(Duration::from_secs(5), Duration::from_mins(1), 4);
        assert_eq!(policy.backoff_after(1), Duration::from_secs(5));
        assert_eq!(policy.backoff_after(2), Duration::from_secs(10));
        assert_eq!(policy.backoff_after(3), Duration::from_secs(20));
        assert_eq!(policy.backoff_after(4), Duration::from_secs(40));
        assert_eq!(policy.backoff_after(5), Duration::from_mins(1)); // capped
    }

    #[test]
    fn exhaustion_is_attempts_capped() {
        let policy = RetryPolicy::new(Duration::from_millis(1), Duration::from_millis(2), 3);
        assert!(!policy.is_exhausted(2));
        assert!(policy.is_exhausted(3));
        assert!(policy.is_exhausted(4));
    }

    #[test]
    fn max_attempts_clamped_to_one() {
        let policy = RetryPolicy::new(Duration::from_millis(1), Duration::from_millis(1), 0);
        assert_eq!(policy.max_attempts(), 1);
    }
}
