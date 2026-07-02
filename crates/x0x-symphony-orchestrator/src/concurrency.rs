//! Concurrency accounting: a global cap plus optional per-state caps.
//!
//! The orchestrator must not claim more issues than it can run. [`Budget`]
//! tracks in-flight runs against a global ceiling and optional per-state
//! ceilings (e.g. at most one `security` issue at a time). It is intentionally
//! synchronous and lock-free-ish: the orchestrator guards it behind a mutex and
//! calls [`Budget::try_acquire`] / [`Budget::release`] as it claims and
//! finishes issues.

use std::collections::BTreeMap;

use x0x_symphony_core::IssueState;

/// Snapshot of available concurrency headroom for a single state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Headroom {
    /// Remaining slots under the global cap.
    pub global: usize,
    /// Remaining slots under the per-state cap, when configured. `usize::MAX`
    /// means "no per-state cap" so it never binds.
    pub per_state: usize,
}

impl Headroom {
    /// Effective remaining slots — the tighter of global and per-state.
    #[must_use]
    pub fn available(self) -> usize {
        self.global.min(self.per_state)
    }

    /// `true` when at least one slot is available under both caps.
    #[must_use]
    pub fn is_open(self) -> bool {
        self.available() > 0
    }
}

/// Concurrent-run accounting.
#[derive(Clone, Debug)]
pub struct Budget {
    global_cap: usize,
    global_used: usize,
    per_state_caps: BTreeMap<IssueState, usize>,
    per_state_used: BTreeMap<IssueState, usize>,
}

impl Budget {
    /// Create a budget with a global cap and optional per-state caps.
    #[must_use]
    pub fn new(global_cap: usize, per_state_caps: BTreeMap<IssueState, usize>) -> Self {
        Self {
            global_cap,
            global_used: 0,
            per_state_caps,
            per_state_used: BTreeMap::new(),
        }
    }

    /// Remaining headroom for `state` without mutating anything.
    #[must_use]
    pub fn headroom(&self, state: &IssueState) -> Headroom {
        let global = self.global_cap.saturating_sub(self.global_used);
        let per_state = match self.per_state_caps.get(state) {
            Some(cap) => {
                let mut used = 0;
                if let Some(value) = self.per_state_used.get(state).copied() {
                    used = value;
                }
                cap.saturating_sub(used)
            }
            None => usize::MAX,
        };
        Headroom { global, per_state }
    }

    /// Reserve a slot for `state` if one is available under both caps.
    ///
    /// Returns `true` on success. On failure nothing is mutated.
    pub fn try_acquire(&mut self, state: &IssueState) -> bool {
        if !self.headroom(state).is_open() {
            return false;
        }
        self.global_used = self.global_used.saturating_add(1);
        if self.per_state_caps.contains_key(state) {
            let entry = self.per_state_used.entry(state.clone()).or_insert(0);
            *entry = entry.saturating_add(1);
        }
        true
    }

    /// Release a slot previously acquired for `state`.
    pub fn release(&mut self, state: &IssueState) {
        self.global_used = self.global_used.saturating_sub(1);
        if let Some(entry) = self.per_state_used.get_mut(state) {
            *entry = entry.saturating_sub(1);
        }
    }

    /// Number of currently in-flight runs.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.global_used
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use x0x_symphony_core::IssueState;

    fn state(name: &str) -> Result<IssueState, Box<dyn Error>> {
        Ok(IssueState::new(name)?)
    }

    #[test]
    fn global_cap_limits_acquires() -> Result<(), Box<dyn Error>> {
        let mut budget = Budget::new(1, BTreeMap::new());
        let todo = state("todo")?;
        assert!(budget.try_acquire(&todo));
        assert!(!budget.try_acquire(&todo));
        budget.release(&todo);
        assert!(budget.try_acquire(&todo));
        Ok(())
    }

    #[test]
    fn per_state_cap_is_independent_of_global() -> Result<(), Box<dyn Error>> {
        let mut caps = BTreeMap::new();
        caps.insert(state("todo")?, 1);
        let mut budget = Budget::new(5, caps);
        let todo = state("todo")?;
        assert!(budget.try_acquire(&todo));
        // Global still has room but the per-state cap is exhausted.
        assert!(!budget.try_acquire(&todo));
        assert_eq!(budget.in_flight(), 1);
        Ok(())
    }

    #[test]
    fn untracked_state_uses_only_global_cap() -> Result<(), Box<dyn Error>> {
        let mut caps = BTreeMap::new();
        caps.insert(state("todo")?, 1);
        let mut budget = Budget::new(2, caps);
        let review = state("review")?;
        assert!(budget.try_acquire(&review));
        assert!(budget.try_acquire(&review));
        assert!(!budget.try_acquire(&review));
        Ok(())
    }
}
