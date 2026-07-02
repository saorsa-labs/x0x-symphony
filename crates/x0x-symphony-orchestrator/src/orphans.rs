//! Startup orphan-workspace sweep.
//!
//! The sweep is deliberately conservative: live self-owned claim workspaces and
//! non-terminal issue workspaces are preserved, while terminal or tracker-missing
//! issue workspaces are moved into the workspace manager's quarantine tree.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use tracing::warn;
use x0x_symphony_core::{Issue, IssueId, RefusedWorkspace, Tracker, Workspace};

use crate::{reconcile::is_fresh_self, Orchestrator, Result};

/// Summary returned by [`Orchestrator::sweep_orphans`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OrphanSweepSummary {
    /// Workspace issue identifiers preserved in place.
    pub preserved: Vec<IssueId>,
    /// Workspace issue identifiers moved into quarantine.
    pub quarantined: Vec<QuarantinedOrphan>,
    /// Workspace entries refused by containment validation or move failure.
    pub refused: Vec<RefusedOrphan>,
}

impl OrphanSweepSummary {
    /// Count of preserved workspaces.
    #[must_use]
    pub fn preserved_count(&self) -> usize {
        self.preserved.len()
    }

    /// Count of quarantined workspaces.
    #[must_use]
    pub fn quarantined_count(&self) -> usize {
        self.quarantined.len()
    }

    /// Count of refused workspace entries.
    #[must_use]
    pub fn refused_count(&self) -> usize {
        self.refused.len()
    }

    fn preserved_ids(&self) -> Vec<String> {
        self.preserved
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect()
    }

    fn quarantined_ids(&self) -> Vec<String> {
        self.quarantined
            .iter()
            .map(|entry| entry.issue_id.as_str().to_owned())
            .collect()
    }

    fn refused_ids(&self) -> Vec<String> {
        self.refused
            .iter()
            .map(|entry| entry.issue_id.clone())
            .collect()
    }
}

/// One workspace moved into orphan quarantine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedOrphan {
    /// Issue identifier derived from the workspace directory name.
    pub issue_id: IssueId,
    /// Original workspace path.
    pub from: PathBuf,
    /// Quarantine destination path.
    pub to: PathBuf,
}

/// One workspace entry refused by the orphan sweep.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefusedOrphan {
    /// Best-effort issue identifier or directory name.
    pub issue_id: String,
    /// Path that was refused.
    pub path: PathBuf,
    /// Human-readable refusal reason.
    pub reason: String,
}

impl<T, R, W> Orchestrator<T, R, W>
where
    T: Tracker,
    W: Workspace,
{
    /// Sweep orphaned workspace directories once at daemon startup.
    ///
    /// A workspace is preserved when it belongs to a fresh self-owned claim or
    /// to a known issue whose state is not terminal for orphan-cleanup purposes.
    /// Tracker-missing issues and terminal issue states are quarantined via the
    /// workspace implementation. Refused entries are counted and logged but do
    /// not abort the sweep.
    ///
    /// # Errors
    ///
    /// Propagates tracker lookup failures, workspace scan failures, or claim
    /// heartbeat parse errors. Individual quarantine move failures are recorded
    /// in the returned summary instead of aborting the sweep.
    pub async fn sweep_orphans(&self) -> Result<OrphanSweepSummary> {
        let scan = self.workspace.list_workspaces().await?;
        let live_claim_names = self.live_claim_workspace_names().await?;
        let mut handles = scan.workspaces;
        handles.sort_by(|left, right| {
            left.issue_id
                .cmp(&right.issue_id)
                .then_with(|| left.path.cmp(&right.path))
        });

        let orphan_ids = handles
            .iter()
            .filter(|handle| !live_claim_names.contains(handle.issue_id.as_str()))
            .map(|handle| handle.issue_id.clone())
            .collect::<Vec<_>>();
        let issues = self.tracker.fetch_by_ids(&orphan_ids).await?;
        let issue_by_id = issues
            .into_iter()
            .map(|issue| (issue.id.clone(), issue))
            .collect::<BTreeMap<_, _>>();
        let quarantine_namespace = self.orphan_quarantine_namespace();

        let mut summary = OrphanSweepSummary::default();
        summary
            .refused
            .extend(scan.refused.into_iter().map(refused));

        for handle in handles {
            if live_claim_names.contains(handle.issue_id.as_str()) {
                summary.preserved.push(handle.issue_id.clone());
                continue;
            }

            if issue_by_id
                .get(&handle.issue_id)
                .is_some_and(|issue| self.preserve_orphan_issue(issue))
            {
                summary.preserved.push(handle.issue_id.clone());
                continue;
            }

            match self
                .workspace
                .quarantine_workspace(&handle, &quarantine_namespace)
                .await
            {
                Ok(to) => summary.quarantined.push(QuarantinedOrphan {
                    issue_id: handle.issue_id.clone(),
                    from: handle.path.clone(),
                    to,
                }),
                Err(error) => summary.refused.push(RefusedOrphan {
                    issue_id: handle.issue_id.as_str().to_owned(),
                    path: handle.path.clone(),
                    reason: error.to_string(),
                }),
            }
        }

        summary.preserved.sort();
        summary
            .quarantined
            .sort_by(|left, right| left.issue_id.cmp(&right.issue_id));
        summary.refused.sort_by(|left, right| {
            left.issue_id
                .cmp(&right.issue_id)
                .then_with(|| left.path.cmp(&right.path))
        });
        Self::warn_sweep_summary(&summary);
        Ok(summary)
    }

    async fn live_claim_workspace_names(&self) -> Result<BTreeSet<String>> {
        let claimed = self
            .tracker
            .fetch_claimed(Some(&self.config.agent_id))
            .await?;
        let mut names = BTreeSet::new();
        for issue in claimed {
            let Some(claim) = &issue.claim else {
                continue;
            };
            if is_fresh_self(
                claim,
                &self.config.agent_id,
                self.clock.as_ref(),
                self.config.claim_ttl,
            )? {
                names.insert(issue.id.as_str().to_owned());
                names.insert(issue.identifier.clone());
                if let Some(claim_issue_id) = &claim.issue_id {
                    names.insert(claim_issue_id.as_str().to_owned());
                }
            }
        }
        Ok(names)
    }

    fn preserve_orphan_issue(&self, issue: &Issue) -> bool {
        issue.state.as_str() != "blocked"
            && !self
                .config
                .terminal_states
                .iter()
                .any(|state| state == &issue.state)
    }

    fn orphan_quarantine_namespace(&self) -> String {
        self.clock.now().format("%Y%m%dT%H%M%SZ").to_string()
    }

    fn warn_sweep_summary(summary: &OrphanSweepSummary) {
        warn!(
            preserved_count = summary.preserved_count(),
            preserved = ?summary.preserved_ids(),
            quarantined_count = summary.quarantined_count(),
            quarantined = ?summary.quarantined_ids(),
            refused_count = summary.refused_count(),
            refused = ?summary.refused_ids(),
            "orphan workspace sweep completed"
        );
    }
}

fn refused(entry: RefusedWorkspace) -> RefusedOrphan {
    RefusedOrphan {
        issue_id: entry.issue_id,
        path: entry.path,
        reason: entry.reason,
    }
}
