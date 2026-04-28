#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

pub mod claim;
pub mod error;
pub mod handoff;
pub mod issue;
pub mod runner;
pub mod tracker;
pub mod workflow;
pub mod workspace;

pub use claim::{Claim, Shard, ShardRole};
pub use error::{Result, SymphonyError};
pub use handoff::{Handoff, ValidationResult, ValidationStatus};
pub use issue::{AgentId, Issue, IssueId, IssueRef, IssueState};
pub use runner::{
    EventStream, Prompt, Runner, RunnerCapabilities, RunnerEvent, RunnerEventKind, SessionContext,
    SessionHandle, SessionId, TurnOutcome, TurnStatus, UsageReport,
};
pub use tracker::{PollContext, ReleaseReason, ReleaseReasonCode, Tracker};
pub use workflow::{Hook, HookName, WorkflowDefinition, WorkflowPath};
pub use workspace::{HookEnv, HookOutcome, HookStatus, Workspace, WorkspaceHandle};
