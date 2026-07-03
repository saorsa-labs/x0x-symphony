#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

pub mod approval;
pub mod claim;
pub mod error;
pub mod handoff;
pub mod issue;
pub mod runner;
pub mod shard;
pub mod signing;
pub mod tracker;
pub mod workers;
pub mod workflow;
pub mod workspace;

pub use approval::{
    approval_decision, content_hash, ApprovalBindingKey, ApprovalConsumed, ApprovalDecision,
    ApprovalEvent, ApprovalState, ApprovalValidity, ApprovalVerdict, ContentHash, DenialEvent,
    APPROVAL_CONSUMED_CONTEXT, APPROVAL_CONTEXT,
};
pub use claim::{Claim, Shard, ShardRole};
pub use error::{Result, SymphonyError};
pub use handoff::{Handoff, ValidationResult, ValidationStatus};
pub use issue::{AgentId, Issue, IssueId, IssueRef, IssueSource, IssueState, SignatureProvenance};
pub use runner::{
    EventStream, Prompt, Runner, RunnerCapabilities, RunnerEvent, RunnerEventKind, SessionContext,
    SessionHandle, SessionId, TurnOutcome, TurnStatus, UsageReport,
};
pub use signing::{sha256_hex, SignatureEnvelope, CLAIM_CONTEXT, HANDOFF_CONTEXT, SIGN_ALGORITHM};
pub use tracker::{PollContext, ReleaseReason, ReleaseReasonCode, Tracker};
pub use workers::{
    PlatformInfo, WorkerCard, DEFAULT_WORKER_CARD_TTL_SECONDS, WORKER_CARD_CONTEXT,
    WORKER_CARD_SCHEMA_VERSION,
};
pub use workflow::{Hook, HookName, LifecycleHooks, WorkflowDefinition, WorkflowPath};
pub use workspace::{
    HookEnv, HookOutcome, HookStatus, RefusedWorkspace, Workspace, WorkspaceHandle, WorkspaceScan,
};
