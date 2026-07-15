//! Tracker-integrity v2 (x0x-symphony#10, design r2): per-author append-only
//! event stores, self-certifying author binding, signed genesis/roster
//! manifests, signed transition events, and a pure two-phase fold.
//!
//! This module is a **parallel path**: v1 lists (`symphony-*` namespace) use
//! the existing tracker code unchanged; v2 lists live in the disjoint
//! `symphony2-*` / [`events::V2_LIST_REF_PREFIX`] namespace and are
//! reconstructed exclusively by [`fold::fold_v2`]. A v2-addressed list with a
//! missing or invalid genesis manifest is REFUSED entirely — there is no v1
//! fallback (downgrade defense, design r2 Q5).
//!
//! Layout:
//!
//! - [`identity`] — local replication of x0x's external-sign DST and
//!   agent-id derivation (pure crypto; lets the fold verify without I/O).
//! - [`events`] — wire types: envelopes, genesis/roster manifests,
//!   transition events, topics/keys.
//! - [`fold`] — the pure two-phase fold (spec:
//!   `docs/design/tracker-integrity-v2.md`).
//! - [`store`] — WP-0 per-author store management over x0xd REST, including
//!   the `AppendOnly` (x0x WP-X) dependency gate.
//!
//! Trust and TTL are deliberately absent from this module's fold path: they
//! are dispatch-time local policy (design r2 findings C2/C3), never fold
//! inputs.

pub mod events;
pub mod fold;
pub mod gate;
pub mod identity;
pub mod store;

pub use events::{
    ApprovalEventV2, ApprovalVerdictV2, BlockReason, ConsumeEventV2, EventEnvelope,
    GenesisManifestV2, RequeueJustification, RosterEventV2, TransitionEventV2, TransitionKind,
    V2ListRef, TRANSITION_CONTEXT_V2, V2_LIST_REF_PREFIX, V2_SCHEMA,
};
pub use fold::{
    fold_v2, AdmittedApprovalV2, AuthorStream, ChainTipV2, ConsumeDiagnostic, EffectiveConsumeV2,
    FoldInput, FoldOutput, ForkEvidence, IssueStateV2, IssueStatusV2, ListRefusal, Rejection,
    RejectionPhase, StoreRecord, LAMPORT_MAX_SKEW,
};
pub use gate::{build_claim_transition, V2ApprovalGate, V2GateConfig, V2GateDecision};
pub use store::{OwnEventStore, StorePolicyMode, V2StoreApi, V2StoreError, V2StoreManager};
