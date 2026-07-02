#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod env;
pub mod error;
pub mod preset;
pub mod runner;
pub mod sandbox;
pub mod spec;

pub use error::{Error, Result};
pub use preset::PresetName;
pub use runner::ShellRunner;
pub use sandbox::{
    Backend, CommandPlan, HostSandbox, IssueSource, NoopSession, PreparedCommand, ProbeCheck,
    ProbeReport, ProbeStatus, Sandbox, SandboxProfile, SandboxSession, SandboxSpec,
    UnavailablePolicy, WrappedCommand,
};
pub use spec::{EventOverflowPolicy, RunnerSpec};
