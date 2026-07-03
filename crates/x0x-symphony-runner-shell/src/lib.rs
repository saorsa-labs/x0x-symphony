#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod env;
pub mod error;
pub mod preset;
pub mod runner;
pub mod spec;

pub use error::{Error, Result};
pub use preset::PresetName;
pub use runner::ShellRunner;
pub use saorsa_sandbox::{
    Backend, CommandPlan, HostSandbox, NoopSession, ProbeCheck, ProbeReport, ProbeStatus, Sandbox,
    SandboxProfile, SandboxSession, SandboxSpec, UnavailablePolicy, WrappedCommand,
};
pub use spec::{EventOverflowPolicy, RunnerSpec};
pub use x0x_symphony_core::IssueSource;
