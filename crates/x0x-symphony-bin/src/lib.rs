#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

/// HTTP API routes, DTOs, and authentication middleware.
pub mod api;
/// Bearer-token file handling shared by daemon and CLI.
pub mod auth;
/// Command-line definitions and command dispatch.
pub mod cli;
/// HTTP client used by the CLI binary.
pub mod client;
/// `WORKFLOW.md` frontmatter loading and validation.
pub mod config;
/// Worker gossip advertisement and live-view maintenance.
pub mod workers;
