#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod containment;
pub mod error;
mod manager;

pub use error::{Error, Result};
pub use manager::{CleanupDecision, Config, Manager};
