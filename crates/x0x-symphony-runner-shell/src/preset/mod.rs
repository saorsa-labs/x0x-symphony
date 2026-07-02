//! Built-in shell-runner presets.
//!
//! Presets are configuration only: each one resolves to a command, argv vector,
//! and declared environment for the canonical shell runner. They do not add
//! bespoke harness protocol logic.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    RunnerSpec,
};

mod claude_code;
mod codex;
mod config_only;

/// Names of built-in shell-runner presets.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresetName {
    /// Codex CLI app-server preset.
    Codex,
    /// Claude Code non-interactive CLI preset.
    ClaudeCode,
    /// Kimi CLI config-only preset.
    Kimi,
    /// GLM CLI config-only preset.
    Glm,
    /// Minimax CLI config-only preset.
    Minimax,
    /// Pi CLI config-only preset.
    Pi,
}

impl PresetName {
    /// Parse a preset name from workflow text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] when `value` is not a known preset.
    pub fn parse(value: &str) -> Result<Self> {
        value.parse()
    }

    /// Return the stable workflow spelling for this preset.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude_code",
            Self::Kimi => "kimi",
            Self::Glm => "glm",
            Self::Minimax => "minimax",
            Self::Pi => "pi",
        }
    }
}

impl fmt::Display for PresetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PresetName {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "codex" => Ok(Self::Codex),
            "claude_code" | "claude-code" | "claude" => Ok(Self::ClaudeCode),
            "kimi" => Ok(Self::Kimi),
            "glm" => Ok(Self::Glm),
            "minimax" => Ok(Self::Minimax),
            "pi" => Ok(Self::Pi),
            _ => Err(Error::invalid_config(
                "runner.preset",
                format!("unknown preset {value}"),
            )),
        }
    }
}

/// Return all built-in presets.
#[must_use]
pub const fn all() -> [PresetName; 6] {
    [
        PresetName::Codex,
        PresetName::ClaudeCode,
        PresetName::Kimi,
        PresetName::Glm,
        PresetName::Minimax,
        PresetName::Pi,
    ]
}

/// Resolve a built-in preset to a shell runner spec.
///
/// # Errors
///
/// Returns an error only if a built-in preset definition is invalid.
pub fn resolve(name: PresetName) -> Result<RunnerSpec> {
    match name {
        PresetName::Codex => codex::spec(),
        PresetName::ClaudeCode => claude_code::spec(),
        PresetName::Kimi => config_only::spec("kimi", "kimi"),
        PresetName::Glm => config_only::spec("glm", "glm"),
        PresetName::Minimax => config_only::spec("minimax", "minimax"),
        PresetName::Pi => config_only::spec("pi", "pi"),
    }
}

pub(crate) fn base_env(spec: RunnerSpec) -> RunnerSpec {
    spec.with_env("NO_COLOR", "1").with_env("TERM", "dumb")
}
