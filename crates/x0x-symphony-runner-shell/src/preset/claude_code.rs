//! Claude Code preset configuration.
//!
//! Pinned against Claude Code 2.1.208: `--print --output-format stream-json`
//! requires `--verbose` (Claude Code rejects the argv otherwise). Verified
//! live 2026-07-15; see `tests/preset_live_smoke.rs`. For other harness
//! versions, override via `runner.command`/`runner.args` or the
//! `runner.claude_code.args` block in `WORKFLOW.md`.

use crate::{error::Result, preset, RunnerSpec};

pub(crate) fn spec() -> Result<RunnerSpec> {
    let spec = RunnerSpec::new("claude")?
        .with_arg("--print")
        .with_arg("--output-format")
        .with_arg("stream-json")
        .with_arg("--verbose");
    Ok(preset::base_env(spec))
}
