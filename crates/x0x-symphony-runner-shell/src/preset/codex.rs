//! Codex preset configuration.
//!
//! Pinned against codex-cli 0.144.1: `codex exec` runs non-interactively and
//! reads the prompt from stdin when no prompt argument is given — matching the
//! shell runner's stdin-only prompt channel. The previous `codex app-server`
//! argv spoke JSON-RPC and rejected a plain rendered prompt ("Failed to
//! deserialize `JSONRPCMessage`"). Verified live 2026-07-15; see
//! `tests/preset_live_smoke.rs`. For other harness versions, override via
//! `runner.command`/`runner.args` or the `runner.codex.args` block in
//! `WORKFLOW.md`.

use crate::{error::Result, preset, RunnerSpec};

pub(crate) fn spec() -> Result<RunnerSpec> {
    let spec = RunnerSpec::new("codex")?.with_arg("exec");
    Ok(preset::base_env(spec))
}
