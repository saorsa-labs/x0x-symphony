//! Pi preset configuration.
//!
//! Pinned against pi 0.80.3: `--print` (`-p`) runs non-interactively and reads
//! the prompt from stdin when no message argument is given. The previous
//! `--stdin` argv is rejected by pi 0.80.3 ("Unknown option: --stdin").
//! Verified live 2026-07-15; see `tests/preset_live_smoke.rs`. For other
//! harness versions, override via `runner.command`/`runner.args` or the
//! `runner.pi.args` block in `WORKFLOW.md`.

use crate::{error::Result, preset, RunnerSpec};

pub(crate) fn spec() -> Result<RunnerSpec> {
    let spec = RunnerSpec::new("pi")?.with_arg("--print");
    Ok(preset::base_env(spec))
}
