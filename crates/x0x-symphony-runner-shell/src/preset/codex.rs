//! Codex preset configuration.

use crate::{error::Result, preset, RunnerSpec};

pub(crate) fn spec() -> Result<RunnerSpec> {
    let spec = RunnerSpec::new("codex")?.with_arg("app-server");
    Ok(preset::base_env(spec))
}
