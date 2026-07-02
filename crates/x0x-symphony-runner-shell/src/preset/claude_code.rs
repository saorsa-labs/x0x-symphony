//! Claude Code preset configuration.

use crate::{error::Result, preset, RunnerSpec};

pub(crate) fn spec() -> Result<RunnerSpec> {
    let spec = RunnerSpec::new("claude")?
        .with_arg("--print")
        .with_arg("--output-format")
        .with_arg("stream-json");
    Ok(preset::base_env(spec))
}
