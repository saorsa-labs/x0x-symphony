//! Config-only presets for harnesses without bespoke protocol logic.

use crate::{error::Result, preset, RunnerSpec};

pub(crate) fn spec(_preset_name: &'static str, command: &'static str) -> Result<RunnerSpec> {
    let spec = RunnerSpec::new(command)?.with_arg("--stdin");
    Ok(preset::base_env(spec))
}
