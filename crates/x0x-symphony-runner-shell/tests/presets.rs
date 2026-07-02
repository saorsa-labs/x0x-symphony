use x0x_symphony_runner_shell::{preset, PresetName, RunnerSpec};

#[test]
fn codex_preset_resolves_expected_command_args_env() -> Result<(), Box<dyn std::error::Error>> {
    let spec = preset::resolve(PresetName::Codex)?;

    assert_eq!(spec.command, "codex");
    assert_eq!(spec.args, ["app-server"]);
    assert_eq!(spec.env.get("NO_COLOR").map(String::as_str), Some("1"));
    assert_eq!(spec.env.get("TERM").map(String::as_str), Some("dumb"));
    assert_eq!(spec.preset, None);

    Ok(())
}

#[test]
fn claude_code_preset_resolves_expected_command_args_env() -> Result<(), Box<dyn std::error::Error>>
{
    let spec = preset::resolve(PresetName::ClaudeCode)?;

    assert_eq!(spec.command, "claude");
    assert_eq!(spec.args, ["--print", "--output-format", "stream-json"]);
    assert_eq!(spec.env.get("NO_COLOR").map(String::as_str), Some("1"));
    assert_eq!(spec.env.get("TERM").map(String::as_str), Some("dumb"));

    Ok(())
}

#[test]
fn workflow_yaml_overrides_claude_code_without_template_rendering(
) -> Result<(), Box<dyn std::error::Error>> {
    let spec = RunnerSpec::from_workflow_yaml(
        r#"
runner:
  kind: shell
  preset: claude_code
  turn_timeout_ms: 1234
  claude_code:
    args: ["--print", "{{ issue.title }}"]
    env:
      SAFE_FLAG: "1"
"#,
    )?;

    assert_eq!(spec.preset, Some(PresetName::ClaudeCode));
    assert_eq!(spec.command, "claude");
    assert_eq!(spec.args, ["--print", "{{ issue.title }}"]);
    assert_eq!(spec.turn_timeout_ms, 1234);
    assert_eq!(spec.env.get("SAFE_FLAG").map(String::as_str), Some("1"));

    Ok(())
}

#[test]
fn kimi_preset_yaml_resolves_to_runnable_spec() -> Result<(), Box<dyn std::error::Error>> {
    let spec = config_only_spec("kimi")?;
    assert_eq!(spec.command, "kimi");
    assert_eq!(spec.args, ["--stdin"]);
    assert_eq!(spec.preset, Some(PresetName::Kimi));
    Ok(())
}

#[test]
fn glm_preset_yaml_resolves_to_runnable_spec() -> Result<(), Box<dyn std::error::Error>> {
    let spec = config_only_spec("glm")?;
    assert_eq!(spec.command, "glm");
    assert_eq!(spec.args, ["--stdin"]);
    assert_eq!(spec.preset, Some(PresetName::Glm));
    Ok(())
}

#[test]
fn minimax_preset_yaml_resolves_to_runnable_spec() -> Result<(), Box<dyn std::error::Error>> {
    let spec = config_only_spec("minimax")?;
    assert_eq!(spec.command, "minimax");
    assert_eq!(spec.args, ["--stdin"]);
    assert_eq!(spec.preset, Some(PresetName::Minimax));
    Ok(())
}

#[test]
fn pi_preset_yaml_resolves_to_runnable_spec() -> Result<(), Box<dyn std::error::Error>> {
    let spec = config_only_spec("pi")?;
    assert_eq!(spec.command, "pi");
    assert_eq!(spec.args, ["--stdin"]);
    assert_eq!(spec.preset, Some(PresetName::Pi));
    Ok(())
}

fn config_only_spec(preset_name: &str) -> Result<RunnerSpec, Box<dyn std::error::Error>> {
    let yaml = format!(
        r"
runner:
  kind: shell
  preset: {preset_name}
"
    );
    Ok(RunnerSpec::from_workflow_yaml(&yaml)?)
}
