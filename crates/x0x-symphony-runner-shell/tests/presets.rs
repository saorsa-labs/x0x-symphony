use x0x_symphony_runner_shell::{
    preset, Backend, PresetName, RunnerSpec, SandboxProfile, UnavailablePolicy,
};

#[test]
fn codex_preset_resolves_expected_command_args_env() -> Result<(), Box<dyn std::error::Error>> {
    let spec = preset::resolve(PresetName::Codex)?;

    assert_eq!(spec.command, "codex");
    // Pinned against codex-cli 0.144.1: `codex exec` reads the prompt from stdin.
    assert_eq!(spec.args, ["exec"]);
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
    // Pinned against Claude Code 2.1.208: stream-json under --print requires --verbose.
    assert_eq!(
        spec.args,
        ["--print", "--output-format", "stream-json", "--verbose"]
    );
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
    // Pinned against pi 0.80.3: `--print` reads the prompt from stdin; `--stdin`
    // is rejected ("Unknown option: --stdin").
    assert_eq!(spec.args, ["--print"]);
    assert_eq!(spec.preset, Some(PresetName::Pi));
    Ok(())
}

#[test]
fn workflow_yaml_parses_sandbox_block() -> Result<(), Box<dyn std::error::Error>> {
    let spec = RunnerSpec::from_workflow_yaml(
        r#"
runner:
  kind: shell
  command: /bin/cat
  sandbox:
    profile: no-network
    backend: sandbox-exec
    on_unavailable: fail-closed
    egress_allow: ["api.example.test"]
    secrets_deny: ["~/.ssh"]
    cpu_seconds: 10
    memory_bytes: 1048576
"#,
    )?;
    let Some(sandbox) = spec.sandbox else {
        return Err("sandbox block was not parsed".into());
    };

    assert_eq!(sandbox.profile, SandboxProfile::NoNetwork);
    assert_eq!(sandbox.backend, Backend::SandboxExec);
    assert_eq!(sandbox.on_unavailable, UnavailablePolicy::FailClosed);
    assert_eq!(sandbox.egress_allow, ["api.example.test"]);
    assert_eq!(sandbox.cpu_seconds, Some(10));
    assert_eq!(sandbox.memory_bytes, Some(1_048_576));

    Ok(())
}

#[test]
fn preset_overrides_prepend_child_sandbox_args() -> Result<(), Box<dyn std::error::Error>> {
    let spec = RunnerSpec::from_workflow_yaml(
        r#"
runner:
  kind: shell
  preset: codex
  codex:
    sandbox_args: ["--sandbox", "workspace-write"]
"#,
    )?;

    // Verified against codex-cli 0.144.1: global `--sandbox` is accepted before
    // the `exec` subcommand.
    assert_eq!(spec.args, ["--sandbox", "workspace-write", "exec"]);

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
