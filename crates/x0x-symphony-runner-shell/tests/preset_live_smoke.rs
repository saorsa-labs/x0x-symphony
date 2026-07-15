//! Live preset contract smoke tests (issue #7).
//!
//! Each test spawns the *real* installed harness with the exact preset argv,
//! feeds a trivial prompt over stdin (the shell runner's only prompt channel),
//! and asserts the harness does not reject the argv with a parse/usage error —
//! the failure mode that shipped in v0.1.2 (`pi --stdin`, `claude --print
//! --output-format stream-json` without `--verbose`).
//!
//! These are dev-machine tests, not CI tests:
//! - they are gated behind `X0X_SYMPHONY_PRESET_SMOKE=1` because they launch
//!   real AI harnesses (which may spend tokens); run them via
//!   `just preset-smoke`;
//! - a preset whose harness binary is absent from `PATH` is skipped with a
//!   message.
//!
//! Pass criteria: the child exits successfully, is still running when the
//! bounded wait elapses (argv accepted, model turn in flight — it is killed),
//! or exits non-zero for a *runtime* reason (auth, untrusted directory). Only
//! an argument-parse/usage failure fails the test.
//!
//! Pinned harness versions (verified 2026-07-15): Claude Code 2.1.208,
//! pi 0.80.3, codex-cli 0.144.1. Kimi/GLM/Minimax remain unpinned config-only
//! placeholders and are intentionally not smoked here.

use std::{path::PathBuf, process::Stdio, time::Duration};

use tokio::{io::AsyncWriteExt, process::Command, time::timeout};
use x0x_symphony_runner_shell::{preset, PresetName};

const SMOKE_ENV: &str = "X0X_SYMPHONY_PRESET_SMOKE";
const PROMPT: &str = "Reply with exactly OK and nothing else.\n";
const WAIT: Duration = Duration::from_secs(30);

/// Substrings that identify an argv/usage rejection (vs a runtime failure).
const USAGE_ERROR_MARKERS: &[&str] = &[
    "unknown option",
    "unknown argument",
    "unexpected argument",
    "unrecognized option",
    "unrecognized subcommand",
    "invalid option",
    "requires --verbose",
    "usage:",
];

#[tokio::test]
async fn claude_code_preset_argv_is_accepted_by_installed_claude(
) -> Result<(), Box<dyn std::error::Error>> {
    smoke(PresetName::ClaudeCode).await
}

#[tokio::test]
async fn pi_preset_argv_is_accepted_by_installed_pi() -> Result<(), Box<dyn std::error::Error>> {
    smoke(PresetName::Pi).await
}

#[tokio::test]
async fn codex_preset_argv_is_accepted_by_installed_codex(
) -> Result<(), Box<dyn std::error::Error>> {
    smoke(PresetName::Codex).await
}

async fn smoke(name: PresetName) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os(SMOKE_ENV).is_none() {
        eprintln!("SKIP {name} live smoke: set {SMOKE_ENV}=1 (or run `just preset-smoke`)");
        return Ok(());
    }
    let spec = preset::resolve(name)?;
    let Some(binary) = find_on_path(&spec.command) else {
        eprintln!(
            "SKIP {name} live smoke: `{}` not found on PATH",
            spec.command
        );
        return Ok(());
    };

    // Run in a scratch workspace so the harness cannot touch the repo. The
    // parent environment is inherited (unlike the runner's env_clear) so the
    // harness can reach its own auth config; the preset env is layered on top.
    let workspace = tempfile::tempdir()?;
    let mut child = Command::new(&binary)
        .args(&spec.args)
        .envs(&spec.env)
        .current_dir(workspace.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("child stdin unavailable")?;
    stdin.write_all(PROMPT.as_bytes()).await?;
    drop(stdin); // EOF so stdin-reading harnesses see a complete prompt.

    match timeout(WAIT, child.wait_with_output()).await {
        Err(_elapsed) => {
            // Argv was accepted and a turn is in flight; that is all this
            // smoke asserts. The child is killed via kill_on_drop.
            eprintln!("PASS {name}: still running after {WAIT:?} (argv accepted); killing");
            Ok(())
        }
        Ok(output) => {
            let output = output?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let combined = format!("{stderr}\n{stdout}").to_lowercase();
            let usage_error = USAGE_ERROR_MARKERS
                .iter()
                .any(|marker| combined.contains(marker));
            if !output.status.success() && usage_error {
                return Err(format!(
                    "{name} preset argv rejected by `{}` ({}): stderr: {} stdout: {}",
                    spec.command,
                    output.status,
                    stderr.trim(),
                    stdout.trim(),
                )
                .into());
            }
            eprintln!(
                "PASS {name}: exited {} without an argv/usage error",
                output.status
            );
            Ok(())
        }
    }
}

fn find_on_path(command: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(command))
        .find(|candidate| candidate.is_file())
}
