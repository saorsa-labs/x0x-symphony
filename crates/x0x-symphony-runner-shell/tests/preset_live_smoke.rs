//! Live preset contract smoke tests (issue #7).
//!
//! Each test spawns the *real* installed harness with the exact preset argv,
//! feeds a trivial prompt over stdin (the shell runner's only prompt channel),
//! and asserts the harness accepts the argv — the failure mode that shipped in
//! v0.1.2 (`pi --stdin`, `claude --print --output-format stream-json` without
//! `--verbose`).
//!
//! These are dev-machine tests, not CI tests:
//! - they are gated behind `X0X_SYMPHONY_PRESET_SMOKE=1` because they launch
//!   real AI harnesses (which may spend tokens); run them via
//!   `just preset-smoke`;
//! - a preset whose harness binary is absent from `PATH` (or not executable)
//!   is skipped with a message.
//!
//! Classification is fail-closed: exit 0 passes, and a child still running at
//! the bounded wait passes (argv accepted, model turn in flight — its process
//! group is killed and reaped). A non-zero exit passes only when the output
//! matches a known *runtime* failure (auth/API-key, provider/rate-limit,
//! codex's untrusted-directory refusal); any other non-zero exit fails with
//! the captured output, so unknown argv rejections cannot slip through.
//!
//! Pinned harness versions (verified 2026-07-15): Claude Code 2.1.208,
//! pi 0.80.3, codex-cli 0.144.1. Kimi/GLM/Minimax remain unpinned config-only
//! placeholders and are intentionally not smoked here.

use std::{path::PathBuf, process::Stdio, time::Duration};

use futures_util::StreamExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    time::timeout,
};
use x0x_symphony_core::{
    Issue, IssueId, IssueState, Prompt, Runner, RunnerEvent, RunnerEventKind, SessionContext,
    SessionHandle, TurnStatus,
};
use x0x_symphony_runner_shell::{preset, PresetName, ShellRunner};

const SMOKE_ENV: &str = "X0X_SYMPHONY_PRESET_SMOKE";
const PROMPT: &str = "Reply with exactly OK and nothing else.\n";
const WAIT: Duration = Duration::from_secs(30);

/// Presets whose harness contract is pinned and live-verified.
const PINNED_PRESETS: &[PresetName] = &[PresetName::ClaudeCode, PresetName::Pi, PresetName::Codex];

/// Known *runtime* (post-argv-parse) failure markers. A non-zero exit passes
/// the smoke only when its output matches one of these; anything else fails
/// closed as a suspected argv/contract rejection.
const RUNTIME_FAILURE_MARKERS: &[&str] = &[
    // Auth / account problems (claude, pi, codex).
    "api key",
    "api-key",
    "api_key",
    "apikey",
    "authentication",
    "unauthorized",
    "not logged in",
    "please log in",
    "login",
    "credential",
    "billing",
    "quota",
    "rate limit",
    "overloaded",
    // pi provider/model resolution happens after argv parsing.
    "provider",
    "no model",
    // codex refuses to run outside a trusted directory (our tempdir workspace).
    "not inside a trusted directory",
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
async fn codex_preset_argv_is_accepted_by_installed_codex() -> Result<(), Box<dyn std::error::Error>>
{
    smoke(PresetName::Codex).await
}

/// Same contract check, but through the production `ShellRunner` spawn path
/// (`env_clear` + declared env only), so the smoke also proves each harness can
/// start under the runner's environment policy rather than the test's
/// inherited environment. `HOME` and `PATH` are declared on the spec the way
/// an operator would allow-list them in `WORKFLOW.md`.
#[tokio::test]
async fn pinned_presets_start_under_production_shell_runner(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os(SMOKE_ENV).is_none() {
        eprintln!("SKIP shell-runner live smoke: set {SMOKE_ENV}=1 (or run `just preset-smoke`)");
        return Ok(());
    }
    for &name in PINNED_PRESETS {
        let mut spec = preset::resolve(name)?;
        if find_on_path(&spec.command).is_none() {
            eprintln!(
                "SKIP {name} shell-runner live smoke: `{}` not found on PATH",
                spec.command
            );
            continue;
        }
        for key in ["HOME", "PATH"] {
            if let Ok(value) = std::env::var(key) {
                spec = spec.with_env(key, value);
            }
        }
        let spec = spec.with_turn_timeout_ms(u64::try_from(WAIT.as_millis())?);

        let workspace = tempfile::tempdir()?;
        let runner = ShellRunner::new(spec)?;
        let mut handle = runner
            .start_session(session_context(workspace.path())?)
            .await?;
        let outcome = runner.run_turn(&mut handle, Prompt::new(PROMPT)).await?;
        let output = drain_event_text(&runner, &handle).await;
        runner.stop_session(handle).await?;

        match outcome.status {
            TurnStatus::Succeeded => {
                eprintln!("PASS {name} (shell runner): turn succeeded");
            }
            // The runner killed the process group at the turn timeout; the
            // argv was accepted and a turn was in flight.
            TurnStatus::TimedOut => {
                eprintln!("PASS {name} (shell runner): argv accepted, turn timed out");
            }
            TurnStatus::Failed | TurnStatus::Cancelled => {
                if !is_known_runtime_failure(&output) {
                    return Err(format!(
                        "{name} preset failed under ShellRunner without a known runtime \
                         cause (suspected argv/contract rejection): {output}",
                    )
                    .into());
                }
                eprintln!("PASS {name} (shell runner): known runtime failure, argv accepted");
            }
        }
    }
    Ok(())
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
    // parent environment is inherited here so the harness can reach its own
    // auth config; `pinned_presets_start_under_production_shell_runner`
    // covers the runner's env_clear policy. The child gets its own process
    // group, mirroring the production runner, so timeout cleanup kills
    // forked grandchildren too.
    let workspace = tempfile::tempdir()?;
    let mut command = Command::new(&binary);
    command
        .args(&spec.args)
        .envs(&spec.env)
        .current_dir(workspace.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn()?;

    let mut stdin = child.stdin.take().ok_or("child stdin unavailable")?;
    stdin.write_all(PROMPT.as_bytes()).await?;
    drop(stdin); // EOF so stdin-reading harnesses see a complete prompt.
    let stdout_pipe = child.stdout.take().ok_or("child stdout unavailable")?;
    let stderr_pipe = child.stderr.take().ok_or("child stderr unavailable")?;
    let stdout_task = tokio::spawn(read_to_string(stdout_pipe));
    let stderr_task = tokio::spawn(read_to_string(stderr_pipe));

    match timeout(WAIT, child.wait()).await {
        Err(_elapsed) => {
            // Argv was accepted and a turn is in flight; that is all this
            // smoke asserts. Kill the whole process group (mirroring the
            // production runner's timeout path) and reap the child.
            kill_process_group(&child)?;
            child.wait().await?;
            stdout_task.abort();
            stderr_task.abort();
            eprintln!("PASS {name}: still running after {WAIT:?} (argv accepted); killed");
            Ok(())
        }
        Ok(status) => {
            let status = status?;
            let stdout = stdout_task.await??;
            let stderr = stderr_task.await??;
            if status.success() {
                eprintln!("PASS {name}: exited {status}");
                return Ok(());
            }
            let combined = format!("{stderr}\n{stdout}");
            if !is_known_runtime_failure(&combined) {
                return Err(format!(
                    "{name} preset argv suspected rejected by `{}` ({status}): stderr: {} \
                     stdout: {}",
                    spec.command,
                    stderr.trim(),
                    stdout.trim(),
                )
                .into());
            }
            eprintln!("PASS {name}: exited {status} with a known runtime (non-argv) failure");
            Ok(())
        }
    }
}

/// Fail-closed non-zero-exit classifier: only recognised runtime failures pass.
fn is_known_runtime_failure(output: &str) -> bool {
    let lowered = output.to_lowercase();
    RUNTIME_FAILURE_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
}

async fn read_to_string(mut pipe: impl AsyncRead + Unpin + Send) -> Result<String, std::io::Error> {
    let mut buffer = Vec::new();
    pipe.read_to_end(&mut buffer).await?;
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

#[cfg(unix)]
fn kill_process_group(child: &Child) -> Result<(), Box<dyn std::error::Error>> {
    use nix::{
        errno::Errno,
        sys::signal::{kill, Signal},
        unistd::Pid,
    };

    let Some(child_id) = child.id() else {
        return Ok(());
    };
    let pgid = i32::try_from(child_id)?;
    match kill(Pid::from_raw(-pgid), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(error.to_string().into()),
    }
}

#[cfg(not(unix))]
fn kill_process_group(_child: &Child) -> Result<(), Box<dyn std::error::Error>> {
    // No process groups on this platform; kill_on_drop covers the direct
    // child and grandchildren may outlive the smoke (same limitation as the
    // production runner's non-unix kill path).
    Ok(())
}

fn find_on_path(command: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(command))
        .find(|candidate| candidate.is_file() && is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(_path: &std::path::Path) -> bool {
    true
}

fn session_context(
    workspace: &std::path::Path,
) -> Result<SessionContext, Box<dyn std::error::Error>> {
    let issue = Issue::new(
        IssueId::new("XSY-0007")?,
        "XSY-0007",
        "Preset live smoke",
        IssueState::new("todo")?,
        "2026-07-15T00:00:00Z",
    )?;
    Ok(SessionContext::new(issue, workspace.to_path_buf()))
}

/// Concatenated stdout+stderr event text for a session.
async fn drain_event_text(runner: &ShellRunner, handle: &SessionHandle) -> String {
    let mut stream = runner.stream_events(handle);
    let mut events: Vec<RunnerEvent> = Vec::new();
    while let Ok(Some(event)) = timeout(Duration::from_millis(20), stream.next()).await {
        events.push(event);
    }
    events
        .iter()
        .filter(|event| {
            matches!(
                event.kind,
                RunnerEventKind::Stdout | RunnerEventKind::Stderr
            )
        })
        .filter_map(|event| event.message.as_deref())
        .collect::<Vec<_>>()
        .join("")
}
