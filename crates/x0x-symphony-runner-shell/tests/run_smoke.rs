use std::{path::Path, time::Duration};

use futures_util::StreamExt;
use tempfile::tempdir;
use tokio::time::timeout;
use x0x_symphony_core::{
    Issue, IssueId, IssueState, Prompt, Runner, RunnerEvent, RunnerEventKind, SessionContext,
    SessionHandle, TurnStatus,
};
use x0x_symphony_runner_shell::{RunnerSpec, ShellRunner};

#[cfg(unix)]
use nix::{errno::Errno, sys::signal::kill, unistd::Pid};

#[tokio::test]
#[cfg(unix)]
async fn shell_runner_streams_prompt_to_arbitrary_child_process(
) -> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempdir()?;
    let spec = RunnerSpec::new("/bin/cat")?.with_turn_timeout_ms(2_000);
    let runner = ShellRunner::new(spec)?;
    let mut handle = runner
        .start_session(session_context(workspace.path())?)
        .await?;

    let outcome = runner
        .run_turn(&mut handle, Prompt::new("hello from stdin\n"))
        .await?;

    assert_eq!(outcome.status, TurnStatus::Succeeded);
    let events = drain_events(&runner, &handle).await;
    assert_event_contains(&events, &RunnerEventKind::Stdout, "hello from stdin");
    let usage = runner.stop_session(handle).await?;
    assert!(usage.duration_ms.is_some());

    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn poisoned_parent_environment_does_not_leak_to_child_env(
) -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("XSY_POISON_TOKEN", "parent-secret");
    let workspace = tempdir()?;
    let spec = RunnerSpec::new("/usr/bin/env")?
        .with_env("SAFE_VISIBLE", "present")
        .with_turn_timeout_ms(2_000);
    let runner = ShellRunner::new(spec)?;
    let mut handle = runner
        .start_session(session_context(workspace.path())?)
        .await?;

    let outcome = runner.run_turn(&mut handle, Prompt::new("")).await?;

    assert_eq!(outcome.status, TurnStatus::Succeeded);
    let stdout = stdout_text(&drain_events(&runner, &handle).await);
    assert!(stdout.contains("SAFE_VISIBLE=present"));
    assert!(!stdout.contains("XSY_POISON_TOKEN=parent-secret"));
    runner.stop_session(handle).await?;

    Ok(())
}

#[test]
#[cfg(unix)]
fn secret_like_workflow_env_requires_explicit_allowlist() -> Result<(), Box<dyn std::error::Error>>
{
    let denied = RunnerSpec::new("/usr/bin/env")?.with_env("API_TOKEN", "secret");
    assert!(ShellRunner::new(denied).is_err());

    let allowed = RunnerSpec::new("/usr/bin/env")?
        .with_env("API_TOKEN", "secret")
        .with_allowed_secret_env("API_TOKEN");
    assert!(ShellRunner::new(allowed).is_ok());

    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn argv_is_static_and_prompt_is_only_issue_content_channel(
) -> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempdir()?;
    let argv_file = workspace.path().join("argv.txt");
    let stdin_file = workspace.path().join("stdin.txt");
    let issue_title = "malicious $(touch should-not-run)";
    let spec = RunnerSpec::new("/bin/sh")?
        .with_args([
            "-c".to_owned(),
            "argv_file=$1; stdin_file=$2; shift 2; printf '%s\n' \"$@\" > \"$argv_file\"; cat > \"$stdin_file\"".to_owned(),
            "sh".to_owned(),
            path_arg(&argv_file),
            path_arg(&stdin_file),
            "{{ issue.title }}".to_owned(),
        ])
        .with_turn_timeout_ms(2_000);
    let runner = ShellRunner::new(spec)?;
    let mut handle = runner
        .start_session(session_context_with_title(workspace.path(), issue_title)?)
        .await?;

    let outcome = runner
        .run_turn(
            &mut handle,
            Prompt::new(format!("Title supplied through stdin: {issue_title}\n")),
        )
        .await?;

    assert_eq!(outcome.status, TurnStatus::Succeeded);
    let argv_text = tokio::fs::read_to_string(argv_file).await?;
    let stdin_text = tokio::fs::read_to_string(stdin_file).await?;
    assert!(argv_text.contains("{{ issue.title }}"));
    assert!(!argv_text.contains(issue_title));
    assert!(stdin_text.contains(issue_title));
    runner.stop_session(handle).await?;

    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn proof_chatty_child_does_not_grow_output_memory_unboundedly(
) -> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempdir()?;
    let spec = RunnerSpec::new("/bin/sh")?
        .with_args([
            "-c".to_owned(),
            "i=0; while [ \"$i\" -lt 50000 ]; do printf 'line-%05d\\n' \"$i\"; i=$((i + 1)); done"
                .to_owned(),
        ])
        .with_event_capacity(8)
        .with_event_high_water_mark(4)
        .with_turn_timeout_ms(5_000);
    let event_capacity = spec.event_capacity;
    let runner = ShellRunner::new(spec)?;
    let mut handle = runner
        .start_session(session_context(workspace.path())?)
        .await?;

    let outcome = runner.run_turn(&mut handle, Prompt::new("")).await?;

    assert_eq!(outcome.status, TurnStatus::Succeeded);
    let events = drain_events(&runner, &handle).await;
    assert!(events.len() <= event_capacity);
    assert!(events
        .iter()
        .any(|event| event.kind == RunnerEventKind::TurnCompleted));
    runner.stop_session(handle).await?;

    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn proof_timeout_kills_forked_children_process_group(
) -> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempdir()?;
    let child_pid_file = workspace.path().join("child.pid");
    let spec = RunnerSpec::new("/bin/sh")?
        .with_args([
            "-c".to_owned(),
            "sleep 30 & echo $! > \"$1\"; wait".to_owned(),
            "sh".to_owned(),
            path_arg(&child_pid_file),
        ])
        .with_turn_timeout_ms(200);
    let runner = ShellRunner::new(spec)?;
    let mut handle = runner
        .start_session(session_context(workspace.path())?)
        .await?;

    let outcome = runner.run_turn(&mut handle, Prompt::new("")).await?;

    assert_eq!(outcome.status, TurnStatus::TimedOut);
    let child_pid = read_pid(&child_pid_file).await?;
    wait_until_process_exits(child_pid).await;
    assert!(!process_exists(child_pid));
    runner.stop_session(handle).await?;

    Ok(())
}

fn session_context(workspace: &Path) -> Result<SessionContext, Box<dyn std::error::Error>> {
    session_context_with_title(workspace, "Shell runner test")
}

fn session_context_with_title(
    workspace: &Path,
    title: &str,
) -> Result<SessionContext, Box<dyn std::error::Error>> {
    let issue = Issue::new(
        IssueId::new("XSY-0004")?,
        "XSY-0004",
        title,
        IssueState::new("todo")?,
        "2026-07-02T00:00:00Z",
    )?;
    Ok(SessionContext::new(issue, workspace.to_path_buf()))
}

async fn drain_events(runner: &ShellRunner, handle: &SessionHandle) -> Vec<RunnerEvent> {
    let mut stream = runner.stream_events(handle);
    let mut events = Vec::new();
    while let Ok(Some(event)) = timeout(Duration::from_millis(20), stream.next()).await {
        events.push(event);
    }
    events
}

fn assert_event_contains(events: &[RunnerEvent], kind: &RunnerEventKind, needle: &str) {
    assert!(events.iter().any(|event| {
        event.kind == *kind
            && event
                .message
                .as_ref()
                .is_some_and(|message| message.contains(needle))
    }));
}

fn stdout_text(events: &[RunnerEvent]) -> String {
    events
        .iter()
        .filter(|event| event.kind == RunnerEventKind::Stdout)
        .filter_map(|event| event.message.as_deref())
        .collect::<Vec<_>>()
        .join("")
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(unix)]
async fn read_pid(path: &Path) -> Result<i32, Box<dyn std::error::Error>> {
    let pid_text = tokio::fs::read_to_string(path).await?;
    Ok(pid_text.trim().parse::<i32>()?)
}

#[cfg(unix)]
async fn wait_until_process_exits(pid: i32) {
    for _ in 0_u8..40 {
        if !process_exists(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(unix)]
fn process_exists(pid: i32) -> bool {
    match kill(Pid::from_raw(pid), None) {
        Err(Errno::ESRCH) => false,
        Ok(()) | Err(_) => true,
    }
}
