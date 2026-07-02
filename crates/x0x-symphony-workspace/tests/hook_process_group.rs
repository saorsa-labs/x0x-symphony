//! Proof tests for hook process-group cleanup on timeout (XSY-0040 item a).
//!
//! These mirror the runner's `proof_timeout_kills_forked_children_process_group`
//! test: a hook that forks a long-running grandchild must, on timeout, kill the
//! whole process group so the grandchild does not outlive the hook.

#![cfg(unix)]

use std::{error::Error, time::Duration};

use nix::{errno::Errno, sys::signal::kill, unistd::Pid};
use tempfile::TempDir;
use tokio::time::timeout;
use x0x_symphony_core::{Hook, HookEnv, HookName, HookStatus, Issue, IssueId, IssueState};
use x0x_symphony_workspace::{Config, Manager};

fn issue() -> Result<Issue, x0x_symphony_core::SymphonyError> {
    Issue::new(
        IssueId::new("XSY-0040")?,
        "XSY-0040",
        "hook pg-kill proof",
        IssueState::new("todo")?,
        "2026-07-02T00:00:00Z",
    )
}

fn manager(temp: &TempDir) -> Result<Manager, x0x_symphony_workspace::Error> {
    Manager::new(Config::new(temp.path().join("workspaces")))
}

fn process_exists(pid: i32) -> bool {
    matches!(kill(Pid::from_raw(pid), None), Ok(()) | Err(Errno::EPERM))
        && !matches!(kill(Pid::from_raw(pid), None), Err(Errno::ESRCH))
}

async fn wait_until_process_exits(pid: i32) {
    for _ in 0_u8..40 {
        if !process_exists(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn proof_hook_timeout_kills_forked_child_process_group() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;
    let handle = workspace.create_for_issue(&issue()?)?;

    // The hook forks a long-lived grandchild (`sleep 30`) and records its pid,
    // then waits. The workspace dir is the hook's cwd, so write the pid file
    // there and read it back from the handle path.
    let pid_file = handle.path.join("child.pid");
    let script = "sleep 30 & echo $! > child.pid; wait";
    let hook = Hook::new(HookName::BeforeRun, script, 200);

    let outcome = workspace
        .run_hook_in(&handle, &hook, &HookEnv::new())
        .await?;

    assert_eq!(outcome.status, HookStatus::TimedOut);

    let pid_text = timeout(Duration::from_secs(2), tokio::fs::read_to_string(&pid_file))
        .await
        .map_err(|_| "child.pid not written before timeout")??;
    let child_pid: i32 = pid_text.trim().parse()?;

    wait_until_process_exits(child_pid).await;
    assert!(
        !process_exists(child_pid),
        "forked hook grandchild must be killed with the process group"
    );

    Ok(())
}
