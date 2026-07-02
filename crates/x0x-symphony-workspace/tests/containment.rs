use std::{error::Error, fs, path::Path};

use tempfile::TempDir;
use x0x_symphony_core::{Hook, HookEnv, HookName, HookStatus, Issue, IssueId, IssueState};
use x0x_symphony_workspace::{
    containment::{sanitize_issue_identifier, ContainmentError},
    CleanupDecision, Config, Manager,
};

fn issue(identifier: &str) -> Result<Issue, x0x_symphony_core::SymphonyError> {
    Issue::new(
        IssueId::new(identifier.to_owned())?,
        identifier,
        "workspace test issue",
        IssueState::new("todo")?,
        "2026-07-02T00:00:00Z",
    )
}

fn manager(temp: &TempDir) -> Result<Manager, x0x_symphony_workspace::Error> {
    Manager::new(Config::new(temp.path().join("workspaces")))
}

#[cfg(unix)]
fn symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[test]
fn rejects_parent_traversal_identifier_dotdot_etc() -> Result<(), Box<dyn Error>> {
    let bad = issue("../../etc")?;
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;

    assert!(workspace.create_for_issue(&bad).is_err());
    Ok(())
}

#[test]
fn rejects_nested_parent_traversal_identifier_a_dotdot_b() -> Result<(), Box<dyn Error>> {
    let bad = issue("a/../../b")?;
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;

    assert!(workspace.create_for_issue(&bad).is_err());
    Ok(())
}

#[test]
fn rejects_absolute_path_identifier() -> Result<(), Box<dyn Error>> {
    let bad = issue("/tmp/escape")?;
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;

    assert!(workspace.create_for_issue(&bad).is_err());
    Ok(())
}

#[test]
fn rejects_slash_and_nul_identifiers() -> Result<(), Box<dyn Error>> {
    let slash = issue("bad/id")?;
    let nul = issue("bad\0id")?;
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;

    assert!(workspace.create_for_issue(&slash).is_err());
    assert!(workspace.create_for_issue(&nul).is_err());
    Ok(())
}

#[test]
fn rejects_unicode_fullwidth_dot_identifier() -> Result<(), Box<dyn Error>> {
    let bad = issue("bad．．id")?;
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;

    assert!(workspace.create_for_issue(&bad).is_err());
    Ok(())
}

#[test]
fn rejects_preplanted_symlink_inside_root_pointing_outside() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let outside = temp.path().join("outside");
    fs::create_dir(&outside)?;
    let workspace = manager(&temp)?;
    symlink_dir(&outside, &workspace.canonical_root().join("XSY-9999"))?;
    let bad = issue("XSY-9999")?;

    assert!(workspace.create_for_issue(&bad).is_err());
    Ok(())
}

#[test]
fn rejects_root_itself_identifier() -> Result<(), Box<dyn Error>> {
    let bad = issue(".")?;
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;

    assert!(workspace.create_for_issue(&bad).is_err());
    Ok(())
}

#[test]
fn rejects_4096_byte_identifier() -> Result<(), Box<dyn Error>> {
    let identifier = "A".repeat(4096);
    let bad = issue(&identifier)?;
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;

    assert!(workspace.create_for_issue(&bad).is_err());
    Ok(())
}

#[test]
fn rejects_trailing_dot_identifier() {
    assert!(matches!(
        sanitize_issue_identifier("XSY-0005."),
        Err(ContainmentError::TrailingDot)
    ));
}

#[test]
fn workspace_path_is_deterministic_from_sanitized_issue_id() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;
    let issue = issue("XSY-0005")?;

    let first = workspace.create_for_issue(&issue)?;
    let second = workspace.create_for_issue(&issue)?;

    assert_eq!(first.path, second.path);
    assert!(first.created_now);
    assert!(!second.created_now);
    assert_eq!(first.path, workspace.canonical_root().join("XSY-0005"));
    Ok(())
}

#[tokio::test]
async fn hook_timeout_produces_structured_outcome() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;
    let handle = workspace.create_for_issue(&issue("XSY-1000")?)?;
    let hook = Hook::new(HookName::BeforeRun, "while true; do :; done", 25);

    let outcome = workspace
        .run_hook_in(&handle, &hook, &HookEnv::new())
        .await?;

    assert_eq!(outcome.status, HookStatus::TimedOut);
    assert_eq!(outcome.exit_code, None);
    Ok(())
}

#[tokio::test]
async fn hook_pipefail_is_enforced() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;
    let handle = workspace.create_for_issue(&issue("XSY-1004")?)?;
    let hook = Hook::new(HookName::BeforeRun, "false | true", 1_000);

    let outcome = workspace
        .run_hook_in(&handle, &hook, &HookEnv::new())
        .await?;

    assert_eq!(outcome.status, HookStatus::Failed);
    Ok(())
}

#[tokio::test]
async fn poisoned_parent_environment_does_not_leak_to_hook() -> Result<(), Box<dyn Error>> {
    std::env::set_var("XSY_POISON_SECRET", "leaked");
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;
    let handle = workspace.create_for_issue(&issue("XSY-1001")?)?;
    let hook = Hook::new(
        HookName::BeforeRun,
        "printf '%s' \"${XSY_POISON_SECRET-unset}\"",
        1_000,
    );

    let outcome = workspace
        .run_hook_in(&handle, &hook, &HookEnv::new())
        .await?;

    assert_eq!(outcome.status, HookStatus::Succeeded);
    assert_eq!(outcome.stdout.as_deref(), Some("unset"));
    Ok(())
}

#[tokio::test]
async fn hook_sensitive_env_denied_without_explicit_allowlist() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;
    let handle = workspace.create_for_issue(&issue("XSY-1002")?)?;
    let hook = Hook::new(HookName::BeforeRun, "printf '%s' \"$API_TOKEN\"", 1_000);
    let env = HookEnv::new().with_var("API_TOKEN", "secret");

    assert!(workspace.run_hook_in(&handle, &hook, &env).await.is_err());
    Ok(())
}

#[tokio::test]
async fn hook_sensitive_env_allowed_when_explicitly_allowlisted() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let config = Config::new(temp.path().join("workspaces")).with_sensitive_env("API_TOKEN");
    let workspace = Manager::new(config)?;
    let handle = workspace.create_for_issue(&issue("XSY-1003")?)?;
    let hook = Hook::new(HookName::BeforeRun, "printf '%s' \"$API_TOKEN\"", 1_000);
    let env = HookEnv::new().with_var("API_TOKEN", "secret");

    let outcome = workspace.run_hook_in(&handle, &hook, &env).await?;

    assert_eq!(outcome.status, HookStatus::Succeeded);
    assert_eq!(outcome.stdout.as_deref(), Some("secret"));
    Ok(())
}

#[test]
fn destroy_refuses_symlink_escape_after_create() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let outside = temp.path().join("outside");
    fs::create_dir(&outside)?;
    let workspace = manager(&temp)?;
    let handle = workspace.create_for_issue(&issue("XSY-2000")?)?;
    fs::remove_dir(&handle.path)?;
    symlink_dir(&outside, &handle.path)?;

    assert!(workspace.destroy_workspace(handle).is_err());
    assert!(outside.exists());
    Ok(())
}

#[test]
fn destroy_refuses_replaced_root_symlink() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;
    let root = workspace.canonical_root().to_path_buf();
    let handle = workspace.create_for_issue(&issue("XSY-2001")?)?;
    let outside_root = temp.path().join("outside-root");
    fs::create_dir(&outside_root)?;
    fs::create_dir(outside_root.join("XSY-2001"))?;
    fs::remove_dir_all(&root)?;
    symlink_dir(&outside_root, &root)?;

    assert!(workspace.destroy_workspace(handle).is_err());
    assert!(outside_root.join("XSY-2001").exists());
    Ok(())
}

#[test]
fn cleanup_preserves_non_terminal_and_deletes_terminal() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;
    let retry_handle = workspace.create_for_issue(&issue("XSY-3000")?)?;
    let retry_path = retry_handle.path.clone();
    let terminal_states = [IssueState::new("done")?];

    let preserved =
        workspace.destroy_if_terminal(retry_handle, &IssueState::new("todo")?, &terminal_states)?;

    assert_eq!(preserved, CleanupDecision::PreservedRetry);
    assert!(retry_path.exists());

    let done_handle = workspace.create_for_issue(&issue("XSY-3001")?)?;
    let done_path = done_handle.path.clone();
    let removed =
        workspace.destroy_if_terminal(done_handle, &IssueState::new("done")?, &terminal_states)?;

    assert_eq!(removed, CleanupDecision::Removed);
    assert!(!done_path.exists());
    Ok(())
}

// Red-team regression tests (XSY-0005 containment review, MEDIUM findings).

#[test]
fn rejects_windows_reserved_device_name_identifier() {
    // Reserved device names are composed entirely of whitelisted ASCII bytes
    // but are not safe filesystem components on Windows. Reject the stem
    // case-insensitively, including extension forms like `CON.txt`.
    for name in [
        "CON", "con", "Con", "PRN", "AUX", "NUL", "COM1", "COM9", "LPT1", "LPT9", "CON.txt",
        "nul.bak", "com3.log",
    ] {
        assert!(
            matches!(
                sanitize_issue_identifier(name),
                Err(ContainmentError::ReservedDeviceName { .. })
            ),
            "{name:?} should be rejected as a reserved Windows device name"
        );
    }
}

#[test]
fn accepts_non_reserved_dotted_identifier() {
    // Sanity check: a normal dotted identifier that shares a prefix with a
    // reserved name but is not itself reserved must still be accepted, so the
    // device-name guard does not over-reject.
    assert!(sanitize_issue_identifier("concept.notes").is_ok());
    assert!(sanitize_issue_identifier("console-1").is_ok());
}

#[tokio::test]
async fn rejects_dangerous_shell_env_variables() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let workspace = manager(&temp)?;
    let handle = workspace.create_for_issue(&issue("XSY-4000")?)?;
    let hook = Hook::new(HookName::BeforeRun, "true", 1_000);

    for name in [
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "CDPATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
    ] {
        let env = HookEnv::new().with_var(name, "/tmp/evil");
        assert!(
            workspace.run_hook_in(&handle, &hook, &env).await.is_err(),
            "{name} should be rejected as a dangerous shell/linker variable"
        );
    }
    Ok(())
}
