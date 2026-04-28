use std::path::PathBuf;

use x0x_symphony_core::{Hook, HookEnv, HookName, HookStatus, Issue, IssueId, IssueState};
use x0x_symphony_workspace::{
    sanitize_issue_identifier, WorkspaceConfig, WorkspaceManager, WorkspaceManagerError,
};

fn issue(identifier: &str) -> Result<Issue, Box<dyn std::error::Error>> {
    Ok(Issue::new(
        IssueId::new("XSY-0005")?,
        identifier,
        "Workspace manager",
        IssueState::new("todo")?,
        "2026-04-28T00:00:00Z",
    )?)
}

fn manager() -> Result<(tempfile::TempDir, WorkspaceManager), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let manager = WorkspaceManager::new(WorkspaceConfig::new(dir.path().join("workspaces")))?;
    Ok((dir, manager))
}

#[test]
fn sanitizes_issue_identifier_deterministically() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        sanitize_issue_identifier("XSY:0005 workspace")?,
        "XSY_0005_workspace"
    );
    assert!(sanitize_issue_identifier("../XSY-0005").is_err());
    assert!(sanitize_issue_identifier("/tmp/XSY-0005").is_err());
    Ok(())
}

#[tokio::test]
async fn creates_and_reuses_deterministic_workspace() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, manager) = manager()?;
    let issue = issue("XSY-0005")?;

    let first = manager.create_workspace(&issue).await?;
    let second = manager.create_workspace(&issue).await?;

    assert!(first.created_now);
    assert!(!second.created_now);
    assert_eq!(first.path, second.path);
    assert!(first.path.ends_with("XSY-0005"));
    Ok(())
}

#[tokio::test]
async fn rejects_traversal_and_absolute_identifiers() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, manager) = manager()?;

    let traversal = manager.create_workspace(&issue("../XSY-0005")?).await;
    assert!(matches!(
        traversal,
        Err(WorkspaceManagerError::InvalidIdentifier(_))
    ));

    let absolute = manager.create_workspace(&issue("/tmp/XSY-0005")?).await;
    assert!(matches!(
        absolute,
        Err(WorkspaceManagerError::InvalidIdentifier(_))
    ));
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_symlink_workspace_component() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("workspaces");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&outside)?;
    std::os::unix::fs::symlink(&outside, root.join("XSY-0005"))?;

    let manager = WorkspaceManager::new(WorkspaceConfig::new(root))?;
    let result = manager.create_workspace(&issue("XSY-0005")?).await;

    assert!(matches!(
        result,
        Err(WorkspaceManagerError::SymlinkRejected(_))
    ));
    Ok(())
}

#[tokio::test]
async fn runs_hook_in_workspace_and_captures_output() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, manager) = manager()?;
    let handle = manager.create_workspace(&issue("XSY-0005")?).await?;
    let hook = Hook::new(HookName::BeforeRun, "pwd", 1_000);

    let outcome = manager
        .run_hook_for(&handle, &hook, &HookEnv::new())
        .await?;

    assert_eq!(outcome.status, HookStatus::Succeeded);
    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(
        outcome.stdout.as_deref().map(str::trim),
        Some(handle.path.to_string_lossy().as_ref())
    );
    Ok(())
}

#[tokio::test]
async fn hook_timeout_produces_structured_outcome() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, manager) = manager()?;
    let handle = manager.create_workspace(&issue("XSY-0005")?).await?;
    let hook = Hook::new(HookName::BeforeRun, "sleep 2", 50);

    let outcome = manager
        .run_hook_for(&handle, &hook, &HookEnv::new())
        .await?;

    assert_eq!(outcome.status, HookStatus::TimedOut);
    Ok(())
}

#[tokio::test]
async fn secret_like_environment_requires_exact_allowlist() -> Result<(), Box<dyn std::error::Error>>
{
    let (_dir, manager) = manager()?;
    let handle = manager.create_workspace(&issue("XSY-0005")?).await?;
    let hook = Hook::new(HookName::BeforeRun, "true", 1_000);

    let denied = manager
        .run_hook_for(
            &handle,
            &hook,
            &HookEnv::new().with_var("API_TOKEN", "secret"),
        )
        .await;

    assert!(matches!(
        denied,
        Err(WorkspaceManagerError::DeniedEnvironment(name)) if name == "API_TOKEN"
    ));
    Ok(())
}

#[tokio::test]
async fn explicitly_allowlisted_secret_environment_is_forwarded(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let manager = WorkspaceManager::new(
        WorkspaceConfig::new(dir.path().join("workspaces")).with_secret_env("API_TOKEN"),
    )?;
    let handle = manager.create_workspace(&issue("XSY-0005")?).await?;
    let hook = Hook::new(HookName::BeforeRun, "test \"$API_TOKEN\" = secret", 1_000);

    let outcome = manager
        .run_hook_for(
            &handle,
            &hook,
            &HookEnv::new().with_var("API_TOKEN", "secret"),
        )
        .await?;

    assert_eq!(outcome.status, HookStatus::Succeeded);
    Ok(())
}

#[tokio::test]
async fn destroy_for_state_preserves_retries_and_deletes_terminal(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, manager) = manager()?;
    let handle = manager.create_workspace(&issue("XSY-0005")?).await?;
    let terminal = vec![IssueState::new("done")?];

    let preserved = manager
        .destroy_for_state(&handle, &IssueState::new("in_progress")?, &terminal)
        .await?;
    assert!(!preserved);
    assert!(handle.path.exists());

    let deleted = manager
        .destroy_for_state(&handle, &IssueState::new("done")?, &terminal)
        .await?;
    assert!(deleted);
    assert!(!handle.path.exists());

    manager.destroy_workspace(&handle).await?;
    Ok(())
}

#[tokio::test]
async fn configured_hook_rejects_workspace_path_outside_root(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, manager) = manager()?;
    let hook = Hook::new(HookName::BeforeRun, "true", 1_000);
    let env = HookEnv::new().with_var(
        x0x_symphony_workspace::WORKSPACE_PATH_ENV,
        PathBuf::from("/").to_string_lossy(),
    );

    let result = manager.run_configured_hook(&hook, &env).await;
    assert!(matches!(
        result,
        Err(WorkspaceManagerError::RootEscape { .. })
    ));
    Ok(())
}
