//! Path sanitization and root-containment helpers.

use std::path::{Path, PathBuf};

use crate::{WorkspaceManagerError, WorkspaceResult};

/// Convert an issue identifier into a safe workspace directory name.
///
/// Allowed characters are ASCII letters, ASCII digits, `.`, `_`, and `-`.
/// Other characters are replaced with `_`. Inputs containing `..` or starting
/// with `/` are rejected rather than rewritten.
///
/// # Errors
///
/// Returns an error when `identifier` is empty, begins with `/`, or contains
/// `..`.
///
/// # Examples
///
/// ```
/// use x0x_symphony_workspace::sanitize_issue_identifier;
///
/// assert_eq!(sanitize_issue_identifier("XSY:0005 workspace")?, "XSY_0005_workspace");
/// assert!(sanitize_issue_identifier("../XSY-0005").is_err());
/// # Ok::<(), x0x_symphony_workspace::WorkspaceManagerError>(())
/// ```
pub fn sanitize_issue_identifier(identifier: &str) -> WorkspaceResult<String> {
    let trimmed = identifier.trim();
    if trimmed.is_empty() {
        return Err(WorkspaceManagerError::InvalidIdentifier(
            "must not be empty".to_owned(),
        ));
    }
    if trimmed.starts_with('/') {
        return Err(WorkspaceManagerError::InvalidIdentifier(
            "must not be absolute".to_owned(),
        ));
    }
    if trimmed.contains("..") {
        return Err(WorkspaceManagerError::InvalidIdentifier(
            "must not contain traversal".to_owned(),
        ));
    }

    Ok(trimmed
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect())
}

/// Compute the deterministic workspace path for an issue identifier.
///
/// The returned path is `root/<sanitized-issue-id>`. `root` is expected to be
/// a canonical manager root; callers still validate the path after creation to
/// protect against filesystem races.
///
/// # Errors
///
/// Returns any error produced by [`sanitize_issue_identifier`].
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use x0x_symphony_workspace::workspace_path_for;
///
/// let path = workspace_path_for(Path::new("/tmp/workspaces"), "XSY:0005")?;
/// assert_eq!(path, Path::new("/tmp/workspaces/XSY_0005"));
/// # Ok::<(), x0x_symphony_workspace::WorkspaceManagerError>(())
/// ```
pub fn workspace_path_for(root: &Path, identifier: &str) -> WorkspaceResult<PathBuf> {
    let key = sanitize_issue_identifier(identifier)?;
    Ok(root.join(key))
}
