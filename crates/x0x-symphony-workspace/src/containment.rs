//! Path containment and issue identifier sanitization.
//!
//! The functions in this module are intentionally small and independently
//! testable because they sit on the workspace security boundary. Identifiers
//! are accepted only when they are already safe path segments; this module never
//! rewrites or normalizes attacker-controlled input into a different name.

use std::{
    ffi::OsStr,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use thiserror::Error;

/// Maximum accepted issue identifier length in bytes.
///
/// The limit keeps each workspace name below the common POSIX single-component
/// filename limit and rejects oversized inputs before they reach the
/// filesystem.
pub const MAX_IDENTIFIER_BYTES: usize = 255;

/// Sanitized issue identifier that is safe to use as one path component.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SanitizedIdentifier(String);

impl SanitizedIdentifier {
    /// Validate and store one issue identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ContainmentError`] when `raw` is empty, too long, starts with a
    /// dot or slash, ends with a dot, contains `..`, or contains a byte outside
    /// `[A-Za-z0-9._-]`.
    pub fn new(raw: &str) -> Result<Self, ContainmentError> {
        sanitize_issue_identifier(raw)
    }

    /// Borrow the sanitized identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SanitizedIdentifier {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SanitizedIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Errors produced by containment checks.
#[derive(Debug, Error)]
pub enum ContainmentError {
    /// The identifier is empty.
    #[error("issue identifier must not be empty")]
    EmptyIdentifier,

    /// The identifier is longer than [`MAX_IDENTIFIER_BYTES`].
    #[error("issue identifier is {actual} bytes; maximum is {max} bytes")]
    IdentifierTooLong {
        /// Actual byte length.
        actual: usize,
        /// Maximum accepted byte length.
        max: usize,
    },

    /// The identifier starts with `.`.
    #[error("issue identifier must not start with '.'")]
    LeadingDot,

    /// The identifier starts with `/`.
    #[error("issue identifier must not start with '/'")]
    LeadingSlash,

    /// The identifier ends with `.`.
    #[error("issue identifier must not end with '.'")]
    TrailingDot,

    /// The identifier contains `..`.
    #[error("issue identifier must not contain '..'")]
    ParentTraversal,

    /// The identifier contains a byte outside the whitelist.
    #[error("issue identifier contains non-whitelisted byte 0x{byte:02x} at offset {offset}")]
    NonWhitelistedByte {
        /// Byte offset in the input string.
        offset: usize,
        /// Rejected byte value.
        byte: u8,
    },

    /// The identifier matches a Windows reserved device name (e.g. `CON`,
    /// `PRN`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`). These names are composed
    /// entirely of whitelisted bytes but are not safe filesystem components on
    /// Windows: they resolve to devices instead of directories. The check is
    /// applied to the name stem (the bytes before the first `.`),
    /// case-insensitively, matching the Windows resolver's behaviour for
    /// names like `CON`, `con`, and `CON.txt`.
    #[error("issue identifier matches a reserved Windows device name: {stem}")]
    ReservedDeviceName {
        /// The matched (uppercased) device-name stem.
        stem: String,
    },

    /// A path that must be absolute was relative.
    #[error("workspace path is not absolute: {path}", path = .path.display())]
    RelativePath {
        /// Rejected path.
        path: PathBuf,
    },

    /// The workspace root exists but is not a directory.
    #[error("workspace root is not a directory: {path}", path = .path.display())]
    RootNotDirectory {
        /// Rejected root path.
        path: PathBuf,
    },

    /// The candidate path resolved outside the canonical root.
    #[error("workspace path escaped root: root={root}, path={path}", root = .root.display(), path = .path.display())]
    EscapesRoot {
        /// Canonical workspace root.
        root: PathBuf,
        /// Canonical candidate path.
        path: PathBuf,
    },

    /// The candidate path resolved to the workspace root itself.
    #[error("workspace path resolves to root itself: {path}", path = .path.display())]
    RootItself {
        /// Canonical candidate path.
        path: PathBuf,
    },

    /// The candidate path is not a direct child of the root.
    #[error("workspace path is not a direct child of root: root={root}, path={path}", root = .root.display(), path = .path.display())]
    NotDirectChild {
        /// Canonical workspace root.
        root: PathBuf,
        /// Canonical candidate path.
        path: PathBuf,
    },

    /// The requested and resolved names differ.
    #[error("workspace path alias mismatch: requested {requested:?}, resolved {resolved:?}")]
    AliasMismatch {
        /// Name requested by the caller.
        requested: String,
        /// Name returned by canonicalization.
        resolved: String,
    },

    /// A path component could not be represented as UTF-8.
    #[error("workspace path has no UTF-8 file name: {path}", path = .path.display())]
    MissingFileName {
        /// Rejected path.
        path: PathBuf,
    },

    /// Filesystem metadata lookup failed.
    #[error("failed to read metadata for {path}: {source}", path = .path.display())]
    Metadata {
        /// Path being queried.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// Canonicalization failed.
    #[error("failed to canonicalize {path}: {source}", path = .path.display())]
    Canonicalize {
        /// Path being canonicalized.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },
}

/// Validate an issue identifier as one safe filesystem path component.
///
/// # Errors
///
/// Returns [`ContainmentError`] for empty input, long input, path traversal,
/// leading or trailing dot hardening failures, leading slash, Unicode or other
/// non-whitelisted bytes, and embedded NUL bytes.
pub fn sanitize_issue_identifier(raw: &str) -> Result<SanitizedIdentifier, ContainmentError> {
    if raw.is_empty() {
        return Err(ContainmentError::EmptyIdentifier);
    }
    if raw.len() > MAX_IDENTIFIER_BYTES {
        return Err(ContainmentError::IdentifierTooLong {
            actual: raw.len(),
            max: MAX_IDENTIFIER_BYTES,
        });
    }
    if raw.starts_with('.') {
        return Err(ContainmentError::LeadingDot);
    }
    if raw.starts_with('/') {
        return Err(ContainmentError::LeadingSlash);
    }
    if raw.ends_with('.') {
        return Err(ContainmentError::TrailingDot);
    }
    if raw.as_bytes().windows(2).any(|window| window == b"..") {
        return Err(ContainmentError::ParentTraversal);
    }

    for (offset, byte) in raw.bytes().enumerate() {
        if !is_allowed_identifier_byte(byte) {
            return Err(ContainmentError::NonWhitelistedByte { offset, byte });
        }
    }

    // Defense in depth: reject identifiers whose stem (bytes before the first
    // `.`) matches a Windows reserved device name. These pass the ASCII
    // whitelist but resolve to devices rather than directories on Windows.
    // See the red-team review of XSY-0005 (MEDIUM finding).
    let stem = match raw.split('.').next() {
        Some(value) => value,
        None => raw,
    };
    let upper_stem = stem.to_ascii_uppercase();
    if is_reserved_windows_device_name(&upper_stem) {
        return Err(ContainmentError::ReservedDeviceName { stem: upper_stem });
    }

    Ok(SanitizedIdentifier(raw.to_owned()))
}

/// Return true when `upper_stem` (already ASCII-uppercased) is a Windows
/// reserved device name.
///
/// Covers `CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, and `LPT1`..`LPT9`.
/// `CONIN$`/`CONOUT$`/`CLOCK$` contain `$`, which the identifier whitelist
/// already rejects, so they are not enumerated here.
#[must_use]
fn is_reserved_windows_device_name(upper_stem: &str) -> bool {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    RESERVED.contains(&upper_stem)
}

/// Build the deterministic workspace path for a sanitized identifier.
#[must_use]
pub fn deterministic_path(root: &Path, identifier: &SanitizedIdentifier) -> PathBuf {
    root.join(identifier.as_str())
}

/// Canonicalize an existing workspace root and require it to be a directory.
///
/// # Errors
///
/// Returns [`ContainmentError`] when the root cannot be canonicalized, resolves
/// to a relative path, or is not a directory.
pub fn canonicalize_root(root: &Path) -> Result<PathBuf, ContainmentError> {
    let canonical = fs::canonicalize(root).map_err(|source| ContainmentError::Canonicalize {
        path: root.to_path_buf(),
        source,
    })?;
    if !canonical.is_absolute() {
        return Err(ContainmentError::RelativePath { path: canonical });
    }

    let metadata = fs::metadata(&canonical).map_err(|source| ContainmentError::Metadata {
        path: canonical.clone(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(ContainmentError::RootNotDirectory { path: canonical });
    }

    Ok(canonical)
}

/// Canonicalize an existing workspace path and verify it remains contained.
///
/// `root` must be the already canonicalized trust anchor returned by
/// [`canonicalize_root`]. It is intentionally not re-canonicalized here: if an
/// attacker replaces the root path with a symlink after manager construction,
/// the stored canonical root remains the prefix used for fail-closed checks.
///
/// The candidate must resolve to a direct child of `root`, not `root` itself.
/// The final component returned by canonicalization must match the requested
/// component exactly, which closes case-folding and symlink alias collisions on
/// case-insensitive filesystems.
///
/// # Errors
///
/// Returns [`ContainmentError`] when the root is not absolute, when the
/// candidate cannot be canonicalized, when the candidate escapes the root, when
/// it is not a direct child, when it resolves to the root itself, or when the
/// requested/resolved final component differs.
pub fn validate_existing_workspace_path(
    root: &Path,
    candidate: &Path,
) -> Result<PathBuf, ContainmentError> {
    if !root.is_absolute() {
        return Err(ContainmentError::RelativePath {
            path: root.to_path_buf(),
        });
    }
    if !candidate.is_absolute() {
        return Err(ContainmentError::RelativePath {
            path: candidate.to_path_buf(),
        });
    }

    let requested_name = utf8_file_name(candidate)?;
    sanitize_issue_identifier(&requested_name)?;

    let canonical_root = root.to_path_buf();
    let canonical_candidate =
        fs::canonicalize(candidate).map_err(|source| ContainmentError::Canonicalize {
            path: candidate.to_path_buf(),
            source,
        })?;

    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(ContainmentError::EscapesRoot {
            root: canonical_root,
            path: canonical_candidate,
        });
    }
    if canonical_candidate == canonical_root {
        return Err(ContainmentError::RootItself {
            path: canonical_candidate,
        });
    }
    if canonical_candidate.parent() != Some(canonical_root.as_path()) {
        return Err(ContainmentError::NotDirectChild {
            root: canonical_root,
            path: canonical_candidate,
        });
    }

    let resolved_name = utf8_file_name(&canonical_candidate)?;
    if requested_name != resolved_name {
        return Err(ContainmentError::AliasMismatch {
            requested: requested_name,
            resolved: resolved_name,
        });
    }

    Ok(canonical_candidate)
}

fn is_allowed_identifier_byte(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-')
}

fn utf8_file_name(path: &Path) -> Result<String, ContainmentError> {
    path.file_name()
        .and_then(OsStr::to_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ContainmentError::MissingFileName {
            path: path.to_path_buf(),
        })
}
