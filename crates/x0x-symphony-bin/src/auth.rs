//! x0x-style bearer token file handling.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// File name used for the local API bearer token.
pub const API_TOKEN_FILE: &str = "api-token";

/// Result alias for authentication helpers.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced while reading or writing bearer tokens.
#[derive(Debug, Error)]
pub enum Error {
    /// A data directory could not be created.
    #[error("failed to create data directory {path}: {source}")]
    CreateDataDir {
        /// Directory path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A token file could not be read.
    #[error("failed to read API token file {path}: {source}")]
    ReadToken {
        /// Token file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A token file could not be written.
    #[error("failed to write API token file {path}: {source}")]
    WriteToken {
        /// Token file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Permissions could not be tightened on the token file.
    #[error("failed to set 0600 permissions on API token file {path}: {source}")]
    SetPermissions {
        /// Token file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Return the API token path inside a daemon data directory.
#[must_use]
pub fn api_token_path(data_dir: &Path) -> PathBuf {
    data_dir.join(API_TOKEN_FILE)
}

/// Load an existing API token or generate a new 32-byte hex token.
///
/// The token file is always chmodded to `0600` on Unix, including when it
/// already existed before this call.
///
/// # Errors
///
/// Returns [`enum@Error`] when the data directory cannot be created, the token file
/// cannot be read or written, or Unix permissions cannot be tightened.
pub async fn load_or_generate_api_token(data_dir: &Path) -> Result<String> {
    tokio::fs::create_dir_all(data_dir)
        .await
        .map_err(|source| Error::CreateDataDir {
            path: data_dir.to_path_buf(),
            source,
        })?;
    let token_path = api_token_path(data_dir);
    match tokio::fs::read_to_string(&token_path).await {
        Ok(content) => {
            set_token_permissions(&token_path).await?;
            let token = content.trim().to_owned();
            if token.is_empty() {
                generate_and_store_token(&token_path).await
            } else {
                Ok(token)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            generate_and_store_token(&token_path).await
        }
        Err(source) => Err(Error::ReadToken {
            path: token_path,
            source,
        }),
    }
}

/// Read a token file and trim trailing whitespace.
///
/// # Errors
///
/// Returns [`Error::ReadToken`] when the file cannot be read.
pub async fn read_api_token(path: &Path) -> Result<String> {
    tokio::fs::read_to_string(path)
        .await
        .map(|content| content.trim().to_owned())
        .map_err(|source| Error::ReadToken {
            path: path.to_path_buf(),
            source,
        })
}

async fn generate_and_store_token(token_path: &Path) -> Result<String> {
    let token = hex::encode(rand::random::<[u8; 32]>());
    tokio::fs::write(token_path, &token)
        .await
        .map_err(|source| Error::WriteToken {
            path: token_path.to_path_buf(),
            source,
        })?;
    set_token_permissions(token_path).await?;
    Ok(token)
}

#[cfg(unix)]
async fn set_token_permissions(token_path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = std::fs::Permissions::from_mode(0o600);
    tokio::fs::set_permissions(token_path, permissions)
        .await
        .map_err(|source| Error::SetPermissions {
            path: token_path.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
async fn set_token_permissions(_token_path: &Path) -> Result<()> {
    Ok(())
}
