//! Async HTTP client used by the `x0x-symphony` CLI.

use std::path::{Path, PathBuf};

use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use thiserror::Error;
use x0x_symphony_core::{ApprovalEvent, ApprovalVerdict, Issue, IssueDraft};

use crate::{
    api::{
        ClaimResponse, HandoffRequest, HandoffResponse, PendingApproval, Proof, ProofList, Routes,
        Status, SubmitApprovalRequest, Task,
    },
    auth, config,
};

/// Default daemon data directory.
pub const DEFAULT_DATA_DIR: &str = "~/.x0x-symphony";

/// Result alias for client operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Client construction options derived from global CLI flags.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Options {
    /// Explicit server URL, if supplied.
    pub server: Option<String>,
    /// Daemon data directory used for port and token defaults.
    pub data_dir: Option<PathBuf>,
    /// Explicit bearer token.
    pub token: Option<String>,
    /// Explicit token file path.
    pub token_file: Option<PathBuf>,
}

/// Errors produced by the CLI HTTP client.
#[derive(Debug, Error)]
pub enum Error {
    /// Data directory expansion failed.
    #[error(transparent)]
    Config(#[from] config::Error),
    /// Token file handling failed.
    #[error(transparent)]
    Auth(#[from] auth::Error),
    /// Reading the daemon port file failed.
    #[error("failed to read daemon port file {path}: {source}")]
    ReadPort {
        /// Port file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The daemon port file did not contain a valid TCP port.
    #[error("daemon port file {path} did not contain a valid port: {value}")]
    InvalidPort {
        /// Port file path.
        path: PathBuf,
        /// Raw file content after trimming.
        value: String,
    },
    /// The HTTP client could not be constructed.
    #[error("failed to construct HTTP client: {source}")]
    BuildClient {
        /// Underlying reqwest error.
        #[source]
        source: reqwest::Error,
    },
    /// A request failed before a response was received.
    #[error("request to {url} failed: {source}")]
    Request {
        /// Request URL.
        url: String,
        /// Underlying reqwest error.
        #[source]
        source: reqwest::Error,
    },
    /// A response body could not be decoded.
    #[error("failed to decode response from {url}: {source}")]
    Decode {
        /// Request URL.
        url: String,
        /// Underlying reqwest error.
        #[source]
        source: reqwest::Error,
    },
    /// The daemon returned a non-success status.
    #[error("daemon returned HTTP {status}: {body}")]
    Http {
        /// HTTP status code.
        status: StatusCode,
        /// Response body text.
        body: String,
    },
}

/// Authenticated client for the local daemon API.
#[derive(Clone, Debug)]
pub struct SymphonyClient {
    server: String,
    token: String,
    http: reqwest::Client,
}

impl Options {
    /// Resolve global CLI options into an authenticated client.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] when defaults cannot be read or the HTTP client cannot
    /// be built.
    pub async fn into_client(self) -> Result<SymphonyClient> {
        let data_dir = self.resolved_data_dir()?;
        let server = match self.server {
            Some(server) => server,
            None => server_from_port_file(&data_dir).await?,
        };
        let token = if let Some(token) = self.token {
            token
        } else {
            let token_file = match self.token_file {
                Some(path) => path,
                None => auth::api_token_path(&data_dir),
            };
            auth::read_api_token(&token_file).await?
        };
        SymphonyClient::new(&server, token)
    }

    fn resolved_data_dir(&self) -> Result<PathBuf> {
        match &self.data_dir {
            Some(path) => Ok(path.clone()),
            None => config::expand_tilde_path(DEFAULT_DATA_DIR, "data-dir").map_err(Into::into),
        }
    }
}

impl SymphonyClient {
    /// Construct a client from a server URL and bearer token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BuildClient`] if reqwest client construction fails.
    pub fn new(server: &str, token: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|source| Error::BuildClient { source })?;
        Ok(Self {
            server: server.trim_end_matches('/').to_owned(),
            token,
            http,
        })
    }

    /// List tasks, optionally filtered by state.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] for transport, status, or decoding failures.
    pub async fn tasks(&self, state: Option<&str>) -> Result<Vec<Task>> {
        let path = state.map_or_else(
            || "/symphony/tasks".to_owned(),
            |state| format!("/symphony/tasks?state={state}"),
        );
        self.get_json(&path).await
    }

    /// Fetch daemon status.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] for transport, status, or decoding failures.
    pub async fn status(&self) -> Result<Status> {
        self.get_json("/symphony/status").await
    }

    /// List network-sourced issues awaiting approval.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] for transport, status, or decoding failures.
    pub async fn approvals_pending(&self) -> Result<Vec<PendingApproval>> {
        self.get_json("/symphony/approvals/pending").await
    }

    /// Approve one network-sourced issue for dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] for transport, status, or decoding failures.
    pub async fn approve(
        &self,
        id: &str,
        expected_content_hash: Option<&str>,
        expected_signer_agent_id: Option<&str>,
    ) -> Result<ApprovalEvent> {
        self.submit_approval(
            id,
            ApprovalVerdict::Approve,
            expected_content_hash,
            expected_signer_agent_id,
        )
        .await
    }

    /// Deny one network-sourced issue for dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] for transport, status, or decoding failures.
    pub async fn deny(
        &self,
        id: &str,
        expected_content_hash: Option<&str>,
        expected_signer_agent_id: Option<&str>,
    ) -> Result<ApprovalEvent> {
        self.submit_approval(
            id,
            ApprovalVerdict::Deny,
            expected_content_hash,
            expected_signer_agent_id,
        )
        .await
    }

    /// Create a symphony-owned issue through the daemon tracker.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] for transport, status, or decoding failures.
    pub async fn create_issue(&self, draft: &IssueDraft) -> Result<Issue> {
        self.post_json("/symphony/issues", draft).await
    }

    /// Claim an issue.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] for transport, status, or decoding failures.
    pub async fn claim(&self, id: &str) -> Result<ClaimResponse> {
        self.post_empty_json(&format!("/symphony/claim/{id}")).await
    }

    /// Record a handoff for an issue.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] for transport, status, or decoding failures.
    pub async fn handoff(
        &self,
        id: &str,
        message: String,
        file: Option<String>,
    ) -> Result<HandoffResponse> {
        let request = HandoffRequest { message, file };
        self.post_json(&format!("/symphony/handoff/{id}"), &request)
            .await
    }

    /// List daemon routes.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] for transport, status, or decoding failures.
    pub async fn routes(&self) -> Result<Routes> {
        self.get_json("/symphony/routes").await
    }

    /// List proof artefacts.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] for transport, status, or decoding failures.
    pub async fn proofs(&self) -> Result<ProofList> {
        self.get_json("/symphony/proofs").await
    }

    /// Show one proof artefact.
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] for transport, status, or decoding failures.
    pub async fn proof(&self, name: &str) -> Result<Proof> {
        self.get_json(&format!("/symphony/proofs/{name}")).await
    }

    async fn submit_approval(
        &self,
        id: &str,
        verdict: ApprovalVerdict,
        expected_content_hash: Option<&str>,
        expected_signer_agent_id: Option<&str>,
    ) -> Result<ApprovalEvent> {
        let request = SubmitApprovalRequest {
            verdict,
            expected_content_hash: expected_content_hash.map(str::to_owned),
            expected_signer_agent_id: expected_signer_agent_id.map(str::to_owned),
        };
        self.post_json(&format!("/symphony/approvals/{id}"), &request)
            .await
    }

    async fn get_json<T>(&self, path: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let url = self.url(path);
        let response = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|source| Error::Request {
                url: url.clone(),
                source,
            })?;
        decode_response(response, &url).await
    }

    async fn post_empty_json<T>(&self, path: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let url = self.url(path);
        let response = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|source| Error::Request {
                url: url.clone(),
                source,
            })?;
        decode_response(response, &url).await
    }

    async fn post_json<T, B>(&self, path: &str, body: &B) -> Result<T>
    where
        T: DeserializeOwned,
        B: serde::Serialize + ?Sized,
    {
        let url = self.url(path);
        let response = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|source| Error::Request {
                url: url.clone(),
                source,
            })?;
        decode_response(response, &url).await
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server)
    }
}

async fn decode_response<T>(response: reqwest::Response, url: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let status = response.status();
    if status.is_success() {
        response.json::<T>().await.map_err(|source| Error::Decode {
            url: url.to_owned(),
            source,
        })
    } else {
        let body = response.text().await.map_err(|source| Error::Decode {
            url: url.to_owned(),
            source,
        })?;
        Err(Error::Http { status, body })
    }
}

async fn server_from_port_file(data_dir: &Path) -> Result<String> {
    let path = data_dir.join("daemon.port");
    let value = tokio::fs::read_to_string(&path)
        .await
        .map_err(|source| Error::ReadPort {
            path: path.clone(),
            source,
        })?;
    let trimmed = value.trim();
    if trimmed.parse::<u16>().is_err() {
        return Err(Error::InvalidPort {
            path,
            value: trimmed.to_owned(),
        });
    }
    Ok(format!("http://127.0.0.1:{trimmed}"))
}
