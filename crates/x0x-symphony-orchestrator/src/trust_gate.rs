//! Trust-level client and x0xd `/contacts` integration for dispatch gates.

use std::{env, fmt, str::FromStr};

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize};

use crate::{Error, Result};

/// Trust relationship assigned by x0xd's contacts store.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum TrustLevel {
    /// Explicitly untrusted and always blocked from network-sourced dispatch.
    Blocked,
    /// No trust relationship is known.
    Unknown,
    /// Recognized, but not fully trusted.
    Known,
    /// Fully trusted for security-sensitive dispatch by default.
    #[default]
    Trusted,
}

impl TrustLevel {
    /// Stable x0xd string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Unknown => "unknown",
            Self::Known => "known",
            Self::Trusted => "trusted",
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TrustLevel {
    type Err = TrustLevelParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "blocked" => Ok(Self::Blocked),
            "unknown" => Ok(Self::Unknown),
            "known" => Ok(Self::Known),
            "trusted" => Ok(Self::Trusted),
            _ => Err(TrustLevelParseError {
                value: value.to_owned(),
            }),
        }
    }
}

/// Error returned when a trust level string is not part of x0xd's contract.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("unknown trust level {value:?}; expected blocked, unknown, known, or trusted")]
pub struct TrustLevelParseError {
    value: String,
}

/// Network-sourced dispatch behavior selected by workflow configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkDispatchPolicy {
    /// Refuse every network-sourced dispatch attempt.
    Off,
    /// Refuse execution until the approval lifecycle grants this task.
    Approve,
    /// Execute after the existing verified-signature and trust checks pass.
    Auto,
}

impl NetworkDispatchPolicy {
    /// Stable workflow configuration string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Approve => "approve",
            Self::Auto => "auto",
        }
    }
}

impl fmt::Display for NetworkDispatchPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NetworkDispatchPolicy {
    type Err = NetworkDispatchPolicyParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "approve" => Ok(Self::Approve),
            "auto" => Ok(Self::Auto),
            _ => Err(NetworkDispatchPolicyParseError {
                value: value.to_owned(),
            }),
        }
    }
}

/// Error returned when a network dispatch policy string is not recognized.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("unknown network dispatch policy {value:?}; expected off, approve, or auto")]
pub struct NetworkDispatchPolicyParseError {
    value: String,
}

/// Trust lookup abstraction used by the orchestrator dispatch gate.
#[async_trait]
pub trait TrustClient: Send + Sync {
    /// Return the trust level for `agent_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the backing trust store cannot be queried or
    /// returns malformed data.
    async fn trust_level(&self, agent_id: &str) -> Result<TrustLevel>;
}

/// Reqwest-backed trust client for x0xd's local `/contacts` API.
#[derive(Debug)]
pub struct X0xdTrustClient {
    base_url: String,
    token: Option<String>,
    http: reqwest::Client,
}

impl X0xdTrustClient {
    /// Construct a trust client for an x0xd base URL.
    ///
    /// The bearer token is read from `X0XD_TOKEN` or `X0X_API_TOKEN` when
    /// present.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TrustClientBuild`] when reqwest client construction
    /// fails.
    pub fn new(base_url: &str) -> Result<Self> {
        let token = non_empty_env("X0XD_TOKEN").or_else(|| non_empty_env("X0X_API_TOKEN"));
        Self::with_token(base_url, token)
    }

    /// Construct a trust client with an explicit optional bearer token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TrustClientBuild`] when reqwest client construction
    /// fails.
    pub fn with_token(base_url: &str, token: Option<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|source| Error::TrustClientBuild { source })?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            token,
            http,
        })
    }

    /// Return the normalized base URL used by this client.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn get_json<T>(&self, path: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let url = self.url(path);
        let mut request = self.http.get(&url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(|source| Error::TrustRequest {
            url: url.clone(),
            source,
        })?;
        decode_response(response, &url).await
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }
}

#[async_trait]
impl TrustClient for X0xdTrustClient {
    async fn trust_level(&self, agent_id: &str) -> Result<TrustLevel> {
        let contacts = self
            .get_json::<ContactsResponse>("/contacts")
            .await?
            .into_contacts();
        let Some(contact) = contacts
            .into_iter()
            .find(|contact| contact.agent_id == agent_id)
        else {
            return Ok(TrustLevel::Unknown);
        };
        contact.trust_level.parse().map_err(Into::into)
    }
}

#[derive(Debug, Default)]
pub(crate) struct UnknownTrustClient;

#[async_trait]
impl TrustClient for UnknownTrustClient {
    async fn trust_level(&self, _agent_id: &str) -> Result<TrustLevel> {
        Ok(TrustLevel::Unknown)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ContactsResponse {
    Wrapped { contacts: Vec<ContactEntry> },
    Bare(Vec<ContactEntry>),
}

impl ContactsResponse {
    fn into_contacts(self) -> Vec<ContactEntry> {
        match self {
            Self::Wrapped { contacts } | Self::Bare(contacts) => contacts,
        }
    }
}

#[derive(Deserialize)]
struct ContactEntry {
    agent_id: String,
    trust_level: String,
}

async fn decode_response<T>(response: reqwest::Response, url: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    if response.status().is_success() {
        response
            .json::<T>()
            .await
            .map_err(|source| Error::TrustDecode {
                url: url.to_owned(),
                source,
            })
    } else {
        let status = response.status();
        let body = response.text().await.map_err(|source| Error::TrustDecode {
            url: url.to_owned(),
            source,
        })?;
        Err(Error::TrustHttp { status, body })
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

impl From<TrustLevelParseError> for Error {
    fn from(source: TrustLevelParseError) -> Self {
        Self::TrustLevel { source }
    }
}
