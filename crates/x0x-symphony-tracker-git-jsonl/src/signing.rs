//! x0xd-backed signing and verification abstractions for the JSONL tracker.
//!
//! The tracker signs at the async trait boundary. Tests inject mock clients and
//! key resolvers; production uses [`X0xdClient`] to call `/agent/sign` and
//! `/agent/verify` without linking x0x as a Rust dependency.

use std::{env, sync::Mutex};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use x0x_symphony_core::SIGN_ALGORITHM;

/// Maximum payload bytes accepted by x0xd's external signing endpoints.
pub const MAX_SIGNING_PAYLOAD_BYTES: usize = 64 * 1024;

/// Signing mode for claim and handoff payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningPolicy {
    /// Do not sign writes and do not verify reads; intended for local dev only.
    Disabled,
    /// Sign writes and verify signed records on read; invalid records are hidden.
    Required,
}

impl SigningPolicy {
    /// Parse a workflow policy string.
    #[must_use]
    pub fn from_config_value(value: &str) -> Option<Self> {
        match value {
            "disabled" => Some(Self::Disabled),
            "required" => Some(Self::Required),
            _ => None,
        }
    }

    /// Stable lowercase spelling used in workflow config.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Required => "required",
        }
    }
}

/// x0xd sign response normalized for tracker use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignResponse {
    /// x0x signer agent id in hex.
    pub agent_id: String,
    /// Base64 ML-DSA-65 public key returned by x0xd.
    pub public_key_b64: String,
    /// Base64 detached ML-DSA-65 signature returned by x0xd.
    pub signature_b64: String,
    /// Signing algorithm string returned by x0xd.
    pub algorithm: String,
    /// Domain-separation context echoed by x0xd.
    pub context: String,
}

/// x0xd agent identity response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentInfo {
    /// x0x agent id in hex.
    pub agent_id: String,
}

/// Async signing/verification client used by the tracker boundary.
#[async_trait]
pub trait SigningClient: Send + Sync {
    /// Sign raw payload bytes under a domain-separation context.
    async fn sign(&self, context: &str, payload: &[u8]) -> Result<SignResponse>;

    /// Verify raw payload bytes under a domain-separation context.
    async fn verify(
        &self,
        context: &str,
        payload: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool>;

    /// Return the local x0xd agent identity.
    async fn agent_identity(&self) -> Result<AgentInfo>;
}

/// Resolver for trusted ML-DSA-65 public keys.
#[async_trait]
pub trait TrustedKeyResolver: Send + Sync {
    /// Resolve the trusted ML-DSA-65 public key bytes for an agent id.
    async fn resolve(&self, agent_id: &str) -> Result<Vec<u8>>;
}

/// Result alias for signing operations.
pub type Result<T> = std::result::Result<T, SigningError>;

/// Errors produced while signing or verifying records.
#[derive(Debug, Error)]
pub enum SigningError {
    /// The reqwest client could not be constructed.
    #[error("failed to construct x0xd HTTP client: {source}")]
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

    /// x0xd returned a non-success status.
    #[error("x0xd returned HTTP {status}: {body}")]
    Http {
        /// HTTP status code.
        status: StatusCode,
        /// Response body text.
        body: String,
    },

    /// Base64 decoding failed.
    #[error("invalid base64 in {field}: {source}")]
    Base64 {
        /// Field name that failed.
        field: &'static str,
        /// Decode error.
        #[source]
        source: base64::DecodeError,
    },

    /// x0xd returned a response that does not match the request.
    #[error("invalid sign response: {0}")]
    InvalidResponse(String),

    /// Payload exceeds x0xd's external signing cap.
    #[error("payload exceeds maximum signable size of {max} bytes: {actual}")]
    PayloadTooLarge {
        /// Maximum accepted bytes.
        max: usize,
        /// Actual payload size.
        actual: usize,
    },

    /// The trusted key resolver rejected the signer.
    #[error("trusted key rejected: {0}")]
    UntrustedKey(String),
}

/// HTTP client for x0xd's external signing endpoints.
#[derive(Debug)]
pub struct X0xdClient {
    base_url: String,
    token: Option<String>,
    http: reqwest::Client,
    trusted_local_key: Mutex<Option<TrustedLocalKey>>,
}

impl X0xdClient {
    /// Construct a client for an x0xd base URL.
    ///
    /// The bearer token is read from `X0X_API_TOKEN` when present. Operators who
    /// use x0x's default token file can export that secret before starting
    /// x0x-symphonyd.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError::BuildClient`] when reqwest client construction
    /// fails.
    pub fn new(base_url: &str) -> Result<Self> {
        let token = env::var("X0X_API_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());
        Self::with_token(base_url, token)
    }

    /// Construct a client with an explicit optional bearer token.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError::BuildClient`] when reqwest client construction
    /// fails.
    pub fn with_token(base_url: &str, token: Option<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|source| SigningError::BuildClient { source })?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            token,
            http,
            trusted_local_key: Mutex::new(None),
        })
    }

    async fn post_json<T, B>(&self, path: &str, body: &B) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = self.url(path);
        let mut request = self.http.post(&url).json(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|source| SigningError::Request {
                url: url.clone(),
                source,
            })?;
        decode_response(response, &url).await
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
        let response = request
            .send()
            .await
            .map_err(|source| SigningError::Request {
                url: url.clone(),
                source,
            })?;
        decode_response(response, &url).await
    }

    fn remember_key(&self, agent_id: &str, public_key_b64: &str) -> Result<()> {
        let key = BASE64
            .decode(public_key_b64)
            .map_err(|source| SigningError::Base64 {
                field: "public_key_b64",
                source,
            })?;
        if let Ok(mut trusted) = self.trusted_local_key.lock() {
            *trusted = Some(TrustedLocalKey {
                agent_id: agent_id.to_owned(),
                public_key: key,
            });
        }
        Ok(())
    }

    async fn bootstrap_key(&self) -> Result<()> {
        let _response = self
            .sign(
                x0x_symphony_core::CLAIM_CONTEXT,
                b"x0x-symphony-key-bootstrap",
            )
            .await?;
        Ok(())
    }

    fn cached_key(&self, agent_id: &str) -> Option<Result<Vec<u8>>> {
        let trusted = self.trusted_local_key.lock().ok()?;
        trusted.as_ref().map(|entry| {
            if entry.agent_id == agent_id {
                Ok(entry.public_key.clone())
            } else {
                Err(SigningError::UntrustedKey(format!(
                    "agent {agent_id} is not the local x0xd signer {}",
                    entry.agent_id
                )))
            }
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }
}

#[async_trait]
impl SigningClient for X0xdClient {
    async fn sign(&self, context: &str, payload: &[u8]) -> Result<SignResponse> {
        if payload.len() > MAX_SIGNING_PAYLOAD_BYTES {
            return Err(SigningError::PayloadTooLarge {
                max: MAX_SIGNING_PAYLOAD_BYTES,
                actual: payload.len(),
            });
        }
        let request = AgentSignRequest {
            context: context.to_owned(),
            payload_b64: BASE64.encode(payload),
        };
        let response: AgentSignResponse = self.post_json("/agent/sign", &request).await?;
        if response.algorithm != SIGN_ALGORITHM {
            return Err(SigningError::InvalidResponse(format!(
                "algorithm {} did not match {SIGN_ALGORITHM}",
                response.algorithm
            )));
        }
        if response.context != context {
            return Err(SigningError::InvalidResponse(format!(
                "context {} did not match {context}",
                response.context
            )));
        }
        self.remember_key(&response.agent_id, &response.public_key_b64)?;
        Ok(SignResponse {
            agent_id: response.agent_id,
            public_key_b64: response.public_key_b64,
            signature_b64: response.signature_b64,
            algorithm: response.algorithm,
            context: response.context,
        })
    }

    async fn verify(
        &self,
        context: &str,
        payload: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool> {
        if payload.len() > MAX_SIGNING_PAYLOAD_BYTES {
            return Err(SigningError::PayloadTooLarge {
                max: MAX_SIGNING_PAYLOAD_BYTES,
                actual: payload.len(),
            });
        }
        let request = AgentVerifyRequest {
            context: context.to_owned(),
            payload_b64: BASE64.encode(payload),
            signature_b64: BASE64.encode(signature),
            public_key_b64: BASE64.encode(public_key),
            algorithm: SIGN_ALGORITHM.to_owned(),
        };
        let response: AgentVerifyResponse = self.post_json("/agent/verify", &request).await?;
        Ok(response.valid)
    }

    async fn agent_identity(&self) -> Result<AgentInfo> {
        let response: AgentInfoResponse = self.get_json("/agent").await?;
        Ok(AgentInfo {
            agent_id: response.agent_id,
        })
    }
}

#[async_trait]
impl TrustedKeyResolver for X0xdClient {
    async fn resolve(&self, agent_id: &str) -> Result<Vec<u8>> {
        if let Some(result) = self.cached_key(agent_id) {
            return result;
        }
        self.bootstrap_key().await?;
        self.cached_key(agent_id).ok_or_else(|| {
            SigningError::UntrustedKey("local x0xd signing key was not cached".to_owned())
        })?
    }
}

#[derive(Debug)]
struct TrustedLocalKey {
    agent_id: String,
    public_key: Vec<u8>,
}

#[derive(Serialize)]
struct AgentSignRequest {
    context: String,
    payload_b64: String,
}

#[derive(Deserialize)]
struct AgentSignResponse {
    agent_id: String,
    public_key_b64: String,
    signature_b64: String,
    algorithm: String,
    context: String,
}

#[derive(Serialize)]
struct AgentVerifyRequest {
    payload_b64: String,
    signature_b64: String,
    public_key_b64: String,
    context: String,
    algorithm: String,
}

#[derive(Deserialize)]
struct AgentVerifyResponse {
    valid: bool,
}

#[derive(Deserialize)]
struct AgentInfoResponse {
    agent_id: String,
}

async fn decode_response<T>(response: reqwest::Response, url: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let status = response.status();
    if status.is_success() {
        response
            .json::<T>()
            .await
            .map_err(|source| SigningError::Decode {
                url: url.to_owned(),
                source,
            })
    } else {
        let body = response
            .text()
            .await
            .map_err(|source| SigningError::Decode {
                url: url.to_owned(),
                source,
            })?;
        Err(SigningError::Http { status, body })
    }
}
