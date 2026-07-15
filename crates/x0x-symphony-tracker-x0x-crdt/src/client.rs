//! Typed HTTP client for x0xd's `TaskList`, `KvStore`, and event endpoints.

use std::{env, pin::Pin};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures_core::Stream;
use futures_util::StreamExt;
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

/// Stream returned by [`X0xdApi::subscribe_events`].
pub type EventStream = Pin<Box<dyn Stream<Item = Result<X0xdEvent>> + Send>>;

/// Result alias for x0xd client operations.
pub type Result<T> = std::result::Result<T, ClientError>;

/// Errors produced while talking to x0xd.
#[derive(Debug, Error)]
pub enum ClientError {
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
}

/// x0xd `TaskList` entry returned by `GET /task-lists`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaskListEntry {
    /// `TaskList` identifier. x0xd currently uses the topic as the id.
    pub id: String,
    /// Gossip topic backing the `TaskList`.
    pub topic: String,
}

/// x0xd named group entry returned by `GET /groups`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NamedGroupEntry {
    /// Stable MLS/named-group identifier.
    pub group_id: String,
    /// Human-readable group name.
    pub name: String,
}

/// x0xd named group details returned by `GET /groups/:id`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NamedGroupDetails {
    /// Stable MLS/named-group identifier.
    pub group_id: String,
    /// Human-readable group name.
    pub name: String,
    /// Local roster projection returned by x0xd.
    #[serde(default)]
    pub members: Vec<NamedGroupMember>,
}

/// x0xd named group member entry returned inside `GET /groups/:id`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NamedGroupMember {
    /// Agent id as x0xd reports it, normally lowercase hex.
    pub agent_id: String,
    /// Membership state (`active`, `pending`, `removed`, `banned`).
    #[serde(default)]
    pub state: Option<String>,
}

/// Result returned by `POST /groups/join`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JoinedGroup {
    /// Stable MLS/named-group identifier joined by x0xd.
    pub group_id: String,
    /// Human-readable group name when x0xd includes it.
    #[serde(default)]
    pub group_name: Option<String>,
}

/// x0xd Task entry returned by `GET /task-lists/:id/tasks`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaskEntry {
    /// Task identifier, currently a 64-character hex `TaskId`.
    pub id: String,
    /// Task title.
    pub title: String,
    /// Task description.
    #[serde(default)]
    pub description: String,
    /// Checkbox-derived state string (`empty`, `claimed:<agent>`, or `done:<agent>`).
    pub state: String,
    /// x0x assignee string, when the `TaskItem` is claimed.
    #[serde(default)]
    pub assignee: Option<String>,
    /// x0x `TaskItem` priority byte.
    #[serde(default)]
    pub priority: u8,
}

/// Draft body used to create a `TaskItem` through x0xd.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AddTaskDraft {
    /// New task title.
    pub title: String,
    /// New task description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl AddTaskDraft {
    /// Construct a task draft with the required title.
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            description: None,
        }
    }

    /// Return a copy with a task description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// x0xd `TaskList` task mutation action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskAction {
    /// Claim a task through `PATCH /task-lists/:id/tasks/:tid`.
    Claim,
    /// Complete a task through `PATCH /task-lists/:id/tasks/:tid`.
    Complete,
}

impl TaskAction {
    /// Stable x0xd request spelling for this action.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Complete => "complete",
        }
    }
}

/// `KvStore` entry metadata returned by `GET /stores/:id/keys`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KvKeyEntry {
    /// `KvStore` key.
    pub key: String,
    /// MIME content type recorded for the value.
    #[serde(default)]
    pub content_type: Option<String>,
    /// Content hash returned by x0xd.
    #[serde(default)]
    pub content_hash: Option<String>,
    /// Value size in bytes.
    #[serde(default)]
    pub size: usize,
    /// Update timestamp returned by x0xd.
    #[serde(default)]
    pub updated_at: Option<u64>,
}

/// Decoded `KvStore` value returned by `GET /stores/:id/:key`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KvValue {
    /// `KvStore` key.
    pub key: String,
    /// Raw value bytes decoded from base64.
    pub value: Vec<u8>,
    /// MIME content type recorded for the value.
    pub content_type: Option<String>,
    /// Content hash returned by x0xd.
    pub content_hash: Option<String>,
    /// Creation timestamp returned by x0xd.
    pub created_at: Option<u64>,
    /// Update timestamp returned by x0xd.
    pub updated_at: Option<u64>,
}

/// Raw event chunk returned by the x0xd `/events` SSE stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X0xdEvent {
    /// SSE event type when the chunk parser can identify it.
    pub event_type: Option<String>,
    /// Raw SSE chunk data.
    pub data: String,
}

/// Async API abstraction used by the tracker and its mock tests.
#[async_trait]
pub trait X0xdApi: Send + Sync {
    /// List known `TaskLists`.
    async fn list_task_lists(&self) -> Result<Vec<TaskListEntry>>;

    /// Create a `TaskList` with `name` and `topic`.
    async fn create_task_list(&self, name: &str, topic: &str) -> Result<String>;

    /// List known named groups.
    async fn list_named_groups(&self) -> Result<Vec<NamedGroupEntry>>;

    /// Fetch named group details, including the local roster projection.
    async fn get_named_group(&self, group_id: &str) -> Result<NamedGroupDetails>;

    /// Join a named group via an x0xd invite link or token.
    async fn join_group(&self, invite: &str, display_name: Option<&str>) -> Result<JoinedGroup>;

    /// List tasks in a `TaskList`.
    async fn list_tasks(&self, list_id: &str) -> Result<Vec<TaskEntry>>;

    /// Add a task to a `TaskList`.
    async fn add_task(&self, list_id: &str, draft: AddTaskDraft) -> Result<String>;

    /// Mutate a task with x0xd's action-based PATCH endpoint.
    async fn update_task(&self, list_id: &str, task_id: &str, action: TaskAction) -> Result<()>;

    /// List known `KvStores`.
    async fn list_kv_stores(&self) -> Result<Vec<TaskListEntry>>;

    /// Create a `KvStore` with `name` and `topic`.
    async fn create_kv_store(&self, name: &str, topic: &str) -> Result<String>;

    /// List keys in a `KvStore`.
    async fn list_kv_keys(&self, store_id: &str) -> Result<Vec<KvKeyEntry>>;

    /// Store raw value bytes in a `KvStore` key.
    async fn put_kv(
        &self,
        store_id: &str,
        key: &str,
        value: &[u8],
        content_type: &str,
    ) -> Result<()>;

    /// Read a raw value from a `KvStore` key.
    async fn get_kv(&self, store_id: &str, key: &str) -> Result<Option<KvValue>>;

    /// Subscribe to the x0xd `/events` SSE stream.
    async fn subscribe_events(&self) -> Result<EventStream>;
}

/// Reqwest-backed x0xd REST client.
#[derive(Debug)]
pub struct X0xdClient {
    base_url: String,
    token: Option<String>,
    http: reqwest::Client,
}

impl X0xdClient {
    /// Construct a client for an x0xd base URL.
    ///
    /// The bearer token is read from `X0X_API_TOKEN` when present.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::BuildClient`] when reqwest client construction fails.
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
    /// Returns [`ClientError::BuildClient`] when reqwest client construction fails.
    pub fn with_token(base_url: &str, token: Option<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|source| ClientError::BuildClient { source })?;
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
        let response = request
            .send()
            .await
            .map_err(|source| ClientError::Request {
                url: url.clone(),
                source,
            })?;
        decode_response(response, &url).await
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
            .map_err(|source| ClientError::Request {
                url: url.clone(),
                source,
            })?;
        decode_response(response, &url).await
    }

    async fn patch_json<T, B>(&self, path: &str, body: &B) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = self.url(path);
        let mut request = self.http.patch(&url).json(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|source| ClientError::Request {
                url: url.clone(),
                source,
            })?;
        decode_response(response, &url).await
    }

    async fn put_json<T, B>(&self, path: &str, body: &B) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = self.url(path);
        let mut request = self.http.put(&url).json(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|source| ClientError::Request {
                url: url.clone(),
                source,
            })?;
        decode_response(response, &url).await
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Create a `KvStore`, optionally requesting an access policy (tracker
    /// v2 uses `Some("append_only")` per the x0x WP-X REST contract).
    ///
    /// Daemons predating the `policy` flag ignore unknown JSON fields, so
    /// callers MUST check [`StoreCreateOutcome::policy`] instead of assuming
    /// the request was honored.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or HTTP failures (including 409
    /// when the store already exists).
    pub async fn create_kv_store_with_policy(
        &self,
        name: &str,
        topic: &str,
        policy: Option<&str>,
    ) -> Result<StoreCreateOutcome> {
        let request = CreateStoreWithPolicyRequest {
            name: name.to_owned(),
            topic: topic.to_owned(),
            policy: policy.map(str::to_owned),
        };
        let response: StoreCreateResponse = self.post_json("/stores", &request).await?;
        Ok(StoreCreateOutcome {
            id: response.id,
            policy: response.policy,
        })
    }

    /// Join a peer's `KvStore` replica by topic with a required
    /// `expected_owner` anchor (hex agent id, supplied out-of-band).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or HTTP failures (including 409
    /// when the store is already joined).
    pub async fn join_kv_store(&self, topic: &str, expected_owner: &str) -> Result<()> {
        let path = format!("/stores/{topic}/join");
        let request = JoinStoreRequest {
            expected_owner: expected_owner.to_owned(),
        };
        let _response: serde_json::Value = self.post_json(&path, &request).await?;
        Ok(())
    }

    /// Fetch the daemon-reported detail entry (owner, policy) for one store
    /// topic from `GET /stores`, or `None` when the store is not registered.
    ///
    /// Tracker v2 re-validates the access policy of an ALREADY-EXISTING event
    /// store through this call on every open: a store created by an older
    /// daemon (or an earlier run) as mutable `signed` must not silently
    /// masquerade as append-only.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or HTTP failures.
    pub async fn kv_store_detail(&self, topic: &str) -> Result<Option<StoreDetailEntry>> {
        let response: StoreDetailListResponse = self.get_json("/stores").await?;
        let (StoreDetailListResponse::Wrapped { stores } | StoreDetailListResponse::Bare(stores)) =
            response;
        Ok(stores.into_iter().find(|entry| entry.id == topic))
    }
}

/// Detail entry from `GET /stores`, keeping only the fields v2 validates.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct StoreDetailEntry {
    /// Store id (currently the topic).
    pub id: String,
    /// Hex-encoded anchored owner, when known.
    #[serde(default)]
    pub owner: Option<String>,
    /// Access policy string reported by the daemon, when present.
    #[serde(default)]
    pub policy: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StoreDetailListResponse {
    Wrapped { stores: Vec<StoreDetailEntry> },
    Bare(Vec<StoreDetailEntry>),
}

/// Outcome of `POST /stores`, including the daemon-reported access policy so
/// callers can verify a requested policy was actually honored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreCreateOutcome {
    /// Store id (currently the topic).
    pub id: String,
    /// Access policy reported by the daemon, when present.
    pub policy: Option<String>,
}

#[async_trait]
impl X0xdApi for X0xdClient {
    async fn list_task_lists(&self) -> Result<Vec<TaskListEntry>> {
        match self
            .get_json::<ListTaskListsResponse>("/task-lists")
            .await?
        {
            ListTaskListsResponse::Wrapped { task_lists, .. } => Ok(task_lists),
            ListTaskListsResponse::Bare(entries) => Ok(entries),
        }
    }

    async fn create_task_list(&self, name: &str, topic: &str) -> Result<String> {
        let request = CreateNamedResourceRequest {
            name: name.to_owned(),
            topic: topic.to_owned(),
        };
        let response: CreateResourceResponse = self.post_json("/task-lists", &request).await?;
        Ok(response.id)
    }

    async fn list_named_groups(&self) -> Result<Vec<NamedGroupEntry>> {
        match self.get_json::<ListNamedGroupsResponse>("/groups").await? {
            ListNamedGroupsResponse::Wrapped { groups, .. } => Ok(groups),
            ListNamedGroupsResponse::Bare(entries) => Ok(entries),
        }
    }

    async fn get_named_group(&self, group_id: &str) -> Result<NamedGroupDetails> {
        let path = format!("/groups/{group_id}");
        self.get_json(&path).await
    }

    async fn join_group(&self, invite: &str, display_name: Option<&str>) -> Result<JoinedGroup> {
        let request = JoinGroupRequest {
            invite: invite.to_owned(),
            display_name: display_name.map(str::to_owned),
        };
        let response: JoinGroupResponse = self.post_json("/groups/join", &request).await?;
        Ok(JoinedGroup {
            group_id: response.group_id,
            group_name: response.group_name,
        })
    }

    async fn list_tasks(&self, list_id: &str) -> Result<Vec<TaskEntry>> {
        let path = format!("/task-lists/{list_id}/tasks");
        match self.get_json::<ListTasksResponse>(&path).await? {
            ListTasksResponse::Wrapped { tasks, .. } => Ok(tasks),
            ListTasksResponse::Bare(entries) => Ok(entries),
        }
    }

    async fn add_task(&self, list_id: &str, draft: AddTaskDraft) -> Result<String> {
        let path = format!("/task-lists/{list_id}/tasks");
        let response: AddTaskResponse = self.post_json(&path, &draft).await?;
        Ok(response.task_id)
    }

    async fn update_task(&self, list_id: &str, task_id: &str, action: TaskAction) -> Result<()> {
        let path = format!("/task-lists/{list_id}/tasks/{task_id}");
        let request = UpdateTaskRequest {
            action: action.as_str().to_owned(),
        };
        let _response: OkResponse = self.patch_json(&path, &request).await?;
        Ok(())
    }

    async fn list_kv_stores(&self) -> Result<Vec<TaskListEntry>> {
        match self.get_json::<ListStoresResponse>("/stores").await? {
            ListStoresResponse::Wrapped { stores, .. } => Ok(stores),
            ListStoresResponse::Bare(entries) => Ok(entries),
        }
    }

    async fn create_kv_store(&self, name: &str, topic: &str) -> Result<String> {
        let request = CreateNamedResourceRequest {
            name: name.to_owned(),
            topic: topic.to_owned(),
        };
        let response: CreateResourceResponse = self.post_json("/stores", &request).await?;
        Ok(response.id)
    }

    async fn list_kv_keys(&self, store_id: &str) -> Result<Vec<KvKeyEntry>> {
        let path = format!("/stores/{store_id}/keys");
        match self.get_json::<ListKeysResponse>(&path).await? {
            ListKeysResponse::Wrapped { keys, .. } => Ok(keys),
            ListKeysResponse::Bare(entries) => Ok(entries),
        }
    }

    async fn put_kv(
        &self,
        store_id: &str,
        key: &str,
        value: &[u8],
        content_type: &str,
    ) -> Result<()> {
        let path = format!("/stores/{store_id}/{key}");
        let request = PutValueRequest {
            value: BASE64.encode(value),
            content_type: Some(content_type.to_owned()),
        };
        let _response: OkResponse = self.put_json(&path, &request).await?;
        Ok(())
    }

    async fn get_kv(&self, store_id: &str, key: &str) -> Result<Option<KvValue>> {
        let path = format!("/stores/{store_id}/{key}");
        let url = self.url(&path);
        let mut request = self.http.get(&url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|source| ClientError::Request {
                url: url.clone(),
                source,
            })?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let decoded: GetValueResponse = decode_response(response, &url).await?;
        let value = BASE64
            .decode(decoded.value)
            .map_err(|source| ClientError::Base64 {
                field: "value",
                source,
            })?;
        Ok(Some(KvValue {
            key: decoded.key,
            value,
            content_type: decoded.content_type,
            content_hash: decoded.content_hash,
            created_at: decoded.created_at,
            updated_at: decoded.updated_at,
        }))
    }

    async fn subscribe_events(&self) -> Result<EventStream> {
        let url = self.url("/events");
        let mut request = self.http.get(&url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|source| ClientError::Request {
                url: url.clone(),
                source,
            })?;
        if !response.status().is_success() {
            return Err(error_response(response).await?);
        }
        let stream_url = url.clone();
        let stream = response.bytes_stream().map(move |chunk| {
            chunk
                .map(|bytes| X0xdEvent {
                    event_type: parse_sse_event_type(&bytes),
                    data: String::from_utf8_lossy(&bytes).into_owned(),
                })
                .map_err(|source| ClientError::Request {
                    url: stream_url.clone(),
                    source,
                })
        });
        Ok(Box::pin(stream))
    }
}

#[derive(Serialize)]
struct CreateNamedResourceRequest {
    name: String,
    topic: String,
}

#[derive(Serialize)]
struct CreateStoreWithPolicyRequest {
    name: String,
    topic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<String>,
}

#[derive(Serialize)]
struct JoinStoreRequest {
    expected_owner: String,
}

#[derive(Deserialize)]
struct StoreCreateResponse {
    id: String,
    #[serde(default)]
    policy: Option<String>,
}

#[derive(Serialize)]
struct JoinGroupRequest {
    invite: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

#[derive(Serialize)]
struct UpdateTaskRequest {
    action: String,
}

#[derive(Serialize)]
struct PutValueRequest {
    value: String,
    content_type: Option<String>,
}

#[derive(Deserialize)]
struct OkResponse {}

#[derive(Deserialize)]
struct CreateResourceResponse {
    id: String,
}

#[derive(Deserialize)]
struct JoinGroupResponse {
    group_id: String,
    #[serde(default)]
    group_name: Option<String>,
}

#[derive(Deserialize)]
struct AddTaskResponse {
    task_id: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ListTaskListsResponse {
    Wrapped { task_lists: Vec<TaskListEntry> },
    Bare(Vec<TaskListEntry>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ListNamedGroupsResponse {
    Wrapped { groups: Vec<NamedGroupEntry> },
    Bare(Vec<NamedGroupEntry>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ListTasksResponse {
    Wrapped { tasks: Vec<TaskEntry> },
    Bare(Vec<TaskEntry>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ListStoresResponse {
    Wrapped { stores: Vec<TaskListEntry> },
    Bare(Vec<TaskListEntry>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ListKeysResponse {
    Wrapped { keys: Vec<KvKeyEntry> },
    Bare(Vec<KvKeyEntry>),
}

#[derive(Deserialize)]
struct GetValueResponse {
    key: String,
    value: String,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    content_hash: Option<String>,
    #[serde(default)]
    created_at: Option<u64>,
    #[serde(default)]
    updated_at: Option<u64>,
}

async fn decode_response<T>(response: reqwest::Response, url: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    if response.status().is_success() {
        response
            .json::<T>()
            .await
            .map_err(|source| ClientError::Decode {
                url: url.to_owned(),
                source,
            })
    } else {
        Err(error_response(response).await?)
    }
}

async fn error_response(
    response: reqwest::Response,
) -> std::result::Result<ClientError, ClientError> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|source| ClientError::Decode {
            url: String::new(),
            source,
        })?;
    Ok(ClientError::Http { status, body })
}

fn parse_sse_event_type(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    text.lines()
        .find_map(|line| line.strip_prefix("event:").map(str::trim))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_action_spelling_matches_x0xd() {
        assert_eq!(TaskAction::Claim.as_str(), "claim");
        assert_eq!(TaskAction::Complete.as_str(), "complete");
    }

    #[test]
    fn parses_sse_event_type_when_chunk_contains_event_line() {
        assert_eq!(
            parse_sse_event_type(b"event: message\ndata: {}\n\n").as_deref(),
            Some("message")
        );
    }
}
