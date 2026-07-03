//! Gossip-backed worker discovery for `x0x-symphonyd`.
//!
//! The daemon publishes signed [`WorkerCard`] advertisements to x0xd's gossip
//! pub/sub HTTP surface and maintains a TTL-reaped live view of cards received
//! from peers. The x0x CRDT tracker snapshots this live view when it creates
//! symphony-owned issues and freezes their shard slate.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{SecondsFormat, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, task::JoinHandle, time::sleep};
use tracing::{info, warn};
use x0x_symphony_core::{
    sha256_hex, AgentId, PlatformInfo, SignatureEnvelope, WorkerCard, SIGN_ALGORITHM,
    WORKER_CARD_CONTEXT, WORKER_CARD_SCHEMA_VERSION,
};
use x0x_symphony_signing::{SigningClient, TrustedKeyResolver, VerifyOutcome};
use x0x_symphony_tracker_x0x_crdt::{WorkerViewProvider, WorkerViewSnapshot};

/// Gossip topic carrying signed worker advertisements.
pub const WORKER_TOPIC: &str = "x0x/symphony/workers/v1";

/// Live worker-card view maintained from the worker gossip topic.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkerView {
    /// Last non-expired card per advertising agent.
    pub cards: BTreeMap<AgentId, WorkerCard>,
    /// Monotonic epoch bumped when the visible worker set changes.
    pub view_epoch: u64,
}

impl WorkerView {
    /// Construct an empty worker view.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cards: BTreeMap::new(),
            view_epoch: 0,
        }
    }
}

/// Worker-card publisher/subscriber owned by the daemon.
pub struct WorkerDiscovery {
    agent_id: AgentId,
    signing_client: Arc<dyn SigningClient>,
    key_resolver: Arc<dyn TrustedKeyResolver>,
    x0xd: X0xdGossipClient,
    view: Arc<RwLock<WorkerView>>,
    local_card_template: WorkerCard,
    publish_enabled: bool,
    current_load: Arc<AtomicU32>,
    consumer_started: AtomicBool,
}

impl WorkerDiscovery {
    /// Construct a worker discovery service around an unsigned local card template.
    ///
    /// # Errors
    ///
    /// Returns an error when the local card does not belong to `agent_id`, uses
    /// an unsupported schema version, or the HTTP client cannot be built.
    pub fn new(
        agent_id: AgentId,
        signing_client: Arc<dyn SigningClient>,
        key_resolver: Arc<dyn TrustedKeyResolver>,
        x0xd_url: impl Into<String>,
        x0xd_token: Option<String>,
        mut local_card_template: WorkerCard,
        publish_enabled: bool,
    ) -> anyhow::Result<Self> {
        if local_card_template.agent_id != agent_id {
            bail!(
                "worker card template agent {} does not match local agent {}",
                local_card_template.agent_id,
                agent_id
            );
        }
        if local_card_template.schema_version != WORKER_CARD_SCHEMA_VERSION {
            bail!(
                "worker card template schema version {} is not supported",
                local_card_template.schema_version
            );
        }
        local_card_template.signature = None;
        local_card_template.ttl_seconds = local_card_template.ttl_seconds.max(1);
        let x0xd = X0xdGossipClient::new(x0xd_url, x0xd_token)?;
        Ok(Self {
            agent_id,
            signing_client,
            key_resolver,
            x0xd,
            view: Arc::new(RwLock::new(WorkerView::new())),
            local_card_template,
            publish_enabled,
            current_load: Arc::new(AtomicU32::new(0)),
            consumer_started: AtomicBool::new(false),
        })
    }

    /// Set the current load advertised by the next published local card.
    pub fn set_current_load(&self, current_load: u32) {
        self.current_load.store(current_load, Ordering::Relaxed);
    }

    /// Publish a freshly signed local worker card to x0xd gossip.
    ///
    /// The local view is updated after x0xd accepts the publish request.
    ///
    /// # Errors
    ///
    /// Returns an error when signing fails, the signer identity does not match
    /// the local agent, serialization fails, or x0xd rejects the request.
    pub async fn publish_card(&self) -> anyhow::Result<()> {
        let mut card = self.local_card_template.clone();
        card.issued_at = now_rfc3339();
        card.current_load = self.current_load.load(Ordering::Relaxed);
        card.signature = None;
        let signing_payload = card
            .signing_payload_bytes()
            .context("failed to serialize worker card signing payload")?;
        let signature = self
            .signing_client
            .sign(WORKER_CARD_CONTEXT, &signing_payload)
            .await
            .context("failed to sign worker card")?;
        if signature.agent_id != self.agent_id.as_str() {
            bail!(
                "worker card signer {} does not match local agent {}",
                signature.agent_id,
                self.agent_id
            );
        }
        card.signature = Some(SignatureEnvelope::new(
            signature.algorithm,
            signature.context,
            signature.public_key_b64,
            signature.signature_b64,
            sha256_hex(&signing_payload),
            signature.agent_id,
        ));
        let payload = serde_json::to_vec(&card).context("failed to encode signed worker card")?;
        self.x0xd
            .publish(WORKER_TOPIC, &payload)
            .await
            .context("failed to publish worker card to x0xd")?;
        self.insert_local_card(card).await;
        Ok(())
    }

    /// Subscribe to the worker topic and spawn the long-lived SSE consumer.
    ///
    /// Calling this method more than once is idempotent after the first
    /// successful subscription.
    ///
    /// # Errors
    ///
    /// Returns an error when the initial `POST /subscribe` request fails.
    pub async fn subscribe(&self) -> anyhow::Result<()> {
        if self.consumer_started.load(Ordering::Acquire) {
            return Ok(());
        }
        let subscription_id = self
            .x0xd
            .subscribe(WORKER_TOPIC)
            .await
            .context("failed to subscribe to worker gossip topic")?;
        if self
            .consumer_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let task = WorkerConsumerTask {
                signing_client: Arc::clone(&self.signing_client),
                key_resolver: Arc::clone(&self.key_resolver),
                x0xd: self.x0xd.clone(),
                view: Arc::clone(&self.view),
            };
            let _consumer = tokio::spawn(async move {
                task.consume_loop(Some(subscription_id)).await;
            });
        }
        Ok(())
    }

    /// Spawn the background worker-discovery loop for the daemon lifetime.
    ///
    /// The loop retries subscribe and publish failures with warnings; x0xd
    /// outages never crash the daemon.
    #[must_use]
    pub async fn run(self: Arc<Self>) -> JoinHandle<()> {
        if let Err(error) = self.subscribe().await {
            warn!(%error, "initial worker gossip subscribe failed; background loop will retry");
        }
        tokio::spawn(async move {
            self.run_loop().await;
        })
    }

    /// Return the current non-expired worker cards, reaping expired entries.
    pub async fn snapshot(&self) -> Vec<WorkerCard> {
        self.snapshot_view().await.cards.into_values().collect()
    }

    /// Return the current non-expired worker view and its epoch.
    pub async fn snapshot_view(&self) -> WorkerView {
        let now = now_rfc3339();
        let mut view = self.view.write().await;
        reap_expired_at(&mut view, &now);
        view.clone()
    }

    async fn run_loop(&self) {
        let publish_interval = self.publish_interval();
        loop {
            if !self.consumer_started.load(Ordering::Acquire) {
                match self.subscribe().await {
                    Ok(()) => info!(topic = WORKER_TOPIC, "worker gossip subscription started"),
                    Err(error) => warn!(%error, "worker gossip subscribe failed; will retry"),
                }
            }
            if self.publish_enabled {
                if let Err(error) = self.publish_card().await {
                    warn!(%error, "worker card publish failed; will retry");
                }
            }
            sleep(publish_interval).await;
        }
    }

    fn publish_interval(&self) -> Duration {
        let ttl = self.local_card_template.ttl_seconds;
        Duration::from_secs((ttl / 2).max(1))
    }

    async fn insert_local_card(&self, card: WorkerCard) {
        let mut view = self.view.write().await;
        let is_new = !view.cards.contains_key(&card.agent_id);
        view.cards.insert(card.agent_id.clone(), card);
        if is_new {
            bump_epoch(&mut view);
        }
    }

    #[cfg(test)]
    async fn verify_and_insert_card_at(
        &self,
        card: WorkerCard,
        now: &str,
    ) -> anyhow::Result<ReceiveOutcome> {
        WorkerConsumerTask {
            signing_client: Arc::clone(&self.signing_client),
            key_resolver: Arc::clone(&self.key_resolver),
            x0xd: self.x0xd.clone(),
            view: Arc::clone(&self.view),
        }
        .verify_and_insert_card_at(card, now)
        .await
    }

    #[cfg(test)]
    async fn process_sse_data_at(&self, data: &str, now: &str) -> anyhow::Result<ReceiveOutcome> {
        WorkerConsumerTask {
            signing_client: Arc::clone(&self.signing_client),
            key_resolver: Arc::clone(&self.key_resolver),
            x0xd: self.x0xd.clone(),
            view: Arc::clone(&self.view),
        }
        .process_sse_data_at(data, now)
        .await
    }
}

#[async_trait::async_trait]
impl WorkerViewProvider for WorkerDiscovery {
    async fn snapshot(&self) -> WorkerViewSnapshot {
        let view = self.snapshot_view().await;
        WorkerViewSnapshot {
            cards: view.cards.into_values().collect(),
            view_epoch: view.view_epoch,
        }
    }
}

#[derive(Clone)]
struct WorkerConsumerTask {
    signing_client: Arc<dyn SigningClient>,
    key_resolver: Arc<dyn TrustedKeyResolver>,
    x0xd: X0xdGossipClient,
    view: Arc<RwLock<WorkerView>>,
}

impl WorkerConsumerTask {
    async fn consume_loop(self, mut subscription_id: Option<String>) {
        let mut backoff = RetryBackoff::default();
        loop {
            if let Some(id) = subscription_id.take() {
                info!(subscription_id = %id, topic = WORKER_TOPIC, "worker gossip subscribed");
            } else {
                match self.x0xd.subscribe(WORKER_TOPIC).await {
                    Ok(id) => {
                        backoff.reset();
                        info!(subscription_id = %id, topic = WORKER_TOPIC, "worker gossip resubscribed");
                    }
                    Err(error) => {
                        warn!(%error, "worker gossip resubscribe failed; will retry");
                        sleep(backoff.next()).await;
                        continue;
                    }
                }
            }

            match self.consume_event_stream_once().await {
                Ok(()) => warn!("worker gossip SSE stream ended; reconnecting"),
                Err(error) => warn!(%error, "worker gossip SSE stream failed; reconnecting"),
            }
            sleep(backoff.next()).await;
        }
    }

    async fn consume_event_stream_once(&self) -> anyhow::Result<()> {
        let response = self
            .x0xd
            .open_events()
            .await
            .context("failed to open x0xd /events stream")?;
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("x0xd /events stream chunk failed")?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(event) = next_sse_chunk(&mut buffer) {
                if let Some(data) = sse_data(&event) {
                    let now = now_rfc3339();
                    if let Err(error) = self.process_sse_data_at(&data, &now).await {
                        warn!(%error, "dropping malformed worker gossip event");
                    }
                }
            }
        }
        Ok(())
    }

    async fn process_sse_data_at(&self, data: &str, now: &str) -> anyhow::Result<ReceiveOutcome> {
        let event: GossipEvent =
            serde_json::from_str(data).context("failed to decode worker gossip event JSON")?;
        if event.topic != WORKER_TOPIC {
            return Ok(ReceiveOutcome::IgnoredTopic);
        }
        if !event.verified {
            warn!(topic = %event.topic, "dropping unverified worker gossip event");
            return Ok(ReceiveOutcome::DroppedUnverified);
        }
        let payload = BASE64
            .decode(event.payload)
            .context("worker gossip payload was not valid base64")?;
        let card: WorkerCard = serde_json::from_slice(&payload)
            .context("worker gossip payload was not a WorkerCard")?;
        self.verify_and_insert_card_at(card, now).await
    }

    async fn verify_and_insert_card_at(
        &self,
        card: WorkerCard,
        now: &str,
    ) -> anyhow::Result<ReceiveOutcome> {
        if card.schema_version != WORKER_CARD_SCHEMA_VERSION {
            warn!(
                agent_id = %card.agent_id,
                schema_version = card.schema_version,
                "dropping worker card with unsupported schema version"
            );
            return Ok(ReceiveOutcome::DroppedInvalid);
        }
        if card.is_expired(now) {
            return Ok(ReceiveOutcome::DroppedExpired);
        }
        if !signature_envelope_is_consistent(&card) {
            warn!(agent_id = %card.agent_id, "dropping worker card with inconsistent signature envelope");
            return Ok(ReceiveOutcome::DroppedInvalid);
        }
        let Some(signature) = &card.signature else {
            return Ok(ReceiveOutcome::DroppedInvalid);
        };
        let public_key = match self.key_resolver.resolve(card.agent_id.as_str()).await {
            Ok(public_key) => public_key,
            Err(error) => {
                warn!(agent_id = %card.agent_id, %error, "dropping worker card from unresolved signer");
                return Ok(ReceiveOutcome::DroppedInvalid);
            }
        };
        let envelope_public_key = match BASE64.decode(&signature.public_key_b64) {
            Ok(public_key) => public_key,
            Err(error) => {
                warn!(agent_id = %card.agent_id, %error, "dropping worker card with invalid public key base64");
                return Ok(ReceiveOutcome::DroppedInvalid);
            }
        };
        if envelope_public_key != public_key {
            warn!(agent_id = %card.agent_id, "dropping worker card whose envelope key does not match the trusted signer key");
            return Ok(ReceiveOutcome::DroppedInvalid);
        }
        let signature_bytes = match BASE64.decode(&signature.signature_b64) {
            Ok(signature_bytes) => signature_bytes,
            Err(error) => {
                warn!(agent_id = %card.agent_id, %error, "dropping worker card with invalid signature base64");
                return Ok(ReceiveOutcome::DroppedInvalid);
            }
        };
        let payload = card
            .signing_payload_bytes()
            .context("failed to serialize worker card for verification")?;
        match self
            .signing_client
            .verify(WORKER_CARD_CONTEXT, &payload, &signature_bytes, &public_key)
            .await
        {
            Ok(VerifyOutcome::Valid) => Ok(self.insert_verified(card).await),
            Ok(VerifyOutcome::Invalid(reason)) => {
                warn!(agent_id = %card.agent_id, reason = %reason, "dropping forged worker card");
                Ok(ReceiveOutcome::DroppedInvalid)
            }
            Ok(VerifyOutcome::TransportError(reason)) => {
                warn!(agent_id = %card.agent_id, reason = %reason, "worker card verification transport failed; dropping card");
                Ok(ReceiveOutcome::DroppedInvalid)
            }
            Err(error) => {
                warn!(agent_id = %card.agent_id, %error, "worker card verification failed; dropping card");
                Ok(ReceiveOutcome::DroppedInvalid)
            }
        }
    }

    async fn insert_verified(&self, card: WorkerCard) -> ReceiveOutcome {
        let mut view = self.view.write().await;
        let is_new = !view.cards.contains_key(&card.agent_id);
        view.cards.insert(card.agent_id.clone(), card);
        if is_new {
            bump_epoch(&mut view);
            ReceiveOutcome::Inserted
        } else {
            ReceiveOutcome::Updated
        }
    }
}

#[derive(Clone)]
struct X0xdGossipClient {
    base_url: String,
    token: Option<String>,
    http: reqwest::Client,
}

impl X0xdGossipClient {
    fn new(base_url: impl Into<String>, token: Option<String>) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .context("failed to construct worker gossip HTTP client")?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            token: token.filter(|value| !value.trim().is_empty()),
            http,
        })
    }

    async fn publish(&self, topic: &str, payload: &[u8]) -> anyhow::Result<()> {
        let request = PublishRequest {
            topic: topic.to_owned(),
            payload: BASE64.encode(payload),
        };
        let response = self.post_json("/publish", &request).await?;
        let decoded: PublishResponse = response
            .json()
            .await
            .context("failed to decode x0xd /publish response")?;
        if !decoded.ok {
            bail!("x0xd /publish returned ok=false");
        }
        Ok(())
    }

    async fn subscribe(&self, topic: &str) -> anyhow::Result<String> {
        let request = SubscribeRequest {
            topic: topic.to_owned(),
        };
        let response = self.post_json("/subscribe", &request).await?;
        let decoded: SubscribeResponse = response
            .json()
            .await
            .context("failed to decode x0xd /subscribe response")?;
        Ok(decoded.subscription_id)
    }

    async fn open_events(&self) -> anyhow::Result<reqwest::Response> {
        let url = self.url("/events");
        let mut request = self.http.get(&url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))?;
        ensure_success(response, &url).await
    }

    async fn post_json<B>(&self, path: &str, body: &B) -> anyhow::Result<reqwest::Response>
    where
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
            .with_context(|| format!("request to {url} failed"))?;
        ensure_success(response, &url).await
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }
}

#[derive(Deserialize, Serialize)]
struct PublishRequest {
    topic: String,
    payload: String,
}

#[derive(Deserialize)]
struct PublishResponse {
    ok: bool,
}

#[derive(Serialize)]
struct SubscribeRequest {
    topic: String,
}

#[derive(Deserialize)]
struct SubscribeResponse {
    subscription_id: String,
}

#[derive(Deserialize)]
struct GossipEvent {
    topic: String,
    payload: String,
    verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiveOutcome {
    IgnoredTopic,
    DroppedUnverified,
    DroppedInvalid,
    DroppedExpired,
    Inserted,
    Updated,
}

#[derive(Debug)]
struct RetryBackoff {
    current: Duration,
}

impl Default for RetryBackoff {
    fn default() -> Self {
        Self {
            current: Duration::from_secs(1),
        }
    }
}

impl RetryBackoff {
    fn next(&mut self) -> Duration {
        let value = self.current;
        self.current = (self.current.saturating_mul(2)).min(Duration::from_secs(30));
        value
    }

    fn reset(&mut self) {
        self.current = Duration::from_secs(1);
    }
}

async fn ensure_success(
    response: reqwest::Response,
    url: &str,
) -> anyhow::Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|error| format!("failed to read error body: {error}"));
    bail!("x0xd {url} returned HTTP {status}: {body}");
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn signature_envelope_is_consistent(card: &WorkerCard) -> bool {
    let Some(signature) = &card.signature else {
        return false;
    };
    signature.algorithm == SIGN_ALGORITHM
        && signature.context == WORKER_CARD_CONTEXT
        && signature.signer_agent_id == card.agent_id.as_str()
        && card
            .signing_payload_sha256()
            .is_ok_and(|digest| digest == signature.payload_sha256)
}

fn reap_expired_at(view: &mut WorkerView, now: &str) {
    let before = view.cards.len();
    view.cards.retain(|_agent_id, card| !card.is_expired(now));
    if view.cards.len() != before {
        bump_epoch(view);
    }
}

fn bump_epoch(view: &mut WorkerView) {
    view.view_epoch = view.view_epoch.saturating_add(1);
}

fn next_sse_chunk(buffer: &mut String) -> Option<String> {
    let (index, separator_len) = sse_boundary(buffer)?;
    let chunk = buffer[..index].to_owned();
    buffer.drain(..index + separator_len);
    Some(chunk)
}

fn sse_boundary(buffer: &str) -> Option<(usize, usize)> {
    match (buffer.find("\n\n"), buffer.find("\r\n\r\n")) {
        (Some(lf), Some(crlf)) if crlf < lf => Some((crlf, 4)),
        (Some(lf), _) => Some((lf, 2)),
        (None, Some(crlf)) => Some((crlf, 4)),
        (None, None) => None,
    }
}

fn sse_data(event: &str) -> Option<String> {
    let lines = event
        .lines()
        .filter_map(|line| {
            line.trim_end_matches('\r')
                .strip_prefix("data:")
                .map(str::trim)
        })
        .collect::<Vec<_>>();
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

/// Build an unsigned local worker-card template for this daemon.
#[must_use]
pub fn local_worker_card_template(
    agent_id: AgentId,
    ttl_seconds: u64,
    capabilities: Vec<String>,
    sandbox_levels: Vec<String>,
    runner_presets: Vec<String>,
    max_load: u32,
) -> WorkerCard {
    WorkerCard {
        schema_version: WORKER_CARD_SCHEMA_VERSION,
        agent_id,
        issued_at: "1970-01-01T00:00:00Z".to_owned(),
        ttl_seconds: ttl_seconds.max(1),
        capabilities,
        sandbox_levels,
        runner_presets,
        current_load: 0,
        max_load,
        platform: PlatformInfo::current(),
        signature: None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use async_trait::async_trait;
    use serde_json::json;
    use tokio::sync::Mutex;
    use x0x_symphony_core::Result as CoreResult;
    use x0x_symphony_signing::{AgentInfo, SignResponse, SigningError};

    use super::*;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn verify_and_insert_accepts_valid_card_and_drops_forged_or_expired() -> TestResult {
        let discovery = test_discovery("agent-a")?;
        let now = "2026-07-03T12:00:00Z";
        let card = signed_card(&discovery, "agent-a", "2026-07-03T11:59:30Z", 60).await?;

        assert_eq!(
            discovery
                .verify_and_insert_card_at(card.clone(), now)
                .await?,
            ReceiveOutcome::Inserted
        );
        assert_eq!(discovery.view.read().await.cards.len(), 1);

        let mut forged = card;
        forged.current_load = 9;
        assert_eq!(
            discovery.verify_and_insert_card_at(forged, now).await?,
            ReceiveOutcome::DroppedInvalid
        );

        let expired = signed_card(&discovery, "agent-a", "2026-07-03T11:58:00Z", 60).await?;
        assert_eq!(
            discovery.verify_and_insert_card_at(expired, now).await?,
            ReceiveOutcome::DroppedExpired
        );
        assert_eq!(discovery.view.read().await.cards.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn sse_event_decode_verifies_before_insert() -> TestResult {
        let discovery = test_discovery("agent-a")?;
        let now = "2026-07-03T12:00:00Z";
        let card = signed_card(&discovery, "agent-a", "2026-07-03T11:59:45Z", 60).await?;
        let payload = BASE64.encode(serde_json::to_vec(&card)?);
        let event = json!({
            "subscription_id": "sub-1",
            "topic": WORKER_TOPIC,
            "payload": payload,
            "sender": "agent-a",
            "verified": true,
            "trust_level": "trusted"
        })
        .to_string();

        assert_eq!(
            discovery.process_sse_data_at(&event, now).await?,
            ReceiveOutcome::Inserted
        );

        let unverified = json!({
            "topic": WORKER_TOPIC,
            "payload": BASE64.encode(serde_json::to_vec(&card)?),
            "verified": false
        })
        .to_string();
        assert_eq!(
            discovery.process_sse_data_at(&unverified, now).await?,
            ReceiveOutcome::DroppedUnverified
        );
        Ok(())
    }

    #[tokio::test]
    async fn snapshot_reaps_expired_cards() -> TestResult {
        let discovery = test_discovery("agent-a")?;
        let now = "2026-07-03T12:00:00Z";
        let live_a = signed_card(&discovery, "agent-a", "2026-07-03T11:59:30Z", 60).await?;
        let live_b = signed_card(&discovery, "agent-b", "2026-07-03T11:59:45Z", 60).await?;
        let expired = signed_card(&discovery, "agent-c", "2026-07-03T11:58:00Z", 60).await?;
        {
            let mut view = discovery.view.write().await;
            view.cards.insert(live_a.agent_id.clone(), live_a);
            view.cards.insert(live_b.agent_id.clone(), live_b);
            view.cards.insert(expired.agent_id.clone(), expired);
        }

        let mut view = discovery.view.write().await;
        reap_expired_at(&mut view, now);
        let live_agents = view
            .cards
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        assert_eq!(
            live_agents,
            vec!["agent-a".to_owned(), "agent-b".to_owned()]
        );
        assert_eq!(view.view_epoch, 1);
        Ok(())
    }

    #[tokio::test]
    async fn publish_card_posts_signed_payload_to_worker_topic() -> TestResult {
        let received = Arc::new(Mutex::new(Vec::<PublishRequest>::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let received_for_server = Arc::clone(&received);
        let app = axum::Router::new().route(
            "/publish",
            axum::routing::post(move |axum::Json(request): axum::Json<PublishRequest>| {
                let received = Arc::clone(&received_for_server);
                async move {
                    received.lock().await.push(request);
                    axum::Json(json!({"ok": true}))
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let discovery = test_discovery_with_url("agent-a", format!("http://{addr}"))?;
        discovery.publish_card().await?;
        server.abort();

        let requests = received.lock().await;
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.topic, WORKER_TOPIC);
        let payload = BASE64.decode(&request.payload)?;
        let card: WorkerCard = serde_json::from_slice(&payload)?;
        assert_eq!(card.agent_id.as_str(), "agent-a");
        assert!(signature_envelope_is_consistent(&card));
        assert_eq!(discovery.snapshot().await.len(), 1);
        Ok(())
    }

    #[test]
    fn sse_parser_collects_data_lines() -> TestResult {
        let mut buffer = "event: message\ndata: {\"a\":1}\n\n".to_owned();
        let chunk = next_sse_chunk(&mut buffer).ok_or("missing SSE chunk")?;
        assert_eq!(sse_data(&chunk).as_deref(), Some("{\"a\":1}"));
        assert!(buffer.is_empty());
        Ok(())
    }

    fn test_discovery(agent_id: &str) -> TestResult<WorkerDiscovery> {
        test_discovery_with_url(agent_id, "http://127.0.0.1:1".to_owned())
    }

    fn test_discovery_with_url(agent_id: &str, url: String) -> TestResult<WorkerDiscovery> {
        let signing = Arc::new(MockSigning::new(agent_id));
        let agent = AgentId::new(agent_id)?;
        let template = local_worker_card_template(
            agent.clone(),
            60,
            vec!["rust".to_owned()],
            vec!["repo-write".to_owned()],
            vec!["claude_code".to_owned()],
            2,
        );
        let signing_client: Arc<dyn SigningClient> = signing.clone();
        let key_resolver: Arc<dyn TrustedKeyResolver> = signing;
        WorkerDiscovery::new(
            agent,
            signing_client,
            key_resolver,
            url,
            None,
            template,
            true,
        )
        .map_err(Into::into)
    }

    async fn signed_card(
        discovery: &WorkerDiscovery,
        agent_id: &str,
        issued_at: &str,
        ttl_seconds: u64,
    ) -> CoreResult<WorkerCard> {
        let mut card = WorkerCard {
            schema_version: WORKER_CARD_SCHEMA_VERSION,
            agent_id: AgentId::new(agent_id)?,
            issued_at: issued_at.to_owned(),
            ttl_seconds: ttl_seconds.max(1),
            capabilities: vec!["rust".to_owned()],
            sandbox_levels: vec!["repo-write".to_owned()],
            runner_presets: vec!["claude_code".to_owned()],
            current_load: 0,
            max_load: 2,
            platform: PlatformInfo {
                os: "linux".to_owned(),
                arch: "x86_64".to_owned(),
                version: "0.0.0".to_owned(),
            },
            signature: None,
        };
        let payload = card.signing_payload_bytes()?;
        let signature = discovery
            .signing_client
            .sign(WORKER_CARD_CONTEXT, &payload)
            .await
            .map_err(|error| {
                x0x_symphony_core::SymphonyError::validation("sign", error.to_string())
            })?;
        card.signature = Some(SignatureEnvelope::new(
            signature.algorithm,
            signature.context,
            signature.public_key_b64,
            signature.signature_b64,
            sha256_hex(&payload),
            agent_id,
        ));
        Ok(card)
    }

    struct MockSigning {
        agent_id: String,
        public_keys: BTreeMap<String, Vec<u8>>,
    }

    impl MockSigning {
        fn new(agent_id: &str) -> Self {
            let mut public_keys = BTreeMap::new();
            for id in ["agent-a", "agent-b", "agent-c", agent_id] {
                public_keys.insert(id.to_owned(), format!("public-key-{id}").into_bytes());
            }
            Self {
                agent_id: agent_id.to_owned(),
                public_keys,
            }
        }

        fn public_key(&self, agent_id: &str) -> Vec<u8> {
            self.public_keys
                .get(agent_id)
                .cloned()
                .unwrap_or_else(|| format!("public-key-{agent_id}").into_bytes())
        }
    }

    #[async_trait]
    impl SigningClient for MockSigning {
        async fn sign(
            &self,
            context: &str,
            payload: &[u8],
        ) -> x0x_symphony_signing::Result<SignResponse> {
            let public_key = self.public_key(&self.agent_id);
            let signature = mock_signature(context, payload, &public_key);
            Ok(SignResponse {
                agent_id: self.agent_id.clone(),
                public_key_b64: BASE64.encode(public_key),
                signature_b64: BASE64.encode(signature),
                algorithm: SIGN_ALGORITHM.to_owned(),
                context: context.to_owned(),
            })
        }

        async fn verify(
            &self,
            context: &str,
            payload: &[u8],
            signature: &[u8],
            public_key: &[u8],
        ) -> x0x_symphony_signing::Result<VerifyOutcome> {
            let expected = mock_signature(context, payload, public_key);
            if signature == expected.as_slice() {
                Ok(VerifyOutcome::Valid)
            } else {
                Ok(VerifyOutcome::Invalid("mock signature mismatch".to_owned()))
            }
        }

        async fn agent_identity(&self) -> x0x_symphony_signing::Result<AgentInfo> {
            Ok(AgentInfo {
                agent_id: self.agent_id.clone(),
            })
        }
    }

    #[async_trait]
    impl TrustedKeyResolver for MockSigning {
        async fn resolve(&self, agent_id: &str) -> x0x_symphony_signing::Result<Vec<u8>> {
            self.public_keys.get(agent_id).cloned().ok_or_else(|| {
                SigningError::UntrustedKey(format!("missing mock public key for {agent_id}"))
            })
        }
    }

    fn mock_signature(context: &str, payload: &[u8], public_key: &[u8]) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(context.as_bytes());
        input.extend_from_slice(b":");
        input.extend_from_slice(public_key);
        input.extend_from_slice(b":");
        input.extend_from_slice(payload);
        sha256_hex(&input).into_bytes()
    }
}
