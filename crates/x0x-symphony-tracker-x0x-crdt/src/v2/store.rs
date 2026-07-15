//! WP-0: per-author event-store management for tracker-integrity v2.
//!
//! Each author owns exactly one event store per list, at topic
//! `symphony2-ev-<list-uuid>-<author-agent-id>` (design r2 finding C4).
//! Readers join every roster peer's store with an `expected_owner` anchor and
//! read keys; store ids are never computed client-side — topics are the
//! addressing.
//!
//! # `AppendOnly` dependency gate
//!
//! Event stores are meant to be created with x0x's
//! `AccessPolicy::AppendOnly` (`POST /stores` with `"policy":
//! "append_only"`; PUT-to-existing and DELETE return 409). That policy ships
//! with x0x WP-X (branch `feat/kv-append-only-policy`, targeted at x0x
//! v0.33.0).
//!
//! TODO(x0x WP-X, x0x-symphony#10): once x0x v0.33.0 is the deployed
//! baseline, remove [`StorePolicyMode::SignedFallback`] and hard-require
//! `append_only`. Until then the fallback mode creates plain `signed` stores
//! (mutable — the C1 deletion residual is NOT closed in that mode) so v2 can
//! be exercised against x0xd ≤ v0.32.x. The mode is configured through the
//! `v2_store_policy` setting; the default is [`StorePolicyMode::AppendOnly`],
//! and creation FAILS LOUDLY when the daemon does not honor the policy.

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::StatusCode;

use x0x_symphony_signing::{SigningClient, SigningError};

use super::events::{
    event_key, event_store_topic, heartbeat_store_topic, EventEnvelope, GenesisManifestV2,
    GenesisPolicy, RosterEventV2, TransitionEventV2, BOOTSTRAP_CONTEXT_V2, CARD_SELF_KEY,
    GENESIS_CONTEXT_V2, GENESIS_KEY, ROSTER_CONTEXT_V2, TRANSITION_CONTEXT_V2, V2_SCHEMA,
};
use super::fold::{AuthorStream, FoldInput, StoreRecord};
use super::identity::decode_b64;
use crate::client::{
    ClientError, KvKeyEntry, KvValue, StoreCreateOutcome, StoreDetailEntry, X0xdApi, X0xdClient,
};
use x0x_symphony_core::sha256_hex;

/// The x0xd REST surface the v2 store manager depends on. A trait so tests
/// can drive the manager against an in-memory daemon double.
#[async_trait]
pub trait V2StoreApi: Send + Sync {
    /// `POST /stores` with an optional access-policy flag.
    async fn create_kv_store_with_policy(
        &self,
        name: &str,
        topic: &str,
        policy: Option<&str>,
    ) -> std::result::Result<StoreCreateOutcome, ClientError>;

    /// `POST /stores/:topic/join` with a required owner anchor.
    async fn join_kv_store(
        &self,
        topic: &str,
        expected_owner: &str,
    ) -> std::result::Result<(), ClientError>;

    /// `GET /stores` filtered to one topic (owner + policy detail).
    async fn kv_store_detail(
        &self,
        topic: &str,
    ) -> std::result::Result<Option<StoreDetailEntry>, ClientError>;

    /// `GET /stores/:topic/keys`.
    async fn list_kv_keys(&self, topic: &str) -> std::result::Result<Vec<KvKeyEntry>, ClientError>;

    /// `GET /stores/:topic/:key`.
    async fn get_kv(
        &self,
        topic: &str,
        key: &str,
    ) -> std::result::Result<Option<KvValue>, ClientError>;

    /// `PUT /stores/:topic/:key`.
    async fn put_kv(
        &self,
        topic: &str,
        key: &str,
        value: &[u8],
        content_type: &str,
    ) -> std::result::Result<(), ClientError>;
}

#[async_trait]
impl V2StoreApi for X0xdClient {
    async fn create_kv_store_with_policy(
        &self,
        name: &str,
        topic: &str,
        policy: Option<&str>,
    ) -> std::result::Result<StoreCreateOutcome, ClientError> {
        Self::create_kv_store_with_policy(self, name, topic, policy).await
    }

    async fn join_kv_store(
        &self,
        topic: &str,
        expected_owner: &str,
    ) -> std::result::Result<(), ClientError> {
        Self::join_kv_store(self, topic, expected_owner).await
    }

    async fn kv_store_detail(
        &self,
        topic: &str,
    ) -> std::result::Result<Option<StoreDetailEntry>, ClientError> {
        Self::kv_store_detail(self, topic).await
    }

    async fn list_kv_keys(&self, topic: &str) -> std::result::Result<Vec<KvKeyEntry>, ClientError> {
        X0xdApi::list_kv_keys(self, topic).await
    }

    async fn get_kv(
        &self,
        topic: &str,
        key: &str,
    ) -> std::result::Result<Option<KvValue>, ClientError> {
        X0xdApi::get_kv(self, topic, key).await
    }

    async fn put_kv(
        &self,
        topic: &str,
        key: &str,
        value: &[u8],
        content_type: &str,
    ) -> std::result::Result<(), ClientError> {
        X0xdApi::put_kv(self, topic, key, value, content_type).await
    }
}

/// Content type for v2 envelope records.
pub const V2_ENVELOPE_CONTENT_TYPE: &str = "application/x0x-symphony-v2+json";

/// Content type for the raw `card-self` public key bytes.
pub const CARD_SELF_CONTENT_TYPE: &str = "application/octet-stream";

/// Store policy mode for newly created v2 event stores.
///
/// See the module docs for the WP-X dependency gate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StorePolicyMode {
    /// Require `append_only` (the design-mandated policy). Creation fails
    /// loudly when the daemon does not honor it.
    #[default]
    AppendOnly,
    /// TODO(x0x WP-X, x0x-symphony#10): interim fallback for x0xd ≤ v0.32.x —
    /// creates mutable `signed` stores. The C1 deletion residual is NOT
    /// closed in this mode; remove once x0x v0.33.0 is the baseline.
    SignedFallback,
}

impl StorePolicyMode {
    /// Parse the `v2_store_policy` config value.
    #[must_use]
    pub fn from_config_value(value: &str) -> Option<Self> {
        match value {
            "append_only" => Some(Self::AppendOnly),
            "signed" => Some(Self::SignedFallback),
            _ => None,
        }
    }

    /// Stable config spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppendOnly => "append_only",
            Self::SignedFallback => "signed",
        }
    }
}

/// Result alias for v2 store operations.
pub type Result<T> = std::result::Result<T, V2StoreError>;

/// Errors produced by v2 store management.
#[derive(Debug, thiserror::Error)]
pub enum V2StoreError {
    /// x0xd REST call failed.
    #[error(transparent)]
    Client(#[from] ClientError),

    /// x0xd signing call failed.
    #[error(transparent)]
    Signing(#[from] SigningError),

    /// The daemon did not honor the requested `append_only` policy.
    ///
    /// This is the loud end of the WP-X gate: it means the connected x0xd
    /// predates x0x v0.33.0 / `AccessPolicy::AppendOnly`. Either upgrade the
    /// daemon or explicitly configure `v2_store_policy = "signed"` (interim,
    /// weaker guarantees — see module docs).
    #[error(
        "x0xd did not honor policy append_only for store {topic} (got {actual:?}); \
         upgrade x0xd to >= 0.33.0 or set v2_store_policy = \"signed\" (interim)"
    )]
    PolicyNotHonored {
        /// Store topic.
        topic: String,
        /// Policy the daemon reported.
        actual: Option<String>,
    },

    /// A record that must be written exactly once already exists with
    /// different bytes.
    #[error("immutable record {key} in {topic} already exists with different content")]
    ImmutableConflict {
        /// Store topic.
        topic: String,
        /// Record key.
        key: String,
    },

    /// The local signer's identity did not match expectations.
    #[error("signer identity mismatch: {0}")]
    SignerMismatch(String),

    /// A value failed local validation.
    #[error("invalid v2 record: {0}")]
    Invalid(String),
}

/// The local author's bound event store for one list.
#[derive(Clone, Debug)]
pub struct OwnEventStore {
    /// List uuid.
    pub list_uuid: String,
    /// Local agent id (lowercase hex).
    pub agent_id: String,
    /// Local ML-DSA-65 public key bytes (also published as `card-self`).
    pub public_key: Vec<u8>,
    /// Event-store topic.
    pub topic: String,
    /// Policy the store was created/verified with.
    pub policy: StorePolicyMode,
}

/// Per-author store manager: creates the local author's store, joins roster
/// peers' stores, publishes card-self/genesis/roster records, and appends
/// transitions. All writes are signed through x0xd's `/agent/sign`; all
/// *state* reads flow to the pure fold ([`super::fold::fold_v2`]).
pub struct V2StoreManager {
    api: Arc<dyn V2StoreApi>,
    signer: Arc<dyn SigningClient>,
    mode: StorePolicyMode,
}

impl V2StoreManager {
    /// Construct a manager.
    #[must_use]
    pub fn new(
        api: Arc<dyn V2StoreApi>,
        signer: Arc<dyn SigningClient>,
        mode: StorePolicyMode,
    ) -> Self {
        Self { api, signer, mode }
    }

    /// Return the configured policy mode.
    #[must_use]
    pub const fn mode(&self) -> StorePolicyMode {
        self.mode
    }

    /// Ensure the local author's event store exists for `list_uuid`, with the
    /// configured policy, and that `card-self` is published.
    ///
    /// # Errors
    ///
    /// Returns [`V2StoreError::PolicyNotHonored`] when the daemon ignores the
    /// requested `append_only` policy (WP-X gate), plus client/signing errors
    /// and [`V2StoreError::ImmutableConflict`] when a different `card-self`
    /// is already present.
    pub async fn ensure_own_store(&self, list_uuid: &str) -> Result<OwnEventStore> {
        // Bootstrap the local signer identity + public key out of a sign
        // response (x0xd's sign response carries both).
        let sign = self
            .signer
            .sign(BOOTSTRAP_CONTEXT_V2, b"x0x-symphony-v2-key-bootstrap")
            .await?;
        let public_key =
            decode_b64("public_key_b64", &sign.public_key_b64).map_err(V2StoreError::Invalid)?;
        let derived = super::identity::derive_agent_id_hex(&public_key);
        if derived != sign.agent_id {
            return Err(V2StoreError::SignerMismatch(format!(
                "x0xd reports agent {} but its key derives to {derived}",
                sign.agent_id
            )));
        }
        let topic = event_store_topic(list_uuid, &sign.agent_id);

        // Create the store with the mandated policy (WP-X REST contract:
        // `"policy": "append_only"`). Older daemons silently ignore unknown
        // JSON fields, so the response policy is re-checked below — silence
        // is not acceptance.
        let requested_policy = match self.mode {
            StorePolicyMode::AppendOnly => Some("append_only"),
            StorePolicyMode::SignedFallback => None,
        };
        let outcome = self
            .api
            .create_kv_store_with_policy(&topic, &topic, requested_policy)
            .await;
        match outcome {
            Ok(StoreCreateOutcome { .. }) => {}
            // Already exists (created by an earlier run or an older daemon) —
            // proceed to the policy verification below, which applies to the
            // reused store exactly as it does to a fresh one.
            Err(ClientError::Http { status, .. }) if status == StatusCode::CONFLICT => {}
            Err(e) => return Err(e.into()),
        }

        // Verify the effective policy on EVERY open, not just creation: a
        // store created earlier (or by an older daemon that silently ignored
        // the policy field) as mutable `signed` must never masquerade as
        // append-only. The daemon-reported detail is the source of truth;
        // silence (no policy field, or store missing from the listing) is
        // NOT acceptance.
        match self.mode {
            StorePolicyMode::AppendOnly => {
                let actual = self
                    .api
                    .kv_store_detail(&topic)
                    .await?
                    .and_then(|detail| detail.policy);
                if actual.as_deref() != Some("append_only") {
                    return Err(V2StoreError::PolicyNotHonored { topic, actual });
                }
            }
            StorePolicyMode::SignedFallback => {
                tracing::warn!(
                    topic = %topic,
                    "v2 event store opened with interim signed policy; \
                     append-only guarantees (design r2 C1) are NOT active \
                     (TODO x0x WP-X / x0x-symphony#10)"
                );
            }
        }

        // Publish card-self exactly once (first key each author writes).
        match self.api.get_kv(&topic, CARD_SELF_KEY).await? {
            Some(existing) if existing.value == public_key => {}
            Some(_) => {
                return Err(V2StoreError::ImmutableConflict {
                    topic,
                    key: CARD_SELF_KEY.to_owned(),
                })
            }
            None => {
                self.api
                    .put_kv(&topic, CARD_SELF_KEY, &public_key, CARD_SELF_CONTENT_TYPE)
                    .await?;
            }
        }

        Ok(OwnEventStore {
            list_uuid: list_uuid.to_owned(),
            agent_id: sign.agent_id,
            public_key,
            topic,
            policy: self.mode,
        })
    }

    /// Join a roster peer's event store with the peer as `expected_owner`.
    /// Already-joined (HTTP 409) is success.
    ///
    /// # Errors
    ///
    /// Returns client errors other than 409.
    pub async fn join_peer_store(&self, list_uuid: &str, peer_agent_id: &str) -> Result<String> {
        let topic = event_store_topic(list_uuid, peer_agent_id);
        match self.api.join_kv_store(&topic, peer_agent_id).await {
            Ok(()) => Ok(topic),
            Err(ClientError::Http { status, .. }) if status == StatusCode::CONFLICT => Ok(topic),
            Err(e) => Err(e.into()),
        }
    }

    /// Join every roster peer's store (excluding `own_agent_id`). Returns the
    /// topics joined; individual failures are returned, not swallowed.
    ///
    /// # Errors
    ///
    /// Returns the first join failure.
    pub async fn join_roster_stores(
        &self,
        list_uuid: &str,
        roster: &[String],
        own_agent_id: &str,
    ) -> Result<Vec<String>> {
        let mut topics = Vec::new();
        for peer in roster {
            if peer == own_agent_id {
                continue;
            }
            topics.push(self.join_peer_store(list_uuid, peer).await?);
        }
        Ok(topics)
    }

    /// Sign `payload` under `context` and return the stored envelope, after
    /// checking the signer matches `own`.
    async fn sign_envelope(
        &self,
        own: &OwnEventStore,
        context: &str,
        payload: &[u8],
    ) -> Result<EventEnvelope> {
        let sign = self.signer.sign(context, payload).await?;
        if sign.agent_id != own.agent_id {
            return Err(V2StoreError::SignerMismatch(format!(
                "x0xd signed as {} but the bound store owner is {}",
                sign.agent_id, own.agent_id
            )));
        }
        Ok(EventEnvelope {
            schema: V2_SCHEMA,
            context: context.to_owned(),
            algorithm: sign.algorithm,
            payload_b64: base64_std(payload),
            public_key_b64: sign.public_key_b64,
            signature_b64: sign.signature_b64,
            signer_agent_id: sign.agent_id,
        })
    }

    /// Write an envelope to `key`, tolerating an identical existing record
    /// (idempotent retry) but refusing divergent overwrite.
    async fn put_once(&self, topic: &str, key: &str, envelope: &EventEnvelope) -> Result<()> {
        let bytes = envelope.encode().map_err(V2StoreError::Invalid)?;
        if let Some(KvValue { value, .. }) = self.api.get_kv(topic, key).await? {
            if value == bytes {
                return Ok(());
            }
            return Err(V2StoreError::ImmutableConflict {
                topic: topic.to_owned(),
                key: key.to_owned(),
            });
        }
        match self
            .api
            .put_kv(topic, key, &bytes, V2_ENVELOPE_CONTENT_TYPE)
            .await
        {
            Ok(()) => Ok(()),
            // AppendOnly PUT-to-existing → 409 (WP-X contract): treat a
            // losing race against our own identical retry as conflict.
            Err(ClientError::Http { status, .. }) if status == StatusCode::CONFLICT => {
                Err(V2StoreError::ImmutableConflict {
                    topic: topic.to_owned(),
                    key: key.to_owned(),
                })
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Publish the signed genesis manifest into the creator's (local) store.
    /// Returns `(manifest, genesis_manifest_hash)`.
    ///
    /// # Errors
    ///
    /// Returns signing/client errors, or [`V2StoreError::ImmutableConflict`]
    /// when a different genesis already exists.
    pub async fn publish_genesis(
        &self,
        own: &OwnEventStore,
        roster: Vec<String>,
        required_trust: Option<String>,
        created_at: u64,
    ) -> Result<(GenesisManifestV2, String)> {
        let manifest = GenesisManifestV2 {
            schema: V2_SCHEMA,
            kind: "genesis".to_owned(),
            list_uuid: own.list_uuid.clone(),
            creator: own.agent_id.clone(),
            roster,
            policy: GenesisPolicy { required_trust },
            created_at,
        };
        let payload = serde_json::to_vec(&manifest)
            .map_err(|e| V2StoreError::Invalid(format!("genesis encode failed: {e}")))?;
        let hash = sha256_hex(&payload);
        let envelope = self
            .sign_envelope(own, GENESIS_CONTEXT_V2, &payload)
            .await?;
        self.put_once(&own.topic, GENESIS_KEY, &envelope).await?;
        Ok((manifest, hash))
    }

    /// Publish a creator-signed roster update establishing `roster_epoch`.
    /// Returns the roster event's payload hash.
    ///
    /// # Errors
    ///
    /// Returns signing/client errors.
    pub async fn publish_roster_update(
        &self,
        own: &OwnEventStore,
        genesis_manifest_hash: &str,
        roster_epoch: u64,
        prev_roster_hash: &str,
        roster: Vec<String>,
    ) -> Result<String> {
        let event = RosterEventV2 {
            schema: V2_SCHEMA,
            kind: "roster".to_owned(),
            list_uuid: own.list_uuid.clone(),
            genesis_manifest_hash: genesis_manifest_hash.to_owned(),
            roster_epoch,
            prev_roster_hash: prev_roster_hash.to_owned(),
            roster,
            actor: own.agent_id.clone(),
        };
        let payload = serde_json::to_vec(&event)
            .map_err(|e| V2StoreError::Invalid(format!("roster encode failed: {e}")))?;
        let hash = sha256_hex(&payload);
        let envelope = self.sign_envelope(own, ROSTER_CONTEXT_V2, &payload).await?;
        let key = super::events::roster_key(roster_epoch, &hash);
        self.put_once(&own.topic, &key, &envelope).await?;
        Ok(hash)
    }

    /// Sign and append a transition event to the local author's store, at
    /// its content-addressed key `ev-<issue-id>-<event-hash>`. Returns the
    /// event's payload hash.
    ///
    /// The caller supplies the complete [`TransitionEventV2`] (lamport,
    /// `author_seq`, `prev_own_event_hash` come from the caller's last fold
    /// view — the manager is deliberately mechanical).
    ///
    /// # Errors
    ///
    /// Returns [`V2StoreError::Invalid`] when the event does not name this
    /// store's author/list, plus signing/client errors.
    pub async fn append_transition(
        &self,
        own: &OwnEventStore,
        event: &TransitionEventV2,
    ) -> Result<String> {
        if event.actor != own.agent_id {
            return Err(V2StoreError::Invalid(format!(
                "event actor {} is not the local author {}",
                event.actor, own.agent_id
            )));
        }
        if event.list_uuid != own.list_uuid {
            return Err(V2StoreError::Invalid(format!(
                "event names list {} but this store serves {}",
                event.list_uuid, own.list_uuid
            )));
        }
        let payload = event.to_signed_bytes().map_err(V2StoreError::Invalid)?;
        let hash = sha256_hex(&payload);
        let envelope = self
            .sign_envelope(own, TRANSITION_CONTEXT_V2, &payload)
            .await?;
        let key = event_key(&event.issue_id, &hash);
        self.put_once(&own.topic, &key, &envelope).await?;
        Ok(hash)
    }

    /// Derive a deterministic, per-claim-unique fencing nonce for a new
    /// claim: `SHA-256(author:seq:lamport:issue:claim)`. Uniqueness follows
    /// from the strictly increasing `author_seq` in the author's chain.
    #[must_use]
    pub fn derive_claim_nonce(
        author: &str,
        author_seq: u64,
        lamport: u64,
        issue_id: &str,
    ) -> String {
        sha256_hex(format!("{author}:{author_seq}:{lamport}:{issue_id}:claim").as_bytes())
    }

    /// Read one author's event store into an [`AuthorStream`] for the fold.
    ///
    /// # Errors
    ///
    /// Returns client errors from key listing or value reads.
    pub async fn read_author_stream(
        &self,
        list_uuid: &str,
        author_agent_id: &str,
    ) -> Result<AuthorStream> {
        let topic = event_store_topic(list_uuid, author_agent_id);
        let keys = self.api.list_kv_keys(&topic).await?;
        let mut card_self = None;
        let mut records = Vec::with_capacity(keys.len());
        for entry in keys {
            let Some(value) = self.api.get_kv(&topic, &entry.key).await? else {
                // Deleted between list and read (impossible under
                // append_only; possible under the interim signed fallback).
                continue;
            };
            if entry.key == CARD_SELF_KEY {
                card_self = Some(value.value.clone());
            }
            records.push(StoreRecord {
                key: entry.key,
                value: value.value,
            });
        }
        Ok(AuthorStream {
            owner: author_agent_id.to_owned(),
            card_self,
            records,
        })
    }

    /// Assemble a [`FoldInput`] for a v2 list: read the creator's stream,
    /// pre-extract the genesis roster to learn membership, then read every
    /// member stream. The returned input feeds [`super::fold::fold_v2`]; all
    /// verification happens there (this method only fetches bytes).
    ///
    /// # Errors
    ///
    /// Returns client errors; a missing/invalid genesis is *not* an error
    /// here — the fold refuses the list itself (downgrade defense stays in
    /// the pure layer).
    pub async fn read_fold_input(&self, list_uuid: &str, creator: &str) -> Result<FoldInput> {
        let creator_stream = self.read_author_stream(list_uuid, creator).await?;
        // Best-effort roster pre-extraction, for addressing only: parse the
        // genesis payload WITHOUT trusting it (fold re-verifies everything).
        let mut members: Vec<String> = Vec::new();
        if let Some(record) = creator_stream.records.iter().find(|r| r.key == GENESIS_KEY) {
            if let Ok(envelope) = EventEnvelope::decode(&record.value) {
                if let Ok(payload) = envelope.payload_bytes() {
                    if let Ok(genesis) = serde_json::from_slice::<GenesisManifestV2>(&payload) {
                        members = genesis.roster;
                    }
                }
            }
        }
        let mut streams = vec![creator_stream];
        for member in members {
            if member == creator {
                continue;
            }
            // A member store we cannot read yet (not joined / no data) must
            // not fail the whole list read.
            match self.read_author_stream(list_uuid, &member).await {
                Ok(stream) => streams.push(stream),
                Err(V2StoreError::Client(ClientError::Http { status, .. }))
                    if status == StatusCode::NOT_FOUND =>
                {
                    tracing::debug!(member = %member, "v2 member stream not available yet");
                }
                Err(e) => return Err(e),
            }
        }
        Ok(FoldInput {
            list_uuid: list_uuid.to_owned(),
            creator: creator.to_owned(),
            streams,
        })
    }

    /// Ensure the local author's mutable heartbeat companion store exists and
    /// write `hb-<issue-id>` with the supplied timestamp payload.
    ///
    /// Heartbeats are v1-style mutable liveness signals and are **never**
    /// fold inputs; they cannot live in the append-only event store (updates
    /// would be immutable), so they get a `signed`-policy companion store.
    ///
    /// # Errors
    ///
    /// Returns client errors from store creation or the write.
    pub async fn put_heartbeat(
        &self,
        own: &OwnEventStore,
        issue_id: &str,
        heartbeat_at: &str,
    ) -> Result<()> {
        let topic = heartbeat_store_topic(&own.list_uuid, &own.agent_id);
        match self
            .api
            .create_kv_store_with_policy(&topic, &topic, None)
            .await
        {
            Ok(_) => {}
            Err(ClientError::Http { status, .. }) if status == StatusCode::CONFLICT => {}
            Err(e) => return Err(e.into()),
        }
        let key = format!("hb-{issue_id}");
        self.api
            .put_kv(&topic, &key, heartbeat_at.as_bytes(), "text/plain")
            .await?;
        Ok(())
    }
}

fn base64_std(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use saorsa_pqc::{MlDsa65, MlDsaOperations, MlDsaSecretKey};
    use tokio::sync::Mutex;
    use x0x_symphony_signing::{AgentInfo, SignResponse, VerifyOutcome};

    use super::*;
    use crate::v2::identity::{assemble_external_dst, derive_agent_id_hex};

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    struct MockSigner {
        agent_id: String,
        public_key_b64: String,
        sk: MlDsaSecretKey,
    }

    impl MockSigner {
        fn generate() -> TestResult<Self> {
            let (pk, sk) = MlDsa65::new().generate_keypair()?;
            Ok(Self {
                agent_id: derive_agent_id_hex(pk.as_bytes()),
                public_key_b64: BASE64.encode(pk.as_bytes()),
                sk,
            })
        }
    }

    #[async_trait]
    impl SigningClient for MockSigner {
        async fn sign(
            &self,
            context: &str,
            payload: &[u8],
        ) -> std::result::Result<SignResponse, SigningError> {
            let canonical = assemble_external_dst(context, payload);
            let sig = MlDsa65::new()
                .sign(&self.sk, &canonical)
                .map_err(|e| SigningError::InvalidResponse(format!("{e}")))?;
            Ok(SignResponse {
                agent_id: self.agent_id.clone(),
                public_key_b64: self.public_key_b64.clone(),
                signature_b64: BASE64.encode(sig.as_bytes()),
                algorithm: "x0x.agent-sign.v2.ml-dsa-65".to_owned(),
                context: context.to_owned(),
            })
        }

        async fn verify(
            &self,
            _context: &str,
            _payload: &[u8],
            _signature: &[u8],
            _public_key: &[u8],
        ) -> std::result::Result<VerifyOutcome, SigningError> {
            Ok(VerifyOutcome::Valid)
        }

        async fn agent_identity(&self) -> std::result::Result<AgentInfo, SigningError> {
            Ok(AgentInfo {
                agent_id: self.agent_id.clone(),
            })
        }
    }

    /// What the mock's `GET /stores` reports for the topic.
    #[derive(Clone)]
    enum MockDetail {
        /// Store is not in the listing at all.
        NotListed,
        /// Listed, but the daemon predates the policy field.
        NoPolicyField,
        /// Listed with this policy string.
        Policy(&'static str),
    }

    /// In-memory daemon double for the store manager.
    struct MockApi {
        /// `create` returns 409 when true (store pre-exists).
        store_exists: bool,
        detail: MockDetail,
        kv: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    }

    impl MockApi {
        fn new(store_exists: bool, detail: MockDetail) -> Self {
            Self {
                store_exists,
                detail,
                kv: Mutex::new(BTreeMap::new()),
            }
        }
    }

    #[async_trait]
    impl V2StoreApi for MockApi {
        async fn create_kv_store_with_policy(
            &self,
            _name: &str,
            topic: &str,
            _policy: Option<&str>,
        ) -> std::result::Result<StoreCreateOutcome, ClientError> {
            if self.store_exists {
                return Err(ClientError::Http {
                    status: StatusCode::CONFLICT,
                    body: "store already exists".to_owned(),
                });
            }
            // An old daemon ignores the policy field and reports nothing.
            Ok(StoreCreateOutcome {
                id: topic.to_owned(),
                policy: None,
            })
        }

        async fn join_kv_store(
            &self,
            _topic: &str,
            _expected_owner: &str,
        ) -> std::result::Result<(), ClientError> {
            Ok(())
        }

        async fn kv_store_detail(
            &self,
            topic: &str,
        ) -> std::result::Result<Option<StoreDetailEntry>, ClientError> {
            Ok(match &self.detail {
                MockDetail::NotListed => None,
                MockDetail::NoPolicyField => Some(StoreDetailEntry {
                    id: topic.to_owned(),
                    owner: None,
                    policy: None,
                }),
                MockDetail::Policy(policy) => Some(StoreDetailEntry {
                    id: topic.to_owned(),
                    owner: None,
                    policy: Some((*policy).to_owned()),
                }),
            })
        }

        async fn list_kv_keys(
            &self,
            topic: &str,
        ) -> std::result::Result<Vec<KvKeyEntry>, ClientError> {
            let kv = self.kv.lock().await;
            Ok(kv
                .keys()
                .filter(|(t, _)| t == topic)
                .map(|(_, key)| KvKeyEntry {
                    key: key.clone(),
                    content_type: None,
                    content_hash: None,
                    size: 0,
                    updated_at: None,
                })
                .collect())
        }

        async fn get_kv(
            &self,
            topic: &str,
            key: &str,
        ) -> std::result::Result<Option<KvValue>, ClientError> {
            let kv = self.kv.lock().await;
            Ok(kv
                .get(&(topic.to_owned(), key.to_owned()))
                .map(|value| KvValue {
                    key: key.to_owned(),
                    value: value.clone(),
                    content_type: None,
                    content_hash: None,
                    created_at: None,
                    updated_at: None,
                }))
        }

        async fn put_kv(
            &self,
            topic: &str,
            key: &str,
            value: &[u8],
            _content_type: &str,
        ) -> std::result::Result<(), ClientError> {
            let mut kv = self.kv.lock().await;
            kv.insert((topic.to_owned(), key.to_owned()), value.to_vec());
            Ok(())
        }
    }

    fn manager(api: MockApi, signer: MockSigner, mode: StorePolicyMode) -> V2StoreManager {
        V2StoreManager::new(Arc::new(api), Arc::new(signer), mode)
    }

    /// FIX 1 (Codex review of PR #11): a store that ALREADY EXISTS as
    /// mutable `signed` must be refused in append-only mode — reuse must
    /// never silently defeat C1.
    #[tokio::test]
    async fn reused_mutable_store_is_refused_in_append_only_mode() -> TestResult {
        let mgr = manager(
            MockApi::new(true, MockDetail::Policy("signed")),
            MockSigner::generate()?,
            StorePolicyMode::AppendOnly,
        );
        let result = mgr.ensure_own_store("list-1").await;
        assert!(matches!(
            result,
            Err(V2StoreError::PolicyNotHonored {
                actual: Some(ref p),
                ..
            }) if p == "signed"
        ));
        Ok(())
    }

    /// Silence is not acceptance: an existing store whose listing omits the
    /// policy field entirely (pre-policy daemon) is refused too.
    #[tokio::test]
    async fn reused_store_with_absent_policy_is_refused() -> TestResult {
        let mgr = manager(
            MockApi::new(true, MockDetail::NoPolicyField),
            MockSigner::generate()?,
            StorePolicyMode::AppendOnly,
        );
        assert!(matches!(
            mgr.ensure_own_store("list-1").await,
            Err(V2StoreError::PolicyNotHonored { actual: None, .. })
        ));
        // Store 409s on create but is missing from GET /stores: also refused.
        let mgr = manager(
            MockApi::new(true, MockDetail::NotListed),
            MockSigner::generate()?,
            StorePolicyMode::AppendOnly,
        );
        assert!(matches!(
            mgr.ensure_own_store("list-1").await,
            Err(V2StoreError::PolicyNotHonored { actual: None, .. })
        ));
        Ok(())
    }

    /// A fresh create against an old daemon that ignored the policy flag is
    /// refused by the same post-create verification.
    #[tokio::test]
    async fn fresh_create_on_policy_ignoring_daemon_is_refused() -> TestResult {
        let mgr = manager(
            MockApi::new(false, MockDetail::Policy("signed")),
            MockSigner::generate()?,
            StorePolicyMode::AppendOnly,
        );
        assert!(matches!(
            mgr.ensure_own_store("list-1").await,
            Err(V2StoreError::PolicyNotHonored { .. })
        ));
        Ok(())
    }

    /// Honored `append_only` (fresh or reused) proceeds and publishes card-self.
    #[tokio::test]
    async fn honored_append_only_store_proceeds_and_publishes_card_self() -> TestResult {
        let signer = MockSigner::generate()?;
        let expected_agent = signer.agent_id.clone();
        let mgr = manager(
            MockApi::new(true, MockDetail::Policy("append_only")),
            signer,
            StorePolicyMode::AppendOnly,
        );
        let own = mgr.ensure_own_store("list-1").await?;
        assert_eq!(own.agent_id, expected_agent);
        assert_eq!(own.policy, StorePolicyMode::AppendOnly);
        Ok(())
    }

    /// The explicit interim fallback still works against mutable stores.
    #[tokio::test]
    async fn signed_fallback_mode_accepts_mutable_store() -> TestResult {
        let mgr = manager(
            MockApi::new(true, MockDetail::Policy("signed")),
            MockSigner::generate()?,
            StorePolicyMode::SignedFallback,
        );
        let own = mgr.ensure_own_store("list-1").await?;
        assert_eq!(own.policy, StorePolicyMode::SignedFallback);
        Ok(())
    }

    #[test]
    fn policy_mode_config_parsing() {
        assert_eq!(
            StorePolicyMode::from_config_value("append_only"),
            Some(StorePolicyMode::AppendOnly)
        );
        assert_eq!(
            StorePolicyMode::from_config_value("signed"),
            Some(StorePolicyMode::SignedFallback)
        );
        assert_eq!(StorePolicyMode::from_config_value("other"), None);
        assert_eq!(StorePolicyMode::default(), StorePolicyMode::AppendOnly);
    }

    #[test]
    fn claim_nonce_is_deterministic_and_seq_unique() {
        let a = V2StoreManager::derive_claim_nonce("author", 1, 10, "issue");
        let b = V2StoreManager::derive_claim_nonce("author", 1, 10, "issue");
        let c = V2StoreManager::derive_claim_nonce("author", 2, 10, "issue");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
