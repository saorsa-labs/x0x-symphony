//! Worker advertisement records shared by daemons.
//!
//! A [`WorkerCard`] is a short-lived, signed statement of one daemon's current
//! worker capabilities. The card payload is signed without its detached
//! signature envelope so receivers can deterministically re-create the exact
//! bytes verified through x0xd.

use std::time::Duration;

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

use crate::{sha256_hex, AgentId, Result, SignatureEnvelope};

/// Domain-separation context for signed worker advertisement cards.
pub const WORKER_CARD_CONTEXT: &str = "x0x-symphony-worker-card-v1";

/// Current worker-card schema version.
pub const WORKER_CARD_SCHEMA_VERSION: u32 = 1;

/// Default worker-card TTL used when workflow config omits `workers.ttl_seconds`.
pub const DEFAULT_WORKER_CARD_TTL_SECONDS: u64 = 60;

/// Platform details advertised by a worker daemon.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// Operating system identifier reported by Rust's target constants.
    pub os: String,
    /// CPU architecture identifier reported by Rust's target constants.
    pub arch: String,
    /// x0x-symphony package version of the advertising daemon.
    pub version: String,
}

impl PlatformInfo {
    /// Build platform info for the currently running binary.
    #[must_use]
    pub fn current() -> Self {
        Self {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

/// Signed worker advertisement broadcast on the worker gossip topic.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerCard {
    /// Version of this card schema. Version 1 is the initial gossip format.
    pub schema_version: u32,
    /// Agent identity of the daemon that issued and signed this card.
    pub agent_id: AgentId,
    /// Issuance timestamp as RFC3339 UTC text.
    pub issued_at: String,
    /// Validity window in seconds from [`Self::issued_at`].
    pub ttl_seconds: u64,
    /// Free-form capability tags advertised by the worker.
    pub capabilities: Vec<String>,
    /// Supported sandbox profile or policy labels.
    pub sandbox_levels: Vec<String>,
    /// Available runner preset names.
    pub runner_presets: Vec<String>,
    /// Number of dispatches currently in flight on this worker.
    pub current_load: u32,
    /// Capacity hint for the maximum concurrent dispatches this worker accepts.
    pub max_load: u32,
    /// Platform details for compatibility-aware scheduling.
    pub platform: PlatformInfo,
    /// Detached signature envelope. Cards are constructed unsigned and signed
    /// immediately before publication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureEnvelope>,
}

impl WorkerCard {
    /// Return deterministic raw bytes signed by x0xd for this worker card.
    ///
    /// The serialized payload is the card as stored, excluding the signature
    /// envelope itself.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the card cannot be encoded.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut clone = self.clone();
        clone.signature = None;
        serde_json::to_vec(&clone).map_err(Into::into)
    }

    /// Return the SHA-256 hex digest of [`Self::signing_payload_bytes`].
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the card cannot be encoded.
    pub fn signing_payload_sha256(&self) -> Result<String> {
        self.signing_payload_bytes()
            .map(|payload| sha256_hex(&payload))
    }

    /// Return `true` when `now` is at or after this card's expiration instant.
    ///
    /// Timestamp parse failures fail closed and are treated as expired.
    #[must_use]
    pub fn is_expired(&self, now: &str) -> bool {
        let Some(issued_at) = parse_timestamp(&self.issued_at) else {
            return true;
        };
        let Some(now) = parse_timestamp(now) else {
            return true;
        };
        let Ok(ttl) = chrono::Duration::from_std(Duration::from_secs(self.ttl_seconds)) else {
            return true;
        };
        now >= issued_at + ttl
    }
}

fn parse_timestamp(value: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SIGN_ALGORITHM, WORKER_CARD_CONTEXT};

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn worker_card_signing_payload_round_trips_without_signature() -> TestResult {
        let mut card = sample_card()?;
        let unsigned_payload = card.signing_payload_bytes()?;
        let payload_sha256 = card.signing_payload_sha256()?;
        card.signature = Some(SignatureEnvelope::new(
            SIGN_ALGORITHM,
            WORKER_CARD_CONTEXT,
            "public-key",
            "signature",
            payload_sha256,
            card.agent_id.to_string(),
        ));

        assert_eq!(card.schema_version, WORKER_CARD_SCHEMA_VERSION);
        assert_eq!(card.signing_payload_bytes()?, unsigned_payload);
        let decoded: WorkerCard = serde_json::from_slice(&unsigned_payload)?;
        assert_eq!(decoded.signature, None);
        assert_eq!(decoded.schema_version, WORKER_CARD_SCHEMA_VERSION);
        assert_eq!(decoded.agent_id, card.agent_id);
        Ok(())
    }

    #[test]
    fn worker_card_expiration_compares_issued_at_plus_ttl() -> TestResult {
        let mut card = sample_card()?;
        card.issued_at = "2026-07-03T12:00:00Z".to_owned();
        card.ttl_seconds = 60;

        assert!(!card.is_expired("2026-07-03T12:00:59Z"));
        assert!(card.is_expired("2026-07-03T12:01:00Z"));
        assert!(card.is_expired("not-a-timestamp"));
        Ok(())
    }

    fn sample_card() -> TestResult<WorkerCard> {
        Ok(WorkerCard {
            schema_version: WORKER_CARD_SCHEMA_VERSION,
            agent_id: AgentId::new("agent-a")?,
            issued_at: "2026-07-03T12:00:00Z".to_owned(),
            ttl_seconds: 60,
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
        })
    }
}
