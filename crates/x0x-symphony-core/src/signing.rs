//! Signing envelope and deterministic payload helpers.
//!
//! Claims and handoffs are signed through x0xd's external ML-DSA-65 signing
//! API. Symphony sends the raw payload bytes returned by these helpers to both
//! `/agent/sign` and `/agent/verify`; x0xd reconstructs its domain-separated
//! transaction buffer internally on both endpoints.

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::{Handoff, Result};

/// Stable signing scheme identifier returned by x0xd for ML-DSA-65 signatures.
pub const SIGN_ALGORITHM: &str = "x0x.agent-sign.v2.ml-dsa-65";

/// Domain-separation context for claim records.
pub const CLAIM_CONTEXT: &str = "x0x-symphony-claim-v1";

/// Domain-separation context for handoff records.
pub const HANDOFF_CONTEXT: &str = "x0x-symphony-handoff-v1";

/// Detached signature metadata stored beside a signed claim or handoff.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignatureEnvelope {
    /// Signing scheme identifier; must be [`SIGN_ALGORITHM`].
    #[serde(deserialize_with = "deserialize_algorithm")]
    pub algorithm: String,
    /// Domain-separation context used for this payload.
    pub context: String,
    /// Base64-encoded ML-DSA-65 public key (1952 decoded bytes).
    pub public_key_b64: String,
    /// Base64-encoded detached ML-DSA-65 signature (3309 decoded bytes).
    pub signature_b64: String,
    /// Lowercase hex SHA-256 of the exact raw payload bytes sent to x0xd.
    pub payload_sha256: String,
    /// x0x agent id that produced the signature.
    pub signer_agent_id: String,
}

impl SignatureEnvelope {
    /// Build a signature envelope from x0xd's sign response fields.
    #[must_use]
    pub fn new(
        algorithm: impl Into<String>,
        context: impl Into<String>,
        public_key_b64: impl Into<String>,
        signature_b64: impl Into<String>,
        payload_sha256: impl Into<String>,
        signer_agent_id: impl Into<String>,
    ) -> Self {
        Self {
            algorithm: algorithm.into(),
            context: context.into(),
            public_key_b64: public_key_b64.into(),
            signature_b64: signature_b64.into(),
            payload_sha256: payload_sha256.into(),
            signer_agent_id: signer_agent_id.into(),
        }
    }
}

impl crate::Claim {
    /// Return deterministic raw bytes signed by x0xd for this claim.
    ///
    /// The serialized payload is the claim as stored, excluding the signature
    /// envelope itself. `heartbeat_at` is intentionally normalized to the empty
    /// string before serialization: heartbeats are mutable liveness signals, not
    /// an ownership attestation, so refreshing a heartbeat does not invalidate
    /// the claim signature.
    ///
    /// Symphony sends these raw bytes to `/agent/sign` and `/agent/verify`;
    /// x0xd reconstructs the external DST internally for both endpoints.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the claim cannot be encoded.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut clone = self.clone();
        clone.signature = None;
        clone.heartbeat_at.clear();
        serde_json::to_vec(&clone).map_err(Into::into)
    }

    /// Return the SHA-256 hex digest of [`Self::signing_payload_bytes`].
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the claim cannot be encoded.
    pub fn signing_payload_sha256(&self) -> Result<String> {
        self.signing_payload_bytes()
            .map(|payload| sha256_hex(&payload))
    }
}

impl Handoff {
    /// Return deterministic raw bytes signed by x0xd for this handoff.
    ///
    /// The serialized payload is the handoff as stored, excluding the signature
    /// envelope itself. Additive optional fields that are absent remain absent,
    /// preserving the bytes committed by older records.
    ///
    /// Symphony sends these raw bytes to `/agent/sign` and `/agent/verify`;
    /// x0xd reconstructs the external DST internally for both endpoints.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the handoff cannot be encoded.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut clone = self.clone();
        clone.signature = None;
        serde_json::to_vec(&clone).map_err(Into::into)
    }

    /// Return the SHA-256 hex digest of [`Self::signing_payload_bytes`].
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the handoff cannot be encoded.
    pub fn signing_payload_sha256(&self) -> Result<String> {
        self.signing_payload_bytes()
            .map(|payload| sha256_hex(&payload))
    }
}

/// Return lowercase hex SHA-256 for arbitrary bytes.
#[must_use]
pub fn sha256_hex(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    let mut encoded = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        encoded.push(hex_nibble(byte >> 4));
        encoded.push(hex_nibble(byte & 0x0f));
    }
    encoded
}

fn hex_nibble(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'a' + (nibble - 10)),
        _ => '0',
    }
}

fn deserialize_algorithm<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<String>::deserialize(deserializer)? {
        Some(value) => Ok(value),
        None => Ok(String::new()),
    }
}
