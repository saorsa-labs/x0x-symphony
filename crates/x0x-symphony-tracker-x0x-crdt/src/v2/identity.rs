//! Pure, local replication of x0x's external signing scheme and agent-id
//! derivation for tracker-integrity v2.
//!
//! The v2 fold ([`crate::v2::fold`]) must verify event envelopes without I/O,
//! so this module re-implements — byte for byte — the two x0x primitives that
//! `/agent/sign` and `/agent/verify` are built on:
//!
//! 1. **External DST (domain-separation tag) assembly.** x0xd signs
//!    `[0xF0] || b"x0x.external-agent-sign.v1" || context_len(u32 BE) || context || payload`
//!    (x0x `src/api/agent_signing.rs`, issue x0x#133). [`assemble_external_dst`]
//!    reproduces that layout exactly, so a signature minted by `/agent/sign`
//!    verifies locally through saorsa-pqc without a daemon round-trip.
//! 2. **Agent-id derivation.** x0x agent ids are
//!    `SHA-256(b"AUTONOMI_PEER_ID_V2:" || ml_dsa_65_public_key_bytes)`
//!    (ant-quic `src/crypto/raw_public_keys/pqc.rs::derive_peer_id_from_public_key`).
//!    [`derive_agent_id_hex`] reproduces the derivation, which makes every
//!    author binding *self-certifying*: possession of a public key proves the
//!    agent id, no TOFU key exchange required (design r2, finding C5).
//!
//! Both constants are pinned by unit tests against vectors computed
//! independently (outside this codebase), and the live test
//! `tests/v2_live_x0xd.rs` cross-checks a real `/agent/sign` response against
//! this local verifier when a daemon is available.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use saorsa_pqc::{MlDsa65, MlDsaOperations, MlDsaPublicKey, MlDsaSignature};
use x0x_symphony_core::sha256_hex;

/// Reserved leading byte of x0x's external-signing namespace.
///
/// Mirrors `x0x::api::agent_signing::NAMESPACE_TAG`.
pub const NAMESPACE_TAG: u8 = 0xF0;

/// ASCII magic pinning the external-signing DST layout version.
///
/// Mirrors `x0x::api::agent_signing::MAGIC`.
pub const MAGIC: &[u8] = b"x0x.external-agent-sign.v1";

/// Domain-separation prefix used by ant-quic when deriving a peer/agent id
/// from an ML-DSA-65 public key.
///
/// Mirrors `ant_quic::crypto::raw_public_keys::pqc::derive_peer_id_from_public_key`.
pub const AGENT_ID_DOMAIN_PREFIX: &[u8] = b"AUTONOMI_PEER_ID_V2:";

/// ML-DSA-65 public key size in bytes (FIPS 204).
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;

/// ML-DSA-65 signature size in bytes (FIPS 204).
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;

/// Assemble the canonical x0x external signing buffer for `context`/`payload`.
///
/// Layout: `[NAMESPACE_TAG] || MAGIC || context_len(u32 BE) || context || payload`.
/// This must stay byte-identical to x0xd's `assemble_buffer`; the u32
/// length prefix makes the `context || payload` boundary unambiguous.
#[must_use]
pub fn assemble_external_dst(context: &str, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + MAGIC.len() + 4 + context.len() + payload.len());
    buf.push(NAMESPACE_TAG);
    buf.extend_from_slice(MAGIC);
    let len = u32::try_from(context.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(context.as_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Derive the lowercase-hex x0x agent id for an ML-DSA-65 public key.
///
/// `SHA-256(b"AUTONOMI_PEER_ID_V2:" || public_key_bytes)`, hex-encoded.
/// The caller is expected to have length-checked `public_key` (the function
/// itself is total: it hashes whatever bytes it is given).
#[must_use]
pub fn derive_agent_id_hex(public_key: &[u8]) -> String {
    let mut input = Vec::with_capacity(AGENT_ID_DOMAIN_PREFIX.len() + public_key.len());
    input.extend_from_slice(AGENT_ID_DOMAIN_PREFIX);
    input.extend_from_slice(public_key);
    sha256_hex(&input)
}

/// Why a detached-signature check failed. Purely descriptive; admission maps
/// this into a rejection reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureCheckError {
    /// The public key was not exactly [`ML_DSA_65_PUBLIC_KEY_SIZE`] bytes or
    /// failed to parse.
    BadPublicKey(String),
    /// The signature was not exactly [`ML_DSA_65_SIGNATURE_SIZE`] bytes or
    /// failed to parse.
    BadSignature(String),
    /// The ML-DSA-65 verification computation itself errored.
    VerifyFailed(String),
    /// The signature did not verify for the supplied payload and key.
    Invalid,
}

impl std::fmt::Display for SignatureCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPublicKey(detail) => write!(f, "bad ML-DSA-65 public key: {detail}"),
            Self::BadSignature(detail) => write!(f, "bad ML-DSA-65 signature: {detail}"),
            Self::VerifyFailed(detail) => write!(f, "ML-DSA-65 verification errored: {detail}"),
            Self::Invalid => write!(f, "signature does not verify"),
        }
    }
}

impl std::error::Error for SignatureCheckError {}

/// Verify a detached ML-DSA-65 signature over the x0x external DST for
/// `context`/`payload`.
///
/// This is the local, pure equivalent of `POST /agent/verify`: it
/// reconstructs the canonical buffer with [`assemble_external_dst`] and runs
/// FIPS-204 verification via saorsa-pqc (the same implementation x0xd links
/// through ant-quic).
///
/// # Errors
///
/// Returns [`SignatureCheckError`] when key or signature bytes are malformed,
/// when verification errors, or when the signature simply does not verify
/// ([`SignatureCheckError::Invalid`]).
pub fn verify_external_signature(
    context: &str,
    payload: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), SignatureCheckError> {
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
        return Err(SignatureCheckError::BadPublicKey(format!(
            "expected {ML_DSA_65_PUBLIC_KEY_SIZE} bytes, got {}",
            public_key.len()
        )));
    }
    if signature.len() != ML_DSA_65_SIGNATURE_SIZE {
        return Err(SignatureCheckError::BadSignature(format!(
            "expected {ML_DSA_65_SIGNATURE_SIZE} bytes, got {}",
            signature.len()
        )));
    }
    let pk = MlDsaPublicKey::from_bytes(public_key)
        .map_err(|e| SignatureCheckError::BadPublicKey(format!("{e}")))?;
    let sig = MlDsaSignature::from_bytes(signature)
        .map_err(|e| SignatureCheckError::BadSignature(format!("{e}")))?;
    let canonical = assemble_external_dst(context, payload);
    let valid = MlDsa65::new()
        .verify(&pk, &canonical, &sig)
        .map_err(|e| SignatureCheckError::VerifyFailed(format!("{e}")))?;
    if valid {
        Ok(())
    } else {
        Err(SignatureCheckError::Invalid)
    }
}

/// Decode a base64 field, mapping failures to a descriptive string.
///
/// # Errors
///
/// Returns a human-readable reason when `value` is not valid base64.
pub fn decode_b64(field: &str, value: &str) -> Result<Vec<u8>, String> {
    BASE64
        .decode(value)
        .map_err(|e| format!("invalid base64 in {field}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    /// Vector computed independently (Python hashlib) from the ant-quic
    /// derivation spec: pubkey bytes = `(i*7+3) % 256` for `i in 0..1952`.
    #[test]
    fn agent_id_derivation_matches_independent_vector() {
        let pk: Vec<u8> = (0..1952u32)
            .map(|i| u8::try_from((i * 7 + 3) % 256).unwrap_or(0))
            .collect();
        assert_eq!(
            derive_agent_id_hex(&pk),
            "33cc4857a534021dcd9ee6679bcea3fc8cc3fb53ec0891c859b2698f6525882b"
        );
    }

    /// Vector computed independently (Python hashlib) from the x0x DST spec:
    /// `SHA-256(assemble("ctx", b"payload"))`.
    #[test]
    fn dst_assembly_matches_independent_vector() {
        let buf = assemble_external_dst("ctx", b"payload");
        assert_eq!(buf[0], NAMESPACE_TAG);
        assert_eq!(&buf[1..=MAGIC.len()], MAGIC);
        assert_eq!(
            x0x_symphony_core::sha256_hex(&buf),
            "800a353496a20b846beb5ad4869c0e3d08886bfca0e5e94539eac6a607cfa05d"
        );
    }

    #[test]
    fn dst_length_prefix_prevents_boundary_smuggling() {
        assert_ne!(
            assemble_external_dst("ab", b"cd"),
            assemble_external_dst("abc", b"d")
        );
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper_rejection() -> TestResult {
        let (pk, sk) = MlDsa65::new().generate_keypair()?;
        let payload = b"v2 event payload";
        let canonical = assemble_external_dst("x0x-symphony-transition-v2", payload);
        let sig = MlDsa65::new().sign(&sk, &canonical)?;

        verify_external_signature(
            "x0x-symphony-transition-v2",
            payload,
            sig.as_bytes(),
            pk.as_bytes(),
        )?;

        // Tampered payload fails.
        assert_eq!(
            verify_external_signature(
                "x0x-symphony-transition-v2",
                b"v2 event payloaD",
                sig.as_bytes(),
                pk.as_bytes(),
            ),
            Err(SignatureCheckError::Invalid)
        );

        // Same payload under another context fails: context is bound into
        // the DST, so signatures never transfer across domains.
        assert_eq!(
            verify_external_signature(
                "x0x-symphony-approval-v2",
                payload,
                sig.as_bytes(),
                pk.as_bytes(),
            ),
            Err(SignatureCheckError::Invalid)
        );
        Ok(())
    }

    #[test]
    fn malformed_key_and_signature_lengths_rejected() {
        let err =
            verify_external_signature("c", b"p", &[0u8; 10], &[0u8; ML_DSA_65_PUBLIC_KEY_SIZE]);
        assert!(matches!(err, Err(SignatureCheckError::BadSignature(_))));
        let err =
            verify_external_signature("c", b"p", &[0u8; ML_DSA_65_SIGNATURE_SIZE], &[0u8; 10]);
        assert!(matches!(err, Err(SignatureCheckError::BadPublicKey(_))));
    }
}
