use serde::{Deserialize, Serialize};
use x0x_symphony_core::{
    sha256_hex, AgentId, Claim, Handoff, IssueId, Result, ShardRole, SignatureEnvelope,
    ValidationResult, ValidationStatus, CLAIM_CONTEXT, HANDOFF_CONTEXT, SIGN_ALGORITHM,
};

const SIGNER_AGENT_ID: &str = "agent-schema-survival";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ClaimV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issue_id: Option<IssueId>,
    by: AgentId,
    at: String,
    heartbeat_at: String,
    shard_role: ShardRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<SignatureEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    future_field: Option<String>,
}

impl ClaimV2 {
    fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut payload_record = self.clone();
        payload_record.signature = None;
        payload_record.heartbeat_at.clear();
        serde_json::to_vec(&payload_record).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct HandoffV2 {
    summary: String,
    files_changed: Vec<String>,
    validation: Vec<ValidationResult>,
    follow_up: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proofs_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issue_id: Option<IssueId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signer_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<SignatureEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    future_field: Option<String>,
}

impl HandoffV2 {
    fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut payload_record = self.clone();
        payload_record.signature = None;
        serde_json::to_vec(&payload_record).map_err(Into::into)
    }
}

#[test]
fn claim_signature_payload_survives_absent_v2_optional_field() -> Result<()> {
    let mut stored_claim = sample_claim()?;
    let original_payload = stored_claim.signing_payload_bytes()?;
    let original_signature = stand_in_signature(CLAIM_CONTEXT, SIGNER_AGENT_ID, &original_payload);
    stored_claim.signature = Some(original_signature.clone());

    let stored_bytes = serde_json::to_vec(&stored_claim)?;
    let mut extended_reader_claim: ClaimV2 = serde_json::from_slice(&stored_bytes)?;

    assert!(extended_reader_claim.future_field.is_none());
    assert_eq!(
        extended_reader_claim.signature.as_ref(),
        Some(&original_signature)
    );

    extended_reader_claim.signature = None;
    let extended_reader_payload = extended_reader_claim.signing_payload_bytes()?;

    // If this byte-identity assertion fails, signing payload construction has
    // re-derived a canonical projection instead of preserving stored serde bytes.
    assert_eq!(original_payload, extended_reader_payload);
    assert_eq!(
        stand_in_signature(CLAIM_CONTEXT, SIGNER_AGENT_ID, &extended_reader_payload),
        original_signature
    );

    extended_reader_claim.future_field = Some("future claim metadata".to_owned());
    let future_payload = extended_reader_claim.signing_payload_bytes()?;
    let future_signature = stand_in_signature(CLAIM_CONTEXT, SIGNER_AGENT_ID, &future_payload);

    assert_ne!(original_payload, future_payload);
    assert_ne!(original_signature, future_signature);

    Ok(())
}

#[test]
fn handoff_signature_payload_survives_absent_v2_optional_field() -> Result<()> {
    let mut stored_handoff = sample_handoff()?;
    let original_payload = stored_handoff.signing_payload_bytes()?;
    let original_signature =
        stand_in_signature(HANDOFF_CONTEXT, SIGNER_AGENT_ID, &original_payload);
    stored_handoff.signature = Some(original_signature.clone());

    let stored_bytes = serde_json::to_vec(&stored_handoff)?;
    let mut extended_reader_handoff: HandoffV2 = serde_json::from_slice(&stored_bytes)?;

    assert!(extended_reader_handoff.future_field.is_none());
    assert_eq!(
        extended_reader_handoff.signature.as_ref(),
        Some(&original_signature)
    );

    extended_reader_handoff.signature = None;
    let extended_reader_payload = extended_reader_handoff.signing_payload_bytes()?;

    // If this byte-identity assertion fails, signing payload construction has
    // re-derived a canonical projection instead of preserving stored serde bytes.
    assert_eq!(original_payload, extended_reader_payload);
    assert_eq!(
        stand_in_signature(HANDOFF_CONTEXT, SIGNER_AGENT_ID, &extended_reader_payload),
        original_signature
    );

    extended_reader_handoff.future_field = Some("future handoff metadata".to_owned());
    let future_payload = extended_reader_handoff.signing_payload_bytes()?;
    let future_signature = stand_in_signature(HANDOFF_CONTEXT, SIGNER_AGENT_ID, &future_payload);

    assert_ne!(original_payload, future_payload);
    assert_ne!(original_signature, future_signature);

    Ok(())
}

fn sample_claim() -> Result<Claim> {
    let claim = Claim::new(
        Some(IssueId::new("XSY-0046")?),
        AgentId::new(SIGNER_AGENT_ID)?,
        "2026-07-03T00:00:00Z",
        ShardRole::Primary,
    )
    .with_heartbeat("2026-07-03T00:05:00Z");
    Ok(claim)
}

fn sample_handoff() -> Result<Handoff> {
    Ok(Handoff::new("Add schema/signature survival coverage")
        .with_file("crates/x0x-symphony-core/tests/schema_signature_survival.rs")
        .with_validation(ValidationResult::new(
            "cargo nextest run --workspace",
            ValidationStatus::Passed,
        ))
        .with_follow_up("Review byte-identity invariant before future schema bumps")
        .with_proofs_dir("proofs/XSY-0046/2026-07-03T00-00-00Z")
        .with_issue_id(IssueId::new("XSY-0046")?)
        .with_signer_agent_id(SIGNER_AGENT_ID))
}

fn stand_in_signature(context: &str, signer_agent_id: &str, payload: &[u8]) -> SignatureEnvelope {
    let digest = sha256_hex(payload);
    SignatureEnvelope::new(
        SIGN_ALGORITHM,
        context,
        "schema-survival-public-key",
        format!("sha256:{digest}"),
        digest,
        signer_agent_id,
    )
}
