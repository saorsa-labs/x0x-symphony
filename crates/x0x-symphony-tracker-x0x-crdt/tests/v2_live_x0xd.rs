//! Live x0xd tests for tracker-integrity v2 (WP-0).
//!
//! All tests are `#[ignore]`d and require a running daemon named by
//! `X0XD_URL` (token via `X0X_API_TOKEN` when the API is protected):
//!
//! ```sh
//! X0XD_URL=http://127.0.0.1:12700 cargo nextest run --test v2_live_x0xd --run-ignored all
//! ```
//!
//! The store test uses the interim `signed` fallback policy by default so it
//! runs against x0xd ≤ v0.32.x. Set `X0X_V2_APPEND_ONLY=1` once the daemon
//! ships x0x WP-X (`AccessPolicy::AppendOnly`, x0x ≥ 0.33.0) to exercise the
//! design-mandated policy end to end.

use std::{
    env, io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use x0x_symphony_signing::{SigningClient, X0xdClient as SigningX0xdClient};
use x0x_symphony_tracker_x0x_crdt::{
    client::X0xdClient,
    v2::{
        events::BOOTSTRAP_CONTEXT_V2,
        fold_v2,
        identity::{derive_agent_id_hex, verify_external_signature},
        IssueStatusV2, StorePolicyMode, TransitionEventV2, TransitionKind, V2StoreManager,
        V2_SCHEMA,
    },
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn base_url() -> TestResult<String> {
    env::var("X0XD_URL")
        .map_err(|source| io::Error::other(format!("X0XD_URL is required: {source}")).into())
}

fn unique_suffix() -> TestResult<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| io::Error::other(format!("system clock before epoch: {source}")))?
        .as_millis())
}

fn policy_mode() -> StorePolicyMode {
    if env::var("X0X_V2_APPEND_ONLY").is_ok_and(|v| v == "1") {
        StorePolicyMode::AppendOnly
    } else {
        StorePolicyMode::SignedFallback
    }
}

/// THE cross-implementation vector: a signature minted by the live daemon's
/// `/agent/sign` must verify through symphony's local DST + ML-DSA-65
/// replication, and the daemon-reported agent id must equal the local
/// derivation from the daemon's public key.
#[tokio::test]
#[ignore = "requires a running x0xd and X0XD_URL"]
async fn live_agent_sign_verifies_locally_and_derivation_matches() -> TestResult {
    let signer = SigningX0xdClient::new(&base_url()?)?;
    let payload = b"tracker-integrity-v2 live cross-check";
    let response = signer.sign(BOOTSTRAP_CONTEXT_V2, payload).await?;

    let public_key = base64_decode(&response.public_key_b64)?;
    let signature = base64_decode(&response.signature_b64)?;

    // Local verification over the replicated external DST.
    verify_external_signature(BOOTSTRAP_CONTEXT_V2, payload, &signature, &public_key)
        .map_err(|e| io::Error::other(format!("local verify failed: {e}")))?;

    // Local agent-id derivation matches the daemon's reported identity.
    assert_eq!(derive_agent_id_hex(&public_key), response.agent_id);
    Ok(())
}

/// WP-0 end to end against one daemon: own store creation (+card-self),
/// genesis publication, one transition, then fold from a fresh read.
#[tokio::test]
#[ignore = "requires a running x0xd and X0XD_URL"]
async fn live_own_store_genesis_and_fold_roundtrip() -> TestResult {
    let url = base_url()?;
    let api = Arc::new(X0xdClient::new(&url)?);
    let signer: Arc<dyn SigningClient> = Arc::new(SigningX0xdClient::new(&url)?);
    let manager = V2StoreManager::new(api, signer, policy_mode());

    let list_uuid = format!("live-v2-{}", unique_suffix()?);
    let own = manager.ensure_own_store(&list_uuid).await?;
    assert_eq!(own.agent_id, derive_agent_id_hex(&own.public_key));

    let (_, genesis_hash) = manager
        .publish_genesis(&own, vec![own.agent_id.clone()], None, 0)
        .await?;

    let issue_id = "live-issue-1";
    let event = TransitionEventV2 {
        schema: V2_SCHEMA,
        list_uuid: list_uuid.clone(),
        genesis_manifest_hash: genesis_hash.clone(),
        roster_epoch: 0,
        issue_id: issue_id.to_owned(),
        actor: own.agent_id.clone(),
        lamport: 1,
        author_seq: 1,
        prev_own_event_hash: genesis_hash,
        kind: TransitionKind::open("live v2 issue".to_owned(), "roundtrip".to_owned()),
    };
    manager.append_transition(&own, &event).await?;

    let input = manager.read_fold_input(&list_uuid, &own.agent_id).await?;
    let out = fold_v2(&input).map_err(|e| io::Error::other(e.to_string()))?;
    let issue = out
        .issues
        .get(issue_id)
        .ok_or_else(|| io::Error::other("folded issue missing"))?;
    assert_eq!(issue.status, IssueStatusV2::Open);
    assert!(
        out.rejections.is_empty(),
        "unexpected: {:?}",
        out.rejections
    );
    Ok(())
}

fn base64_decode(value: &str) -> TestResult<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    Ok(STANDARD.decode(value)?)
}
