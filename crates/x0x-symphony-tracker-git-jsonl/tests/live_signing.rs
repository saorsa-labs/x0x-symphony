// Live x0xd signing integration tests.
//
// These tests are ignored by default because they require a running x0xd with
// `/agent/sign` and `/agent/verify` enabled.
//
// Manual run:
//
// X0XD_URL=http://127.0.0.1:<port> \
// X0XD_TOKEN=... \
// cargo test -p x0x-symphony-tracker-git-jsonl --test live_signing -- --ignored --nocapture

use std::{env, error::Error};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use x0x_symphony_core::{AgentId, Claim, IssueId, ShardRole, CLAIM_CONTEXT, SIGN_ALGORITHM};
use x0x_symphony_tracker_git_jsonl::signing::{SigningClient, X0xdClient};

const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
const MANUAL_RUN: &str = "X0XD_URL=http://127.0.0.1:<port> X0XD_TOKEN=... \
cargo test -p x0x-symphony-tracker-git-jsonl --test live_signing -- --ignored --nocapture";

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
#[ignore = "requires a running x0xd; set X0XD_URL and run with --ignored"]
async fn live_x0xd_sign_verify_claim_payload_round_trip() -> TestResult {
    let Some(base_url) = live_x0xd_url() else {
        eprintln!(
            "skipping live x0xd signing round trip: set X0XD_URL and optional X0XD_TOKEN, then run `{MANUAL_RUN}`"
        );
        return Ok(());
    };

    let client = X0xdClient::with_token(&base_url, live_x0xd_token())?;
    let claim = Claim::new(
        Some(IssueId::new("XSY-0044")?),
        AgentId::new("x0xd-live-signing-test")?,
        "2026-07-03T00:00:00Z",
        ShardRole::ManualM1,
    );
    let payload = claim.signing_payload_bytes()?;

    let signed = client.sign(CLAIM_CONTEXT, &payload).await?;
    assert_eq!(signed.algorithm, SIGN_ALGORITHM);
    assert_eq!(signed.context, CLAIM_CONTEXT);

    let public_key = BASE64.decode(&signed.public_key_b64)?;
    assert_eq!(
        public_key.len(),
        ML_DSA_65_PUBLIC_KEY_BYTES,
        "x0xd returned an ML-DSA-65 public key with an unexpected decoded size"
    );
    let signature = BASE64.decode(&signed.signature_b64)?;
    assert!(
        !signature.is_empty(),
        "x0xd returned an empty detached signature"
    );

    let verified = client
        .verify(CLAIM_CONTEXT, &payload, &signature, &public_key)
        .await?;
    assert!(
        verified,
        "x0xd /agent/verify rejected the payload signed by /agent/sign"
    );
    Ok(())
}

fn live_x0xd_url() -> Option<String> {
    non_empty_env("X0XD_URL")
}

fn live_x0xd_token() -> Option<String> {
    non_empty_env("X0XD_TOKEN").or_else(|| non_empty_env("X0X_API_TOKEN"))
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}
