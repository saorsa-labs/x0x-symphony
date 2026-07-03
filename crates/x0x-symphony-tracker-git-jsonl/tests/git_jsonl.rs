use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use proptest::{prelude::*, test_runner::TestCaseError};
use serde_json::{Map, Value};
use tempfile::TempDir;
use x0x_symphony_core::{
    sha256_hex, AgentId, Claim, Handoff, Issue, IssueId, IssueRef, IssueState, PollContext,
    ReleaseReason, ReleaseReasonCode, Shard, ShardRole, SignatureEnvelope, Tracker,
    ValidationResult, ValidationStatus, CLAIM_CONTEXT, HANDOFF_CONTEXT, SIGN_ALGORITHM,
};
use x0x_symphony_tracker_git_jsonl::{
    parse_issue_line, serialize_issue,
    signing::{
        AgentInfo, SignResponse, SigningClient, SigningError, SigningPolicy, TrustedKeyResolver,
        VerifyOutcome,
    },
    IssueDraft, JsonlTracker, TrackerError,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

const V1_ISSUE_FIXTURE: &str = include_str!("fixtures/v1_issue.json");

#[tokio::test]
async fn round_trip_create_claim_heartbeat_handoff_review() -> TestResult {
    let repo = init_repo()?;
    let tracker = JsonlTracker::new(repo.path());
    let issue = tracker.create_issue(
        IssueDraft::new("Implement adapter")?
            .with_description("Exercise the full JSONL tracker lifecycle.")
            .with_priority(2)
            .with_label("x0x-symphony"),
    )?;
    assert_eq!(issue.id.as_str(), "XSY-0001");

    let agent = AgentId::new("agent-a")?;
    let claim = tracker.claim(&issue.id, &agent).await?;
    tracker.heartbeat(&claim).await?;
    let handoff = Handoff::new("adapter lifecycle completed")
        .with_file("crates/x0x-symphony-tracker-git-jsonl/src/lib.rs")
        .with_validation(ValidationResult::new(
            "integration lifecycle",
            ValidationStatus::Passed,
        ));
    tracker.handoff(&claim, handoff).await?;

    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].state, IssueState::new("review")?);
    assert!(fetched[0].claim.is_none());
    assert!(fetched[0].handoff.is_some());
    assert_eq!(commit_count(repo.path())?, 5);
    Ok(())
}

#[tokio::test]
async fn create_issue_assigns_shard_from_static_workers() -> TestResult {
    let repo = init_plain()?;
    let workers = vec![
        AgentId::new("agent-a")?,
        AgentId::new("agent-b")?,
        AgentId::new("agent-c")?,
        AgentId::new("agent-d")?,
    ];
    let tracker = JsonlTracker::builder(repo.path())
        .shard_workers(workers.clone())
        .shard_replication_factor(3)
        .build();

    let issue = tracker.create_issue(IssueDraft::new("Assign me")?)?;
    let expected = x0x_symphony_core::shard::assign(&issue.id, &workers, 3)
        .ok_or_else(|| io::Error::other("expected shard for non-empty workers"))?;

    assert_eq!(issue.shard.as_ref(), Some(&expected));
    let primary = issue
        .shard
        .as_ref()
        .map(|shard| shard.primary.clone())
        .ok_or_else(|| io::Error::other("created issue did not include shard"))?;
    let claim = tracker.claim(&issue.id, &primary).await?;
    assert_eq!(claim.shard_role, ShardRole::Primary);
    Ok(())
}

#[tokio::test]
async fn create_issue_without_workers_keeps_manual_m1_claims() -> TestResult {
    let repo = init_plain()?;
    let tracker = JsonlTracker::new(repo.path());
    let issue = tracker.create_issue(IssueDraft::new("Manual fallback")?)?;

    assert!(issue.shard.is_none());
    let claim = tracker.claim(&issue.id, &AgentId::new("agent-a")?).await?;
    assert_eq!(claim.shard_role, ShardRole::ManualM1);
    Ok(())
}

#[tokio::test]
async fn non_shard_worker_cannot_claim_sharded_issue() -> TestResult {
    let repo = init_plain()?;
    let tracker = JsonlTracker::builder(repo.path())
        .shard_workers(vec![AgentId::new("agent-a")?])
        .build();
    let issue = tracker.create_issue(IssueDraft::new("Reject outsider")?)?;

    match tracker.claim(&issue.id, &AgentId::new("agent-b")?).await {
        Err(error) => {
            assert!(error.to_string().contains("not in the issue shard slate"));
            Ok(())
        }
        Ok(_) => Err(Into::into(io::Error::other(
            "non-shard worker claim was accepted",
        ))),
    }
}

#[tokio::test]
async fn release_transition_returns_issue_to_todo_without_git() -> TestResult {
    let temp = TempDir::new()?;
    fs::create_dir_all(temp.path().join("issues"))?;
    fs::write(temp.path().join("issues").join("issues.jsonl"), "")?;
    let tracker = JsonlTracker::new(temp.path());
    let issue = tracker.create_issue(IssueDraft::new("Release me")?)?;
    let agent = AgentId::new("agent-a")?;
    let claim = tracker.claim(&issue.id, &agent).await?;

    tracker
        .release(
            &claim,
            ReleaseReason::new(ReleaseReasonCode::OperatorCancelled, "test release"),
        )
        .await?;

    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].state, IssueState::new("todo")?);
    assert!(fetched[0].claim.is_none());
    Ok(())
}

#[tokio::test]
async fn fetch_candidates_resolves_blockers_live_by_id() -> TestResult {
    let temp = TempDir::new()?;
    let issues_dir = temp.path().join("issues");
    fs::create_dir_all(&issues_dir)?;
    let lines = [
        issue_json("XSY-0001", "done", Vec::new())?,
        issue_json("XSY-0002", "todo", vec![("XSY-0001", "todo")])?,
        issue_json("XSY-0003", "todo", vec![("XSY-0004", "done")])?,
        issue_json("XSY-0004", "todo", Vec::new())?,
    ];
    fs::write(
        issues_dir.join("issues.jsonl"),
        format!("{}\n", lines.join("\n")),
    )?;

    let tracker = JsonlTracker::new(temp.path());
    let ctx = PollContext::new(
        vec![IssueState::new("todo")?],
        vec![IssueState::new("done")?],
    );
    let candidates = tracker.fetch_candidates(&ctx).await?;
    let ids = candidates
        .iter()
        .map(|issue| issue.id.as_str().to_owned())
        .collect::<Vec<_>>();

    assert!(ids.contains(&"XSY-0002".to_owned()));
    assert!(!ids.contains(&"XSY-0003".to_owned()));
    Ok(())
}

#[test]
fn schema_violation_is_structured() -> TestResult {
    let temp = TempDir::new()?;
    let issues_dir = temp.path().join("issues");
    fs::create_dir_all(&issues_dir)?;
    fs::write(
        issues_dir.join("issues.jsonl"),
        "{\"id\":\"\",\"identifier\":\"XSY-0001\",\"title\":\"Bad\",\"description\":\"\",\"priority\":2,\"state\":\"todo\",\"branch_name\":null,\"url\":null,\"labels\":[],\"blocked_by\":[],\"created_at\":\"2026-07-02T00:00:00Z\",\"updated_at\":\"2026-07-02T00:00:00Z\"}\n",
    )?;
    let tracker = JsonlTracker::new(temp.path());

    match tracker.load_issues() {
        Err(TrackerError::Schema { line, reason }) => {
            assert_eq!(line, 1);
            assert!(reason.contains("id"));
            Ok(())
        }
        Err(other) => Err(Into::into(io::Error::other(format!(
            "unexpected error: {other}"
        )))),
        Ok(_) => Err(Into::into(io::Error::other(
            "schema violation was accepted",
        ))),
    }
}

#[tokio::test]
async fn multiprocess_claims_serialize_on_git_index_lock() -> TestResult {
    let repo = init_repo()?;
    let seed = issue_json("XSY-0001", "todo", Vec::new())?;
    fs::write(
        repo.path().join("issues").join("issues.jsonl"),
        format!("{seed}\n"),
    )?;
    run_git(repo.path(), &["add", "issues/issues.jsonl"])?;
    run_git(repo.path(), &["commit", "-m", "seed claim target"])?;

    let lock_path = git_dir(repo.path())?.join("index.lock");
    fs::write(&lock_path, "held by parent test\n")?;

    let exe = env::current_exe()?;
    let mut child_a = spawn_claim_child(&exe, repo.path(), "agent-a")?;
    let mut child_b = spawn_claim_child(&exe, repo.path(), "agent-b")?;
    thread::sleep(Duration::from_millis(150));
    fs::remove_file(&lock_path)?;

    let output_a = child_a.wait()?;
    let output_b = child_b.wait()?;
    let mut codes = [exit_code(output_a)?, exit_code(output_b)?];
    codes.sort_unstable();
    assert_eq!(codes, [0, 2]);

    let tracker = JsonlTracker::new(repo.path());
    let fetched = tracker.fetch_by_ids(&[IssueId::new("XSY-0001")?]).await?;
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].state, IssueState::new("in_progress")?);
    assert!(fetched[0].claim.is_some());
    Ok(())
}

#[tokio::test]
async fn multiprocess_claim_child() -> TestResult {
    let repo = match env::var("XSY_MULTIPROCESS_REPO") {
        Ok(value) => PathBuf::from(value),
        Err(env::VarError::NotPresent) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let agent = AgentId::new(env::var("XSY_MULTIPROCESS_AGENT")?)?;
    let tracker = JsonlTracker::builder(repo)
        .lock_attempts(80)
        .lock_backoff(Duration::from_millis(10), Duration::from_millis(25))
        .build();
    let issue = IssueId::new("XSY-0001")?;
    match tracker.claim(&issue, &agent).await {
        Ok(_) => std::process::exit(0),
        Err(error) => {
            let message = error.to_string();
            if message.contains("not claimable") || message.contains("active claim") {
                std::process::exit(2);
            }
            Err(io::Error::other(message).into())
        }
    }
}

proptest! {
    #[test]
    fn schema_v1_arbitrary_issue_round_trip_is_byte_identical(
        issue in arbitrary_issue_strategy()
    ) {
        let serialized = serialize_issue(&issue)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let parsed = parse_issue_line(1, &serialized)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let reserialized = serialize_issue(&parsed)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(serialized, reserialized);
    }
}

#[test]
fn unknown_fields_survive_write_read_cycle_byte_for_byte() -> TestResult {
    let temp = TempDir::new()?;
    let issues_dir = temp.path().join("issues");
    fs::create_dir_all(&issues_dir)?;
    let line = v1_issue_with_future_fields();
    let path = issues_dir.join("issues.jsonl");
    fs::write(&path, format!("{line}\n"))?;

    let tracker = JsonlTracker::new(temp.path());
    let loaded = tracker.load_issues()?;
    let issue = loaded
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::other("expected one loaded issue"))?;
    let serialized = serialize_issue(&issue)?;
    fs::write(&path, format!("{serialized}\n"))?;

    let reloaded = tracker.load_issues()?;
    let issue = reloaded
        .first()
        .ok_or_else(|| io::Error::other("expected one reloaded issue"))?;
    assert_eq!(serialize_issue(issue)?, line);
    assert_eq!(
        issue.extra.get("future_field"),
        Some(&serde_json::json!([1, 2, 3]))
    );
    assert_eq!(
        issue.extra.get("another"),
        Some(&serde_json::json!({"nested": true}))
    );
    Ok(())
}

#[test]
fn legacy_issue_defaults_schema_version_and_writes_v1() -> TestResult {
    let temp = TempDir::new()?;
    let issues_dir = temp.path().join("issues");
    fs::create_dir_all(&issues_dir)?;
    let legacy = issue_json("XSY-0200", "todo", Vec::new())?;
    let path = issues_dir.join("issues.jsonl");
    fs::write(&path, format!("{legacy}\n"))?;

    let tracker = JsonlTracker::new(temp.path());
    let loaded = tracker.load_issues()?;
    let issue = loaded
        .first()
        .ok_or_else(|| io::Error::other("expected one legacy issue"))?;
    assert_eq!(issue.schema_version, 1);

    let serialized = serialize_issue(issue)?;
    fs::write(&path, format!("{serialized}\n"))?;
    let written = fs::read_to_string(&path)?;
    assert!(written.starts_with("{\"schema_version\":1,"));
    Ok(())
}

#[test]
fn canned_v1_fixture_is_byte_stable() -> TestResult {
    let parsed = parse_issue_line(1, V1_ISSUE_FIXTURE)?;
    assert_eq!(parsed.schema_version, 1);
    assert_eq!(serialize_issue(&parsed)?, V1_ISSUE_FIXTURE);
    Ok(())
}

#[tokio::test]
async fn required_policy_signs_and_verifies_claims() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = tracker.create_issue(IssueDraft::new("Signed claim")?)?;
    let agent = AgentId::new(SIGNER)?;

    let claim = tracker.claim(&issue.id, &agent).await?;
    let envelope = claim.signature.as_ref().ok_or("missing claim signature")?;
    assert_eq!(envelope.algorithm, SIGN_ALGORITHM);
    assert_eq!(envelope.context, CLAIM_CONTEXT);
    assert_eq!(envelope.signer_agent_id, SIGNER);

    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(fetched.len(), 1);
    assert!(fetched[0]
        .claim
        .as_ref()
        .and_then(|c| c.signature.as_ref())
        .is_some());
    Ok(())
}

#[tokio::test]
async fn required_policy_signs_and_verifies_handoffs_with_bindings() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = tracker.create_issue(IssueDraft::new("Signed handoff")?)?;
    let agent = AgentId::new(SIGNER)?;
    let claim = tracker.claim(&issue.id, &agent).await?;

    tracker
        .handoff(&claim, Handoff::new("ready").with_file("src/lib.rs"))
        .await?;

    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(fetched.len(), 1);
    let handoff = fetched[0].handoff.as_ref().ok_or("missing handoff")?;
    assert_eq!(handoff.issue_id.as_ref(), Some(&issue.id));
    assert_eq!(handoff.signer_agent_id.as_deref(), Some(SIGNER));
    assert_eq!(
        handoff.signature.as_ref().map(|sig| sig.context.as_str()),
        Some(HANDOFF_CONTEXT)
    );
    Ok(())
}

#[tokio::test]
async fn disabled_policy_allows_unsigned_claims() -> TestResult {
    let repo = init_plain()?;
    let tracker = JsonlTracker::new(repo.path());
    let issue = tracker.create_issue(IssueDraft::new("Unsigned local dev")?)?;
    let agent = AgentId::new("local-dev")?;
    let claim = tracker.claim(&issue.id, &agent).await?;
    assert!(claim.signature.is_none());

    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(fetched.len(), 1);
    assert!(fetched[0].claim.is_some());
    Ok(())
}

#[tokio::test]
async fn required_policy_drops_unsigned_claims() -> TestResult {
    let repo = init_plain()?;
    let unsigned = JsonlTracker::new(repo.path());
    let issue = unsigned.create_issue(IssueDraft::new("Unsigned claim")?)?;
    let agent = AgentId::new(SIGNER)?;
    let _claim = unsigned.claim(&issue.id, &agent).await?;

    let required = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let fetched = required
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert!(fetched.is_empty());
    Ok(())
}

#[tokio::test]
async fn heartbeat_refresh_preserves_claim_signature() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = tracker.create_issue(IssueDraft::new("Heartbeat")?)?;
    let agent = AgentId::new(SIGNER)?;
    let claim = tracker.claim(&issue.id, &agent).await?;
    let before_signature = claim.signature.clone();
    let before_payload = claim.signing_payload_bytes()?;

    tracker.heartbeat(&claim).await?;

    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    let refreshed = fetched
        .first()
        .and_then(|issue| issue.claim.as_ref())
        .ok_or("missing refreshed claim")?;
    assert_eq!(refreshed.signature, before_signature);
    assert_ne!(refreshed.heartbeat_at, claim.heartbeat_at);
    assert_eq!(refreshed.signing_payload_bytes()?, before_payload);
    Ok(())
}

#[tokio::test]
async fn rejects_context_cross_replay_from_claim_to_handoff() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = tracker.create_issue(IssueDraft::new("Cross replay")?)?;
    let agent = AgentId::new(SIGNER)?;
    let claim = tracker.claim(&issue.id, &agent).await?;
    let claim_signature = claim.signature.clone().ok_or("missing claim signature")?;

    let mut tampered = tracker.load_issues()?.remove(0);
    tampered.claim = None;
    tampered.state = IssueState::new("review")?;
    let mut handoff = Handoff::new("bad replay")
        .with_issue_id(issue.id.clone())
        .with_signer_agent_id(SIGNER);
    handoff.signature = Some(claim_signature);
    tampered.handoff = Some(handoff);
    write_single_issue(repo.path(), &tampered)?;

    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert!(fetched.is_empty());
    Ok(())
}

#[tokio::test]
async fn rejects_payload_substitution() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue_a = tracker.create_issue(IssueDraft::new("Payload A")?)?;
    let issue_b = tracker.create_issue(IssueDraft::new("Payload B")?)?;
    let agent = AgentId::new(SIGNER)?;
    let claim_a = tracker.claim(&issue_a.id, &agent).await?;
    let mut claim_b = Claim::new(
        Some(issue_b.id.clone()),
        agent,
        "2026-07-02T01:00:00Z",
        ShardRole::ManualM1,
    );
    claim_b.signature = claim_a.signature;

    let mut issues = tracker.load_issues()?;
    let target = issues
        .iter_mut()
        .find(|issue| issue.id == issue_b.id)
        .ok_or("issue B missing")?;
    target.state = IssueState::new("in_progress")?;
    target.claim = Some(claim_b);
    write_issues(repo.path(), &issues)?;

    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue_b.id))
        .await?;
    assert!(fetched.is_empty());
    Ok(())
}

#[tokio::test]
async fn rejects_envelope_public_key_swap_even_when_verify_would_pass() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = tracker.create_issue(IssueDraft::new("Key swap")?)?;
    let agent = AgentId::new(SIGNER)?;
    let _claim = tracker.claim(&issue.id, &agent).await?;

    let mut tampered = tracker.load_issues()?.remove(0);
    let claim = tampered.claim.as_mut().ok_or("missing claim")?;
    let envelope = claim.signature.as_mut().ok_or("missing signature")?;
    envelope.public_key_b64 = BASE64.encode(OTHER_KEY);
    write_single_issue(repo.path(), &tampered)?;

    let verifier = MockSigningClient {
        verify_always_true: true,
        ..MockSigningClient::default()
    };
    let verifying_tracker = signed_tracker(repo.path(), verifier, trusted_resolver());
    let fetched = verifying_tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert!(fetched.is_empty());
    Ok(())
}

#[tokio::test]
async fn rejects_truncated_and_extended_payload_digests() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = tracker.create_issue(IssueDraft::new("Digest attack")?)?;
    let agent = AgentId::new(SIGNER)?;
    let _claim = tracker.claim(&issue.id, &agent).await?;

    let mut truncated = tracker.load_issues()?.remove(0);
    let claim = truncated.claim.as_mut().ok_or("missing claim")?;
    let payload = claim.signing_payload_bytes()?;
    let envelope = claim.signature.as_mut().ok_or("missing signature")?;
    envelope.payload_sha256 = sha256_hex(&payload[..payload.len().saturating_sub(1)]);
    write_single_issue(repo.path(), &truncated)?;
    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert!(fetched.is_empty());

    let mut extended = truncated;
    let claim = extended.claim.as_mut().ok_or("missing claim")?;
    let mut extended_payload = claim.signing_payload_bytes()?;
    extended_payload.extend_from_slice(b"extra");
    let envelope = claim.signature.as_mut().ok_or("missing signature")?;
    envelope.payload_sha256 = sha256_hex(&extended_payload);
    write_single_issue(repo.path(), &extended)?;
    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert!(fetched.is_empty());
    Ok(())
}

#[tokio::test]
async fn rejects_algorithm_downgrade_and_null() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = tracker.create_issue(IssueDraft::new("Algorithm")?)?;
    let agent = AgentId::new(SIGNER)?;
    let _claim = tracker.claim(&issue.id, &agent).await?;

    let mut downgraded = tracker.load_issues()?.remove(0);
    downgraded
        .claim
        .as_mut()
        .and_then(|claim| claim.signature.as_mut())
        .ok_or("missing signature")?
        .algorithm = "x0x.agent-sign.v1.ml-dsa-65".to_owned();
    write_single_issue(repo.path(), &downgraded)?;
    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert!(fetched.is_empty());

    let mut value = serde_json::to_value(&downgraded)?;
    value["claim"]["signature"]["algorithm"] = Value::Null;
    fs::write(
        repo.path().join("issues").join("issues.jsonl"),
        format!("{}\n", serde_json::to_string(&value)?),
    )?;
    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert!(fetched.is_empty());
    Ok(())
}

#[tokio::test]
async fn rejects_handoff_replay_across_issue_ids() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue_a = tracker.create_issue(IssueDraft::new("Handoff A")?)?;
    let issue_b = tracker.create_issue(IssueDraft::new("Handoff B")?)?;
    let agent = AgentId::new(SIGNER)?;
    let claim_a = tracker.claim(&issue_a.id, &agent).await?;
    tracker.handoff(&claim_a, Handoff::new("ready A")).await?;
    let handoff_a = tracker
        .fetch_by_ids(std::slice::from_ref(&issue_a.id))
        .await?
        .remove(0)
        .handoff
        .ok_or("missing handoff A")?;

    let mut issues = tracker.load_issues()?;
    let target = issues
        .iter_mut()
        .find(|issue| issue.id == issue_b.id)
        .ok_or("issue B missing")?;
    target.state = IssueState::new("review")?;
    target.handoff = Some(handoff_a);
    write_issues(repo.path(), &issues)?;

    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue_b.id))
        .await?;
    assert!(fetched.is_empty());
    Ok(())
}

#[tokio::test]
async fn rejects_signer_claim_owner_mismatch() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = tracker.create_issue(IssueDraft::new("Owner mismatch")?)?;
    let other = AgentId::new("agent-b")?;
    let mut claim = Claim::new(
        Some(issue.id.clone()),
        other,
        "2026-07-02T01:00:00Z",
        ShardRole::ManualM1,
    );
    let payload = claim.signing_payload_bytes()?;
    claim.signature = Some(SignatureEnvelope::new(
        SIGN_ALGORITHM,
        CLAIM_CONTEXT,
        BASE64.encode(TRUSTED_KEY),
        BASE64.encode(b"synthetic"),
        sha256_hex(&payload),
        SIGNER,
    ));

    let mut tampered = tracker.load_issues()?.remove(0);
    tampered.state = IssueState::new("in_progress")?;
    tampered.claim = Some(claim);
    write_single_issue(repo.path(), &tampered)?;

    let verifier = MockSigningClient {
        verify_always_true: true,
        ..MockSigningClient::default()
    };
    let verifying_tracker = signed_tracker(repo.path(), verifier, trusted_resolver());
    let fetched = verifying_tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert!(fetched.is_empty());
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_base64_in_envelope() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = tracker.create_issue(IssueDraft::new("Invalid b64")?)?;
    let agent = AgentId::new(SIGNER)?;
    let _claim = tracker.claim(&issue.id, &agent).await?;

    let mut tampered = tracker.load_issues()?.remove(0);
    tampered
        .claim
        .as_mut()
        .and_then(|claim| claim.signature.as_mut())
        .ok_or("missing signature")?
        .public_key_b64 = "not%%%base64".to_owned();
    write_single_issue(repo.path(), &tampered)?;

    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert!(fetched.is_empty());
    Ok(())
}

#[tokio::test]
async fn oversized_payload_fails_required_signing_without_partial_write() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = tracker.create_issue(IssueDraft::new("Oversized")?)?;
    let large_agent = AgentId::new(format!("agent-{}", "x".repeat(70_000)))?;

    let error = tracker
        .claim(&issue.id, &large_agent)
        .await
        .err()
        .ok_or("oversized claim unexpectedly succeeded")?;
    assert!(error.to_string().contains("maximum signable size"));
    let loaded = tracker.load_issues()?;
    assert_eq!(loaded[0].state, IssueState::new("todo")?);
    assert!(loaded[0].claim.is_none());
    Ok(())
}

#[tokio::test]
async fn x0xd_unavailable_fails_required_but_disabled_still_writes() -> TestResult {
    let required_repo = init_plain()?;
    let failing = MockSigningClient {
        fail_sign: true,
        ..MockSigningClient::default()
    };
    let required = signed_tracker(required_repo.path(), failing, trusted_resolver());
    let required_issue = required.create_issue(IssueDraft::new("Required failure")?)?;
    let agent = AgentId::new(SIGNER)?;
    assert!(required.claim(&required_issue.id, &agent).await.is_err());
    assert!(required.load_issues()?[0].claim.is_none());

    let disabled_repo = init_plain()?;
    let disabled = JsonlTracker::new(disabled_repo.path());
    let disabled_issue = disabled.create_issue(IssueDraft::new("Disabled succeeds")?)?;
    let claim = disabled.claim(&disabled_issue.id, &agent).await?;
    assert!(claim.signature.is_none());
    Ok(())
}

#[tokio::test]
async fn verify_endpoint_false_drops_record() -> TestResult {
    let repo = init_plain()?;
    let signer = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = signer.create_issue(IssueDraft::new("Verify false")?)?;
    let agent = AgentId::new(SIGNER)?;
    let _claim = signer.claim(&issue.id, &agent).await?;

    let verifier = MockSigningClient {
        verify_false: true,
        ..MockSigningClient::default()
    };
    let verifying_tracker = signed_tracker(repo.path(), verifier, trusted_resolver());
    let fetched = verifying_tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert!(fetched.is_empty());
    Ok(())
}

#[tokio::test]
async fn verify_invalid_signature_drops_record() -> TestResult {
    let repo = init_plain()?;
    let tracker = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = tracker.create_issue(IssueDraft::new("Invalid signature")?)?;
    let agent = AgentId::new(SIGNER)?;
    let _claim = tracker.claim(&issue.id, &agent).await?;

    let mut tampered = tracker.load_issues()?.remove(0);
    tampered
        .claim
        .as_mut()
        .and_then(|claim| claim.signature.as_mut())
        .ok_or("missing signature")?
        .signature_b64 = BASE64.encode(b"definitely-invalid");
    write_single_issue(repo.path(), &tampered)?;

    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert!(fetched.is_empty());
    Ok(())
}

#[tokio::test]
async fn verify_transport_error_surfaces_as_error() -> TestResult {
    let repo = init_plain()?;
    let signer = signed_tracker(
        repo.path(),
        MockSigningClient::default(),
        trusted_resolver(),
    );
    let issue = signer.create_issue(IssueDraft::new("Transport failure")?)?;
    let agent = AgentId::new(SIGNER)?;
    let _claim = signer.claim(&issue.id, &agent).await?;

    let verifier = MockSigningClient {
        verify_transport: MockVerifyTransport::Unavailable,
        ..MockSigningClient::default()
    };
    let verifying_tracker = signed_tracker(repo.path(), verifier, trusted_resolver());
    let ctx = PollContext::new(
        vec![IssueState::new("in_progress")?],
        vec![IssueState::new("done")?],
    );
    let error = verifying_tracker
        .fetch_candidates(&ctx)
        .await
        .err()
        .ok_or("transport failure was silently accepted")?;
    let message = error.to_string();
    assert!(message.contains("signature verification transport error"));
    assert!(message.contains("x0xd unavailable"));
    Ok(())
}

#[tokio::test]
async fn verify_cache_avoids_repeated_calls() -> TestResult {
    let repo = init_plain()?;
    let client = MockSigningClient::default();
    let tracker = signed_tracker(repo.path(), client.clone(), trusted_resolver());
    let issue = tracker.create_issue(IssueDraft::new("Cached verify")?)?;
    let agent = AgentId::new(SIGNER)?;
    let _claim = tracker.claim(&issue.id, &agent).await?;

    let first = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    let second = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;

    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert_eq!(client.verify_call_count()?, 1);
    Ok(())
}

#[tokio::test]
async fn verify_cache_invalidates_on_payload_change() -> TestResult {
    let repo = init_plain()?;
    let client = MockSigningClient::default();
    let tracker = signed_tracker(repo.path(), client.clone(), trusted_resolver());
    let issue = tracker.create_issue(IssueDraft::new("Cache invalidation")?)?;
    let agent = AgentId::new(SIGNER)?;
    let _claim = tracker.claim(&issue.id, &agent).await?;

    let fetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(fetched.len(), 1);
    assert_eq!(client.verify_call_count()?, 1);

    let mut changed = tracker.load_issues()?.remove(0);
    let claim = changed.claim.as_mut().ok_or("missing claim")?;
    claim.at = "2026-07-02T03:00:00Z".to_owned();
    let payload = claim.signing_payload_bytes()?;
    let envelope = claim.signature.as_mut().ok_or("missing signature")?;
    envelope.payload_sha256 = sha256_hex(&payload);
    envelope.signature_b64 = BASE64.encode(fake_signature(CLAIM_CONTEXT, &payload, TRUSTED_KEY));
    write_single_issue(repo.path(), &changed)?;

    let refetched = tracker
        .fetch_by_ids(std::slice::from_ref(&issue.id))
        .await?;
    assert_eq!(refetched.len(), 1);
    assert_eq!(client.verify_call_count()?, 2);
    Ok(())
}

#[test]
fn signing_payload_bytes_are_stable_and_digest_matches() -> TestResult {
    let agent = AgentId::new(SIGNER)?;
    let claim = Claim::new(
        Some(IssueId::new("XSY-9000")?),
        agent,
        "2026-07-02T01:00:00Z",
        ShardRole::ManualM1,
    );
    assert_eq!(
        claim.signing_payload_bytes()?,
        claim.signing_payload_bytes()?
    );
    assert_eq!(
        claim.signing_payload_sha256()?,
        sha256_hex(&claim.signing_payload_bytes()?)
    );

    let mut signed = claim.clone();
    signed.signature = Some(SignatureEnvelope::new(
        SIGN_ALGORITHM,
        CLAIM_CONTEXT,
        BASE64.encode(TRUSTED_KEY),
        BASE64.encode(b"synthetic"),
        claim.signing_payload_sha256()?,
        SIGNER,
    ));
    assert_eq!(
        signed.signing_payload_bytes()?,
        claim.signing_payload_bytes()?
    );
    assert_eq!(
        claim
            .clone()
            .with_heartbeat("2026-07-02T02:00:00Z")
            .signing_payload_bytes()?,
        claim.signing_payload_bytes()?
    );

    let handoff = Handoff::new("ready");
    let with_absent_optional_fields = Handoff {
        summary: "ready".to_owned(),
        files_changed: Vec::new(),
        validation: Vec::new(),
        follow_up: Vec::new(),
        proofs_dir: None,
        issue_id: None,
        signer_agent_id: None,
        signature: None,
    };
    assert_eq!(
        handoff.signing_payload_bytes()?,
        with_absent_optional_fields.signing_payload_bytes()?
    );
    Ok(())
}

const SIGNER: &str = "agent-a";
const TRUSTED_KEY: &[u8] = b"trusted-key-a";
const OTHER_KEY: &[u8] = b"trusted-key-b";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MockVerifyTransport {
    Available,
    Unavailable,
}

#[derive(Clone)]
struct MockSigningClient {
    signer_agent_id: String,
    public_key: Vec<u8>,
    fail_sign: bool,
    verify_false: bool,
    verify_always_true: bool,
    verify_transport: MockVerifyTransport,
    verify_calls: Arc<Mutex<usize>>,
    max_payload: usize,
}

impl MockSigningClient {
    fn verify_call_count(&self) -> TestResult<usize> {
        self.verify_calls
            .lock()
            .map(|calls| *calls)
            .map_err(|_| io::Error::other("verify call counter lock poisoned").into())
    }
}

impl Default for MockSigningClient {
    fn default() -> Self {
        Self {
            signer_agent_id: SIGNER.to_owned(),
            public_key: TRUSTED_KEY.to_vec(),
            fail_sign: false,
            verify_false: false,
            verify_always_true: false,
            verify_transport: MockVerifyTransport::Available,
            verify_calls: Arc::new(Mutex::new(0)),
            max_payload: 64 * 1024,
        }
    }
}

#[async_trait]
impl SigningClient for MockSigningClient {
    async fn sign(
        &self,
        context: &str,
        payload: &[u8],
    ) -> x0x_symphony_tracker_git_jsonl::signing::Result<SignResponse> {
        if self.fail_sign {
            return Err(SigningError::InvalidResponse(
                "signing unavailable".to_owned(),
            ));
        }
        if payload.len() > self.max_payload {
            return Err(SigningError::PayloadTooLarge {
                max: self.max_payload,
                actual: payload.len(),
            });
        }
        Ok(SignResponse {
            agent_id: self.signer_agent_id.clone(),
            public_key_b64: BASE64.encode(&self.public_key),
            signature_b64: BASE64.encode(fake_signature(context, payload, &self.public_key)),
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
    ) -> x0x_symphony_tracker_git_jsonl::signing::Result<VerifyOutcome> {
        let mut calls = self.verify_calls.lock().map_err(|_| {
            SigningError::InvalidResponse("verify call counter lock poisoned".to_owned())
        })?;
        *calls = calls.saturating_add(1);
        drop(calls);
        if self.verify_transport == MockVerifyTransport::Unavailable {
            return Ok(VerifyOutcome::TransportError("x0xd unavailable".to_owned()));
        }
        if self.verify_always_true {
            return Ok(VerifyOutcome::Valid);
        }
        if self.verify_false {
            return Ok(VerifyOutcome::Invalid(
                "x0xd verify endpoint returned false".to_owned(),
            ));
        }
        if signature == fake_signature(context, payload, public_key) {
            Ok(VerifyOutcome::Valid)
        } else {
            Ok(VerifyOutcome::Invalid("signature mismatch".to_owned()))
        }
    }

    async fn agent_identity(&self) -> x0x_symphony_tracker_git_jsonl::signing::Result<AgentInfo> {
        Ok(AgentInfo {
            agent_id: self.signer_agent_id.clone(),
        })
    }
}

struct MockResolver {
    agent_id: String,
    public_key: Vec<u8>,
    calls: Mutex<usize>,
}

#[async_trait]
impl TrustedKeyResolver for MockResolver {
    async fn resolve(
        &self,
        agent_id: &str,
    ) -> x0x_symphony_tracker_git_jsonl::signing::Result<Vec<u8>> {
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| SigningError::UntrustedKey("resolver lock poisoned".to_owned()))?;
        *calls = calls.saturating_add(1);
        if agent_id == self.agent_id {
            Ok(self.public_key.clone())
        } else {
            Err(SigningError::UntrustedKey(format!(
                "agent {agent_id} is not trusted"
            )))
        }
    }
}

fn trusted_resolver() -> Arc<dyn TrustedKeyResolver> {
    Arc::new(MockResolver {
        agent_id: SIGNER.to_owned(),
        public_key: TRUSTED_KEY.to_vec(),
        calls: Mutex::new(0),
    })
}

fn signed_tracker(
    repo: &Path,
    client: MockSigningClient,
    resolver: Arc<dyn TrustedKeyResolver>,
) -> JsonlTracker {
    JsonlTracker::builder(repo)
        .signing(
            SigningPolicy::Required,
            Some(Arc::new(client)),
            Some(resolver),
        )
        .build()
}

fn fake_signature(context: &str, payload: &[u8], public_key: &[u8]) -> Vec<u8> {
    format!(
        "{context}:{}:{}",
        sha256_hex(payload),
        BASE64.encode(public_key)
    )
    .into_bytes()
}

fn init_plain() -> TestResult<TempDir> {
    let repo = TempDir::new()?;
    fs::create_dir_all(repo.path().join("issues"))?;
    fs::write(repo.path().join("issues").join("issues.jsonl"), "")?;
    Ok(repo)
}

fn write_single_issue(repo: &Path, issue: &Issue) -> TestResult {
    write_issues(repo, std::slice::from_ref(issue))
}

fn write_issues(repo: &Path, issues: &[Issue]) -> TestResult {
    let mut content = String::new();
    for issue in issues {
        content.push_str(&serialize_issue(issue)?);
        content.push('\n');
    }
    fs::write(repo.join("issues").join("issues.jsonl"), content)?;
    Ok(())
}

fn init_repo() -> TestResult<TempDir> {
    let repo = TempDir::new()?;
    fs::create_dir_all(repo.path().join("issues"))?;
    fs::write(repo.path().join("issues").join("issues.jsonl"), "")?;
    run_git(repo.path(), &["init", "-q"])?;
    run_git(repo.path(), &["checkout", "-B", "main"])?;
    run_git(
        repo.path(),
        &["config", "user.email", "agent@example.invalid"],
    )?;
    run_git(repo.path(), &["config", "user.name", "x0x-symphony test"])?;
    run_git(repo.path(), &["add", "issues/issues.jsonl"])?;
    run_git(repo.path(), &["commit", "-m", "seed issues"])?;
    Ok(repo)
}

fn run_git(repo: &Path, args: &[&str]) -> TestResult {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Into::into(io::Error::other(format!(
            "git {args:?} failed: {stderr}"
        ))))
    }
}

fn git_dir(repo: &Path) -> TestResult<PathBuf> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("rev-parse")
        .arg("--git-dir")
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Into::into(io::Error::other(format!(
            "git rev-parse failed: {stderr}"
        ))));
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(repo.join(path))
    }
}

fn commit_count(repo: &Path) -> TestResult<usize> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("rev-list")
        .arg("--count")
        .arg("HEAD")
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Into::into(io::Error::other(format!(
            "git rev-list failed: {stderr}"
        ))));
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<usize>()
        .map_err(Into::into)
}

fn spawn_claim_child(exe: &Path, repo: &Path, agent: &str) -> TestResult<std::process::Child> {
    Command::new(exe)
        .arg("--exact")
        .arg("multiprocess_claim_child")
        .arg("--nocapture")
        .env("XSY_MULTIPROCESS_REPO", repo)
        .env("XSY_MULTIPROCESS_AGENT", agent)
        .spawn()
        .map_err(Into::into)
}

fn exit_code(status: ExitStatus) -> TestResult<i32> {
    status
        .code()
        .ok_or_else(|| io::Error::other("child terminated without an exit code"))
        .map_err(Into::into)
}

fn issue_json(id: &str, state: &str, blockers: Vec<(&str, &str)>) -> TestResult<String> {
    let blocked_by = blockers
        .into_iter()
        .map(|(blocker_id, blocker_state)| {
            serde_json::json!({
                "id": blocker_id,
                "identifier": blocker_id,
                "state": blocker_state,
            })
        })
        .collect::<Vec<_>>();
    let value = serde_json::json!({
        "id": id,
        "identifier": id,
        "title": format!("Issue {id}"),
        "description": "test issue",
        "priority": 2,
        "state": state,
        "branch_name": null,
        "url": null,
        "labels": ["x0x-symphony"],
        "blocked_by": blocked_by,
        "created_at": "2026-07-02T00:00:00Z",
        "updated_at": "2026-07-02T00:00:00Z"
    });
    serde_json::to_string(&value).map_err(Into::into)
}

const fn v1_issue_with_future_fields() -> &'static str {
    "{\"schema_version\":1,\"id\":\"XSY-0101\",\"identifier\":\"XSY-0101\",\"title\":\"Future fields\",\"description\":\"test issue\",\"priority\":2,\"state\":\"todo\",\"branch_name\":null,\"url\":null,\"labels\":[\"x0x-symphony\"],\"blocked_by\":[],\"created_at\":\"2026-07-02T00:00:00Z\",\"updated_at\":\"2026-07-02T00:00:00Z\",\"another\":{\"nested\":true},\"future_field\":[1,2,3]}"
}

fn arbitrary_issue_strategy() -> BoxedStrategy<Issue> {
    let identity = (
        issue_id_strategy(),
        non_empty_text_strategy(),
        text_strategy(),
        prop::option::of(0_u8..=5),
        issue_state_strategy(),
    );
    let metadata = (
        prop::option::of(non_empty_text_strategy()),
        prop::option::of(non_empty_text_strategy()),
        prop::collection::vec(label_strategy(), 0..4),
        prop::collection::vec(issue_ref_strategy(), 0..3),
    );
    let symphony = (
        prop::option::of(shard_strategy()),
        prop::option::of(claim_strategy()),
        prop::option::of(handoff_strategy()),
    );
    let timestamps = (
        timestamp_strategy(),
        timestamp_strategy(),
        issue_extra_strategy(),
    );

    (identity, metadata, symphony, timestamps)
        .prop_map(
            |(
                (id, title, description, priority, state),
                (branch_name, url, labels, blocked_by),
                (shard, claim, handoff),
                (created_at, updated_at, extra),
            )| Issue {
                schema_version: 1,
                identifier: id.as_str().to_owned(),
                id,
                title,
                description,
                priority,
                state,
                branch_name,
                url,
                labels,
                blocked_by,
                shard,
                claim,
                handoff,
                signature_provenance: None,
                created_at,
                updated_at,
                extra,
            },
        )
        .boxed()
}

fn issue_id_strategy() -> impl Strategy<Value = IssueId> {
    (1_u32..10_000).prop_filter_map("valid issue id", |suffix| {
        IssueId::new(format!("XSY-{suffix:04}")).ok()
    })
}

fn agent_id_strategy() -> impl Strategy<Value = AgentId> {
    (1_u32..10_000).prop_filter_map("valid agent id", |suffix| {
        AgentId::new(format!("agent-{suffix:04}")).ok()
    })
}

fn issue_state_strategy() -> impl Strategy<Value = IssueState> {
    prop::sample::select(vec![
        "todo",
        "in_progress",
        "review",
        "blocked",
        "done",
        "cancelled",
        "duplicate",
    ])
    .prop_filter_map("valid issue state", |state| IssueState::new(state).ok())
}

fn issue_ref_strategy() -> impl Strategy<Value = IssueRef> {
    (issue_id_strategy(), issue_state_strategy()).prop_map(|(id, state)| {
        let identifier = id.as_str().to_owned();
        IssueRef::new(id, identifier, state)
    })
}

fn shard_strategy() -> impl Strategy<Value = Shard> {
    (
        agent_id_strategy(),
        prop::collection::vec(agent_id_strategy(), 0..3),
        1_u64..3_600_001,
        0_u64..100,
    )
        .prop_map(|(primary, backups, claim_ttl_ms, created_view_epoch)| {
            Shard::new(primary, backups, claim_ttl_ms, created_view_epoch)
        })
}

fn shard_role_strategy() -> impl Strategy<Value = ShardRole> {
    prop_oneof![
        Just(ShardRole::Primary),
        (0_usize..3).prop_map(ShardRole::Backup),
        Just(ShardRole::ManualM1),
    ]
}

fn claim_strategy() -> impl Strategy<Value = Claim> {
    (
        prop::option::of(issue_id_strategy()),
        agent_id_strategy(),
        timestamp_strategy(),
        timestamp_strategy(),
        shard_role_strategy(),
        prop::option::of(signature_envelope_strategy()),
    )
        .prop_map(
            |(issue_id, by, at, heartbeat_at, shard_role, signature)| Claim {
                issue_id,
                by,
                at,
                heartbeat_at,
                shard_role,
                signature,
            },
        )
}

fn handoff_strategy() -> impl Strategy<Value = Handoff> {
    (
        non_empty_text_strategy(),
        prop::collection::vec(path_strategy(), 0..4),
        prop::collection::vec(validation_result_strategy(), 0..3),
        prop::collection::vec(text_strategy(), 0..3),
        prop::option::of(path_strategy()),
        prop::option::of(issue_id_strategy()),
        prop::option::of(non_empty_text_strategy()),
        prop::option::of(signature_envelope_strategy()),
    )
        .prop_map(
            |(
                summary,
                files_changed,
                validation,
                follow_up,
                proofs_dir,
                issue_id,
                signer_agent_id,
                signature,
            )| Handoff {
                summary,
                files_changed,
                validation,
                follow_up,
                proofs_dir,
                issue_id,
                signer_agent_id,
                signature,
            },
        )
}

fn signature_envelope_strategy() -> impl Strategy<Value = SignatureEnvelope> {
    (
        prop::sample::select(vec![SIGN_ALGORITHM.to_owned()]),
        prop::sample::select(vec![CLAIM_CONTEXT.to_owned(), HANDOFF_CONTEXT.to_owned()]),
        non_empty_text_strategy(),
        non_empty_text_strategy(),
        "[0-9a-f]{64}",
        non_empty_text_strategy(),
    )
        .prop_map(
            |(
                algorithm,
                context,
                public_key_b64,
                signature_b64,
                payload_sha256,
                signer_agent_id,
            )| SignatureEnvelope {
                algorithm,
                context,
                public_key_b64,
                signature_b64,
                payload_sha256,
                signer_agent_id,
            },
        )
}

fn validation_result_strategy() -> impl Strategy<Value = ValidationResult> {
    (
        non_empty_text_strategy(),
        validation_status_strategy(),
        prop::option::of(-255_i32..=255_i32),
    )
        .prop_map(|(command, status, exit_code)| ValidationResult {
            command,
            status,
            exit_code,
        })
}

fn validation_status_strategy() -> impl Strategy<Value = ValidationStatus> {
    prop_oneof![
        Just(ValidationStatus::Passed),
        Just(ValidationStatus::Failed),
        Just(ValidationStatus::Skipped),
    ]
}

fn issue_extra_strategy() -> impl Strategy<Value = BTreeMap<String, Value>> {
    let acceptance = prop::collection::vec(text_strategy(), 0..3).prop_map(strings_value);
    let validation = prop::collection::vec(text_strategy(), 0..3).prop_map(strings_value);
    let links = prop::collection::vec(non_empty_text_strategy(), 0..3).prop_map(strings_value);
    let unknown = prop::collection::btree_map("x_[a-z][a-z0-9_]{0,8}", json_value_strategy(), 0..4);

    (acceptance, validation, links, unknown).prop_map(
        |(acceptance, validation, links, mut unknown)| {
            unknown.insert("acceptance".to_owned(), acceptance);
            unknown.insert("validation".to_owned(), validation);
            unknown.insert("links".to_owned(), links);
            unknown
        },
    )
}

fn json_value_strategy() -> BoxedStrategy<Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-10_000_i64..=10_000_i64).prop_map(|number| Value::Number(number.into())),
        text_strategy().prop_map(Value::String),
    ];

    leaf.prop_recursive(3, 16, 3, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..3).prop_map(Value::Array),
            prop::collection::btree_map("[a-z][a-z0-9_]{0,8}", inner, 0..3).prop_map(|entries| {
                let mut object = Map::new();
                for (key, value) in entries {
                    object.insert(key, value);
                }
                Value::Object(object)
            }),
        ]
    })
    .boxed()
}

fn strings_value(strings: Vec<String>) -> Value {
    Value::Array(strings.into_iter().map(Value::String).collect())
}

fn non_empty_text_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9][A-Za-z0-9 _.,:/-]{0,48}"
}

fn text_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9 _.,:/-]{0,48}"
}

fn label_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,16}"
}

fn path_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_.-]{0,16}".prop_map(|name| format!("src/{name}.rs"))
}

fn timestamp_strategy() -> impl Strategy<Value = String> {
    (0_u32..60, 0_u32..60)
        .prop_map(|(minute, second)| format!("2026-07-02T00:{minute:02}:{second:02}Z"))
}

#[tokio::test]
async fn block_and_fetch_claimed_round_trip_blocked_reason_survives() -> TestResult {
    let repo = init_repo()?;
    let tracker = JsonlTracker::new(repo.path());
    let issue = tracker.create_issue(
        IssueDraft::new("Orchestrator blocked reason round-trip")?
            .with_description("block() must persist a structured reason that survives reload."),
    )?;
    let id = issue.id.clone();

    let agent = AgentId::new("agent-a")?;
    let claim = tracker.claim(&id, &agent).await?;

    // A freshly-claimed issue is visible via fetch_claimed for this agent.
    let claimed = tracker.fetch_claimed(Some(&agent)).await?;
    assert_eq!(claimed.len(), 1, "claim should be visible to its owner");
    assert_eq!(claimed[0].id, id);

    // Move it to blocked with a structured reason (as the orchestrator does on
    // retry exhaustion).
    let reason = ReleaseReason::new(ReleaseReasonCode::RetryExhausted, "runner failed 3x");
    tracker.block(&claim, reason.clone()).await?;

    // The claim is cleared: no claimed issues remain for this agent.
    let claimed_after = tracker.fetch_claimed(Some(&agent)).await?;
    assert!(
        claimed_after.is_empty(),
        "block must clear the claim; got {claimed_after:?}"
    );

    // Reload through the public reader path and assert the reason survived.
    let fetched = tracker.fetch_by_ids(std::slice::from_ref(&id)).await?;
    assert_eq!(fetched.len(), 1);
    let blocked = &fetched[0];
    assert_eq!(blocked.state, IssueState::new("blocked")?);
    assert!(blocked.claim.is_none(), "block must clear the claim field");
    let stored = blocked
        .extra
        .get("blocked_reason")
        .ok_or("blocked_reason missing from extra")?;
    let restored: ReleaseReason =
        serde_json::from_value(stored.clone()).map_err(|e| io::Error::other(e.to_string()))?;
    assert_eq!(restored, reason, "blocked_reason must round-trip exactly");

    // Byte-stable serialization: the on-disk line must parse and re-serialize to
    // itself, and the blocked_reason must be present in the parsed record.
    let path = repo.path().join("issues").join("issues.jsonl");
    let line = fs::read_to_string(&path)?
        .lines()
        .find(|l| l.contains("\"id\":\"XSY-"))
        .ok_or("issue line present on disk")?
        .to_owned();
    let parsed = parse_issue_line(1, &line)?;
    assert_eq!(parsed.id, id);
    assert!(parsed.extra.contains_key("blocked_reason"));
    assert_eq!(
        serialize_issue(&parsed)?,
        line,
        "serialization must be byte-stable across a parse/serialize round-trip"
    );
    Ok(())
}
