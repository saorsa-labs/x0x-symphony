use std::{
    collections::BTreeMap,
    error::Error,
    io,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use reqwest::StatusCode;
use serde_json::json;
use tokio::{net::TcpListener, sync::broadcast, task::JoinHandle};
use x0x_symphony_bin::api::{
    build_router, sign_approval_event, AppState, EventNotice, PendingApproval,
    PendingApprovalProvenance,
};
use x0x_symphony_core::{
    content_hash, sha256_hex, AgentId, ApprovalConsumed, ApprovalEvent, ApprovalState,
    ApprovalVerdict, Claim, Handoff, Issue, IssueId, IssueSource, IssueState, PollContext,
    ReleaseReason, SignatureProvenance, SymphonyError, Tracker, APPROVAL_CONTEXT, SIGN_ALGORITHM,
};
use x0x_symphony_signing::{
    AgentInfo, SignResponse, SigningClient, SigningError, TrustedKeyResolver, VerifyOutcome,
};

const API_TOKEN: &str = "secret-token";
const OPERATOR: &str = "operator";
const CREATED_AT: &str = "2026-07-03T00:00:00Z";
const APPROVED_AT: &str = "2026-07-03T12:00:00Z";

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

struct TestServer {
    base_url: String,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SignedMaterial {
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

struct MockSigningClient {
    agent_id: String,
    records: Mutex<BTreeMap<(String, Vec<u8>), SignedMaterial>>,
    last_public_key: Mutex<Option<Vec<u8>>>,
}

impl MockSigningClient {
    fn new(agent_id: &str) -> Self {
        Self {
            agent_id: agent_id.to_owned(),
            records: Mutex::new(BTreeMap::new()),
            last_public_key: Mutex::new(None),
        }
    }
}

#[async_trait]
impl SigningClient for MockSigningClient {
    async fn sign(
        &self,
        context: &str,
        payload: &[u8],
    ) -> x0x_symphony_signing::Result<SignResponse> {
        let material = signed_material(context, payload);
        let mut records = self.records.lock().map_err(signing_lock_error)?;
        records.insert((context.to_owned(), payload.to_vec()), material.clone());
        drop(records);

        let mut last_public_key = self.last_public_key.lock().map_err(signing_lock_error)?;
        *last_public_key = Some(material.public_key.clone());

        Ok(SignResponse {
            agent_id: self.agent_id.clone(),
            public_key_b64: BASE64.encode(&material.public_key),
            signature_b64: BASE64.encode(&material.signature),
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
        let records = self.records.lock().map_err(signing_lock_error)?;
        let Some(material) = records.get(&(context.to_owned(), payload.to_vec())) else {
            return Ok(VerifyOutcome::Invalid("payload was not signed".to_owned()));
        };
        if material.signature.as_slice() == signature
            && material.public_key.as_slice() == public_key
        {
            Ok(VerifyOutcome::Valid)
        } else {
            Ok(VerifyOutcome::Invalid(
                "signature or public key did not match signed payload".to_owned(),
            ))
        }
    }

    async fn agent_identity(&self) -> x0x_symphony_signing::Result<AgentInfo> {
        Ok(AgentInfo {
            agent_id: self.agent_id.clone(),
        })
    }
}

#[async_trait]
impl TrustedKeyResolver for MockSigningClient {
    async fn resolve(&self, agent_id: &str) -> x0x_symphony_signing::Result<Vec<u8>> {
        if agent_id != self.agent_id {
            return Err(SigningError::UntrustedKey(format!(
                "agent {agent_id} is not {}",
                self.agent_id
            )));
        }
        let public_key = self
            .last_public_key
            .lock()
            .map_err(signing_lock_error)?
            .clone()
            .ok_or_else(|| SigningError::UntrustedKey("no key recorded".to_owned()))?;
        Ok(public_key)
    }
}

struct InMemoryTracker {
    issues: Mutex<Vec<Issue>>,
    approvals: Mutex<BTreeMap<IssueId, ApprovalState>>,
    requeues: Mutex<Vec<IssueId>>,
}

impl InMemoryTracker {
    fn new(issues: Vec<Issue>) -> Self {
        Self {
            issues: Mutex::new(issues),
            approvals: Mutex::new(BTreeMap::new()),
            requeues: Mutex::new(Vec::new()),
        }
    }

    fn requeued(&self) -> TestResult<Vec<IssueId>> {
        Ok(self.requeues.lock().map_err(tracker_lock_error)?.clone())
    }
}

#[async_trait]
impl Tracker for InMemoryTracker {
    async fn list_issues(&self) -> x0x_symphony_core::Result<Vec<Issue>> {
        Ok(self.issues.lock().map_err(tracker_lock_error)?.clone())
    }

    async fn fetch_candidates(&self, _ctx: &PollContext) -> x0x_symphony_core::Result<Vec<Issue>> {
        Ok(self.issues.lock().map_err(tracker_lock_error)?.clone())
    }

    async fn fetch_by_ids(&self, ids: &[IssueId]) -> x0x_symphony_core::Result<Vec<Issue>> {
        Ok(self
            .issues
            .lock()
            .map_err(tracker_lock_error)?
            .iter()
            .filter(|issue| ids.iter().any(|id| id == &issue.id))
            .cloned()
            .collect())
    }

    async fn claim(&self, _id: &IssueId, _agent_id: &AgentId) -> x0x_symphony_core::Result<Claim> {
        Err(SymphonyError::Tracker(
            "in-memory approval tracker does not claim".to_owned(),
        ))
    }

    async fn heartbeat(&self, _claim: &Claim) -> x0x_symphony_core::Result<()> {
        Ok(())
    }

    async fn release(
        &self,
        _claim: &Claim,
        _reason: ReleaseReason,
    ) -> x0x_symphony_core::Result<()> {
        Ok(())
    }

    async fn handoff(&self, _claim: &Claim, _handoff: Handoff) -> x0x_symphony_core::Result<()> {
        Ok(())
    }

    async fn requeue_blocked(
        &self,
        issue_id: &IssueId,
        _reason: ReleaseReason,
    ) -> x0x_symphony_core::Result<()> {
        // Mirror the CRDT adapter: the blocked claim blob becomes released,
        // which reconstructs the issue as `todo` without a blocked_reason.
        let mut issues = self.issues.lock().map_err(tracker_lock_error)?;
        let issue = issues
            .iter_mut()
            .find(|issue| &issue.id == issue_id)
            .ok_or_else(|| SymphonyError::Tracker(format!("unknown issue {issue_id}")))?;
        if issue.state.as_str() != "blocked" {
            return Err(SymphonyError::Tracker(format!(
                "issue {issue_id} is not blocked"
            )));
        }
        issue.state = IssueState::new("todo")?;
        issue.extra.remove("blocked_reason");
        drop(issues);
        self.requeues
            .lock()
            .map_err(tracker_lock_error)?
            .push(issue_id.clone());
        Ok(())
    }

    async fn load_approval_state(
        &self,
        issue_id: &IssueId,
    ) -> x0x_symphony_core::Result<ApprovalState> {
        Ok(self
            .approvals
            .lock()
            .map_err(tracker_lock_error)?
            .get(issue_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn store_approval(&self, event: &ApprovalEvent) -> x0x_symphony_core::Result<()> {
        let mut approvals = self.approvals.lock().map_err(tracker_lock_error)?;
        approvals
            .entry(event.issue_id.clone())
            .or_default()
            .events
            .push(event.clone());
        Ok(())
    }

    async fn store_consumed(&self, event: &ApprovalConsumed) -> x0x_symphony_core::Result<()> {
        let mut approvals = self.approvals.lock().map_err(tracker_lock_error)?;
        approvals
            .entry(event.issue_id.clone())
            .or_default()
            .consumed
            .push(event.clone());
        Ok(())
    }
}

#[tokio::test]
async fn sign_approval_event_output_verifies_by_gate_path() -> TestResult {
    let issue = network_issue("XSY-SYMMETRY", "Symmetry", "todo", "network-signer")?;
    let signing = MockSigningClient::new(OPERATOR);
    let event = unsigned_event(&issue, ApprovalVerdict::Approve, "network-signer")?;

    let signed = sign_approval_event(&signing, event).await?;
    let signature = signed
        .signature
        .as_ref()
        .ok_or_else(|| test_error("signed approval event lacked signature"))?;
    let payload = signed.signing_payload_bytes()?;
    let signature_bytes = BASE64.decode(&signature.signature_b64)?;
    let public_key = signing.resolve(OPERATOR).await?;

    let outcome = signing
        .verify(APPROVAL_CONTEXT, &payload, &signature_bytes, &public_key)
        .await?;
    assert_eq!(outcome, VerifyOutcome::Valid);
    assert_eq!(signature.context, APPROVAL_CONTEXT);
    Ok(())
}

#[tokio::test]
async fn post_approve_stores_signed_event() -> TestResult {
    let issue_id = "XSY-POST-APPROVE";
    let tracker = Arc::new(InMemoryTracker::new(vec![network_issue(
        issue_id,
        "Approve me",
        "todo",
        "network-signer",
    )?]));
    let server = spawn_approval_server(tracker.clone(), Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    let response =
        post_approval(&server, &client, issue_id, &json!({ "verdict": "approve" })).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let event = response.json::<ApprovalEvent>().await?;
    assert_eq!(event.verdict, ApprovalVerdict::Approve);
    let signature = event
        .signature
        .as_ref()
        .ok_or_else(|| test_error("approval response lacked signature"))?;
    assert_eq!(signature.context, APPROVAL_CONTEXT);

    let stored = tracker
        .load_approval_state(&IssueId::new(issue_id)?)
        .await?;
    let [stored_event] = stored.events.as_slice() else {
        return Err(test_error("expected exactly one stored approval event").into());
    };
    assert_eq!(stored_event, &event);
    Ok(())
}

#[tokio::test]
async fn post_deny_stores_denial() -> TestResult {
    let issue_id = "XSY-POST-DENY";
    let tracker = Arc::new(InMemoryTracker::new(vec![network_issue(
        issue_id,
        "Deny me",
        "todo",
        "network-signer",
    )?]));
    let server = spawn_approval_server(tracker.clone(), Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    let response = post_approval(&server, &client, issue_id, &json!({ "verdict": "deny" })).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let event = response.json::<ApprovalEvent>().await?;
    assert_eq!(event.verdict, ApprovalVerdict::Deny);

    let stored = tracker
        .load_approval_state(&IssueId::new(issue_id)?)
        .await?;
    let [stored_event] = stored.events.as_slice() else {
        return Err(test_error("expected exactly one stored denial event").into());
    };
    assert_eq!(stored_event.verdict, ApprovalVerdict::Deny);
    Ok(())
}

#[tokio::test]
async fn post_approve_emits_approval_granted_event() -> TestResult {
    let issue_id = "XSY-POST-APPROVE-EVENT";
    let issue = network_issue(issue_id, "Approve event", "todo", "network-signer")?;
    let expected_hash = content_hash(&issue).to_string();
    let tracker = Arc::new(InMemoryTracker::new(vec![issue]));
    let (server, mut events_rx) =
        spawn_approval_server_with_events(tracker, Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    let response =
        post_approval(&server, &client, issue_id, &json!({ "verdict": "approve" })).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _event = response.json::<ApprovalEvent>().await?;

    let notice = next_event_with_kind(&mut events_rx, "approval_granted").await?;
    let data: serde_json::Value = serde_json::from_str(&notice.data)?;
    assert_eq!(
        data.get("issue_id").and_then(serde_json::Value::as_str),
        Some(issue_id)
    );
    assert_eq!(
        data.get("approver_agent_id")
            .and_then(serde_json::Value::as_str),
        Some(OPERATOR)
    );
    assert_eq!(
        data.get("content_hash").and_then(serde_json::Value::as_str),
        Some(expected_hash.as_str())
    );
    Ok(())
}

#[tokio::test]
async fn post_deny_emits_approval_denied_event() -> TestResult {
    let issue_id = "XSY-POST-DENY-EVENT";
    let tracker = Arc::new(InMemoryTracker::new(vec![network_issue(
        issue_id,
        "Deny event",
        "todo",
        "network-signer",
    )?]));
    let (server, mut events_rx) =
        spawn_approval_server_with_events(tracker, Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    let response = post_approval(&server, &client, issue_id, &json!({ "verdict": "deny" })).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _event = response.json::<ApprovalEvent>().await?;

    let notice = next_event_with_kind(&mut events_rx, "approval_denied").await?;
    let data: serde_json::Value = serde_json::from_str(&notice.data)?;
    assert_eq!(
        data.get("issue_id").and_then(serde_json::Value::as_str),
        Some(issue_id)
    );
    assert_eq!(
        data.get("approver_agent_id")
            .and_then(serde_json::Value::as_str),
        Some(OPERATOR)
    );
    assert!(data.get("content_hash").is_none());
    Ok(())
}

#[tokio::test]
async fn stale_content_hash_returns_409() -> TestResult {
    let issue_id = "XSY-STALE-HASH";
    let tracker = Arc::new(InMemoryTracker::new(vec![network_issue(
        issue_id,
        "Stale hash",
        "todo",
        "network-signer",
    )?]));
    let server = spawn_approval_server(tracker.clone(), Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    let response = post_approval(
        &server,
        &client,
        issue_id,
        &json!({ "verdict": "approve", "expected_content_hash": "stale" }),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_no_approval_events(&tracker, issue_id).await?;
    Ok(())
}

#[tokio::test]
async fn stale_signer_returns_409() -> TestResult {
    let issue_id = "XSY-STALE-SIGNER";
    let tracker = Arc::new(InMemoryTracker::new(vec![network_issue(
        issue_id,
        "Stale signer",
        "todo",
        "network-signer",
    )?]));
    let server = spawn_approval_server(tracker.clone(), Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    let response = post_approval(
        &server,
        &client,
        issue_id,
        &json!({ "verdict": "approve", "expected_signer_agent_id": "other-signer" }),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_no_approval_events(&tracker, issue_id).await?;
    Ok(())
}

#[tokio::test]
async fn non_network_sourced_returns_409() -> TestResult {
    let issue_id = "XSY-LOCAL";
    let tracker = Arc::new(InMemoryTracker::new(vec![local_issue(
        issue_id,
        "Local issue",
        "todo",
    )?]));
    let server = spawn_approval_server(tracker.clone(), Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    let response =
        post_approval(&server, &client, issue_id, &json!({ "verdict": "approve" })).await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_no_approval_events(&tracker, issue_id).await?;
    Ok(())
}

#[tokio::test]
async fn missing_signing_client_returns_503() -> TestResult {
    let issue_id = "XSY-NO-SIGNER";
    let tracker = Arc::new(InMemoryTracker::new(vec![network_issue(
        issue_id,
        "No signer",
        "todo",
        "network-signer",
    )?]));
    let server = spawn_approval_server(tracker.clone(), None).await?;
    let client = reqwest::Client::new();

    let response =
        post_approval(&server, &client, issue_id, &json!({ "verdict": "approve" })).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_no_approval_events(&tracker, issue_id).await?;
    Ok(())
}

#[tokio::test]
async fn get_pending_returns_network_sourced_unapproved() -> TestResult {
    let pending_issue = network_issue(
        "XSY-PENDING-NEEDS-APPROVAL",
        "Needs approval",
        "todo",
        "network-signer-a",
    )?;
    let approved_issue = network_issue(
        "XSY-PENDING-APPROVED",
        "Already approved",
        "todo",
        "network-signer-b",
    )?;
    let tracker = Arc::new(InMemoryTracker::new(vec![
        pending_issue.clone(),
        approved_issue,
    ]));
    let server = spawn_approval_server(tracker, Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    let approve_response = post_approval(
        &server,
        &client,
        "XSY-PENDING-APPROVED",
        &json!({ "verdict": "approve" }),
    )
    .await?;
    assert_eq!(approve_response.status(), StatusCode::OK);

    let response = client
        .get(format!("{}/symphony/approvals/pending", server.base_url))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let pending = response.json::<Vec<PendingApproval>>().await?;
    let [row] = pending.as_slice() else {
        return Err(test_error("expected exactly one pending approval row").into());
    };
    assert_eq!(row.issue_id, pending_issue.id.to_string());
    assert_eq!(row.title, pending_issue.title);
    assert_eq!(row.content_hash, content_hash(&pending_issue).as_str());
    assert_eq!(row.signer_agent_id, "network-signer-a");
    assert_eq!(row.approval_summary.events, 0);
    assert_eq!(row.approval_summary.consumed, 0);
    assert!(!row.approval_summary.has_deny);
    let Some(provenance) = &row.provenance else {
        return Err(test_error("pending row lacked provenance").into());
    };
    if let PendingApprovalProvenance::Verified { signer_agent_id } = provenance {
        assert_eq!(signer_agent_id, "network-signer-a");
    } else {
        return Err(test_error("pending row provenance was not verified").into());
    }
    Ok(())
}

/// Issue #6 defect 1: the dispatch gate parks approval-gated issues as
/// `blocked` with reason `awaiting_approval`, but the pending scan only
/// accepted `todo`/`in_progress` — the act of awaiting approval removed the issue
/// from the very list the operator approves from. Blocked/`awaiting_approval`
/// issues must appear in pending with their payload hash and signer; blocked
/// issues with any other reason must not.
#[tokio::test]
async fn get_pending_includes_blocked_awaiting_approval() -> TestResult {
    let awaiting = blocked_awaiting_issue(
        "XSY-PENDING-BLOCKED",
        "Parked by the gate",
        "network-signer-a",
    )?;
    let mut retry_exhausted = network_issue(
        "XSY-PENDING-RETRY-EXHAUSTED",
        "Blocked for another reason",
        "blocked",
        "network-signer-b",
    )?;
    retry_exhausted.extra.insert(
        "blocked_reason".to_owned(),
        json!({ "code": "retry_exhausted", "message": "runner failed" }),
    );
    let tracker = Arc::new(InMemoryTracker::new(vec![
        awaiting.clone(),
        retry_exhausted,
    ]));
    let server = spawn_approval_server(tracker, Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/symphony/approvals/pending", server.base_url))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let pending = response.json::<Vec<PendingApproval>>().await?;
    let [row] = pending.as_slice() else {
        return Err(test_error("expected exactly one pending approval row").into());
    };
    assert_eq!(row.issue_id, awaiting.id.to_string());
    assert_eq!(row.state, "blocked");
    assert_eq!(row.content_hash, content_hash(&awaiting).as_str());
    assert_eq!(row.signer_agent_id, "network-signer-a");
    Ok(())
}

/// Issue #6: approving a blocked/`awaiting_approval` issue must return it to
/// `todo` so the orchestrator can re-claim it and consume the approval — the
/// approval alone must not leave the issue parked forever.
#[tokio::test]
async fn post_approve_requeues_blocked_awaiting_issue() -> TestResult {
    let issue_id = "XSY-APPROVE-REQUEUE";
    let tracker = Arc::new(InMemoryTracker::new(vec![blocked_awaiting_issue(
        issue_id,
        "Approve and requeue",
        "network-signer",
    )?]));
    let server = spawn_approval_server(tracker.clone(), Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    let response =
        post_approval(&server, &client, issue_id, &json!({ "verdict": "approve" })).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let stored = tracker
        .load_approval_state(&IssueId::new(issue_id)?)
        .await?;
    assert_eq!(stored.events.len(), 1, "approval event must be durable");
    assert_eq!(tracker.requeued()?, vec![IssueId::new(issue_id)?]);
    let issues = tracker.fetch_by_ids(&[IssueId::new(issue_id)?]).await?;
    let [issue] = issues.as_slice() else {
        return Err(test_error("issue should remain in tracker").into());
    };
    assert_eq!(issue.state.as_str(), "todo");
    Ok(())
}

/// Denials must leave the issue parked: only an approval resumes dispatch.
#[tokio::test]
async fn post_deny_does_not_requeue_blocked_awaiting_issue() -> TestResult {
    let issue_id = "XSY-DENY-NO-REQUEUE";
    let tracker = Arc::new(InMemoryTracker::new(vec![blocked_awaiting_issue(
        issue_id,
        "Deny and stay parked",
        "network-signer",
    )?]));
    let server = spawn_approval_server(tracker.clone(), Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    let response = post_approval(&server, &client, issue_id, &json!({ "verdict": "deny" })).await?;
    assert_eq!(response.status(), StatusCode::OK);

    assert!(tracker.requeued()?.is_empty(), "deny must not requeue");
    let issues = tracker.fetch_by_ids(&[IssueId::new(issue_id)?]).await?;
    let [issue] = issues.as_slice() else {
        return Err(test_error("issue should remain in tracker").into());
    };
    assert_eq!(issue.state.as_str(), "blocked");
    Ok(())
}

/// Approving an issue that is not parked (still todo) must not attempt a
/// requeue: pre-approvals are stored and consumed by the gate on first claim.
#[tokio::test]
async fn post_approve_on_todo_issue_does_not_requeue() -> TestResult {
    let issue_id = "XSY-APPROVE-TODO-NO-REQUEUE";
    let tracker = Arc::new(InMemoryTracker::new(vec![network_issue(
        issue_id,
        "Pre-approve me",
        "todo",
        "network-signer",
    )?]));
    let server = spawn_approval_server(tracker.clone(), Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    let response =
        post_approval(&server, &client, issue_id, &json!({ "verdict": "approve" })).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(tracker.requeued()?.is_empty());
    Ok(())
}

/// Crash recovery (issue #6 review fix 3): the daemon stored a signed approval
/// but crashed before the requeue, leaving the issue approved-but-parked.
/// The pending scan must keep surfacing it, and approving again must be
/// idempotent: the duplicate approval is stored and the requeue finally runs.
#[tokio::test]
async fn pending_surfaces_approved_but_still_blocked_issue_and_reapprove_recovers() -> TestResult {
    let issue_id = "XSY-CRASH-RECOVERY";
    let issue = blocked_awaiting_issue(
        issue_id,
        "Crash between store and requeue",
        "network-signer",
    )?;
    let tracker = Arc::new(InMemoryTracker::new(vec![issue.clone()]));
    // Simulate the crash aftermath: a fresh, signed, unconsumed approval is
    // durable while the issue is still parked and no requeue happened.
    let offline_signer = MockSigningClient::new(OPERATOR);
    let event = ApprovalEvent::approve(
        IssueId::new(issue_id)?,
        content_hash(&issue),
        AgentId::new("network-signer")?,
        rfc3339_now(),
        AgentId::new(OPERATOR)?,
        None,
    );
    let stored = sign_approval_event(&offline_signer, event).await?;
    tracker.store_approval(&stored).await?;

    let server = spawn_approval_server(tracker.clone(), Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();

    // Surfaced despite decision == Approved, because it is still parked.
    let response = client
        .get(format!("{}/symphony/approvals/pending", server.base_url))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let pending = response.json::<Vec<PendingApproval>>().await?;
    let [row] = pending.as_slice() else {
        return Err(test_error("approved-but-parked issue must stay visible in pending").into());
    };
    assert_eq!(row.issue_id, issue_id);
    assert_eq!(row.approval_summary.events, 1);

    // Re-approving recovers: duplicate event stored, requeue runs.
    let approve =
        post_approval(&server, &client, issue_id, &json!({ "verdict": "approve" })).await?;
    assert_eq!(approve.status(), StatusCode::OK);
    assert_eq!(tracker.requeued()?, vec![IssueId::new(issue_id)?]);
    let issues = tracker.fetch_by_ids(&[IssueId::new(issue_id)?]).await?;
    let [recovered] = issues.as_slice() else {
        return Err(test_error("issue should remain in tracker").into());
    };
    assert_eq!(recovered.state.as_str(), "todo");

    // Once requeued, it leaves the pending list.
    let response = client
        .get(format!("{}/symphony/approvals/pending", server.base_url))
        .bearer_auth(API_TOKEN)
        .send()
        .await?;
    let pending = response.json::<Vec<PendingApproval>>().await?;
    assert!(pending.is_empty(), "requeued issue must leave pending");
    Ok(())
}

/// Two concurrent approve calls race on the requeue: exactly one converts the
/// blocked claim, both report success, and the tracker sees a single requeue
/// (the gate's consumption then guarantees a single dispatch).
#[tokio::test]
async fn concurrent_approves_single_requeue() -> TestResult {
    let issue_id = "XSY-CONCURRENT-APPROVE";
    let tracker = Arc::new(InMemoryTracker::new(vec![blocked_awaiting_issue(
        issue_id,
        "Race the requeue",
        "network-signer",
    )?]));
    let server = spawn_approval_server(tracker.clone(), Some(mock_signing_client())).await?;
    let client = reqwest::Client::new();
    let body = json!({ "verdict": "approve" });

    let (first, second) = tokio::join!(
        post_approval(&server, &client, issue_id, &body),
        post_approval(&server, &client, issue_id, &body),
    );
    assert_eq!(first?.status(), StatusCode::OK);
    assert_eq!(second?.status(), StatusCode::OK);

    assert_eq!(
        tracker.requeued()?,
        vec![IssueId::new(issue_id)?],
        "exactly one requeue despite two approvals"
    );
    let issues = tracker.fetch_by_ids(&[IssueId::new(issue_id)?]).await?;
    let [issue] = issues.as_slice() else {
        return Err(test_error("issue should remain in tracker").into());
    };
    assert_eq!(issue.state.as_str(), "todo");
    Ok(())
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

fn signed_material(context: &str, payload: &[u8]) -> SignedMaterial {
    let digest = sha256_hex(payload);
    SignedMaterial {
        public_key: format!("{context}:public:{digest}").into_bytes(),
        signature: format!("{context}:signature:{digest}").into_bytes(),
    }
}

fn signing_lock_error<T>(_error: PoisonError<T>) -> SigningError {
    SigningError::InvalidResponse("mock signing lock poisoned".to_owned())
}

fn tracker_lock_error<T>(_error: PoisonError<T>) -> SymphonyError {
    SymphonyError::Tracker("mock tracker lock poisoned".to_owned())
}

fn mock_signing_client() -> Arc<dyn SigningClient> {
    Arc::new(MockSigningClient::new(OPERATOR))
}

async fn spawn_approval_server(
    tracker: Arc<InMemoryTracker>,
    signing_client: Option<Arc<dyn SigningClient>>,
) -> TestResult<TestServer> {
    let (server, _events_rx) = spawn_approval_server_with_events(tracker, signing_client).await?;
    Ok(server)
}

async fn spawn_approval_server_with_events(
    tracker: Arc<InMemoryTracker>,
    signing_client: Option<Arc<dyn SigningClient>>,
) -> TestResult<(TestServer, broadcast::Receiver<EventNotice>)> {
    let tracker: Arc<dyn Tracker> = tracker;
    let state = AppState::new(tracker, AgentId::new(OPERATOR)?, API_TOKEN.to_owned(), None)
        .with_signing_client(signing_client);
    let events_rx = state.events_sender().subscribe();
    let server = spawn_server(state).await?;
    Ok((server, events_rx))
}

async fn spawn_server(state: AppState) -> TestResult<TestServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = build_router(state);
    let task = tokio::spawn(async move {
        let result = axum::serve(listener, app).await;
        if let Err(_error) = result {}
    });
    Ok(TestServer {
        base_url: format!("http://{addr}"),
        task,
    })
}

async fn next_event_with_kind(
    events_rx: &mut broadcast::Receiver<EventNotice>,
    kind: &'static str,
) -> TestResult<EventNotice> {
    Ok(tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let notice = events_rx.recv().await?;
            if notice.kind == kind {
                return Ok::<EventNotice, broadcast::error::RecvError>(notice);
            }
        }
    })
    .await??)
}

async fn post_approval(
    server: &TestServer,
    client: &reqwest::Client,
    issue_id: &str,
    body: &serde_json::Value,
) -> TestResult<reqwest::Response> {
    Ok(client
        .post(format!("{}/symphony/approvals/{issue_id}", server.base_url))
        .bearer_auth(API_TOKEN)
        .json(body)
        .send()
        .await?)
}

async fn assert_no_approval_events(tracker: &InMemoryTracker, issue_id: &str) -> TestResult {
    let state = tracker
        .load_approval_state(&IssueId::new(issue_id)?)
        .await?;
    assert!(state.events.is_empty());
    Ok(())
}

fn unsigned_event(
    issue: &Issue,
    verdict: ApprovalVerdict,
    signer: &str,
) -> TestResult<ApprovalEvent> {
    let signer = AgentId::new(signer)?;
    let approver = AgentId::new(OPERATOR)?;
    Ok(match verdict {
        ApprovalVerdict::Approve => ApprovalEvent::approve(
            issue.id.clone(),
            content_hash(issue),
            signer,
            APPROVED_AT,
            approver,
            None,
        ),
        ApprovalVerdict::Deny => ApprovalEvent::deny(
            issue.id.clone(),
            content_hash(issue),
            signer,
            APPROVED_AT,
            approver,
            None,
        ),
    })
}

/// Network-sourced issue the dispatch gate parked as blocked/`awaiting_approval`,
/// exactly as reconstructed from a Blocked claim blob after a daemon restart.
fn blocked_awaiting_issue(id: &str, title: &str, signer: &str) -> TestResult<Issue> {
    let mut issue = network_issue(id, title, "blocked", signer)?;
    issue.extra.insert(
        "blocked_reason".to_owned(),
        json!({
            "code": "awaiting_approval",
            "message": format!(
                "network-sourced dispatch requires a valid approval for signer {signer} and current payload"
            ),
        }),
    );
    Ok(issue)
}

fn network_issue(id: &str, title: &str, state: &str, signer: &str) -> TestResult<Issue> {
    let mut issue = base_issue(id, title, state)?;
    issue.description = format!("Network task body for {id}");
    issue.extra.insert(
        "issue_source".to_owned(),
        json!(IssueSource::NetworkSourced.as_str()),
    );
    issue.signature_provenance = Some(SignatureProvenance::verified(signer));
    Ok(issue)
}

fn local_issue(id: &str, title: &str, state: &str) -> TestResult<Issue> {
    let mut issue = base_issue(id, title, state)?;
    issue.description = format!("Local task body for {id}");
    Ok(issue)
}

fn base_issue(id: &str, title: &str, state: &str) -> TestResult<Issue> {
    Ok(Issue::new(
        IssueId::new(id)?,
        id,
        title,
        IssueState::new(state)?,
        CREATED_AT,
    )?)
}

fn test_error(message: &str) -> io::Error {
    io::Error::other(message.to_owned())
}
