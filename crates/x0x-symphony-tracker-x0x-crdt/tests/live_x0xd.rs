use std::{
    env,
    error::Error,
    io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use x0x_symphony_core::{AgentId, Handoff, IssueId, IssueState, Tracker};
use x0x_symphony_tracker_git_jsonl::signing::{SigningClient, X0xdClient as SigningX0xdClient};
use x0x_symphony_tracker_x0x_crdt::{
    client::{AddTaskDraft, X0xdApi, X0xdClient},
    mapping::store_id_for_list,
    X0xCrdtTracker,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

#[tokio::test]
#[ignore = "requires a running x0xd and X0XD_URL"]
async fn live_create_claim_heartbeat_handoff_against_x0xd() -> TestResult {
    let base_url = env::var("X0XD_URL").map_err(|source| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("X0XD_URL is required for the ignored live test: {source}"),
        )
    })?;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| io::Error::other(format!("system clock before epoch: {source}")))?
        .as_millis();
    let list_id = format!("symphony-live-{suffix}");
    let store_id = store_id_for_list(&list_id);

    let client = Arc::new(X0xdClient::new(&base_url)?);
    let signing_client = SigningX0xdClient::new(&base_url)?;
    let agent = AgentId::new(signing_client.agent_identity().await?.agent_id)?;

    client.create_task_list(&list_id, &list_id).await?;
    client.create_kv_store(&store_id, &store_id).await?;
    let task_id = client
        .add_task(
            &list_id,
            AddTaskDraft::new("x0x-symphony live CRDT adapter test")
                .with_description("create -> claim -> heartbeat -> handoff"),
        )
        .await?;

    let tracker = X0xCrdtTracker::from_client(&base_url, &list_id, agent.clone(), client);
    let issue_id = IssueId::new(task_id)?;
    let claim = tracker.claim(&issue_id, &agent).await?;
    tracker.heartbeat(&claim).await?;
    tracker
        .handoff(
            &claim,
            Handoff::new("live x0xd CRDT adapter round trip completed")
                .with_file("crates/x0x-symphony-tracker-x0x-crdt/src/lib.rs"),
        )
        .await?;

    let fetched = tracker.fetch_by_ids(&[issue_id]).await?;
    let issue = fetched
        .first()
        .ok_or_else(|| io::Error::other("live issue disappeared after handoff"))?;
    assert_eq!(issue.state, IssueState::new("review")?);
    assert!(issue.handoff.is_some());
    Ok(())
}
