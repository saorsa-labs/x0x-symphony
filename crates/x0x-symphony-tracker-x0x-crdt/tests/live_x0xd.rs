use std::{
    env,
    error::Error,
    io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use x0x_symphony_core::{AgentId, Handoff, IssueId, IssueState, PollContext, Tracker};
use x0x_symphony_signing::{SigningClient, X0xdClient as SigningX0xdClient};
use x0x_symphony_tracker_x0x_crdt::{
    client::{AddTaskDraft, X0xdApi, X0xdClient},
    mapping::store_id_for_list,
    X0xCrdtTracker,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn unique_suffix() -> TestResult<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| io::Error::other(format!("system clock before epoch: {source}")))?
        .as_millis())
}

fn scoped_list_id(group_id: &str, list_id: &str) -> String {
    format!("x0x.group.{group_id}.symphony.{list_id}")
}

async fn post_json(
    http: &reqwest::Client,
    base_url: &str,
    path: &str,
    body: serde_json::Value,
) -> TestResult<serde_json::Value> {
    let url = format!("{}{path}", base_url.trim_end_matches('/'));
    let mut request = http.post(url).json(&body);
    if let Ok(token) = env::var("X0X_API_TOKEN") {
        if !token.trim().is_empty() {
            request = request.bearer_auth(token);
        }
    }
    let response = request.send().await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(io::Error::other(format!("x0xd returned HTTP {status}: {body}")).into());
    }
    serde_json::from_str(&body).map_err(Into::into)
}

async fn create_group(http: &reqwest::Client, base_url: &str, name: &str) -> TestResult<String> {
    let response = post_json(
        http,
        base_url,
        "/groups",
        serde_json::json!({
            "name": name,
            "description": "x0x-symphony MLS isolation live test",
            "preset": "private_secure"
        }),
    )
    .await?;
    response
        .get("group_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("/groups response missing group_id").into())
}

async fn create_invite(
    http: &reqwest::Client,
    base_url: &str,
    group_id: &str,
) -> TestResult<String> {
    let path = format!("/groups/{group_id}/invite");
    let response = post_json(http, base_url, &path, serde_json::json!({})).await?;
    response
        .get("invite_link")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("/groups/:id/invite response missing invite_link").into())
}

async fn join_group(http: &reqwest::Client, base_url: &str, invite: &str) -> TestResult {
    let _response = post_json(
        http,
        base_url,
        "/groups/join",
        serde_json::json!({"invite": invite, "display_name": "symphony-live-member"}),
    )
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires three running x0xd daemons: X0XD_URL_OWNER, X0XD_URL_MEMBER, X0XD_URL_OUTSIDER"]
async fn live_group_scoped_task_lists_are_isolated_between_daemons() -> TestResult {
    let owner_url = env::var("X0XD_URL_OWNER").map_err(|source| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("X0XD_URL_OWNER is required for the ignored MLS isolation test: {source}"),
        )
    })?;
    let member_url = env::var("X0XD_URL_MEMBER").map_err(|source| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("X0XD_URL_MEMBER is required for the ignored MLS isolation test: {source}"),
        )
    })?;
    let outsider_url = env::var("X0XD_URL_OUTSIDER").map_err(|source| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("X0XD_URL_OUTSIDER is required for the ignored MLS isolation test: {source}"),
        )
    })?;
    let suffix = unique_suffix()?;
    let http = reqwest::Client::new();

    let owner_group = create_group(&http, &owner_url, &format!("symphony-owner-{suffix}")).await?;
    let outsider_group =
        create_group(&http, &outsider_url, &format!("symphony-other-{suffix}")).await?;
    let invite = create_invite(&http, &owner_url, &owner_group).await?;
    join_group(&http, &member_url, &invite).await?;

    let owner_client = Arc::new(X0xdClient::new(&owner_url)?);
    let member_client = Arc::new(X0xdClient::new(&member_url)?);
    let outsider_client = Arc::new(X0xdClient::new(&outsider_url)?);
    let list_id = "symphony-live-private";
    let scoped_owner_list = scoped_list_id(&owner_group, list_id);
    owner_client
        .create_task_list(&scoped_owner_list, &scoped_owner_list)
        .await?;
    owner_client
        .add_task(
            &scoped_owner_list,
            AddTaskDraft::new("private MLS task").with_description("visible only to group members"),
        )
        .await?;

    let ctx = PollContext::new(
        vec![IssueState::new("todo")?],
        vec![IssueState::new("done")?],
    );
    let member_agent = AgentId::new(
        SigningX0xdClient::new(&member_url)?
            .agent_identity()
            .await?
            .agent_id,
    )?;
    let outsider_agent = AgentId::new(
        SigningX0xdClient::new(&outsider_url)?
            .agent_identity()
            .await?
            .agent_id,
    )?;
    let member_tracker = X0xCrdtTracker::builder(&member_url, list_id, member_agent)
        .client(member_client)
        .group(owner_group)
        .build()?;
    let outsider_tracker = X0xCrdtTracker::builder(&outsider_url, list_id, outsider_agent)
        .client(outsider_client)
        .group(outsider_group)
        .build()?;

    let member_candidates = member_tracker.fetch_candidates(&ctx).await?;
    let outsider_candidates = outsider_tracker.fetch_candidates(&ctx).await?;

    assert!(!member_candidates.is_empty());
    assert!(outsider_candidates.is_empty());
    Ok(())
}

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
