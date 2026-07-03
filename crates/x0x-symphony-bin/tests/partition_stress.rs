use std::{
    env,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};

use reqwest::{Client, RequestBuilder};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use tokio::time::{sleep, Instant};
use x0x_symphony_bin::api::{ClaimResponse, Task};
use x0x_symphony_core::{Issue, IssueDraft};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const HELP: &str = "run scripts/partition-stress.sh or set \
SYMPHONY_PARTITION_A_URL, SYMPHONY_PARTITION_B_URL, \
SYMPHONY_PARTITION_LIST_ID, and SYMPHONY_PARTITION_PHASE";
const DEFAULT_WAIT_SECONDS: u64 = 30;

#[tokio::test]
#[ignore = "requires two running x0x-symphonyd daemons and SYMPHONY_PARTITION_PHASE=create|partitioned_claim|healed_verify"]
async fn partition_reunion_phased_stress_harness() -> TestResult {
    let Some(env) = PartitionEnv::from_env()? else {
        return Ok(());
    };

    match env.phase {
        Phase::Create => phase_create(&env).await,
        Phase::PartitionedClaim => phase_partitioned_claim(&env).await,
        Phase::HealedVerify => phase_healed_verify(&env).await,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Create,
    PartitionedClaim,
    HealedVerify,
}

impl Phase {
    fn parse(value: &str) -> TestResult<Self> {
        match value {
            "create" => Ok(Self::Create),
            "partitioned_claim" => Ok(Self::PartitionedClaim),
            "healed_verify" => Ok(Self::HealedVerify),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid SYMPHONY_PARTITION_PHASE={other}; expected create, \
partitioned_claim, or healed_verify"
                ),
            )
            .into()),
        }
    }
}

struct PartitionEnv {
    a: DaemonClient,
    b: DaemonClient,
    list_id: String,
    phase: Phase,
    state_file: Option<PathBuf>,
    a_proofs_dir: Option<PathBuf>,
    b_proofs_dir: Option<PathBuf>,
    wait_seconds: u64,
}

impl PartitionEnv {
    fn from_env() -> TestResult<Option<Self>> {
        let required = [
            "SYMPHONY_PARTITION_A_URL",
            "SYMPHONY_PARTITION_B_URL",
            "SYMPHONY_PARTITION_LIST_ID",
            "SYMPHONY_PARTITION_PHASE",
        ];
        let missing = required
            .iter()
            .filter(|name| env::var(name).map_or(true, |value| value.trim().is_empty()))
            .copied()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            eprintln!(
                "skipping ignored partition stress harness; missing {} ({HELP})",
                missing.join(", ")
            );
            return Ok(None);
        }

        let a_url = required_env("SYMPHONY_PARTITION_A_URL")?;
        let b_url = required_env("SYMPHONY_PARTITION_B_URL")?;
        let phase = Phase::parse(&required_env("SYMPHONY_PARTITION_PHASE")?)?;
        Ok(Some(Self {
            a: DaemonClient::new(&a_url, optional_env("SYMPHONY_PARTITION_A_TOKEN"))?,
            b: DaemonClient::new(&b_url, optional_env("SYMPHONY_PARTITION_B_TOKEN"))?,
            list_id: required_env("SYMPHONY_PARTITION_LIST_ID")?,
            phase,
            state_file: optional_env("SYMPHONY_PARTITION_STATE_FILE").map(PathBuf::from),
            a_proofs_dir: optional_env("SYMPHONY_PARTITION_A_PROOFS_DIR").map(PathBuf::from),
            b_proofs_dir: optional_env("SYMPHONY_PARTITION_B_PROOFS_DIR").map(PathBuf::from),
            wait_seconds: optional_seconds(
                "SYMPHONY_PARTITION_WAIT_SECONDS",
                DEFAULT_WAIT_SECONDS,
            )?,
        }))
    }

    fn state_file(&self) -> TestResult<&Path> {
        self.state_file.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "SYMPHONY_PARTITION_STATE_FILE is required after the create phase; \
run scripts/partition-stress.sh or reuse the state file printed by create",
            )
            .into()
        })
    }

    fn loser_proofs_dir(&self, loser: &str, state: &PartitionState) -> TestResult<&Path> {
        if state.claim_a_by.as_deref() == Some(loser) {
            return self.a_proofs_dir.as_deref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SYMPHONY_PARTITION_A_PROOFS_DIR is required because daemon A is the loser",
                )
                .into()
            });
        }
        if state.claim_b_by.as_deref() == Some(loser) {
            return self.b_proofs_dir.as_deref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SYMPHONY_PARTITION_B_PROOFS_DIR is required because daemon B is the loser",
                )
                .into()
            });
        }
        Err(io::Error::other(format!(
            "loser {loser} was not one of the partitioned claims: A={:?}, B={:?}",
            state.claim_a_by, state.claim_b_by
        ))
        .into())
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct PartitionState {
    list_id: String,
    issue_id: String,
    primary: String,
    backups: Vec<String>,
    claim_a_by: Option<String>,
    claim_b_by: Option<String>,
}

impl PartitionState {
    fn load(path: &Path, list_id: &str) -> TestResult<Self> {
        let raw = fs::read_to_string(path).map_err(|source| {
            io::Error::new(
                source.kind(),
                format!("failed to read state file {}: {source}", path.display()),
            )
        })?;
        let state = serde_json::from_str::<Self>(&raw)?;
        if state.list_id != list_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "state file {} was created for list {}, not {list_id}",
                    path.display(),
                    state.list_id
                ),
            )
            .into());
        }
        Ok(state)
    }

    fn save(&self, path: &Path) -> TestResult {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let encoded = serde_json::to_string_pretty(self)?;
        fs::write(path, format!("{encoded}\n"))?;
        Ok(())
    }

    fn shard_rank(&self, agent: &str) -> Option<usize> {
        if agent == self.primary {
            return Some(0);
        }
        self.backups
            .iter()
            .position(|backup| backup == agent)
            .map(|index| index + 1)
    }

    fn expected_winner_and_loser(&self) -> TestResult<(&str, &str)> {
        let a = self.claim_a_by.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "state file does not contain daemon A partitioned claim owner",
            )
        })?;
        let b = self.claim_b_by.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "state file does not contain daemon B partitioned claim owner",
            )
        })?;
        if a == b {
            return Err(io::Error::other(format!(
                "partitioned claims were not independent; both daemons claimed as {a}"
            ))
            .into());
        }
        let a_rank = self.shard_rank(a).ok_or_else(|| {
            io::Error::other(format!("daemon A claimant {a} is not in shard slate"))
        })?;
        let b_rank = self.shard_rank(b).ok_or_else(|| {
            io::Error::other(format!("daemon B claimant {b} is not in shard slate"))
        })?;
        if a_rank < b_rank {
            Ok((a, b))
        } else {
            Ok((b, a))
        }
    }
}

#[derive(Debug)]
struct DaemonClient {
    base_url: String,
    token: Option<String>,
    http: Client,
}

impl DaemonClient {
    fn new(base_url: &str, token: Option<String>) -> TestResult<Self> {
        let http = Client::builder().build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            token,
            http,
        })
    }

    async fn create_issue(&self, draft: &IssueDraft) -> TestResult<Issue> {
        self.post_json("/symphony/issues", draft).await
    }

    async fn claim(&self, issue_id: &str) -> TestResult<ClaimResponse> {
        let path = format!("/symphony/claim/{issue_id}");
        self.post_json(&path, &serde_json::json!({})).await
    }

    async fn tasks(&self) -> TestResult<Vec<Task>> {
        self.get_json("/symphony/tasks").await
    }

    async fn get_json<T>(&self, path: &str) -> TestResult<T>
    where
        T: DeserializeOwned,
    {
        let url = self.url(path);
        let request = self.auth(self.http.get(&url));
        let response = request.send().await?;
        decode_response(response, &url).await
    }

    async fn post_json<T, B>(&self, path: &str, body: &B) -> TestResult<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = self.url(path);
        let request = self.auth(self.http.post(&url).json(body));
        let response = request.send().await?;
        decode_response(response, &url).await
    }

    fn auth(&self, request: RequestBuilder) -> RequestBuilder {
        if let Some(token) = self
            .token
            .as_deref()
            .filter(|token| !token.trim().is_empty())
        {
            request.bearer_auth(token)
        } else {
            request
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }
}

async fn decode_response<T>(response: reqwest::Response, url: &str) -> TestResult<T>
where
    T: DeserializeOwned,
{
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(io::Error::other(format!("{url} returned HTTP {status}: {body}")).into());
    }
    Ok(serde_json::from_str(&body)?)
}

async fn phase_create(env: &PartitionEnv) -> TestResult {
    let draft = IssueDraft {
        title: format!("XSY-0029 partition stress on {}", env.list_id),
        description: Some(
            "ignored end-to-end partition reunion harness task; created before the split"
                .to_owned(),
        ),
        priority: Some(1),
        labels: vec!["x0x-symphony".to_owned(), "partition-stress".to_owned()],
    };
    let issue = env.a.create_issue(&draft).await?;
    let shard = issue.shard.as_ref().ok_or_else(|| {
        io::Error::other(format!(
            "created issue {} did not receive a shard slate; ensure both daemons have published worker cards",
            issue.id
        ))
    })?;
    if shard.backups.is_empty() {
        return Err(io::Error::other(format!(
            "created issue {} has no backup shard owner; wait for both daemons to discover each other before partitioning",
            issue.id
        ))
        .into());
    }
    let state = PartitionState {
        list_id: env.list_id.clone(),
        issue_id: issue.id.to_string(),
        primary: shard.primary.to_string(),
        backups: shard.backups.iter().map(ToString::to_string).collect(),
        claim_a_by: None,
        claim_b_by: None,
    };
    let _visible = wait_for_task(&env.b, &state.issue_id, env.wait_seconds).await?;
    if let Some(path) = &env.state_file {
        state.save(path)?;
        println!("SYMPHONY_PARTITION_STATE_FILE={}", path.display());
    }
    println!("SYMPHONY_PARTITION_ISSUE_ID={}", state.issue_id);
    println!("SYMPHONY_PARTITION_PRIMARY={}", state.primary);
    println!("SYMPHONY_PARTITION_BACKUPS={}", state.backups.join(","));
    Ok(())
}

async fn phase_partitioned_claim(env: &PartitionEnv) -> TestResult {
    let path = env.state_file()?;
    let mut state = PartitionState::load(path, &env.list_id)?;
    let (claim_a, claim_b) =
        tokio::try_join!(env.a.claim(&state.issue_id), env.b.claim(&state.issue_id),)?;
    if claim_a.id != state.issue_id || claim_b.id != state.issue_id {
        return Err(io::Error::other(format!(
            "claim responses did not match issue {}: A={}, B={}",
            state.issue_id, claim_a.id, claim_b.id
        ))
        .into());
    }
    if claim_a.by == claim_b.by {
        return Err(io::Error::other(format!(
            "both partitioned daemons claimed as {}; expected independent local agents",
            claim_a.by
        ))
        .into());
    }
    ensure_claimant_is_shard_owner(&state, &claim_a.by, "daemon A")?;
    ensure_claimant_is_shard_owner(&state, &claim_b.by, "daemon B")?;
    state.claim_a_by = Some(claim_a.by);
    state.claim_b_by = Some(claim_b.by);
    state.save(path)?;
    println!("SYMPHONY_PARTITION_CLAIM_A={:?}", state.claim_a_by);
    println!("SYMPHONY_PARTITION_CLAIM_B={:?}", state.claim_b_by);
    Ok(())
}

async fn phase_healed_verify(env: &PartitionEnv) -> TestResult {
    let state = PartitionState::load(env.state_file()?, &env.list_id)?;
    let (expected_winner, expected_loser) = state.expected_winner_and_loser()?;
    let (task_a, task_b) = wait_for_winner(env, &state.issue_id, expected_winner).await?;
    assert_eq!(
        task_a.claim_by.as_deref(),
        Some(expected_winner),
        "daemon A should converge on the lower-index shard winner"
    );
    assert_eq!(
        task_b.claim_by.as_deref(),
        Some(expected_winner),
        "daemon B should converge on the lower-index shard winner"
    );
    let proof_root = env.loser_proofs_dir(expected_loser, &state)?;
    let marker = find_abandon_marker(proof_root, &state.issue_id, expected_winner, expected_loser)?;
    println!("SYMPHONY_PARTITION_WINNER={expected_winner}");
    println!("SYMPHONY_PARTITION_LOSER={expected_loser}");
    println!("SYMPHONY_PARTITION_ABANDON_PROOF={}", marker.display());
    Ok(())
}

fn ensure_claimant_is_shard_owner(
    state: &PartitionState,
    claimant: &str,
    daemon_name: &str,
) -> TestResult {
    if state.shard_rank(claimant).is_some() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{daemon_name} claimed as {claimant}, which is not in shard slate primary={} backups={:?}",
            state.primary, state.backups
        ))
        .into())
    }
}

async fn wait_for_task(
    client: &DaemonClient,
    issue_id: &str,
    wait_seconds: u64,
) -> TestResult<Task> {
    let deadline = Instant::now() + Duration::from_secs(wait_seconds);
    loop {
        if let Some(task) = find_task(client.tasks().await?, issue_id) {
            return Ok(task);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "issue {issue_id} was not visible before timeout"
            ))
            .into());
        }
        sleep(Duration::from_secs(1)).await;
    }
}

async fn wait_for_winner(
    env: &PartitionEnv,
    issue_id: &str,
    expected_winner: &str,
) -> TestResult<(Task, Task)> {
    let deadline = Instant::now() + Duration::from_secs(env.wait_seconds);
    loop {
        let a_task = find_task(env.a.tasks().await?, issue_id);
        let b_task = find_task(env.b.tasks().await?, issue_id);
        if let (Some(a), Some(b)) = (a_task, b_task) {
            if a.claim_by.as_deref() == Some(expected_winner)
                && b.claim_by.as_deref() == Some(expected_winner)
            {
                return Ok((a, b));
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "issue {issue_id} did not converge to expected winner {expected_winner} before timeout"
            ))
            .into());
        }
        sleep(Duration::from_secs(1)).await;
    }
}

fn find_task(tasks: Vec<Task>, issue_id: &str) -> Option<Task> {
    tasks.into_iter().find(|task| task.id == issue_id)
}

fn find_abandon_marker(
    proofs_root: &Path,
    issue_id: &str,
    expected_winner: &str,
    expected_loser: &str,
) -> TestResult<PathBuf> {
    let issue_dir = proofs_root.join(issue_id);
    let entries = fs::read_dir(&issue_dir).map_err(|source| {
        io::Error::new(
            source.kind(),
            format!(
                "failed to read abandon proof directory {}: {source}",
                issue_dir.display()
            ),
        )
    })?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() || !ends_with_abandoned(&path) {
            continue;
        }
        let marker = path.join("abandon.json");
        if marker_is_expected(&marker, issue_id, expected_winner, expected_loser)? {
            return Ok(path);
        }
    }
    Err(io::Error::other(format!(
        "no abandon proof marker for loser {expected_loser} and winner {expected_winner} under {}",
        issue_dir.display()
    ))
    .into())
}

fn ends_with_abandoned(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with("-abandoned"))
}

fn marker_is_expected(
    marker: &Path,
    issue_id: &str,
    expected_winner: &str,
    expected_loser: &str,
) -> TestResult<bool> {
    if !marker.is_file() {
        return Ok(false);
    }
    let raw = fs::read_to_string(marker)?;
    let value = serde_json::from_str::<Value>(&raw)?;
    Ok(
        value.get("issue_id").and_then(Value::as_str) == Some(issue_id)
            && nested_str(&value, &["abandoned_claim", "by"]) == Some(expected_loser)
            && nested_str(&value, &["reason", "code"]) == Some("conflict")
            && value.get("winning_agent_id").and_then(Value::as_str) == Some(expected_winner),
    )
}

fn nested_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_str()
}

fn required_env(name: &str) -> TestResult<String> {
    env::var(name)
        .map(|value| value.trim().to_owned())
        .map_err(|source| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{name} is required for the ignored partition stress harness: {source}"),
            )
            .into()
        })
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name).ok().and_then(|value| {
        let trimmed = value.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    })
}

fn optional_seconds(name: &str, default: u64) -> TestResult<u64> {
    let Some(value) = optional_env(name) else {
        return Ok(default);
    };
    value.parse::<u64>().map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be an unsigned integer number of seconds: {source}"),
        )
        .into()
    })
}
