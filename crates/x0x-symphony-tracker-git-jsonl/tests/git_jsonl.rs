use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    thread,
    time::Duration,
};

use proptest::{prelude::*, test_runner::TestCaseError};
use serde_json::{Map, Value};
use tempfile::TempDir;
use x0x_symphony_core::{
    AgentId, Claim, Handoff, Issue, IssueId, IssueRef, IssueState, PollContext, ReleaseReason,
    ReleaseReasonCode, Shard, ShardRole, Tracker, ValidationResult, ValidationStatus,
};
use x0x_symphony_tracker_git_jsonl::{
    parse_issue_line, serialize_issue, IssueDraft, JsonlTracker, TrackerError,
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
        prop::option::of(non_empty_text_strategy()),
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
    )
        .prop_map(
            |(summary, files_changed, validation, follow_up, proofs_dir)| Handoff {
                summary,
                files_changed,
                validation,
                follow_up,
                proofs_dir,
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
