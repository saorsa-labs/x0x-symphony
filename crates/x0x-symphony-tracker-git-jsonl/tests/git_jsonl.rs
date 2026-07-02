use std::{
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
    AgentId, Handoff, IssueId, IssueState, PollContext, ReleaseReason, ReleaseReasonCode, Tracker,
    ValidationResult, ValidationStatus,
};
use x0x_symphony_tracker_git_jsonl::{
    parse_issue_line, serialize_issue, IssueDraft, JsonlTracker, TrackerError,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

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
    fn unknown_fields_are_byte_stable_after_parse_serialize(
        extra in proptest::collection::btree_map("[a-z][a-z0-9_]{0,8}", "[ -~]{0,24}", 1..8)
    ) {
        let mut object = base_issue_object();
        let mut original_unknown = Vec::new();
        for (key, text) in extra {
            let field = format!("x_{key}");
            let value = Value::String(text);
            let bytes = serde_json::to_string(&value)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            object.insert(field.clone(), value);
            original_unknown.push((field, bytes));
        }
        let line = serde_json::to_string(&Value::Object(object))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let parsed = parse_issue_line(1, &line)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let serialized = serialize_issue(&parsed)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let reparsed = serde_json::from_str::<Value>(&serialized)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let Value::Object(after) = reparsed else {
            return Err(TestCaseError::fail("serialized issue was not an object"));
        };
        for (field, before_bytes) in original_unknown {
            let Some(after_value) = after.get(&field) else {
                return Err(TestCaseError::fail(format!("missing unknown field {field}")));
            };
            let after_bytes = serde_json::to_string(after_value)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert_eq!(before_bytes, after_bytes);
        }
    }
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

fn base_issue_object() -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("id".to_owned(), Value::String("XSY-0100".to_owned()));
    object.insert(
        "identifier".to_owned(),
        Value::String("XSY-0100".to_owned()),
    );
    object.insert("title".to_owned(), Value::String("Property".to_owned()));
    object.insert("description".to_owned(), Value::String(String::new()));
    object.insert("priority".to_owned(), Value::Number(2_u8.into()));
    object.insert("state".to_owned(), Value::String("todo".to_owned()));
    object.insert("branch_name".to_owned(), Value::Null);
    object.insert("url".to_owned(), Value::Null);
    object.insert("labels".to_owned(), Value::Array(Vec::new()));
    object.insert("blocked_by".to_owned(), Value::Array(Vec::new()));
    object.insert(
        "created_at".to_owned(),
        Value::String("2026-07-02T00:00:00Z".to_owned()),
    );
    object.insert(
        "updated_at".to_owned(),
        Value::String("2026-07-02T00:00:00Z".to_owned()),
    );
    object
}
