use proptest::{prelude::*, test_runner::Config};
use x0x_symphony_core::{shard, AgentId, IssueId};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn assignment_is_deterministic() -> TestResult {
    let issue_id = IssueId::new("XSY-0013")?;
    let workers = workers(&["agent-a", "agent-b", "agent-c", "agent-d"])?;

    let first = shard::assign(&issue_id, &workers, 3);
    let second = shard::assign(&issue_id, &workers, 3);

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn backup_count_respects_k_and_worker_bounds() -> TestResult {
    let issue_id = IssueId::new("XSY-0013")?;
    let workers = workers(&["agent-a", "agent-b"])?;

    let shard = shard::assign(&issue_id, &workers, 5)
        .ok_or_else(|| std::io::Error::other("non-empty workers should assign a shard"))?;
    assert_eq!(shard.backups.len(), 1);

    let no_backups = shard::assign(&issue_id, &workers, 1)
        .ok_or_else(|| std::io::Error::other("non-empty workers should assign a shard"))?;
    assert!(no_backups.backups.is_empty());
    Ok(())
}

#[test]
fn empty_workers_leave_issue_unsharded_for_manual_m1() -> TestResult {
    let issue_id = IssueId::new("XSY-0013")?;

    assert!(shard::assign(&issue_id, &[], 3).is_none());
    Ok(())
}

#[test]
fn duplicate_workers_are_deduplicated() -> TestResult {
    let issue_id = IssueId::new("XSY-0013")?;
    let workers = workers(&["agent-a", "agent-a", "agent-b"])?;

    let shard = shard::assign(&issue_id, &workers, 3)
        .ok_or_else(|| std::io::Error::other("non-empty workers should assign a shard"))?;
    assert_ne!(shard.primary, shard.backups[0]);
    assert_eq!(shard.backups.len(), 1);
    Ok(())
}

proptest! {
    #![proptest_config(Config { cases: 32, failure_persistence: None, ..Config::default() })]

    #[test]
    fn primary_assignment_is_approximately_uniform(seed in any::<u64>()) {
        // These worker ids hash to all eight possible leading three-bit
        // prefixes, giving the XOR Voronoi partition equal-sized buckets while
        // still exercising real AgentId hashing.
        let workers = workers(&[
            "uniform-worker-18",
            "uniform-worker-5",
            "uniform-worker-0",
            "uniform-worker-11",
            "uniform-worker-19",
            "uniform-worker-1",
            "uniform-worker-10",
            "uniform-worker-2",
        ])
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let mut counts = vec![0_usize; workers.len()];
        let sample_count = 4_096_usize;

        for index in 0..sample_count {
            let issue_id = IssueId::new(format!("XSY-{seed:016x}-{index:04x}"))
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let assigned = shard::assign(&issue_id, &workers, 3)
                .ok_or_else(|| TestCaseError::fail("non-empty workers should assign a shard"))?;
            let Some(worker_index) = workers.iter().position(|worker| worker == &assigned.primary) else {
                return Err(TestCaseError::fail("assigned primary must come from worker list"));
            };
            counts[worker_index] = counts[worker_index].saturating_add(1);
        }

        let expected = sample_count / workers.len();
        let tolerance = expected / 4;
        for count in counts {
            prop_assert!(count >= expected.saturating_sub(tolerance));
            prop_assert!(count <= expected.saturating_add(tolerance));
        }
    }
}

fn workers(values: &[&str]) -> TestResult<Vec<AgentId>> {
    values
        .iter()
        .map(|value| AgentId::new(*value).map_err(Into::into))
        .collect()
}
