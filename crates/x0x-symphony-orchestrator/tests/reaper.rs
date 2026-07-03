use std::{collections::BTreeSet, error::Error, fs, path::Path};

use chrono::{DateTime, TimeZone, Utc};
use x0x_symphony_core::IssueId;
use x0x_symphony_orchestrator::{reap_old_proofs, ReapReport};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[tokio::test]
async fn old_proofs_are_reaped_and_recent_proofs_are_kept() -> TestResult {
    let temp = tempfile::tempdir()?;
    let proofs_dir = temp.path();
    let old_dir = proof_run_dir(proofs_dir, "XSY-0001", "2026-05-01T000000Z")?;
    let recent_dir = proof_run_dir(proofs_dir, "XSY-0002", "2026-06-25T000000Z")?;
    let now = utc(2026, 7, 1, 0, 0, 0)?;

    let report = reap_old_proofs(proofs_dir, now, 30, &BTreeSet::new()).await;

    assert_eq!(
        report,
        ReapReport {
            scanned: 2,
            reaped: 1,
            skipped_active: 0,
            errors: 0,
        }
    );
    assert!(!old_dir.exists());
    assert!(recent_dir.exists());
    Ok(())
}

#[tokio::test]
async fn active_issue_proofs_are_skipped_even_when_old() -> TestResult {
    let temp = tempfile::tempdir()?;
    let proofs_dir = temp.path();
    let old_dir = proof_run_dir(proofs_dir, "XSY-0001", "2026-05-01T000000Z")?;
    let now = utc(2026, 7, 1, 0, 0, 0)?;
    let active_issue_ids = BTreeSet::from([IssueId::new("XSY-0001")?]);

    let report = reap_old_proofs(proofs_dir, now, 30, &active_issue_ids).await;

    assert_eq!(
        report,
        ReapReport {
            scanned: 1,
            reaped: 0,
            skipped_active: 1,
            errors: 0,
        }
    );
    assert!(old_dir.exists());
    Ok(())
}

#[tokio::test]
async fn unparseable_timestamp_is_skipped_without_panic() -> TestResult {
    let temp = tempfile::tempdir()?;
    let proofs_dir = temp.path();
    let bad_dir = proof_run_dir(proofs_dir, "XSY-0001", "not-a-proof-timestamp")?;
    let now = utc(2026, 7, 1, 0, 0, 0)?;

    let report = reap_old_proofs(proofs_dir, now, 30, &BTreeSet::new()).await;

    assert_eq!(
        report,
        ReapReport {
            scanned: 1,
            reaped: 0,
            skipped_active: 0,
            errors: 0,
        }
    );
    assert!(bad_dir.exists());
    Ok(())
}

#[tokio::test]
async fn retention_window_larger_than_age_reaps_nothing() -> TestResult {
    let temp = tempfile::tempdir()?;
    let proofs_dir = temp.path();
    let old_dir = proof_run_dir(proofs_dir, "XSY-0001", "2026-05-01T000000Z")?;
    let collision_dir = proof_run_dir(proofs_dir, "XSY-0001", "2026-05-01T000000Z-01")?;
    let now = utc(2026, 7, 1, 0, 0, 0)?;

    let report = reap_old_proofs(proofs_dir, now, 3_650, &BTreeSet::new()).await;

    assert_eq!(
        report,
        ReapReport {
            scanned: 2,
            reaped: 0,
            skipped_active: 0,
            errors: 0,
        }
    );
    assert!(old_dir.exists());
    assert!(collision_dir.exists());
    Ok(())
}

fn proof_run_dir(
    proofs_dir: &Path,
    issue_id: &str,
    timestamp: &str,
) -> TestResult<std::path::PathBuf> {
    let dir = proofs_dir.join(issue_id).join(timestamp);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("manifest.json"), b"{}\n")?;
    Ok(dir)
}

fn utc(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> TestResult<DateTime<Utc>> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .ok_or_else(|| Box::<dyn Error>::from("invalid UTC test instant"))
}
