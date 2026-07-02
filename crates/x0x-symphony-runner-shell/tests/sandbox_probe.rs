use std::path::Path;

use x0x_symphony_runner_shell::{
    Backend, HostSandbox, Sandbox, SandboxProfile, SandboxSpec, UnavailablePolicy,
};

#[tokio::test]
async fn sandbox_probe_reports_all_current_platform_checks(
) -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = HostSandbox::new(SandboxSpec {
        profile: SandboxProfile::NoNetwork,
        backend: Backend::Auto,
        on_unavailable: UnavailablePolicy::Warn,
        ..SandboxSpec::default()
    })?;

    let report = sandbox.probe().await?;
    let names = report
        .checks
        .iter()
        .map(|check| check.name.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        [
            "write-outside-workspace",
            "secret-read",
            "host-pid-invisible",
            "non-allowlisted-network",
        ]
    );
    assert_eq!(report.profile, SandboxProfile::NoNetwork);
    assert_current_platform_backend(report.backend);

    Ok(())
}

#[cfg(target_os = "macos")]
fn assert_current_platform_backend(backend: Backend) {
    if Path::new("/usr/bin/sandbox-exec").is_file() {
        assert_eq!(backend, Backend::SandboxExec);
    }
}

#[cfg(target_os = "linux")]
fn assert_current_platform_backend(backend: Backend) {
    assert!(matches!(
        backend,
        Backend::SandboxRuntime | Backend::Bubblewrap | Backend::Landlock | Backend::None
    ));
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn assert_current_platform_backend(backend: Backend) {
    assert_eq!(backend, Backend::None);
}
