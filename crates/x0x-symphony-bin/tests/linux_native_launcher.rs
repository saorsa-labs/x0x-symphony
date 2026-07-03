#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use saorsa_sandbox::linux::{self, LauncherConfig};

fn symphonyd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_x0x-symphonyd"))
}

fn unique_runtime_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path =
        std::env::temp_dir().join(format!("xsy-launcher-test-{}-{nanos}", std::process::id()));
    fs::create_dir(&path)?;
    Ok(path)
}

fn base_config(program: &Path, workspace: &Path) -> LauncherConfig {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_owned(), "/usr/bin:/bin".to_owned());
    LauncherConfig {
        program: program.to_path_buf(),
        args: Vec::new(),
        cwd: workspace.to_path_buf(),
        env,
        read_only_paths: existing_paths([
            PathBuf::from("/bin"),
            PathBuf::from("/usr"),
            PathBuf::from("/lib"),
            PathBuf::from("/lib64"),
            PathBuf::from("/dev/null"),
            program.to_path_buf(),
        ]),
        read_write_paths: vec![workspace.to_path_buf()],
        deny_network: true,
    }
}

fn existing_paths(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    paths.into_iter().filter(|path| path.exists()).collect()
}

fn run_launcher(
    config: &LauncherConfig,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let runtime_dir = unique_runtime_dir()?;
    let sock_path = runtime_dir.join("launcher.sock");
    let listener = UnixListener::bind(&sock_path)?;
    listener.set_nonblocking(true)?;
    let mut child = Command::new(symphonyd_bin())
        .arg("--__saorsa-sandbox-launcher")
        .arg("--socket")
        .arg(&sock_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stream = accept_with_timeout(&listener, &mut child, Duration::from_secs(5))?;
    stream.write_all(&config.to_json_vec()?)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let output = wait_with_timeout(&mut child, Duration::from_secs(10))?;
    fs::remove_dir_all(runtime_dir)?;
    Ok(output)
}

fn accept_with_timeout(
    listener: &UnixListener,
    child: &mut Child,
    timeout: Duration,
) -> Result<UnixStream, Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        match listener.accept() {
            Ok((stream, _addr)) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error.into()),
        }
    }
    child.kill()?;
    let _ = child.wait();
    Err("launcher did not connect to protocol socket".into())
}

fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait()? {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if let Some(mut pipe) = child.stdout.take() {
                pipe.read_to_end(&mut stdout)?;
            }
            if let Some(mut pipe) = child.stderr.take() {
                pipe.read_to_end(&mut stderr)?;
            }
            return Ok(std::process::Output {
                status,
                stdout,
                stderr,
            });
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    child.kill()?;
    let _ = child.wait();
    Err("launcher timed out".into())
}

#[test]
fn landlock_denies_outside_path_and_allows_workspace() -> Result<(), Box<dyn std::error::Error>> {
    let probe = linux::native_probe_with_network_policy(true);
    if !probe.landlock_supported {
        eprintln!("skipping Landlock launcher test: {}", probe.landlock_detail);
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace)?;
    let forbidden_file = root.path().join("outside.txt");
    let allowed_file = workspace.join("inside.txt");
    fs::write(&forbidden_file, b"outside")?;
    fs::write(&allowed_file, b"inside")?;
    let shell = PathBuf::from("/bin/sh");
    let mut config = base_config(&shell, &workspace);
    config.args = vec![
        "-c".to_owned(),
        "cat \"$1\" >/dev/null 2>&1 && exit 42; cat \"$2\" >/dev/null".to_owned(),
        "sh".to_owned(),
        forbidden_file.to_string_lossy().into_owned(),
        allowed_file.to_string_lossy().into_owned(),
    ];

    let output = run_launcher(&config)?;

    assert!(
        output.status.success(),
        "status={}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn launcher_does_not_exec_target_without_config() -> Result<(), Box<dyn std::error::Error>> {
    let runtime_dir = unique_runtime_dir()?;
    let sock_path = runtime_dir.join("launcher.sock");
    let listener = UnixListener::bind(&sock_path)?;
    listener.set_nonblocking(true)?;
    let marker_dir = tempfile::tempdir()?;
    let marker = marker_dir.path().join("marker");
    let mut child = Command::new(symphonyd_bin())
        .arg("--__saorsa-sandbox-launcher")
        .arg("--socket")
        .arg(&sock_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let _stream = accept_with_timeout(&listener, &mut child, Duration::from_secs(5))?;

    child.kill()?;
    let _ = child.wait()?;

    assert!(!marker.exists());
    fs::remove_dir_all(runtime_dir)?;
    Ok(())
}
