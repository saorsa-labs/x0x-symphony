//! `Runner` implementation backed by `tokio::process::Command`.

use std::{
    collections::BTreeMap,
    io,
    pin::Pin,
    process::{ExitStatus, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    task::{Context, Poll},
    time::Instant,
};

use async_trait::async_trait;
use futures_core::Stream;
use futures_util::stream;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};
use x0x_symphony_core::{
    EventStream, Prompt, Runner, RunnerCapabilities, RunnerEvent, RunnerEventKind, SessionContext,
    SessionHandle, SessionId, SymphonyError, TurnOutcome, TurnStatus, UsageReport,
};

use crate::{
    env,
    error::{Error, Result},
    RunnerSpec,
};

const READ_CHUNK_BYTES: usize = 8 * 1024;

/// Shell-backed implementation of the core [`Runner`] trait.
///
/// The runner executes the resolved [`RunnerSpec`] directly as an argv array.
/// It never invokes a shell implicitly and never renders issue fields into argv.
pub struct ShellRunner {
    spec: Arc<RunnerSpec>,
    capabilities: RunnerCapabilities,
    sessions: Arc<Mutex<BTreeMap<SessionId, SessionState>>>,
    next_session: AtomicU64,
}

impl ShellRunner {
    /// Construct a shell runner from a resolved spec.
    ///
    /// # Errors
    ///
    /// Returns an error when the static portion of the spec is invalid.
    pub fn new(spec: RunnerSpec) -> Result<Self> {
        spec.validate()?;
        let mut capabilities = RunnerCapabilities::new("shell");
        if let Some(preset) = spec.preset {
            capabilities = capabilities.with_label(preset.as_str());
        }
        Ok(Self {
            spec: Arc::new(spec),
            capabilities,
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            next_session: AtomicU64::new(1),
        })
    }

    /// Borrow the resolved runner spec.
    #[must_use]
    pub fn spec(&self) -> &RunnerSpec {
        &self.spec
    }

    fn sessions(&self) -> Result<MutexGuard<'_, BTreeMap<SessionId, SessionState>>> {
        self.sessions
            .lock()
            .map_err(|_| Error::SessionRegistryPoisoned)
    }

    fn session_parts(
        &self,
        id: &SessionId,
    ) -> Result<(BoundedEventQueue, BTreeMap<String, String>)> {
        let sessions = self.sessions()?;
        let session = sessions.get(id).ok_or_else(|| Error::UnknownSession {
            session_id: id.as_str().to_owned(),
        })?;
        Ok((session.events.clone(), session.env.clone()))
    }

    fn set_last_usage(&self, id: &SessionId, usage: UsageReport) -> Result<()> {
        let mut sessions = self.sessions()?;
        let session = sessions.get_mut(id).ok_or_else(|| Error::UnknownSession {
            session_id: id.as_str().to_owned(),
        })?;
        session.last_usage = usage;
        Ok(())
    }

    async fn run_child(
        &self,
        sess: &SessionHandle,
        prompt: Prompt,
        events: BoundedEventQueue,
        child_env: BTreeMap<String, String>,
    ) -> Result<TurnOutcome> {
        let started = Instant::now();
        let mut command = self.command_for_session(sess, child_env);
        let mut child = command.spawn().map_err(|source| Error::Spawn {
            command: self.spec.command.clone(),
            source,
        })?;

        let stdin = take_pipe(child.stdin.take(), "stdin", &self.spec.command, &mut child)?;
        let stdout = take_pipe(
            child.stdout.take(),
            "stdout",
            &self.spec.command,
            &mut child,
        )?;
        let stderr = take_pipe(
            child.stderr.take(),
            "stderr",
            &self.spec.command,
            &mut child,
        )?;

        let writer = tokio::spawn(write_prompt(stdin, prompt, events.clone()));
        let stdout_reader = tokio::spawn(stream_reader(
            stdout,
            RunnerEventKind::Stdout,
            events.clone(),
        ));
        let stderr_reader = tokio::spawn(stream_reader(
            stderr,
            RunnerEventKind::Stderr,
            events.clone(),
        ));

        let status =
            wait_with_timeout(&mut child, self.spec.turn_timeout(), &self.spec.command).await?;
        join_background_task(writer, "stdin writer", &events).await;
        join_background_task(stdout_reader, "stdout reader", &events).await;
        join_background_task(stderr_reader, "stderr reader", &events).await;

        let duration_ms = elapsed_ms(started);
        let usage = UsageReport::new().with_duration_ms(duration_ms);
        let outcome = outcome_from_wait_status(status, usage);
        let completion_message = match outcome.summary.clone() {
            Some(summary) => summary,
            None => "turn completed".to_owned(),
        };
        events.send(
            RunnerEvent::new(RunnerEventKind::TurnCompleted).with_message(completion_message),
        );
        Ok(outcome)
    }

    fn command_for_session(
        &self,
        sess: &SessionHandle,
        child_env: BTreeMap<String, String>,
    ) -> Command {
        let mut command = Command::new(&self.spec.command);
        command
            .args(&self.spec.args)
            .current_dir(&sess.workspace_path)
            .env_clear()
            .envs(child_env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_process_group(&mut command);
        command
    }
}

#[async_trait]
impl Runner for ShellRunner {
    fn name(&self) -> &'static str {
        "shell"
    }

    fn capabilities(&self) -> &RunnerCapabilities {
        &self.capabilities
    }

    async fn start_session(&self, ctx: SessionContext) -> x0x_symphony_core::Result<SessionHandle> {
        let child_env = env::build_child_env(&self.spec, &ctx).map_err(SymphonyError::from)?;
        let session_number = self.next_session.fetch_add(1, Ordering::Relaxed);
        let session_id = SessionId::new(format!("shell-{session_number}"));
        let (events, receiver) =
            BoundedEventQueue::new(self.spec.event_capacity, self.spec.event_high_water_mark);
        let handle = SessionHandle::new(session_id.clone(), ctx.workspace_path, now_rfc3339());
        events.send(RunnerEvent::new(RunnerEventKind::SessionStarted));

        let state = SessionState {
            env: child_env,
            events,
            receiver,
            stream_taken: false,
            last_usage: UsageReport::new(),
        };
        self.sessions()
            .map_err(SymphonyError::from)?
            .insert(session_id, state);
        Ok(handle)
    }

    async fn run_turn(
        &self,
        sess: &mut SessionHandle,
        prompt: Prompt,
    ) -> x0x_symphony_core::Result<TurnOutcome> {
        let (events, child_env) = self.session_parts(&sess.id).map_err(SymphonyError::from)?;
        let outcome = self
            .run_child(sess, prompt, events, child_env)
            .await
            .map_err(SymphonyError::from)?;
        self.set_last_usage(&sess.id, outcome.usage.clone())
            .map_err(SymphonyError::from)?;
        Ok(outcome)
    }

    fn stream_events(&self, sess: &SessionHandle) -> EventStream {
        let Ok(mut sessions) = self.sessions.lock() else {
            tracing::warn!(
                session_id = sess.id.as_str(),
                "runner session registry is poisoned"
            );
            return Box::pin(stream::empty::<RunnerEvent>());
        };
        let Some(session) = sessions.get_mut(&sess.id) else {
            return Box::pin(stream::empty::<RunnerEvent>());
        };
        if session.stream_taken {
            return Box::pin(stream::empty::<RunnerEvent>());
        }
        session.stream_taken = true;
        Box::pin(SharedReceiverStream {
            receiver: Arc::clone(&session.receiver),
        })
    }

    async fn stop_session(&self, sess: SessionHandle) -> x0x_symphony_core::Result<UsageReport> {
        let state = self
            .sessions()
            .map_err(SymphonyError::from)?
            .remove(&sess.id)
            .ok_or_else(|| Error::UnknownSession {
                session_id: sess.id.as_str().to_owned(),
            })
            .map_err(SymphonyError::from)?;
        Ok(state.last_usage)
    }
}

struct SessionState {
    env: BTreeMap<String, String>,
    events: BoundedEventQueue,
    receiver: Arc<Mutex<mpsc::Receiver<RunnerEvent>>>,
    stream_taken: bool,
    last_usage: UsageReport,
}

#[derive(Clone)]
struct BoundedEventQueue {
    sender: mpsc::Sender<RunnerEvent>,
    receiver: Arc<Mutex<mpsc::Receiver<RunnerEvent>>>,
    high_water_mark: usize,
}

impl BoundedEventQueue {
    fn new(
        capacity: usize,
        high_water_mark: usize,
    ) -> (Self, Arc<Mutex<mpsc::Receiver<RunnerEvent>>>) {
        let (sender, receiver) = mpsc::channel(capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        (
            Self {
                sender,
                receiver: Arc::clone(&receiver),
                high_water_mark,
            },
            receiver,
        )
    }

    fn send(&self, event: RunnerEvent) {
        self.warn_if_high_water();
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(event)) => self.drop_oldest_and_send(event),
            Err(mpsc::error::TrySendError::Closed(_event)) => {
                tracing::warn!("dropping runner event because receiver is closed");
            }
        }
    }

    fn warn_if_high_water(&self) {
        let occupied = self.sender.max_capacity() - self.sender.capacity();
        if occupied >= self.high_water_mark {
            tracing::warn!(
                occupied,
                capacity = self.sender.max_capacity(),
                "runner event channel reached high-water mark"
            );
        }
    }

    fn drop_oldest_and_send(&self, event: RunnerEvent) {
        let Ok(mut receiver) = self.receiver.lock() else {
            tracing::warn!("runner event channel receiver mutex is poisoned; dropping event");
            return;
        };
        match receiver.try_recv() {
            Ok(_dropped) => {
                tracing::warn!("runner event channel full; dropped oldest event");
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                tracing::warn!("runner event channel reported full but no event was available");
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                tracing::warn!("runner event channel disconnected while dropping oldest event");
            }
        }
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_event)) => {
                tracing::warn!("runner event channel stayed full after dropping oldest event");
            }
            Err(mpsc::error::TrySendError::Closed(_event)) => {
                tracing::warn!("dropping runner event because receiver is closed");
            }
        }
    }
}

struct SharedReceiverStream {
    receiver: Arc<Mutex<mpsc::Receiver<RunnerEvent>>>,
}

impl Stream for SharedReceiverStream {
    type Item = RunnerEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Ok(mut receiver) = self.receiver.lock() {
            Pin::new(&mut *receiver).poll_recv(cx)
        } else {
            tracing::warn!("runner event stream receiver mutex is poisoned");
            Poll::Ready(None)
        }
    }
}

fn take_pipe<T>(
    pipe: Option<T>,
    stream_name: &'static str,
    command: &str,
    child: &mut Child,
) -> Result<T> {
    if let Some(pipe) = pipe {
        Ok(pipe)
    } else {
        kill_process_group(child, command)?;
        Err(Error::MissingPipe {
            command: command.to_owned(),
            stream: stream_name,
        })
    }
}

async fn write_prompt(
    mut stdin: tokio::process::ChildStdin,
    prompt: Prompt,
    events: BoundedEventQueue,
) {
    if let Err(error) = stdin.write_all(prompt.as_str().as_bytes()).await {
        if error.kind() != io::ErrorKind::BrokenPipe {
            events.send(
                RunnerEvent::new(RunnerEventKind::Error)
                    .with_message(format!("failed to write prompt to stdin: {error}")),
            );
        }
        return;
    }
    if let Err(error) = stdin.shutdown().await {
        if error.kind() != io::ErrorKind::BrokenPipe {
            events.send(
                RunnerEvent::new(RunnerEventKind::Error)
                    .with_message(format!("failed to close child stdin: {error}")),
            );
        }
    }
}

async fn stream_reader<R>(mut reader: R, kind: RunnerEventKind, events: BoundedEventQueue)
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(bytes_read) => {
                let message = String::from_utf8_lossy(&buffer[..bytes_read]).into_owned();
                events.send(RunnerEvent::new(kind.clone()).with_message(message));
            }
            Err(error) => {
                events.send(
                    RunnerEvent::new(RunnerEventKind::Error)
                        .with_message(format!("failed to read child stream: {error}")),
                );
                break;
            }
        }
    }
}

async fn join_background_task(
    task: JoinHandle<()>,
    task_name: &'static str,
    events: &BoundedEventQueue,
) {
    if let Err(error) = task.await {
        events.send(
            RunnerEvent::new(RunnerEventKind::Error)
                .with_message(format!("{task_name} task failed: {error}")),
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum WaitStatus {
    Exited(ExitStatus),
    TimedOut,
}

async fn wait_with_timeout(
    child: &mut Child,
    turn_timeout: std::time::Duration,
    command: &str,
) -> Result<WaitStatus> {
    match timeout(turn_timeout, child.wait()).await {
        Ok(wait_result) => wait_result
            .map(WaitStatus::Exited)
            .map_err(|source| Error::Wait {
                command: command.to_owned(),
                source,
            }),
        Err(_elapsed) => {
            kill_process_group(child, command)?;
            child.wait().await.map_err(|source| Error::Wait {
                command: command.to_owned(),
                source,
            })?;
            Ok(WaitStatus::TimedOut)
        }
    }
}

fn outcome_from_wait_status(status: WaitStatus, usage: UsageReport) -> TurnOutcome {
    match status {
        WaitStatus::Exited(exit_status) if exit_status.success() => {
            TurnOutcome::new(TurnStatus::Succeeded, usage).with_summary(exit_summary(exit_status))
        }
        WaitStatus::Exited(exit_status) => {
            TurnOutcome::new(TurnStatus::Failed, usage).with_summary(exit_summary(exit_status))
        }
        WaitStatus::TimedOut => {
            TurnOutcome::new(TurnStatus::TimedOut, usage).with_summary("turn timed out")
        }
    }
}

fn exit_summary(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit_code={code}"),
        None => platform_exit_summary(status),
    }
}

#[cfg(unix)]
fn platform_exit_summary(status: ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;

    match status.signal() {
        Some(signal) => format!("signal={signal}"),
        None => "terminated_without_exit_code".to_owned(),
    }
}

#[cfg(not(unix))]
fn platform_exit_summary(_status: ExitStatus) -> String {
    "terminated_without_exit_code".to_owned()
}

fn elapsed_ms(started: Instant) -> u64 {
    let millis = started.elapsed().as_millis();
    u64::try_from(millis).map_or(u64::MAX, |value| value)
}

fn now_rfc3339() -> String {
    match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to format session timestamp");
            "1970-01-01T00:00:00Z".to_owned()
        }
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn kill_process_group(child: &mut Child, command: &str) -> Result<()> {
    use nix::{
        errno::Errno,
        sys::signal::{kill, Signal},
        unistd::Pid,
    };

    let Some(child_id) = child.id() else {
        return Ok(());
    };
    let pgid = i32::try_from(child_id).map_err(|error| Error::KillProcessGroup {
        command: command.to_owned(),
        message: format!("child id does not fit process id: {error}"),
    })?;
    match kill(Pid::from_raw(-pgid), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(Error::KillProcessGroup {
            command: command.to_owned(),
            message: error.to_string(),
        }),
    }
}

#[cfg(not(unix))]
fn kill_process_group(child: &mut Child, command: &str) -> Result<()> {
    child.start_kill().map_err(|error| Error::KillProcessGroup {
        command: command.to_owned(),
        message: error.to_string(),
    })
}
