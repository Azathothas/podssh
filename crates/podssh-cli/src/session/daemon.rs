//! `podssh session serve` (T-186), the session's daemon, which `start` runs
//! in the background. In order: the refusals of the command line and of
//! `PODSSH_LISTEN`, before any bind; the bind of the socket, which is the
//! probe, through the listener of `podssh pipe` (mode 0600, and a client of
//! another user closed); the session on the road and the SSH client of
//! `podssh ssh`, with a pty, its output into the [`Model`] and its input
//! from `send`; the line of ready; then the requests of each client. It
//! ends at `stop`, a minute after its session ended (so that the last
//! screen can be read), after an hour with no request, or at SIGINT,
//! SIGTERM or SIGHUP; the socket's file goes at each end.

use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use podssh_ssh::io::Feed;
use podssh_ssh::retry::Phase;
use podssh_ssh::{Log, Request, RequestTty};
use serde_json::Map;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, watch, Notify};

use super::model::Model;
use super::wire::{self, Op, Wait};
use super::SessionArgs;
use crate::exitmap::sysexits::{EX_TEMPFAIL, EX_UNAVAILABLE, EX_USAGE};
use crate::pipe::address::Address;
use crate::pipe::listen::Listener;
use crate::pipe::pump::{End, Writer};
use crate::relay_settings::Refusal;
use crate::ssh::resolve::{self, Env, Resolved};

/// A session that ended answers for this long more, so that its last
/// screen can be read.
pub const GRACE: Duration = Duration::from_secs(60);
/// With no request for this long, the daemon ends its session.
pub const IDLE_LIMIT: Duration = Duration::from_secs(3600);
/// How often the daemon looks whether its session is ready.
const TICK: Duration = Duration::from_millis(50);

/// Run `podssh session serve`; the exit code.
pub fn run(args: &SessionArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let plan = match plan(args) {
        Ok(plan) => plan,
        Err(refusal) => return refusal.report("session", err),
    };
    super::start::no_stdin();
    let Some(runtime) = super::runtime(err) else { return super::NO_RUNTIME };
    // On the heap: the future of a road is large.
    let code = runtime.block_on(Box::pin(serve(args, plan, out, err)));
    // A client's task may still wait; the daemon is done.
    runtime.shutdown_background();
    code
}

/// What the daemon needs before it binds.
pub(super) struct Plan {
    resolved: Resolved,
    log: Arc<Log>,
    /// The socket.
    path: String,
}

/// The refusals that come before any bind: `PODSSH_LISTEN` (78), the
/// command line as `podssh ssh` resolves it (64, 78), and the place of the
/// socket (78). `start` makes them too, before its child starts.
pub(super) fn plan(args: &SessionArgs) -> Result<Plan, Refusal> {
    crate::pipe::listen::allowed()?;
    crate::pins::apply(args.ssh.relay_addr.as_deref())?;
    let mut resolved = resolve::resolve_or_refuse(&args.ssh, &Env::from_process())?;
    if !matches!(resolved.options.request, Request::Shell | Request::Exec(_)) {
        return Err(Refusal::usage(
            "SessionType in ssh_config asks for no shell and no command, and podssh session holds one of them",
        ));
    }
    // One session with a pty, its input from send and its output into the
    // model: no terminal of this process, no escape character, no forward,
    // no X11 and no control socket.
    let options = &mut resolved.options;
    options.request_tty = RequestTty::Force;
    options.stdin_null = false;
    options.escape_char = None;
    options.interrupt_signal = false;
    let forwards = !resolved.local.is_empty() || !resolved.options.remote_forwards.is_empty();
    if forwards || resolved.x11.is_some() || resolved.control.path.is_some() {
        let note = "podssh session opens no forward, no X11 and no control socket: those of ssh_config are not used";
        resolved.notes.push(note.to_string());
    }
    resolved.local.clear();
    resolved.options.remote_forwards.clear();
    resolved.x11 = None;
    resolved.control = Default::default();
    resolved.persist = None;
    resolved.upgrade = None;
    resolved.record = None;
    let log = Arc::new(Log::new(resolved.options.log_level));
    let path = super::place::new(args.name(), args.socket.as_deref())?;
    Ok(Plan { resolved, log, path })
}

/// What the daemon shares with each client.
struct Shared {
    name: String,
    /// The destination as the command line names it.
    host: String,
    model: Mutex<Model>,
    life: Mutex<Life>,
    /// Bumped at each change of the model and at the end: each wait wakes.
    changed: watch::Sender<u64>,
    /// The session's input: what `send` puts waits there until the session
    /// reads it, as keys typed ahead (the feed of T-185).
    keys: Feed,
    stop: Notify,
}

struct Life {
    /// The session's exit code, and when it ended.
    ended: Option<(i32, Instant)>,
    last_request: Instant,
}

impl Shared {
    fn model(&self) -> MutexGuard<'_, Model> {
        self.model.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn life(&self) -> MutexGuard<'_, Life> {
        self.life.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn bump(&self) {
        self.changed.send_modify(|n| *n = n.wrapping_add(1));
    }

    fn ended(&self) -> Option<i32> {
        self.life().ended.map(|(code, _)| code)
    }

    fn end(&self, code: i32) {
        self.life().ended = Some((code, Instant::now()));
        self.bump();
    }

    fn touched(&self) {
        self.life().last_request = Instant::now();
    }

    /// When the daemon ends unless something comes: a minute after its
    /// session's end, else an hour after the last request.
    fn deadline(&self) -> Instant {
        let life = self.life();
        match life.ended {
            Some((_, at)) => at + GRACE,
            None => life.last_request + IDLE_LIMIT,
        }
    }
}

async fn serve(args: &SessionArgs, plan: Plan, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Plan { mut resolved, log, path } = plan;
    // Held until the daemon ends, before the probe of the socket.
    let _lock = match socket_lock(&path) {
        Ok(lock) => lock,
        Err(line) => {
            let _ = writeln!(err, "podssh session: {line}");
            return EX_UNAVAILABLE;
        }
    };
    // A client of another user that was closed is said; the others with -v.
    let mut say = |line: &str| if line.starts_with("closed") { log.info(line) } else { log.verbose(line) };
    let mut listener = match Listener::bind(&Address::UnixListen(path.clone()), &mut say).await {
        Ok(listener) => listener,
        Err((code, line)) => {
            let _ = writeln!(err, "podssh session: {line}");
            // An AF_UNIX socket needs Windows 10 1803; a named pipe, none.
            if cfg!(windows) && args.socket.is_none() {
                let _ = writeln!(err, "podssh session: --socket \\\\.\\pipe\\NAME listens on a named pipe instead");
            }
            let _ = writeln!(
                err,
                "podssh session: with no listener, podssh ssh -tt HOST COMMAND runs a command with a pty in one call"
            );
            return code;
        }
    };
    for note in &resolved.notes {
        log.verbose(note);
    }
    for warning in &resolved.warnings {
        log.info(warning);
    }
    let (sink, pieces) = mpsc::channel(64);
    let keys = Feed::new();
    resolved.options.output = Some(sink);
    resolved.options.feed = Some(keys.clone());
    let (rows, cols) = size();
    let now = Instant::now();
    let shared = Arc::new(Shared {
        name: args.name().to_string(),
        host: args.ssh.destination.clone().unwrap_or_default(),
        model: Mutex::new(Model::new(rows, cols, now)),
        life: Mutex::new(Life { ended: None, last_request: now }),
        changed: watch::channel(0).0,
        keys,
        stop: Notify::new(),
    });
    let mut draining = tokio::spawn(drain(pieces, shared.clone()));
    let mut session = Box::pin(crate::ssh::connect_and_run(resolved, log.clone()));
    let (mut running, mut ready) = (true, false);
    let mut tick = tokio::time::interval(TICK);
    let mut signals = crate::agent::serve::Stop::new();
    loop {
        let until = tokio::time::Instant::from_std(shared.deadline());
        tokio::select! {
            code = &mut session, if running => {
                running = false;
                if !ready && podssh_ssh::retry::phase() < Phase::Requested {
                    // The connection or the login failed, and the log said
                    // why: start passes it on, with this code.
                    return code;
                }
                // The last output reaches the model before the end is told.
                let _ = tokio::time::timeout(Duration::from_secs(1), &mut draining).await;
                if !ready && !announce(&shared.name, &path, args.detach, out) {
                    return EX_TEMPFAIL;
                }
                ready = true;
                log.verbose(&format!("the session ended with {code}; its screen is kept {} s more", GRACE.as_secs()));
                shared.end(code);
            }
            _ = tick.tick(), if !ready => {
                if podssh_ssh::retry::phase() >= Phase::Requested {
                    if !announce(&shared.name, &path, args.detach, out) {
                        return EX_TEMPFAIL;
                    }
                    ready = true;
                }
            }
            accepted = listener.accept(&mut say) => match accepted {
                Ok(end) => {
                    tokio::spawn(client(end, shared.clone()));
                }
                Err(e) => {
                    log.error(&format!("{path}: {e}"));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            () = shared.stop.notified() => return 0,
            () = tokio::time::sleep_until(until) => {
                if Instant::now() < shared.deadline() {
                    continue;
                }
                return match shared.ended() {
                    Some(code) => code,
                    None => {
                        log.info(&format!("no request for {} s: the session ends", IDLE_LIMIT.as_secs()));
                        0
                    }
                };
            }
            code = signals.next() => return code,
        }
    }
}

/// The pty's size, as the session asks for it: the terminal's, else
/// `COLUMNS` and `LINES`, else 80 by 24.
fn size() -> (u16, u16) {
    let size = podssh_ssh::terminal::size().unwrap_or_else(podssh_ssh::terminal::fallback_size);
    let fit = |n: u32| u16::try_from(n).unwrap_or(u16::MAX).max(1);
    (fit(size.rows), fit(size.cols))
}

/// The line of ready on stdout, out of the starter's terminal first; then,
/// for `start`, stdout and stderr go to the null device. Whether the line
/// was written: `start` that has gone before it reads none, and nobody
/// would know of the session.
fn announce(name: &str, path: &str, detach: bool, out: &mut dyn Write) -> bool {
    if detach {
        super::start::leave_terminal();
    }
    let said = writeln!(out, "{}", wire::ready(name, path, std::process::id())).and_then(|()| out.flush()).is_ok();
    if detach {
        super::start::leave();
    }
    said || !detach
}

/// The session's output into the model, as it comes; each piece wakes the
/// waits. It ends with the session, whose sink goes with it.
async fn drain(mut pieces: mpsc::Receiver<(Vec<u8>, bool)>, shared: Arc<Shared>) {
    // A terminal shows stderr's bytes as it shows stdout's.
    while let Some((bytes, _stderr)) = pieces.recv().await {
        shared.model().output(&bytes, Instant::now());
        shared.bump();
    }
}

/// One client: each request line, answered, until the client closes, or
/// until it asked to stop.
async fn client(end: End, shared: Arc<Shared>) {
    let mut reader = BufReader::new(end.read);
    let mut writer = end.write;
    loop {
        let mut line = Vec::new();
        match (&mut reader).take(wire::MAX_LINE as u64 + 1).read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if line.len() > wire::MAX_LINE {
            let _ = answer(&mut writer, &wire::failed(EX_USAGE, "a line longer than 1 MiB")).await;
            return;
        }
        shared.touched();
        let (reply, stop) = match wire::parse_request(&line) {
            Err((code, why)) => (wire::failed(code, &why), false),
            Ok(request) if request.name != shared.name => {
                let why = format!("this socket is the session {}'s, not {}'s", shared.name, request.name);
                (wire::failed(EX_USAGE, &why), false)
            }
            Ok(request) => act(request.op, &shared).await,
        };
        if answer(&mut writer, &reply).await.is_err() {
            return;
        }
        if stop {
            shared.stop.notify_one();
            return;
        }
    }
}

async fn answer(writer: &mut Writer, line: &str) -> std::io::Result<()> {
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

/// The answer to an operation, and whether the daemon stops after it.
async fn act(op: Op, shared: &Shared) -> (String, bool) {
    match op {
        Op::Info => {
            let size = shared.model().size();
            let fields = wire::info(&shared.name, &shared.host, std::process::id(), shared.ended(), size);
            (wire::ok(fields), false)
        }
        Op::Send(bytes) => (send(shared, bytes).await, false),
        Op::Wait(wait) => (wait_for(shared, wait).await, false),
        Op::Capture { raw } => {
            let model = shared.model();
            let fields =
                if raw { wire::raw(&model.raw()) } else { wire::screen(model.screen(), model.cursor(), model.size()) };
            (wire::ok(fields), false)
        }
        Op::Stop => (wire::ok(Map::new()), true),
    }
}

/// The line of a session that ended.
fn ended_line(code: i32) -> String {
    format!("the session ended with status {code}")
}

/// Type `bytes` into the session: what comes after them counts for a wait.
async fn send(shared: &Shared, bytes: Vec<u8>) -> String {
    if let Some(code) = shared.ended() {
        return wire::failed(EX_UNAVAILABLE, &ended_line(code));
    }
    shared.model().sent(Instant::now());
    shared.bump();
    shared.keys.put(&bytes);
    wire::ok(Map::new())
}

/// Wait until the text of `wait` came, or the output stopped for its idle
/// time, within its limit: 75 when the limit passed first, 69 when the
/// session ended first.
async fn wait_for(shared: &Shared, wait: Wait) -> String {
    let mut changes = shared.changed.subscribe();
    let until = Instant::now() + wait.timeout;
    loop {
        let (matched, left) = {
            let model = shared.model();
            let matched = wait.text.as_deref().is_some_and(|text| model.matched(text));
            (matched, wait.idle.map(|idle| model.idle_left(idle, Instant::now())))
        };
        if matched {
            return wire::ok(wire::by("match"));
        }
        if let Some(code) = shared.ended() {
            return wire::failed(EX_UNAVAILABLE, &ended_line(code));
        }
        if left == Some(Duration::ZERO) {
            return wire::ok(wire::by("idle"));
        }
        let now = Instant::now();
        if now >= until {
            let why = format!("nothing that the wait asked for came within {} s", wait.timeout.as_secs_f32());
            return wire::failed(EX_TEMPFAIL, &why);
        }
        let next = left.map_or(until, |left| (now + left).min(until));
        tokio::select! {
            _ = changes.changed() => {}
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(next)) => {}
        }
    }
}

/// The lock of a socket's file, `PATH.lock`, which the daemon holds for its
/// life (T-392): two starts of one name could both find the path free, and
/// the second, whose bind failed, would remove the first's socket, so that
/// its session answered nobody. Another daemon's lock is a refusal (69); a
/// lock that cannot be had lets the daemon go on as before. An abstract
/// name of Linux and a named pipe of Windows have no file: their bind
/// alone decides.
pub(super) fn socket_lock(path: &str) -> Result<Option<std::fs::File>, String> {
    if path.starts_with('@') || path.starts_with(r"\\.\pipe\") {
        return Ok(None);
    }
    let lock = std::path::PathBuf::from(format!("{path}.lock"));
    match crate::node_install::lock::try_hold(&lock) {
        Ok(crate::node_install::lock::Tried::Held(file)) => Ok(Some(file)),
        Ok(crate::node_install::lock::Tried::Taken(pid)) => Err(format!(
            "{path}: another podssh session serves it{}, as it holds {}",
            pid.map_or_else(String::new, |pid| format!(" (pid {pid})")),
            lock.display()
        )),
        Err(_) => Ok(None),
    }
}
