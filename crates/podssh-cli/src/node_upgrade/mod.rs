//! A node that keeps its sessions across its own upgrade (T-668). SIGUSR2,
//! which `podssh update` sends each node of `--detach` that it replaced,
//! asks a node of the pair's road to take the binary now at its path: it
//! runs that binary once as a probe, which must say that it takes a node's
//! sessions; then it stops its socket as a stop does, with each session's
//! `close` saying that the node upgrades, hands each session of its keeper
//! over (the layer's state, the channel's keys and nonces, the target's TCP
//! connection), and becomes the new binary by `execve`, with its pid, its
//! words and its environment. The new binary reads the sessions before it
//! connects, keeps each as a session whose link was lost, and goes online;
//! each client resumes as after any loss, and the sshd's connection is the
//! one of before. A session that cannot move ends at its resume, with why.
//! A binary that does not start gives the sessions back to this one, which
//! serves on. This binary started again at the user's request is no helper
//! (Q61).
//!
//! Where the system has no such signal (Windows), nothing asks, and a node
//! goes on with its binary until it starts again, as before.

pub mod mark;
#[cfg(unix)]
mod pass;
#[cfg(unix)]
mod probe;
pub mod state;

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::e2e::{ends, hold};
use podssh_relay::session::handover::{Handed, Movable, Moved};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::SessionId;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::net::TcpStream;

/// The variable that names the sessions for the binary that takes a node's
/// place, set by podssh alone; `probe` makes `--version` say what it takes.
pub const VARIABLE: &str = "PODSSH_HANDOVER";
/// The value of [`VARIABLE`] of a probe.
pub const PROBE: &str = "probe";
/// The start of the line that a binary which takes a node's sessions adds
/// to `--version` when probed, and the version of the handover after it.
pub const PROBE_WORD: &str = "podssh-handover ";
pub const HANDOVER_VERSION: &str = "1";
/// The code of a node's serve after an upgrade whose binary did not start:
/// the node serves again, with the sessions back. Never a process's code.
pub const AGAIN: i32 = i32::MIN;

/// The sessions that the binary before this one handed over, or that came
/// back from a binary that did not start, until a keeper takes them.
static TAKEN: Mutex<Option<Vec<Handed>>> = Mutex::new(None);
/// Whether this process took a node's place.
static TOOK: AtomicBool = AtomicBool::new(false);
/// The binary that passed its probe, and its line, once an upgrade is asked.
static ASKED: Mutex<Option<(PathBuf, String)>> = Mutex::new(None);
/// The keeper of the node's sessions, for the handover.
static KEEPER: Mutex<Option<Arc<dyn HandOver>>> = Mutex::new(None);
/// Where the node's lines go.
static LINES: Mutex<Option<Arc<dyn Fn(String) + Send + Sync>>> = Mutex::new(None);

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn say(line: String) {
    match lock(&LINES).clone() {
        Some(say) => say(line),
        None => podssh_ssh::err_line!("podssh node: {line}"),
    }
}

/// The node's lines from now on: its label's, and a detached run's log.
pub(crate) fn lines(say: Arc<dyn Fn(String) + Send + Sync>) {
    *lock(&LINES) = Some(say);
}

/// Whether this process took the place of a node of the binary before it:
/// a detached run's terminal and streams were left already.
pub fn took() -> bool {
    TOOK.load(Ordering::SeqCst)
}

/// A keeper whose sessions a handover can take.
trait HandOver: Send + Sync {
    fn hand_over(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Handed>> + '_>>;
}

impl<A> HandOver for Keeper<A>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + Movable,
{
    fn hand_over(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Handed>> + '_>> {
        Box::pin(Keeper::hand_over(self))
    }
}

/// At the start of `podssh node`: a stray signal of an upgrade ends no node
/// of a road that does not take one, and the sessions that the binary
/// before this one handed over are read, before anything connects.
pub fn start(err: &mut dyn Write) {
    #[cfg(unix)]
    // SAFETY: the disposition of one signal, before the runtime starts;
    // the pair's road listens for it again.
    unsafe {
        libc::signal(libc::SIGUSR2, libc::SIG_IGN);
    }
    let Some(value) = std::env::var_os(VARIABLE) else { return };
    let value = value.to_string_lossy().into_owned();
    if value == PROBE {
        return;
    }
    #[cfg(unix)]
    match read(&value) {
        Ok(None) => {}
        Ok(Some((from, handed))) => {
            let moved = handed.iter().filter(|h| h.target.is_ok()).count();
            let _ = writeln!(
                err,
                "podssh node: took {moved} of {} sessions over from {from}: each resumes on this binary's socket",
                handed.len()
            );
            TOOK.store(true, Ordering::SeqCst);
            *lock(&TAKEN) = Some(handed);
        }
        Err(why) => {
            TOOK.store(true, Ordering::SeqCst);
            let _ = writeln!(err, "podssh node: the sessions of the binary before this one are lost: {why}");
        }
    }
    #[cfg(not(unix))]
    let _ = (value, err);
}

/// The sessions in the memory that `value` names, when it names this
/// process.
#[cfg(unix)]
fn read(value: &str) -> Result<Option<(String, Vec<Handed>)>, String> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let Some(fd) = pass::fd_of(value)? else { return Ok(None) };
    // SAFETY: the descriptor that the binary before this one left open for
    // this one, named with this pid; nothing else of this process owns it.
    let memory = unsafe { OwnedFd::from_raw_fd(fd) };
    let bytes = pass::read_memory(memory)?;
    pass::taken(&bytes).map(Some)
}

/// The stop of a node of the pair's road: Ctrl-C or SIGTERM, as
/// [`stop_signal`], or an upgrade whose binary passed its probe.
pub(crate) async fn stop() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut asked) = signal(SignalKind::user_defined2()) {
            mark::serving();
            let stopped = stop_signal();
            tokio::pin!(stopped);
            loop {
                tokio::select! {
                    () = &mut stopped => return,
                    got = asked.recv() => {
                        // A stream of the signal that ended leaves the stop alone.
                        if got.is_none() {
                            return stopped.await;
                        }
                        if ready().await {
                            return;
                        }
                    }
                }
            }
        }
    }
    stop_signal().await
}

/// An upgrade is asked: the binary at this binary's path, probed. Whether
/// it passed, and the node stops for it.
#[cfg(unix)]
async fn ready() -> bool {
    let binary = match crate::update::replace::running() {
        Ok(binary) => binary,
        Err(why) => {
            say(format!("an upgrade was asked, but {why}: the node goes on with this binary"));
            return false;
        }
    };
    let shown = crate::update::replace::shown(&binary);
    let path = binary.clone();
    let probed = tokio::task::spawn_blocking(move || probe::probe(&path)).await;
    match probed {
        Ok(Ok(line)) => {
            say(format!("an upgrade was asked: {shown} is {line}; this node hands its sessions over to it"));
            podssh_relay::reverse::node::set_upgrading(true);
            *lock(&ASKED) = Some((binary, line));
            true
        }
        Ok(Err(why)) => {
            say(format!("an upgrade was asked, but {shown} {why}: the node goes on with this binary"));
            false
        }
        Err(e) => {
            say(format!("an upgrade was asked, but its probe failed ({e}): the node goes on with this binary"));
            false
        }
    }
}

/// After the node's road ended: when an upgrade ended it, each session goes
/// to the new binary, which takes this process's place; `Some(AGAIN)` when
/// that binary did not start, its sessions back for this one. `None` for
/// any other end.
pub(crate) async fn after() -> Option<i32> {
    let (binary, _line) = lock(&ASKED).take()?;
    let keeper = lock(&KEEPER).clone();
    let handed = match keeper {
        Some(keeper) => keeper.hand_over().await,
        None => Vec::new(),
    };
    let moved = handed.iter().filter(|h| h.target.is_ok()).count();
    for why in handed.iter().filter_map(|h| h.target.as_ref().err()).filter(|why| !why.is_empty()) {
        say(format!("a session ends at its resume: {why}"));
    }
    let shown = crate::update::replace::shown(&binary);
    say(format!("{moved} of {} sessions go to {shown}", handed.len()));
    hand(binary, handed)
}

/// A node's end: the handover of an upgrade, which ends this binary, else
/// `finish`'s code.
pub(crate) async fn or_finish(finish: impl FnOnce() -> i32) -> i32 {
    match after().await {
        Some(code) => code,
        None => finish(),
    }
}

#[cfg(unix)]
fn hand(binary: PathBuf, handed: Vec<Handed>) -> Option<i32> {
    let (back, why) = pass::become_binary(&binary, &crate::version::line(), handed);
    let shown = crate::update::replace::shown(&binary);
    say(format!("{shown} did not start ({why}): this binary serves its {} sessions again", back.len()));
    podssh_relay::reverse::node::set_upgrading(false);
    *lock(&TAKEN) = Some(back);
    Some(AGAIN)
}

#[cfg(not(unix))]
fn hand(_: PathBuf, handed: Vec<Handed>) -> Option<i32> {
    *lock(&TAKEN) = Some(handed);
    Some(AGAIN)
}

/// A keeper for the sessions of a node whose `restore` makes each target
/// from what moved; filled with the sessions that the binary before this
/// one handed over, and kept for the next handover.
fn keeper_with<A, R>(deadline: Duration, restore: R) -> Arc<Keeper<A>>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + Movable,
    R: FnMut(SessionId, Moved) -> Result<A, String>,
{
    let keeper = Arc::new(Keeper::new(deadline));
    if let Some(handed) = lock(&TAKEN).take() {
        for line in keeper.take_over(handed, restore) {
            say(line);
        }
        sweep(&keeper);
    }
    *lock(&KEEPER) = Some(keeper.clone());
    keeper
}

/// The sessions that wait with no link are forgotten at their deadline,
/// also when no new link comes to start the node's own sweep.
fn sweep<A>(keeper: &Arc<Keeper<A>>)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + Movable,
{
    let keeper = Arc::downgrade(keeper);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let Some(keeper) = keeper.upgrade() else { return };
            keeper.expire().await;
        }
    });
}

/// The connection of a target, back in this binary's runtime.
fn connection(socket: std::net::TcpStream) -> Result<TcpStream, String> {
    socket.set_nonblocking(true).map_err(|e| format!("its connection: {e}"))?;
    TcpStream::from_std(socket).map_err(|e| format!("its connection: {e}"))
}

/// The keeper of a node whose sessions run the end-to-end channel.
pub(crate) fn channel_keeper(node: &ends::Node, deadline: Duration) -> Arc<Keeper<DuplexStream>> {
    let node = node.clone();
    keeper_with(deadline, move |id, moved: Moved| {
        let channel = moved.channel.ok_or("it ran no end-to-end channel, which this node runs")?;
        hold::resume(id, &channel, connection(moved.socket)?, &node)
    })
}

/// The keeper of a node of `--no-e2e`, whose sessions reach their target as
/// it is.
pub(crate) fn tcp_keeper(deadline: Duration) -> Arc<Keeper<TcpStream>> {
    keeper_with(deadline, |_, moved: Moved| match moved.channel {
        Some(_) => Err("it ran the end-to-end channel, which --no-e2e turns off".to_string()),
        None => connection(moved.socket),
    })
}

/// The keeper of a node whose sessions' targets do not move (UDP flows):
/// each handed session ends at its resume, with why.
pub(crate) fn pipe_keeper(deadline: Duration) -> Arc<Keeper<DuplexStream>> {
    keeper_with(deadline, |_, _| Err("this node's targets do not move".to_string()))
}

/// Ctrl-C, or SIGTERM on Unix. When no signal can be watched, the node runs
/// until the relay ends it, and does not stop at once.
pub(crate) async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                stopped = tokio::signal::ctrl_c() => {
                    if stopped.is_err() {
                        term.recv().await;
                    }
                }
                _ = term.recv() => {}
            }
            return;
        }
    }
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
