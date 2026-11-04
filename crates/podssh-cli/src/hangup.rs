//! The signals that end a client of a node's layer (T-586): SIGHUP, SIGTERM
//! and SIGINT on Unix, Ctrl-C, Ctrl-Break and the console's close on
//! Windows. OpenSSH sends SIGHUP to its ProxyCommand as it exits and does
//! not wait for it, so `podssh operator` died of it before it ended its
//! session: the node kept the session as a loss for its whole deadline, with
//! its connection to sshd, and a run of short logins filled the node's
//! budget (GitHub #112).
//!
//! Taken, a signal is the end of the application's bytes: the layer's input
//! ends, the layer sends `CLOSE` after the bytes in flight, and the node
//! forgets the session at once. The session then has [`AFTER_SIGNAL`] to
//! end, for the node's answer and the leg's Close; nobody reads its bytes
//! any more. A process runs one command, and the command takes the signals
//! once: each session of the layer in it reads them ([`taken`]). Where the
//! layer ends one direction with `END` (T-632), an end of the input would end
//! that direction alone, so the reads fail at a signal ([`ending_wholly`]).

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;

/// How long a session may take to end after a signal: the node's answer to
/// the `CLOSE`, then the leg's Close and the relay's answer.
pub const AFTER_SIGNAL: Duration = Duration::from_secs(2);

/// Which signals end the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    /// Each of them: a byte pipe (`operator`, `pipe`), whose parent ends it
    /// with any.
    All,
    /// SIGHUP and SIGTERM, and the console's close: `ssh`, whose Ctrl-C goes
    /// to the remote command.
    Ends,
}

/// The signals that this process took.
#[derive(Clone)]
pub struct Hangup {
    came: watch::Receiver<bool>,
}

/// The process's signals, once taken.
static TAKEN: Mutex<Option<Hangup>> = Mutex::new(None);

/// Take `which` from now on, inside the runtime: none ends the process by
/// itself any more, each ends the sessions of the layer. They are set up
/// before this returns, so that a signal right after it is not lost. A
/// second call keeps the first's.
pub fn take(which: Which) -> Hangup {
    let mut taken = TAKEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(hangup) = taken.as_ref() {
        return hangup.clone();
    }
    let (tx, came) = watch::channel(false);
    let stops = Stops::of(which);
    tokio::spawn(async move {
        if stops.next().await {
            let _ = tx.send(true);
        }
        // With none taken, the sender goes, and nothing ever comes.
    });
    let hangup = Hangup { came };
    *taken = Some(hangup.clone());
    hangup
}

/// The signals that this process took, if it took any.
pub fn taken() -> Option<Hangup> {
    TAKEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
}

impl Hangup {
    /// When a signal comes; never, when none could be taken.
    pub async fn came(&self) {
        let mut came = self.came.clone();
        // The value is read and let go before any other wait.
        let seen = came.wait_for(|signalled| *signalled).await.is_ok();
        if !seen {
            std::future::pending::<()>().await;
        }
    }
}

/// `app`, whose bytes end at a signal of `hangup`: its reads give the end of
/// the input from then on, and the layer sends `CLOSE`. With no `hangup`,
/// `app` as it is.
pub fn ending<A>(app: A, hangup: Option<&Hangup>) -> Ending<A> {
    let stop: Pin<Box<dyn Future<Output = ()> + Send>> = match hangup.cloned() {
        Some(hangup) => Box::pin(async move { hangup.came().await }),
        None => Box::pin(std::future::pending::<()>()),
    };
    Ending { app, stop, ended: false, whole: false }
}

/// [`ending`], for a session whose layer ends one direction with `END`
/// (T-632): at a signal its reads fail, so that the layer ends the whole
/// session with `CLOSE` and the far end forgets it at once, where an end of
/// the input would end this side's bytes alone.
pub fn ending_wholly<A>(app: A, hangup: Option<&Hangup>) -> Ending<A> {
    Ending { whole: true, ..ending(app, hangup) }
}

/// `work`, or `None` at a signal of `hangup`: before the node took the
/// session, there is nothing to close, and nothing to wait for.
pub async fn unless<F: Future>(hangup: Option<&Hangup>, work: F) -> Option<F::Output> {
    let Some(hangup) = hangup else { return Some(work.await) };
    tokio::select! {
        out = work => Some(out),
        () = hangup.came() => None,
    }
}

/// `session`, which `hangup` cuts [`AFTER_SIGNAL`] after a signal: `None`
/// when it was cut. With no `hangup`, `session` to its end.
pub async fn bounded<F: Future>(hangup: Option<&Hangup>, session: F) -> Option<F::Output> {
    let Some(hangup) = hangup else { return Some(session.await) };
    tokio::pin!(session);
    tokio::select! {
        out = &mut session => return Some(out),
        () = hangup.came() => {}
    }
    tokio::time::timeout(AFTER_SIGNAL, session).await.ok()
}

/// An application whose input ends at a signal.
pub struct Ending<A> {
    app: A,
    stop: Pin<Box<dyn Future<Output = ()> + Send>>,
    ended: bool,
    /// A signal fails the reads: the end of the whole session.
    whole: bool,
}

impl<A: AsyncRead + Unpin> AsyncRead for Ending<A> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if !this.ended && this.stop.as_mut().poll(cx).is_ready() {
            this.ended = true;
        }
        if this.ended && this.whole {
            let why = "a signal ended the session";
            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, why)));
        }
        if this.ended {
            // The end of the input: nothing filled.
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.app).poll_read(cx, buf)
    }
}

impl<A: AsyncWrite + Unpin> AsyncWrite for Ending<A> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.app).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.app).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.app).poll_shutdown(cx)
    }
}

/// The signals, set up in the runtime.
#[cfg(unix)]
struct Stops(Vec<tokio::signal::unix::Signal>);

#[cfg(unix)]
impl Stops {
    fn of(which: Which) -> Stops {
        use tokio::signal::unix::{signal, SignalKind};
        let mut kinds = vec![(SignalKind::hangup(), libc::SIGHUP), (SignalKind::terminate(), libc::SIGTERM)];
        if which == Which::All {
            kinds.push((SignalKind::interrupt(), libc::SIGINT));
        }
        // A signal ignored at the start stays so, as a shell keeps it: nohup's
        // SIGHUP, a detached run's (`--detach`, `ssh -f`).
        kinds.retain(|&(_, number)| !ignored(number));
        // One that cannot be taken keeps its default: a probe, not a guess.
        Stops(kinds.into_iter().filter_map(|(kind, _)| signal(kind).ok()).collect())
    }

    /// Whether one came; `false` when none was taken.
    async fn next(mut self) -> bool {
        if self.0.is_empty() {
            return false;
        }
        let waits = self.0.iter_mut().map(|signal| Box::pin(signal.recv()));
        futures_util::future::select_all(waits).await.0.is_some()
    }
}

/// Whether the process ignores `number`, read from its disposition.
#[cfg(unix)]
fn ignored(number: libc::c_int) -> bool {
    // SAFETY: a query alone (no new action), into a zeroed struct that the
    // call fills.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(number, std::ptr::null(), &mut old) == 0 && old.sa_sigaction == libc::SIG_IGN
    }
}

#[cfg(windows)]
struct Stops {
    c: Option<tokio::signal::windows::CtrlC>,
    brk: Option<tokio::signal::windows::CtrlBreak>,
    close: Option<tokio::signal::windows::CtrlClose>,
}

#[cfg(windows)]
impl Stops {
    fn of(which: Which) -> Stops {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close};
        let all = which == Which::All;
        Stops {
            c: all.then(|| ctrl_c().ok()).flatten(),
            brk: all.then(|| ctrl_break().ok()).flatten(),
            close: ctrl_close().ok(),
        }
    }

    /// Whether one came; `false` when none was taken.
    async fn next(self) -> bool {
        let Stops { mut c, mut brk, mut close } = self;
        if c.is_none() && brk.is_none() && close.is_none() {
            return false;
        }
        let c = async move {
            match c.as_mut() {
                Some(c) => c.recv().await,
                None => std::future::pending().await,
            }
        };
        let brk = async move {
            match brk.as_mut() {
                Some(brk) => brk.recv().await,
                None => std::future::pending().await,
            }
        };
        let close = async move {
            match close.as_mut() {
                Some(close) => close.recv().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            Some(()) = c => true,
            Some(()) = brk => true,
            Some(()) = close => true,
            else => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A hangup of the test: its sender, and the receiver that a signal
    /// would feed.
    fn hangup() -> (watch::Sender<bool>, Hangup) {
        let (tx, came) = watch::channel(false);
        (tx, Hangup { came })
    }

    /// Before the signal the bytes pass both ways; after it, the input
    /// ends though its writer goes on, and the output still passes.
    #[tokio::test]
    async fn the_input_ends_at_the_signal_and_the_output_goes_on() {
        let (tx, hangup) = hangup();
        let (ours, mut theirs) = tokio::io::duplex(1024);
        let mut app = ending(ours, Some(&hangup));
        theirs.write_all(b"before").await.unwrap();
        let mut got = [0u8; 6];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"before");
        tx.send(true).unwrap();
        theirs.write_all(b"after").await.unwrap();
        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), app.read_to_end(&mut rest)).await;
        assert_eq!(read.expect("the input ended").unwrap(), 0, "no byte after the signal");
        app.write_all(b"out").await.unwrap();
        let mut out = [0u8; 3];
        theirs.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"out");
    }

    /// Where the layer ends one direction with `END` (T-632), a signal
    /// fails the reads, which the layer takes as the end of the session.
    #[tokio::test]
    async fn a_signal_fails_the_reads_where_the_session_ends_wholly() {
        let (tx, hangup) = hangup();
        let (ours, _theirs) = tokio::io::duplex(1024);
        let mut app = ending_wholly(ours, Some(&hangup));
        tx.send(true).unwrap();
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(5), app.read(&mut buf)).await.expect("the read ended");
        assert_eq!(read.unwrap_err().kind(), std::io::ErrorKind::ConnectionAborted);
    }

    /// With no signal taken, the application is as it was.
    #[tokio::test]
    async fn with_no_hangup_the_input_is_as_it_was() {
        let (ours, mut theirs) = tokio::io::duplex(1024);
        let mut app = ending(ours, None);
        theirs.write_all(b"bytes").await.unwrap();
        drop(theirs);
        let mut got = Vec::new();
        app.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"bytes");
    }

    /// A session that ends by itself is not cut; one that goes on after a
    /// signal is, [`AFTER_SIGNAL`] later.
    #[tokio::test(start_paused = true)]
    async fn a_session_is_cut_after_the_signal_and_its_time() {
        let (tx, hangup) = hangup();
        assert_eq!(bounded(Some(&hangup), async { 7 }).await, Some(7));
        let started = tokio::time::Instant::now();
        let signal = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            tx.send(true).unwrap();
        };
        let (cut, ()) = tokio::join!(bounded(Some(&hangup), std::future::pending::<()>()), signal);
        assert_eq!(cut, None);
        let (spent, due) = (started.elapsed(), Duration::from_secs(1) + AFTER_SIGNAL);
        assert!(spent >= due && spent < due + Duration::from_millis(100), "cut after {spent:?}");
        assert_eq!(bounded(None, async { 8 }).await, Some(8));
    }

    /// Before the node took the session, a signal ends the wait at once.
    #[tokio::test(start_paused = true)]
    async fn a_signal_before_the_session_ends_the_wait_at_once() {
        let (tx, hangup) = hangup();
        assert_eq!(unless(Some(&hangup), async { 9 }).await, Some(9));
        tx.send(true).unwrap();
        let started = tokio::time::Instant::now();
        assert_eq!(unless(Some(&hangup), std::future::pending::<()>()).await, None);
        assert!(started.elapsed() < Duration::from_millis(100));
    }
}
